/*
 * qemu_command.c: QEMU command generation
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "qemu_dbus.h"
#include "qemu_interface.h"
#include "qemu_alias.h"
#include "qemu_security.h"
#include "qemu_passt.h"
#include "qemu_slirp.h"
#include "qemu_block.h"
#include "qemu_fd.h"
#include "viralloc.h"
#include "virlog.h"
#include "virarch.h"
#include "virerror.h"
#include "virfile.h"
#include "virqemu.h"
#include "virstring.h"
#include "virtime.h"
#include "viruuid.h"
#include "domain_nwfilter.h"
#include "domain_addr.h"
#include "domain_conf.h"
#include "netdev_bandwidth_conf.h"
#include "virnetdevopenvswitch.h"
#include "device_conf.h"
#include "storage_source_conf.h"
#include "virtpm.h"
#include "virnuma.h"
#include "virgic.h"
#include "virmdev.h"
#include "virutil.h"

#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_command");

VIR_ENUM_DECL(qemuDiskCacheV2);

VIR_ENUM_IMPL(qemuDiskCacheV2,
              VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback",
              "directsync",
              "unsafe",
);

VIR_ENUM_IMPL(qemuVideo,
              VIR_DOMAIN_VIDEO_TYPE_LAST,
              "", /* default value, we shouldn't see this */
              "std",
              "cirrus",
              "vmware",
              "", /* don't support xen */
              "", /* don't support vbox */
              "qxl",
              "", /* don't support parallels */
              "", /* no need for virtio */
              "" /* don't support gop */,
              "" /* 'none' doesn't make sense here */,
              "bochs-display",
              "", /* ramfb can't be used with -vga */
);

VIR_ENUM_IMPL(qemuSoundCodec,
              VIR_DOMAIN_SOUND_CODEC_TYPE_LAST,
              "hda-duplex",
              "hda-micro",
              "hda-output",
);

VIR_ENUM_DECL(qemuControllerModelUSB);

VIR_ENUM_IMPL(qemuControllerModelUSB,
              VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST,
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
              "qusb1",
              "qusb2",
              "qemu-xhci",
              "none",
);

VIR_ENUM_DECL(qemuNumaPolicy);
VIR_ENUM_IMPL(qemuNumaPolicy,
              VIR_DOMAIN_NUMATUNE_MEM_LAST,
              "bind",
              "preferred",
              "interleave",
              "restrictive",
);


const char *
qemuAudioDriverTypeToString(virDomainAudioType type)
{
    switch (type) {
        case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
            return "pa";
        case VIR_DOMAIN_AUDIO_TYPE_FILE:
            return "wav";
        case VIR_DOMAIN_AUDIO_TYPE_NONE:
        case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        case VIR_DOMAIN_AUDIO_TYPE_JACK:
        case VIR_DOMAIN_AUDIO_TYPE_OSS:
        case VIR_DOMAIN_AUDIO_TYPE_SDL:
        case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        case VIR_DOMAIN_AUDIO_TYPE_LAST:
            break;
    }
    return virDomainAudioTypeTypeToString(type);
}


virDomainAudioType
qemuAudioDriverTypeFromString(const char *str)
{
    if (STREQ(str, "pa")) {
        return VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO;
    } else if (STREQ(str, "wav")) {
        return VIR_DOMAIN_AUDIO_TYPE_FILE;
    }
    return virDomainAudioTypeTypeFromString(str);
}


static const char *
qemuOnOffAuto(virTristateSwitch s)
{
    if (s == VIR_TRISTATE_SWITCH_ABSENT)
        return NULL;

    return virTristateSwitchTypeToString(s);
}


static int
qemuBuildObjectCommandlineFromJSON(virCommand *cmd,
                                   virJSONValue *props,
                                   virQEMUCaps *qemuCaps)
{
    g_autofree char *arg = NULL;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_JSON)) {
        if (!(arg = virJSONValueToString(props, false)))
            return -1;
    } else {
        const char *type = virJSONValueObjectGetString(props, "qom-type");
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        virBufferAsprintf(&buf, "%s,", type);

        if (virQEMUBuildCommandLineJSON(props, &buf, "qom-type",
                                        virQEMUBuildCommandLineJSONArrayBitmap) < 0)
            return -1;

        arg = virBufferContentAndReset(&buf);
    }

    virCommandAddArgList(cmd, "-object", arg, NULL);
    return 0;
}


static int
qemuBuildNetdevCommandlineFromJSON(virCommand *cmd,
                                   virJSONValue *props,
                                   virQEMUCaps *qemuCaps)
{
    g_autofree char *arg = NULL;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV_JSON)) {
        if (!(arg = virJSONValueToString(props, false)))
            return -1;
    } else {
        const char *type = virJSONValueObjectGetString(props, "type");
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        virBufferAsprintf(&buf, "%s,", type);

        if (virQEMUBuildCommandLineJSON(props, &buf, "type",
                                        virQEMUBuildCommandLineJSONArrayObjectsStr) < 0)
            return -1;

        arg = virBufferContentAndReset(&buf);
    }

    virCommandAddArgList(cmd, "-netdev", arg, NULL);
    return 0;
}


static void
qemuBuildDeviceCommandlineHandleOverrides(virJSONValue *props,
                                          qemuDomainXmlNsDef *nsdef)
{
    const char *alias = virJSONValueObjectGetString(props, "id");
    size_t i;

    /* If the device doesn't have an alias we can't override its props */
    if (!alias)
        return;

    for (i = 0; i < nsdef->ndeviceOverride; i++) {
        qemuDomainXmlNsDeviceOverride *dev = nsdef->deviceOverride + i;
        size_t j;

        if (STRNEQ(alias, dev->alias))
            continue;

        for (j = 0; j < dev->nfrontend; j++) {
            qemuDomainXmlNsOverrideProperty *prop = dev->frontend + j;

            virJSONValueObjectRemoveKey(props, prop->name, NULL);
            if (prop->json) {
                g_autoptr(virJSONValue) copy = virJSONValueCopy(prop->json);

                virJSONValueObjectAppend(props, prop->name, &copy);
            }
        }
    }
}


static int
qemuBuildDeviceCommandlineFromJSON(virCommand *cmd,
                                   virJSONValue *props,
                                   const virDomainDef *def,
                                   virQEMUCaps *qemuCaps)
{
    qemuDomainXmlNsDef *nsdef = def->namespaceData;
    g_autofree char *arg = NULL;

    if (nsdef && nsdef->ndeviceOverride > 0)
        qemuBuildDeviceCommandlineHandleOverrides(props, nsdef);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_JSON)) {
        if (!(arg = virJSONValueToString(props, false)))
            return -1;
    } else {
        const char *driver = virJSONValueObjectGetString(props, "driver");
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

        virBufferAsprintf(&buf, "%s,", driver);

        if (virQEMUBuildCommandLineJSON(props, &buf, "driver", NULL) < 0)
            return -1;

        arg = virBufferContentAndReset(&buf);
    }

    virCommandAddArgList(cmd, "-device", arg, NULL);
    return 0;
}


/**
 * qemuBuildMasterKeyCommandLine:
 * @cmd: the command to modify
 * @qemuCaps qemu capabilities object
 * @domainLibDir: location to find the master key

 * Formats the command line for a master key if available
 *
 * Returns 0 on success, -1 w/ error message on failure
 */
static int
qemuBuildMasterKeyCommandLine(virCommand *cmd,
                              qemuDomainObjPrivate *priv)
{
    g_autofree char *alias = NULL;
    g_autofree char *path = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(alias = qemuDomainGetMasterKeyAlias()))
        return -1;

    /* Get the path. NB, the mocked test will not have the created
     * file so we cannot check for existence, which is no different
     * than other command line options which do not check for the
     * existence of socket files before using.
     */
    if (!(path = qemuDomainGetMasterKeyFilePath(priv->libDir)))
        return -1;

    if (qemuMonitorCreateObjectProps(&props, "secret", alias,
                                     "s:format", "raw",
                                     "s:file", path,
                                     NULL) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static char *
qemuBuildDeviceAddressPCIGetBus(const virDomainDef *domainDef,
                                const virDomainDeviceInfo *info)
{
    g_autofree char *devStr = NULL;
    const char *contAlias = NULL;
    bool contIsPHB = false;
    int contTargetIndex = 0;
    size_t i;

    if (!(devStr = virPCIDeviceAddressAsString(&info->addr.pci)))
        return NULL;

    for (i = 0; i < domainDef->ncontrollers; i++) {
        virDomainControllerDef *cont = domainDef->controllers[i];

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            cont->idx == info->addr.pci.bus) {
            contAlias = cont->info.alias;
            contIsPHB = virDomainControllerIsPSeriesPHB(cont);
            contTargetIndex = cont->opts.pciopts.targetIndex;

            if (!contAlias) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Device alias was not set for PCI controller with index '%1$u' required for device at address '%2$s'"),
                               info->addr.pci.bus, devStr);
                return NULL;
            }

            if (virDomainDeviceAliasIsUserAlias(contAlias)) {
                /* When domain has builtin pci-root controller we don't put it
                 * onto cmd line. Therefore we can't set its alias. In that
                 * case, use the default one. */
                if (!qemuDomainIsPSeries(domainDef) &&
                    cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
                    if (virQEMUCapsHasPCIMultiBus(domainDef))
                        contAlias = "pci.0";
                    else
                        contAlias = "pci";
                } else if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
                    contAlias = "pcie.0";
                }
            }
            break;
        }
    }

    if (!contAlias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find PCI controller with index '%1$u' required for device at address '%2$s'"),
                       info->addr.pci.bus, devStr);
        return NULL;
    }

    /* The PCI bus created by a spapr-pci-host-bridge device with
     * alias 'x' will be called 'x.0' rather than 'x'; however,
     * this does not apply to the implicit PHB in a pSeries guest,
     * which always has the hardcoded name 'pci.0' */
    if (contIsPHB && contTargetIndex > 0)
        return g_strdup_printf("%s.0", contAlias);

    /* For all other controllers, the bus name matches the alias
     * of the corresponding controller */
    return g_strdup(contAlias);
}


static int
qemuBuildDeviceAddresDriveProps(virJSONValue *props,
                                const virDomainDef *domainDef,
                                const virDomainDeviceInfo *info)
{
    g_autofree char *bus = NULL;
    virDomainControllerDef *controller = NULL;
    const char *controllerAlias = NULL;

    switch (info->addr.drive.diskbus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        /* When domain has builtin IDE controller we don't put it onto cmd
         * line. Therefore we can't set its alias. In that case, use the
         * default one. */
        if (qemuDomainHasBuiltinIDE(domainDef)) {
            controllerAlias = "ide";
        } else {
            if (!(controllerAlias = virDomainControllerAliasFind(domainDef,
                                                                 VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                                                 info->addr.drive.controller)))
                return -1;
        }

        bus = g_strdup_printf("%s.%u", controllerAlias, info->addr.drive.bus);

        if (virJSONValueObjectAdd(&props,
                                  "s:bus", bus,
                                  "u:unit", info->addr.drive.unit,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_DISK_BUS_SATA:
        /* When domain has builtin SATA controller we don't put it onto cmd
         * line. Therefore we can't set its alias. In that case, use the
         * default one. */
        if (qemuDomainIsQ35(domainDef) &&
            info->addr.drive.controller == 0) {
            controllerAlias = "ide";
        } else {
            if (!(controllerAlias = virDomainControllerAliasFind(domainDef,
                                                                 VIR_DOMAIN_CONTROLLER_TYPE_SATA,
                                                                 info->addr.drive.controller)))
                return -1;
        }

        bus = g_strdup_printf("%s.%u", controllerAlias, info->addr.drive.unit);

        if (virJSONValueObjectAdd(&props,
                                  "s:bus", bus,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        if (virJSONValueObjectAdd(&props,
                                  "u:unit", info->addr.drive.unit,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (!(controller = virDomainDeviceFindSCSIController(domainDef, &info->addr.drive))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to find a SCSI controller for idx=%1$d"),
                           info->addr.drive.controller);
            return -1;
        }

        switch ((virDomainControllerModelSCSI) controller->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DC390:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AM53C974:
            bus = g_strdup_printf("%s.%u", controller->info.alias, info->addr.drive.bus);

            if (virJSONValueObjectAdd(&props,
                                      "s:bus", bus,
                                      "u:scsi-id", info->addr.drive.unit,
                                      NULL) < 0)
                return -1;

            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
            bus = g_strdup_printf("%s.0", controller->info.alias);

            if (virJSONValueObjectAdd(&props,
                                      "s:bus", bus,
                                      "u:channel", info->addr.drive.bus,
                                      "u:scsi-id", info->addr.drive.target,
                                      "u:lun", info->addr.drive.unit,
                                      NULL) < 0)
                return -1;

            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected SCSI controller model %1$d"),
                           controller->model);
            return -1;
        }

        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("address type drive is not supported for bus '%1$s'"),
                       NULLSTR(virDomainDiskBusTypeToString(info->addr.drive.diskbus)));
        return -1;
    }

    return 0;
}


static int
qemuBuildDeviceAddressProps(virJSONValue *props,
                            const virDomainDef *domainDef,
                            const virDomainDeviceInfo *info)
{
    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI: {
        g_autofree char *pciaddr = NULL;
        g_autofree char *bus = qemuBuildDeviceAddressPCIGetBus(domainDef, info);

        if (!bus)
            return -1;

        if (info->addr.pci.function != 0)
            pciaddr = g_strdup_printf("0x%x.0x%x", info->addr.pci.slot, info->addr.pci.function);
        else
            pciaddr = g_strdup_printf("0x%x", info->addr.pci.slot);

        if (virJSONValueObjectAdd(&props,
                                  "s:bus", bus,
                                  "T:multifunction", info->addr.pci.multi,
                                  "s:addr", pciaddr,
                                  "p:acpi-index", info->acpiIndex,
                                  NULL) < 0)
            return -1;

        return 0;
    }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB: {
        const char *contAlias = NULL;
        g_auto(virBuffer) port = VIR_BUFFER_INITIALIZER;
        g_autofree char *bus = NULL;

        if (!(contAlias = virDomainControllerAliasFind(domainDef,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                                       info->addr.usb.bus)))
            return -1;

        bus = g_strdup_printf("%s.0", contAlias);

        virDomainUSBAddressPortFormatBuf(&port, info->addr.usb.port);

        if (virJSONValueObjectAdd(&props,
                                  "s:bus", bus,
                                  "S:port", virBufferCurrentContent(&port),
                                  NULL) < 0)
            return -1;

        return 0;
    }

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (info->addr.spaprvio.has_reg) {
            if (virJSONValueObjectAdd(&props,
                                      "P:reg", info->addr.spaprvio.reg,
                                      NULL) < 0)
                return -1;
        }
        return 0;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW: {
        g_autofree char *devno = g_strdup_printf(VIR_CCW_DEVICE_ADDRESS_FMT,
                                                 info->addr.ccw.cssid,
                                                 info->addr.ccw.ssid,
                                                 info->addr.ccw.devno);

        if (virJSONValueObjectAdd(&props, "s:devno", devno, NULL) < 0)
            return -1;

        return 0;
    }

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (virJSONValueObjectAdd(&props,
                                  "u:iobase", info->addr.isa.iobase,
                                  "p:irq", info->addr.isa.irq,
                                  NULL) < 0)
            return -1;

        return 0;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (virJSONValueObjectAdd(&props,
                                  "u:slot", info->addr.dimm.slot,
                                  "P:addr", info->addr.dimm.base,
                                  NULL) < 0)
            return -1;

        return 0;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        return qemuBuildDeviceAddresDriveProps(props, domainDef, info);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL: {
        const char *contAlias;
        g_autofree char *bus = NULL;

        if (!(contAlias = virDomainControllerAliasFind(domainDef,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
                                                       info->addr.vioserial.controller)))
            return -1;

        bus = g_strdup_printf("%s.%d", contAlias, info->addr.vioserial.bus);

        if (virJSONValueObjectAdd(&props,
                                  "s:bus", bus,
                                  "i:nr", info->addr.vioserial.port,
                                  NULL) < 0)
            return -1;

        return 0;
    }

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    default:
        return 0;
    }
}


/**
 * qemuDeviceVideoGetModel:
 * @qemuCaps: qemu capabilities
 * @video: video device definition
 * @virtio: the returned video device is a 'virtio' device
 * @virtioBusSuffix: the returned device needs to get the bus-suffix
 *
 * Returns the model of the device for @video and @qemuCaps. @virtio and
 * @virtioBusSuffix are filled with the corresponding flags.
 */
static const char *
qemuDeviceVideoGetModel(virQEMUCaps *qemuCaps,
                        const virDomainVideoDef *video,
                        bool *virtio,
                        bool *virtioBusSuffix)
{
    const char *model = NULL;
    bool primaryVga = false;
    virTristateBool accel3d = VIR_TRISTATE_BOOL_ABSENT;

    *virtio = false;
    *virtioBusSuffix = false;

    if (video->accel)
        accel3d = video->accel->accel3d;

    if (video->primary && qemuDomainSupportsVideoVga(video, qemuCaps))
        primaryVga = true;

    /* We try to chose the best model for primary video device by preferring
     * model with VGA compatibility mode.  For some video devices on some
     * architectures there might not be such model so fallback to one
     * without VGA compatibility mode. */
    if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
        if (primaryVga) {
            model = "vhost-user-vga";
        } else {
            model = "vhost-user-gpu";
            *virtio = true;
            *virtioBusSuffix = true;
        }
    } else {
        if (primaryVga) {
            switch ((virDomainVideoType) video->type) {
            case VIR_DOMAIN_VIDEO_TYPE_VGA:
                model = "VGA";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
                model = "cirrus-vga";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
                model = "vmware-svga";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_QXL:
                model = "qxl-vga";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_VGA_GL) &&
                    accel3d == VIR_TRISTATE_BOOL_YES)
                    model = "virtio-vga-gl";
                else
                    model = "virtio-vga";

                *virtio = true;
                *virtioBusSuffix = false;
                break;
            case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
                model = "bochs-display";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
                model = "ramfb";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
            case VIR_DOMAIN_VIDEO_TYPE_XEN:
            case VIR_DOMAIN_VIDEO_TYPE_VBOX:
            case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
            case VIR_DOMAIN_VIDEO_TYPE_GOP:
            case VIR_DOMAIN_VIDEO_TYPE_NONE:
            case VIR_DOMAIN_VIDEO_TYPE_LAST:
                break;
            }
        } else {
            switch ((virDomainVideoType) video->type) {
            case VIR_DOMAIN_VIDEO_TYPE_QXL:
                model = "qxl";
                break;
            case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_GL_PCI) &&
                    accel3d == VIR_TRISTATE_BOOL_YES)
                    model = "virtio-gpu-gl";
                else
                    model = "virtio-gpu";

                *virtio = true;
                *virtioBusSuffix = true;
                break;
            case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
            case VIR_DOMAIN_VIDEO_TYPE_VGA:
            case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
            case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
            case VIR_DOMAIN_VIDEO_TYPE_XEN:
            case VIR_DOMAIN_VIDEO_TYPE_VBOX:
            case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
            case VIR_DOMAIN_VIDEO_TYPE_GOP:
            case VIR_DOMAIN_VIDEO_TYPE_NONE:
            case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
            case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
            case VIR_DOMAIN_VIDEO_TYPE_LAST:
                break;
            }
        }
    }

    if (!model || STREQ(model, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid model for video type '%1$s'"),
                       virDomainVideoTypeToString(video->type));
        return NULL;
    }

    return model;
}


static void
qemuBuildVirtioDevGetConfigDev(const virDomainDeviceDef *device,
                               virQEMUCaps *qemuCaps,
                               const char **baseName,
                               virDomainVirtioOptions **virtioOptions,
                               bool *has_tmodel,
                               bool *has_ntmodel,
                               bool *useBusSuffix)
{
    switch (device->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            if (virStorageSourceGetActualType(device->data.disk->src) == VIR_STORAGE_TYPE_VHOST_USER)
                *baseName = "vhost-user-blk";
            else
                *baseName = "virtio-blk";

            *virtioOptions = device->data.disk->virtio;
            *has_tmodel = device->data.disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_NET:
            *baseName = "virtio-net";
            *virtioOptions = device->data.net->virtio;
            *has_tmodel = device->data.net->model == VIR_DOMAIN_NET_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.net->model == VIR_DOMAIN_NET_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            if (device->data.hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST) {
                *baseName = "vhost-scsi";
                *has_tmodel = device->data.hostdev->source.subsys.u.scsi_host.model == VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_VIRTIO_TRANSITIONAL;
                *has_ntmodel = device->data.hostdev->source.subsys.u.scsi_host.model == VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_VIRTIO_NON_TRANSITIONAL;
            }
            break;

        case VIR_DOMAIN_DEVICE_RNG:
            *baseName = "virtio-rng";
            *virtioOptions = device->data.rng->virtio;
            *has_tmodel = device->data.rng->model == VIR_DOMAIN_RNG_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.rng->model == VIR_DOMAIN_RNG_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_FS:
            switch (device->data.fs->fsdriver) {
            case VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT:
            case VIR_DOMAIN_FS_DRIVER_TYPE_PATH:
            case VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE:
                *baseName = "virtio-9p";
                break;

            case VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS:
                *baseName = "vhost-user-fs";
                break;

            case VIR_DOMAIN_FS_DRIVER_TYPE_LOOP:
            case VIR_DOMAIN_FS_DRIVER_TYPE_NBD:
            case VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP:
            case VIR_DOMAIN_FS_DRIVER_TYPE_LAST:
                break;

            }
            *virtioOptions = device->data.fs->virtio;
            *has_tmodel = device->data.fs->model == VIR_DOMAIN_FS_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.fs->model == VIR_DOMAIN_FS_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_MEMBALLOON:
            *baseName = "virtio-balloon";
            *virtioOptions = device->data.memballoon->virtio;
            *has_tmodel = device->data.memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_VSOCK:
            *baseName = "vhost-vsock";
            *virtioOptions = device->data.vsock->virtio;
            *has_tmodel = device->data.vsock->model == VIR_DOMAIN_VSOCK_MODEL_VIRTIO_TRANSITIONAL;
            *has_ntmodel = device->data.vsock->model == VIR_DOMAIN_VSOCK_MODEL_VIRTIO_NON_TRANSITIONAL;
            break;

        case VIR_DOMAIN_DEVICE_INPUT:
            *virtioOptions = device->data.input->virtio;

            switch ((virDomainInputType) device->data.input->type) {
            case VIR_DOMAIN_INPUT_TYPE_MOUSE:
                *baseName = "virtio-mouse";
                break;

            case VIR_DOMAIN_INPUT_TYPE_TABLET:
                *baseName = "virtio-tablet";
                break;

            case VIR_DOMAIN_INPUT_TYPE_KBD:
                *baseName = "virtio-keyboard";
                break;

            case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
                *baseName = "virtio-input-host";
                break;

            case VIR_DOMAIN_INPUT_TYPE_EVDEV:
            case VIR_DOMAIN_INPUT_TYPE_LAST:
            default:
                break;
            }
            break;

        case VIR_DOMAIN_DEVICE_CONTROLLER:
            if (device->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL) {
                *baseName = "virtio-serial";
                *virtioOptions = device->data.controller->virtio;
                *has_tmodel = device->data.controller->model == VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_VIRTIO_TRANSITIONAL;
                *has_ntmodel = device->data.controller->model == VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_VIRTIO_NON_TRANSITIONAL;
            } else if (device->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
                *baseName = "virtio-scsi";
                *virtioOptions = device->data.controller->virtio;
                *has_tmodel = device->data.controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL;
                *has_ntmodel = device->data.controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL;
            }
            break;

        case VIR_DOMAIN_DEVICE_VIDEO: {
            bool virtio;
            bool virtioBusSuffix;

            if (!(*baseName = qemuDeviceVideoGetModel(qemuCaps,
                                                      device->data.video,
                                                      &virtio,
                                                      &virtioBusSuffix)))
                return;

            if (!virtioBusSuffix)
                *useBusSuffix = false;

            *virtioOptions = device->data.video->virtio;
        }
            break;

        case VIR_DOMAIN_DEVICE_CRYPTO: {
            *baseName = "virtio-crypto";
            *virtioOptions = device->data.crypto->virtio;
            break;
        }

        case VIR_DOMAIN_DEVICE_LEASE:
        case VIR_DOMAIN_DEVICE_SOUND:
        case VIR_DOMAIN_DEVICE_WATCHDOG:
        case VIR_DOMAIN_DEVICE_GRAPHICS:
        case VIR_DOMAIN_DEVICE_HUB:
        case VIR_DOMAIN_DEVICE_REDIRDEV:
        case VIR_DOMAIN_DEVICE_NONE:
        case VIR_DOMAIN_DEVICE_SMARTCARD:
        case VIR_DOMAIN_DEVICE_CHR:
        case VIR_DOMAIN_DEVICE_NVRAM:
        case VIR_DOMAIN_DEVICE_SHMEM:
        case VIR_DOMAIN_DEVICE_TPM:
        case VIR_DOMAIN_DEVICE_PANIC:
        case VIR_DOMAIN_DEVICE_MEMORY:
        case VIR_DOMAIN_DEVICE_IOMMU:
        case VIR_DOMAIN_DEVICE_AUDIO:
        case VIR_DOMAIN_DEVICE_LAST:
        default:
            break;
    }
}


static int
qemuBuildVirtioDevGetConfig(const virDomainDeviceDef *device,
                            virQEMUCaps *qemuCaps,
                            char **devtype,
                            virDomainVirtioOptions **virtioOptions)
{
    virDomainDeviceInfo *info = virDomainDeviceGetInfo(device);
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *baseName = NULL;
    const char *implName = NULL;
    bool has_tmodel = false;
    bool has_ntmodel = false;
    bool useBusSuffix = true;

    qemuBuildVirtioDevGetConfigDev(device, qemuCaps, &baseName,
                                   virtioOptions, &has_tmodel,
                                   &has_ntmodel, &useBusSuffix);

    if (!baseName) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unknown base name while formatting virtio device"));
        return -1;
    }

    virBufferAdd(&buf, baseName, -1);

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        implName = "pci";
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        implName = "device";
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        implName = "ccw";
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected address type for '%1$s'"), baseName);
        return -1;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceAddressType, info->type);
        return -1;
    }

    if (useBusSuffix)
        virBufferAsprintf(&buf, "-%s", implName);

    if (has_tmodel || has_ntmodel) {
        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio (non-)transitional models are not supported for address type=%1$s"),
                           virDomainDeviceAddressTypeToString(info->type));
        }

        if (has_tmodel) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL)) {
                virBufferAddLit(&buf, "-transitional");
            }
            /* No error if -transitional is not supported: our address
             * allocation will force the device into plain PCI bus, which
             * is functionally identical to standard 'virtio-XXX' behavior
             */
        } else if (has_ntmodel) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL)) {
                virBufferAddLit(&buf, "-non-transitional");
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtio non-transitional model not supported for this qemu"));
                return -1;
            }
        }
    }

    *devtype = virBufferContentAndReset(&buf);

    return 0;
}


/**
 * qemuBuildVirtioDevProps
 * @devtype: virDomainDeviceType of the device. Ex: VIR_DOMAIN_DEVICE_TYPE_RNG
 * @devdata: *Def * of the device definition
 * @qemuCaps: qemu capabilities
 *
 * Build the qemu virtio -device JSON properties name from the passed parameters.
 */
static virJSONValue *
qemuBuildVirtioDevProps(virDomainDeviceType devtype,
                        const void *devdata,
                        virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const virDomainDeviceDef device = { .type = devtype };
    g_autofree char *model = NULL;
    virDomainVirtioOptions *virtioOptions = NULL;

    /* We temporarily cast the const away here, but that's safe to do
     * because the called function simply sets the correct member of
     * device to devdata based on devtype. Further uses of device will
     * not touch its contents */
    virDomainDeviceSetData((virDomainDeviceDef *) &device, (void *) devdata);

    if (qemuBuildVirtioDevGetConfig(&device, qemuCaps, &model, &virtioOptions) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", model,
                              NULL) < 0)
        return NULL;

    if (virtioOptions) {
        if (virJSONValueObjectAdd(&props,
                                  "T:iommu_platform", virtioOptions->iommu,
                                  "T:ats", virtioOptions->ats,
                                  "T:packed", virtioOptions->packed,
                                  "T:page-per-vq", virtioOptions->page_per_vq,
                                  NULL) < 0)
            return NULL;
    }

    return g_steal_pointer(&props);
}


static int
qemuBuildRomProps(virJSONValue *props,
                  virDomainDeviceInfo *info)
{
    const char *romfile = NULL;
    int rombar = -1;

    if (info->romenabled == VIR_TRISTATE_BOOL_ABSENT &&
        info->rombar == VIR_TRISTATE_SWITCH_ABSENT &&
        !info->romfile)
        return 0;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ROM tuning is only supported for PCI devices"));
        return -1;
    }

    if (info->romenabled == VIR_TRISTATE_BOOL_NO) {
        romfile = "";
    } else {
        romfile = info->romfile;

        switch (info->rombar) {
        case VIR_TRISTATE_SWITCH_OFF:
            rombar = 0;
            break;
        case VIR_TRISTATE_SWITCH_ON:
            rombar = 1;
            break;
        case VIR_TRISTATE_SWITCH_ABSENT:
        case VIR_TRISTATE_SWITCH_LAST:
            break;
        }
    }

    if (virJSONValueObjectAdd(&props,
                              "k:rombar", rombar,
                              "S:romfile", romfile,
                              NULL) < 0)
        return -1;

    return 0;
}


/**
 * qemuBuildSecretInfoProps:
 * @secinfo: pointer to the secret info object
 * @props: json properties to return
 *
 * Build the JSON properties for the secret info type.
 *
 * Returns 0 on success with the filled in JSON property; otherwise,
 * returns -1 on failure error message set.
 */
int
qemuBuildSecretInfoProps(qemuDomainSecretInfo *secinfo,
                         virJSONValue **propsret)
{
    g_autofree char *keyid = NULL;

    if (!(keyid = qemuDomainGetMasterKeyAlias()))
        return -1;

    return qemuMonitorCreateObjectProps(propsret, "secret",
                                        secinfo->alias, "s:data",
                                        secinfo->ciphertext, "s:keyid",
                                        keyid, "s:iv", secinfo->iv,
                                        "s:format", "base64", NULL);
}


/**
 * qemuBuildObjectSecretCommandLine:
 * @cmd: the command to modify
 * @secinfo: pointer to the secret info object
 * @qemuCaps: qemu capabilities
 *
 * If the secinfo is available and associated with an AES secret,
 * then format the command line for the secret object. This object
 * will be referenced by the device that needs/uses it, so it needs
 * to be in place first.
 *
 * Returns 0 on success, -1 w/ error message on failure
 */
static int
qemuBuildObjectSecretCommandLine(virCommand *cmd,
                                 qemuDomainSecretInfo *secinfo,
                                 virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (qemuBuildSecretInfoProps(secinfo, &props) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
        return -1;

    return 0;
}


/* qemuBuildTLSx509BackendProps:
 * @tlspath: path to the TLS credentials
 * @listen: boolean listen for client or server setting
 * @verifypeer: boolean to enable peer verification (form of authorization)
 * @alias: alias for the TLS credentials object
 * @secalias: if one exists, the alias of the security object for passwordid
 * @propsret: json properties to return
 *
 * Create a backend string for the tls-creds-x509 object.
 *
 * Returns 0 on success, -1 on failure with error set.
 */
int
qemuBuildTLSx509BackendProps(const char *tlspath,
                             bool isListen,
                             bool verifypeer,
                             const char *alias,
                             const char *secalias,
                             virJSONValue **propsret)
{
    if (qemuMonitorCreateObjectProps(propsret, "tls-creds-x509", alias,
                                     "s:dir", tlspath,
                                     "s:endpoint", (isListen ? "server": "client"),
                                     "b:verify-peer", (isListen ? verifypeer : true),
                                     "S:passwordid", secalias,
                                     NULL) < 0)
        return -1;

    return 0;
}


/* qemuBuildTLSx509CommandLine:
 * @cmd: Pointer to command
 * @tlspath: path to the TLS credentials
 * @listen: boolean listen for client or server setting
 * @verifypeer: boolean to enable peer verification (form of authorization)
 * @certEncSecretAlias: alias of a 'secret' object for decrypting TLS private key
 *                      (optional)
 * @alias: TLS object alias
 * @qemuCaps: capabilities
 *
 * Create the command line for a TLS object
 *
 * Returns 0 on success, -1 on failure with error set.
 */
static int
qemuBuildTLSx509CommandLine(virCommand *cmd,
                            const char *tlspath,
                            bool isListen,
                            bool verifypeer,
                            const char *certEncSecretAlias,
                            const char *alias,
                            virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (qemuBuildTLSx509BackendProps(tlspath, isListen, verifypeer, alias,
                                     certEncSecretAlias, &props) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
        return -1;

    return 0;
}


static void
qemuBuildChrChardevReconnectStr(virBuffer *buf,
                                const virDomainChrSourceReconnectDef *def)
{
    if (def->enabled == VIR_TRISTATE_BOOL_YES) {
        virBufferAsprintf(buf, ",reconnect=%u", def->timeout);
    } else if (def->enabled == VIR_TRISTATE_BOOL_NO) {
        virBufferAddLit(buf, ",reconnect=0");
    }
}


static char *
qemuBuildChardevStr(const virDomainChrSourceDef *dev,
                    const char *charAlias)
{

    qemuDomainChrSourcePrivate *chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev);
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *path;
    virTristateSwitch append;

    switch ((virDomainChrType) dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferAsprintf(&buf, "null,id=%s", charAlias);
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferAsprintf(&buf, "vc,id=%s", charAlias);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAsprintf(&buf, "pty,id=%s", charAlias);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV: {
        const char *backend = "serial";

        if (STRPREFIX(charAlias, "charparallel"))
            backend = "parallel";

        virBufferAsprintf(&buf, "%s,id=%s,path=", backend, charAlias);
        virQEMUBuildBufferEscapeComma(&buf, dev->data.file.path);
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(&buf, "file,id=%s", charAlias);
        path = dev->data.file.path;
        append = dev->data.file.append;

        if (chrSourcePriv->sourcefd) {
            path = qemuFDPassGetPath(chrSourcePriv->sourcefd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        virBufferAddLit(&buf, ",path=");
        virQEMUBuildBufferEscapeComma(&buf, path);
        if (append != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&buf, ",append=%s",
                              virTristateSwitchTypeToString(append));
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(&buf, "pipe,id=%s,path=", charAlias);
        virQEMUBuildBufferEscapeComma(&buf, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAsprintf(&buf, "stdio,id=%s", charAlias);
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
                          "udp,id=%s,host=%s,port=%s,localaddr=%s,"
                          "localport=%s",
                          charAlias,
                          connectHost,
                          dev->data.udp.connectService,
                          bindHost, bindService);
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferAsprintf(&buf,
                          "socket,id=%s,host=%s,port=%s",
                          charAlias,
                          dev->data.tcp.host,
                          dev->data.tcp.service);

        if (dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET)
            virBufferAddLit(&buf, ",telnet=on");

        if (dev->data.tcp.listen) {
            virBufferAddLit(&buf, ",server=on");
            if (!chrSourcePriv->wait)
                virBufferAddLit(&buf, ",wait=off");
        }

        qemuBuildChrChardevReconnectStr(&buf, &dev->data.tcp.reconnect);

        if (chrSourcePriv->tlsCredsAlias)
            virBufferAsprintf(&buf, ",tls-creds=%s", chrSourcePriv->tlsCredsAlias);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&buf, "socket,id=%s", charAlias);
        if (chrSourcePriv->directfd) {
            virBufferAsprintf(&buf, ",fd=%s", qemuFDPassDirectGetPath(chrSourcePriv->directfd));
        } else {
            virBufferAddLit(&buf, ",path=");
            virQEMUBuildBufferEscapeComma(&buf, dev->data.nix.path);
        }

        if (dev->data.nix.listen) {
            virBufferAddLit(&buf, ",server=on");
            if (!chrSourcePriv->wait)
                virBufferAddLit(&buf, ",wait=off");
        }

        qemuBuildChrChardevReconnectStr(&buf, &dev->data.nix.reconnect);
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        virBufferAsprintf(&buf, "spicevmc,id=%s,name=%s", charAlias,
                          virDomainChrSpicevmcTypeToString(dev->data.spicevmc));
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        virBufferAsprintf(&buf, "spiceport,id=%s,name=%s", charAlias,
                          dev->data.spiceport.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
        virBufferAsprintf(&buf, "qemu-vdagent,id=%s,name=vdagent",
                          charAlias);
        if (dev->data.qemuVdagent.clipboard != VIR_TRISTATE_BOOL_ABSENT)
            virBufferAsprintf(&buf, ",clipboard=%s",
                              virTristateSwitchTypeToString(dev->data.qemuVdagent.clipboard));
        switch (dev->data.qemuVdagent.mouse) {
            case VIR_DOMAIN_MOUSE_MODE_CLIENT:
                virBufferAddLit(&buf, ",mouse=on");
                break;
            case VIR_DOMAIN_MOUSE_MODE_SERVER:
                virBufferAddLit(&buf, ",mouse=off");
                break;
            case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
            case VIR_DOMAIN_MOUSE_MODE_LAST:
            default:
                break;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        virBufferAsprintf(&buf, "dbus,id=%s,name=%s", charAlias,
                          dev->data.dbus.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
    default:
        break;
    }

    if (dev->logfile) {
        path = dev->logfile;
        append = dev->logappend;

        if (chrSourcePriv->logfd) {
            path = qemuFDPassGetPath(chrSourcePriv->logfd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        virBufferAddLit(&buf, ",logfile=");
        virQEMUBuildBufferEscapeComma(&buf, path);
        if (append != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&buf, ",logappend=%s",
                              virTristateSwitchTypeToString(append));
        }
    }

    return virBufferContentAndReset(&buf);
}


static int
qemuBuildChardevCommand(virCommand *cmd,
                        const virDomainChrSourceDef *dev,
                        const char *charAlias,
                        virQEMUCaps *qemuCaps)
{
    qemuDomainChrSourcePrivate *chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev);
    g_autofree char *charstr = NULL;

    switch ((virDomainChrType) dev->type) {
    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (dev->data.tcp.haveTLS == VIR_TRISTATE_BOOL_YES) {
            g_autofree char *objalias = NULL;
            const char *tlsCertEncSecAlias = NULL;

            /* Add the secret object first if necessary. The
             * secinfo is added only to a TCP serial device during
             * qemuDomainSecretChardevPrepare. Subsequently called
             * functions can just check the config fields */
            if (chrSourcePriv->secinfo) {
                if (qemuBuildObjectSecretCommandLine(cmd,
                                                     chrSourcePriv->secinfo,
                                                     qemuCaps) < 0)
                    return -1;

                tlsCertEncSecAlias = chrSourcePriv->secinfo->alias;
            }

            if (!(objalias = qemuAliasTLSObjFromSrcAlias(charAlias)))
                return -1;

            if (qemuBuildTLSx509CommandLine(cmd, chrSourcePriv->tlsCertPath,
                                            dev->data.tcp.listen,
                                            chrSourcePriv->tlsVerify,
                                            tlsCertEncSecAlias,
                                            objalias, qemuCaps) < 0) {
                return -1;
            }

            chrSourcePriv->tlsCredsAlias = g_steal_pointer(&objalias);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        qemuFDPassTransferCommand(chrSourcePriv->sourcefd, cmd);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        qemuFDPassDirectTransferCommand(chrSourcePriv->directfd, cmd);
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%1$s'"),
                       virDomainChrTypeToString(dev->type));
        return -1;
    }

    qemuFDPassTransferCommand(chrSourcePriv->logfd, cmd);

    if (!(charstr = qemuBuildChardevStr(dev, charAlias)))
        return -1;

    virCommandAddArgList(cmd, "-chardev", charstr, NULL);

    qemuDomainChrSourcePrivateClearFDPass(chrSourcePriv);

    return 0;
}


bool
qemuDiskConfigBlkdeviotuneEnabled(const virDomainDiskDef *disk)
{
    return !!disk->blkdeviotune.group_name ||
           virDomainBlockIoTuneInfoHasAny(&disk->blkdeviotune);
}


/**
 * qemuDiskBusIsSD:
 * @bus: disk bus
 *
 * Unfortunately it is not possible to use -device for SD devices.
 * Fortunately, those don't need static PCI addresses, so we can use -drive
 * without -device.
 */
bool
qemuDiskBusIsSD(int bus)
{
    return bus == VIR_DOMAIN_DISK_BUS_SD;
}


static int
qemuBuildDriveSourceStr(virDomainDiskDef *disk,
                        virBuffer *buf)
{
    virStorageType actualType = virStorageSourceGetActualType(disk->src);
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(disk->src);
    qemuDomainSecretInfo **encinfo = NULL;
    bool rawluks = false;

    if (srcpriv)
        encinfo = srcpriv->encinfo;

    switch (actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_DIR:
        virBufferAddLit(buf, "file=");
        if (actualType == VIR_STORAGE_TYPE_DIR) {
            virBufferAddLit(buf, "fat:");

            if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                virBufferAddLit(buf, "floppy:");
        }

        virQEMUBuildBufferEscapeComma(buf, disk->src->path);
        break;

    case VIR_STORAGE_TYPE_NETWORK: {
        g_autoptr(virJSONValue) props = NULL;
        g_autoptr(virJSONValue) wrap = NULL;

        if (!(props = qemuBlockStorageSourceGetBackendProps(disk->src,
                                                            QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_LEGACY)))
            return -1;

        if (virJSONValueObjectAdd(&wrap, "a:file", &props, NULL) < 0)
            return -1;

        if (virQEMUBuildCommandLineJSON(wrap, buf, NULL,
                                        virQEMUBuildCommandLineJSONArrayNumbered) < 0)
            return -1;
        break;
    }

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unsupported storage type for this code path"));
        return -1;
    }

    virBufferAddLit(buf, ",");

    if (encinfo) {
        if (disk->src->format == VIR_STORAGE_FILE_RAW) {
            virBufferAsprintf(buf, "key-secret=%s,", encinfo[0]->alias);
            rawluks = true;
        } else if (disk->src->format == VIR_STORAGE_FILE_QCOW2 &&
                   disk->src->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
            virBufferAddLit(buf, "encrypt.format=luks,");
            virBufferAsprintf(buf, "encrypt.key-secret=%s,", encinfo[0]->alias);
        }
    }

    if (disk->src->format > 0 &&
        actualType != VIR_STORAGE_TYPE_DIR) {
        const char *qemuformat = virStorageFileFormatTypeToString(disk->src->format);
        if (rawluks)
            qemuformat = "luks";
        virBufferAsprintf(buf, "format=%s,", qemuformat);
    }

    return 0;
}


static void
qemuBuildDiskGetErrorPolicy(virDomainDiskDef *disk,
                            const char **wpolicy,
                            const char **rpolicy)
{
    if (disk->error_policy)
        *wpolicy = virDomainDiskErrorPolicyTypeToString(disk->error_policy);

    if (disk->rerror_policy)
        *rpolicy = virDomainDiskErrorPolicyTypeToString(disk->rerror_policy);

    if (disk->error_policy == VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE) {
        /* in the case of enospace, the option is spelled
         * differently in qemu, and it's only valid for werror,
         * not for rerror, so leave rerror NULL.
         */
        *wpolicy = "enospc";
    } else if (!*rpolicy) {
        /* for other policies, rpolicy can match wpolicy */
        *rpolicy = *wpolicy;
    }
}


static char *
qemuBuildDriveStr(virDomainDiskDef *disk)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    int detect_zeroes = virDomainDiskGetDetectZeroesMode(disk->discard,
                                                         disk->detect_zeroes);

    if (qemuBuildDriveSourceStr(disk, &opt) < 0)
        return NULL;

    virBufferAsprintf(&opt, "if=sd,index=%d", virDiskNameToIndex(disk->dst));

    if (disk->src->readonly)
        virBufferAddLit(&opt, ",readonly=on");

    /* qemu rejects some parameters for an empty -drive, so we need to skip
     * them in that case:
     * cache: modifies properties of the format driver which is not present
     * copy_on_read: really only works for floppies
     * discard: modifies properties of format driver
     * detect_zeroes: works but really depends on discard so it's useless
     * iomode: setting it to 'native' requires a specific cache mode
     */
    if (!virStorageSourceIsEmpty(disk->src)) {
        if (disk->cachemode) {
            virBufferAsprintf(&opt, ",cache=%s",
                              qemuDiskCacheV2TypeToString(disk->cachemode));
        }

        if (disk->copy_on_read) {
            virBufferAsprintf(&opt, ",copy-on-read=%s",
                              virTristateSwitchTypeToString(disk->copy_on_read));
        }

        if (disk->discard) {
            virBufferAsprintf(&opt, ",discard=%s",
                              virDomainDiskDiscardTypeToString(disk->discard));
        }

        if (detect_zeroes) {
            virBufferAsprintf(&opt, ",detect-zeroes=%s",
                              virDomainDiskDetectZeroesTypeToString(detect_zeroes));
        }

        if (disk->iomode) {
            virBufferAsprintf(&opt, ",aio=%s",
                              virDomainDiskIoTypeToString(disk->iomode));
        }
    }

    return virBufferContentAndReset(&opt);
}


virJSONValue *
qemuBuildDiskDeviceProps(const virDomainDef *def,
                         virDomainDiskDef *disk,
                         virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *driver = NULL;
    g_autofree char *scsiVPDDeviceId = NULL;
    virTristateSwitch shareRW = VIR_TRISTATE_SWITCH_ABSENT;
    g_autofree char *chardev = NULL;
    g_autofree char *drive = NULL;
    unsigned int bootindex = 0;
    unsigned int logical_block_size = disk->blockio.logical_block_size;
    unsigned int physical_block_size = disk->blockio.physical_block_size;
    unsigned int discard_granularity = disk->blockio.discard_granularity;
    g_autoptr(virJSONValue) wwn = NULL;
    g_autofree char *serial = NULL;
    virTristateSwitch removable = VIR_TRISTATE_SWITCH_ABSENT;
    virTristateSwitch writeCache = VIR_TRISTATE_SWITCH_ABSENT;
    const char *biosCHSTrans = NULL;
    const char *wpolicy = NULL;
    const char *rpolicy = NULL;

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_SATA:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
            driver = "ide-cd";
        else
            driver = "ide-hd";

        break;

    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            driver = "scsi-block";
        } else {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                driver = "scsi-cd";
            } else {
                driver = "scsi-hd";
                removable = disk->removable;
            }

            /* qemu historically used the name of -drive as one of the device
             * ids in the Vital Product Data Device Identification page if
             * disk serial was not set and the disk serial otherwise.
             * To avoid a guest-visible regression we need to provide it
             * ourselves especially for cases when -blockdev will be used */
            if (disk->serial) {
                scsiVPDDeviceId = g_strdup(disk->serial);
            } else {
                if (!(scsiVPDDeviceId = qemuAliasDiskDriveFromDisk(disk)))
                    return NULL;
            }
        }

        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO: {
        virTristateSwitch scsi = VIR_TRISTATE_SWITCH_ABSENT;
        g_autofree char *iothread = NULL;

        if (disk->iothread > 0)
            iothread = g_strdup_printf("iothread%u", disk->iothread);

        if (virStorageSourceGetActualType(disk->src) != VIR_STORAGE_TYPE_VHOST_USER &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_SCSI)) {
            /* if sg_io is true but the scsi option isn't supported,
             * that means it's just always on in this version of qemu.
             */
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
                scsi = VIR_TRISTATE_SWITCH_ON;
            } else {
                if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_SCSI_DEFAULT_DISABLED))
                    scsi = VIR_TRISTATE_SWITCH_OFF;
            }
        }

        if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_DISK, disk, qemuCaps)))
            return NULL;

        if (virJSONValueObjectAdd(&props,
                                  "S:iothread", iothread,
                                  "T:ioeventfd", disk->ioeventfd,
                                  "T:event_idx", disk->event_idx,
                                  "T:scsi", scsi,
                                  "p:num-queues", disk->queues,
                                  "p:queue-size", disk->queue_size,
                                  NULL) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_DISK_BUS_USB:
        driver = "usb-storage";

        if (disk->removable == VIR_TRISTATE_SWITCH_ABSENT)
            removable = VIR_TRISTATE_SWITCH_OFF;
        else
            removable = disk->removable;

        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        driver = "floppy";
        break;

    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk bus '%1$s' with device setup"),
                       NULLSTR(virDomainDiskBusTypeToString(disk->bus)));
        return NULL;
    }

    if (driver) {
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", driver,
                                  NULL) < 0)
            return NULL;
    }

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
        disk->info.addr.drive.diskbus = disk->bus;

    if (qemuBuildDeviceAddressProps(props, def, &disk->info) < 0)
        return NULL;

    if (disk->src->shared)
        shareRW = VIR_TRISTATE_SWITCH_ON;

    if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_VHOST_USER) {
        chardev = qemuDomainGetVhostUserChrAlias(disk->info.alias);
    } else {
        if (qemuDomainDiskGetBackendAlias(disk, &drive) < 0)
            return NULL;
    }

    /* bootindex for floppies is configured via the fdc controller */
    if (disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY)
        bootindex = disk->info.effectiveBootIndex;

    if (disk->wwn) {
        unsigned long long w = 0;

        if (virStrToLong_ull(disk->wwn, NULL, 16, &w) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Failed to parse wwn '%1$s' as number"), disk->wwn);
            return NULL;
        }

        wwn = virJSONValueNewNumberUlong(w);
    }

    /* 'write-cache' component of disk->cachemode is set on device level.
     * VIR_DOMAIN_DISK_DEVICE_LUN translates into 'scsi-block' where any
     * caching setting makes no sense. */
    if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN) {
        bool wb;

        if (qemuDomainDiskCachemodeFlags(disk->cachemode, &wb, NULL, NULL)) {
            writeCache = virTristateSwitchFromBool(wb);
        }
    }

    if (disk->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT)
        biosCHSTrans = virDomainDiskGeometryTransTypeToString(disk->geometry.trans);

    if (disk->serial) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        virBufferEscape(&buf, '\\', " ", "%s", disk->serial);
        serial = virBufferContentAndReset(&buf);
    }

    qemuBuildDiskGetErrorPolicy(disk, &wpolicy, &rpolicy);

    if (virJSONValueObjectAdd(&props,
                              "S:device_id", scsiVPDDeviceId,
                              "T:share-rw", shareRW,
                              "S:drive", drive,
                              "S:chardev", chardev,
                              "s:id", disk->info.alias,
                              "p:bootindex", bootindex,
                              "p:logical_block_size", logical_block_size,
                              "p:physical_block_size", physical_block_size,
                              "p:discard_granularity", discard_granularity,
                              "A:wwn", &wwn,
                              "p:rotation_rate", disk->rotation_rate,
                              "S:vendor", disk->vendor,
                              "S:product", disk->product,
                              "T:removable", removable,
                              "S:write-cache", qemuOnOffAuto(writeCache),
                              "p:cyls", disk->geometry.cylinders,
                              "p:heads", disk->geometry.heads,
                              "p:secs", disk->geometry.sectors,
                              "S:bios-chs-trans", biosCHSTrans,
                              "S:serial", serial,
                              "S:werror", wpolicy,
                              "S:rerror", rpolicy,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildZPCIDevProps(virDomainDeviceInfo *dev)
{
    virJSONValue *props = NULL;
    g_autofree char *alias = g_strdup_printf("zpci%u", dev->addr.pci.zpci.uid.value);

    virJSONValueObjectAdd(&props,
                          "s:driver", "zpci",
                          "u:uid", dev->addr.pci.zpci.uid.value,
                          "u:fid", dev->addr.pci.zpci.fid.value,
                          "s:target", dev->alias,
                          "s:id", alias,
                          NULL);

    return props;
}


static int
qemuCommandAddExtDevice(virCommand *cmd,
                        virDomainDeviceInfo *dev,
                        const virDomainDef *def,
                        virQEMUCaps *qemuCaps)
{
    if (dev->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        dev->addr.pci.extFlags == VIR_PCI_ADDRESS_EXTENSION_NONE) {
        return 0;
    }

    if (dev->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        g_autoptr(virJSONValue) devprops = NULL;

        if (!(devprops = qemuBuildZPCIDevProps(dev)))
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static void
qemuBuildFloppyCommandLineControllerOptionsImplicit(virCommand *cmd,
                                                    unsigned int bootindexA,
                                                    unsigned int bootindexB)
{
    if (bootindexA > 0) {
        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "isa-fdc.bootindexA=%u", bootindexA);
    }

    if (bootindexB > 0) {
        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "isa-fdc.bootindexB=%u", bootindexB);
    }
}


static int
qemuBuildFloppyCommandLineControllerOptionsExplicit(virCommand *cmd,
                                                    unsigned int bootindexA,
                                                    unsigned int bootindexB,
                                                    const virDomainDef *def,
                                                    virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "isa-fdc",
                              "p:bootindexA", bootindexA,
                              "p:bootindexB", bootindexB,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildFloppyCommandLineControllerOptions(virCommand *cmd,
                                            const virDomainDef *def,
                                            virQEMUCaps *qemuCaps)
{
    unsigned int bootindexA = 0;
    unsigned int bootindexB = 0;
    bool hasfloppy = false;
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];

        if (disk->bus != VIR_DOMAIN_DISK_BUS_FDC)
            continue;

        hasfloppy = true;

        if (disk->info.addr.drive.unit) {
            bootindexB = disk->info.effectiveBootIndex;
        } else {
            bootindexA = disk->info.effectiveBootIndex;
        }
    }

    if (!hasfloppy)
        return 0;

    if (qemuDomainNeedsFDC(def)) {
        if (qemuBuildFloppyCommandLineControllerOptionsExplicit(cmd,
                                                                bootindexA,
                                                                bootindexB,
                                                                def,
                                                                qemuCaps) < 0)
            return -1;
    } else {
        qemuBuildFloppyCommandLineControllerOptionsImplicit(cmd,
                                                            bootindexA,
                                                            bootindexB);
    }

    return 0;
}


static int
qemuBuildObjectCommandline(virCommand *cmd,
                           virJSONValue *objProps,
                           virQEMUCaps *qemuCaps)
{
    if (!objProps)
        return 0;

    if (qemuBuildObjectCommandlineFromJSON(cmd, objProps, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildBlockStorageSourceAttachDataCommandline(virCommand *cmd,
                                                 qemuBlockStorageSourceAttachData *data,
                                                 virQEMUCaps *qemuCaps)
{
    char *tmp;
    size_t i;

    if (qemuBuildObjectCommandline(cmd, data->prmgrProps, qemuCaps) < 0 ||
        qemuBuildObjectCommandline(cmd, data->authsecretProps, qemuCaps) < 0 ||
        qemuBuildObjectCommandline(cmd, data->httpcookiesecretProps, qemuCaps) < 0 ||
        qemuBuildObjectCommandline(cmd, data->tlsKeySecretProps, qemuCaps) < 0 ||
        qemuBuildObjectCommandline(cmd, data->tlsProps, qemuCaps) < 0)
        return -1;

    for (i = 0; i < data->encryptsecretCount; ++i) {
        if (qemuBuildObjectCommandline(cmd, data->encryptsecretProps[i], qemuCaps) < 0) {
            return -1;
        }
    }

    if (data->driveCmd)
        virCommandAddArgList(cmd, "-drive", data->driveCmd, NULL);

    if (data->chardevDef) {
        if (qemuBuildChardevCommand(cmd, data->chardevDef, data->chardevAlias, qemuCaps) < 0)
            return -1;
    }

    qemuFDPassTransferCommand(data->fdpass, cmd);

    if (data->storageProps) {
        if (!(tmp = virJSONValueToString(data->storageProps, false)))
            return -1;

        virCommandAddArgList(cmd, "-blockdev", tmp, NULL);
        VIR_FREE(tmp);
    }

    if (data->storageSliceProps) {
        if (!(tmp = virJSONValueToString(data->storageSliceProps, false)))
            return -1;

        virCommandAddArgList(cmd, "-blockdev", tmp, NULL);
        VIR_FREE(tmp);
    }

    if (data->formatProps) {
        if (!(tmp = virJSONValueToString(data->formatProps, false)))
            return -1;

        virCommandAddArgList(cmd, "-blockdev", tmp, NULL);
        VIR_FREE(tmp);
    }

    return 0;
}


static int
qemuBuildDiskSourceCommandLine(virCommand *cmd,
                               virDomainDiskDef *disk,
                               virQEMUCaps *qemuCaps)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    g_autoptr(virJSONValue) copyOnReadProps = NULL;
    g_autofree char *copyOnReadPropsStr = NULL;
    size_t i;

    if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_VHOST_USER) {
        if (!(data = qemuBuildStorageSourceChainAttachPrepareChardev(disk)))
            return -1;
    } else if (!qemuDiskBusIsSD(disk->bus)) {
        if (virStorageSourceIsEmpty(disk->src))
            return 0;

        if (!(data = qemuBuildStorageSourceChainAttachPrepareBlockdev(disk->src)))
            return -1;

        if (disk->copy_on_read == VIR_TRISTATE_SWITCH_ON &&
            !(copyOnReadProps = qemuBlockStorageGetCopyOnReadProps(disk)))
            return -1;
    } else {
        if (!(data = qemuBuildStorageSourceChainAttachPrepareDrive(disk)))
            return -1;
    }

    for (i = data->nsrcdata; i > 0; i--) {
        if (qemuBuildBlockStorageSourceAttachDataCommandline(cmd,
                                                             data->srcdata[i - 1],
                                                             qemuCaps) < 0)
            return -1;
    }

    if (copyOnReadProps) {
        if (!(copyOnReadPropsStr = virJSONValueToString(copyOnReadProps, false)))
            return -1;

        virCommandAddArgList(cmd, "-blockdev", copyOnReadPropsStr, NULL);
    }

    return 0;
}


static int
qemuBuildDiskCommandLine(virCommand *cmd,
                         const virDomainDef *def,
                         virDomainDiskDef *disk,
                         virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) devprops = NULL;

    if (qemuBuildDiskSourceCommandLine(cmd, disk, qemuCaps) < 0)
        return -1;

    /* SD cards are currently instantiated via -drive if=sd, so the -device
     * part must be skipped */
    if (qemuDiskBusIsSD(disk->bus))
        return 0;

    if (qemuCommandAddExtDevice(cmd, &disk->info, def, qemuCaps) < 0)
        return -1;

    if (!(devprops = qemuBuildDiskDeviceProps(def, disk, qemuCaps)))
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildDisksCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    size_t i;

    if (qemuBuildFloppyCommandLineControllerOptions(cmd, def, qemuCaps) < 0)
        return -1;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];

        /* transient disks with shared backing image will be hotplugged after
         * the VM is started */
        if (disk->transient &&
            disk->transientShareBacking == VIR_TRISTATE_BOOL_YES)
            continue;

        if (qemuBuildDiskCommandLine(cmd, def, disk, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


virJSONValue *
qemuBuildVHostUserFsDevProps(virDomainFSDef *fs,
                             const virDomainDef *def,
                             const char *chardev_alias,
                             qemuDomainObjPrivate *priv)
{
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_FS, fs, priv->qemuCaps)))
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:id", fs->info.alias,
                              "s:chardev", chardev_alias,
                              "P:queue-size", fs->queue_size,
                              "s:tag", fs->dst,
                              "p:bootindex", fs->info.bootIndex,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &fs->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildVHostUserFsCommandLine(virCommand *cmd,
                                virDomainFSDef *fs,
                                const virDomainDef *def,
                                qemuDomainObjPrivate *priv)
{
    g_autofree char *chardev_alias = qemuDomainGetVhostUserChrAlias(fs->info.alias);
    g_autoptr(virJSONValue) devprops = NULL;
    g_autoptr(virDomainChrSourceDef) chrsrc = virDomainChrSourceDefNew(priv->driver->xmlopt);

    if (!chrsrc)
        return -1;

    chrsrc->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    chrsrc->data.nix.path = qemuDomainGetVHostUserFSSocketPath(priv, fs);

    if (qemuBuildChardevCommand(cmd, chrsrc, chardev_alias, priv->qemuCaps) < 0)
        return -1;

    if (qemuCommandAddExtDevice(cmd, &fs->info, def, priv->qemuCaps) < 0)
        return -1;

    if (!(devprops = qemuBuildVHostUserFsDevProps(fs, def, chardev_alias, priv)))
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static char *
qemuBuildFSStr(virDomainFSDef *fs)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    const char *wrpolicy = virDomainFSWrpolicyTypeToString(fs->wrpolicy);

    if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_PATH ||
        fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) {
        virBufferAddLit(&opt, "local");
        if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_MAPPED) {
            virBufferAddLit(&opt, ",security_model=mapped");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virBufferAddLit(&opt, ",security_model=passthrough");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_SQUASH) {
            virBufferAddLit(&opt, ",security_model=none");
        }
        if (fs->multidevs == VIR_DOMAIN_FS_MULTIDEVS_REMAP) {
            virBufferAddLit(&opt, ",multidevs=remap");
        } else if (fs->multidevs == VIR_DOMAIN_FS_MULTIDEVS_FORBID) {
            virBufferAddLit(&opt, ",multidevs=forbid");
        } else if (fs->multidevs == VIR_DOMAIN_FS_MULTIDEVS_WARN) {
            virBufferAddLit(&opt, ",multidevs=warn");
        }
        if (fs->fmode) {
            virBufferAsprintf(&opt, ",fmode=%04o", fs->fmode);
        }
        if (fs->dmode) {
            virBufferAsprintf(&opt, ",dmode=%04o", fs->dmode);
        }
    } else if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE) {
        /* removed since qemu 4.0.0 see v3.1.0-29-g93aee84f57 */
        virBufferAddLit(&opt, "handle");
    }

    if (fs->wrpolicy)
        virBufferAsprintf(&opt, ",writeout=%s", wrpolicy);

    virBufferAsprintf(&opt, ",id=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferAddLit(&opt, ",path=");
    virQEMUBuildBufferEscapeComma(&opt, fs->src->path);

    if (fs->readonly)
        virBufferAddLit(&opt, ",readonly");

    return virBufferContentAndReset(&opt);
}


static int
qemuBuildFSDevCmd(virCommand *cmd,
                  const virDomainDef *def,
                  virDomainFSDef *fs,
                  virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) devprops = NULL;
    g_autofree char *fsdev = g_strdup_printf("%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);

    if (!(devprops = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_FS, fs, qemuCaps)))
        return -1;

    if (virJSONValueObjectAdd(&devprops,
                              "s:id", fs->info.alias,
                              "s:fsdev", fsdev,
                              "s:mount_tag", fs->dst,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceAddressProps(devprops, def, &fs->info) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildFSDevCommandLine(virCommand *cmd,
                          virDomainFSDef *fs,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    g_autofree char *fsdevstr = NULL;

    virCommandAddArg(cmd, "-fsdev");
    if (!(fsdevstr = qemuBuildFSStr(fs)))
        return -1;
    virCommandAddArg(cmd, fsdevstr);

    if (qemuCommandAddExtDevice(cmd, &fs->info, def, qemuCaps) < 0)
        return -1;

    if (qemuBuildFSDevCmd(cmd, def, fs, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildFilesystemCommandLine(virCommand *cmd,
                               const virDomainDef *def,
                               virQEMUCaps *qemuCaps,
                               qemuDomainObjPrivate *priv)
{
    size_t i;

    for (i = 0; i < def->nfss; i++) {
        switch (def->fss[i]->fsdriver) {
        case VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT:
        case VIR_DOMAIN_FS_DRIVER_TYPE_PATH:
        case VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE:
            /* these drivers are handled by virtio-9p-pci */
            if (qemuBuildFSDevCommandLine(cmd, def->fss[i], def, qemuCaps) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS:
            /* vhost-user-fs-pci */
            if (qemuBuildVHostUserFsCommandLine(cmd, def->fss[i], def, priv) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FS_DRIVER_TYPE_LOOP:
        case VIR_DOMAIN_FS_DRIVER_TYPE_NBD:
        case VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP:
        case VIR_DOMAIN_FS_DRIVER_TYPE_LAST:
            break;
        }
    }

    return 0;
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
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI:
        return QEMU_CAPS_DEVICE_QEMU_XHCI;
    default:
        return -1;
    }
}


static int
qemuValidateDomainDeviceDefControllerUSB(const virDomainControllerDef *def,
                                         virQEMUCaps *qemuCaps)
{
    if (def->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("no model provided for USB controller"));
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, qemuControllerModelUSBToCaps(def->model))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("USB controller model '%1$s' not supported in this QEMU binary"),
                       virDomainControllerModelUSBTypeToString(def->model));
        return -1;
    }

    if (def->opts.usbopts.ports != -1) {
        if (def->model != VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI &&
            def->model != VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("usb controller type '%1$s' doesn't support 'ports' with this QEMU binary"),
                           virDomainControllerModelUSBTypeToString(def->model));
            return -1;
        }
    }

    return 0;
}


static const char *
qemuBuildUSBControllerFindMasterAlias(const virDomainDef *domainDef,
                                      const virDomainControllerDef *def)
{
    size_t i;

    for (i = 0; i < domainDef->ncontrollers; i++) {
        const virDomainControllerDef *tmp = domainDef->controllers[i];

        if (tmp->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
            continue;

        if (tmp->idx != def->idx)
            continue;

        if (tmp->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB)
            continue;

        return tmp->info.alias;
    }

    return NULL;
}


static virJSONValue *
qemuBuildUSBControllerDevProps(const virDomainDef *domainDef,
                               virDomainControllerDef *def,
                               virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (qemuValidateDomainDeviceDefControllerUSB(def, qemuCaps) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", qemuControllerModelUSBTypeToString(def->model),
                              "k:p2", def->opts.usbopts.ports,
                              "k:p3", def->opts.usbopts.ports,
                              NULL) < 0)
        return NULL;

    if (def->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB) {
        g_autofree char *masterbus = NULL;
        const char *alias;

        if (!(alias = qemuBuildUSBControllerFindMasterAlias(domainDef, def))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("masterbus not found"));
            return NULL;
        }

        masterbus = g_strdup_printf("%s.0", alias);

        if (virJSONValueObjectAdd(&props,
                                  "s:masterbus", masterbus,
                                  "i:firstport", def->info.master.usb.startport,
                                  NULL) < 0)
            return NULL;
    } else {
        if (virJSONValueObjectAdd(&props,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return NULL;
    }

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBuildControllerSCSIDevProps(virDomainControllerDef *def,
                                virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *iothread = NULL;
    const char *driver = NULL;

    switch ((virDomainControllerModelSCSI) def->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
        if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_CONTROLLER, def,
                                              qemuCaps)))
            return NULL;

        if (def->iothread > 0)
            iothread = g_strdup_printf("iothread%u", def->iothread);

        if (virJSONValueObjectAdd(&props,
                                  "S:iothread", iothread,
                                  "s:id", def->info.alias,
                                  "p:num_queues", def->queues,
                                  "p:cmd_per_lun", def->cmd_per_lun,
                                  "p:max_sectors", def->max_sectors,
                                  "T:ioeventfd", def->ioeventfd,
                                  NULL) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
        driver = "lsi";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
        driver = "spapr-vscsi";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
        driver = "mptsas1068";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
        driver = "megasas";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
        driver = "pvscsi";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AM53C974:
        driver = "am53c974";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DC390:
        driver = "dc-390";
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90: /* It is built-in dev */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported controller model: %1$s"),
                       virDomainControllerModelSCSITypeToString(def->model));
        return NULL;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected SCSI controller model %1$d"),
                       def->model);
        return NULL;
    }

    if (driver) {
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", driver,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return NULL;
    }

    return g_steal_pointer(&props);
}


static int
qemuBuildControllerPCIDevProps(virDomainControllerDef *def,
                               virJSONValue **devprops)
{
    g_autoptr(virJSONValue) props = NULL;
    const virDomainPCIControllerOpts *pciopts = &def->opts.pciopts;
    const char *modelName = virDomainControllerPCIModelNameTypeToString(pciopts->modelName);

    *devprops = NULL;

    /* Skip the implicit PHB for pSeries guests */
    if (def->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
        pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE &&
        pciopts->targetIndex == 0) {
        return 0;
    }

    if (!modelName) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown virDomainControllerPCIModelName value: %1$d"),
                       pciopts->modelName);
        return -1;
    }

    switch ((virDomainControllerModelPCI) def->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", modelName,
                                  "i:chassis_nr", pciopts->chassisNr,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", modelName,
                                  "i:bus_nr", pciopts->busNr,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        if (pciopts->numaNode != -1 &&
            virJSONValueObjectAdd(&props, "i:numa_node", pciopts->numaNode, NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", modelName,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", modelName,
                                  "i:port", pciopts->port,
                                  "i:chassis", pciopts->chassis,
                                  "s:id", def->info.alias,
                                  "T:hotplug", pciopts->hotplug,
                                  NULL) < 0)
            return -1;

        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", modelName,
                                  "i:index", pciopts->targetIndex,
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        if (pciopts->numaNode != -1 &&
            virJSONValueObjectAdd(&props, "i:numa_node", pciopts->numaNode, NULL) < 0)
            return -1;

        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported PCI Express root controller"));
        return -1;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected PCI controller model %1$d"),
                       def->model);
        return -1;
    }

    *devprops = g_steal_pointer(&props);
    return 0;
}



/**
 * qemuBuildControllerDevStr:
 * @domainDef: domain definition
 * @def: controller definition
 * @qemuCaps: QEMU binary capabilities
 * @devprops: filled with JSON object describing @def
 *
 * Turn @def into a description of the controller that QEMU will understand,
 * to be used either on the command line or through the monitor.
 *
 * The description will be returned in @devstr and can be NULL, eg. when
 * passing in one of the built-in controllers. The returned string must be
 * freed by the caller.
 *
 * The number pointed to by @nusbcontroller will be increased by one every
 * time the description for a USB controller has been generated successfully.
 *
 * Returns: 0 on success, <0 on failure
 */
int
qemuBuildControllerDevProps(const virDomainDef *domainDef,
                            virDomainControllerDef *def,
                            virQEMUCaps *qemuCaps,
                            virJSONValue **devprops)
{
    g_autoptr(virJSONValue) props = NULL;

    *devprops = NULL;

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        if (!(props = qemuBuildControllerSCSIDevProps(def, qemuCaps)))
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_CONTROLLER, def,
                                              qemuCaps)))
            return -1;

        if (virJSONValueObjectAdd(&props,
                                  "s:id", def->info.alias,
                                  "k:max_ports", def->opts.vioserial.ports,
                                  "k:vectors", def->opts.vioserial.vectors,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "usb-ccid",
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "ahci",
                                  "s:id", def->info.alias,
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (!(props = qemuBuildUSBControllerDevProps(domainDef, def, qemuCaps)))
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        if (qemuBuildControllerPCIDevProps(def, &props) < 0)
            return -1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported controller type: %1$s"),
                       virDomainControllerTypeToString(def->type));
        return -1;
    }

    if (!props)
        return 0;

    if (qemuBuildDeviceAddressProps(props, domainDef, &def->info) < 0)
        return -1;

    *devprops = g_steal_pointer(&props);
    return 0;
}


static bool
qemuBuildDomainForbidLegacyUSBController(const virDomainDef *def)
{
    if (qemuDomainIsQ35(def) ||
        qemuDomainIsARMVirt(def) ||
        qemuDomainIsRISCVVirt(def))
        return true;

    return false;
}


static int
qemuBuildLegacyUSBControllerCommandLine(virCommand *cmd,
                                        const virDomainDef *def)
{
    size_t i;
    size_t nlegacy = 0;
    size_t nusb = 0;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
            continue;

        /* If we have mode='none', there are no other USB controllers */
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            return 0;

        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT)
            nlegacy++;
        else
            nusb++;
    }

    if (nlegacy > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Multiple legacy USB controllers are not supported"));
        return -1;
    }

    if (nusb == 0 &&
        !qemuBuildDomainForbidLegacyUSBController(def) &&
        !ARCH_IS_S390(def->os.arch)) {
        /* We haven't added any USB controller yet, but we haven't been asked
         * not to add one either. Add a legacy USB controller, unless we're
         * creating a kind of guest we want to keep legacy-free */
        virCommandAddArg(cmd, "-usb");
    }

    return 0;
}


/**
 * qemuBuildSkipController:
 * @controller: Controller to check
 * @def: Domain definition
 *
 * Returns true if this controller can be skipped for command line
 * generation or device validation.
 */
static bool
qemuBuildSkipController(const virDomainControllerDef *controller,
                        const virDomainDef *def)
{
    /* skip pcie-root */
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
        controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT)
        return true;

    /* Skip pci-root, except for pSeries guests (which actually
     * support more than one PCI Host Bridge per guest) */
    if (!qemuDomainIsPSeries(def) &&
        controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
        controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT)
        return true;

    /* first SATA controller on Q35 machines is implicit */
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA &&
        controller->idx == 0 && qemuDomainIsQ35(def))
        return true;

    /* first IDE controller is implicit on various machines */
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
        controller->idx == 0 && qemuDomainHasBuiltinIDE(def))
        return true;

    /* first ESP SCSI controller is implicit on certain machine types */
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
        controller->idx == 0 &&
        controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90 &&
        qemuDomainHasBuiltinESP(def)) {
        return true;
    }

    return false;
}

static void
qemuBuildPMPCIRootHotplugCommandLine(virCommand *cmd,
                                     const virDomainControllerDef *controller)
{
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
        controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
        controller->idx == 0 &&
        controller->opts.pciopts.hotplug != VIR_TRISTATE_SWITCH_ABSENT) {
            virCommandAddArg(cmd, "-global");
            virCommandAddArgFormat(cmd, "PIIX4_PM.acpi-root-pci-hotplug=%s",
                                   virTristateSwitchTypeToString(controller->opts.pciopts.hotplug));
    }
    return;
}

static int
qemuBuildControllersByTypeCommandLine(virCommand *cmd,
                                      const virDomainDef *def,
                                      virQEMUCaps *qemuCaps,
                                      virDomainControllerType type)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];
        g_autoptr(virJSONValue) props = NULL;

        if (cont->type != type)
            continue;

        qemuBuildPMPCIRootHotplugCommandLine(cmd, cont);

        if (qemuBuildSkipController(cont, def))
            continue;

        /* skip USB controllers with type none.*/
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
            continue;
        }

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT &&
            !qemuBuildDomainForbidLegacyUSBController(def)) {

            /* An appropriate default USB controller model should already
             * have been selected in qemuDomainDeviceDefPostParse(); if
             * we still have no model by now, we have to fall back to the
             * legacy USB controller.
             *
             * Note that we *don't* want to end up with the legacy USB
             * controller for q35 and virt machines, so we go ahead and
             * fail in qemuBuildControllerDevStr(); on the other hand,
             * for s390 machines we want to ignore any USB controller
             * (see 548ba43028 for the full story), so we skip
             * qemuBuildControllerDevStr() but we don't ultimately end
             * up adding the legacy USB controller */
            continue;
        }

        if (qemuBuildControllerDevProps(def, cont, qemuCaps, &props) < 0)
            return -1;

        if (!props)
            continue;

        if (qemuCommandAddExtDevice(cmd, &cont->info, def, qemuCaps) < 0)
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildControllersCommandLine(virCommand *cmd,
                                const virDomainDef *def,
                                virQEMUCaps *qemuCaps)
{
    size_t i;
    int contOrder[] = {
        /*
         * List of controller types that we add commandline args for,
         * *in the order we want to add them*.
         *
         * The floppy controller is implicit on PIIX4 and older Q35
         * machines. For newer Q35 machines it is added out of the
         * controllers loop, after the floppy drives.
         *
         * We don't add PCI/PCIe root controller either, because it's
         * implicit, but we do add PCI bridges and other PCI
         * controllers, so we leave that in to check each
         * one. Likewise, we don't do anything for the primary IDE
         * controller on an i440fx machine or primary SATA on q35, but
         * we do add those beyond these two exceptions.
         *
         * CCID controllers are formatted separately after USB hubs,
         * because they go on the USB bus.
         */
        VIR_DOMAIN_CONTROLLER_TYPE_PCI,
        VIR_DOMAIN_CONTROLLER_TYPE_USB,
        VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
        VIR_DOMAIN_CONTROLLER_TYPE_IDE,
        VIR_DOMAIN_CONTROLLER_TYPE_SATA,
        VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
    };

    for (i = 0; i < G_N_ELEMENTS(contOrder); i++) {
        if (qemuBuildControllersByTypeCommandLine(cmd, def, qemuCaps, contOrder[i]) < 0)
            return -1;
    }

    if (qemuBuildLegacyUSBControllerCommandLine(cmd, def) < 0)
        return -1;

    return 0;
}


static int
qemuBuildMemoryBackendPropsShare(virJSONValue *props,
                                 virDomainMemoryAccess memAccess)
{
    switch (memAccess) {
    case VIR_DOMAIN_MEMORY_ACCESS_SHARED:
        return virJSONValueObjectAdd(&props, "b:share", true, NULL);

    case VIR_DOMAIN_MEMORY_ACCESS_PRIVATE:
        return virJSONValueObjectAdd(&props, "b:share", false, NULL);

    case VIR_DOMAIN_MEMORY_ACCESS_DEFAULT:
    case VIR_DOMAIN_MEMORY_ACCESS_LAST:
        break;
    }

    return 0;
}


static int
qemuBuildMemoryGetDefaultPagesize(virQEMUDriverConfig *cfg,
                                  unsigned long long *pagesize)
{
    virHugeTLBFS *p;

    if (!cfg->nhugetlbfs) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("hugetlbfs filesystem is not mounted or disabled by administrator config"));
        return -1;
    }

    if (!(p = virFileGetDefaultHugepage(cfg->hugetlbfs, cfg->nhugetlbfs)))
        p = &cfg->hugetlbfs[0];

    *pagesize = p->size;
    return 0;
}


static int
qemuBuildMemoryGetPagesize(virQEMUDriverConfig *cfg,
                           const virDomainDef *def,
                           const virDomainMemoryDef *mem,
                           unsigned long long *pagesizeRet,
                           bool *needHugepageRet,
                           bool *useHugepageRet,
                           bool *preallocRet)
{
    const long system_page_size = virGetSystemPageSizeKB();
    unsigned long long pagesize = 0;
    const char *nvdimmPath = NULL;
    bool needHugepage = false;
    bool useHugepage = false;
    bool prealloc = false;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        pagesize = mem->source.dimm.pagesize;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        pagesize = mem->source.virtio_mem.pagesize;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        nvdimmPath = mem->source.nvdimm.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        nvdimmPath = mem->source.virtio_pmem.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    needHugepage = !!pagesize;
    useHugepage = !!pagesize;

    if (pagesize == 0) {
        virDomainHugePage *master_hugepage = NULL;
        virDomainHugePage *hugepage = NULL;
        bool thisHugepage = false;
        size_t i;

        /* Find the huge page size we want to use */
        for (i = 0; i < def->mem.nhugepages; i++) {
            hugepage = &def->mem.hugepages[i];

            if (!hugepage->nodemask) {
                master_hugepage = hugepage;
                continue;
            }

            /* just find the master hugepage in case we don't use NUMA */
            if (mem->targetNode < 0)
                continue;

            if (virBitmapGetBit(hugepage->nodemask, mem->targetNode,
                                &thisHugepage) < 0) {
                /* Ignore this error. It's not an error after all. Well,
                 * the nodemask for this <page/> can contain lower NUMA
                 * nodes than we are querying in here. */
                continue;
            }

            if (thisHugepage) {
                /* Hooray, we've found the page size */
                needHugepage = true;
                break;
            }
        }

        if (i == def->mem.nhugepages) {
            /* We have not found specific huge page to be used with this
             * NUMA node. Use the generic setting then (<page/> without any
             * @nodemask) if possible. */
            hugepage = master_hugepage;
        }

        if (hugepage) {
            pagesize = hugepage->size;
            useHugepage = true;
        }
    }

    if (pagesize == system_page_size) {
        /* However, if user specified to use "huge" page
         * of regular system page size, it's as if they
         * hasn't specified any huge pages at all. */
        pagesize = 0;
        needHugepage = false;
        useHugepage = false;
    } else if (useHugepage && pagesize == 0) {
        if (qemuBuildMemoryGetDefaultPagesize(cfg, &pagesize) < 0)
            return -1;
    }

    if (def->mem.allocation == VIR_DOMAIN_MEMORY_ALLOCATION_IMMEDIATE)
        prealloc = true;

    /* If the NVDIMM is a real device then there's nothing to prealloc.
     * If anything, we would be only wearing off the device.
     * Similarly, virtio-pmem-pci doesn't need prealloc either. */
    if (nvdimmPath) {
        if (mem->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
            !mem->source.nvdimm.pmem) {
            prealloc = true;
        }
    } else if (useHugepage) {
        prealloc = true;
    }

    if (pagesizeRet)
        *pagesizeRet = pagesize;
    if (needHugepageRet)
        *needHugepageRet = needHugepage;
    if (useHugepageRet)
        *useHugepageRet = useHugepage;
    if (preallocRet)
        *preallocRet = prealloc;

    return 0;
}


/**
 * qemuBuildMemoryBackendProps:
 * @backendProps: [out] constructed object
 * @alias: alias of the device
 * @cfg: qemu driver config object
 * @priv: pointer to domain private object
 * @def: domain definition object
 * @mem: memory definition object
 * @force: forcibly use one of the backends
 * @nodemaskRet: [out] bitmap where the memory should be allocated
 *
 * Creates a configuration object that represents memory backend of given guest
 * NUMA node (domain @def and @mem). Use @priv->autoNodeset to fine tune the
 * placement of the memory on the host NUMA nodes.
 *
 * By default, if no memory-backend-* object is necessary to fulfil the guest
 * configuration value of 1 is returned. This behaviour can be suppressed by
 * setting @force to true in which case 0 would be returned.
 *
 * Then, if one of the three memory-backend-* should be used, the @priv->qemuCaps
 * is consulted to check if qemu does support it.
 *
 * Returns: 0 on success,
 *          1 on success and if there's no need to use memory-backend-*
 *         -1 on error.
 */
int
qemuBuildMemoryBackendProps(virJSONValue **backendProps,
                            const char *alias,
                            virQEMUDriverConfig *cfg,
                            qemuDomainObjPrivate *priv,
                            const virDomainDef *def,
                            const virDomainMemoryDef *mem,
                            bool force,
                            bool systemMemory,
                            virBitmap **nodemaskRet)
{
    const char *backendType = "memory-backend-file";
    virDomainNumatuneMemMode mode;
    virDomainMemoryAccess memAccess = mem->access;
    g_autofree char *memPath = NULL;
    bool prealloc = false;
    virBitmap *nodemask = NULL;
    int rc;
    g_autoptr(virJSONValue) props = NULL;
    bool nodeSpecified = virDomainNumatuneNodeSpecified(def->numa, mem->targetNode);
    unsigned long long pagesize = 0;
    bool needHugepage = false;
    bool useHugepage = false;
    bool hasSourceNodes = false;
    const char *nvdimmPath = NULL;
    int discard = mem->discard;
    bool disableCanonicalPath = false;

    /* Disabling canonical path is required for migration compatibility of
     * system memory objects, see below */

    /* The difference between @needHugepage and @useHugepage is that the latter
     * is true whenever huge page is defined for the current memory cell.
     * Either directly, or transitively via global domain huge pages. The
     * former is true whenever "memory-backend-file" must be used to satisfy
     * @useHugepage. */

    *backendProps = NULL;

    if (mem->targetNode >= 0) {
        if (memAccess == VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
            memAccess = virDomainNumaGetNodeMemoryAccessMode(def->numa, mem->targetNode);

        if (discard == VIR_TRISTATE_BOOL_ABSENT)
            discard = virDomainNumaGetNodeDiscard(def->numa, mem->targetNode);
    }

    if (memAccess == VIR_DOMAIN_MEMORY_ACCESS_DEFAULT)
        memAccess = def->mem.access;

    if (discard == VIR_TRISTATE_BOOL_ABSENT)
        discard = def->mem.discard;

    if (virDomainNumatuneGetMode(def->numa, mem->targetNode, &mode) < 0 &&
        virDomainNumatuneGetMode(def->numa, -1, &mode) < 0)
        mode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;

    if (qemuBuildMemoryGetPagesize(cfg, def, mem, &pagesize,
                                   &needHugepage, &useHugepage, &prealloc) < 0)
        return -1;

    props = virJSONValueNewObject();

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        nodemask = mem->source.dimm.nodes;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        nodemask = mem->source.virtio_mem.nodes;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        nodemask = mem->source.sgx_epc.nodes;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        nvdimmPath = mem->source.nvdimm.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        nvdimmPath = mem->source.virtio_pmem.path;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    hasSourceNodes = !!nodemask;

    if (mem->model == VIR_DOMAIN_MEMORY_MODEL_SGX_EPC) {
        backendType = "memory-backend-epc";
        if (!priv->memPrealloc)
            prealloc = true;

    } else if (!nvdimmPath &&
               def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_MEMFD) {
        backendType = "memory-backend-memfd";

        if (useHugepage &&
            (virJSONValueObjectAdd(&props, "b:hugetlb", useHugepage, NULL) < 0 ||
             virJSONValueObjectAdd(&props, "U:hugetlbsize", pagesize << 10, NULL) < 0)) {
            return -1;
        }

        if (qemuBuildMemoryBackendPropsShare(props, memAccess) < 0)
            return -1;

        if (systemMemory)
            disableCanonicalPath = true;
    } else if (useHugepage || nvdimmPath || memAccess ||
               def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_FILE) {

        if (nvdimmPath) {
            memPath = g_strdup(nvdimmPath);
        } else if (useHugepage) {
            if (qemuGetDomainHupageMemPath(priv->driver, def, pagesize, &memPath) < 0)
                return -1;
        } else {
            /* We can have both pagesize and mem source. If that's the case,
             * prefer hugepages as those are more specific. */
            if (qemuGetMemoryBackingPath(priv->driver, def, mem->info.alias, &memPath) < 0)
                return -1;
        }

        if (virJSONValueObjectAdd(&props,
                                  "s:mem-path", memPath,
                                  NULL) < 0)
            return -1;

        if (!nvdimmPath &&
            virJSONValueObjectAdd(&props,
                                  "T:discard-data", discard,
                                  NULL) < 0) {
            return -1;
        }

        if (qemuBuildMemoryBackendPropsShare(props, memAccess) < 0)
            return -1;

        if (systemMemory)
            disableCanonicalPath = true;

    } else {
        backendType = "memory-backend-ram";
    }

    /* This is a terrible hack, but unfortunately there is no better way.
     * The replacement for '-m X' argument is not simple '-machine
     * memory-backend' and '-object memory-backend-*,size=X' (which was the
     * idea). This is because of create_default_memdev() in QEMU sets
     * 'x-use-canonical-path-for-ramblock-id' attribute to false and is
     * documented in QEMU in qemu-options.hx under 'memory-backend'. Note
     * that QEMU considers 'x-use-canonical-path-for-ramblock-id' stable
     * and supported despite the 'x-' prefix.
     * See QEMU commit 8db0b20415c129cf5e577a593a4a0372d90b7cc9.
     */
    if (disableCanonicalPath &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_X_USE_CANONICAL_PATH_FOR_RAMBLOCK_ID) &&
        virJSONValueObjectAdd(&props, "b:x-use-canonical-path-for-ramblock-id", false, NULL) < 0)
        return -1;

    if (mem->model == VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MEM_PCI_PREALLOC)) {
            /* Explicitly disable prealloc for virtio-mem if it isn't supported.
             * Warn users if their config would result in prealloc. */
            if (priv->memPrealloc || prealloc) {
                VIR_WARN("Memory preallocation is unsupported for virtio-mem memory devices");
            }

            if (priv->memPrealloc &&
                virJSONValueObjectAppendBoolean(props, "prealloc", 0) < 0)
                return -1;
        }

        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MEMORY_BACKEND_RESERVE) &&
            virJSONValueObjectAppendBoolean(props, "reserve", 0) < 0)
            return -1;
    } else {
        if (!priv->memPrealloc &&
            virJSONValueObjectAdd(&props,
                                  "B:prealloc", prealloc,
                                  "p:prealloc-threads", def->mem.allocation_threads,
                                  NULL) < 0)
            return -1;
    }

    if (virJSONValueObjectAdd(&props, "U:size", mem->size * 1024, NULL) < 0)
        return -1;

    if (mem->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        virJSONValueObjectAdd(&props, "P:align",
                              mem->source.nvdimm.alignsize * 1024, NULL) < 0)
        return -1;

    if (mem->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        mem->source.nvdimm.pmem) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE_PMEM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("nvdimm pmem property is not available with this QEMU binary"));
            return -1;
        }
        if (virJSONValueObjectAdd(&props, "b:pmem", true, NULL) < 0)
            return -1;
    }

    if (!hasSourceNodes &&
        virDomainNumatuneMaybeGetNodeset(def->numa, priv->autoNodeset,
                                         &nodemask, mem->targetNode) < 0) {
        return -1;
    }

    if (nodemask) {
        /* Make sure the requested nodeset is sensible */
        if (!virNumaNodesetIsAvailable(nodemask))
            return -1;

        /* If mode is "restrictive", we should only use cgroups setting allowed memory
         * nodes, and skip passing the host-nodes and policy parameters to QEMU command
         * line which means we will use system default memory policy. */
        if (mode != VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) {
            if (virJSONValueObjectAdd(&props,
                                      "m:host-nodes", nodemask,
                                      "S:policy", qemuNumaPolicyTypeToString(mode),
                                      NULL) < 0)
                return -1;
        }

        if (nodemaskRet)
            *nodemaskRet = nodemask;
    }

    /* If none of the following is requested... */
    if (!needHugepage && !hasSourceNodes && !nodeSpecified &&
        !nvdimmPath &&
        memAccess == VIR_DOMAIN_MEMORY_ACCESS_DEFAULT &&
        def->mem.source != VIR_DOMAIN_MEMORY_SOURCE_FILE &&
        def->mem.source != VIR_DOMAIN_MEMORY_SOURCE_MEMFD &&
        !force) {
        /* report back that using the new backend is not necessary
         * to achieve the desired configuration */
        rc = 1;
    } else {
        /* otherwise check the required capability */
        if (STREQ(backendType, "memory-backend-memfd") &&
            !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_OBJECT_MEMORY_MEMFD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the memory-backend-memfd object"));
            return -1;
        }

        rc = 0;
    }

    if (virJSONValueObjectPrependString(props, "id", alias) < 0 ||
        virJSONValueObjectPrependString(props, "qom-type", backendType) < 0)
        return -1;

    *backendProps = g_steal_pointer(&props);

    return rc;
}


static int
qemuBuildMemoryCellBackendProps(virDomainDef *def,
                                virQEMUDriverConfig *cfg,
                                size_t cell,
                                qemuDomainObjPrivate *priv,
                                virJSONValue **props,
                                virBitmap **nodemask)
{
    g_autofree char *alias = NULL;
    virDomainMemoryDef mem = { 0 };
    unsigned long long memsize = virDomainNumaGetNodeMemorySize(def->numa,
                                                                cell);

    alias = g_strdup_printf("ram-node%zu", cell);

    mem.size = memsize;
    mem.targetNode = cell;
    mem.info.alias = alias;

    return qemuBuildMemoryBackendProps(props, alias, cfg, priv, def,
                                       &mem, false, false, nodemask);
}


static int
qemuBuildMemoryDimmBackendStr(virCommand *cmd,
                              virDomainMemoryDef *mem,
                              virDomainDef *def,
                              virQEMUDriverConfig *cfg,
                              qemuDomainObjPrivate *priv)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autoptr(virJSONValue) tcProps = NULL;
    virBitmap *nodemask = NULL;
    g_autofree char *alias = NULL;

    if (!mem->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("memory device alias is not assigned"));
        return -1;
    }

    alias = g_strdup_printf("mem%s", mem->info.alias);

    if (qemuBuildMemoryBackendProps(&props, alias, cfg, priv,
                                    def, mem, true, false, &nodemask) < 0)
        return -1;

    if (qemuBuildThreadContextProps(&tcProps, &props, def, priv, nodemask) < 0)
        return -1;

    if (tcProps &&
        qemuBuildObjectCommandlineFromJSON(cmd, tcProps,
                                           priv->qemuCaps) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


virJSONValue *
qemuBuildMemoryDeviceProps(virQEMUDriverConfig *cfg,
                           qemuDomainObjPrivate *priv,
                           const virDomainDef *def,
                           const virDomainMemoryDef *mem)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *device = NULL;
    g_autofree char *uuidstr = NULL;
    virTristateBool unarmed = VIR_TRISTATE_BOOL_ABSENT;
    g_autofree char *memdev = NULL;
    unsigned long long labelsize = 0;
    unsigned long long blocksize = 0;
    unsigned long long requestedsize = 0;
    unsigned long long address = 0;
    bool prealloc = false;

    if (!mem->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing alias for memory device"));
        return NULL;
    }

    memdev = g_strdup_printf("mem%s", mem->info.alias);

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        device = "pc-dimm";
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        device = "nvdimm";
        if (mem->target.nvdimm.readonly)
            unarmed = VIR_TRISTATE_BOOL_YES;

        if (mem->target.nvdimm.uuid) {
            uuidstr = g_new0(char, VIR_UUID_STRING_BUFLEN);
            virUUIDFormat(mem->target.nvdimm.uuid, uuidstr);
        }

        labelsize = mem->target.nvdimm.labelsize;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        device = "virtio-pmem-pci";
        address = mem->target.virtio_pmem.address;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        device = "virtio-mem-pci";

        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MEM_PCI_PREALLOC) &&
            qemuBuildMemoryGetPagesize(cfg, def, mem, NULL, NULL, NULL, &prealloc) < 0)
            return NULL;

        blocksize = mem->target.virtio_mem.blocksize;
        requestedsize = mem->target.virtio_mem.requestedsize;
        address = mem->target.virtio_mem.address;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainMemoryModel, mem->model);
        return NULL;
        break;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", device,
                              "k:node", mem->targetNode,
                              "P:label-size", labelsize * 1024,
                              "P:block-size", blocksize * 1024,
                              "P:requested-size", requestedsize * 1024,
                              "S:uuid", uuidstr,
                              "T:unarmed", unarmed,
                              "s:memdev", memdev,
                              "B:prealloc", prealloc,
                              "P:memaddr", address,
                              "s:id", mem->info.alias,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &mem->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


int
qemuBuildThreadContextProps(virJSONValue **tcProps,
                            virJSONValue **memProps,
                            const virDomainDef *def,
                            qemuDomainObjPrivate *priv,
                            virBitmap *nodemask)
{
    g_autoptr(virJSONValue) props = NULL;
    virBitmap *emulatorpin = NULL;
    g_autoptr(virBitmap) emulatorNodes = NULL;
    g_autofree char *tcAlias = NULL;
    const char *memalias = NULL;
    bool prealloc = false;

    *tcProps = NULL;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_THREAD_CONTEXT))
        return 0;

    if (!nodemask)
        return 0;

    if (virJSONValueObjectGetBoolean(*memProps, "prealloc", &prealloc) < 0 ||
        !prealloc)
        return 0;

    emulatorpin = qemuDomainEvaluateCPUMask(def,
                                            def->cputune.emulatorpin,
                                            priv->autoNodeset);

    if (emulatorpin && virNumaIsAvailable()) {
        if (virNumaCPUSetToNodeset(emulatorpin, &emulatorNodes) < 0)
            return -1;

        virBitmapIntersect(emulatorNodes, nodemask);

        if (virBitmapIsAllClear(emulatorNodes))
            return 0;

        nodemask = emulatorNodes;
    }

    memalias = virJSONValueObjectGetString(*memProps, "id");
    if (!memalias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("memory device alias is not assigned"));
        return -1;
    }

    tcAlias = g_strdup_printf("tc-%s", memalias);

    if (virJSONValueObjectAdd(&props,
                              "s:qom-type", "thread-context",
                              "s:id", tcAlias,
                              "m:node-affinity", nodemask,
                              NULL) < 0)
        return -1;

    if (virJSONValueObjectAdd(memProps,
                              "s:prealloc-context", tcAlias,
                              NULL) < 0)
        return -1;

    priv->threadContextAliases = g_slist_prepend(priv->threadContextAliases,
                                                 g_steal_pointer(&tcAlias));

    *tcProps = g_steal_pointer(&props);
    return 0;
}


static char *
qemuBuildLegacyNicStr(virDomainNetDef *net)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    const char *netmodel = virDomainNetGetModelString(net);

    return g_strdup_printf("nic,macaddr=%s,netdev=host%s%s%s%s%s",
                           virMacAddrFormat(&net->mac, macaddr),
                           net->info.alias, netmodel ? ",model=" : "",
                           NULLSTR_EMPTY(netmodel),
                           (net->info.alias ? ",id=" : ""),
                           NULLSTR_EMPTY(net->info.alias));
}


virJSONValue *
qemuBuildNicDevProps(virDomainDef *def,
                     virDomainNetDef *net,
                     virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    g_autofree char *netdev = g_strdup_printf("host%s", net->info.alias);

    if (virDomainNetIsVirtioModel(net)) {
        const char *tx = NULL;
        virTristateSwitch mq = VIR_TRISTATE_SWITCH_ABSENT;
        unsigned long long vectors = 0;
        virTristateSwitch failover = VIR_TRISTATE_SWITCH_ABSENT;

        switch (net->driver.virtio.txmode) {
        case VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD:
            tx = "bh";
            break;

        case VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER:
            tx = "timer";
            break;

        case VIR_DOMAIN_NET_VIRTIO_TX_MODE_DEFAULT:
            break;

        case VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST:
        default:
            /* this should never happen, if it does, we need
             * to add another case to this switch.
             */
            virReportEnumRangeError(virDomainNetVirtioTxModeType,
                                    net->driver.virtio.txmode);
            return NULL;
        }

        if (net->driver.virtio.queues > 1) {
            if (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
                /* ccw provides a one to one relation of fds to queues and
                 * does not support the vectors option
                 */
                mq = VIR_TRISTATE_SWITCH_ON;
            } else {
                /* As advised at https://www.linux-kvm.org/page/Multiqueue
                 * we should add vectors=2*N+2 where N is the vhostfdSize
                 */
                mq = VIR_TRISTATE_SWITCH_ON;
                vectors = 2 * net->driver.virtio.queues + 2;
            }
        }

        if (net->teaming && net->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_PERSISTENT)
            failover = VIR_TRISTATE_SWITCH_ON;

        if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_NET, net, qemuCaps)))
            return NULL;

        if (virJSONValueObjectAdd(&props,
                                  "S:tx", tx,
                                  "T:ioeventfd", net->driver.virtio.ioeventfd,
                                  "T:event_idx", net->driver.virtio.event_idx,
                                  "T:csum", net->driver.virtio.host.csum,
                                  "T:gso", net->driver.virtio.host.gso,
                                  "T:host_tso4", net->driver.virtio.host.tso4,
                                  "T:host_tso6", net->driver.virtio.host.tso6,
                                  "T:host_ecn", net->driver.virtio.host.ecn,
                                  "T:host_ufo", net->driver.virtio.host.ufo,
                                  "T:mrg_rxbuf", net->driver.virtio.host.mrg_rxbuf,
                                  "T:guest_csum", net->driver.virtio.guest.csum,
                                  "T:guest_tso4", net->driver.virtio.guest.tso4,
                                  "T:guest_tso6", net->driver.virtio.guest.tso6,
                                  "T:guest_ecn", net->driver.virtio.guest.ecn,
                                  "T:guest_ufo", net->driver.virtio.guest.ufo,
                                  "T:mq", mq,
                                  "P:vectors", vectors,
                                  "p:rx_queue_size", net->driver.virtio.rx_queue_size,
                                  "p:tx_queue_size", net->driver.virtio.tx_queue_size,
                                  "T:rss", net->driver.virtio.rss,
                                  "T:hash", net->driver.virtio.rss_hash_report,
                                  "p:host_mtu", net->mtu,
                                  "T:failover", failover,
                                  NULL) < 0)
            return NULL;
    } else {
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", virDomainNetGetModelString(net),
                                  NULL) < 0)
            return NULL;
    }

    virMacAddrFormat(&net->mac, macaddr);

    if (virJSONValueObjectAdd(&props,
                              "s:netdev", netdev,
                              "s:id", net->info.alias,
                              "s:mac", macaddr,
                              "p:bootindex", net->info.effectiveBootIndex,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &net->info) < 0)
        return NULL;

    if (qemuBuildRomProps(props, &net->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static char *
qemuBuildHostNetSocketAddr(virDomainNetDef *net)
{
    return g_strdup_printf("%s:%d",
                           NULLSTR_EMPTY(net->data.socket.address),
                           net->data.socket.port);
}


virJSONValue *
qemuBuildHostNetProps(virDomainObj *vm,
                      virDomainNetDef *net)
{
    virDomainNetType netType = virDomainNetGetActualType(net);
    size_t i;
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    g_autoptr(virJSONValue) netprops = NULL;
    g_autofree char *alias = g_strdup_printf("host%s", net->info.alias);

    if (net->script && netType != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("scripts are not supported on interfaces of type %1$s"),
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
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET: {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        /* for one tapfd/vhostfd 'fd=' shall be used, for more use 'fds=' */
        const char *tapfd_field = "s:fd";
        g_autofree char *tapfd_arg = NULL;
        const char *vhostfd_field = "S:vhostfd";
        g_autofree char *vhostfd_arg = NULL;
        bool vhost = false;
        size_t nfds;
        GSList *n;

        if (netpriv->tapfds) {
            nfds = 0;
            for (n = netpriv->tapfds; n; n = n->next) {
                virBufferAsprintf(&buf, "%s:", qemuFDPassDirectGetPath(n->data));
                nfds++;
            }

            if (nfds > 1)
                tapfd_field = "s:fds";
        }

        virBufferTrim(&buf, ":");
        tapfd_arg = virBufferContentAndReset(&buf);

        if (netpriv->vhostfds) {
            vhost = true;

            nfds = 0;
            for (n = netpriv->vhostfds; n; n = n->next) {
                virBufferAsprintf(&buf, "%s:", qemuFDPassDirectGetPath(n->data));
                nfds++;
            }

            if (nfds > 1)
                vhostfd_field = "s:vhostfds";
        }

        virBufferTrim(&buf, ":");
        vhostfd_arg = virBufferContentAndReset(&buf);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "tap",
                                  tapfd_field, tapfd_arg,
                                  "B:vhost", vhost,
                                  vhostfd_field, vhostfd_arg,
                                  NULL) < 0)
            return NULL;


        if (net->tune.sndbuf_specified &&
            virJSONValueObjectAppendNumberUlong(netprops, "sndbuf", net->tune.sndbuf) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT: {
        g_autofree char *addr = qemuBuildHostNetSocketAddr(net);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "socket",
                                  "s:connect", addr,
                                  NULL) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_SERVER: {
        g_autofree char *addr = qemuBuildHostNetSocketAddr(net);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "socket",
                                  "s:listen", addr,
                                  NULL) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_MCAST: {
        g_autofree char *addr = qemuBuildHostNetSocketAddr(net);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "socket",
                                  "s:mcast", addr,
                                  NULL) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_UDP: {
        g_autofree char *addr = qemuBuildHostNetSocketAddr(net);
        g_autofree char *localaddr = g_strdup_printf("%s:%d",
                                                     net->data.socket.localaddr,
                                                     net->data.socket.localport);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "socket",
                                  "s:udp", addr,
                                  "s:localaddr", localaddr,
                                  NULL) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
        if (net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {
            if (qemuPasstAddNetProps(vm, net, &netprops) < 0)
                return NULL;
        } else if (netpriv->slirpfd) {
            if (virJSONValueObjectAdd(&netprops,
                                      "s:type", "socket",
                                      "s:fd", qemuFDPassDirectGetPath(netpriv->slirpfd),
                                      NULL) < 0)
                return NULL;
        } else {
            if (virJSONValueObjectAdd(&netprops, "s:type", "user", NULL) < 0)
                return NULL;

            for (i = 0; i < net->guestIP.nips; i++) {
                const virNetDevIPAddr *ip = net->guestIP.ips[i];
                g_autofree char *addr = NULL;

                if (!(addr = virSocketAddrFormat(&ip->address)))
                    return NULL;

                if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
                    g_autofree char *ipv4netaddr = NULL;

                    if (ip->prefix)
                        ipv4netaddr = g_strdup_printf("%s/%u", addr, ip->prefix);
                    else
                        ipv4netaddr = g_strdup(addr);

                    if (virJSONValueObjectAppendString(netprops, "net", ipv4netaddr) < 0)
                        return NULL;
                } else if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6)) {
                    if (virJSONValueObjectAdd(&netprops,
                                              "s:ipv6-prefix", addr,
                                              "p:ipv6-prefixlen", ip->prefix,
                                              NULL) < 0)
                        return NULL;
                }
            }
        }
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        if (virJSONValueObjectAdd(&netprops, "s:type", "user", NULL) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER: {
        g_autofree char *charalias = g_strdup_printf("char%s", net->info.alias);

        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "vhost-user",
                                  "s:chardev", charalias,
                                  NULL) < 0)
            return NULL;

        if (net->driver.virtio.queues > 1 &&
            virJSONValueObjectAppendNumberUlong(netprops, "queues", net->driver.virtio.queues) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_VDPA:
        /* Caller will pass the fd to qemu with add-fd */
        if (virJSONValueObjectAdd(&netprops,
                                  "s:type", "vhost-vdpa",
                                  "s:vhostdev", qemuFDPassGetPath(netpriv->vdpafd),
                                  NULL) < 0)
            return NULL;

        if (net->driver.virtio.queues > 1 &&
            virJSONValueObjectAppendNumberUlong(netprops, "queues", net->driver.virtio.queues) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        /* Should have been handled earlier via PCI/USB hotplug code. */
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("network device type '%1$s' is not supported by this hypervisor"),
                       virDomainNetTypeToString(netType));
        return NULL;

    case VIR_DOMAIN_NET_TYPE_LAST:
        virReportEnumRangeError(virDomainNetType, netType);
        return NULL;
    }

    if (virJSONValueObjectAdd(&netprops, "s:id", alias, NULL) < 0)
        return NULL;

    return g_steal_pointer(&netprops);
}


virJSONValue *
qemuBuildWatchdogDevProps(const virDomainDef *def,
                          virDomainWatchdogDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", virDomainWatchdogModelTypeToString(dev->model),
                              "s:id", dev->info.alias,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildWatchdogCommandLine(virCommand *cmd,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    virDomainWatchdogDef *watchdog = NULL;
    const char *action;
    int actualAction;
    ssize_t i = 0;
    bool itco_pin_strap = false;

    if (def->nwatchdogs == 0)
        return 0;

    for (i = 0; i < def->nwatchdogs; i++) {
        g_autoptr(virJSONValue) props = NULL;

        watchdog = def->watchdogs[i];

        /* iTCO is part of q35 and cannot be added */
        if (watchdog->model == VIR_DOMAIN_WATCHDOG_MODEL_ITCO) {
            itco_pin_strap = true;
            continue;
        }

        if (qemuCommandAddExtDevice(cmd, &watchdog->info, def, qemuCaps) < 0)
            return -1;

        if (!(props = qemuBuildWatchdogDevProps(def, watchdog)))
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps))
            return -1;
    }

    if (itco_pin_strap)
        virCommandAddArgList(cmd, "-global", "ICH9-LPC.noreboot=off", NULL);

    /* qemu doesn't have a 'dump' action; we tell qemu to 'pause', then
       libvirt listens for the watchdog event, and we perform the dump
       ourselves. so convert 'dump' to 'pause' for the qemu cli. The
       validator already checked that all watchdogs have the same action.
    */
    actualAction = watchdog->action;
    if (watchdog->action == VIR_DOMAIN_WATCHDOG_ACTION_DUMP)
        actualAction = VIR_DOMAIN_WATCHDOG_ACTION_PAUSE;

    action = virDomainWatchdogActionTypeToString(actualAction);
    if (!action) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid watchdog action"));
        return -1;
    }
    virCommandAddArgList(cmd, "-watchdog-action", action, NULL);

    return 0;
}


static int
qemuBuildMemballoonCommandLine(virCommand *cmd,
                               const virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (!virDomainDefHasMemballoon(def))
        return 0;

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_MEMBALLOON,
                                          def->memballoon, qemuCaps)))
        return -1;

    if (virJSONValueObjectAdd(&props,
                              "s:id", def->memballoon->info.alias,
                              "T:deflate-on-oom", def->memballoon->autodeflate,
                              "T:free-page-reporting", def->memballoon->free_page_reporting,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceAddressProps(props, def, &def->memballoon->info) < 0)
        return -1;

    if (qemuCommandAddExtDevice(cmd, &def->memballoon->info, def, qemuCaps) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static char *
qemuBuildNVRAMDevStr(virDomainNVRAMDef *dev)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "spapr-nvram.reg=0x%llx",
                      dev->info.addr.spaprvio.reg);

    return virBufferContentAndReset(&buf);
}


static int
qemuBuildNVRAMCommandLine(virCommand *cmd,
                          const virDomainDef *def)
{
    g_autofree char *optstr = NULL;

    if (!def->nvram)
        return 0;

    virCommandAddArg(cmd, "-global");
    optstr = qemuBuildNVRAMDevStr(def->nvram);
    if (!optstr)
        return -1;

    virCommandAddArg(cmd, optstr);

    return 0;
}


virJSONValue *
qemuBuildInputVirtioDevProps(const virDomainDef *def,
                             virDomainInputDef *dev,
                             virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *evdev = NULL;

    switch ((virDomainInputType)dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        break;
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainInputType, dev->type);
        return NULL;
    }

    if (dev->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH)
        evdev = dev->source.evdev;

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_INPUT, dev, qemuCaps)))
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:id", dev->info.alias,
                              "S:evdev", evdev,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildInputUSBDevProps(const virDomainDef *def,
                          virDomainInputDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *driver = NULL;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
        driver = "usb-mouse";
        break;
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
        driver = "usb-tablet";
        break;
    case VIR_DOMAIN_INPUT_TYPE_KBD:
        driver = "usb-kbd";
        break;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", driver,
                              "s:id", dev->info.alias,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBuildInputEvdevProps(virDomainInputDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;

    if (qemuMonitorCreateObjectProps(&props, "input-linux", dev->info.alias,
                                     "s:evdev", dev->source.evdev,
                                     "T:repeat", dev->source.repeat,
                                     NULL) < 0)
        return NULL;

    if (dev->source.grab == VIR_DOMAIN_INPUT_SOURCE_GRAB_ALL &&
        virJSONValueObjectAdd(&props, "b:grab_all", true, NULL) < 0)
        return NULL;

    if (dev->source.grabToggle != VIR_DOMAIN_INPUT_SOURCE_GRAB_TOGGLE_DEFAULT &&
        virJSONValueObjectAdd(&props, "s:grab-toggle",
                              virDomainInputSourceGrabToggleTypeToString(dev->source.grabToggle),
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildInputCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDef *input = def->inputs[i];

        if (qemuCommandAddExtDevice(cmd, &input->info, def, qemuCaps) < 0)
            return -1;

        if (input->type == VIR_DOMAIN_INPUT_TYPE_EVDEV) {
            g_autoptr(virJSONValue) props = NULL;

            if (!(props = qemuBuildInputEvdevProps(input)))
                return -1;

            if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
                return -1;
        } else {
            g_autoptr(virJSONValue) props = NULL;

            switch ((virDomainInputBus) input->bus) {
            case VIR_DOMAIN_INPUT_BUS_USB:
                if (!(props = qemuBuildInputUSBDevProps(def, input)))
                    return -1;
                break;

            case VIR_DOMAIN_INPUT_BUS_VIRTIO:
                if (!(props = qemuBuildInputVirtioDevProps(def, input, qemuCaps)))
                    return -1;

            case VIR_DOMAIN_INPUT_BUS_DEFAULT:
            case VIR_DOMAIN_INPUT_BUS_PS2:
            case VIR_DOMAIN_INPUT_BUS_XEN:
            case VIR_DOMAIN_INPUT_BUS_PARALLELS:
            case VIR_DOMAIN_INPUT_BUS_NONE:
            case VIR_DOMAIN_INPUT_BUS_LAST:
                break;
            }

            if (props &&
                qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
                return -1;
        }
    }

    return 0;
}

static char *
qemuGetAudioIDString(const virDomainDef *def, int id)
{
    virDomainAudioDef *audio = virDomainDefFindAudioByID(def, id);
    if (!audio) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find audio backend for sound device"));
        return NULL;
    }
    return g_strdup_printf("audio%d", audio->id);
}

static int
qemuBuildSoundDevCmd(virCommand *cmd,
                     const virDomainDef *def,
                     virDomainSoundDef *sound,
                     virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *model = NULL;
    g_autofree char *audioid = NULL;
    virTristateBool multichannel = VIR_TRISTATE_BOOL_ABSENT;

    switch (sound->model) {
    case VIR_DOMAIN_SOUND_MODEL_ES1370:
        model = "ES1370";
        break;
    case VIR_DOMAIN_SOUND_MODEL_AC97:
        model = "AC97";
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH6:
        model = "intel-hda";
        break;
    case VIR_DOMAIN_SOUND_MODEL_USB:
        model = "usb-audio";
        multichannel = sound->multichannel;
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH9:
        model = "ich9-intel-hda";
        break;
    case VIR_DOMAIN_SOUND_MODEL_SB16:
        model = "sb16";
        break;
    case VIR_DOMAIN_SOUND_MODEL_PCSPK: /* pc-speaker is handled separately */
    case VIR_DOMAIN_SOUND_MODEL_ICH7:
    case VIR_DOMAIN_SOUND_MODEL_LAST:
        return -1;
    }

    if (!virDomainSoundModelSupportsCodecs(sound)) {
        if (!(audioid = qemuGetAudioIDString(def, sound->audioId)))
            return -1;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", model,
                              "s:id", sound->info.alias,
                              "S:audiodev", audioid,
                              "T:multi", multichannel,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceAddressProps(props, def, &sound->info) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildSoundCodecCmd(virCommand *cmd,
                       const virDomainDef *def,
                       virDomainSoundDef *sound,
                       virDomainSoundCodecDef *codec,
                       virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *audioid = NULL;
    g_autofree char *alias = g_strdup_printf("%s-codec%d", sound->info.alias, codec->cad);
    g_autofree char *bus = g_strdup_printf("%s.0", sound->info.alias);

    if (!(audioid = qemuGetAudioIDString(def, sound->audioId)))
        return -1;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", qemuSoundCodecTypeToString(codec->type),
                              "s:id", alias,
                              "s:bus", bus,
                              "i:cad", codec->cad,
                              "S:audiodev", audioid,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildSoundCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    size_t i, j;

    for (i = 0; i < def->nsounds; i++) {
        virDomainSoundDef *sound = def->sounds[i];

        /* Sadly pcspk device doesn't use -device syntax. And it
         * was handled already in qemuBuildMachineCommandLine().
         */
        if (sound->model == VIR_DOMAIN_SOUND_MODEL_PCSPK)
            continue;

        if (qemuCommandAddExtDevice(cmd, &sound->info, def, qemuCaps) < 0)
            return -1;

        if (qemuBuildSoundDevCmd(cmd, def, sound, qemuCaps) < 0)
            return -1;

        if (virDomainSoundModelSupportsCodecs(sound)) {
            for (j = 0; j < sound->ncodecs; j++) {
                if (qemuBuildSoundCodecCmd(cmd, def, sound, sound->codecs[j],
                                           qemuCaps) < 0)
                    return -1;
            }

            if (j == 0) {
                virDomainSoundCodecDef codec = { VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX, 0 };

                if (qemuBuildSoundCodecCmd(cmd, def, sound, &codec, qemuCaps) < 0)
                    return -1;
            }
        }
    }
    return 0;
}


static int
qemuBuildDeviceVideoCmd(virCommand *cmd,
                        const virDomainDef *def,
                        virDomainVideoDef *video,
                        virQEMUCaps *qemuCaps)
{
    const char *model = NULL;
    virTristateBool virgl = VIR_TRISTATE_BOOL_ABSENT;
    bool virtio = false;
    bool virtioBusSuffix = false;
    g_autoptr(virJSONValue) props = NULL;
    unsigned int max_outputs = 0;

    if (!(model = qemuDeviceVideoGetModel(qemuCaps, video, &virtio, &virtioBusSuffix)))
        return -1;

    if (virtio) {
        if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_VIDEO, video, qemuCaps)))
            return -1;
    } else {
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", model,
                                  NULL) < 0)
            return -1;
    }

    if (video->backend != VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER &&
        video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
        if (video->accel &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_VIRGL)) {
            virgl = video->accel->accel3d;
        }
    }

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL ||
        video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO)
        max_outputs = video->heads;

    if (virJSONValueObjectAdd(&props,
                              "s:id", video->info.alias,
                              "T:virgl", virgl,
                              "p:max_outputs", max_outputs,
                              NULL) < 0)
        return -1;

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (virJSONValueObjectAdd(&props,
                                  "p:ram_size", video->ram * 1024,
                                  "p:vram_size", video->vram * 1024,
                                  NULL) < 0)
            return -1;

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_QXL_VRAM64)) {
            if (virJSONValueObjectAdd(&props,
                                      "u:vram64_size_mb", video->vram64 / 1024,
                                      NULL) < 0)
                return -1;
        }

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_QXL_VGAMEM)) {
            if (virJSONValueObjectAdd(&props,
                                      "u:vgamem_mb", video->vgamem / 1024,
                                      NULL) < 0)
                return -1;
        }
    } else if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
        g_autofree char *alias = qemuDomainGetVhostUserChrAlias(video->info.alias);

        if (virJSONValueObjectAdd(&props,
                                  "s:chardev", alias,
                                  NULL) < 0)
            return -1;
    } else if ((video->type == VIR_DOMAIN_VIDEO_TYPE_VGA &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_VGA_VGAMEM)) ||
               (video->type == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_VMWARE_SVGA_VGAMEM))) {
        if (virJSONValueObjectAdd(&props,
                                  "p:vgamem_mb", video->vram / 1024,
                                  NULL) < 0)
            return -1;
    } else if (video->type == VIR_DOMAIN_VIDEO_TYPE_BOCHS) {
        if (virJSONValueObjectAdd(&props,
                                  "p:vgamem", video->vram * 1024,
                                  NULL) < 0)
            return -1;
    } else if (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
        if (virJSONValueObjectAdd(&props, "T:blob", video->blob, NULL) < 0)
            return -1;
    }

    if (video->res) {
        if (virJSONValueObjectAdd(&props,
                                  "p:xres", video->res->x,
                                  "p:yres", video->res->y,
                                  NULL) < 0)
            return -1;
    }

    if (qemuBuildDeviceAddressProps(props, def, &video->info) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildVideoCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          qemuDomainObjPrivate *priv)
{
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDef *video = def->videos[i];

        if (video->type == VIR_DOMAIN_VIDEO_TYPE_NONE)
            continue;

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            qemuDomainVideoPrivate *videopriv = QEMU_DOMAIN_VIDEO_PRIVATE(video);
            g_autoptr(virDomainChrSourceDef) chrsrc = virDomainChrSourceDefNew(priv->driver->xmlopt);
            g_autofree char *chrAlias = qemuDomainGetVhostUserChrAlias(video->info.alias);
            g_autofree char *name = g_strdup_printf("%s-vhost-user", video->info.alias);
            qemuDomainChrSourcePrivate *chrsrcpriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chrsrc);

            chrsrc->type = VIR_DOMAIN_CHR_TYPE_UNIX;
            chrsrcpriv->directfd = qemuFDPassDirectNew(name, &videopriv->vhost_user_fd);

            if (qemuBuildChardevCommand(cmd, chrsrc, chrAlias, priv->qemuCaps) < 0)
                return -1;
        }

        if (qemuCommandAddExtDevice(cmd, &def->videos[i]->info, def, priv->qemuCaps) < 0)
            return -1;

        if (qemuBuildDeviceVideoCmd(cmd, def, video, priv->qemuCaps) < 0)
            return -1;
    }

    return 0;
}


virJSONValue *
qemuBuildPCIHostdevDevProps(const virDomainDef *def,
                            virDomainHostdevDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainHostdevSubsysPCI *pcisrc = &dev->source.subsys.u.pci;
    virDomainNetTeamingInfo *teaming;
    g_autofree char *host = g_strdup_printf(VIR_PCI_DEVICE_ADDRESS_FMT,
                                            pcisrc->addr.domain,
                                            pcisrc->addr.bus,
                                            pcisrc->addr.slot,
                                            pcisrc->addr.function);
    const char *failover_pair_id = NULL;

    /* caller has to assign proper passthrough backend type */
    switch (pcisrc->backend) {
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
        break;

    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN:
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid PCI passthrough type '%1$s'"),
                       virDomainHostdevSubsysPCIBackendTypeToString(pcisrc->backend));
        return NULL;
    }

    if (dev->parentnet)
        teaming = dev->parentnet->teaming;
    else
        teaming = dev->teaming;

    if (teaming &&
        teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT &&
        teaming->persistent)
        failover_pair_id = teaming->persistent;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "vfio-pci",
                              "s:host", host,
                              "s:id", dev->info->alias,
                              "p:bootindex", dev->info->effectiveBootIndex,
                              "S:failover_pair_id", failover_pair_id,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, dev->info) < 0)
        return NULL;

    if (qemuBuildRomProps(props, dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildUSBHostdevDevProps(const virDomainDef *def,
                            virDomainHostdevDef *dev,
                            virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainHostdevSubsysUSB *usbsrc = &dev->source.subsys.u.usb;
    unsigned int hostbus = 0;
    unsigned int hostaddr = 0;
    g_autofree char *hostdevice = NULL;
    virTristateSwitch guestReset = VIR_TRISTATE_SWITCH_ABSENT;
    virTristateSwitch guestResetsAll = VIR_TRISTATE_SWITCH_ABSENT;

    if (!dev->missing) {
        if (usbsrc->bus == 0 && usbsrc->device == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("USB host device is missing bus/device information"));
            return NULL;
        }

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_HOST_HOSTDEVICE)) {
            hostdevice = g_strdup_printf("/dev/bus/usb/%03d/%03d",
                                         usbsrc->bus, usbsrc->device);
        } else {
            hostbus = usbsrc->bus;
            hostaddr = usbsrc->device;
        }
    }

    switch (usbsrc->guestReset) {
    case VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_OFF:
        guestReset = VIR_TRISTATE_SWITCH_OFF;
        break;
    case VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_UNINITIALIZED:
        guestReset = VIR_TRISTATE_SWITCH_ON;
        guestResetsAll = VIR_TRISTATE_SWITCH_OFF;
        break;
    case VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_ON:
        guestReset = VIR_TRISTATE_SWITCH_ON;
        guestResetsAll = VIR_TRISTATE_SWITCH_ON;
        break;
    case VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_DEFAULT:
    case VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_LAST:
        break;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "usb-host",
                              "S:hostdevice", hostdevice,
                              "p:hostbus", hostbus,
                              "p:hostaddr", hostaddr,
                              "s:id", dev->info->alias,
                              "p:bootindex",  dev->info->bootIndex,
                              "T:guest-reset", guestReset,
                              "T:guest-resets-all", guestResetsAll,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildHubDevCmd(virCommand *cmd,
                   const virDomainDef *def,
                   virDomainHubDef *dev,
                   virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "usb-hub",
                              "s:id", dev->info.alias,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildHubCommandLine(virCommand *cmd,
                        const virDomainDef *def,
                        virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nhubs; i++) {
        if (qemuBuildHubDevCmd(cmd, def, def->hubs[i], qemuCaps) < 0)
            return -1;
    }

    return 0;
}


virJSONValue *
qemuBuildSCSIVHostHostdevDevProps(const virDomainDef *def,
                                  virDomainHostdevDef *dev,
                                  virQEMUCaps *qemuCaps,
                                  char *vhostfdName)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &dev->source.subsys.u.scsi_host;

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_HOSTDEV, dev, qemuCaps)))
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:wwpn", hostsrc->wwpn,
                              "s:vhostfd", vhostfdName,
                              "s:id", dev->info->alias,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildSCSIHostdevDevProps(const virDomainDef *def,
                             virDomainHostdevDef *dev,
                             const char *backendAlias)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "scsi-generic",
                              "s:drive", backendAlias,
                              "s:id", dev->info->alias,
                              "p:bootindex", dev->info->bootIndex,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}

int
qemuOpenChrChardevUNIXSocket(const virDomainChrSourceDef *dev)
{
    struct sockaddr_un addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create UNIX socket"));
        goto error;
    }

    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, dev->data.nix.path) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("UNIX socket path '%1$s' too long"),
                       dev->data.nix.path);
        goto error;
    }

    if (unlink(dev->data.nix.path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to unlink %1$s"),
                             dev->data.nix.path);
        goto error;
    }

    if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        virReportSystemError(errno,
                             _("Unable to bind to UNIX socket path '%1$s'"),
                             dev->data.nix.path);
        goto error;
    }

    if (listen(fd, 1) < 0) {
        virReportSystemError(errno,
                             _("Unable to listen to UNIX socket path '%1$s'"),
                             dev->data.nix.path);
        goto error;
    }

    /* We run QEMU with umask 0002. Compensate for the umask
     * libvirtd might be running under to get the same permission
     * QEMU would have. */
    if (virFileUpdatePerm(dev->data.nix.path, 0002, 0664) < 0)
        goto error;

    return fd;

 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}


static const char *
qemuBuildHostdevMdevModelTypeString(virDomainHostdevSubsysMediatedDev *mdev)
{
    /* when the 'ramfb' attribute is set, we must use the nohotplug variant
     * rather than 'vfio-pci' */
    if (mdev->model == VIR_MDEV_MODEL_TYPE_VFIO_PCI &&
        mdev->ramfb == VIR_TRISTATE_SWITCH_ON)
        return "vfio-pci-nohotplug";

    return virMediatedDeviceModelTypeToString(mdev->model);
}


virJSONValue *
qemuBuildHostdevMediatedDevProps(const virDomainDef *def,
                                 virDomainHostdevDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &dev->source.subsys.u.mdev;
    g_autofree char *mdevPath = NULL;
    /* 'ramfb' property must be omitted unless it's to be enabled */
    bool ramfb = mdevsrc->ramfb == VIR_TRISTATE_SWITCH_ON;

    mdevPath = virMediatedDeviceGetSysfsPath(mdevsrc->uuidstr);

    if (virJSONValueObjectAdd(&props,
                              "s:driver", qemuBuildHostdevMdevModelTypeString(mdevsrc),
                              "s:id", dev->info->alias,
                              "s:sysfsdev", mdevPath,
                              "S:display", qemuOnOffAuto(mdevsrc->display),
                              "B:ramfb", ramfb,
                              "p:bootindex", dev->info->bootIndex,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIDetachPrepare(virDomainHostdevDef *hostdev,
                                  virQEMUCaps *qemuCaps G_GNUC_UNUSED)
{
    virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;
    g_autoptr(qemuBlockStorageSourceAttachData) ret = g_new0(qemuBlockStorageSourceAttachData, 1);
    virStorageSource *src;
    qemuDomainStorageSourcePrivate *srcpriv;

    switch (scsisrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE:
        src = scsisrc->u.host.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI:
        src = scsisrc->u.iscsi.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainHostdevSCSIProtocolType, scsisrc->protocol);
        return NULL;
    }

    srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    ret->storageNodeName = qemuBlockStorageSourceGetStorageNodename(src);
    ret->storageAttached = true;

    if (srcpriv && srcpriv->secinfo)
        ret->authsecretAlias = g_strdup(srcpriv->secinfo->alias);

    return g_steal_pointer(&ret);
}


qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIAttachPrepare(virDomainHostdevDef *hostdev,
                                  const char **backendAlias,
                                  virQEMUCaps *qemuCaps G_GNUC_UNUSED)
{
    virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;
    g_autoptr(qemuBlockStorageSourceAttachData) ret = g_new0(qemuBlockStorageSourceAttachData, 1);
    virStorageSource *src = NULL;

    switch (scsisrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE:
        src = scsisrc->u.host.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI:
        src = scsisrc->u.iscsi.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainHostdevSCSIProtocolType, scsisrc->protocol);
        return NULL;
    }

    ret->storageNodeName = qemuBlockStorageSourceGetStorageNodename(src);
    *backendAlias = qemuBlockStorageSourceGetStorageNodename(src);

    if (!(ret->storageProps = qemuBlockStorageSourceGetBackendProps(src,
                                                                    QEMU_BLOCK_STORAGE_SOURCE_BACKEND_PROPS_SKIP_UNMAP)))
        return NULL;

    if (qemuBuildStorageSourceAttachPrepareCommon(src, ret) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


static int
qemuBuildHostdevSCSICommandLine(virCommand *cmd,
                                const virDomainDef *def,
                                virDomainHostdevDef *hostdev,
                                virQEMUCaps *qemuCaps)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;
    g_autoptr(virJSONValue) devprops = NULL;
    const char *backendAlias = NULL;

    if (!(data = qemuBuildHostdevSCSIAttachPrepare(hostdev, &backendAlias, qemuCaps)))
        return -1;

    if (qemuBuildBlockStorageSourceAttachDataCommandline(cmd, data, qemuCaps) < 0)
        return -1;

    if (!(devprops = qemuBuildSCSIHostdevDevProps(def, hostdev, backendAlias)))
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildHostdevCommandLine(virCommand *cmd,
                            const virDomainDef *def,
                            virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        virDomainHostdevSubsys *subsys = &hostdev->source.subsys;
        virDomainHostdevSubsysMediatedDev *mdevsrc = &subsys->u.mdev;
        g_autoptr(virJSONValue) devprops = NULL;
        g_autofree char *vhostfdName = NULL;
        int vhostfd = -1;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;

        switch (subsys->type) {
        /* USB */
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (!(devprops = qemuBuildUSBHostdevDevProps(def, hostdev, qemuCaps)))
                return -1;

            if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
                return -1;
            break;

        /* PCI */
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
           /* Ignore unassigned devices  */
           if (hostdev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED)
               continue;

            if (qemuCommandAddExtDevice(cmd, hostdev->info, def, qemuCaps) < 0)
                return -1;

            if (!(devprops = qemuBuildPCIHostdevDevProps(def, hostdev)))
                return -1;

            if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
                return -1;
            break;

        /* SCSI */
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            if (qemuBuildHostdevSCSICommandLine(cmd, def, hostdev, qemuCaps) < 0)
                return -1;
            break;

        /* SCSI_host */
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            if (hostdev->source.subsys.u.scsi_host.protocol ==
                VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST) {

                if (virSCSIVHostOpenVhostSCSI(&vhostfd) < 0)
                    return -1;

                vhostfdName = g_strdup_printf("%d", vhostfd);

                virCommandPassFD(cmd, vhostfd,
                                 VIR_COMMAND_PASS_FD_CLOSE_PARENT);

                if (!(devprops = qemuBuildSCSIVHostHostdevDevProps(def,
                                                                   hostdev,
                                                                   qemuCaps,
                                                                   vhostfdName)))
                    return -1;

                if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
                    return -1;
            }

            break;

        /* MDEV */
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
            switch (mdevsrc->model) {
            case VIR_MDEV_MODEL_TYPE_VFIO_PCI:
            case VIR_MDEV_MODEL_TYPE_VFIO_CCW:
            case VIR_MDEV_MODEL_TYPE_VFIO_AP:
                break;
            case VIR_MDEV_MODEL_TYPE_LAST:
            default:
                virReportEnumRangeError(virMediatedDeviceModelType,
                                        subsys->u.mdev.model);
                return -1;
            }

            if (!(devprops = qemuBuildHostdevMediatedDevProps(def, hostdev)))
                return -1;

            if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
                return -1;
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuBuildMonitorCommandLine(virCommand *cmd,
                            qemuDomainObjPrivate *priv)
{
    if (!priv->monConfig)
        return 0;

    if (qemuBuildChardevCommand(cmd,
                                priv->monConfig,
                                "charmonitor",
                                priv->qemuCaps) < 0)
        return -1;

    virCommandAddArg(cmd, "-mon");
    virCommandAddArg(cmd, "chardev=charmonitor,id=monitor,mode=control");

    return 0;
}


static virJSONValue *
qemuBuildVirtioSerialPortDevProps(const virDomainDef *def,
                                  virDomainChrDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *driver;
    const char *targetname = NULL;
    g_autofree char *chardev = NULL;

    switch (dev->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        driver = "virtconsole";
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        driver = "virtserialport";
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use virtio serial for parallel/serial devices"));
        return NULL;
    }

    if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        /* Check it's a virtio-serial address */
        if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("virtio serial device has invalid address type"));
            return NULL;
        }

    }

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        dev->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
        dev->target.name &&
        STRNEQ(dev->target.name, "com.redhat.spice.0")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported spicevmc target name '%1$s'"),
                       dev->target.name);
        return NULL;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", driver,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    chardev = g_strdup_printf("char%s", dev->info.alias);

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        (dev->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC ||
         dev->target.name)) {
        if (dev->target.name)
            targetname = dev->target.name;
        else
            targetname = "com.redhat.spice.0";
    }

    if (virJSONValueObjectAdd(&props,
                              "s:chardev", chardev,
                              "s:id", dev->info.alias,
                              "S:name", targetname,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBuildSclpDevProps(virDomainChrDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *chardev = g_strdup_printf("char%s", dev->info.alias);
    const char *driver = NULL;

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE) {
        switch (dev->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
            driver = "sclpconsole";
            break;
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            driver = "sclplmconsole";
            break;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use slcp with devices other than console"));
        return NULL;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", driver,
                              "s:chardev", chardev,
                              "s:id", dev->info.alias,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildRNGBackendChrdev(virCommand *cmd,
                          virDomainRNGDef *rng,
                          virQEMUCaps *qemuCaps)
{
    g_autofree char *charAlias = qemuAliasChardevFromDevAlias(rng->info.alias);

    switch (rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        /* no chardev backend is needed */
        return 0;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (qemuBuildChardevCommand(cmd,
                                    rng->source.chardev,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;
        break;
    }

    return 0;
}


int
qemuBuildRNGBackendProps(virDomainRNGDef *rng,
                         virJSONValue **props)
{
    g_autofree char *objAlias = NULL;
    g_autofree char *charBackendAlias = NULL;

    objAlias = g_strdup_printf("obj%s", rng->info.alias);

    switch (rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (qemuMonitorCreateObjectProps(props, "rng-random", objAlias,
                                         "s:filename", rng->source.file,
                                         NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (!(charBackendAlias = qemuAliasChardevFromDevAlias(rng->info.alias)))
            return -1;

        if (qemuMonitorCreateObjectProps(props, "rng-egd", objAlias,
                                         "s:chardev", charBackendAlias,
                                         NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        if (qemuMonitorCreateObjectProps(props, "rng-builtin", objAlias,
                                         NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    return 0;
}


virJSONValue *
qemuBuildRNGDevProps(const virDomainDef *def,
                     virDomainRNGDef *dev,
                     virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *rng = g_strdup_printf("obj%s", dev->info.alias);
    unsigned int period = 0;

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_RNG, dev, qemuCaps)))
        return NULL;

    if (dev->rate > 0) {
        period = dev->period;

        if (period == 0)
            period = 1000;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:rng", rng,
                              "s:id", dev->info.alias,
                              "p:max-bytes", dev->rate,
                              "p:period", period,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildRNGCommandLine(virCommand *cmd,
                        const virDomainDef *def,
                        virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nrngs; i++) {
        g_autoptr(virJSONValue) props = NULL;
        virDomainRNGDef *rng = def->rngs[i];
        g_autoptr(virJSONValue) devprops = NULL;

        if (!rng->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("RNG device is missing alias"));
            return -1;
        }

        /* possibly add character device for backend */
        if (qemuBuildRNGBackendChrdev(cmd, rng, qemuCaps) < 0)
            return -1;

        if (qemuBuildRNGBackendProps(rng, &props) < 0)
            return -1;

        if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
            return -1;

        /* add the device */
        if (qemuCommandAddExtDevice(cmd, &rng->info, def, qemuCaps) < 0)
            return -1;

        if (!(devprops = qemuBuildRNGDevProps(def, rng, qemuCaps)))
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static char *
qemuBuildSmbiosBiosStr(virSysinfoBIOSDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=0");

    /* 0:Vendor */
    if (def->vendor) {
        virBufferAddLit(&buf, ",vendor=");
        virQEMUBuildBufferEscapeComma(&buf, def->vendor);
    }
    /* 0:BIOS Version */
    if (def->version) {
        virBufferAddLit(&buf, ",version=");
        virQEMUBuildBufferEscapeComma(&buf, def->version);
    }
    /* 0:BIOS Release Date */
    if (def->date) {
        virBufferAddLit(&buf, ",date=");
        virQEMUBuildBufferEscapeComma(&buf, def->date);
    }
    /* 0:System BIOS Major Release and 0:System BIOS Minor Release */
    if (def->release) {
        virBufferAddLit(&buf, ",release=");
        virQEMUBuildBufferEscapeComma(&buf, def->release);
    }

    return virBufferContentAndReset(&buf);
}


static char *
qemuBuildSmbiosSystemStr(virSysinfoSystemDef *def,
                         bool skip_uuid)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!def ||
        (!def->manufacturer && !def->product && !def->version &&
         !def->serial && (!def->uuid || skip_uuid) &&
         def->sku && !def->family))
        return NULL;

    virBufferAddLit(&buf, "type=1");

    /* 1:Manufacturer */
    if (def->manufacturer) {
        virBufferAddLit(&buf, ",manufacturer=");
        virQEMUBuildBufferEscapeComma(&buf, def->manufacturer);
    }
     /* 1:Product Name */
    if (def->product) {
        virBufferAddLit(&buf, ",product=");
        virQEMUBuildBufferEscapeComma(&buf, def->product);
    }
    /* 1:Version */
    if (def->version) {
        virBufferAddLit(&buf, ",version=");
        virQEMUBuildBufferEscapeComma(&buf, def->version);
    }
    /* 1:Serial Number */
    if (def->serial) {
        virBufferAddLit(&buf, ",serial=");
        virQEMUBuildBufferEscapeComma(&buf, def->serial);
    }
    /* 1:UUID */
    if (def->uuid && !skip_uuid) {
        virBufferAddLit(&buf, ",uuid=");
        virQEMUBuildBufferEscapeComma(&buf, def->uuid);
    }
    /* 1:SKU Number */
    if (def->sku) {
        virBufferAddLit(&buf, ",sku=");
        virQEMUBuildBufferEscapeComma(&buf, def->sku);
    }
    /* 1:Family */
    if (def->family) {
        virBufferAddLit(&buf, ",family=");
        virQEMUBuildBufferEscapeComma(&buf, def->family);
    }

    return virBufferContentAndReset(&buf);
}


static char *
qemuBuildSmbiosBaseBoardStr(virSysinfoBaseBoardDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=2");

    /* 2:Manufacturer */
    virBufferAddLit(&buf, ",manufacturer=");
    virQEMUBuildBufferEscapeComma(&buf, def->manufacturer);
    /* 2:Product Name */
    if (def->product) {
        virBufferAddLit(&buf, ",product=");
        virQEMUBuildBufferEscapeComma(&buf, def->product);
    }
    /* 2:Version */
    if (def->version) {
        virBufferAddLit(&buf, ",version=");
        virQEMUBuildBufferEscapeComma(&buf, def->version);
    }
    /* 2:Serial Number */
    if (def->serial) {
        virBufferAddLit(&buf, ",serial=");
        virQEMUBuildBufferEscapeComma(&buf, def->serial);
    }
    /* 2:Asset Tag */
    if (def->asset) {
        virBufferAddLit(&buf, ",asset=");
        virQEMUBuildBufferEscapeComma(&buf, def->asset);
    }
    /* 2:Location */
    if (def->location) {
        virBufferAddLit(&buf, ",location=");
        virQEMUBuildBufferEscapeComma(&buf, def->location);
    }

    return virBufferContentAndReset(&buf);
}


static char *
qemuBuildSmbiosOEMStringsStr(virSysinfoOEMStringsDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=11");

    for (i = 0; i < def->nvalues; i++) {
        virBufferAddLit(&buf, ",value=");
        virQEMUBuildBufferEscapeComma(&buf, def->values[i]);
    }

    return virBufferContentAndReset(&buf);
}


static char *
qemuBuildSmbiosChassisStr(virSysinfoChassisDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=3");

    /* 3:Manufacturer */
    virBufferAddLit(&buf, ",manufacturer=");
    virQEMUBuildBufferEscapeComma(&buf, def->manufacturer);
    /* 3:Version */
    if (def->version) {
        virBufferAddLit(&buf, ",version=");
        virQEMUBuildBufferEscapeComma(&buf, def->version);
    }
    /* 3:Serial Number */
    if (def->serial) {
        virBufferAddLit(&buf, ",serial=");
        virQEMUBuildBufferEscapeComma(&buf, def->serial);
    }
    /* 3:Asset Tag */
    if (def->asset) {
        virBufferAddLit(&buf, ",asset=");
        virQEMUBuildBufferEscapeComma(&buf, def->asset);
    }
    /* 3:Sku */
    if (def->sku) {
        virBufferAddLit(&buf, ",sku=");
        virQEMUBuildBufferEscapeComma(&buf, def->sku);
    }

    return virBufferContentAndReset(&buf);
}


static int
qemuBuildSmbiosCommandLine(virCommand *cmd,
                           virQEMUDriver *driver,
                           const virDomainDef *def)
{
    size_t i;
    virSysinfoDef *source = NULL;
    bool skip_uuid = false;

    if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_NONE ||
        def->os.smbios_mode == VIR_DOMAIN_SMBIOS_EMULATE)
        return 0;

    /* should we really error out or just warn in those cases ? */
    if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
        if (driver->hostsysinfo == NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Host SMBIOS information is not available"));
            return -1;
        }
        source = driver->hostsysinfo;
        /* Host and guest uuid must differ, by definition of UUID. */
        skip_uuid = true;
    } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_SYSINFO) {
        for (i = 0; i < def->nsysinfo; i++) {
            if (def->sysinfo[i]->type == VIR_SYSINFO_SMBIOS) {
                source = def->sysinfo[i];
                break;
            }
        }

        if (!source) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Domain '%1$s' sysinfo are not available"),
                           def->name);
            return -1;
        }
        /* domain_conf guaranteed that system_uuid matches guest uuid. */
    }
    if (source != NULL) {
        char *smbioscmd;

        smbioscmd = qemuBuildSmbiosBiosStr(source->bios);
        if (smbioscmd != NULL) {
            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }
        smbioscmd = qemuBuildSmbiosSystemStr(source->system, skip_uuid);
        if (smbioscmd != NULL) {
            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }

        if (source->nbaseBoard > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("qemu does not support more than one entry to Type 2 in SMBIOS table"));
            return -1;
        }

        for (i = 0; i < source->nbaseBoard; i++) {
            if (!(smbioscmd =
                  qemuBuildSmbiosBaseBoardStr(source->baseBoard + i)))
                return -1;

            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }

        smbioscmd = qemuBuildSmbiosChassisStr(source->chassis);
        if (smbioscmd != NULL) {
            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }

        if (source->oemStrings) {
            if (!(smbioscmd = qemuBuildSmbiosOEMStringsStr(source->oemStrings)))
                return -1;

            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }
    }

    return 0;
}


static int
qemuBuildSysinfoCommandLine(virCommand *cmd,
                            const virDomainDef *def)
{
    size_t i;

    /* We need to handle VIR_SYSINFO_FWCFG here, because
     * VIR_SYSINFO_SMBIOS is handled in qemuBuildSmbiosCommandLine() */
    for (i = 0; i < def->nsysinfo; i++) {
        size_t j;

        if (def->sysinfo[i]->type != VIR_SYSINFO_FWCFG)
            continue;

        for (j = 0; j < def->sysinfo[i]->nfw_cfgs; j++) {
            const virSysinfoFWCfgDef *f = &def->sysinfo[i]->fw_cfgs[j];
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

            virBufferAsprintf(&buf, "name=%s", f->name);

            if (f->value)
                virBufferEscapeString(&buf, ",string=%s", f->value);
            else
                virBufferEscapeString(&buf, ",file=%s", f->file);

            virCommandAddArg(cmd, "-fw_cfg");
            virCommandAddArgBuffer(cmd, &buf);
        }
    }

    return 0;
}


static int
qemuBuildVMGenIDCommandLine(virCommand *cmd,
                            const virDomainDef *def,
                            virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    char guid[VIR_UUID_STRING_BUFLEN];

    if (!def->genidRequested)
        return 0;

    virUUIDFormat(def->genid, guid);

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "vmgenid",
                              "s:guid", guid,
                              "s:id", "vmgenid0",
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static char *
qemuBuildClockArgStr(virDomainClockDef *def)
{
    size_t i;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    switch ((virDomainClockOffsetType) def->offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        virBufferAddLit(&buf, "base=utc");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virBufferAddLit(&buf, "base=localtime");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE: {
        g_autoptr(GDateTime) now = g_date_time_new_now_utc();
        g_autoptr(GDateTime) then = NULL;
        g_autofree char *thenstr = NULL;

        if (def->data.variable.basis == VIR_DOMAIN_CLOCK_BASIS_LOCALTIME) {
            long localOffset;

            /* in the case of basis='localtime', rather than trying to
             * keep that basis (and associated offset from UTC) in the
             * status and deal with adding in the difference each time
             * there is an RTC_CHANGE event, it is simpler and less
             * error prone to just convert the adjustment an offset
             * from UTC right now (and change the status to
             * "basis='utc' to reflect this). This eliminates
             * potential errors in both RTC_CHANGE events and in
             * migration (in the case that the status of DST, or the
             * timezone of the destination host, changed relative to
             * startup).
             */
            if (virTimeLocalOffsetFromUTC(&localOffset) < 0)
               return NULL;
            def->data.variable.adjustment += localOffset;
            def->data.variable.basis = VIR_DOMAIN_CLOCK_BASIS_UTC;
        }

        then = g_date_time_add_seconds(now, def->data.variable.adjustment);
        thenstr = g_date_time_format(then, "%Y-%m-%dT%H:%M:%S");

        /* when an RTC_CHANGE event is received from qemu, we need to
         * have the adjustment used at domain start time available to
         * compute the new offset from UTC. As this new value is
         * itself stored in def->data.variable.adjustment, we need to
         * save a copy of it now.
        */
        def->data.variable.adjustment0 = def->data.variable.adjustment;

        virBufferAsprintf(&buf, "base=%s", thenstr);
    }   break;

    case VIR_DOMAIN_CLOCK_OFFSET_ABSOLUTE: {
        g_autoptr(GDateTime) then = g_date_time_new_from_unix_utc(def->data.starttime);
        g_autofree char *thenstr = g_date_time_format(then, "%Y-%m-%dT%H:%M:%S");

        virBufferAsprintf(&buf, "base=%s", thenstr);
    }   break;

    case VIR_DOMAIN_CLOCK_OFFSET_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported clock offset '%1$s'"),
                       virDomainClockOffsetTypeToString(def->offset));
        return NULL;
    }

    /* Look for an 'rtc' timer element, and add in appropriate
     * clock= and driftfix= */
    for (i = 0; i < def->ntimers; i++) {
        if (def->timers[i]->name == VIR_DOMAIN_TIMER_NAME_RTC) {
            switch (def->timers[i]->track) {
            case VIR_DOMAIN_TIMER_TRACK_NONE: /* unspecified - use hypervisor default */
                break;
            case VIR_DOMAIN_TIMER_TRACK_BOOT:
                return NULL;
            case VIR_DOMAIN_TIMER_TRACK_GUEST:
                virBufferAddLit(&buf, ",clock=vm");
                break;
            case VIR_DOMAIN_TIMER_TRACK_WALL:
                virBufferAddLit(&buf, ",clock=host");
                break;
            case VIR_DOMAIN_TIMER_TRACK_REALTIME:
                virBufferAddLit(&buf, ",clock=rt");
                break;
            case VIR_DOMAIN_TIMER_TRACK_LAST:
                break;
            }

            switch (def->timers[i]->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
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
                return NULL;
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break; /* no need to check other timers - there is only one rtc */
        }
    }

    return virBufferContentAndReset(&buf);
}


/* NOTE: Building of commands can change def->clock->data.* values, so
 *       virDomainDef is not const here.
 */
static int
qemuBuildClockCommandLine(virCommand *cmd,
                          virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    size_t i;
    g_autofree char *rtcopt = NULL;

    virCommandAddArg(cmd, "-rtc");
    if (!(rtcopt = qemuBuildClockArgStr(&def->clock)))
        return -1;
    virCommandAddArg(cmd, rtcopt);

    if (def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE &&
        def->clock.data.timezone) {
        virCommandAddEnvPair(cmd, "TZ", def->clock.data.timezone);
    }

    for (i = 0; i < def->clock.ntimers; i++) {
        switch ((virDomainTimerNameType)def->clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
            /* qemuDomainDefValidateClockTimers will handle this
             * error condition  */
            return -1;

        case VIR_DOMAIN_TIMER_NAME_TSC:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
            /* Timers above are handled when building -cpu.  */
        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;

        case VIR_DOMAIN_TIMER_NAME_RTC:
            /* Already handled in qemuDomainDefValidateClockTimers */
            break;

        case VIR_DOMAIN_TIMER_NAME_PIT:
            switch (def->clock.timers[i]->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* delay is the default if we don't have kernel
                   (kvm-pit), otherwise, the default is catchup. */
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM_PIT_TICK_POLICY))
                    virCommandAddArgList(cmd, "-global",
                                         "kvm-pit.lost_tick_policy=delay", NULL);
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                /* Do nothing - qemuDomainDefValidateClockTimers handled
                 * the possible error condition here. */
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM_PIT_TICK_POLICY))
                    virCommandAddArgList(cmd, "-global",
                                         "kvm-pit.lost_tick_policy=discard", NULL);
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
                /* no way to support this mode for pit in qemu */
                return -1;
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            /* Modern qemu versions configure the HPET timer via -machine. See
             * qemuBuildMachineCommandLine.
             *
             * the only meaningful attribute for hpet is "present". If present
             * is VIR_TRISTATE_BOOL_ABSENT, that means it wasn't specified, and
             * should be left at the default for the hypervisor. "default" when
             * -no-hpet exists is VIR_TRISTATE_BOOL_YES, and when -no-hpet
             *  doesn't exist is VIR_TRISTATE_BOOL_NO. "confusing"?  "yes"! */

            if (def->clock.timers[i]->present == VIR_TRISTATE_BOOL_NO &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_HPET) &&
                (def->os.arch == VIR_ARCH_I686 ||
                 def->os.arch == VIR_ARCH_X86_64)) {
                virCommandAddArg(cmd, "-no-hpet");
            }
            break;
        }
    }

    return 0;
}


static void
qemuBuildPMCommandLine(virCommand *cmd,
                       const virDomainDef *def,
                       qemuDomainObjPrivate *priv)
{
    virQEMUCaps *qemuCaps = priv->qemuCaps;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SET_ACTION)) {
        /* with new qemu we always want '-no-shutdown' on startup and we set
         * all the other behaviour later during startup */
        virCommandAddArg(cmd, "-no-shutdown");
    } else {
        if (priv->allowReboot == VIR_TRISTATE_BOOL_NO)
            virCommandAddArg(cmd, "-no-reboot");
        else
            virCommandAddArg(cmd, "-no-shutdown");
    }

    /* Use old syntax of -no-acpi only if qemu didn't report that it supports the
     * new syntax */
    if (virQEMUCapsMachineSupportsACPI(qemuCaps, def->virtType, def->os.machine) == VIR_TRISTATE_BOOL_ABSENT &&
        (def->os.arch == VIR_ARCH_I686 ||
         def->os.arch == VIR_ARCH_X86_64 ||
         def->os.arch == VIR_ARCH_AARCH64)) {
        if (def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON)
            virCommandAddArg(cmd, "-no-acpi");
    }

    if (def->pm.s3 || def->pm.s4) {
        const char *pm_object = "PIIX4_PM";

        if (qemuDomainIsQ35(def))
            pm_object = "ICH9-LPC";

        if (def->pm.s3) {
            virCommandAddArg(cmd, "-global");
            virCommandAddArgFormat(cmd, "%s.disable_s3=%d",
                                   pm_object, def->pm.s3 == VIR_TRISTATE_BOOL_NO);
        }

        if (def->pm.s4) {
            virCommandAddArg(cmd, "-global");
            virCommandAddArgFormat(cmd, "%s.disable_s4=%d",
                                   pm_object, def->pm.s4 == VIR_TRISTATE_BOOL_NO);
        }
    }
}


static int
qemuBuildBootCommandLine(virCommand *cmd,
                         const virDomainDef *def)
{
    g_auto(virBuffer) boot_buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *boot_opts_str = NULL;

    if (def->os.bootmenu) {
        if (def->os.bootmenu == VIR_TRISTATE_BOOL_YES)
            virBufferAddLit(&boot_buf, "menu=on,");
        else
            virBufferAddLit(&boot_buf, "menu=off,");
    }

    if (def->os.bios.rt_set) {
        virBufferAsprintf(&boot_buf,
                          "reboot-timeout=%d,",
                          def->os.bios.rt_delay);
    }

    if (def->os.bm_timeout_set)
        virBufferAsprintf(&boot_buf, "splash-time=%u,", def->os.bm_timeout);

    virBufferAddLit(&boot_buf, "strict=on");

    boot_opts_str = virBufferContentAndReset(&boot_buf);
    if (boot_opts_str) {
        virCommandAddArg(cmd, "-boot");
        virCommandAddArg(cmd, boot_opts_str);
    }

    if (def->os.kernel)
        virCommandAddArgList(cmd, "-kernel", def->os.kernel, NULL);
    if (def->os.initrd)
        virCommandAddArgList(cmd, "-initrd", def->os.initrd, NULL);
    if (def->os.cmdline)
        virCommandAddArgList(cmd, "-append", def->os.cmdline, NULL);
    if (def->os.dtb)
        virCommandAddArgList(cmd, "-dtb", def->os.dtb, NULL);
    if (def->os.slic_table) {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        virCommandAddArg(cmd, "-acpitable");
        virBufferAddLit(&buf, "sig=SLIC,file=");
        virQEMUBuildBufferEscapeComma(&buf, def->os.slic_table);
        virCommandAddArgBuffer(cmd, &buf);
    }

    return 0;
}


static int
qemuBuildIOMMUCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const virDomainIOMMUDef *iommu = def->iommu;

    if (!iommu)
        return 0;

    switch (iommu->model) {
    case VIR_DOMAIN_IOMMU_MODEL_INTEL:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "intel-iommu",
                                  "s:id", iommu->info.alias,
                                  "S:intremap", qemuOnOffAuto(iommu->intremap),
                                  "T:caching-mode", iommu->caching_mode,
                                  "S:eim", qemuOnOffAuto(iommu->eim),
                                  "T:device-iotlb", iommu->iotlb,
                                  "z:aw-bits", iommu->aw_bits,
                                  NULL) < 0)
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
            return -1;

        return 0;

    case VIR_DOMAIN_IOMMU_MODEL_VIRTIO:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "virtio-iommu",
                                  "s:id", iommu->info.alias,
                                  NULL) < 0) {
            return -1;
        }

        if (qemuBuildDeviceAddressProps(props, def, &iommu->info) < 0)
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
            return -1;

        return 0;

    case VIR_DOMAIN_IOMMU_MODEL_SMMUV3:
        /* There is no -device for SMMUv3, so nothing to be done here */
        return 0;

    case VIR_DOMAIN_IOMMU_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainIOMMUModel, iommu->model);
        return -1;
    }

    return 0;
}


static int
qemuBuildGlobalControllerCommandLine(virCommand *cmd,
                                     const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            cont->opts.pciopts.pcihole64) {
            const char *hoststr = NULL;

            switch (cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
                hoststr = "i440FX-pcihost";
                break;

            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                hoststr = "q35-pcihost";
                break;

            default:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("64-bit PCI hole setting is only for root PCI controllers"));
                return -1;
            }

            virCommandAddArg(cmd, "-global");
            virCommandAddArgFormat(cmd, "%s.pci-hole64-size=%luK", hoststr,
                                   cont->opts.pciopts.pcihole64size);
        }
    }

    return 0;
}


static int
qemuBuildCpuModelArgStr(virQEMUDriver *driver,
                        const virDomainDef *def,
                        virBuffer *buf,
                        virQEMUCaps *qemuCaps)
{
    size_t i;
    virCPUDef *cpu = def->cpu;

    switch ((virCPUMode) cpu->mode) {
    case VIR_CPU_MODE_HOST_PASSTHROUGH:
    case VIR_CPU_MODE_MAXIMUM:
        if (cpu->mode == VIR_CPU_MODE_MAXIMUM)
            virBufferAddLit(buf, "max");
        else
            virBufferAddLit(buf, "host");

        if (def->os.arch == VIR_ARCH_ARMV7L &&
            driver->hostarch == VIR_ARCH_AARCH64) {
            virBufferAddLit(buf, ",aarch64=off");
        }

        if (cpu->migratable) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MIGRATABLE)) {
                virBufferAsprintf(buf, ",migratable=%s",
                                  virTristateSwitchTypeToString(cpu->migratable));
            }
        }
        break;

    case VIR_CPU_MODE_HOST_MODEL:
        /* HOST_MODEL is a valid CPU mode for domain XMLs of all archs, meaning
         * that we can't move this validation to parse time. By the time we reach
         * this point, all non-PPC64 archs must have translated the CPU model to
         * something else and set the CPU mode to MODE_CUSTOM.
         */
        if (ARCH_IS_PPC64(def->os.arch)) {
            virBufferAddLit(buf, "host");
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected host-model CPU for %1$s architecture"),
                           virArchToString(def->os.arch));
            return -1;
        }
        break;

    case VIR_CPU_MODE_CUSTOM:
        virBufferAdd(buf, cpu->model, -1);
        break;

    case VIR_CPU_MODE_LAST:
        break;
    }

    if ((ARCH_IS_S390(def->os.arch) || ARCH_IS_ARM(def->os.arch)) &&
        cpu->features &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU features not supported by hypervisor for %1$s architecture"),
                       virArchToString(def->os.arch));
        return -1;
    }

    if (cpu->vendor_id)
        virBufferAsprintf(buf, ",vendor=%s", cpu->vendor_id);

    for (i = 0; i < cpu->nfeatures; i++) {
        const char *featname =
            virQEMUCapsCPUFeatureToQEMU(def->os.arch, cpu->features[i].name);
        switch ((virCPUFeaturePolicy) cpu->features[i].policy) {
        case VIR_CPU_FEATURE_FORCE:
        case VIR_CPU_FEATURE_REQUIRE:
            virBufferAsprintf(buf, ",%s=on", featname);
            break;

        case VIR_CPU_FEATURE_DISABLE:
        case VIR_CPU_FEATURE_FORBID:
            virBufferAsprintf(buf, ",%s=off", featname);
            break;

        case VIR_CPU_FEATURE_OPTIONAL:
        case VIR_CPU_FEATURE_LAST:
            break;
        }
    }

    return 0;
}

static int
qemuBuildCpuCommandLine(virCommand *cmd,
                        virQEMUDriver *driver,
                        const virDomainDef *def,
                        virQEMUCaps *qemuCaps)
{
    virArch hostarch = virArchFromHost();
    g_autofree char *cpu = NULL;
    g_autofree char *cpu_flags = NULL;
    g_auto(virBuffer) cpu_buf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (def->cpu &&
        (def->cpu->mode != VIR_CPU_MODE_CUSTOM || def->cpu->model)) {
        if (qemuBuildCpuModelArgStr(driver, def, &cpu_buf, qemuCaps) < 0)
            return -1;
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
              strstr(def->emulator, "kvm")) ||
             strstr(def->emulator, "x86_64"))) {
            virBufferAddLit(&cpu_buf, "qemu32");
        }
    }

    /* Handle paravirtual timers  */
    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDef *timer = def->clock.timers[i];

        switch ((virDomainTimerNameType)timer->name) {
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
            if (timer->present != VIR_TRISTATE_BOOL_ABSENT) {
                /* QEMU expects on/off -> virTristateSwitch. */
                virBufferAsprintf(&buf, ",kvmclock=%s",
                                  virTristateSwitchTypeToString(timer->present));
            }
            break;
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
            if (timer->present == VIR_TRISTATE_BOOL_YES)
                virBufferAddLit(&buf, ",hv-time=on");
            break;
        case VIR_DOMAIN_TIMER_NAME_TSC:
            if (timer->frequency > 0)
                virBufferAsprintf(&buf, ",tsc-frequency=%llu", timer->frequency);
            break;
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
            switch (timer->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                virBufferAddLit(&buf, ",kvm-no-adjvtime=off");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                virBufferAddLit(&buf, ",kvm-no-adjvtime=on");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break;
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_HPET:
            break;
        case VIR_DOMAIN_TIMER_NAME_LAST:
        default:
            virReportEnumRangeError(virDomainTimerNameType, timer->name);
            return -1;
        }
    }

    if (def->apic_eoi) {
        virBufferAsprintf(&buf, ",kvm-pv-eoi=%s", def->apic_eoi ==
                          VIR_TRISTATE_SWITCH_ON ? "on" : "off");
    }

    if (def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK]) {
        virBufferAsprintf(&buf, ",kvm-pv-unhalt=%s",
                          def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK] ==
                          VIR_TRISTATE_SWITCH_ON ? "on" : "off");
    }

    if (def->features[VIR_DOMAIN_FEATURE_HYPERV] != VIR_DOMAIN_HYPERV_MODE_NONE) {
        switch ((virDomainHyperVMode) def->features[VIR_DOMAIN_FEATURE_HYPERV]) {
        case VIR_DOMAIN_HYPERV_MODE_CUSTOM:
            break;

        case VIR_DOMAIN_HYPERV_MODE_PASSTHROUGH:
            virBufferAsprintf(&buf, ",hv-%s=on", "passthrough");
            break;

        case VIR_DOMAIN_HYPERV_MODE_NONE:
        case VIR_DOMAIN_HYPERV_MODE_LAST:
        default:
            virReportEnumRangeError(virDomainHyperVMode,
                                    def->features[VIR_DOMAIN_FEATURE_HYPERV]);
            return -1;
        }

        for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
            switch ((virDomainHyperv) i) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
            case VIR_DOMAIN_HYPERV_VPINDEX:
            case VIR_DOMAIN_HYPERV_RUNTIME:
            case VIR_DOMAIN_HYPERV_SYNIC:
            case VIR_DOMAIN_HYPERV_STIMER:
            case VIR_DOMAIN_HYPERV_RESET:
            case VIR_DOMAIN_HYPERV_FREQUENCIES:
            case VIR_DOMAIN_HYPERV_REENLIGHTENMENT:
            case VIR_DOMAIN_HYPERV_TLBFLUSH:
            case VIR_DOMAIN_HYPERV_IPI:
            case VIR_DOMAIN_HYPERV_EVMCS:
            case VIR_DOMAIN_HYPERV_AVIC:
                if (def->hyperv_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAsprintf(&buf, ",hv-%s=on",
                                      virDomainHypervTypeToString(i));
                if ((i == VIR_DOMAIN_HYPERV_STIMER) &&
                    (def->hyperv_stimer_direct == VIR_TRISTATE_SWITCH_ON))
                    virBufferAsprintf(&buf, ",%s=on", VIR_CPU_x86_HV_STIMER_DIRECT);
                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                if (def->hyperv_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAsprintf(&buf, ",%s=0x%x",
                                      VIR_CPU_x86_HV_SPINLOCKS,
                                      def->hyperv_spinlocks);
                break;

            case VIR_DOMAIN_HYPERV_VENDOR_ID:
                if (def->hyperv_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAsprintf(&buf, ",hv-vendor-id=%s",
                                      def->hyperv_vendor_id);
                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
    }

    for (i = 0; i < def->npanics; i++) {
        if (def->panics[i]->model == VIR_DOMAIN_PANIC_MODEL_HYPERV) {
            virBufferAddLit(&buf, ",hv-crash");
            break;
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON) {
        for (i = 0; i < VIR_DOMAIN_KVM_LAST; i++) {
            switch ((virDomainKVM) i) {
            case VIR_DOMAIN_KVM_HIDDEN:
                if (def->kvm_features->features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAddLit(&buf, ",kvm=off");
                break;

            case VIR_DOMAIN_KVM_DEDICATED:
                if (def->kvm_features->features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAddLit(&buf, ",kvm-hint-dedicated=on");
                break;

            case VIR_DOMAIN_KVM_POLLCONTROL:
                if (def->kvm_features->features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAddLit(&buf, ",kvm-poll-control=on");
                break;

            case VIR_DOMAIN_KVM_PVIPI:
                if (def->kvm_features->features[i] == VIR_TRISTATE_SWITCH_OFF)
                    virBufferAddLit(&buf, ",kvm-pv-ipi=off");
                break;

            case VIR_DOMAIN_KVM_DIRTY_RING:
                break;

            case VIR_DOMAIN_KVM_LAST:
                break;
            }
        }
    }

    /* ppc64 guests always have PMU enabled, but the 'pmu' option
     * is not supported. */
    if (def->features[VIR_DOMAIN_FEATURE_PMU] && !ARCH_IS_PPC64(def->os.arch)) {
        virTristateSwitch pmu = def->features[VIR_DOMAIN_FEATURE_PMU];
        virBufferAsprintf(&buf, ",pmu=%s",
                          virTristateSwitchTypeToString(pmu));
    }

    if (def->cpu && def->cpu->cache) {
        virCPUCacheDef *cache = def->cpu->cache;
        bool hostOff = false;
        bool l3Off = false;

        switch (cache->mode) {
        case VIR_CPU_CACHE_MODE_EMULATE:
            virBufferAddLit(&buf, ",l3-cache=on");
            hostOff = true;
            break;

        case VIR_CPU_CACHE_MODE_PASSTHROUGH:
            virBufferAddLit(&buf, ",host-cache-info=on");
            l3Off = true;
            break;

        case VIR_CPU_CACHE_MODE_DISABLE:
            hostOff = l3Off = true;
            break;

        case VIR_CPU_CACHE_MODE_LAST:
            break;
        }

        if (hostOff &&
            (def->cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH ||
             def->cpu->mode == VIR_CPU_MODE_MAXIMUM))
            virBufferAddLit(&buf, ",host-cache-info=off");

        if (l3Off)
            virBufferAddLit(&buf, ",l3-cache=off");
    }

    if (def->cpu && def->cpu->addr) {
        virCPUMaxPhysAddrDef *addr = def->cpu->addr;

        switch (addr->mode) {
        case VIR_CPU_MAX_PHYS_ADDR_MODE_PASSTHROUGH:
            virBufferAddLit(&buf, ",host-phys-bits=on");

            if (addr->limit > 0)
                virBufferAsprintf(&buf, ",host-phys-bits-limit=%d", addr->limit);
            break;

        case VIR_CPU_MAX_PHYS_ADDR_MODE_EMULATE:
            if (addr->bits > 0)
                virBufferAsprintf(&buf, ",phys-bits=%d", addr->bits);
            else
                virBufferAddLit(&buf, ",host-phys-bits=off");
            break;

        case VIR_CPU_MAX_PHYS_ADDR_MODE_LAST:
            break;
        }
    }

    cpu = virBufferContentAndReset(&cpu_buf);
    cpu_flags = virBufferContentAndReset(&buf);

    if (cpu_flags && !cpu) {
        const char *default_model;

        switch ((int)def->os.arch) {
        case VIR_ARCH_I686:
            default_model = "qemu32";
            break;
        case VIR_ARCH_X86_64:
            default_model = "qemu64";
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CPU flags requested but can't determine default CPU for arch %1$s"),
                           virArchToString(def->os.arch));
            return -1;
        }

        cpu = g_strdup(default_model);
    }

    if (cpu) {
        virCommandAddArg(cmd, "-cpu");
        virCommandAddArgFormat(cmd, "%s%s", cpu, NULLSTR_EMPTY(cpu_flags));
    }

    return 0;
}


static int
qemuAppendKeyWrapMachineParms(virBuffer *buf,
                              const virDomainDef *def)
{
    if (!def->keywrap)
        return 0;

    if (def->keywrap->aes == VIR_TRISTATE_SWITCH_ABSENT &&
        def->keywrap->dea == VIR_TRISTATE_SWITCH_ABSENT)
        return 0;

    if (def->os.arch != VIR_ARCH_S390 &&
        def->os.arch != VIR_ARCH_S390X) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'aes-key-wrap'/'dea-key-wrap' is not available on this architecture"));
        return -1;
    }

    if (def->keywrap->aes != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, ",aes-key-wrap=%s",
                          virTristateSwitchTypeToString(def->keywrap->aes));

    if (def->keywrap->dea != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, ",dea-key-wrap=%s",
                          virTristateSwitchTypeToString(def->keywrap->dea));

    return 0;
}


static void
qemuAppendLoadparmMachineParm(virBuffer *buf,
                              const virDomainDef *def)
{
    size_t i = 0;

    if (def->os.arch != VIR_ARCH_S390 &&
        def->os.arch != VIR_ARCH_S390X)
        return;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];

        if (disk->info.bootIndex == 1 && disk->info.loadparm) {
            virBufferAsprintf(buf, ",loadparm=%s", disk->info.loadparm);
            return;
        }
    }

    /* Network boot device */
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];

        if (net->info.bootIndex == 1 && net->info.loadparm) {
            virBufferAsprintf(buf, ",loadparm=%s", net->info.loadparm);
            return;
        }
    }

    for (i = 0; i< def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        virDomainHostdevSubsys *subsys = &hostdev->source.subsys;
        virDomainHostdevSubsysMediatedDev *mdevsrc = &subsys->u.mdev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;

        /* Only get the load parameter from a bootable disk */
        if (subsys->type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV &&
            subsys->type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        /* For MDEV hostdevs, only CCW types are bootable */
        if (subsys->type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV &&
            mdevsrc->model != VIR_MDEV_MODEL_TYPE_VFIO_CCW)
            continue;

        if (hostdev->info->bootIndex == 1 && hostdev->info->loadparm) {
            virBufferAsprintf(buf, ",loadparm=%s", hostdev->info->loadparm);
            return;
        }
    }
}


static int
qemuBuildNameCommandLine(virCommand *cmd,
                         virQEMUDriverConfig *cfg,
                         const virDomainDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCommandAddArg(cmd, "-name");

    /* The 'guest' option let's us handle a name with '=' embedded in it */
    virBufferAddLit(&buf, "guest=");
    virQEMUBuildBufferEscapeComma(&buf, def->name);

    if (cfg->setProcessName)
        virBufferAsprintf(&buf, ",process=qemu:%s", def->name);

    virBufferAddLit(&buf, ",debug-threads=on");

    virCommandAddArgBuffer(cmd, &buf);

    return 0;
}


static int
qemuAppendDomainFeaturesMachineParam(virBuffer *buf,
                                     const virDomainDef *def,
                                     virQEMUCaps *qemuCaps)
{
    virTristateSwitch vmport = def->features[VIR_DOMAIN_FEATURE_VMPORT];
    virTristateSwitch smm = def->features[VIR_DOMAIN_FEATURE_SMM];

    if (vmport != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, ",vmport=%s",
                          virTristateSwitchTypeToString(vmport));

    if (smm != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, ",smm=%s", virTristateSwitchTypeToString(smm));

    if (def->features[VIR_DOMAIN_FEATURE_GIC] == VIR_TRISTATE_SWITCH_ON) {
        bool hasGICVersionOption = virQEMUCapsGetArch(qemuCaps) == VIR_ARCH_AARCH64;

        switch ((virGICVersion) def->gic_version) {
        case VIR_GIC_VERSION_2:
            if (!hasGICVersionOption) {
                /* If the gic-version option is not available, we can't
                 * configure the GIC; however, we know that before the
                 * option was introduced the guests would always get a
                 * GICv2, so in order to maintain compatibility with
                 * those old QEMU versions all we need to do is stop
                 * early instead of erroring out */
                break;
            }
            G_GNUC_FALLTHROUGH;

        case VIR_GIC_VERSION_3:
        case VIR_GIC_VERSION_HOST:
            if (!hasGICVersionOption) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("gic-version option is not available with this QEMU binary"));
                return -1;
            }

            virBufferAsprintf(buf, ",gic-version=%s",
                              virGICVersionTypeToString(def->gic_version));
            break;

        case VIR_GIC_VERSION_NONE:
        case VIR_GIC_VERSION_LAST:
        default:
            break;
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_IOAPIC] != VIR_DOMAIN_IOAPIC_NONE) {
        switch ((virDomainIOAPIC) def->features[VIR_DOMAIN_FEATURE_IOAPIC]) {
        case VIR_DOMAIN_IOAPIC_QEMU:
            virBufferAddLit(buf, ",kernel_irqchip=split");
            break;
        case VIR_DOMAIN_IOAPIC_KVM:
            virBufferAddLit(buf, ",kernel_irqchip=on");
            break;
        case VIR_DOMAIN_IOAPIC_NONE:
        case VIR_DOMAIN_IOAPIC_LAST:
            break;
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_HPT] == VIR_TRISTATE_SWITCH_ON) {

        if (def->hpt_resizing != VIR_DOMAIN_HPT_RESIZING_NONE) {
            virBufferAsprintf(buf, ",resize-hpt=%s",
                              virDomainHPTResizingTypeToString(def->hpt_resizing));
        }

        if (def->hpt_maxpagesize > 0) {
            virBufferAsprintf(buf, ",cap-hpt-max-page-size=%lluk",
                              def->hpt_maxpagesize);
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_HTM] != VIR_TRISTATE_SWITCH_ABSENT) {
        const char *str;
        str = virTristateSwitchTypeToString(def->features[VIR_DOMAIN_FEATURE_HTM]);
        virBufferAsprintf(buf, ",cap-htm=%s", str);
    }

    if (def->features[VIR_DOMAIN_FEATURE_NESTED_HV] != VIR_TRISTATE_SWITCH_ABSENT) {
        const char *str;
        str = virTristateSwitchTypeToString(def->features[VIR_DOMAIN_FEATURE_NESTED_HV]);
        virBufferAsprintf(buf, ",cap-nested-hv=%s", str);
    }

    if (def->features[VIR_DOMAIN_FEATURE_CCF_ASSIST] != VIR_TRISTATE_SWITCH_ABSENT) {
        const char *str;
        str = virTristateSwitchTypeToString(def->features[VIR_DOMAIN_FEATURE_CCF_ASSIST]);
        virBufferAsprintf(buf, ",cap-ccf-assist=%s", str);
    }

    if (def->features[VIR_DOMAIN_FEATURE_CFPC] != VIR_DOMAIN_CFPC_NONE) {
        const char *str = virDomainCFPCTypeToString(def->features[VIR_DOMAIN_FEATURE_CFPC]);
        virBufferAsprintf(buf, ",cap-cfpc=%s", str);
    }

    if (def->features[VIR_DOMAIN_FEATURE_SBBC] != VIR_DOMAIN_SBBC_NONE) {
        const char *str = virDomainSBBCTypeToString(def->features[VIR_DOMAIN_FEATURE_SBBC]);
        virBufferAsprintf(buf, ",cap-sbbc=%s", str);
    }

    if (def->features[VIR_DOMAIN_FEATURE_IBS] != VIR_DOMAIN_IBS_NONE) {
        const char *str = virDomainIBSTypeToString(def->features[VIR_DOMAIN_FEATURE_IBS]);
        virBufferAsprintf(buf, ",cap-ibs=%s", str);
    }

    return 0;
}


static int
qemuAppendDomainMemoryMachineParams(virBuffer *buf,
                                    virQEMUDriverConfig *cfg,
                                    const virDomainDef *def,
                                    virQEMUCaps *qemuCaps)
{
    virTristateSwitch dump = def->mem.dump_core;
    bool nvdimmAdded = false;
    int epcNum = 0;
    size_t i;

    if (dump == VIR_TRISTATE_SWITCH_ABSENT)
        dump = virTristateSwitchFromBool(cfg->dumpGuestCore);

    virBufferAsprintf(buf, ",dump-guest-core=%s", virTristateSwitchTypeToString(dump));

    if (def->mem.nosharepages)
        virBufferAddLit(buf, ",mem-merge=off");

    for (i = 0; i < def->nmems; i++) {
        int targetNode = def->mems[i]->targetNode;

        switch (def->mems[i]->model) {
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
            if (!nvdimmAdded) {
                virBufferAddLit(buf, ",nvdimm=on");
                nvdimmAdded = true;
            }
            break;

        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
            /* add sgx epc memory to -machine parameter */

            if (targetNode < 0) {
                /* set NUMA target node to 0 by default if user doesn't
                 * specify it. */
                targetNode = 0;
            }

            virBufferAsprintf(buf, ",sgx-epc.%d.memdev=mem%s,sgx-epc.%d.node=%d",
                              epcNum, def->mems[i]->info.alias, epcNum, targetNode);

            epcNum++;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            break;
        }
    }

    if (!virDomainNumaGetNodeCount(def->numa)) {
        const char *defaultRAMid = NULL;

        /* QEMU is obsoleting -mem-path and -mem-prealloc. That means we have
         * to switch to memory-backend-* even for regular RAM and to keep
         * domain migratable we have to set the same ID as older QEMUs would.
         * If domain has no NUMA nodes and QEMU is new enough to expose ID of
         * the default RAM we want to use it for default RAM (construct
         * memory-backend-* with corresponding attributes instead of obsolete
         * -mem-path and -mem-prealloc).
         * This generates only reference for the memory-backend-* object added
         * later in qemuBuildMemCommandLine() */
        defaultRAMid = virQEMUCapsGetMachineDefaultRAMid(qemuCaps,
                                                         def->virtType,
                                                         def->os.machine);
        if (defaultRAMid)
            virBufferAsprintf(buf, ",memory-backend=%s", defaultRAMid);
    }

    return 0;
}


/**
 * qemuBuildMachineACPI:
 * @machineOptsBuf: buffer for formatting argument of '-machine'
 * @def: domain definition
 * @qemuCaps: qemu capabilities object
 *
 * Logic for formatting the 'acpi=' parameter for '-machine'. See comments below
 */
static void
qemuBuildMachineACPI(virBuffer *machineOptsBuf,
                     const virDomainDef *def,
                     virQEMUCaps *qemuCaps)
{
    virTristateSwitch defACPI = def->features[VIR_DOMAIN_FEATURE_ACPI];

    /* We format this field only when qemu reports that the current machine
     * type supports ACPI in 'query-machines' */
    if (virQEMUCapsMachineSupportsACPI(qemuCaps, def->virtType, def->os.machine) != VIR_TRISTATE_BOOL_YES)
        return;

    /* Historically ACPI is configured by the presence or absence of the
     * '<acpi/>' element without any property. The conf code thus allows only
     * VIR_TRISTATE_SWITCH_ON and VIR_TRISTATE_SWITCH_ABSENT as values.
     *
     * Convert VIR_TRISTATE_SWITCH_ABSENT to VIR_TRISTATE_SWITCH_OFF.
     */
    if (defACPI == VIR_TRISTATE_SWITCH_ABSENT)
        defACPI = VIR_TRISTATE_SWITCH_OFF;

    virBufferAsprintf(machineOptsBuf, ",acpi=%s",
                      virTristateSwitchTypeToString(defACPI));
}


static int
qemuBuildMachineCommandLine(virCommand *cmd,
                            virQEMUDriverConfig *cfg,
                            const virDomainDef *def,
                            virQEMUCaps *qemuCaps,
                            qemuDomainObjPrivate *priv)
{
    virCPUDef *cpu = def->cpu;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virCommandAddArg(cmd, "-machine");
    virBufferAdd(&buf, def->os.machine, -1);

    /* To avoid the collision of creating USB controllers when calling
     * machine->init in QEMU, it needs to set usb=off
     */
    virBufferAddLit(&buf, ",usb=off");

    if (qemuAppendKeyWrapMachineParms(&buf, def) < 0)
        return -1;

    if (qemuAppendDomainFeaturesMachineParam(&buf, def, qemuCaps) < 0)
        return -1;

    if (def->iommu) {
        switch (def->iommu->model) {
        case VIR_DOMAIN_IOMMU_MODEL_SMMUV3:
            virBufferAddLit(&buf, ",iommu=smmuv3");
            break;

        case VIR_DOMAIN_IOMMU_MODEL_INTEL:
        case VIR_DOMAIN_IOMMU_MODEL_VIRTIO:
            /* These IOMMUs are formatted in qemuBuildIOMMUCommandLine */
            break;

        case VIR_DOMAIN_IOMMU_MODEL_LAST:
        default:
            virReportEnumRangeError(virDomainIOMMUModel, def->iommu->model);
            return -1;
        }
    }

    if (qemuAppendDomainMemoryMachineParams(&buf, cfg, def, qemuCaps) < 0)
        return -1;

    if (cpu && cpu->model &&
        cpu->mode == VIR_CPU_MODE_HOST_MODEL &&
        qemuDomainIsPSeries(def)) {
        virBufferAsprintf(&buf, ",max-cpu-compat=%s", cpu->model);
    }

    qemuAppendLoadparmMachineParm(&buf, def);

    if (def->sec) {
        switch ((virDomainLaunchSecurity) def->sec->sectype) {
        case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_CONFIDENTAL_GUEST_SUPPORT)) {
                virBufferAddLit(&buf, ",confidential-guest-support=lsec0");
            } else {
                virBufferAddLit(&buf, ",memory-encryption=lsec0");
            }
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_PV:
            virBufferAddLit(&buf, ",confidential-guest-support=lsec0");
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
        case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
            virReportEnumRangeError(virDomainLaunchSecurity, def->sec->sectype);
            return -1;
        }
    }

    if (virDomainDefHasOldStyleUEFI(def)) {
        if (priv->pflash0)
            virBufferAsprintf(&buf, ",pflash0=%s",
                              qemuBlockStorageSourceGetEffectiveNodename(priv->pflash0));
        if (def->os.loader->nvram)
            virBufferAsprintf(&buf, ",pflash1=%s",
                              qemuBlockStorageSourceGetEffectiveNodename(def->os.loader->nvram));
    }

    if (virDomainNumaHasHMAT(def->numa))
        virBufferAddLit(&buf, ",hmat=on");

    /* On x86 targets, graphics=off activates the serial console
     * output mode in the firmware. On non-x86 targets it has
     * various other undesirable effects that we certainly do
     * not want to have. We rely on the validation code to have
     * blocked useserial=yes on non-x86
     */
    if (def->os.bios.useserial == VIR_TRISTATE_BOOL_YES) {
        virBufferAddLit(&buf, ",graphics=off");
    }

    for (i = 0; i < def->clock.ntimers; i++) {
        switch ((virDomainTimerNameType)def->clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_HPET:
            /* qemuBuildClockCommandLine handles the old-style config via '-no-hpet' */
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_HPET) &&
                def->clock.timers[i]->present != VIR_TRISTATE_BOOL_ABSENT) {
                virBufferAsprintf(&buf, ",hpet=%s",
                                  virTristateSwitchTypeToString(def->clock.timers[i]->present));
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_TSC:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        }
    }

    /* PC speaker is a bit different than the rest of sound cards
     * which are handled in qemuBuildSoundCommandLine(). */
    for (i = 0; i < def->nsounds; i++) {
        const virDomainSoundDef *sound = def->sounds[i];
        g_autofree char *audioid = NULL;

        if (sound->model != VIR_DOMAIN_SOUND_MODEL_PCSPK)
            continue;

        if (!(audioid = qemuGetAudioIDString(def, sound->audioId)))
            return -1;

        virBufferAsprintf(&buf, ",pcspk-audiodev=%s", audioid);
        break;
    }

    qemuBuildMachineACPI(&buf, def, qemuCaps);

    virCommandAddArgBuffer(cmd, &buf);

    return 0;
}


static void
qemuBuildAccelCommandLine(virCommand *cmd,
                          const virDomainDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCommandAddArg(cmd, "-accel");

    switch ((virDomainVirtType)def->virtType) {
    case VIR_DOMAIN_VIRT_QEMU:
        virBufferAddLit(&buf, "tcg");

        if (def->features[VIR_DOMAIN_FEATURE_TCG] == VIR_TRISTATE_SWITCH_ON &&
            def->tcg_features->tb_cache > 0) {
            virBufferAsprintf(&buf, ",tb-size=%llu",
                              def->tcg_features->tb_cache >> 10);
        }
        break;

    case VIR_DOMAIN_VIRT_KVM:
        virBufferAddLit(&buf, "kvm");
        /*
         * only handle the kvm case, tcg case use the legacy style
         * not that either kvm or tcg can be specified by libvirt
         * so do not worry about the conflict of specifying both
         * */
        if (def->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON &&
            def->kvm_features->features[VIR_DOMAIN_KVM_DIRTY_RING] == VIR_TRISTATE_SWITCH_ON) {
            virBufferAsprintf(&buf, ",dirty-ring-size=%d", def->kvm_features->dirty_ring_size);
        }
        break;

    case VIR_DOMAIN_VIRT_HVF:
        virBufferAddLit(&buf, "hvf");
        break;

    case VIR_DOMAIN_VIRT_KQEMU:
    case VIR_DOMAIN_VIRT_XEN:
    case VIR_DOMAIN_VIRT_LXC:
    case VIR_DOMAIN_VIRT_UML:
    case VIR_DOMAIN_VIRT_OPENVZ:
    case VIR_DOMAIN_VIRT_TEST:
    case VIR_DOMAIN_VIRT_VMWARE:
    case VIR_DOMAIN_VIRT_HYPERV:
    case VIR_DOMAIN_VIRT_VBOX:
    case VIR_DOMAIN_VIRT_PHYP:
    case VIR_DOMAIN_VIRT_PARALLELS:
    case VIR_DOMAIN_VIRT_BHYVE:
    case VIR_DOMAIN_VIRT_VZ:
    case VIR_DOMAIN_VIRT_NONE:
    case VIR_DOMAIN_VIRT_LAST:
        break;
    }

    virCommandAddArgBuffer(cmd, &buf);
}


static void
qemuBuildTSEGCommandLine(virCommand *cmd,
                         const virDomainDef *def)
{
    if (!def->tseg_specified)
        return;

    virCommandAddArg(cmd, "-global");

    /* PostParse callback guarantees that the size is divisible by 1 MiB */
    virCommandAddArgFormat(cmd, "mch.extended-tseg-mbytes=%llu",
                           def->tseg_size >> 20);
}


static int
qemuBuildSmpCommandLine(virCommand *cmd,
                        virDomainDef *def,
                        virQEMUCaps *qemuCaps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(def);
    unsigned int nvcpus = 0;
    virDomainVcpuDef *vcpu;
    size_t i;

    /* count non-hotpluggable enabled vcpus. Hotpluggable ones will be added
     * in a different way */
    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);
        if (vcpu->online && vcpu->hotpluggable == VIR_TRISTATE_BOOL_NO)
            nvcpus++;
    }

    virCommandAddArg(cmd, "-smp");

    virBufferAsprintf(&buf, "%u", nvcpus);

    if (nvcpus != maxvcpus)
        virBufferAsprintf(&buf, ",maxcpus=%u", maxvcpus);
    /* sockets, cores, and threads are either all zero
     * or all non-zero, thus checking one of them is enough */
    if (def->cpu && def->cpu->sockets) {
        if (def->cpu->dies != 1 && !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMP_DIES)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only 1 die per socket is supported"));
            return -1;
        }
        virBufferAsprintf(&buf, ",sockets=%u", def->cpu->sockets);
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMP_DIES))
            virBufferAsprintf(&buf, ",dies=%u", def->cpu->dies);
        virBufferAsprintf(&buf, ",cores=%u", def->cpu->cores);
        virBufferAsprintf(&buf, ",threads=%u", def->cpu->threads);
    } else {
        virBufferAsprintf(&buf, ",sockets=%u", virDomainDefGetVcpusMax(def));
        virBufferAsprintf(&buf, ",cores=%u", 1);
        virBufferAsprintf(&buf, ",threads=%u", 1);
    }

    virCommandAddArgBuffer(cmd, &buf);
    return 0;
}


static int
qemuBuildMemPathStr(const virDomainDef *def,
                    virCommand *cmd,
                    qemuDomainObjPrivate *priv)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    const long system_page_size = virGetSystemPageSizeKB();
    g_autofree char *mem_path = NULL;
    bool prealloc = false;

    /* There are two cases where we want to put -mem-path onto
     * the command line: First one is when there are no guest
     * NUMA nodes and hugepages are configured. The second one is
     * if user requested file allocation. */
    if (def->mem.nhugepages &&
        def->mem.hugepages[0].size != system_page_size) {
        unsigned long long pagesize = def->mem.hugepages[0].size;
        if (!pagesize &&
            qemuBuildMemoryGetDefaultPagesize(cfg, &pagesize) < 0)
            return -1;
        if (qemuGetDomainHupageMemPath(priv->driver, def, pagesize, &mem_path) < 0)
            return -1;
        prealloc = true;
    } else if (def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_FILE) {
        if (qemuGetMemoryBackingPath(priv->driver, def, "ram", &mem_path) < 0)
            return -1;
    }

    if (def->mem.allocation == VIR_DOMAIN_MEMORY_ALLOCATION_IMMEDIATE)
        prealloc = true;

    if (prealloc && !priv->memPrealloc) {
        virCommandAddArgList(cmd, "-mem-prealloc", NULL);
        priv->memPrealloc = true;
    }

    if (mem_path)
        virCommandAddArgList(cmd, "-mem-path", mem_path, NULL);

    return 0;
}


static int
qemuBuildMemCommandLineMemoryDefaultBackend(virCommand *cmd,
                                            const virDomainDef *def,
                                            qemuDomainObjPrivate *priv,
                                            const char *defaultRAMid)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    g_autoptr(virJSONValue) props = NULL;
    g_autoptr(virJSONValue) tcProps = NULL;
    virBitmap *nodemask = NULL;
    virDomainMemoryDef mem = { 0 };

    mem.size = virDomainDefGetMemoryInitial(def);
    mem.targetNode = -1;
    mem.info.alias = (char *) defaultRAMid;

    if (qemuBuildMemoryBackendProps(&props, defaultRAMid, cfg, priv,
                                    def, &mem, false, true, &nodemask) < 0)
        return -1;

    if (qemuBuildThreadContextProps(&tcProps, &props, def, priv, nodemask) < 0)
        return -1;

    if (tcProps &&
        qemuBuildObjectCommandlineFromJSON(cmd, tcProps,
                                           priv->qemuCaps) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildMemCommandLine(virCommand *cmd,
                        const virDomainDef *def,
                        virQEMUCaps *qemuCaps,
                        qemuDomainObjPrivate *priv)
{
    const char *defaultRAMid = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned long long memsize = virDomainDefGetMemoryInitial(def);

    virCommandAddArg(cmd, "-m");

    /* Without memory hotplug we've historically supplied the memory size in
     * mebibytes to qemu. Since the code will now use kibibytes we need to round
     * it here too. */
    if (!virDomainDefHasMemoryHotplug(def))
        memsize &= ~0x1FF;

    virBufferAsprintf(&buf, "size=%lluk", memsize);

    if (virDomainDefHasMemoryHotplug(def)) {
        if (def->mem.memory_slots > 0)
            virBufferAsprintf(&buf, ",slots=%u", def->mem.memory_slots);

        if (def->mem.max_memory > 0)
            virBufferAsprintf(&buf, ",maxmem=%lluk", def->mem.max_memory);
    }

    virCommandAddArgBuffer(cmd, &buf);

    defaultRAMid = virQEMUCapsGetMachineDefaultRAMid(qemuCaps,
                                                     def->virtType,
                                                     def->os.machine);

    if (defaultRAMid) {
        /* As documented in qemuBuildMachineCommandLine() if QEMU is new enough
         * to expose default RAM ID we must use memory-backend-* even for
         * regular memory because -mem-path and -mem-prealloc are obsolete.
         * However, if domain has one or more NUMA nodes then there is no
         * default RAM and we mustn't generate the memory object. */
        if (!virDomainNumaGetNodeCount(def->numa) &&
            qemuBuildMemCommandLineMemoryDefaultBackend(cmd, def, priv, defaultRAMid) < 0)
            return -1;
    } else {
        /*
         * Add '-mem-path' (and '-mem-prealloc') parameter here if
         * the hugepages and no numa node is specified.
         */
        if (!virDomainNumaGetNodeCount(def->numa) &&
            qemuBuildMemPathStr(def, cmd, priv) < 0)
            return -1;
    }

    virCommandAddArg(cmd, "-overcommit");
    virCommandAddArgFormat(cmd, "mem-lock=%s", def->mem.locked ? "on" : "off");

    return 0;
}


static int
qemuBuildIOThreadCommandLine(virCommand *cmd,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->niothreadids; i++) {
        g_autoptr(virJSONValue) props = NULL;
        const virDomainIOThreadIDDef *iothread = def->iothreadids[i];
        g_autofree char *alias = NULL;

        alias = g_strdup_printf("iothread%u", iothread->iothread_id);

        if (qemuMonitorCreateObjectProps(&props, "iothread", alias,
                                         "k:thread-pool-min", iothread->thread_pool_min,
                                         "k:thread-pool-max", iothread->thread_pool_max,
                                         NULL) < 0)
            return -1;

        if (iothread->set_poll_max_ns &&
            virJSONValueObjectAdd(&props,
                                  "U:poll-max-ns", iothread->poll_max_ns,
                                  NULL) < 0)
            return -1;

        if (iothread->set_poll_grow &&
            virJSONValueObjectAdd(&props,
                                  "U:poll-grow", iothread->poll_grow,
                                  NULL) < 0)
            return -1;

        if (iothread->set_poll_shrink &&
            virJSONValueObjectAdd(&props,
                                  "U:poll-shrink", iothread->poll_shrink,
                                  NULL) < 0)
            return -1;

        if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
            return -1;
    }

    if (def->defaultIOThread) {
        g_autoptr(virJSONValue) props = NULL;

        if (qemuMonitorCreateObjectProps(&props, "main-loop", "main-loop",
                                         "k:thread-pool-min", def->defaultIOThread->thread_pool_min,
                                         "k:thread-pool-max", def->defaultIOThread->thread_pool_max,
                                         NULL) < 0)
            return -1;

        if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildNumaCellCache(virCommand *cmd,
                       const virDomainDef *def,
                       size_t cell)
{
    size_t ncaches = virDomainNumaGetNodeCacheCount(def->numa, cell);
    size_t i;

    if (ncaches == 0)
        return 0;

    for (i = 0; i < ncaches; i++) {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        unsigned int level;
        unsigned int size;
        unsigned int line;
        virNumaCacheAssociativity associativity;
        virNumaCachePolicy policy;

        if (virDomainNumaGetNodeCache(def->numa, cell, i,
                                      &level, &size, &line,
                                      &associativity, &policy) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to format NUMA node cache"));
            return -1;
        }

        virBufferAsprintf(&buf,
                          "hmat-cache,node-id=%zu,size=%uK,level=%u",
                          cell, size, level);

        switch (associativity) {
        case VIR_NUMA_CACHE_ASSOCIATIVITY_NONE:
            virBufferAddLit(&buf, ",associativity=none");
            break;
        case VIR_NUMA_CACHE_ASSOCIATIVITY_DIRECT:
            virBufferAddLit(&buf, ",associativity=direct");
            break;
        case VIR_NUMA_CACHE_ASSOCIATIVITY_FULL:
            virBufferAddLit(&buf, ",associativity=complex");
            break;
        case VIR_NUMA_CACHE_ASSOCIATIVITY_LAST:
            break;
        }

        switch (policy) {
        case VIR_NUMA_CACHE_POLICY_NONE:
            virBufferAddLit(&buf, ",policy=none");
            break;
        case VIR_NUMA_CACHE_POLICY_WRITEBACK:
            virBufferAddLit(&buf, ",policy=write-back");
            break;
        case VIR_NUMA_CACHE_POLICY_WRITETHROUGH:
            virBufferAddLit(&buf, ",policy=write-through");
            break;
        case VIR_NUMA_CACHE_POLICY_LAST:
            break;
        }

        if (line > 0)
            virBufferAsprintf(&buf, ",line=%u", line);

        virCommandAddArg(cmd, "-numa");
        virCommandAddArgBuffer(cmd, &buf);
    }

    return 0;
}


VIR_ENUM_DECL(qemuDomainMemoryHierarchy);
VIR_ENUM_IMPL(qemuDomainMemoryHierarchy,
              4, /* Maximum level of cache */
              "memory", /* Special case, whole memory not specific cache */
              "first-level",
              "second-level",
              "third-level");

static int
qemuBuildNumaHMATCommandLine(virCommand *cmd,
                             const virDomainDef *def)
{
    size_t nlatencies;
    size_t i;

    if (!def->numa)
        return 0;

    nlatencies = virDomainNumaGetInterconnectsCount(def->numa);
    for (i = 0; i < nlatencies; i++) {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        virNumaInterconnectType type;
        unsigned int initiator;
        unsigned int target;
        unsigned int cache;
        virMemoryLatency accessType;
        unsigned long value;
        const char *hierarchyStr;
        const char *accessStr;

        if (virDomainNumaGetInterconnect(def->numa, i,
                                         &type, &initiator, &target,
                                         &cache, &accessType, &value) < 0)
            return -1;

        hierarchyStr = qemuDomainMemoryHierarchyTypeToString(cache);
        accessStr = virMemoryLatencyTypeToString(accessType);
        virBufferAsprintf(&buf,
                          "hmat-lb,initiator=%u,target=%u,hierarchy=%s,data-type=%s-",
                          initiator, target, hierarchyStr, accessStr);

        switch (type) {
        case VIR_NUMA_INTERCONNECT_TYPE_LATENCY:
            virBufferAsprintf(&buf, "latency,latency=%lu", value);
            break;
        case VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH:
            virBufferAsprintf(&buf, "bandwidth,bandwidth=%luK", value);
            break;
        }

        virCommandAddArg(cmd, "-numa");
        virCommandAddArgBuffer(cmd, &buf);
    }

    return 0;
}


static int
qemuBuildNumaCPUs(virBuffer *buf,
                  virBitmap *cpu)
{
    g_autofree char *cpumask = NULL;
    char *tmpmask = NULL;
    char *next = NULL;

    if (!cpu)
        return 0;

    if (!(cpumask = virBitmapFormat(cpu)))
        return -1;

    for (tmpmask = cpumask; tmpmask; tmpmask = next) {
        if ((next = strchr(tmpmask, ',')))
            *(next++) = '\0';
        virBufferAddLit(buf, ",cpus=");
        virBufferAdd(buf, tmpmask, -1);
    }

    return 0;
}


static int
qemuBuildNumaCommandLine(virQEMUDriverConfig *cfg,
                         virDomainDef *def,
                         virCommand *cmd,
                         qemuDomainObjPrivate *priv)
{
    size_t i, j;
    virQEMUCaps *qemuCaps = priv->qemuCaps;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virJSONValue **nodeBackends = NULL;
    g_autofree virBitmap **nodemask = NULL;
    bool needBackend = false;
    bool hmat = false;
    int ret = -1;
    size_t ncells = virDomainNumaGetNodeCount(def->numa);
    ssize_t masterInitiator = -1;
    int rc;

    if (!virDomainNumatuneNodesetIsAvailable(def->numa, priv->autoNodeset))
        goto cleanup;

    if (!virQEMUCapsGetMachineNumaMemSupported(qemuCaps,
                                               def->virtType,
                                               def->os.machine))
        needBackend = true;

    if (virDomainNumaHasHMAT(def->numa)) {
        needBackend = true;
        hmat = true;
    }

    nodeBackends = g_new0(virJSONValue *, ncells);
    nodemask = g_new0(virBitmap *, ncells);

    for (i = 0; i < ncells; i++) {
        if ((rc = qemuBuildMemoryCellBackendProps(def, cfg, i, priv,
                                                  &nodeBackends[i],
                                                  &nodemask[i])) < 0)
            goto cleanup;

        if (rc == 0)
            needBackend = true;
    }

    if (!needBackend &&
        qemuBuildMemPathStr(def, cmd, priv) < 0)
        goto cleanup;

    for (i = 0; i < ncells; i++) {
        if (virDomainNumaGetNodeCpumask(def->numa, i)) {
            masterInitiator = i;
            break;
        }
    }

    if (masterInitiator < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("At least one NUMA node has to have CPUs"));
        goto cleanup;
    }

    for (i = 0; i < ncells; i++) {
        ssize_t initiator = virDomainNumaGetNodeInitiator(def->numa, i);

        if (needBackend) {
            g_autoptr(virJSONValue) tcProps = NULL;

            if (qemuBuildThreadContextProps(&tcProps, &nodeBackends[i],
                                            def, priv, nodemask[i]) < 0)
                goto cleanup;

            if (tcProps &&
                qemuBuildObjectCommandlineFromJSON(cmd, tcProps,
                                                   priv->qemuCaps) < 0)
                goto cleanup;

            if (qemuBuildObjectCommandlineFromJSON(cmd, nodeBackends[i],
                                                   priv->qemuCaps) < 0)
                goto cleanup;
        }

        virCommandAddArg(cmd, "-numa");
        virBufferAsprintf(&buf, "node,nodeid=%zu", i);

        if (qemuBuildNumaCPUs(&buf, virDomainNumaGetNodeCpumask(def->numa, i)) < 0)
            goto cleanup;

        if (hmat) {
            if (initiator < 0)
                initiator = masterInitiator;

            virBufferAsprintf(&buf, ",initiator=%zd", initiator);
        }

        if (needBackend)
            virBufferAsprintf(&buf, ",memdev=ram-node%zu", i);
        else
            virBufferAsprintf(&buf, ",mem=%llu",
                              virDomainNumaGetNodeMemorySize(def->numa, i) / 1024);

        virCommandAddArgBuffer(cmd, &buf);
    }

    /* If NUMA node distance is specified for at least one pair
     * of nodes, we have to specify all the distances. Even
     * though they might be the default ones. */
    if (virDomainNumaNodesDistancesAreBeingSet(def->numa)) {
        for (i = 0; i < ncells; i++) {
            for (j = 0; j < ncells; j++) {
                size_t distance = virDomainNumaGetNodeDistance(def->numa, i, j);

                virCommandAddArg(cmd, "-numa");
                virBufferAsprintf(&buf, "dist,src=%zu,dst=%zu,val=%zu", i, j, distance);

                virCommandAddArgBuffer(cmd, &buf);
            }
        }
    }

    if (hmat) {
        if (qemuBuildNumaHMATCommandLine(cmd, def) < 0)
            goto cleanup;

        /* This can't be moved into any of the loops above,
         * because hmat-cache can be specified only after hmat-lb. */
        for (i = 0; i < ncells; i++) {
            if (qemuBuildNumaCellCache(cmd, def, i) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (nodeBackends) {
        for (i = 0; i < ncells; i++)
            virJSONValueFree(nodeBackends[i]);

        VIR_FREE(nodeBackends);
    }

    return ret;
}


static int
qemuBuildMemoryDeviceCommandLine(virCommand *cmd,
                                 virQEMUDriverConfig *cfg,
                                 virDomainDef *def,
                                 qemuDomainObjPrivate *priv)
{
    size_t i;

    /* memory hotplug requires NUMA to be enabled - we already checked
     * that memory devices are present only when NUMA is */
    for (i = 0; i < def->nmems; i++) {
        g_autoptr(virJSONValue) props = NULL;

        if (qemuBuildMemoryDimmBackendStr(cmd, def->mems[i], def, cfg, priv) < 0)
            return -1;

        switch (def->mems[i]->model) {
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
            if (!(props = qemuBuildMemoryDeviceProps(cfg, priv, def, def->mems[i])))
                return -1;

            if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, priv->qemuCaps) < 0)
                return -1;

            break;

        /* sgx epc memory will be added to -machine parameter, so skip here */
        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuBuildAudioCommonProps(virDomainAudioIOCommon *def,
                          virJSONValue **props)
{
    unsigned int frequency = 0;
    unsigned int channels = 0;
    const char *format = NULL;

    if (def->fixedSettings == VIR_TRISTATE_BOOL_YES) {
        frequency = def->frequency;
        channels = def->channels;
        if (def->format != VIR_DOMAIN_AUDIO_FORMAT_DEFAULT)
            format = virDomainAudioFormatTypeToString(def->format);
    }

    return virJSONValueObjectAdd(props,
                                 "T:mixing-engine", def->mixingEngine,
                                 "T:fixed-settings", def->fixedSettings,
                                 "p:voices", def->voices,
                                 "p:buffer-length", def->bufferLength,
                                 "p:frequency", frequency,
                                 "p:channels", channels,
                                 "S:format", format,
                                 NULL);
}


static int
qemuBuildAudioALSAProps(virDomainAudioIOALSA *def,
                        virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "S:dev", def->dev,
                                 NULL);
}


static int
qemuBuildAudioCoreAudioProps(virDomainAudioIOCoreAudio *def,
                             virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "p:buffer-count", def->bufferCount,
                                 NULL);
}


static int
qemuBuildAudioJackProps(virDomainAudioIOJack *def,
                        virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "S:server-name", def->serverName,
                                 "S:client-name", def->clientName,
                                 "S:connect-ports", def->connectPorts,
                                 "T:exact-name", def->exactName,
                                 NULL);
}


static int
qemuBuildAudioOSSProps(virDomainAudioIOOSS *def,
                       virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "S:dev", def->dev,
                                 "p:buffer-count", def->bufferCount,
                                 "T:try-poll", def->tryPoll,
                                 NULL);
}


static int
qemuBuildAudioPulseAudioProps(virDomainAudioIOPulseAudio *def,
                              virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "S:name", def->name,
                                 "S:stream-name", def->streamName,
                                 "p:latency", def->latency,
                                 NULL);
}


static int
qemuBuildAudioSDLProps(virDomainAudioIOSDL *def,
                       virJSONValue **props)
{
    return virJSONValueObjectAdd(props,
                                 "p:buffer-count", def->bufferCount,
                                 NULL);
}


static int
qemuBuildAudioCommandLineArg(virCommand *cmd,
                             virDomainAudioDef *def)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autoptr(virJSONValue) in = NULL;
    g_autoptr(virJSONValue) out = NULL;
    g_autofree char *propsstr = NULL;
    g_autofree char *alias = g_strdup_printf("audio%d", def->id);

    if (virJSONValueObjectAdd(&props,
                              "s:id", alias,
                              "s:driver", qemuAudioDriverTypeToString(def->type),
                              "p:timer-period", def->timerPeriod,
                              NULL) < 0)
        return -1;

    if (qemuBuildAudioCommonProps(&def->input, &in) < 0 ||
        qemuBuildAudioCommonProps(&def->output, &out) < 0)
        return -1;

    switch (def->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        if (qemuBuildAudioALSAProps(&def->backend.alsa.input, &in) < 0 ||
            qemuBuildAudioALSAProps(&def->backend.alsa.output, &out) < 0)
            return -1;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        if (qemuBuildAudioCoreAudioProps(&def->backend.coreaudio.input, &in) < 0 ||
            qemuBuildAudioCoreAudioProps(&def->backend.coreaudio.output, &out) < 0)
            return -1;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_JACK:
        if (qemuBuildAudioJackProps(&def->backend.jack.input, &in) < 0 ||
            qemuBuildAudioJackProps(&def->backend.jack.output, &out) < 0)
            return -1;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_OSS: {
        g_autoptr(virJSONValue) dspPolicy = NULL;

        if (def->backend.oss.dspPolicySet)
            dspPolicy = virJSONValueNewNumberInt(def->backend.oss.dspPolicy);

        if (qemuBuildAudioOSSProps(&def->backend.oss.input, &in) < 0 ||
            qemuBuildAudioOSSProps(&def->backend.oss.output, &out) < 0)
            return -1;

        if (virJSONValueObjectAdd(&props,
                                  "T:try-mmap", def->backend.oss.tryMMap,
                                  "T:exclusive", def->backend.oss.exclusive,
                                  "A:dsp-policy", &dspPolicy,
                                  NULL) < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        if (qemuBuildAudioPulseAudioProps(&def->backend.pulseaudio.input, &in) < 0 ||
            qemuBuildAudioPulseAudioProps(&def->backend.pulseaudio.output, &out) < 0)
            return -1;

        if (virJSONValueObjectAdd(&props,
                                  "S:server", def->backend.pulseaudio.serverName,
                                  NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SDL:
        if (qemuBuildAudioSDLProps(&def->backend.sdl.input, &in) < 0 ||
            qemuBuildAudioSDLProps(&def->backend.sdl.output, &out) < 0)
            return -1;

        if (def->backend.sdl.driver) {
            /*
             * Some SDL audio driver names are different on SDL 1.2
             * vs 2.0.  Given how old SDL 1.2 is, we're not going
             * make any attempt to support it here as it is unlikely
             * to have an real world users. We can assume libvirt
             * driver name strings match SDL 2.0 names.
             */
            virCommandAddEnvPair(cmd, "SDL_AUDIODRIVER",
                                 virDomainAudioSDLDriverTypeToString(
                                     def->backend.sdl.driver));
        }
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        if (virJSONValueObjectAdd(&props,
                                  "S:path", def->backend.file.path,
                                  NULL) < 0)
            return -1;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainAudioType, def->type);
        return -1;
    }

    if (virJSONValueObjectAdd(&props,
                              "A:in", &in,
                              "A:out", &out,
                              NULL) < 0)
        return -1;

    if (!(propsstr = virJSONValueToString(props, false)))
        return -1;

    virCommandAddArgList(cmd, "-audiodev", propsstr, NULL);
    return 0;
}

static int
qemuBuildAudioCommandLine(virCommand *cmd,
                          virDomainDef *def)
{
    size_t i;
    for (i = 0; i < def->naudios; i++) {
        if (qemuBuildAudioCommandLineArg(cmd, def->audios[i]) < 0)
            return -1;
    }
    return 0;
}


static int
qemuBuildGraphicsSDLCommandLine(virQEMUDriverConfig *cfg G_GNUC_UNUSED,
                                virCommand *cmd,
                                virQEMUCaps *qemuCaps G_GNUC_UNUSED,
                                virDomainGraphicsDef *graphics)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;

    if (graphics->data.sdl.xauth)
        virCommandAddEnvPair(cmd, "XAUTHORITY", graphics->data.sdl.xauth);
    if (graphics->data.sdl.display)
        virCommandAddEnvPair(cmd, "DISPLAY", graphics->data.sdl.display);
    if (graphics->data.sdl.fullscreen)
        virCommandAddArg(cmd, "-full-screen");

    virCommandAddArg(cmd, "-display");
    virBufferAddLit(&opt, "sdl");

    if (graphics->data.sdl.gl != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(&opt, ",gl=%s",
                          virTristateSwitchTypeToString(graphics->data.sdl.gl));

    virCommandAddArgBuffer(cmd, &opt);

    return 0;
}


static int
qemuBuildGraphicsVNCCommandLine(virQEMUDriverConfig *cfg,
                                const virDomainDef *def,
                                virCommand *cmd,
                                virQEMUCaps *qemuCaps,
                                virDomainGraphicsDef *graphics)
{
    g_autofree char *audioid = qemuGetAudioIDString(def, graphics->data.vnc.audioId);
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    virDomainGraphicsListenDef *glisten = NULL;
    bool escapeAddr;

    if (!audioid)
        return -1;

    if (!(glisten = virDomainGraphicsGetListen(graphics, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing listen element"));
        return -1;
    }

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
        virBufferAddLit(&opt, "vnc=unix:");
        virQEMUBuildBufferEscapeComma(&opt, glisten->socket);
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        if (!graphics->data.vnc.autoport &&
            (graphics->data.vnc.port < 5900 ||
             graphics->data.vnc.port > 65535)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc port must be in range [5900,65535]"));
            return -1;
        }

        if (glisten->address) {
            escapeAddr = strchr(glisten->address, ':') != NULL;
            if (escapeAddr)
                virBufferAsprintf(&opt, "[%s]", glisten->address);
            else
                virBufferAdd(&opt, glisten->address, -1);
        }
        virBufferAsprintf(&opt, ":%d",
                          graphics->data.vnc.port - 5900);

        if (graphics->data.vnc.websocket)
            virBufferAsprintf(&opt, ",websocket=%d", graphics->data.vnc.websocket);
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        virBufferAddLit(&opt, "none");
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        break;
    }

    if (graphics->data.vnc.sharePolicy) {
        virBufferAsprintf(&opt, ",share=%s",
                          virDomainGraphicsVNCSharePolicyTypeToString(
                              graphics->data.vnc.sharePolicy));
    }

    if (graphics->data.vnc.auth.passwd || cfg->vncPassword) {
        virBufferAddLit(&opt, ",password=on");
    }

    if (cfg->vncTLS) {
        qemuDomainGraphicsPrivate *gfxPriv = QEMU_DOMAIN_GRAPHICS_PRIVATE(graphics);
        const char *secretAlias = NULL;

        if (gfxPriv->secinfo) {
            if (qemuBuildObjectSecretCommandLine(cmd,
                                                 gfxPriv->secinfo,
                                                 qemuCaps) < 0)
                return -1;
            secretAlias = gfxPriv->secinfo->alias;
        }

        if (qemuBuildTLSx509CommandLine(cmd,
                                        cfg->vncTLSx509certdir,
                                        true,
                                        cfg->vncTLSx509verify,
                                        secretAlias,
                                        gfxPriv->tlsAlias,
                                        qemuCaps) < 0)
            return -1;

        virBufferAsprintf(&opt, ",tls-creds=%s", gfxPriv->tlsAlias);
    }

    if (cfg->vncSASL) {
        virBufferAddLit(&opt, ",sasl=on");

        if (cfg->vncSASLdir)
            virCommandAddEnvPair(cmd, "SASL_CONF_PATH", cfg->vncSASLdir);

        /* TODO: Support ACLs later */
    }

    if (graphics->data.vnc.powerControl != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&opt, ",power-control=%s",
                          graphics->data.vnc.powerControl == VIR_TRISTATE_BOOL_YES ?
                          "on" : "off");
    }

    virBufferAsprintf(&opt, ",audiodev=%s", audioid);

    virCommandAddArg(cmd, "-vnc");
    virCommandAddArgBuffer(cmd, &opt);
    if (graphics->data.vnc.keymap)
        virCommandAddArgList(cmd, "-k", graphics->data.vnc.keymap, NULL);

    return 0;
}


static int
qemuBuildGraphicsSPICECommandLine(virQEMUDriverConfig *cfg,
                                  virCommand *cmd,
                                  virDomainGraphicsDef *graphics)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    virDomainGraphicsListenDef *glisten = NULL;
    int port = graphics->data.spice.port;
    int tlsPort = graphics->data.spice.tlsPort;
    size_t i;
    bool hasSecure = false;
    bool hasInsecure = false;

    if (!(glisten = virDomainGraphicsGetListen(graphics, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing listen element"));
        return -1;
    }

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
        virBufferAddLit(&opt, "unix,addr=");
        virQEMUBuildBufferEscapeComma(&opt, glisten->socket);
        virBufferAddLit(&opt, ",");
        hasInsecure = true;
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        if (port > 0) {
            virBufferAsprintf(&opt, "port=%u,", port);
            hasInsecure = true;
        }

        if (tlsPort > 0) {
            virBufferAsprintf(&opt, "tls-port=%u,", tlsPort);
            hasSecure = true;
        }

        if (port > 0 || tlsPort > 0) {
            if (glisten->address)
                virBufferAsprintf(&opt, "addr=%s,", glisten->address);
        }

        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        /* QEMU requires either port or tls-port to be specified if there is no
         * other argument. Use a dummy port=0. */
        virBufferAddLit(&opt, "port=0,");
        hasInsecure = true;
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        break;
    }

    if (cfg->spiceSASL) {
        virBufferAddLit(&opt, "sasl=on,");

        if (cfg->spiceSASLdir)
            virCommandAddEnvPair(cmd, "SASL_CONF_PATH",
                                 cfg->spiceSASLdir);

        /* TODO: Support ACLs later */
    }

    if (graphics->data.spice.mousemode) {
        switch (graphics->data.spice.mousemode) {
        case VIR_DOMAIN_MOUSE_MODE_SERVER:
            virBufferAddLit(&opt, "agent-mouse=off,");
            break;
        case VIR_DOMAIN_MOUSE_MODE_CLIENT:
            virBufferAddLit(&opt, "agent-mouse=on,");
            break;
        case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
            break;
        case VIR_DOMAIN_MOUSE_MODE_LAST:
        default:
            virReportEnumRangeError(virDomainMouseMode,
                                    graphics->data.spice.mousemode);
            return -1;
        }
    }

    /* In the password case we set it via monitor command, to avoid
     * making it visible on CLI, so there's no use of password=XXX
     * in this bit of the code */
    if (!graphics->data.spice.auth.passwd &&
        !cfg->spicePassword)
        virBufferAddLit(&opt, "disable-ticketing=on,");

    if (hasSecure) {
        virBufferAddLit(&opt, "x509-dir=");
        virQEMUBuildBufferEscapeComma(&opt, cfg->spiceTLSx509certdir);
        virBufferAddLit(&opt, ",");
    }

    switch (graphics->data.spice.defaultMode) {
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
        if (!hasSecure) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spice defaultMode secure requested in XML configuration, but TLS connection is not available"));
            return -1;
        }
        virBufferAddLit(&opt, "tls-channel=default,");
        break;
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
        if (!hasInsecure) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spice defaultMode insecure requested in XML configuration, but plaintext connection is not available"));
            return -1;
        }
        virBufferAddLit(&opt, "plaintext-channel=default,");
        break;
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_LAST:
        /* nothing */
        break;
    }

    for (i = 0; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST; i++) {
        switch (graphics->data.spice.channels[i]) {
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
            if (!hasSecure) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("spice secure channels set in XML configuration, but TLS connection is not available"));
                return -1;
            }
            virBufferAsprintf(&opt, "tls-channel=%s,",
                              virDomainGraphicsSpiceChannelNameTypeToString(i));
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
            if (!hasInsecure) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("spice insecure channels set in XML configuration, but plaintext connection is not available"));
                return -1;
            }
            virBufferAsprintf(&opt, "plaintext-channel=%s,",
                              virDomainGraphicsSpiceChannelNameTypeToString(i));
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
            break;
        }
    }

    if (graphics->data.spice.image)
        virBufferAsprintf(&opt, "image-compression=%s,",
                          virDomainGraphicsSpiceImageCompressionTypeToString(graphics->data.spice.image));
    if (graphics->data.spice.jpeg)
        virBufferAsprintf(&opt, "jpeg-wan-compression=%s,",
                          virDomainGraphicsSpiceJpegCompressionTypeToString(graphics->data.spice.jpeg));
    if (graphics->data.spice.zlib)
        virBufferAsprintf(&opt, "zlib-glz-wan-compression=%s,",
                          virDomainGraphicsSpiceZlibCompressionTypeToString(graphics->data.spice.zlib));
    if (graphics->data.spice.playback)
        virBufferAsprintf(&opt, "playback-compression=%s,",
                          virTristateSwitchTypeToString(graphics->data.spice.playback));
    if (graphics->data.spice.streaming)
        virBufferAsprintf(&opt, "streaming-video=%s,",
                          virDomainGraphicsSpiceStreamingModeTypeToString(graphics->data.spice.streaming));
    if (graphics->data.spice.copypaste == VIR_TRISTATE_BOOL_NO)
        virBufferAddLit(&opt, "disable-copy-paste=on,");

    if (graphics->data.spice.filetransfer == VIR_TRISTATE_BOOL_NO)
        virBufferAddLit(&opt, "disable-agent-file-xfer=on,");

    if (graphics->data.spice.gl == VIR_TRISTATE_BOOL_YES) {
        /* spice.gl is a TristateBool, but qemu expects on/off: use
         * TristateSwitch helper */
        virBufferAsprintf(&opt, "gl=%s,",
                          virTristateSwitchTypeToString(graphics->data.spice.gl));

        if (graphics->data.spice.rendernode) {
            virBufferAddLit(&opt, "rendernode=");
            virQEMUBuildBufferEscapeComma(&opt, graphics->data.spice.rendernode);
            virBufferAddLit(&opt, ",");
        }
    }

    /* Turn on seamless migration unconditionally. If migration destination
     * doesn't support it, it fallbacks to previous migration algorithm silently. */
    virBufferAddLit(&opt, "seamless-migration=on,");

    virBufferTrim(&opt, ",");

    virCommandAddArg(cmd, "-spice");
    virCommandAddArgBuffer(cmd, &opt);
    if (graphics->data.spice.keymap)
        virCommandAddArgList(cmd, "-k",
                             graphics->data.spice.keymap, NULL);

    return 0;
}


static int
qemuBuildGraphicsEGLHeadlessCommandLine(virQEMUDriverConfig *cfg G_GNUC_UNUSED,
                                        virCommand *cmd,
                                        virDomainGraphicsDef *graphics)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&opt, "egl-headless");

    if (graphics->data.egl_headless.rendernode) {
        virBufferAddLit(&opt, ",rendernode=");
        virQEMUBuildBufferEscapeComma(&opt,
                                      graphics->data.egl_headless.rendernode);
    }

    virCommandAddArg(cmd, "-display");
    virCommandAddArgBuffer(cmd, &opt);

    return 0;
}


static int
qemuBuildGraphicsDBusCommandLine(virDomainDef *def,
                                 virCommand *cmd,
                                 virDomainGraphicsDef *graphics)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&opt, "dbus");

    if (graphics->data.dbus.p2p) {
        virBufferAddLit(&opt, ",p2p=on");
    } else {
        virBufferAddLit(&opt, ",addr=");
        virQEMUBuildBufferEscapeComma(&opt, graphics->data.dbus.address);
    }
    if (graphics->data.dbus.gl != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(&opt, ",gl=%s",
                          virTristateSwitchTypeToString(graphics->data.dbus.gl));
    if (graphics->data.dbus.rendernode) {
        virBufferAddLit(&opt, ",rendernode=");
        virQEMUBuildBufferEscapeComma(&opt,
                                      graphics->data.dbus.rendernode);
    }

    if (graphics->data.dbus.audioId > 0) {
        g_autofree char *audioid = qemuGetAudioIDString(def, graphics->data.dbus.audioId);
        if (!audioid)
            return -1;
        virBufferAsprintf(&opt, ",audiodev=%s", audioid);
    }

    virCommandAddArg(cmd, "-display");
    virCommandAddArgBuffer(cmd, &opt);

    return 0;
}


static int
qemuBuildGraphicsCommandLine(virQEMUDriverConfig *cfg,
                             virCommand *cmd,
                             virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = def->graphics[i];

        switch (graphics->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            if (qemuBuildGraphicsSDLCommandLine(cfg, cmd,
                                                qemuCaps, graphics) < 0)
                return -1;

            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            if (qemuBuildGraphicsVNCCommandLine(cfg, def, cmd,
                                                qemuCaps, graphics) < 0)
                return -1;

            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            if (qemuBuildGraphicsSPICECommandLine(cfg, cmd,
                                                  graphics) < 0)
                return -1;

            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
            if (qemuBuildGraphicsEGLHeadlessCommandLine(cfg, cmd,
                                                        graphics) < 0)
                return -1;

            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
            if (qemuBuildGraphicsDBusCommandLine(def, cmd, graphics) < 0)
                return -1;

            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
            return -1;
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainGraphicsType, graphics->type);
            return -1;
        }
    }

    return 0;
}

static int
qemuInterfaceVhostuserConnect(virCommand *cmd,
                              virDomainNetDef *net,
                              virQEMUCaps *qemuCaps)
{
    g_autofree char *charAlias = qemuAliasChardevFromDevAlias(net->info.alias);

    switch ((virDomainChrType)net->data.vhostuser->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (qemuBuildChardevCommand(cmd,
                                    net->data.vhostuser,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("vhost-user type '%1$s' not supported"),
                       virDomainChrTypeToString(net->data.vhostuser->type));
        return -1;
    }

    return 0;
}


int
qemuBuildInterfaceConnect(virDomainObj *vm,
                          virDomainNetDef *net,
                          virNetDevVPortProfileOp vmop)
{

    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainNetType actualType = virDomainNetGetActualType(net);
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    VIR_AUTOCLOSE vdpafd = -1;
    bool vhostfd = false; /* also used to signal processing of tapfds */
    size_t tapfdSize = net->driver.virtio.queues;
    g_autofree int *tapfd = g_new0(int, tapfdSize + 1);

    memset(tapfd, -1, (tapfdSize + 1) * sizeof(*tapfd));

    if (tapfdSize == 0)
        tapfdSize = 1;

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        vhostfd = true;
        if (qemuInterfaceBridgeConnect(vm->def, priv->driver, net,
                                       tapfd, &tapfdSize) < 0)
            return -1;
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        vhostfd = true;
        if (qemuInterfaceDirectConnect(vm->def, priv->driver, net,
                                       tapfd, tapfdSize, vmop) < 0)
            return -1;
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (qemuInterfaceEthernetConnect(vm->def, priv->driver, net,
                                         tapfd, tapfdSize) < 0)
            return -1;
        vhostfd = true;
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        break;

    case VIR_DOMAIN_NET_TYPE_VDPA:
        if ((vdpafd = qemuVDPAConnect(net->data.vdpa.devicepath)) < 0)
            return -1;

        netpriv->vdpafd = qemuFDPassNew(net->info.alias, priv);
        qemuFDPassAddFD(netpriv->vdpafd, &vdpafd, "-vdpa");
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    /* 'vhostfd' is set to true in all cases when we need to process tapfds */
    if (vhostfd) {
        size_t i;

        for (i = 0; i < tapfdSize; i++) {
            g_autofree char *name = g_strdup_printf("tapfd-%s%zu", net->info.alias, i);
            int fd = tapfd[i]; /* we want to keep the array intact for security labeling*/

            netpriv->tapfds = g_slist_prepend(netpriv->tapfds, qemuFDPassDirectNew(name, &fd));
        }

        netpriv->tapfds = g_slist_reverse(netpriv->tapfds);

        for (i = 0; i < tapfdSize; i++) {
            if (qemuSecuritySetTapFDLabel(priv->driver->securityManager,
                                          vm->def, tapfd[i]) < 0)
                return -1;
        }

        if (qemuInterfaceOpenVhostNet(vm, net) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildInterfaceCommandLine(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virCommand *cmd,
                              virDomainNetDef *net,
                              virQEMUCaps *qemuCaps,
                              virNetDevVPortProfileOp vmop,
                              size_t *nnicindexes,
                              int **nicindexes)
{
    virDomainDef *def = vm->def;
    int ret = -1;
    g_autoptr(virJSONValue) nicprops = NULL;
    g_autofree char *nic = NULL;
    virDomainNetType actualType = virDomainNetGetActualType(net);
    const virNetDevBandwidth *actualBandwidth;
    bool requireNicdev = false;
    g_autoptr(virJSONValue) hostnetprops = NULL;
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    GSList *n;

    if (qemuDomainValidateActualNetDef(net, qemuCaps) < 0)
        return -1;

    if (qemuBuildInterfaceConnect(vm, net, vmop) < 0)
        return -1;

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        /* NET_TYPE_HOSTDEV devices are really hostdev devices, so
         * their commandlines are constructed with other hostdevs.
         */
        ret = 0;
        goto cleanup;
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        requireNicdev = true;

        if (qemuInterfaceVhostuserConnect(cmd, net, qemuCaps) < 0)
            goto cleanup;

        if (virNetDevOpenvswitchGetVhostuserIfname(net->data.vhostuser->data.nix.path,
                                                   net->data.vhostuser->data.nix.listen,
                                                   &net->ifname) < 0)
            goto cleanup;

        break;

    case VIR_DOMAIN_NET_TYPE_VDPA:
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* nada */
        break;
    }

    /* For types whose implementations use a netdev on the host, add
     * an entry to nicindexes for passing on to systemd.
    */
    switch ((virDomainNetType)actualType) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    {
        int nicindex;

        /* network and bridge use a tap device, and direct uses a
         * macvtap device
         */
        if (driver->privileged && nicindexes && nnicindexes &&
            net->ifname) {
            if (virNetDevGetIndex(net->ifname, &nicindex) < 0)
                goto cleanup;

            VIR_APPEND_ELEMENT(*nicindexes, *nnicindexes, nicindex);
        }
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
       /* These types don't use a network device on the host, but
        * instead use some other type of connection to the emulated
        * device in the qemu process.
        *
        * (Note that hostdev can't be considered as "using a network
        * device", because by the time it is being used, it has been
        * detached from the hostside network driver so it doesn't show
        * up in the list of interfaces on the host - it's just some
        * PCI device.)
        */
       break;
    }

    qemuDomainInterfaceSetDefaultQDisc(driver, net);

    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportsBandwidth(actualType)) {
            if (virDomainNetDefIsOvsport(net)) {
                if (virNetDevOpenvswitchInterfaceSetQos(net->ifname, actualBandwidth,
                                                        def->uuid,
                                                        !virDomainNetTypeSharesHostView(net)) < 0)
                    goto cleanup;
            } else if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false,
                                             !virDomainNetTypeSharesHostView(net)) < 0) {
                goto cleanup;
            }
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet",
                     virDomainNetTypeToString(actualType));
        }
    }

    if (net->mtu && net->managed_tap != VIR_TRISTATE_BOOL_NO &&
        virNetDevSetMTU(net->ifname, net->mtu) < 0)
        goto cleanup;

    for (n = netpriv->tapfds; n; n = n->next)
        qemuFDPassDirectTransferCommand(n->data, cmd);

    for (n = netpriv->vhostfds; n; n = n->next)
        qemuFDPassDirectTransferCommand(n->data, cmd);

    qemuFDPassDirectTransferCommand(netpriv->slirpfd, cmd);
    qemuFDPassTransferCommand(netpriv->vdpafd, cmd);

    if (!(hostnetprops = qemuBuildHostNetProps(vm, net)))
        goto cleanup;

    if (qemuBuildNetdevCommandlineFromJSON(cmd, hostnetprops, qemuCaps) < 0)
        goto cleanup;

    /* Possible combinations:
     *
     *   Old way: -netdev type=tap,id=netdev1 \
     *              -net nic,model=e1000,netdev=netdev1
     *   New way: -netdev type=tap,id=netdev1 -device e1000,id=netdev1
     */
    if (qemuDomainSupportsNicdev(def, net)) {
        if (qemuCommandAddExtDevice(cmd, &net->info, def, qemuCaps) < 0)
            goto cleanup;

        if (!(nicprops = qemuBuildNicDevProps(def, net, qemuCaps)))
            goto cleanup;
        if (qemuBuildDeviceCommandlineFromJSON(cmd, nicprops, def, qemuCaps) < 0)
            goto cleanup;
    } else if (!requireNicdev) {
        if (qemuCommandAddExtDevice(cmd, &net->info, def, qemuCaps) < 0)
            goto cleanup;

        if (!(nic = qemuBuildLegacyNicStr(net)))
            goto cleanup;
        virCommandAddArgList(cmd, "-net", nic, NULL);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Nicdev support unavailable"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuDomainNetworkPrivateClearFDs(netpriv);

    if (ret < 0) {
        virErrorPtr saved_err;

        virErrorPreserveLast(&saved_err);
        virDomainConfNWFilterTeardown(net);
        virErrorRestore(&saved_err);
    }
    return ret;
}


/* NOTE: Not using const virDomainDef here since eventually a call is made
 *       into qemuSecuritySetTapFDLabel which calls it's driver
 *       API domainSetSecurityTapFDLabel that doesn't use the const format.
 */
static int
qemuBuildNetCommandLine(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virCommand *cmd,
                        virQEMUCaps *qemuCaps,
                        virNetDevVPortProfileOp vmop,
                        size_t *nnicindexes,
                        int **nicindexes)
{
    size_t i;
    int last_good_net = -1;
    virErrorPtr originalError = NULL;
    virDomainDef *def = vm->def;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];

        if (qemuBuildInterfaceCommandLine(driver, vm, cmd, net,
                                          qemuCaps, vmop,
                                          nnicindexes, nicindexes) < 0)
            goto error;

        last_good_net = i;
    }
    return 0;

 error:
    /* free up any resources in the network driver
     * but don't overwrite the original error */
    virErrorPreserveLast(&originalError);
    for (i = 0; last_good_net != -1 && i <= last_good_net; i++)
        virDomainConfNWFilterTeardown(def->nets[i]);
    virErrorRestore(&originalError);
    return -1;
}


static int
qemuBuildSmartcardCommandLine(virCommand *cmd,
                              const virDomainDef *def,
                              virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainSmartcardDef *smartcard;
    const char *contAlias = NULL;
    g_autofree char *bus = NULL;

    if (!def->nsmartcards)
        return 0;

    smartcard = def->smartcards[0];

    switch (smartcard->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "ccid-card-emulated",
                                  "s:backend", "nss-emulated",
                                  NULL) < 0)
            return -1;

        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES: {
        const char *database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;

        if (smartcard->data.cert.database)
            database = smartcard->data.cert.database;

        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "ccid-card-emulated",
                                  "s:backend", "certificates",
                                  "s:cert1", smartcard->data.cert.file[0],
                                  "s:cert2", smartcard->data.cert.file[1],
                                  "s:cert3", smartcard->data.cert.file[2],
                                  "s:db", database,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH: {
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(smartcard->info.alias);

        if (qemuBuildChardevCommand(cmd,
                                    smartcard->data.passthru,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;

        if (virJSONValueObjectAdd(&props,
                                  "s:driver", "ccid-card-passthru",
                                  "s:chardev", charAlias,
                                  NULL) < 0)
            return -1;
    }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainSmartcardType, smartcard->type);
        return -1;
    }

    if (!(contAlias = virDomainControllerAliasFind(def,
                                                   VIR_DOMAIN_CONTROLLER_TYPE_CCID,
                                                   smartcard->info.addr.ccid.controller)))
        return -1;

    bus = g_strdup_printf("%s.0", contAlias);

    if (virJSONValueObjectAdd(&props,
                              "s:id", smartcard->info.alias,
                              "s:bus", bus,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


virJSONValue *
qemuBuildShmemDevProps(virDomainDef *def,
                       virDomainShmemDef *shmem)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *chardev = NULL;
    g_autofree char *memdev = NULL;
    virTristateSwitch master = VIR_TRISTATE_SWITCH_ABSENT;

    if (shmem->server.enabled) {
        chardev = g_strdup_printf("char%s", shmem->info.alias);
    } else {
        memdev = g_strdup_printf("shmmem-%s", shmem->info.alias);

        switch (shmem->role) {
        case VIR_DOMAIN_SHMEM_ROLE_MASTER:
            master = VIR_TRISTATE_SWITCH_ON;
            break;
        case VIR_DOMAIN_SHMEM_ROLE_PEER:
            master = VIR_TRISTATE_SWITCH_OFF;
            break;
        case VIR_DOMAIN_SHMEM_ROLE_DEFAULT:
        case VIR_DOMAIN_SHMEM_ROLE_LAST:
            break;
        }
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", virDomainShmemModelTypeToString(shmem->model),
                              "s:id", shmem->info.alias,
                              "S:chardev", chardev,
                              "S:memdev", memdev,
                              "S:master", qemuOnOffAuto(master),
                              "p:vectors", shmem->msi.vectors,
                              "T:ioeventfd", shmem->msi.ioeventfd,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &shmem->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildShmemBackendMemProps(virDomainShmemDef *shmem)
{
    g_autofree char *mem_alias = NULL;
    g_autofree char *mem_path = NULL;
    virJSONValue *ret = NULL;

    mem_path = g_strdup_printf("/dev/shm/%s", shmem->name);

    mem_alias = g_strdup_printf("shmmem-%s", shmem->info.alias);

    qemuMonitorCreateObjectProps(&ret, "memory-backend-file", mem_alias,
                                 "s:mem-path", mem_path,
                                 "U:size", shmem->size,
                                 "b:share", true,
                                 NULL);

    return ret;
}


static int
qemuBuildShmemCommandLine(virCommand *cmd,
                          virDomainDef *def,
                          virDomainShmemDef *shmem,
                          virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) memProps = NULL;
    g_autoptr(virJSONValue) devProps = NULL;

    if (shmem->size) {
        /*
         * Thanks to our parsing code, we have a guarantee that the
         * size is power of two and is at least a mebibyte in size.
         * But because it may change in the future, the checks are
         * doubled in here.
         */
        if (shmem->size & (shmem->size - 1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("shmem size must be a power of two"));
            return -1;
        }
        if (shmem->size < 1024 * 1024) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("shmem size must be at least 1 MiB (1024 KiB)"));
            return -1;
        }
    }

    if (shmem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 'pci' addresses are supported for the shared memory device"));
        return -1;
    }

    switch (shmem->model) {
    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM:
        /* unreachable, rejected by validation */
        break;

    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN:
        if (!(memProps = qemuBuildShmemBackendMemProps(shmem)))
            return -1;

        if (qemuBuildObjectCommandlineFromJSON(cmd, memProps, qemuCaps) < 0)
            return -1;

        G_GNUC_FALLTHROUGH;
    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL:
        devProps = qemuBuildShmemDevProps(def, shmem);
        break;

    case VIR_DOMAIN_SHMEM_MODEL_LAST:
        break;
    }

    if (!devProps)
        return -1;

    if (qemuCommandAddExtDevice(cmd, &shmem->info, def, qemuCaps) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devProps, def, qemuCaps) < 0)
        return -1;

    if (shmem->server.enabled) {
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(shmem->info.alias);

        if (qemuBuildChardevCommand(cmd,
                                    shmem->server.chr,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static virQEMUCapsFlags
qemuChrSerialTargetModelToCaps(virDomainChrSerialTargetModel targetModel)
{
    switch (targetModel) {
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL:
        return QEMU_CAPS_DEVICE_ISA_SERIAL;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_USB_SERIAL:
        return QEMU_CAPS_DEVICE_USB_SERIAL;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PCI_SERIAL:
        return QEMU_CAPS_DEVICE_PCI_SERIAL;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY:
        return QEMU_CAPS_DEVICE_SPAPR_VTY;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE:
        return QEMU_CAPS_DEVICE_SCLPCONSOLE;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPLMCONSOLE:
        return QEMU_CAPS_DEVICE_SCLPLMCONSOLE;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011:
        return QEMU_CAPS_DEVICE_PL011;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_DEBUGCON:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_LAST:
        break;
    }

    return 0;
}


static int
qemuBuildChrDeviceCommandLine(virCommand *cmd,
                              const virDomainDef *def,
                              virDomainChrDef *chr,
                              virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuBuildChrDeviceProps(def, chr, qemuCaps)))
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static bool
qemuChrIsPlatformDevice(const virDomainDef *def,
                        virDomainChrDef *chr)
{
    if (def->os.arch == VIR_ARCH_ARMV6L ||
        def->os.arch == VIR_ARCH_ARMV7L ||
        def->os.arch == VIR_ARCH_AARCH64) {

        /* pl011 (used on mach-virt) is a platform device */
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM &&
            chr->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011) {
            return true;
        }
    }

    if (ARCH_IS_RISCV(def->os.arch)) {

        /* 16550a (used by riscv/virt guests) is a platform device */
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM &&
            chr->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A) {
            return true;
        }
    }

    /* If we got all the way here and we're still stuck with the default
     * target type for a serial device, it means we have no clue what kind of
     * device we're talking about and we must treat it as a platform device. */
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE) {
        return true;
    }

    return false;
}


static int
qemuBuildSerialCommandLine(virCommand *cmd,
                           const virDomainDef *def,
                           virQEMUCaps *qemuCaps)
{
    size_t i;
    bool havespice = false;

    if (def->nserials) {
        for (i = 0; i < def->ngraphics && !havespice; i++) {
            if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
                havespice = true;
        }
    }

    for (i = 0; i < def->nserials; i++) {
        virDomainChrDef *serial = def->serials[i];
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(serial->info.alias);

        if (serial->source->type == VIR_DOMAIN_CHR_TYPE_SPICEPORT && !havespice)
            continue;

        if (qemuBuildChardevCommand(cmd,
                                    serial->source,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;

        /* If the device is not a platform device, build the devstr */
        if (!qemuChrIsPlatformDevice(def, serial)) {
            if (qemuBuildChrDeviceCommandLine(cmd, def, serial, qemuCaps) < 0)
                return -1;
        } else {
            virQEMUCapsFlags caps;

            caps = qemuChrSerialTargetModelToCaps(serial->targetModel);

            if (caps && !virQEMUCapsGet(qemuCaps, caps)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("'%1$s' is not supported in this QEMU binary"),
                               virDomainChrSerialTargetModelTypeToString(serial->targetModel));
                return -1;
            }

            virCommandAddArg(cmd, "-serial");
            virCommandAddArgFormat(cmd, "chardev:char%s", serial->info.alias);
        }
    }

    return 0;
}


static int
qemuBuildParallelsCommandLine(virCommand *cmd,
                              const virDomainDef *def,
                              virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nparallels; i++) {
        virDomainChrDef *parallel = def->parallels[i];
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(parallel->info.alias);

        if (qemuBuildChardevCommand(cmd,
                                    parallel->source,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;

        if (qemuBuildChrDeviceCommandLine(cmd, def, parallel,
                                          qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildChannelsCommandLine(virCommand *cmd,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDef *channel = def->channels[i];
        g_autoptr(virJSONValue) netdevprops = NULL;
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(channel->info.alias);

        if (qemuBuildChardevCommand(cmd,
                                    channel->source,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;

        switch ((virDomainChrChannelTargetType) channel->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!(netdevprops = qemuBuildChannelGuestfwdNetdevProps(channel)))
                return -1;

            if (qemuBuildNetdevCommandlineFromJSON(cmd, netdevprops, qemuCaps) < 0)
                return -1;
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            if (qemuBuildChrDeviceCommandLine(cmd, def, channel, qemuCaps) < 0)
                return -1;
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST:
            return -1;
        }
    }

    return 0;
}


static int
qemuBuildConsoleCommandLine(virCommand *cmd,
                            const virDomainDef *def,
                            virQEMUCaps *qemuCaps)
{
    size_t i;

    /* Explicit console devices */
    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDef *console = def->consoles[i];
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(console->info.alias);

        switch (console->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
            if (qemuBuildChardevCommand(cmd,
                                        console->source,
                                        charAlias,
                                        qemuCaps) < 0)
                return -1;

            if (qemuBuildChrDeviceCommandLine(cmd, def, console, qemuCaps) < 0)
                return -1;
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            break;

        default:
            return -1;
        }
    }

    return 0;
}


virJSONValue *
qemuBuildRedirdevDevProps(const virDomainDef *def,
                          virDomainRedirdevDef *dev)
{
    g_autoptr(virJSONValue) props = NULL;
    virDomainRedirFilterDef *redirfilter = def->redirfilter;
    g_autofree char *chardev = g_strdup_printf("char%s", dev->info.alias);
    g_autofree char *filter = NULL;

    if (redirfilter) {
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        size_t i;

        for (i = 0; i < redirfilter->nusbdevs; i++) {
            virDomainRedirFilterUSBDevDef *usbdev = redirfilter->usbdevs[i];
            if (usbdev->usbClass >= 0)
                virBufferAsprintf(&buf, "0x%02X:", usbdev->usbClass);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->vendor >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->vendor);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->product >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->product);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->version >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->version);
            else
                virBufferAddLit(&buf, "-1:");

            virBufferAsprintf(&buf, "%u|", usbdev->allow);
        }
        virBufferTrim(&buf, "|");

        filter = virBufferContentAndReset(&buf);
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "usb-redir",
                              "s:chardev", chardev,
                              "s:id", dev->info.alias,
                              "S:filter", filter,
                              "p:bootindex", dev->info.bootIndex,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildRedirdevCommandLine(virCommand *cmd,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDef *redirdev = def->redirdevs[i];
        g_autoptr(virJSONValue) devprops = NULL;
        g_autofree char *charAlias = qemuAliasChardevFromDevAlias(redirdev->info.alias);

        if (qemuBuildChardevCommand(cmd,
                                    redirdev->source,
                                    charAlias,
                                    qemuCaps) < 0)
            return -1;

        if (!(devprops = qemuBuildRedirdevDevProps(def, redirdev)))
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}



static void
qemuBuildDomainLoaderCommandLine(virCommand *cmd,
                                 virDomainDef *def)
{
    virDomainLoaderDef *loader = def->os.loader;

    if (!loader)
        return;

    switch ((virDomainLoader) loader->type) {
    case VIR_DOMAIN_LOADER_TYPE_ROM:
        virCommandAddArg(cmd, "-bios");
        virCommandAddArg(cmd, loader->path);
        break;

    case VIR_DOMAIN_LOADER_TYPE_PFLASH:
        if (loader->secure == VIR_TRISTATE_BOOL_YES) {
            virCommandAddArgList(cmd,
                                 "-global",
                                 "driver=cfi.pflash01,property=secure,value=on",
                                 NULL);
        }
        break;

    case VIR_DOMAIN_LOADER_TYPE_NONE:
    case VIR_DOMAIN_LOADER_TYPE_LAST:
        /* nada */
        break;
    }
}


static int
qemuBuildTPMDevCmd(virCommand *cmd,
                   const virDomainDef *def,
                   virDomainTPMDef *tpm,
                   virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    const char *model = virDomainTPMModelTypeToString(tpm->model);
    g_autofree char *tpmdev = g_strdup_printf("tpm-%s", tpm->info.alias);

    if (tpm->model == VIR_DOMAIN_TPM_MODEL_TIS && !ARCH_IS_X86(def->os.arch))
        model = "tpm-tis-device";

    if (virJSONValueObjectAdd(&props,
                              "s:driver", model,
                              "s:tpmdev", tpmdev,
                              "s:id", tpm->info.alias,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceAddressProps(props, def, &tpm->info) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


/* this function is exported so that tests can mock the FDs */
int
qemuBuildTPMOpenBackendFDs(const char *tpmdev,
                           int *tpmfd,
                           int *cancelfd)
{
    g_autofree char *cancel_path = NULL;

    if (!(cancel_path = virTPMCreateCancelPath(tpmdev)))
        return -1;

    if ((*tpmfd = open(tpmdev, O_RDWR)) < 0) {
        virReportSystemError(errno, _("Could not open TPM device %1$s"),
                             tpmdev);
        return -1;
    }

    if ((*cancelfd = open(cancel_path, O_WRONLY)) < 0) {
        virReportSystemError(errno,
                             _("Could not open TPM device's cancel path %1$s"),
                             cancel_path);
        VIR_FORCE_CLOSE(*tpmfd);
        return -1;
    }

    return 0;
}


static char *
qemuBuildTPMBackendStr(virDomainTPMDef *tpm,
                       qemuFDPass *passtpm,
                       qemuFDPass *passcancel)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (tpm->type == VIR_DOMAIN_TPM_TYPE_EXTERNAL)
        virBufferAddLit(&buf, "emulator");
    else
        virBufferAsprintf(&buf, "%s", virDomainTPMBackendTypeToString(tpm->type));
    virBufferAsprintf(&buf, ",id=tpm-%s", tpm->info.alias);

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        virBufferAddLit(&buf, ",path=");
        virQEMUBuildBufferEscapeComma(&buf, qemuFDPassGetPath(passtpm));

        virBufferAddLit(&buf, ",cancel-path=");
        virQEMUBuildBufferEscapeComma(&buf, qemuFDPassGetPath(passcancel));
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        virBufferAddLit(&buf, ",chardev=chrtpm");
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


static int
qemuBuildTPMCommandLine(virCommand *cmd,
                        const virDomainDef *def,
                        virDomainTPMDef *tpm,
                        qemuDomainObjPrivate *priv)
{
    g_autofree char *tpmdevstr = NULL;
    g_autoptr(qemuFDPass) passtpm = NULL;
    g_autoptr(qemuFDPass) passcancel = NULL;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH: {
        VIR_AUTOCLOSE fdtpm = -1;
        VIR_AUTOCLOSE fdcancel = -1;

        if (qemuBuildTPMOpenBackendFDs(tpm->data.passthrough.source->data.file.path,
                                       &fdtpm, &fdcancel) < 0)
            return -1;

        passtpm = qemuFDPassNew(tpm->info.alias, priv);
        passcancel = qemuFDPassNew(tpm->info.alias, priv);

        qemuFDPassAddFD(passtpm, &fdtpm, "-tpm");
        qemuFDPassAddFD(passcancel, &fdcancel, "-cancel");
    }
        break;

    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        if (qemuBuildChardevCommand(cmd, tpm->data.emulator.source, "chrtpm", priv->qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        if (qemuBuildChardevCommand(cmd, tpm->data.external.source, "chrtpm", priv->qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_TPM_TYPE_LAST:
        virReportEnumRangeError(virDomainTPMBackendType, tpm->type);
        return -1;
    }

    qemuFDPassTransferCommand(passtpm, cmd);
    qemuFDPassTransferCommand(passcancel, cmd);

    if (!(tpmdevstr = qemuBuildTPMBackendStr(tpm, passtpm, passcancel)))
        return -1;

    virCommandAddArgList(cmd, "-tpmdev", tpmdevstr, NULL);

    if (qemuBuildTPMDevCmd(cmd, def, tpm, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildTPMProxyCommandLine(virCommand *cmd,
                             virDomainTPMDef *tpm,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", virDomainTPMModelTypeToString(tpm->model),
                              "s:id", tpm->info.alias,
                              "s:host-path", tpm->data.passthrough.source->data.file.path,
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildTPMsCommandLine(virCommand *cmd,
                         const virDomainDef *def,
                         qemuDomainObjPrivate *priv)
{
    size_t i;

    for (i = 0; i < def->ntpms; i++) {
        if (def->tpms[i]->model == VIR_DOMAIN_TPM_MODEL_SPAPR_PROXY) {
            if (qemuBuildTPMProxyCommandLine(cmd, def->tpms[i], def, priv->qemuCaps) < 0)
                return -1;
        } else if (qemuBuildTPMCommandLine(cmd, def, def->tpms[i], priv) < 0) {
            return -1;
        }
    }

    return 0;
}


static int
qemuBuildSEVCommandLine(virDomainObj *vm, virCommand *cmd,
                        virDomainSEVDef *sev)
{
    g_autoptr(virJSONValue) props = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *dhpath = NULL;
    g_autofree char *sessionpath = NULL;

    VIR_DEBUG("policy=0x%x cbitpos=%d reduced_phys_bits=%d",
              sev->policy, sev->cbitpos, sev->reduced_phys_bits);

    if (sev->dh_cert)
        dhpath = g_strdup_printf("%s/dh_cert.base64", priv->libDir);

    if (sev->session)
        sessionpath = g_strdup_printf("%s/session.base64", priv->libDir);

    if (qemuMonitorCreateObjectProps(&props, "sev-guest", "lsec0",
                                     "u:cbitpos", sev->cbitpos,
                                     "u:reduced-phys-bits", sev->reduced_phys_bits,
                                     "u:policy", sev->policy,
                                     "S:dh-cert-file", dhpath,
                                     "S:session-file", sessionpath,
                                     "T:kernel-hashes", sev->kernel_hashes,
                                     NULL) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildPVCommandLine(virDomainObj *vm, virCommand *cmd)
{
    g_autoptr(virJSONValue) props = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;

    if (qemuMonitorCreateObjectProps(&props, "s390-pv-guest", "lsec0",
                                     NULL) < 0)
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildSecCommandLine(virDomainObj *vm, virCommand *cmd,
                        virDomainSecDef *sec)
{
    if (!sec)
        return 0;

    switch ((virDomainLaunchSecurity) sec->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        return qemuBuildSEVCommandLine(vm, cmd, &sec->data.sev);
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        return qemuBuildPVCommandLine(vm, cmd);
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
        virReportEnumRangeError(virDomainLaunchSecurity, sec->sectype);
        return -1;
    }

    return 0;
}


static int
qemuBuildVMCoreInfoCommandLine(virCommand *cmd,
                               const virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;

    if (def->features[VIR_DOMAIN_FEATURE_VMCOREINFO] != VIR_TRISTATE_SWITCH_ON)
        return 0;

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "vmcoreinfo",
                              NULL) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildPanicCommandLine(virCommand *cmd,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->npanics; i++) {
        switch ((virDomainPanicModel) def->panics[i]->model) {
        case VIR_DOMAIN_PANIC_MODEL_ISA: {
            g_autoptr(virJSONValue) props = NULL;

            if (virJSONValueObjectAdd(&props,
                                      "s:driver", "pvpanic",
                                      NULL) < 0)
                return -1;

            /* pvpanic uses 'ioport' instead of 'iobase' so
             * qemuBuildDeviceAddressProps can't be used */
            if (def->panics[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA) {
                if (virJSONValueObjectAdd(&props,
                                          "u:ioport", def->panics[i]->info.addr.isa.iobase,
                                          NULL) < 0)
                    return -1;
            }

            if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
                return -1;

            break;
        }

        case VIR_DOMAIN_PANIC_MODEL_PVPANIC: {
            g_autoptr(virJSONValue) props = NULL;

            if (virJSONValueObjectAdd(&props,
                                      "s:driver", "pvpanic-pci",
                                      NULL) < 0)
                return -1;

            if (qemuBuildDeviceAddressProps(props, def, &def->panics[i]->info) < 0)
                return -1;

            if (qemuBuildDeviceCommandlineFromJSON(cmd, props, def, qemuCaps) < 0)
                return -1;

            break;
        }

        case VIR_DOMAIN_PANIC_MODEL_S390:
        case VIR_DOMAIN_PANIC_MODEL_HYPERV:
        case VIR_DOMAIN_PANIC_MODEL_PSERIES:
        /* default model value was changed before in post parse */
        case VIR_DOMAIN_PANIC_MODEL_DEFAULT:
        case VIR_DOMAIN_PANIC_MODEL_LAST:
            break;
        }
    }

    return 0;
}


static virJSONValue *
qemuBuildPRManagerInfoPropsInternal(const char *alias,
                                    const char *path)
{
    virJSONValue *ret = NULL;

    if (qemuMonitorCreateObjectProps(&ret,
                                     "pr-manager-helper", alias,
                                     "s:path", path, NULL) < 0)
        return NULL;

    return ret;
}


/**
 * qemuBuildPRManagedManagerInfoProps:
 *
 * Build the JSON properties for the pr-manager object corresponding to the PR
 * daemon managed by libvirt.
 */
virJSONValue *
qemuBuildPRManagedManagerInfoProps(qemuDomainObjPrivate *priv)
{
    g_autofree char *path = NULL;

    if (!(path = qemuDomainGetManagedPRSocketPath(priv)))
        return NULL;

    return qemuBuildPRManagerInfoPropsInternal(qemuDomainGetManagedPRAlias(),
                                               path);
}


/**
 * qemuBuildPRManagerInfoProps:
 * @src: storage source
 *
 * Build the JSON properties for the pr-manager object.
 */
virJSONValue *
qemuBuildPRManagerInfoProps(virStorageSource *src)
{
    return qemuBuildPRManagerInfoPropsInternal(src->pr->mgralias, src->pr->path);
}


static int
qemuBuildManagedPRCommandLine(virCommand *cmd,
                              const virDomainDef *def,
                              qemuDomainObjPrivate *priv)
{
    g_autoptr(virJSONValue) props = NULL;

    if (!virDomainDefHasManagedPR(def))
        return 0;

    if (!(props = qemuBuildPRManagedManagerInfoProps(priv)))
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuBuildPflashBlockdevOne(virCommand *cmd,
                           virStorageSource *src,
                           virQEMUCaps *qemuCaps)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    size_t i;

    if (!(data = qemuBuildStorageSourceChainAttachPrepareBlockdev(src)))
        return -1;

    for (i = data->nsrcdata; i > 0; i--) {
        if (qemuBuildBlockStorageSourceAttachDataCommandline(cmd,
                                                             data->srcdata[i - 1],
                                                             qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildPflashBlockdevCommandLine(virCommand *cmd,
                                   virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virDomainDefHasOldStyleUEFI(vm->def))
        return 0;

    if (priv->pflash0 &&
        qemuBuildPflashBlockdevOne(cmd, priv->pflash0, priv->qemuCaps) < 0)
        return -1;

    if (vm->def->os.loader->nvram &&
        qemuBuildPflashBlockdevOne(cmd, vm->def->os.loader->nvram, priv->qemuCaps) < 0)
        return -1;

    return 0;
}


virJSONValue *
qemuBuildDBusVMStateInfoProps(virQEMUDriver *driver,
                              virDomainObj *vm)
{
    virJSONValue *ret = NULL;
    const char *alias = qemuDomainGetDBusVMStateAlias();
    g_autofree char *addr = qemuDBusGetAddress(driver, vm);

    if (!addr)
        return NULL;

    qemuMonitorCreateObjectProps(&ret,
                                 "dbus-vmstate", alias,
                                 "s:addr", addr, NULL);
    return ret;
}


static int
qemuBuildDBusVMStateCommandLine(virCommand *cmd,
                                virQEMUDriver *driver,
                                virDomainObj *vm)
{
    g_autoptr(virJSONValue) props = NULL;
    qemuDomainObjPrivate *priv = QEMU_DOMAIN_PRIVATE(vm);

    if (!priv->dbusVMStateIds)
        return 0;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {
        VIR_INFO("dbus-vmstate object is not supported by this QEMU binary");
        return 0;
    }

    if (!(props = qemuBuildDBusVMStateInfoProps(driver, vm)))
        return -1;

    if (qemuBuildObjectCommandlineFromJSON(cmd, props, priv->qemuCaps) < 0)
        return -1;

    priv->dbusVMState = true;

    return 0;
}


/**
 * qemuBuildCommandLineValidate:
 *
 * Prior to taking the plunge and building a long command line only
 * to find some configuration option isn't valid, let's do a couple
 * of checks and fail early.
 *
 * Returns 0 on success, returns -1 and messages what the issue is.
 */
static int
qemuBuildCommandLineValidate(virQEMUDriver *driver,
                             const virDomainDef *def)
{
    size_t i;
    int sdl = 0;
    int vnc = 0;
    int spice = 0;
    int egl_headless = 0;
    int dbus = 0;

    if (!driver->privileged) {
        /* If we have no cgroups then we can have no tunings that
         * require them */

        if (virMemoryLimitIsSet(def->mem.hard_limit) ||
            virMemoryLimitIsSet(def->mem.soft_limit) ||
            virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory tuning is not available in session mode"));
            return -1;
        }

        if (def->blkio.weight) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available in session mode"));
            return -1;
        }

        if (def->cputune.sharesSpecified || def->cputune.period ||
            def->cputune.quota || def->cputune.global_period ||
            def->cputune.global_quota || def->cputune.emulator_period ||
            def->cputune.emulator_quota || def->cputune.iothread_period ||
            def->cputune.iothread_quota) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU tuning is not available in session mode"));
            return -1;
        }
    }

    for (i = 0; i < def->ngraphics; ++i) {
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
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
            ++egl_headless;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
            ++dbus;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
        }
    }

    if (sdl > 1 || vnc > 1 || spice > 1 || egl_headless > 1 || dbus > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 1 graphics device of each type (sdl, vnc, spice, headless, dbus) is supported"));
        return -1;
    }

    if (def->virtType == VIR_DOMAIN_VIRT_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_LINUX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu emulator '%1$s' does not support xen"),
                       def->emulator);
        return -1;
    }

    return 0;
}


static int
qemuBuildSeccompSandboxCommandLine(virCommand *cmd,
                                   virQEMUDriverConfig *cfg,
                                   virQEMUCaps *qemuCaps G_GNUC_UNUSED)
{
    if (cfg->seccompSandbox == 0) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SECCOMP_SANDBOX))
            virCommandAddArgList(cmd, "-sandbox", "off", NULL);
        return 0;
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SECCOMP_SANDBOX)) {
        virCommandAddArgList(cmd, "-sandbox",
                             "on,obsolete=deny,elevateprivileges=deny,"
                             "spawn=deny,resourcecontrol=deny",
                             NULL);
        return 0;
    }

    return 0;

}


virJSONValue *
qemuBuildVsockDevProps(virDomainDef *def,
                       virDomainVsockDef *vsock,
                       virQEMUCaps *qemuCaps,
                       const char *fdprefix)
{
    qemuDomainVsockPrivate *priv = (qemuDomainVsockPrivate *)vsock->privateData;
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *vhostfd = g_strdup_printf("%s%d", fdprefix, priv->vhostfd);

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_VSOCK, vsock, qemuCaps)))
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:id", vsock->info.alias,
                              "u:guest-cid", vsock->guest_cid,
                              "s:vhostfd", vhostfd,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &vsock->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildVsockCommandLine(virCommand *cmd,
                          virDomainDef *def,
                          virDomainVsockDef *vsock,
                          virQEMUCaps *qemuCaps)
{
    qemuDomainVsockPrivate *priv = (qemuDomainVsockPrivate *)vsock->privateData;
    g_autoptr(virJSONValue) devprops = NULL;

    if (!(devprops = qemuBuildVsockDevProps(def, vsock, qemuCaps, "")))
        return -1;

    if (priv->vhostfd != -1)
        virCommandPassFD(cmd, priv->vhostfd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    priv->vhostfd = -1;

    if (qemuCommandAddExtDevice(cmd, &vsock->info, def, qemuCaps) < 0)
        return -1;

    if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
        return -1;

    return 0;
}


VIR_ENUM_DECL(qemuCryptoBackend);
VIR_ENUM_IMPL(qemuCryptoBackend,
              VIR_DOMAIN_CRYPTO_BACKEND_LAST,
              "cryptodev-backend-builtin",
              "cryptodev-backend-lkcf",
);


static int
qemuBuildCryptoBackendProps(virDomainCryptoDef *crypto,
                            virJSONValue **props)
{
    g_autofree char *objAlias = NULL;

    objAlias = g_strdup_printf("obj%s", crypto->info.alias);

    if (qemuMonitorCreateObjectProps(props,
                                     qemuCryptoBackendTypeToString(crypto->backend),
                                     objAlias,
                                     "p:queues", crypto->queues,
                                     NULL) < 0)
        return -1;

    return 0;
}


static virJSONValue *
qemuBuildCryptoDevProps(const virDomainDef *def,
                        virDomainCryptoDef *dev,
                        virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *crypto = g_strdup_printf("obj%s", dev->info.alias);

    if (!(props = qemuBuildVirtioDevProps(VIR_DOMAIN_DEVICE_CRYPTO, dev, qemuCaps)))
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:cryptodev", crypto,
                              "s:id", dev->info.alias,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &dev->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static int
qemuBuildCryptoCommandLine(virCommand *cmd,
                           const virDomainDef *def,
                           virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->ncryptos; i++) {
        g_autoptr(virJSONValue) props = NULL;
        virDomainCryptoDef *crypto = def->cryptos[i];
        g_autoptr(virJSONValue) devprops = NULL;

        if (!crypto->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Crypto device is missing alias"));
            return -1;
        }

        if (qemuBuildCryptoBackendProps(crypto, &props) < 0)
            return -1;

        if (qemuBuildObjectCommandlineFromJSON(cmd, props, qemuCaps) < 0)
            return -1;

        /* add the device */
        if (qemuCommandAddExtDevice(cmd, &crypto->info, def, qemuCaps) < 0)
            return -1;

        if (!(devprops = qemuBuildCryptoDevProps(def, crypto, qemuCaps)))
            return -1;

        if (qemuBuildDeviceCommandlineFromJSON(cmd, devprops, def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


static int
qemuBuildAsyncTeardownCommandLine(virCommand *cmd,
                                  const virDomainDef *def,
                                  virQEMUCaps *qemuCaps)
{
    g_autofree char *async = NULL;
    virTristateBool enabled = def->features[VIR_DOMAIN_FEATURE_ASYNC_TEARDOWN];

    if (enabled != VIR_TRISTATE_BOOL_ABSENT &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_RUN_WITH_ASYNC_TEARDOWN)) {
        async = g_strdup_printf("async-teardown=%s",
                                virTristateSwitchTypeToString(enabled));
        virCommandAddArgList(cmd, "-run-with", async, NULL);
    }

    return 0;
}


typedef enum {
    QEMU_COMMAND_DEPRECATION_BEHAVIOR_NONE = 0,
    QEMU_COMMAND_DEPRECATION_BEHAVIOR_OMIT,
    QEMU_COMMAND_DEPRECATION_BEHAVIOR_REJECT,
    QEMU_COMMAND_DEPRECATION_BEHAVIOR_CRASH,

    QEMU_COMMAND_DEPRECATION_BEHAVIOR_LAST
} qemuCommandDeprecationBehavior;


VIR_ENUM_DECL(qemuCommandDeprecationBehavior);
VIR_ENUM_IMPL(qemuCommandDeprecationBehavior,
              QEMU_COMMAND_DEPRECATION_BEHAVIOR_LAST,
              "none",
              "omit",
              "reject",
              "crash");

static void
qemuBuildCompatDeprecatedCommandLine(virCommand *cmd,
                                     virQEMUDriverConfig *cfg,
                                     virDomainDef *def,
                                     virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *propsstr = NULL;
    qemuDomainXmlNsDef *nsdata = def->namespaceData;
    qemuCommandDeprecationBehavior behavior = QEMU_COMMAND_DEPRECATION_BEHAVIOR_NONE;
    const char *behaviorStr = cfg->deprecationBehavior;
    int tmp;
    const char *deprecatedOutput = NULL;
    const char *deprecatedInput = NULL;

    if (nsdata && nsdata->deprecationBehavior)
        behaviorStr = nsdata->deprecationBehavior;

    if ((tmp = qemuCommandDeprecationBehaviorTypeFromString(behaviorStr)) < 0) {
        VIR_WARN("Unsupported deprecation behavior '%s' for VM '%s'",
                 behaviorStr, def->name);
        return;
    }

    behavior = tmp;

    if (behavior == QEMU_COMMAND_DEPRECATION_BEHAVIOR_NONE)
        return;

    /* we don't try to enable this feature at all if qemu doesn't support it,
     * so that a downgrade of qemu version doesn't impact startup of the VM */
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_COMPAT_DEPRECATED)) {
        VIR_DEBUG("-compat not supported for VM '%s'", def->name);
        return;
    }

    switch (behavior) {
    case QEMU_COMMAND_DEPRECATION_BEHAVIOR_OMIT:
    case QEMU_COMMAND_DEPRECATION_BEHAVIOR_NONE:
    case QEMU_COMMAND_DEPRECATION_BEHAVIOR_LAST:
    default:
        deprecatedOutput = "hide";
        break;

    case QEMU_COMMAND_DEPRECATION_BEHAVIOR_REJECT:
        deprecatedOutput = "hide";
        deprecatedInput = "reject";
        break;

    case QEMU_COMMAND_DEPRECATION_BEHAVIOR_CRASH:
        deprecatedOutput = "hide";
        deprecatedInput = "crash";
        break;
    }

    if (virJSONValueObjectAdd(&props,
                              "S:deprecated-output", deprecatedOutput,
                              "S:deprecated-input", deprecatedInput,
                              NULL) < 0)
        return;

    if (!(propsstr = virJSONValueToString(props, false)))
        return;

    virCommandAddArgList(cmd, "-compat", propsstr, NULL);
}


/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 */
virCommand *
qemuBuildCommandLine(virDomainObj *vm,
                     const char *migrateURI,
                     virDomainMomentObj *snapshot,
                     virNetDevVPortProfileOp vmop,
                     size_t *nnicindexes,
                     int **nicindexes)
{
    size_t i;
    char uuid[VIR_UUID_STRING_BUFLEN];
    g_autoptr(virCommand) cmd = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainDef *def = vm->def;
    virQEMUCaps *qemuCaps = priv->qemuCaps;

    VIR_DEBUG("Building qemu commandline for def=%s(%p) migrateURI=%s snapshot=%p vmop=%d",
              def->name, def, migrateURI, snapshot, vmop);

    if (qemuBuildCommandLineValidate(driver, def) < 0)
        return NULL;

    cmd = virCommandNew(def->emulator);

    virCommandAddEnvPassCommon(cmd);

    /* For system QEMU we want to set both HOME and all the XDG variables to
     * libDir/qemu otherwise apps QEMU links to might try to access the default
     * home dir '/' which would always result in a permission issue.
     *
     * For session QEMU, we only want to set XDG_CACHE_HOME as cache data
     * may be purged at any time and that should not affect any app. We
     * do want VMs to integrate with services in user's session so we're
     * not re-setting any other env variables
     */
    if (!driver->privileged) {
        virCommandAddEnvFormat(cmd, "XDG_CACHE_HOME=%s/%s",
                               priv->libDir, ".cache");
    } else {
        virCommandAddEnvPair(cmd, "HOME", priv->libDir);
        virCommandAddEnvXDG(cmd, priv->libDir);
    }

    if (qemuBuildNameCommandLine(cmd, cfg, def) < 0)
        return NULL;

    qemuBuildCompatDeprecatedCommandLine(cmd, cfg, def, qemuCaps);

    virCommandAddArg(cmd, "-S"); /* freeze CPUs during startup */

    if (qemuBuildMasterKeyCommandLine(cmd, priv) < 0)
        return NULL;

    if (qemuBuildDBusVMStateCommandLine(cmd, driver, vm) < 0)
        return NULL;

    if (qemuBuildManagedPRCommandLine(cmd, def, priv) < 0)
        return NULL;

    if (qemuBuildPflashBlockdevCommandLine(cmd, vm) < 0)
        return NULL;

    /* QEMU 1.2 and later have a binary flag -enable-fips that must be
     * used for VNC auth to obey FIPS settings; but the flag only
     * exists on Linux, and with no way to probe for it via QMP.  Our
     * solution: if FIPS mode is required, then unconditionally use the flag.
     *
     * In QEMU 5.2.0, use of -enable-fips was deprecated. In scenarios
     * where FIPS is required, QEMU must be built against libgcrypt
     * which automatically enforces FIPS compliance.
     *
     * Note this is the only use of driver->hostFips.
     */
    if (driver->hostFips &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_ENABLE_FIPS))
        virCommandAddArg(cmd, "-enable-fips");

    if (qemuBuildMachineCommandLine(cmd, cfg, def, qemuCaps, priv) < 0)
        return NULL;

    qemuBuildAccelCommandLine(cmd, def);

    qemuBuildTSEGCommandLine(cmd, def);

    if (qemuBuildCpuCommandLine(cmd, driver, def, qemuCaps) < 0)
        return NULL;

    qemuBuildDomainLoaderCommandLine(cmd, def);

    if (qemuBuildMemCommandLine(cmd, def, qemuCaps, priv) < 0)
        return NULL;

    if (qemuBuildSmpCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildIOThreadCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (virDomainNumaGetNodeCount(def->numa) &&
        qemuBuildNumaCommandLine(cfg, def, cmd, priv) < 0)
        return NULL;

    virUUIDFormat(def->uuid, uuid);
    virCommandAddArgList(cmd, "-uuid", uuid, NULL);

    if (qemuBuildSmbiosCommandLine(cmd, driver, def) < 0)
        return NULL;

    if (qemuBuildSysinfoCommandLine(cmd, def) < 0)
        return NULL;

    if (qemuBuildVMGenIDCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (!def->ngraphics) {
        virCommandAddArg(cmd, "-display");
        virCommandAddArg(cmd, "none");
    }

    /* Disable global config files and default devices */
    virCommandAddArg(cmd, "-no-user-config");
    virCommandAddArg(cmd, "-nodefaults");

    if (qemuBuildMonitorCommandLine(cmd, priv) < 0)
        return NULL;

    if (qemuBuildClockCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    qemuBuildPMCommandLine(cmd, def, priv);

    if (qemuBuildBootCommandLine(cmd, def) < 0)
        return NULL;

    if (qemuBuildIOMMUCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildGlobalControllerCommandLine(cmd, def) < 0)
        return NULL;

    if (qemuBuildControllersCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildMemoryDeviceCommandLine(cmd, cfg, def, priv) < 0)
        return NULL;

    if (qemuBuildHubCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildControllersByTypeCommandLine(cmd, def, qemuCaps,
                                              VIR_DOMAIN_CONTROLLER_TYPE_CCID) < 0)
        return NULL;

    if (qemuBuildDisksCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildFilesystemCommandLine(cmd, def, qemuCaps, priv) < 0)
        return NULL;

    if (qemuBuildNetCommandLine(driver, vm, cmd, qemuCaps, vmop,
                                nnicindexes, nicindexes) < 0)
        return NULL;

    if (qemuBuildSmartcardCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildSerialCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildParallelsCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildChannelsCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildConsoleCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildTPMsCommandLine(cmd, def, priv) < 0)
        return NULL;

    if (qemuBuildInputCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildAudioCommandLine(cmd, def) < 0)
        return NULL;

    if (qemuBuildGraphicsCommandLine(cfg, cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildVideoCommandLine(cmd, def, priv) < 0)
        return NULL;

    if (qemuBuildSoundCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildWatchdogCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildRedirdevCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildHostdevCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (migrateURI)
        virCommandAddArgList(cmd, "-incoming", migrateURI, NULL);

    if (qemuBuildMemballoonCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildRNGCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildNVRAMCommandLine(cmd, def) < 0)
        return NULL;

    if (qemuBuildVMCoreInfoCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildSecCommandLine(vm, cmd, def->sec) < 0)
        return NULL;

    if (snapshot)
        virCommandAddArgList(cmd, "-loadvm", snapshot->def->name, NULL);

    if (def->namespaceData) {
        qemuDomainXmlNsDef *qemuxmlns;
        GStrv n;

        qemuxmlns = def->namespaceData;
        for (n = qemuxmlns->args; n && *n; n++)
            virCommandAddArg(cmd, *n);
        for (i = 0; i < qemuxmlns->num_env; i++)
            virCommandAddEnvPair(cmd, qemuxmlns->env[i].name,
                                 NULLSTR_EMPTY(qemuxmlns->env[i].value));
    }

    if (qemuBuildSeccompSandboxCommandLine(cmd, cfg, qemuCaps) < 0)
        return NULL;

    if (qemuBuildPanicCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    for (i = 0; i < def->nshmems; i++) {
        if (qemuBuildShmemCommandLine(cmd, def, def->shmems[i], qemuCaps) < 0)
            return NULL;
    }

    if (def->vsock &&
        qemuBuildVsockCommandLine(cmd, def, def->vsock, qemuCaps) < 0)
        return NULL;

    if (qemuBuildCryptoCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (qemuBuildAsyncTeardownCommandLine(cmd, def, qemuCaps) < 0)
        return NULL;

    if (cfg->logTimestamp)
        virCommandAddArgList(cmd, "-msg", "timestamp=on", NULL);

    return g_steal_pointer(&cmd);
}


static virJSONValue *
qemuBuildSerialChrDeviceProps(const virDomainDef *def,
                              virDomainChrDef *serial,
                              virQEMUCaps *qemuCaps)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *chardev = g_strdup_printf("char%s", serial->info.alias);
    virQEMUCapsFlags caps;

    switch ((virDomainChrSerialTargetModel) serial->targetModel) {
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_USB_SERIAL:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PCI_SERIAL:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPLMCONSOLE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_DEBUGCON:

        caps = qemuChrSerialTargetModelToCaps(serial->targetModel);

        if (caps && !virQEMUCapsGet(qemuCaps, caps)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("'%1$s' is not supported in this QEMU binary"),
                           virDomainChrSerialTargetModelTypeToString(serial->targetModel));
            return NULL;
        }
        break;

    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_LAST:
        /* Except from _LAST, which is just a guard value and will never
         * be used, all of the above are platform devices, which means
         * qemuBuildSerialCommandLine() will have taken the appropriate
         * branch and we will not have ended up here. */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid target model for serial device"));
        return NULL;
    }

    if (virJSONValueObjectAdd(&props,
                              "s:driver", virDomainChrSerialTargetModelTypeToString(serial->targetModel),
                              "s:chardev", chardev,
                              "s:id", serial->info.alias,
                              NULL) < 0)
        return NULL;

    if (serial->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL &&
        virJSONValueObjectAdd(&props,
                              "k:index", serial->target.port,
                              NULL) < 0)
        return NULL;

    if (qemuBuildDeviceAddressProps(props, def, &serial->info) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValue *
qemuBuildParallelChrDeviceProps(virDomainChrDef *chr)
{
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *chardev = g_strdup_printf("char%s", chr->info.alias);

    if (virJSONValueObjectAdd(&props,
                              "s:driver", "isa-parallel",
                              "s:chardev", chardev,
                              "s:id", chr->info.alias,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


virJSONValue *
qemuBuildChannelGuestfwdNetdevProps(virDomainChrDef *chr)
{
    g_autofree char *guestfwdstr = NULL;
    g_autoptr(virJSONValue) guestfwdstrobj = NULL;
    g_autoptr(virJSONValue) guestfwdarr = virJSONValueNewArray();
    g_autofree char *addr = NULL;
    virJSONValue *ret = NULL;

    if (!(addr = virSocketAddrFormat(chr->target.addr)))
        return NULL;

    guestfwdstr = g_strdup_printf("tcp:%s:%i-chardev:char%s",
                                  addr,
                                  virSocketAddrGetPort(chr->target.addr),
                                  chr->info.alias);

    /* this may seem weird, but qemu indeed decided that 'guestfwd' parameter
     * is an array of objects which have just one member named 'str' which
     * contains the description */
    if (virJSONValueObjectAdd(&guestfwdstrobj, "s:str", guestfwdstr, NULL) < 0)
        return NULL;

    if (virJSONValueArrayAppend(guestfwdarr, &guestfwdstrobj) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&ret,
                              "s:type", "user",
                              "a:guestfwd", &guestfwdarr,
                              "s:id", chr->info.alias,
                              NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValue *
qemuBuildChannelChrDeviceProps(const virDomainDef *def,
                               virDomainChrDef *chr)
{
    switch ((virDomainChrChannelTargetType)chr->targetType) {
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
        return qemuBuildVirtioSerialPortDevProps(def, chr);

    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
        /* guestfwd is as a netdev handled separately */
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE:
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST:
        break;
    }

    return NULL;
}

static virJSONValue *
qemuBuildConsoleChrDeviceProps(const virDomainDef *def,
                               virDomainChrDef *chr)
{
    switch ((virDomainChrConsoleTargetType)chr->targetType) {
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
        return qemuBuildSclpDevProps(chr);

    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
        return qemuBuildVirtioSerialPortDevProps(def, chr);

    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_UML:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported console target type %1$s"),
                       NULLSTR(virDomainChrConsoleTargetTypeToString(chr->targetType)));
        break;
    }

    return NULL;
}


virJSONValue *
qemuBuildChrDeviceProps(const virDomainDef *vmdef,
                        virDomainChrDef *chr,
                        virQEMUCaps *qemuCaps)
{
    switch ((virDomainChrDeviceType)chr->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        return qemuBuildSerialChrDeviceProps(vmdef, chr, qemuCaps);

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        return qemuBuildParallelChrDeviceProps(chr);

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        return qemuBuildChannelChrDeviceProps(vmdef, chr);

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        return qemuBuildConsoleChrDeviceProps(vmdef, chr);

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        break;
    }

    return NULL;
}


virJSONValue *
qemuBuildHotpluggableCPUProps(const virDomainVcpuDef *vcpu)
{
    qemuDomainVcpuPrivate *vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);
    g_autoptr(virJSONValue) ret = NULL;

    if (!(ret = virJSONValueCopy(vcpupriv->props)))
        return NULL;

    if (virJSONValueObjectPrependString(ret, "id", vcpupriv->alias) < 0 ||
        virJSONValueObjectPrependString(ret, "driver", vcpupriv->type) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


/**
 * qemuBuildStorageSourceAttachPrepareDrive:
 * @disk: disk object to prepare
 *
 * Prepare qemuBlockStorageSourceAttachData *for use with the old approach
 * using -drive/drive_add. See qemuBlockStorageSourceAttachPrepareBlockdev.
 */
static qemuBlockStorageSourceAttachData *
qemuBuildStorageSourceAttachPrepareDrive(virDomainDiskDef *disk)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;

    data = g_new0(qemuBlockStorageSourceAttachData, 1);

    if (!(data->driveCmd = qemuBuildDriveStr(disk)))
        return NULL;

    return g_steal_pointer(&data);
}


/**
 * qemuBuildStorageSourceAttachPrepareChardev:
 * @src: disk source to prepare
 *
 * Prepare qemuBlockStorageSourceAttachData *for vhost-user disk
 * to be used with -chardev.
 */
static qemuBlockStorageSourceAttachData *
qemuBuildStorageSourceAttachPrepareChardev(virDomainDiskDef *disk)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;

    data = g_new0(qemuBlockStorageSourceAttachData, 1);

    data->chardevDef = disk->src->vhostuser;
    data->chardevAlias = qemuDomainGetVhostUserChrAlias(disk->info.alias);

    return g_steal_pointer(&data);
}


/**
 * qemuBuildStorageSourceAttachPrepareCommon:
 * @src: storage source
 * @data: already initialized data for disk source addition
 *
 * Prepare data for configuration associated with the disk source such as
 * secrets/TLS/pr objects etc ...
 */
int
qemuBuildStorageSourceAttachPrepareCommon(virStorageSource *src,
                                          qemuBlockStorageSourceAttachData *data)
{
    qemuDomainStorageSourcePrivate *srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *tlsKeySecretAlias = NULL;

    if (src->pr &&
        !virStoragePRDefIsManaged(src->pr) &&
        !(data->prmgrProps = qemuBuildPRManagerInfoProps(src)))
        return -1;

    if (srcpriv) {
        if (srcpriv->secinfo &&
            qemuBuildSecretInfoProps(srcpriv->secinfo, &data->authsecretProps) < 0)
            return -1;

        if (srcpriv->encinfo) {
            size_t i;

            data->encryptsecretCount = srcpriv->enccount;
            data->encryptsecretProps = g_new0(virJSONValue *, srcpriv->enccount);
            data->encryptsecretAlias = g_new0(char *, srcpriv->enccount);

            for (i = 0; i < srcpriv->enccount; ++i) {
                if (qemuBuildSecretInfoProps(srcpriv->encinfo[i], &data->encryptsecretProps[i]) < 0)
                    return -1;
            }
        }

        if (srcpriv->httpcookie &&
            qemuBuildSecretInfoProps(srcpriv->httpcookie, &data->httpcookiesecretProps) < 0)
            return -1;

        if (srcpriv->tlsKeySecret) {
            if (qemuBuildSecretInfoProps(srcpriv->tlsKeySecret, &data->tlsKeySecretProps) < 0)
                return -1;

            tlsKeySecretAlias = srcpriv->tlsKeySecret->alias;
        }

        data->fdpass = srcpriv->fdpass;
    }

    if (src->haveTLS == VIR_TRISTATE_BOOL_YES &&
        qemuBuildTLSx509BackendProps(src->tlsCertdir, false, true, src->tlsAlias,
                                     tlsKeySecretAlias, &data->tlsProps) < 0)
        return -1;

    return 0;
}


/**
 * qemuBuildStorageSourceChainAttachPrepareDrive:
 * @disk: disk definition
 *
 * Prepares qemuBlockStorageSourceChainData *for attaching @disk via -drive.
 */
qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareDrive(virDomainDiskDef *disk)
{
    g_autoptr(qemuBlockStorageSourceAttachData) elem = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    data = g_new0(qemuBlockStorageSourceChainData, 1);

    if (!(elem = qemuBuildStorageSourceAttachPrepareDrive(disk)))
        return NULL;

    if (qemuBuildStorageSourceAttachPrepareCommon(disk->src, elem) < 0)
        return NULL;

    VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, elem);

    return g_steal_pointer(&data);
}


/**
 * qemuBuildStorageSourceChainAttachPrepareChardev:
 * @src: disk definition
 *
 * Prepares qemuBlockStorageSourceChainData *for attaching a vhost-user
 * disk's backend via -chardev.
 */
qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareChardev(virDomainDiskDef *disk)
{
    g_autoptr(qemuBlockStorageSourceAttachData) elem = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    data = g_new0(qemuBlockStorageSourceChainData, 1);

    if (!(elem = qemuBuildStorageSourceAttachPrepareChardev(disk)))
        return NULL;

    VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, elem);

    return g_steal_pointer(&data);
}


static int
qemuBuildStorageSourceChainAttachPrepareBlockdevOne(qemuBlockStorageSourceChainData *data,
                                                    virStorageSource *src,
                                                    virStorageSource *backingStore)
{
    g_autoptr(qemuBlockStorageSourceAttachData) elem = NULL;

    if (!(elem = qemuBlockStorageSourceAttachPrepareBlockdev(src, backingStore)))
        return -1;

    if (qemuBuildStorageSourceAttachPrepareCommon(src, elem) < 0)
        return -1;

    VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, elem);

    return 0;
}


/**
 * qemuBuildStorageSourceChainAttachPrepareBlockdev:
 * @top: storage source chain
 *
 * Prepares qemuBlockStorageSourceChainData *for attaching the chain of images
 * starting at @top via -blockdev.
 */
qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdev(virStorageSource *top)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    virStorageSource *n;

    data = g_new0(qemuBlockStorageSourceChainData, 1);

    for (n = top; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (qemuBuildStorageSourceChainAttachPrepareBlockdevOne(data, n,
                                                                n->backingStore) < 0)
            return NULL;
    }

    return g_steal_pointer(&data);
}


/**
 * qemuBuildStorageSourceChainAttachPrepareBlockdevTop:
 * @top: storage source chain
 * @backingStore: a storage source to use as backing of @top
 *
 * Prepares qemuBlockStorageSourceChainData *for attaching of @top image only
 * via -blockdev.
 */
qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdevTop(virStorageSource *top,
                                                    virStorageSource *backingStore)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    data = g_new0(qemuBlockStorageSourceChainData, 1);

    if (qemuBuildStorageSourceChainAttachPrepareBlockdevOne(data, top, backingStore) < 0)
        return NULL;

    return g_steal_pointer(&data);
}


/* qemuVDPAConnect:
 * @devicepath: the path to the vdpa device
 *
 * returns: file descriptor of the vdpa device
 */
int
qemuVDPAConnect(const char *devicepath)
{
    int fd;

    if ((fd = open(devicepath, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open '%1$s' for vdpa device"),
                             devicepath);
        return -1;
    }

    return fd;
}
