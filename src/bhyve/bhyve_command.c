/*
 * bhyve_command.c: bhyve command generation
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 */

#include <config.h>

#include "bhyve_capabilities.h"
#include "bhyve_command.h"
#include "bhyve_domain.h"
#include "bhyve_conf.h"
#include "bhyve_driver.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virlog.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_command");

static int
bhyveBuildNetArgStr(const virDomainDef *def,
                    virDomainNetDef *net,
                    struct _bhyveConn *driver,
                    virCommand *cmd,
                    bool dryRun)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char *realifname = NULL;
    char *brname = NULL;
    char *nic_model = NULL;
    int ret = -1;
    virDomainNetType actualType = virDomainNetGetActualType(net);

    if (net->model == VIR_DOMAIN_NET_MODEL_VIRTIO) {
        nic_model = g_strdup("virtio-net");
    } else if (net->model == VIR_DOMAIN_NET_MODEL_E1000) {
        if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_NET_E1000) != 0) {
            nic_model = g_strdup("e1000");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("NIC model 'e1000' is not supported by given bhyve binary"));
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("NIC model is not supported"));
        return -1;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        brname = g_strdup(virDomainNetGetActualBridgeName(net));
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Network type %1$d is not supported"),
                       virDomainNetGetActualType(net));
        goto cleanup;
    }

    if (!dryRun) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, NULL, NULL, 0,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           virDomainNetGetActualPortOptionsIsolated(net),
                                           NULL, 0, NULL,
                                           VIR_NETDEV_TAP_CREATE_IFUP | VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
            goto cleanup;
        }

        realifname = virNetDevTapGetRealDeviceName(net->ifname);

        if (realifname == NULL)
            goto cleanup;

        VIR_DEBUG("%s -> %s", net->ifname, realifname);
        /* hack on top of other hack: we need to set
         * interface to 'UP' again after re-opening to find its
         * name
         */
        if (virNetDevSetOnline(net->ifname, true) != 0)
            goto cleanup;
    } else {
        realifname = g_strdup("tap0");
    }


    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,%s,%s,mac=%s",
                           net->info.addr.pci.slot, nic_model,
                           realifname, virMacAddrFormat(&net->mac, macaddr));

    ret = 0;
 cleanup:
    if (ret < 0)
        VIR_FREE(net->ifname);
    VIR_FREE(brname);
    VIR_FREE(realifname);
    VIR_FREE(nic_model);

    return ret;
}

static int
bhyveBuildConsoleArgStr(const virDomainDef *def, virCommand *cmd)
{
    virDomainChrDef *chr = NULL;

    if (!def->nserials)
        return 0;

    chr = def->serials[0];

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_NMDM) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only nmdm console types are supported"));
        return -1;
    }

    /* bhyve supports only two ports: com1 and com2 */
    if (chr->target.port > 2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only two serial ports are supported"));
        return -1;
    }

    virCommandAddArg(cmd, "-l");
    virCommandAddArgFormat(cmd, "com%d,%s",
                           chr->target.port + 1, chr->source->data.file.path);

    return 0;
}

static int
bhyveBuildAHCIControllerArgStr(const virDomainDef *def,
                               virDomainControllerDef *controller,
                               struct _bhyveConn *driver,
                               virCommand *cmd)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *disk_source;
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        g_auto(virBuffer) device = VIR_BUFFER_INITIALIZER;
        virDomainDiskDef *disk = def->disks[i];

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SATA)
            continue;

        if (disk->info.addr.drive.controller != controller->idx)
            continue;

        VIR_DEBUG("disk %zu controller %d", i, controller->idx);

        if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
            (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk type"));
            return -1;
        }

        if (virDomainDiskTranslateSourcePool(disk) < 0)
            return -1;

        disk_source = virDomainDiskGetSource(disk);

        if ((disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
            (disk_source == NULL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cdrom device without source path not supported"));
            return -1;
        }

        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_AHCI32SLOT))
                virBufferAsprintf(&device, ",hd:%s", disk_source);
            else
                virBufferAsprintf(&device, "-hd,%s", disk_source);
            break;
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_AHCI32SLOT))
                virBufferAsprintf(&device, ",cd:%s", disk_source);
            else
                virBufferAsprintf(&device, "-cd,%s", disk_source);
            break;
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
        case VIR_DOMAIN_DISK_DEVICE_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            return -1;
        }
        virBufferAddBuffer(&buf, &device);
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,ahci%s",
                           controller->info.addr.pci.slot,
                           virBufferCurrentContent(&buf));

    return 0;
}

static int
bhyveBuildUSBControllerArgStr(const virDomainDef *def,
                              virDomainControllerDef *controller,
                              virCommand *cmd)
{
    size_t i;
    int ndevices = 0;

    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDef *input = def->inputs[i];

        if (input->bus != VIR_DOMAIN_INPUT_BUS_USB) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only USB input devices are supported"));
            return -1;
        }

        if (input->type != VIR_DOMAIN_INPUT_TYPE_TABLET) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only tablet input devices are supported"));
            return -1;
        }
        ndevices++;
    }

    if (ndevices != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only single input device is supported"));
        return -1;
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:%d,xhci,tablet",
                           controller->info.addr.pci.slot,
                           controller->info.addr.pci.function);

    return 0;
}

static int
bhyveBuildVirtIODiskArgStr(const virDomainDef *def G_GNUC_UNUSED,
                           virDomainDiskDef *disk,
                           virCommand *cmd)
{
    const char *disk_source;

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        return -1;

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return -1;
    }

    if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
        (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return -1;
    }

    disk_source = virDomainDiskGetSource(disk);

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,virtio-blk,%s",
                           disk->info.addr.pci.slot,
                           disk_source);

    return 0;
}

static int
bhyveBuildDiskArgStr(const virDomainDef *def,
                     virDomainDiskDef *disk,
                     virCommand *cmd)
{
    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        /* Handled by bhyveBuildAHCIControllerArgStr() */
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (bhyveBuildVirtIODiskArgStr(def, disk, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return -1;
    }
    return 0;
}

static int
bhyveBuildControllerArgStr(const virDomainDef *def,
                           virDomainControllerDef *controller,
                           struct _bhyveConn *driver,
                           virCommand *cmd,
                           unsigned *nusbcontrollers,
                           unsigned *nisacontrollers)
{
    switch (controller->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        if (controller->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported PCI controller model: only PCI root supported"));
            return -1;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        if (bhyveBuildAHCIControllerArgStr(def, controller, driver, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (++*nusbcontrollers > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only single USB controller is supported"));
            return -1;
        }

        if (bhyveBuildUSBControllerArgStr(def, controller, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
        if (++*nisacontrollers > 1) {
             virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            "%s", _("only single ISA controller is supported"));
             return -1;
        }
        virCommandAddArg(cmd, "-s");
        virCommandAddArgFormat(cmd, "%d:0,lpc",
                                controller->info.addr.pci.slot);
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported controller device"));
        return -1;

    }
    return 0;
}

static int
bhyveBuildGraphicsArgStr(const virDomainDef *def,
                         virDomainGraphicsDef *graphics,
                         virDomainVideoDef *video,
                         struct _bhyveConn *driver,
                         virCommand *cmd,
                         bool dryRun)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    virDomainGraphicsListenDef *glisten = NULL;
    bool escapeAddr;
    unsigned short port;

    if (!(bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_LPC_BOOTROM) ||
        def->os.bootloader ||
        !def->os.loader) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Graphics are only supported when booting using UEFI"));
        return -1;
    }

    if (!(bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_FBUF)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Bhyve version does not support framebuffer"));
        return -1;
    }

    if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only VNC supported"));
        return -1;
    }

    if (!(glisten = virDomainGraphicsGetListen(graphics, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing listen element"));
        return -1;
    }

    virBufferAsprintf(&opt, "%d:%d,fbuf", video->info.addr.pci.slot, video->info.addr.pci.function);

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        virBufferAddLit(&opt, ",tcp=");

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

        if (!dryRun) {
            if (graphics->data.vnc.autoport) {
                if (virPortAllocatorAcquire(driver->remotePorts, &port) < 0)
                    return -1;
                graphics->data.vnc.port = port;
            } else {
                if (virPortAllocatorSetUsed(graphics->data.vnc.port) < 0)
                    VIR_WARN("Failed to mark VNC port '%d' as used by '%s'",
                             graphics->data.vnc.port, def->name);
            }
        }

        virBufferAsprintf(&opt, ":%d", graphics->data.vnc.port);
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported listen type"));
        return -1;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainGraphicsListenType, glisten->type);
        return -1;
    }

    if (graphics->data.vnc.auth.passwd) {
        if (!(bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_VNC_PASSWORD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VNC Password authentication not supported by bhyve"));
            return -1;
        }

        if (strchr(graphics->data.vnc.auth.passwd, ',')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Password may not contain ',' character"));
            return -1;
        }

        virBufferAsprintf(&opt, ",password=%s", graphics->data.vnc.auth.passwd);
    } else {
        if (!(bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_VNC_PASSWORD))
            VIR_WARN("%s", _("Security warning: VNC auth is not supported."));
        else
            VIR_WARN("%s", _("Security warning: VNC is used without authentication."));
    }

    if (video->res)
        virBufferAsprintf(&opt, ",w=%d,h=%d", video->res->x, video->res->y);

    if (video->driver)
        virBufferAsprintf(&opt, ",vga=%s",
                          virDomainVideoVGAConfTypeToString(video->driver->vgaconf));

    virCommandAddArg(cmd, "-s");
    virCommandAddArgBuffer(cmd, &opt);
    return 0;

}

static int
bhyveBuildSoundArgStr(const virDomainDef *def G_GNUC_UNUSED,
                      virDomainSoundDef *sound,
                      virDomainAudioDef *audio,
                      struct _bhyveConn *driver,
                      virCommand *cmd)
{
    g_auto(virBuffer) params = VIR_BUFFER_INITIALIZER;

    if (!(bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_SOUND_HDA)) {
        /* Currently, bhyve only supports "hda" sound devices, so
           if it's not supported, sound devices are not supported at all */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Sound devices emulation is not supported by given bhyve binary"));
        return -1;
    }

    if (sound->model != VIR_DOMAIN_SOUND_MODEL_ICH7) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Sound device model is not supported"));
        return -1;
    }

    virCommandAddArg(cmd, "-s");

    if (audio) {
        switch (audio->type) {
        case  VIR_DOMAIN_AUDIO_TYPE_OSS:
            if (virDomainAudioIOCommonIsSet(&audio->input) ||
                virDomainAudioIOCommonIsSet(&audio->output)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("cannot set common audio backend settings"));
                return -1;
            }

            if (audio->backend.oss.input.dev)
                virBufferAsprintf(&params, ",play=%s",
                                  audio->backend.oss.input.dev);

            if (audio->backend.oss.output.dev)
                virBufferAsprintf(&params, ",rec=%s",
                                  audio->backend.oss.output.dev);

            break;

        case VIR_DOMAIN_AUDIO_TYPE_NONE:
        case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        case VIR_DOMAIN_AUDIO_TYPE_JACK:
        case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        case VIR_DOMAIN_AUDIO_TYPE_SDL:
        case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        case VIR_DOMAIN_AUDIO_TYPE_FILE:
        case VIR_DOMAIN_AUDIO_TYPE_DBUS:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported audio backend '%1$s'"),
                           virDomainAudioTypeTypeToString(audio->type));
            return -1;
        case VIR_DOMAIN_AUDIO_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainAudioType, audio->type);
            return -1;
        }
    }

    virCommandAddArgFormat(cmd, "%d:%d,hda%s",
                           sound->info.addr.pci.slot,
                           sound->info.addr.pci.function,
                           virBufferCurrentContent(&params));

    return 0;
}

static int
bhyveBuildFSArgStr(const virDomainDef *def G_GNUC_UNUSED,
                   virDomainFSDef *fs,
                   virCommand *cmd)
{
    g_auto(virBuffer) params = VIR_BUFFER_INITIALIZER;

    switch (fs->type) {
    case VIR_DOMAIN_FS_TYPE_MOUNT:
        break;
    case VIR_DOMAIN_FS_TYPE_BLOCK:
    case VIR_DOMAIN_FS_TYPE_FILE:
    case VIR_DOMAIN_FS_TYPE_TEMPLATE:
    case VIR_DOMAIN_FS_TYPE_RAM:
    case VIR_DOMAIN_FS_TYPE_BIND:
    case VIR_DOMAIN_FS_TYPE_VOLUME:
    case VIR_DOMAIN_FS_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem type '%1$s'"),
                       virDomainFSTypeToString(fs->type));
        return -1;
    }

    switch (fs->fsdriver) {
    case VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT:
        /* The only supported driver by bhyve currently */
        break;
    case VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PATH:
    case VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE:
    case VIR_DOMAIN_FS_DRIVER_TYPE_LOOP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_NBD:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem driver '%1$s'"),
                       virDomainFSDriverTypeToString(fs->fsdriver));
        return -1;
    }

    switch (fs->accessmode) {
    case VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH:
        /* This is the only supported mode for now, does not need specific configuration */
        break;
    case VIR_DOMAIN_FS_ACCESSMODE_MAPPED:
    case VIR_DOMAIN_FS_ACCESSMODE_SQUASH:
    case VIR_DOMAIN_FS_ACCESSMODE_DEFAULT:
    case VIR_DOMAIN_FS_ACCESSMODE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem accessmode '%1$s'"),
                       virDomainFSAccessModeTypeToString(fs->accessmode));
        return -1;
    }

    if (fs->readonly)
        virBufferAddLit(&params, ",ro");

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:%d,virtio-9p,%s=%s%s",
                           fs->info.addr.pci.slot,
                           fs->info.addr.pci.function,
                           fs->dst,
                           fs->src->path,
                           virBufferCurrentContent(&params));

    return 0;
}

virCommand *
virBhyveProcessBuildBhyveCmd(struct _bhyveConn *driver, virDomainDef *def,
                             bool dryRun)
{
    /*
     * /usr/sbin/bhyve -c 2 -m 256 -AI -H -P \
     *            -s 0:0,hostbridge \
     *            -s 1:0,virtio-net,tap0 \
     *            -s 2:0,ahci-hd,${IMG} \
     *            -S 31,uart,stdio \
     *            vm0
     */
    g_autoptr(virCommand) cmd = virCommandNew(BHYVE);
    size_t i;
    unsigned nusbcontrollers = 0;
    unsigned nisacontrollers = 0;
    unsigned nvcpus = virDomainDefGetVcpus(def);

    /* CPUs */
    virCommandAddArg(cmd, "-c");
    if (def->cpu && def->cpu->sockets) {
        if (def->cpu->dies != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only 1 die per socket is supported"));
            return NULL;
        }
        if (nvcpus != def->cpu->sockets * def->cpu->cores * def->cpu->threads) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid CPU topology: total number of vCPUs must equal the product of sockets, cores, and threads"));
            return NULL;
        }

        if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_CPUTOPOLOGY) != 0) {
            virCommandAddArgFormat(cmd, "cpus=%d,sockets=%d,cores=%d,threads=%d",
                                   nvcpus,
                                   def->cpu->sockets,
                                   def->cpu->cores,
                                   def->cpu->threads);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support defining CPU topology"));
            return NULL;
        }
    } else {
        virCommandAddArgFormat(cmd, "%d", nvcpus);
    }

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%llu",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    if (def->mem.locked)
        virCommandAddArg(cmd, "-S"); /* Wire guest memory */

    /* Options */
    if (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON)
        virCommandAddArg(cmd, "-A"); /* Create an ACPI table */
    if (def->features[VIR_DOMAIN_FEATURE_APIC] == VIR_TRISTATE_SWITCH_ON)
        virCommandAddArg(cmd, "-I"); /* Present ioapic to the guest */
    if (def->features[VIR_DOMAIN_FEATURE_MSRS] == VIR_TRISTATE_SWITCH_ON) {
        if (def->msrs_features[VIR_DOMAIN_MSRS_UNKNOWN] == VIR_DOMAIN_MSRS_UNKNOWN_IGNORE)
            virCommandAddArg(cmd, "-w");
    }

    switch (def->clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
        /* used by default in bhyve */
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_RTC_UTC) != 0) {
            virCommandAddArg(cmd, "-u");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support UTC clock"));
            return NULL;
        }
        break;
    default:
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("unsupported clock offset '%1$s'"),
                        virDomainClockOffsetTypeToString(def->clock.offset));
         return NULL;
    }

    /* Clarification about -H and -P flags from Peter Grehan:
     * -H and -P flags force the guest to exit when it executes IA32 HLT and PAUSE
     * instructions respectively.
     *
     * For the HLT exit, bhyve uses that to infer that the guest is idling and can
     * be put to sleep until an external event arrives. If this option is not used,
     * the guest will always use 100% of CPU on the host.
     *
     * The PAUSE exit is most useful when there are large numbers of guest VMs running,
     * since it forces the guest to exit when it spins on a lock acquisition.
     */
    virCommandAddArg(cmd, "-H"); /* vmexit from guest on hlt */
    virCommandAddArg(cmd, "-P"); /* vmexit from guest on pause */

    virCommandAddArgList(cmd, "-s", "0:0,hostbridge", NULL);

    if (def->os.bootloader == NULL &&
        def->os.loader) {
        if ((bhyveDriverGetBhyveCaps(driver) & BHYVE_CAP_LPC_BOOTROM)) {
            virCommandAddArg(cmd, "-l");
            virCommandAddArgFormat(cmd, "bootrom,%s", def->os.loader->path);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support UEFI loader"));
            return NULL;
        }
    }

    /* Devices */
    for (i = 0; i < def->ncontrollers; i++) {
        if (bhyveBuildControllerArgStr(def, def->controllers[i], driver, cmd,
                                       &nusbcontrollers, &nisacontrollers) < 0)
            return NULL;
    }
    for (i = 0; i < def->nnets; i++) {
        if (bhyveBuildNetArgStr(def, def->nets[i], driver, cmd, dryRun) < 0)
            return NULL;
    }
    for (i = 0; i < def->ndisks; i++) {
        if (bhyveBuildDiskArgStr(def, def->disks[i], cmd) < 0)
            return NULL;
    }

    if (def->ngraphics && def->nvideos) {
        if (def->ngraphics == 1 && def->nvideos == 1) {
            if (bhyveBuildGraphicsArgStr(def, def->graphics[0], def->videos[0],
                                         driver, cmd, dryRun) < 0)
                return NULL;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Multiple graphics devices are not supported"));
             return NULL;
        }
    }

    for (i = 0; i < def->nsounds; i++) {
        if (bhyveBuildSoundArgStr(def, def->sounds[i],
                                  virDomainDefFindAudioByID(def, def->sounds[i]->audioId),
                                  driver, cmd) < 0)
            return NULL;
    }

    for (i = 0; i < def->nfss; i++) {
        if (bhyveBuildFSArgStr(def, def->fss[i], cmd) < 0)
            return NULL;
    }

    if (bhyveBuildConsoleArgStr(def, cmd) < 0)
        return NULL;

    if (def->namespaceData) {
        bhyveDomainCmdlineDef *bhyvecmd;

        VIR_WARN("Booting the guest using command line pass-through feature, "
                 "which could potentially cause inconsistent state and "
                 "upgrade issues");

        bhyvecmd = def->namespaceData;
        for (i = 0; i < bhyvecmd->num_args; i++)
            virCommandAddArg(cmd, bhyvecmd->args[i]);
    }

    virCommandAddArg(cmd, def->name);

    return g_steal_pointer(&cmd);
}

virCommand *
virBhyveProcessBuildDestroyCmd(struct _bhyveConn *driver G_GNUC_UNUSED,
                               virDomainDef *def)
{
    virCommand *cmd = virCommandNew(BHYVECTL);

    virCommandAddArg(cmd, "--destroy");
    virCommandAddArgPair(cmd, "--vm", def->name);

    return cmd;
}

static void
virAppendBootloaderArgs(virCommand *cmd, virDomainDef *def)
{
    g_auto(GStrv) blargs = NULL;

    /* XXX: Handle quoted? */
    blargs = g_strsplit(def->os.bootloaderArgs, " ", 0);
    virCommandAddArgSet(cmd, (const char * const *)blargs);
}

static virCommand *
virBhyveProcessBuildBhyveloadCmd(virDomainDef *def, virDomainDiskDef *disk)
{
    virCommand *cmd;

    cmd = virCommandNew(BHYVELOAD);

    if (def->os.bootloaderArgs == NULL) {
        VIR_DEBUG("bhyveload with default arguments");

        /* Memory (MB) */
        virCommandAddArg(cmd, "-m");
        virCommandAddArgFormat(cmd, "%llu",
                               VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

        /* Image path */
        virCommandAddArg(cmd, "-d");
        virCommandAddArg(cmd, virDomainDiskGetSource(disk));

        /* VM name */
        virCommandAddArg(cmd, def->name);
    } else {
        VIR_DEBUG("bhyveload with arguments");
        virAppendBootloaderArgs(cmd, def);
    }

    return cmd;
}

static virCommand *
virBhyveProcessBuildCustomLoaderCmd(virDomainDef *def)
{
    virCommand *cmd;

    if (def->os.bootloaderArgs == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Custom loader requires explicit %1$s configuration"),
                       "bootloader_args");
        return NULL;
    }

    VIR_DEBUG("custom loader '%s' with arguments", def->os.bootloader);

    cmd = virCommandNew(def->os.bootloader);
    virAppendBootloaderArgs(cmd, def);
    return cmd;
}

static bool
virBhyveUsableDisk(virDomainDiskDef *disk)
{
    if (virDomainDiskTranslateSourcePool(disk) < 0)
        return false;

    if ((disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) &&
        (disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return false;
    }

    if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
        (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return false;
    }

    return true;
}

static void
virBhyveFormatGrubDevice(virBuffer *devicemap, virDomainDiskDef *def)
{
    if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAsprintf(devicemap, "(cd) %s\n",
                          virDomainDiskGetSource(def));
    else
        virBufferAsprintf(devicemap, "(hd0) %s\n",
                          virDomainDiskGetSource(def));
}

static virCommand *
virBhyveProcessBuildGrubbhyveCmd(virDomainDef *def,
                                 struct _bhyveConn *driver,
                                 const char *devmap_file,
                                 char **devicesmap_out)
{
    virDomainDiskDef *hdd;
    virDomainDiskDef *cd;
    virDomainDiskDef *userdef;
    virDomainDiskDef *diskdef;
    virCommand *cmd;
    unsigned int best_idx = UINT_MAX;
    size_t i;

    if (def->os.bootloaderArgs != NULL)
        return virBhyveProcessBuildCustomLoaderCmd(def);

    /* Search disk list for CD or HDD device. We'll respect <boot order=''> if
     * present and otherwise pick the first CD or failing that HDD we come
     * across. */
    cd = hdd = userdef = NULL;
    for (i = 0; i < def->ndisks; i++) {
        if (!virBhyveUsableDisk(def->disks[i]))
            continue;

        diskdef = def->disks[i];

        if (diskdef->info.bootIndex && diskdef->info.bootIndex < best_idx) {
            userdef = diskdef;
            best_idx = userdef->info.bootIndex;
            continue;
        }

        if (cd == NULL &&
            def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
            cd = diskdef;
            VIR_INFO("Picking %s as CD", virDomainDiskGetSource(cd));
        }

        if (hdd == NULL &&
            def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            hdd = diskdef;
            VIR_INFO("Picking %s as HDD", virDomainDiskGetSource(hdd));
        }
    }

    cmd = virCommandNew(def->os.bootloader);

    VIR_DEBUG("grub-bhyve with default arguments");

    if (devicesmap_out != NULL) {
        g_auto(virBuffer) devicemap = VIR_BUFFER_INITIALIZER;

        /* Grub device.map (just for boot) */
        if (userdef != NULL) {
            virBhyveFormatGrubDevice(&devicemap, userdef);
        } else {
            if (hdd != NULL)
                virBhyveFormatGrubDevice(&devicemap, hdd);

            if (cd != NULL)
                virBhyveFormatGrubDevice(&devicemap, cd);
        }

        *devicesmap_out = virBufferContentAndReset(&devicemap);
    }

    virCommandAddArg(cmd, "--root");
    if (userdef != NULL) {
        if (userdef->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
            virCommandAddArg(cmd, "cd");
        else
            virCommandAddArg(cmd, "hd0,msdos1");
    } else if (cd != NULL) {
        virCommandAddArg(cmd, "cd");
    } else {
        virCommandAddArg(cmd, "hd0,msdos1");
    }

    virCommandAddArg(cmd, "--device-map");
    virCommandAddArg(cmd, devmap_file);

    /* Memory in MB */
    virCommandAddArg(cmd, "--memory");
    virCommandAddArgFormat(cmd, "%llu",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    if ((bhyveDriverGetGrubCaps(driver) & BHYVE_GRUB_CAP_CONSDEV) != 0 &&
        def->nserials > 0) {
        virDomainChrDef *chr;

        chr = def->serials[0];

        if (chr->source->type != VIR_DOMAIN_CHR_TYPE_NMDM) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only nmdm console types are supported"));
            return NULL;
        }

        virCommandAddArg(cmd, "--cons-dev");
        virCommandAddArg(cmd, chr->source->data.file.path);
    }

    /* VM name */
    virCommandAddArg(cmd, def->name);

    return cmd;
}

static virDomainDiskDef *
virBhyveGetBootDisk(virDomainDef *def)
{
    size_t i;
    virDomainDiskDef *match = NULL;
    int boot_dev = -1;

    if (def->ndisks < 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Domain should have at least one disk defined"));
        return NULL;
    }

    if (def->os.nBootDevs > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only one boot device is supported"));
        return NULL;
    } else if (def->os.nBootDevs == 1) {
        switch (def->os.bootDevs[0]) {
        case VIR_DOMAIN_BOOT_CDROM:
            boot_dev = VIR_DOMAIN_DISK_DEVICE_CDROM;
            break;
        case VIR_DOMAIN_BOOT_DISK:
            boot_dev = VIR_DOMAIN_DISK_DEVICE_DISK;
            break;
        case VIR_DOMAIN_BOOT_FLOPPY:
        case VIR_DOMAIN_BOOT_NET:
        case VIR_DOMAIN_BOOT_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cannot boot from device %1$s"),
                           virDomainBootTypeToString(def->os.bootDevs[0]));
            return NULL;
        }
    }

    if (boot_dev != -1) {
        /* If boot_dev is set, we return the first device of
         * the request type */
        for (i = 0; i < def->ndisks; i++) {
            if (!virBhyveUsableDisk(def->disks[i]))
                continue;

            if (def->disks[i]->device == boot_dev) {
                match = def->disks[i];
                break;
            }
        }

        if (match == NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cannot find boot device of requested type %1$s"),
                           virDomainBootTypeToString(def->os.bootDevs[0]));
            return NULL;
        }
    } else {
        /* Otherwise, if boot_dev is not set, we try to find if bootIndex
         * is set for individual device. However, as bhyve does not support
         * specifying real boot priority for devices, we allow only single
         * device with boot priority set.
         */
        int first_usable_disk_index = -1;

        for (i = 0; i < def->ndisks; i++) {
            if (!virBhyveUsableDisk(def->disks[i]))
                continue;
            else
                first_usable_disk_index = i;

            if (def->disks[i]->info.bootIndex > 0) {
                if (match == NULL) {
                    match = def->disks[i];
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only one boot device is supported"));
                    return NULL;
                }
            }
        }

        /* If user didn't explicitly specify boot priority,
         * just return the first usable disk */
        if ((match == NULL) && (first_usable_disk_index >= 0))
            return def->disks[first_usable_disk_index];
    }

    return match;
}

virCommand *
virBhyveProcessBuildLoadCmd(struct _bhyveConn *driver, virDomainDef *def,
                            const char *devmap_file, char **devicesmap_out)
{
    virDomainDiskDef *disk = NULL;

    if (def->os.bootloader == NULL) {
        disk = virBhyveGetBootDisk(def);

        if (disk == NULL)
            return NULL;

        return virBhyveProcessBuildBhyveloadCmd(def, disk);
    } else if (strstr(def->os.bootloader, "grub-bhyve") != NULL) {
        return virBhyveProcessBuildGrubbhyveCmd(def, driver, devmap_file,
                                                devicesmap_out);
    } else {
        return virBhyveProcessBuildCustomLoaderCmd(def);
    }
}
