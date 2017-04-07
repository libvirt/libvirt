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

#include <sys/types.h>
#include <net/if.h>
#include <net/if_tap.h>

#include "bhyve_capabilities.h"
#include "bhyve_command.h"
#include "bhyve_domain.h"
#include "bhyve_driver.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virlog.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"
#include "storage/storage_driver.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_command");

static int
bhyveBuildNetArgStr(virConnectPtr conn,
                    const virDomainDef *def,
                    virDomainNetDefPtr net,
                    virCommandPtr cmd,
                    bool dryRun)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char *realifname = NULL;
    char *brname = NULL;
    char *nic_model = NULL;
    int ret = -1;
    virDomainNetType actualType = virDomainNetGetActualType(net);

    if (STREQ(net->model, "virtio")) {
        if (VIR_STRDUP(nic_model, "virtio-net") < 0)
            return -1;
    } else if (STREQ(net->model, "e1000")) {
        if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_NET_E1000) != 0) {
            if (VIR_STRDUP(nic_model, "e1000") < 0)
                return -1;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("NIC model 'e1000' is not supported "
                             "by given bhyve binary"));
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("NIC model '%s' is not supported"),
                       net->model);
        return -1;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        if (VIR_STRDUP(brname, virDomainNetGetActualBridgeName(net)) < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Network type %d is not supported"),
                       virDomainNetGetActualType(net));
        goto cleanup;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, VIR_NET_GENERATED_PREFIX) ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (VIR_STRDUP(net->ifname, VIR_NET_GENERATED_PREFIX "%d") < 0)
            goto cleanup;
    }

    if (!dryRun) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, NULL, NULL, 0,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
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
        if (VIR_STRDUP(realifname, "tap0") < 0)
            goto cleanup;
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
bhyveBuildConsoleArgStr(const virDomainDef *def, virCommandPtr cmd)
{

    virDomainChrDefPtr chr = NULL;

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
                               virDomainControllerDefPtr controller,
                               virConnectPtr conn,
                               virCommandPtr cmd)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virBuffer device = VIR_BUFFER_INITIALIZER;
    const char *disk_source;
    size_t i;
    int ret = -1;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];
        if (disk->bus != VIR_DOMAIN_DISK_BUS_SATA)
            continue;

        if (disk->info.addr.drive.controller != controller->idx)
            continue;

        VIR_DEBUG("disk %zu controller %d", i, controller->idx);

        if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
            (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk type"));
            goto error;
        }

        if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
            goto error;

        disk_source = virDomainDiskGetSource(disk);

        if ((disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
            (disk_source == NULL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("cdrom device without source path "
                                 "not supported"));
                goto error;
        }

        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_AHCI32SLOT))
                virBufferAsprintf(&device, ",hd:%s", disk_source);
            else
                virBufferAsprintf(&device, "-hd,%s", disk_source);
            break;
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_AHCI32SLOT))
                virBufferAsprintf(&device, ",cd:%s", disk_source);
            else
                virBufferAsprintf(&device, "-cd,%s", disk_source);
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            goto error;
        }
        virBufferAddBuffer(&buf, &device);
        virBufferFreeAndReset(&device);
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,ahci%s",
                           controller->info.addr.pci.slot,
                           virBufferCurrentContent(&buf));

    ret = 0;
 error:
    virBufferFreeAndReset(&buf);
    return ret;
}

static int
bhyveBuildUSBControllerArgStr(const virDomainDef *def,
                              virDomainControllerDefPtr controller,
                              virCommandPtr cmd)
{
    size_t i;
    int ndevices = 0;

    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDefPtr input = def->inputs[i];

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
bhyveBuildVirtIODiskArgStr(const virDomainDef *def ATTRIBUTE_UNUSED,
                     virDomainDiskDefPtr disk,
                     virConnectPtr conn,
                     virCommandPtr cmd)
{
    const char *disk_source;

    if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
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
bhyveBuildLPCArgStr(const virDomainDef *def ATTRIBUTE_UNUSED,
                    virCommandPtr cmd)
{
    virCommandAddArgList(cmd, "-s", "1,lpc", NULL);
    return 0;
}

static int
bhyveBuildGraphicsArgStr(const virDomainDef *def ATTRIBUTE_UNUSED,
                         virDomainGraphicsDefPtr graphics,
                         virDomainVideoDefPtr video,
                         virConnectPtr conn,
                         virCommandPtr cmd)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    virDomainGraphicsListenDefPtr glisten = NULL;
    bool escapeAddr;

    if (!(bhyveDriverGetCaps(conn) & BHYVE_CAP_LPC_BOOTROM) ||
        def->os.bootloader ||
        !def->os.loader) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Graphics are only supported"
                         " when booting using UEFI"));
        return -1;
    }

    if (!(bhyveDriverGetCaps(conn) & BHYVE_CAP_FBUF)) {
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
        goto error;
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
            goto error;
        }

        if (graphics->data.vnc.auth.passwd) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc password auth not supported"));
            goto error;
        } else {
             /* Bhyve doesn't support VNC Auth yet, so print a warning about
              * unauthenticated VNC sessions */
             VIR_WARN("%s", _("Security warning: currently VNC auth is not"
                              " supported."));
        }

        if (glisten->address) {
            escapeAddr = strchr(glisten->address, ':') != NULL;
            if (escapeAddr)
                virBufferAsprintf(&opt, "[%s]", glisten->address);
            else
                virBufferAdd(&opt, glisten->address, -1);
        }

        virBufferAsprintf(&opt, ":%d", graphics->data.vnc.port);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported listen type"));
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgBuffer(cmd, &opt);
    return 0;

 error:
    virBufferFreeAndReset(&opt);
    return -1;
}

virCommandPtr
virBhyveProcessBuildBhyveCmd(virConnectPtr conn,
                             virDomainDefPtr def, bool dryRun)
{
    /*
     * /usr/sbin/bhyve -c 2 -m 256 -AI -H -P \
     *            -s 0:0,hostbridge \
     *            -s 1:0,virtio-net,tap0 \
     *            -s 2:0,ahci-hd,${IMG} \
     *            -S 31,uart,stdio \
     *            vm0
     */
    size_t i;
    bool add_lpc = false;
    int nusbcontrollers = 0;

    virCommandPtr cmd = virCommandNew(BHYVE);

    /* CPUs */
    virCommandAddArg(cmd, "-c");
    virCommandAddArgFormat(cmd, "%d", virDomainDefGetVcpus(def));

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%llu",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    /* Options */
    if (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON)
        virCommandAddArg(cmd, "-A"); /* Create an ACPI table */
    if (def->features[VIR_DOMAIN_FEATURE_APIC] == VIR_TRISTATE_SWITCH_ON)
        virCommandAddArg(cmd, "-I"); /* Present ioapic to the guest */

    switch (def->clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
        /* used by default in bhyve */
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_RTC_UTC) != 0) {
            virCommandAddArg(cmd, "-u");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support "
                          "UTC clock"));
            goto error;
        }
        break;
    default:
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("unsupported clock offset '%s'"),
                        virDomainClockOffsetTypeToString(def->clock.offset));
         goto error;
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
        if ((bhyveDriverGetCaps(conn) & BHYVE_CAP_LPC_BOOTROM)) {
            virCommandAddArg(cmd, "-l");
            virCommandAddArgFormat(cmd, "bootrom,%s", def->os.loader->path);
            add_lpc = true;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Installed bhyve binary does not support "
                             "UEFI loader"));
            goto error;
        }
    }

    /* Devices */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr controller = def->controllers[i];
        switch (controller->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
                if (controller->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       "%s", _("unsupported PCI controller model: only PCI root supported"));
                        goto error;
                }
                break;
        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
                if (bhyveBuildAHCIControllerArgStr(def, controller, conn, cmd) < 0)
                    goto error;
                break;
        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
                if (++nusbcontrollers > 1) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       "%s", _("only single USB controller is supported"));
                        goto error;
                }

                if (bhyveBuildUSBControllerArgStr(def, controller, cmd) < 0)
                    goto error;
                break;
        }
    }
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (bhyveBuildNetArgStr(conn, def, net, cmd, dryRun) < 0)
            goto error;
    }
    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_SATA:
            /* Handled by bhyveBuildAHCIControllerArgStr() */
            break;
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
            if (bhyveBuildVirtIODiskArgStr(def, disk, conn, cmd) < 0)
                goto error;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            goto error;
        }
    }

    if (def->ngraphics && def->nvideos) {
        if (def->ngraphics == 1 && def->nvideos == 1) {
            if (bhyveBuildGraphicsArgStr(def, def->graphics[0], def->videos[0], conn, cmd) < 0)
                goto error;
            add_lpc = true;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Multiple graphics devices are not supported"));
             goto error;
        }
    }

    if (add_lpc || def->nserials)
        bhyveBuildLPCArgStr(def, cmd);

    if (bhyveBuildConsoleArgStr(def, cmd) < 0)
        goto error;

    virCommandAddArg(cmd, def->name);

    return cmd;

 error:
    virCommandFree(cmd);
    return NULL;
}

virCommandPtr
virBhyveProcessBuildDestroyCmd(bhyveConnPtr driver ATTRIBUTE_UNUSED,
                               virDomainDefPtr def)
{
    virCommandPtr cmd = virCommandNew(BHYVECTL);

    virCommandAddArg(cmd, "--destroy");
    virCommandAddArgPair(cmd, "--vm", def->name);

    return cmd;
}

static void
virAppendBootloaderArgs(virCommandPtr cmd, virDomainDefPtr def)
{
    char **blargs;

    /* XXX: Handle quoted? */
    blargs = virStringSplit(def->os.bootloaderArgs, " ", 0);
    virCommandAddArgSet(cmd, (const char * const *)blargs);
    virStringListFree(blargs);
}

static virCommandPtr
virBhyveProcessBuildBhyveloadCmd(virDomainDefPtr def, virDomainDiskDefPtr disk)
{
    virCommandPtr cmd;

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

static virCommandPtr
virBhyveProcessBuildCustomLoaderCmd(virDomainDefPtr def)
{
    virCommandPtr cmd;

    if (def->os.bootloaderArgs == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Custom loader requires explicit %s configuration"),
                       "bootloader_args");
        return NULL;
    }

    VIR_DEBUG("custom loader '%s' with arguments", def->os.bootloader);

    cmd = virCommandNew(def->os.bootloader);
    virAppendBootloaderArgs(cmd, def);
    return cmd;
}

static bool
virBhyveUsableDisk(virConnectPtr conn, virDomainDiskDefPtr disk)
{

    if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
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
virBhyveFormatGrubDevice(virBufferPtr devicemap, virDomainDiskDefPtr def)
{

    if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAsprintf(devicemap, "(cd) %s\n",
                          virDomainDiskGetSource(def));
    else
        virBufferAsprintf(devicemap, "(hd0) %s\n",
                          virDomainDiskGetSource(def));
}

static virCommandPtr
virBhyveProcessBuildGrubbhyveCmd(virDomainDefPtr def,
                                 virConnectPtr conn,
                                 const char *devmap_file,
                                 char **devicesmap_out)
{
    virDomainDiskDefPtr hdd, cd, userdef, diskdef;
    virBuffer devicemap;
    virCommandPtr cmd;
    unsigned int best_idx = UINT_MAX;
    size_t i;

    if (def->os.bootloaderArgs != NULL)
        return virBhyveProcessBuildCustomLoaderCmd(def);

    devicemap = (virBuffer)VIR_BUFFER_INITIALIZER;

    /* Search disk list for CD or HDD device. We'll respect <boot order=''> if
     * present and otherwise pick the first CD or failing that HDD we come
     * across. */
    cd = hdd = userdef = NULL;
    for (i = 0; i < def->ndisks; i++) {
        if (!virBhyveUsableDisk(conn, def->disks[i]))
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

    if ((bhyveDriverGetGrubCaps(conn) & BHYVE_GRUB_CAP_CONSDEV) != 0 &&
        def->nserials > 0) {
        virDomainChrDefPtr chr;

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

static virDomainDiskDefPtr
virBhyveGetBootDisk(virConnectPtr conn, virDomainDefPtr def)
{
    size_t i;
    virDomainDiskDefPtr match = NULL;
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
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cannot boot from device %s"),
                           virDomainBootTypeToString(def->os.bootDevs[0]));
            return NULL;
        }
    }

    if (boot_dev != -1) {
        /* If boot_dev is set, we return the first device of
         * the request type */
        for (i = 0; i < def->ndisks; i++) {
            if (!virBhyveUsableDisk(conn, def->disks[i]))
                continue;

            if (def->disks[i]->device == boot_dev) {
                match = def->disks[i];
                break;
            }
        }

        if (match == NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Cannot find boot device of requested type %s"),
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
            if (!virBhyveUsableDisk(conn, def->disks[i]))
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

        /* If user didn't explicily specify boot priority,
         * just return the first usable disk */
        if ((match == NULL) && (first_usable_disk_index >= 0))
            return def->disks[first_usable_disk_index];
    }

    return match;
}

virCommandPtr
virBhyveProcessBuildLoadCmd(virConnectPtr conn, virDomainDefPtr def,
                            const char *devmap_file, char **devicesmap_out)
{
    virDomainDiskDefPtr disk = NULL;

    if (def->os.bootloader == NULL) {
        disk = virBhyveGetBootDisk(conn, def);

        if (disk == NULL)
            return NULL;

        return virBhyveProcessBuildBhyveloadCmd(def, disk);
    } else if (strstr(def->os.bootloader, "grub-bhyve") != NULL) {
        return virBhyveProcessBuildGrubbhyveCmd(def, conn, devmap_file,
                                                devicesmap_out);
    } else {
        return virBhyveProcessBuildCustomLoaderCmd(def);
    }
}
