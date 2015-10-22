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
bhyveBuildNetArgStr(const virDomainDef *def,
                    virDomainNetDefPtr net,
                    virCommandPtr cmd,
                    bool dryRun)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char *realifname = NULL;
    char *brname = NULL;
    int actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        if (VIR_STRDUP(brname, virDomainNetGetActualBridgeName(net)) < 0)
            return -1;
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Network type %d is not supported"),
                       virDomainNetGetActualType(net));
        return -1;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, VIR_NET_GENERATED_PREFIX) ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (VIR_STRDUP(net->ifname, VIR_NET_GENERATED_PREFIX "%d") < 0) {
            VIR_FREE(brname);
            return -1;
        }
    }

    if (!dryRun) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, NULL, NULL, 0,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           VIR_NETDEV_TAP_CREATE_IFUP | VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
            VIR_FREE(net->ifname);
            VIR_FREE(brname);
            return -1;
        }

        realifname = virNetDevTapGetRealDeviceName(net->ifname);

        if (realifname == NULL) {
            VIR_FREE(net->ifname);
            VIR_FREE(brname);
            return -1;
        }

        VIR_DEBUG("%s -> %s", net->ifname, realifname);
        /* hack on top of other hack: we need to set
         * interface to 'UP' again after re-opening to find its
         * name
         */
        if (virNetDevSetOnline(net->ifname, true) != 0) {
            VIR_FREE(realifname);
            VIR_FREE(net->ifname);
            VIR_FREE(brname);
            return -1;
        }
    } else {
        if (VIR_STRDUP(realifname, "tap0") < 0)
            return -1;
    }


    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,virtio-net,%s,mac=%s",
                           net->info.addr.pci.slot,
                           realifname, virMacAddrFormat(&net->mac, macaddr));
    VIR_FREE(realifname);

    return 0;
}

static int
bhyveBuildConsoleArgStr(const virDomainDef *def, virCommandPtr cmd)
{

    virDomainChrDefPtr chr = NULL;

    if (!def->nserials)
        return 0;

    chr = def->serials[0];

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_NMDM) {
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

    virCommandAddArgList(cmd, "-s", "1,lpc", NULL);
    virCommandAddArg(cmd, "-l");
    virCommandAddArgFormat(cmd, "com%d,%s",
                           chr->target.port + 1, chr->source.data.file.path);

    return 0;
}

static int
bhyveBuildDiskArgStr(const virDomainDef *def ATTRIBUTE_UNUSED,
                     virDomainDiskDefPtr disk,
                     virCommandPtr cmd)
{
    const char *bus_type;
    const char *disk_source;

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            bus_type = "ahci-hd";
            break;
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            bus_type = "ahci-cd";
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            return -1;
        }
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            bus_type = "virtio-blk";
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            return -1;
        }
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk bus type"));
        return -1;
    }

    if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
        (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return -1;
    }

    disk_source = virDomainDiskGetSource(disk);

    if ((disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
        (disk_source == NULL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cdrom device without source path "
                             "not supported"));
            return -1;
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,%s,%s",
                           disk->info.addr.pci.slot, bus_type,
                           disk_source);

    return 0;
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
    /* Devices */
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        if (bhyveBuildNetArgStr(def, net, cmd, dryRun) < 0)
            goto error;
    }
    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
            goto error;

        if (bhyveBuildDiskArgStr(def, disk, cmd) < 0)
            goto error;
    }
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
    virStringFreeList(blargs);
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
    int best_idx;
    size_t i;

    if (def->os.bootloaderArgs != NULL)
        return virBhyveProcessBuildCustomLoaderCmd(def);

    best_idx = INT_MAX;
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

        if (chr->source.type != VIR_DOMAIN_CHR_TYPE_NMDM) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only nmdm console types are supported"));
            return NULL;
        }

        virCommandAddArg(cmd, "--cons-dev");
        virCommandAddArg(cmd, chr->source.data.file.path);
    }

    /* VM name */
    virCommandAddArg(cmd, def->name);

    return cmd;
}

virCommandPtr
virBhyveProcessBuildLoadCmd(virConnectPtr conn, virDomainDefPtr def,
                            const char *devmap_file, char **devicesmap_out)
{
    virDomainDiskDefPtr disk;

    if (def->ndisks < 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain should have at least one disk defined"));
        return NULL;
    }

    if (def->os.bootloader == NULL) {
        disk = def->disks[0];

        if (!virBhyveUsableDisk(conn, disk))
            return NULL;

        return virBhyveProcessBuildBhyveloadCmd(def, disk);
    } else if (strstr(def->os.bootloader, "grub-bhyve") != NULL) {
        return virBhyveProcessBuildGrubbhyveCmd(def, conn, devmap_file,
                                                devicesmap_out);
    } else {
        return virBhyveProcessBuildCustomLoaderCmd(def);
    }
}
