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

#include "bhyve_command.h"
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
bhyveBuildNetArgStr(const virDomainDef *def, virCommandPtr cmd)
{
    virDomainNetDefPtr net = NULL;
    char *brname = NULL;
    char *realifname = NULL;
    int *tapfd = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    if (def->nnets != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain should have one and only one net defined"));
        return -1;
    }

    net = def->nets[0];

    if (net) {
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

        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, tapfd, 1,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           VIR_NETDEV_TAP_CREATE_IFUP | VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
            VIR_FREE(net->ifname);
            VIR_FREE(brname);
            return -1;
        }
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
        VIR_FREE(net->ifname);
        VIR_FREE(brname);
        return -1;
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "1:0,virtio-net,%s,mac=%s",
                           realifname, virMacAddrFormat(&net->mac, macaddr));

    return 0;
}

static int
bhyveBuildDiskArgStr(const virDomainDef *def, virCommandPtr cmd)
{
    virDomainDiskDefPtr disk;
    const char *bus_type;

    if (def->ndisks != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain should have one and only one disk defined"));
        return -1;
    }

    disk = def->disks[0];

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        bus_type = "ahci-hd";
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        bus_type = "virtio-blk";
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk bus type"));
        return -1;
    }

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return -1;
    }

    if (virDomainDiskGetType(disk) != VIR_DOMAIN_DISK_TYPE_FILE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return -1;
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "2:0,%s,%s", bus_type,
                           virDomainDiskGetSource(disk));

    return 0;
}

virCommandPtr
virBhyveProcessBuildBhyveCmd(bhyveConnPtr driver ATTRIBUTE_UNUSED,
                             virDomainObjPtr vm)
{
    /*
     * /usr/sbin/bhyve -c 2 -m 256 -AI -H -P \
     *            -s 0:0,hostbridge \
     *            -s 1:0,virtio-net,tap0 \
     *            -s 2:0,ahci-hd,${IMG} \
     *            -S 31,uart,stdio \
     *            vm0
     */
    virCommandPtr cmd = virCommandNew(BHYVE);

    /* CPUs */
    virCommandAddArg(cmd, "-c");
    virCommandAddArgFormat(cmd, "%d", vm->def->vcpus);

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%llu",
                           VIR_DIV_UP(vm->def->mem.max_balloon, 1024));

    /* Options */
    if (vm->def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_DOMAIN_FEATURE_STATE_ON)
        virCommandAddArg(cmd, "-A"); /* Create an ACPI table */
    if (vm->def->features[VIR_DOMAIN_FEATURE_APIC] == VIR_DOMAIN_FEATURE_STATE_ON)
        virCommandAddArg(cmd, "-I"); /* Present ioapic to the guest */

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
    if (bhyveBuildNetArgStr(vm->def, cmd) < 0)
        goto error;
    if (bhyveBuildDiskArgStr(vm->def, cmd) < 0)
        goto error;
    virCommandAddArg(cmd, vm->def->name);

    return cmd;

 error:
    virCommandFree(cmd);
    return NULL;
}

virCommandPtr
virBhyveProcessBuildDestroyCmd(bhyveConnPtr driver ATTRIBUTE_UNUSED,
                               virDomainObjPtr vm)
{
    virCommandPtr cmd = virCommandNew(BHYVECTL);

    virCommandAddArg(cmd, "--destroy");
    virCommandAddArgPair(cmd, "--vm", vm->def->name);

    return cmd;
}

virCommandPtr
virBhyveProcessBuildLoadCmd(bhyveConnPtr driver ATTRIBUTE_UNUSED,
                            virDomainObjPtr vm)
{
    virCommandPtr cmd;
    virDomainDiskDefPtr disk;

    if (vm->def->ndisks != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain should have one and only one disk defined"));
        return NULL;
    }

    disk = vm->def->disks[0];

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return NULL;
    }

    if (virDomainDiskGetType(disk) != VIR_DOMAIN_DISK_TYPE_FILE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return NULL;
    }

    cmd = virCommandNew(BHYVELOAD);

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%llu",
                           VIR_DIV_UP(vm->def->mem.max_balloon, 1024));

    /* Image path */
    virCommandAddArg(cmd, "-d");
    virCommandAddArg(cmd, virDomainDiskGetSource(disk));

    /* VM name */
    virCommandAddArg(cmd, vm->def->name);

    return cmd;
}
