/*
 * qemu_capabilities.c: QEMU capabilities generation
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_capabilities.h"
#include "viralloc.h"
#include "vircrypto.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virfilecache.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "cpu/cpu.h"
#include "cpu/cpu_x86.h"
#include "domain_conf.h"
#include "vircommand.h"
#include "virbitmap.h"
#include "virnodesuspend.h"
#include "virnuma.h"
#include "virhostcpu.h"
#include "qemu_monitor.h"
#include "virstring.h"
#include "qemu_hostdev.h"
#include "qemu_domain.h"
#define __QEMU_CAPSPRIV_H_ALLOW__
#include "qemu_capspriv.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_capabilities");

/* While not public, these strings must not change. They
 * are used in domain status files which are read on
 * daemon restarts
 */
VIR_ENUM_IMPL(virQEMUCaps, QEMU_CAPS_LAST,
              /* 0 */
              "kqemu",
              "vnc-colon",
              "no-reboot",
              "drive",
              "drive-boot",

              /* 5 */
              "name",
              "uuid",
              "domid",
              "vnet-hdr",
              "migrate-kvm-stdio",

              /* 10 */
              "migrate-qemu-tcp",
              "migrate-qemu-exec",
              "drive-cache-v2",
              "kvm",
              "drive-format",

              /* 15 */
              "vga",
              "0.10",
              "pci-device",
              "mem-path",
              "drive-serial",

              /* 20 */
              "xen-domid",
              "migrate-qemu-unix",
              "chardev",
              "enable-kvm",
              "monitor-json",

              /* 25 */
              "balloon",
              "device",
              "sdl",
              "smp-topology",
              "netdev",

              /* 30 */
              "rtc",
              "vhost-net",
              "rtc-td-hack",
              "no-hpet",
              "no-kvm-pit",

              /* 35 */
              "tdf",
              "pci-configfd",
              "nodefconfig",
              "boot-menu",
              "enable-kqemu",

              /* 40 */
              "fsdev",
              "nesting",
              "name-process",
              "drive-readonly",
              "smbios-type",

              /* 45 */
              "vga-qxl",
              "spice",
              "vga-none",
              "migrate-qemu-fd",
              "boot-index",

              /* 50 */
              "hda-duplex",
              "drive-aio",
              "pci-multibus",
              "pci-bootindex",
              "ccid-emulated",

              /* 55 */
              "ccid-passthru",
              "chardev-spicevmc",
              "device-spicevmc",
              "virtio-tx-alg",
              "device-qxl-vga",

              /* 60 */
              "pci-multifunction",
              "virtio-blk-pci.ioeventfd",
              "sga",
              "virtio-blk-pci.event_idx",
              "virtio-net-pci.event_idx",

              /* 65 */
              "cache-directsync",
              "piix3-usb-uhci",
              "piix4-usb-uhci",
              "usb-ehci",
              "ich9-usb-ehci1",

              /* 70 */
              "vt82c686b-usb-uhci",
              "pci-ohci",
              "usb-redir",
              "usb-hub",
              "no-shutdown",

              /* 75 */
              "cache-unsafe",
              "rombar",
              "ich9-ahci",
              "no-acpi",
              "fsdev-readonly",

              /* 80 */
              "virtio-blk-pci.scsi",
              "blk-sg-io",
              "drive-copy-on-read",
              "cpu-host",
              "fsdev-writeout",

              /* 85 */
              "drive-iotune",
              "system_wakeup",
              "scsi-disk.channel",
              "scsi-block",
              "transaction",

              /* 90 */
              "block-job-sync",
              "block-job-async",
              "scsi-cd",
              "ide-cd",
              "no-user-config",

              /* 95 */
              "hda-micro",
              "dump-guest-memory",
              "nec-usb-xhci",
              "virtio-s390",
              "balloon-event",

              /* 100 */
              "bridge",
              "lsi",
              "virtio-scsi-pci",
              "blockio",
              "disable-s3",

              /* 105 */
              "disable-s4",
              "usb-redir.filter",
              "ide-drive.wwn",
              "scsi-disk.wwn",
              "seccomp-sandbox",

              /* 110 */
              "reboot-timeout",
              "dump-guest-core",
              "seamless-migration",
              "block-commit",
              "vnc",

              /* 115 */
              "drive-mirror",
              "usb-redir.bootindex",
              "usb-host.bootindex",
              "blockdev-snapshot-sync",
              "qxl",

              /* 120 */
              "VGA",
              "cirrus-vga",
              "vmware-svga",
              "device-video-primary",
              "s390-sclp",

              /* 125 */
              "usb-serial",
              "usb-net",
              "add-fd",
              "nbd-server",
              "virtio-rng",

              /* 130 */
              "rng-random",
              "rng-egd",
              "virtio-ccw",
              "dtb",
              "megasas",

              /* 135 */
              "ipv6-migration",
              "machine-opt",
              "machine-usb-opt",
              "tpm-passthrough",
              "tpm-tis",

              /* 140 */
              "nvram",
              "pci-bridge",
              "vfio-pci",
              "vfio-pci.bootindex",
              "scsi-generic",

              /* 145 */
              "scsi-generic.bootindex",
              "mem-merge",
              "vnc-websocket",
              "drive-discard",
              "mlock",

              /* 150 */
              "vnc-share-policy",
              "device-del-event",
              "dmi-to-pci-bridge",
              "i440fx-pci-hole64-size",
              "q35-pci-hole64-size",

              /* 155 */
              "usb-storage",
              "usb-storage.removable",
              "virtio-mmio",
              "ich9-intel-hda",
              "kvm-pit-lost-tick-policy",

              /* 160 */
              "boot-strict",
              "pvpanic",
              "enable-fips",
              "spice-file-xfer-disable",
              "spiceport",

              /* 165 */
              "usb-kbd",
              "host-pci-multidomain",
              "msg-timestamp",
              "active-commit",
              "change-backing-file",

              /* 170 */
              "memory-backend-ram",
              "numa",
              "memory-backend-file",
              "usb-audio",
              "rtc-reset-reinjection",

              /* 175 */
              "splash-timeout",
              "iothread",
              "migrate-rdma",
              "ivshmem",
              "drive-iotune-max",

              /* 180 */
              "VGA.vgamem_mb",
              "vmware-svga.vgamem_mb",
              "qxl.vgamem_mb",
              "qxl-vga.vgamem_mb",
              "pc-dimm",

              /* 185 */
              "machine-vmport-opt",
              "aes-key-wrap",
              "dea-key-wrap",
              "pci-serial",
              "aarch64-off",

              /* 190 */
              "vhost-user-multiqueue",
              "migration-event",
              "gpex-pcihost",
              "ioh3420",
              "x3130-upstream",

              /* 195 */
              "xio3130-downstream",
              "rtl8139",
              "e1000",
              "virtio-net",
              "gic-version",

              /* 200 */
              "incoming-defer",
              "virtio-gpu",
              "virtio-gpu.virgl",
              "virtio-keyboard",
              "virtio-mouse",

              /* 205 */
              "virtio-tablet",
              "virtio-input-host",
              "chardev-file-append",
              "ich9-disable-s3",
              "ich9-disable-s4",

              /* 210 */
              "vserport-change-event",
              "virtio-balloon-pci.deflate-on-oom",
              "mptsas1068",
              "spice-gl",
              "qxl.vram64_size_mb",

              /* 215 */
              "qxl-vga.vram64_size_mb",
              "chardev-logfile",
              "debug-threads",
              "secret",
              "pxb",

              /* 220 */
              "pxb-pcie",
              "device-tray-moved-event",
              "nec-usb-xhci-ports",
              "virtio-scsi-pci.iothread",
              "name-guest",

              /* 225 */
              "qxl.max_outputs",
              "qxl-vga.max_outputs",
              "spice-unix",
              "drive-detect-zeroes",
              "tls-creds-x509",

              /* 230 */
              "display",
              "intel-iommu",
              "smm",
              "virtio-pci-disable-legacy",
              "query-hotpluggable-cpus",

              /* 235 */
              "virtio-net.rx_queue_size",
              "machine-iommu",
              "virtio-vga",
              "drive-iotune-max-length",
              "ivshmem-plain",

              /* 240 */
              "ivshmem-doorbell",
              "query-qmp-schema",
              "gluster.debug_level",
              "vhost-scsi",
              "drive-iotune-group",

              /* 245 */
              "query-cpu-model-expansion",
              "virtio-net.host_mtu",
              "spice-rendernode",
              "nvdimm",
              "pcie-root-port",

              /* 250 */
              "query-cpu-definitions",
              "block-write-threshold",
              "query-named-block-nodes",
              "cpu-cache",
              "qemu-xhci",

              /* 255 */
              "kernel-irqchip",
              "kernel-irqchip.split",
              "intel-iommu.intremap",
              "intel-iommu.caching-mode",
              "intel-iommu.eim",

              /* 260 */
              "intel-iommu.device-iotlb",
              "virtio.iommu_platform",
              "virtio.ats",
              "loadparm",
              "spapr-pci-host-bridge",

              /* 265 */
              "spapr-pci-host-bridge.numa_node",
              "vnc-multi-servers",
              "virtio-net.tx_queue_size",
    );


struct virQEMUCapsMachineType {
    char *name;
    char *alias;
    unsigned int maxCpus;
    bool hotplugCpus;
};

typedef struct _virQEMUCapsHostCPUData virQEMUCapsHostCPUData;
typedef virQEMUCapsHostCPUData *virQEMUCapsHostCPUDataPtr;
struct _virQEMUCapsHostCPUData {
    /* Only the "info" part is stored in the capabilities cache, the rest is
     * re-computed from other fields and external data sources everytime we
     * probe QEMU or load the cache.
     */
    qemuMonitorCPUModelInfoPtr info;
    /* Host CPU definition reported in domain capabilities. */
    virCPUDefPtr reported;
    /* Migratable host CPU definition used for updating guest CPU. */
    virCPUDefPtr migratable;
    /* CPU definition with features detected by libvirt using virCPUGetHost
     * combined with features reported by QEMU. This is used for backward
     * compatible comparison between a guest CPU and a host CPU. */
    virCPUDefPtr full;
};

/*
 * Update the XML parser/formatter when adding more
 * information to this struct so that it gets cached
 * correctly. It does not have to be ABI-stable, as
 * the cache will be discarded & repopulated if the
 * timestamp on the libvirtd binary changes.
 *
 * And don't forget to update virQEMUCapsNewCopy.
 */
struct _virQEMUCaps {
    virObject object;

    bool usedQMP;

    char *binary;
    time_t ctime;
    time_t libvirtCtime;

    virBitmapPtr flags;

    unsigned int version;
    unsigned int kvmVersion;
    unsigned int libvirtVersion;
    char *package;

    virArch arch;

    virDomainCapsCPUModelsPtr kvmCPUModels;
    virDomainCapsCPUModelsPtr tcgCPUModels;

    size_t nmachineTypes;
    struct virQEMUCapsMachineType *machineTypes;

    size_t ngicCapabilities;
    virGICCapability *gicCapabilities;

    virQEMUCapsHostCPUData kvmCPU;
    virQEMUCapsHostCPUData tcgCPU;
};

struct virQEMUCapsSearchData {
    virArch arch;
};


static virClassPtr virQEMUCapsClass;
static void virQEMUCapsDispose(void *obj);

static int virQEMUCapsOnceInit(void)
{
    if (!(virQEMUCapsClass = virClassNew(virClassForObject(),
                                         "virQEMUCaps",
                                         sizeof(virQEMUCaps),
                                         virQEMUCapsDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUCaps)

static virArch virQEMUCapsArchFromString(const char *arch)
{
    if (STREQ(arch, "i386"))
        return VIR_ARCH_I686;
    if (STREQ(arch, "arm"))
        return VIR_ARCH_ARMV7L;
    if (STREQ(arch, "or32"))
        return VIR_ARCH_OR32;

    return virArchFromString(arch);
}


static const char *virQEMUCapsArchToString(virArch arch)
{
    if (arch == VIR_ARCH_I686)
        return "i386";
    else if (arch == VIR_ARCH_ARMV7L)
        return "arm";
    else if (arch == VIR_ARCH_OR32)
        return "or32";

    return virArchToString(arch);
}


/* Checks whether a domain with @guest arch can run natively on @host.
 */
bool
virQEMUCapsGuestIsNative(virArch host,
                         virArch guest)
{
    if (host == guest)
        return true;

    if (host == VIR_ARCH_X86_64 && guest == VIR_ARCH_I686)
        return true;

    if (host == VIR_ARCH_AARCH64 && guest == VIR_ARCH_ARMV7L)
        return true;

    if (ARCH_IS_PPC64(host) && ARCH_IS_PPC64(guest))
        return true;

    return false;
}


/* Given a host and guest architectures, find a suitable QEMU target.
 *
 * This is meant to be used as a second attempt if qemu-system-$guestarch
 * can't be found, eg. on a x86_64 host you want to use qemu-system-i386,
 * if available, instead of qemu-system-x86_64 to run i686 guests */
static virArch
virQEMUCapsFindTarget(virArch hostarch,
                      virArch guestarch)
{
    if (virQEMUCapsGuestIsNative(hostarch, guestarch))
        guestarch = hostarch;

    /* Both ppc64 and ppc64le guests can use the ppc64 target */
    if (ARCH_IS_PPC64(guestarch))
        guestarch = VIR_ARCH_PPC64;

    return guestarch;
}

static virCommandPtr
virQEMUCapsProbeCommand(const char *qemu,
                        virQEMUCapsPtr qemuCaps,
                        uid_t runUid, gid_t runGid)
{
    virCommandPtr cmd = virCommandNew(qemu);

    if (qemuCaps) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_USER_CONFIG))
            virCommandAddArg(cmd, "-no-user-config");
        else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NODEFCONFIG))
            virCommandAddArg(cmd, "-nodefconfig");
    }

    virCommandAddEnvPassCommon(cmd);
    virCommandClearCaps(cmd);
    virCommandSetGID(cmd, runGid);
    virCommandSetUID(cmd, runUid);

    return cmd;
}


static void
virQEMUCapsSetDefaultMachine(virQEMUCapsPtr qemuCaps,
                             size_t defIdx)
{
    struct virQEMUCapsMachineType tmp = qemuCaps->machineTypes[defIdx];

    memmove(qemuCaps->machineTypes + 1,
            qemuCaps->machineTypes,
            sizeof(qemuCaps->machineTypes[0]) * defIdx);

    qemuCaps->machineTypes[0] = tmp;
}

/* Format is:
 * <machine> <desc> [(default)|(alias of <canonical>)]
 */
static int
virQEMUCapsParseMachineTypesStr(const char *output,
                                virQEMUCapsPtr qemuCaps)
{
    const char *p = output;
    const char *next;
    size_t defIdx = 0;

    do {
        const char *t;
        char *name;
        char *canonical = NULL;

        if ((next = strchr(p, '\n')))
            ++next;

        if (STRPREFIX(p, "Supported machines are:"))
            continue;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (VIR_STRNDUP(name, p, t - p) < 0)
            return -1;

        p = t;
        if ((t = strstr(p, "(default)")) && (!next || t < next))
            defIdx = qemuCaps->nmachineTypes;

        if ((t = strstr(p, "(alias of ")) && (!next || t < next)) {
            p = t + strlen("(alias of ");
            if (!(t = strchr(p, ')')) || (next && t >= next)) {
                VIR_FREE(name);
                continue;
            }

            if (VIR_STRNDUP(canonical, p, t - p) < 0) {
                VIR_FREE(name);
                return -1;
            }
        }

        if (VIR_REALLOC_N(qemuCaps->machineTypes, qemuCaps->nmachineTypes + 1) < 0) {
            VIR_FREE(name);
            VIR_FREE(canonical);
            return -1;
        }
        qemuCaps->nmachineTypes++;
        if (canonical) {
            qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].name = canonical;
            qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].alias = name;
        } else {
            qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].name = name;
            qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].alias = NULL;
        }
        /* When parsing from command line we don't have information about maxCpus */
        qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].maxCpus = 0;
        qemuCaps->machineTypes[qemuCaps->nmachineTypes-1].hotplugCpus = false;
    } while ((p = next));


    if (defIdx)
        virQEMUCapsSetDefaultMachine(qemuCaps, defIdx);

    return 0;
}

static int
virQEMUCapsProbeMachineTypes(virQEMUCapsPtr qemuCaps,
                             uid_t runUid, gid_t runGid)
{
    char *output;
    int ret = -1;
    virCommandPtr cmd;
    int status;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(qemuCaps->binary)) {
        virReportSystemError(errno, _("Cannot find QEMU binary %s"),
                             qemuCaps->binary);
        return -1;
    }

    cmd = virQEMUCapsProbeCommand(qemuCaps->binary, qemuCaps, runUid, runGid);
    virCommandAddArgList(cmd, "-M", "?", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    /* Ignore failure from older qemu that did not understand '-M ?'.  */
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (virQEMUCapsParseMachineTypesStr(output, qemuCaps) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}


typedef int
(*virQEMUCapsParseCPUModels)(const char *output,
                             virQEMUCapsPtr qemuCaps);

/* Format:
 *      <arch> <model>
 * qemu-0.13 encloses some model names in []:
 *      <arch> [<model>]
 */
static int
virQEMUCapsParseX86Models(const char *output,
                          virQEMUCapsPtr qemuCaps)
{
    const char *p = output;
    const char *next;
    virDomainCapsCPUModelsPtr cpus;

    if (!(cpus = virDomainCapsCPUModelsNew(0)))
        return -1;

    do {
        const char *t;
        size_t len;

        if ((next = strchr(p, '\n')))
            next++;

        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (!STRPREFIX(p, "x86"))
            continue;

        p = t;
        while (*p == ' ')
            p++;

        if (*p == '\0' || *p == '\n')
            continue;

        if (next)
            len = next - p - 1;
        else
            len = strlen(p);

        if (len > 2 && *p == '[' && p[len - 1] == ']') {
            p++;
            len -= 2;
        }

        if (virDomainCapsCPUModelsAdd(cpus, p, len,
                                      VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            goto error;
    } while ((p = next));

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        virDomainCapsCPUModelsPtr kvmCPUs;

        if (!(kvmCPUs = virDomainCapsCPUModelsCopy(cpus)))
            goto error;

        qemuCaps->kvmCPUModels = kvmCPUs;
    }
    qemuCaps->tcgCPUModels = cpus;

    return 0;

 error:
    virObjectUnref(cpus);
    return -1;
}

/* ppc64 parser.
 * Format : PowerPC <machine> <description>
 */
static int
virQEMUCapsParsePPCModels(const char *output,
                          virQEMUCapsPtr qemuCaps)
{
    const char *p = output;
    const char *next;
    virDomainCapsCPUModelsPtr cpus;

    if (!(cpus = virDomainCapsCPUModelsNew(0)))
        return -1;

    do {
        const char *t;

        if ((next = strchr(p, '\n')))
            next++;

        if (!STRPREFIX(p, "PowerPC "))
            continue;

        /* Skip the preceding sub-string "PowerPC " */
        p += 8;

        /*Malformed string, does not obey the format 'PowerPC <model> <desc>'*/
        if (!(t = strchr(p, ' ')) || (next && t >= next))
            continue;

        if (*p == '\0')
            break;

        if (*p == '\n')
            continue;

        if (virDomainCapsCPUModelsAdd(cpus, p, t - p - 1,
                                      VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0)
            goto error;
    } while ((p = next));

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        virDomainCapsCPUModelsPtr kvmCPUs;

        if (!(kvmCPUs = virDomainCapsCPUModelsCopy(cpus)))
            goto error;

        qemuCaps->kvmCPUModels = kvmCPUs;
    }
    qemuCaps->tcgCPUModels = cpus;

    return 0;

 error:
    virObjectUnref(cpus);
    return -1;
}

static int
virQEMUCapsProbeCPUModels(virQEMUCapsPtr qemuCaps, uid_t runUid, gid_t runGid)
{
    char *output = NULL;
    int ret = -1;
    virQEMUCapsParseCPUModels parse;
    virCommandPtr cmd;

    if (ARCH_IS_X86(qemuCaps->arch)) {
        parse = virQEMUCapsParseX86Models;
    } else if (ARCH_IS_PPC64(qemuCaps->arch)) {
        parse = virQEMUCapsParsePPCModels;
    } else {
        VIR_DEBUG("don't know how to parse %s CPU models",
                  virArchToString(qemuCaps->arch));
        return 0;
    }

    cmd = virQEMUCapsProbeCommand(qemuCaps->binary, qemuCaps, runUid, runGid);
    virCommandAddArgList(cmd, "-cpu", "?", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (parse(output, qemuCaps) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);

    return ret;
}

static char *
virQEMUCapsFindBinary(const char *format,
                      const char *archstr)
{
    char *ret = NULL;
    char *binary = NULL;

    if (virAsprintf(&binary, format, archstr) < 0)
        goto out;

    ret = virFindFileInPath(binary);
    VIR_FREE(binary);
    if (ret && virFileIsExecutable(ret))
        goto out;

    VIR_FREE(ret);

 out:
    return ret;
}

static char *
virQEMUCapsFindBinaryForArch(virArch hostarch,
                             virArch guestarch)
{
    char *ret = NULL;
    const char *archstr;
    virArch target;

    /* First attempt: try the guest architecture as it is */
    archstr = virQEMUCapsArchToString(guestarch);
    if ((ret = virQEMUCapsFindBinary("qemu-system-%s", archstr)) != NULL)
        goto out;

    /* Second attempt: try looking up by target instead */
    target = virQEMUCapsFindTarget(hostarch, guestarch);
    if (target != guestarch) {
        archstr = virQEMUCapsArchToString(target);
        if ((ret = virQEMUCapsFindBinary("qemu-system-%s", archstr)) != NULL)
            goto out;
    }

    /* Third attempt, i686 only: try 'qemu' */
    if (guestarch == VIR_ARCH_I686) {
        if ((ret = virQEMUCapsFindBinary("%s", "qemu")) != NULL)
            goto out;
    }

 out:
    return ret;
}

static int
virQEMUCapsInitGuest(virCapsPtr caps,
                     virFileCachePtr cache,
                     virArch hostarch,
                     virArch guestarch)
{
    size_t i;
    char *kvmbin = NULL;
    char *binary = NULL;
    virQEMUCapsPtr qemubinCaps = NULL;
    virQEMUCapsPtr kvmbinCaps = NULL;
    int ret = -1;

    /* Check for existence of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = virQEMUCapsFindBinaryForArch(hostarch, guestarch);

    /* Ignore binary if extracting version info fails */
    if (binary) {
        if (!(qemubinCaps = virQEMUCapsCacheLookup(cache, binary))) {
            virResetLastError();
            VIR_FREE(binary);
        }
    }

    /* qemu-kvm/kvm binaries can only be used if
     *  - host & guest arches match
     *  - hostarch is x86_64 and guest arch is i686 (needs -cpu qemu32)
     *  - hostarch is aarch64 and guest arch is armv7l (needs -cpu aarch64=off)
     *  - hostarch and guestarch are both ppc64*
     */
    if (virQEMUCapsGuestIsNative(hostarch, guestarch)) {
        const char *kvmbins[] = {
            "/usr/libexec/qemu-kvm", /* RHEL */
            "qemu-kvm", /* Fedora */
            "kvm", /* Debian/Ubuntu */
            NULL,
        };

        /* x86 32-on-64 can be used with qemu-system-i386 and
         * qemu-system-x86_64, so if we don't find a specific kvm binary,
         * we can just fall back to the host arch native binary and
         * everything works fine.
         *
         * arm is different in that 32-on-64 _only_ works with
         * qemu-system-aarch64. So we have to add it to the kvmbins list
         */
        if (hostarch == VIR_ARCH_AARCH64 && guestarch == VIR_ARCH_ARMV7L)
            kvmbins[3] = "qemu-system-aarch64";

        for (i = 0; i < ARRAY_CARDINALITY(kvmbins); ++i) {
            if (!kvmbins[i])
                continue;

            kvmbin = virFindFileInPath(kvmbins[i]);

            if (!kvmbin)
                continue;

            if (!(kvmbinCaps = virQEMUCapsCacheLookup(cache, kvmbin))) {
                virResetLastError();
                VIR_FREE(kvmbin);
                continue;
            }

            if (!binary) {
                binary = kvmbin;
                qemubinCaps = kvmbinCaps;
                kvmbin = NULL;
                kvmbinCaps = NULL;
            }
            break;
        }
    }

    ret = virQEMUCapsInitGuestFromBinary(caps,
                                         binary, qemubinCaps,
                                         kvmbin, kvmbinCaps,
                                         guestarch);

    VIR_FREE(binary);
    VIR_FREE(kvmbin);
    virObjectUnref(qemubinCaps);
    virObjectUnref(kvmbinCaps);

    return ret;
}

int
virQEMUCapsInitGuestFromBinary(virCapsPtr caps,
                               const char *binary,
                               virQEMUCapsPtr qemubinCaps,
                               const char *kvmbin,
                               virQEMUCapsPtr kvmbinCaps,
                               virArch guestarch)
{
    virCapsGuestPtr guest;
    bool haskvm = false;
    virCapsGuestMachinePtr *machines = NULL;
    size_t nmachines = 0;
    int ret = -1;
    bool hasdisksnapshot = false;

    if (!binary)
        return 0;

    if (virFileExists("/dev/kvm") &&
        (virQEMUCapsGet(qemubinCaps, QEMU_CAPS_KVM) ||
         virQEMUCapsGet(qemubinCaps, QEMU_CAPS_ENABLE_KVM) ||
         kvmbin))
        haskvm = true;

    if (virQEMUCapsGetMachineTypesCaps(qemubinCaps, &nmachines, &machines) < 0)
        goto cleanup;

    /* We register kvm as the base emulator too, since we can
     * just give -no-kvm to disable acceleration if required */
    if ((guest = virCapabilitiesAddGuest(caps,
                                         VIR_DOMAIN_OSTYPE_HVM,
                                         guestarch,
                                         binary,
                                         NULL,
                                         nmachines,
                                         machines)) == NULL)
        goto cleanup;

    machines = NULL;
    nmachines = 0;

    /* CPU selection is always available, because all QEMU versions
     * we support can use at least '-cpu host' */
    if (!virCapabilitiesAddGuestFeature(guest, "cpuselection", true, false))
        goto cleanup;

    if (virQEMUCapsGet(qemubinCaps, QEMU_CAPS_BOOTINDEX) &&
        !virCapabilitiesAddGuestFeature(guest, "deviceboot", true, false))
        goto cleanup;

    if (virQEMUCapsGet(qemubinCaps, QEMU_CAPS_DISK_SNAPSHOT))
        hasdisksnapshot = true;

    if (!virCapabilitiesAddGuestFeature(guest, "disksnapshot", hasdisksnapshot,
                                        false))
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (haskvm) {
        virCapsGuestDomainPtr dom;

        if (kvmbin &&
            virQEMUCapsGetMachineTypesCaps(kvmbinCaps, &nmachines, &machines) < 0)
            goto cleanup;

        if ((dom = virCapabilitiesAddGuestDomain(guest,
                                                 VIR_DOMAIN_VIRT_KVM,
                                                 kvmbin ? kvmbin : binary,
                                                 NULL,
                                                 nmachines,
                                                 machines)) == NULL) {
            goto cleanup;
        }

        machines = NULL;
        nmachines = 0;
    }

    if ((ARCH_IS_X86(guestarch) || guestarch == VIR_ARCH_AARCH64) &&
        virCapabilitiesAddGuestFeature(guest, "acpi", true, true) == NULL) {
        goto cleanup;
    }

    if (ARCH_IS_X86(guestarch) &&
        virCapabilitiesAddGuestFeature(guest, "apic", true, false) == NULL) {
        goto cleanup;
    }

    if ((guestarch == VIR_ARCH_I686) &&
        (virCapabilitiesAddGuestFeature(guest, "pae", true, false) == NULL ||
         virCapabilitiesAddGuestFeature(guest, "nonpae", true, false) == NULL))
        goto cleanup;

    ret = 0;

 cleanup:

    virCapabilitiesFreeMachines(machines, nmachines);

    return ret;
}


virCPUDefPtr
virQEMUCapsProbeHostCPUForEmulator(virArch hostArch,
                                   virQEMUCapsPtr qemuCaps,
                                   virDomainVirtType type)
{
    size_t nmodels;
    char **models;
    virCPUDefPtr cpu;

    if (virQEMUCapsGetCPUDefinitions(qemuCaps, type, &models, &nmodels) < 0)
        return NULL;

    cpu = virCPUGetHost(hostArch, VIR_CPU_TYPE_GUEST, NULL,
                        (const char **) models, nmodels);

    virStringListFreeCount(models, nmodels);
    return cpu;
}


virCapsPtr
virQEMUCapsInit(virFileCachePtr cache)
{
    virCapsPtr caps;
    size_t i;
    virArch hostarch = virArchFromHost();

    if ((caps = virCapabilitiesNew(hostarch,
                                   true, true)) == NULL)
        goto error;

    /* Some machines have problematic NUMA toplogy causing
     * unexpected failures. We don't want to break the QEMU
     * driver in this scenario, so log errors & carry on
     */
    if (virCapabilitiesInitNUMA(caps) < 0) {
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_WARN("Failed to query host NUMA topology, disabling NUMA capabilities");
    }

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

    if (!(caps->host.cpu = virCPUProbeHost(caps->host.arch)))
        VIR_WARN("Failed to get host CPU");

    /* Add the power management features of the host */
    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    /* Add huge pages info */
    if (virCapabilitiesInitPages(caps) < 0)
        VIR_WARN("Failed to get pages info");

    /* Add domain migration transport URIs */
    virCapabilitiesAddHostMigrateTransport(caps, "tcp");
    virCapabilitiesAddHostMigrateTransport(caps, "rdma");

    /* QEMU can support pretty much every arch that exists,
     * so just probe for them all - we gracefully fail
     * if a qemu-system-$ARCH binary can't be found
     */
    for (i = 0; i < VIR_ARCH_LAST; i++)
        if (virQEMUCapsInitGuest(caps, cache,
                                 hostarch,
                                 i) < 0)
            goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}


static int
virQEMUCapsComputeCmdFlags(const char *help,
                           unsigned int version,
                           virQEMUCapsPtr qemuCaps,
                           bool check_yajl ATTRIBUTE_UNUSED)
{
    const char *p;
    const char *fsdev, *netdev;
    const char *cache;

    if (strstr(help, "-no-kvm"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_KVM);
    if (strstr(help, "-enable-kvm"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_ENABLE_KVM);
    if (strstr(help, ",process="))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NAME_PROCESS);

    cache = strstr(help, "cache=");
    if (cache && (p = strchr(cache, ']'))) {
        if (memmem(cache, p - cache, "directsync", sizeof("directsync") - 1))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
        if (memmem(cache, p - cache, "unsafe", sizeof("unsafe") - 1))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_UNSAFE);
    }
    if (strstr(help, "aio=threads|native"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_AIO);
    if (strstr(help, "copy-on-read=on|off"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_COPY_ON_READ);
    if (strstr(help, "bps="))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_IOTUNE);

    if (strstr(help, "-display"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DISPLAY);
    if ((p = strstr(help, "-vga")) && !strstr(help, "-std-vga")) {
        const char *nl = strstr(p, "\n");
        if ((p = strstr(p, "|none")) && p < nl)
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_VGA_NONE);
    }
    if (strstr(help, "-spice"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SPICE);
    if (strstr(help, "-vnc"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VNC);
    if (strstr(help, "seamless-migration="))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SEAMLESS_MIGRATION);
    if (strstr(help, "boot=on"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_BOOT);
    if (strstr(help, "serial=s"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_SERIAL);
    if (strstr(help, "host=[seg:]bus"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_HOST_PCI_MULTIDOMAIN);
    if (strstr(help, "-mem-path"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MEM_PATH);
    if (strstr(help, "-chardev spicevmc"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEVMC);
    if (strstr(help, "-chardev spiceport"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEPORT);
    if (strstr(help, "-nodefconfig"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NODEFCONFIG);
    if (strstr(help, "-no-user-config"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_USER_CONFIG);
    /* The trailing ' ' is important to avoid a bogus match */
    if (strstr(help, "-rtc "))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_RTC);
    /* to wit */
    if (strstr(help, "-rtc-td-hack"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_RTC_TD_HACK);
    if (strstr(help, "-no-hpet"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_HPET);
    if (strstr(help, "-no-acpi"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_ACPI);
    if (strstr(help, "-no-kvm-pit-reinjection"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_KVM_PIT);
    if (strstr(help, "-tdf"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_TDF);
    if (strstr(help, "-enable-nesting"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NESTING);
    if (strstr(help, ",menu=on"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_BOOT_MENU);
    if (strstr(help, ",reboot-timeout=rb_time"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_REBOOT_TIMEOUT);
    if (strstr(help, ",splash-time=sp_time"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SPLASH_TIMEOUT);
    if ((fsdev = strstr(help, "-fsdev"))) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV);
        if (strstr(fsdev, "readonly"))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV_READONLY);
        if (strstr(fsdev, "writeout"))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV_WRITEOUT);
    }
    if (strstr(help, "-smbios type"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SMBIOS_TYPE);
    if (strstr(help, "-sandbox"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SECCOMP_SANDBOX);

    if ((netdev = strstr(help, "-netdev"))) {
        /* Disable -netdev on 0.12 since although it exists,
         * the corresponding netdev_add/remove monitor commands
         * do not, and we need them to be able to do hotplug.
         * But see below about RHEL build. */
        if (version >= 13000) {
            if (strstr(netdev, "bridge"))
                virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV_BRIDGE);
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV);
        }
    }

    if (strstr(help, "-sdl"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SDL);

    if (strstr(help, ",vhost="))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VHOST_NET);

    /* Do not use -no-shutdown if qemu doesn't support it or SIGTERM handling
     * is most likely buggy when used with -no-shutdown (which applies for qemu
     * 0.14.* and 0.15.0)
     */
    if (strstr(help, "-no-shutdown") && (version < 14000 || version > 15000))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_SHUTDOWN);

    if (strstr(help, "dump-guest-core=on|off"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DUMP_GUEST_CORE);

    if (strstr(help, "-dtb"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DTB);

    if (strstr(help, "-machine"))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_OPT);

    /* While JSON mode was available in 0.12.0, it was too
     * incomplete to contemplate using. The 0.13.0 release
     * is good enough to use, even though it lacks one or
     * two features. This is also true of versions of qemu
     * built for RHEL, labeled 0.12.1, but with extra text
     * in the help output that mentions that features were
     * backported for libvirt. The benefits of JSON mode now
     * outweigh the downside.
     */
#if WITH_YAJL
    if (version >= 13000) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MONITOR_JSON);
    } else if (version >= 12000 &&
               strstr(help, "libvirt")) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MONITOR_JSON);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV);
    }
#else
    /* Starting with qemu 0.15 and newer, upstream qemu no longer
     * promises to keep the human interface stable, but requests that
     * we use QMP (the JSON interface) for everything.  If the user
     * forgot to include YAJL libraries when building their own
     * libvirt but is targeting a newer qemu, we are better off
     * telling them to recompile (the spec file includes the
     * dependency, so distros won't hit this).  This check is
     * also in m4/virt-yajl.m4 (see $with_yajl).  */
    if (version >= 15000 ||
        (version >= 12000 && strstr(help, "libvirt"))) {
        if (check_yajl) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu binary requires libvirt to be "
                             "compiled with yajl"));
            return -1;
        }
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV);
    }
#endif

    if (version >= 13000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_PCI_MULTIFUNCTION);

    if (version >= 1001000) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_IPV6_MIGRATION);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VNC_SHARE_POLICY);
    }

    return 0;
}

/* We parse the output of 'qemu -help' to get the QEMU
 * version number. The first bit is easy, just parse
 * 'QEMU PC emulator version x.y.z'
 * or
 * 'QEMU emulator version x.y.z'.
 *
 * With qemu-kvm, however, that is followed by a string
 * in parenthesis as follows:
 *  - qemu-kvm-x.y.z in stable releases
 *  - kvm-XX for kvm versions up to kvm-85
 *  - qemu-kvm-devel-XX for kvm version kvm-86 and later
 *
 * For qemu-kvm versions before 0.10.z, we need to detect
 * the KVM version number for some features. With 0.10.z
 * and later, we just need the QEMU version number and
 * whether it is KVM QEMU or mainline QEMU.
 */
#define QEMU_VERSION_STR_1  "QEMU emulator version"
#define QEMU_VERSION_STR_2  "QEMU PC emulator version"
#define QEMU_KVM_VER_PREFIX "(qemu-kvm-"
#define KVM_VER_PREFIX      "(kvm-"

#define SKIP_BLANKS(p) do { while ((*(p) == ' ') || (*(p) == '\t')) (p)++; } while (0)

int virQEMUCapsParseHelpStr(const char *qemu,
                            const char *help,
                            virQEMUCapsPtr qemuCaps,
                            unsigned int *version,
                            bool *is_kvm,
                            unsigned int *kvm_version,
                            bool check_yajl,
                            const char *qmperr)
{
    unsigned major, minor, micro;
    const char *p = help;
    char *strflags;

    *version = *kvm_version = 0;
    *is_kvm = false;

    if (STRPREFIX(p, QEMU_VERSION_STR_1))
        p += strlen(QEMU_VERSION_STR_1);
    else if (STRPREFIX(p, QEMU_VERSION_STR_2))
        p += strlen(QEMU_VERSION_STR_2);
    else
        goto fail;

    SKIP_BLANKS(p);

    major = virParseNumber(&p);
    if (major == -1 || *p != '.')
        goto fail;

    ++p;

    minor = virParseNumber(&p);
    if (minor == -1)
        goto fail;

    if (*p != '.') {
        micro = 0;
    } else {
        ++p;
        micro = virParseNumber(&p);
        if (micro == -1)
            goto fail;
    }

    SKIP_BLANKS(p);

    if (STRPREFIX(p, QEMU_KVM_VER_PREFIX)) {
        *is_kvm = true;
        p += strlen(QEMU_KVM_VER_PREFIX);
    } else if (STRPREFIX(p, KVM_VER_PREFIX)) {
        int ret;

        *is_kvm = true;
        p += strlen(KVM_VER_PREFIX);

        ret = virParseNumber(&p);
        if (ret == -1)
            goto fail;

        *kvm_version = ret;
    }

    *version = (major * 1000 * 1000) + (minor * 1000) + micro;

    if (*version < 12000) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("QEMU version >= 0.12.00 is required, but %d.%d.%d found"),
                       major, minor, micro);
        goto cleanup;
    }

    /* Refuse to parse -help output for QEMU releases >= 1.2.0 that should be
     * using QMP probing.
     */
    if (*version >= 1002000) {
        if (qmperr && *qmperr) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QEMU / QMP failed: %s"),
                           qmperr);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("QEMU %u.%u.%u is too new for help parsing"),
                           major, minor, micro);
        }
        goto cleanup;
    }

    if (virQEMUCapsComputeCmdFlags(help, *version,
                                   qemuCaps, check_yajl) < 0)
        goto cleanup;

    strflags = virBitmapString(qemuCaps->flags);
    VIR_DEBUG("Version %u.%u.%u, cooked version %u, flags %s",
              major, minor, micro, *version, NULLSTR(strflags));
    VIR_FREE(strflags);

    if (*kvm_version)
        VIR_DEBUG("KVM version %d detected", *kvm_version);
    else if (*is_kvm)
        VIR_DEBUG("qemu-kvm version %u.%u.%u detected", major, minor, micro);

    return 0;

 fail:
    p = strchr(help, '\n');
    if (!p)
        p = strchr(help, '\0');

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse %s version number in '%.*s'"),
                   qemu, (int) (p - help), help);

 cleanup:
    return -1;
}


struct virQEMUCapsStringFlags {
    const char *value;
    int flag;
};


struct virQEMUCapsStringFlags virQEMUCapsCommands[] = {
    { "system_wakeup", QEMU_CAPS_WAKEUP },
    { "transaction", QEMU_CAPS_TRANSACTION },
    { "block_stream", QEMU_CAPS_BLOCKJOB_SYNC },
    { "block-stream", QEMU_CAPS_BLOCKJOB_ASYNC },
    { "dump-guest-memory", QEMU_CAPS_DUMP_GUEST_MEMORY },
    { "query-spice", QEMU_CAPS_SPICE },
    { "query-kvm", QEMU_CAPS_KVM },
    { "block-commit", QEMU_CAPS_BLOCK_COMMIT },
    { "query-vnc", QEMU_CAPS_VNC },
    { "drive-mirror", QEMU_CAPS_DRIVE_MIRROR },
    { "blockdev-snapshot-sync", QEMU_CAPS_DISK_SNAPSHOT },
    { "add-fd", QEMU_CAPS_ADD_FD },
    { "nbd-server-start", QEMU_CAPS_NBD_SERVER },
    { "change-backing-file", QEMU_CAPS_CHANGE_BACKING_FILE },
    { "rtc-reset-reinjection", QEMU_CAPS_RTC_RESET_REINJECTION },
    { "migrate-incoming", QEMU_CAPS_INCOMING_DEFER },
    { "query-hotpluggable-cpus", QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS },
    { "query-qmp-schema", QEMU_CAPS_QUERY_QMP_SCHEMA },
    { "query-cpu-model-expansion", QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION},
    { "query-cpu-definitions", QEMU_CAPS_QUERY_CPU_DEFINITIONS},
    { "query-named-block-nodes", QEMU_CAPS_QUERY_NAMED_BLOCK_NODES}
};

struct virQEMUCapsStringFlags virQEMUCapsMigration[] = {
    { "rdma-pin-all", QEMU_CAPS_MIGRATE_RDMA },
};

struct virQEMUCapsStringFlags virQEMUCapsEvents[] = {
    { "BALLOON_CHANGE", QEMU_CAPS_BALLOON_EVENT },
    { "SPICE_MIGRATE_COMPLETED", QEMU_CAPS_SEAMLESS_MIGRATION },
    { "DEVICE_DELETED", QEMU_CAPS_DEVICE_DEL_EVENT },
    { "MIGRATION", QEMU_CAPS_MIGRATION_EVENT },
    { "VSERPORT_CHANGE", QEMU_CAPS_VSERPORT_CHANGE },
    { "DEVICE_TRAY_MOVED", QEMU_CAPS_DEVICE_TRAY_MOVED },
    { "BLOCK_WRITE_THRESHOLD", QEMU_CAPS_BLOCK_WRITE_THRESHOLD },
};

struct virQEMUCapsStringFlags virQEMUCapsObjectTypes[] = {
    { "hda-duplex", QEMU_CAPS_HDA_DUPLEX },
    { "hda-micro", QEMU_CAPS_HDA_MICRO },
    { "ccid-card-emulated", QEMU_CAPS_CCID_EMULATED },
    { "ccid-card-passthru", QEMU_CAPS_CCID_PASSTHRU },
    { "piix3-usb-uhci", QEMU_CAPS_PIIX3_USB_UHCI },
    { "piix4-usb-uhci", QEMU_CAPS_PIIX4_USB_UHCI },
    { "usb-ehci", QEMU_CAPS_USB_EHCI },
    { "ich9-usb-ehci1", QEMU_CAPS_ICH9_USB_EHCI1 },
    { "vt82c686b-usb-uhci", QEMU_CAPS_VT82C686B_USB_UHCI },
    { "pci-ohci", QEMU_CAPS_PCI_OHCI },
    { "nec-usb-xhci", QEMU_CAPS_NEC_USB_XHCI },
    { "usb-redir", QEMU_CAPS_USB_REDIR },
    { "usb-hub", QEMU_CAPS_USB_HUB },
    { "ich9-ahci", QEMU_CAPS_ICH9_AHCI },
    { "virtio-blk-s390", QEMU_CAPS_VIRTIO_S390 },
    { "virtio-blk-ccw", QEMU_CAPS_VIRTIO_CCW },
    { "sclpconsole", QEMU_CAPS_SCLP_S390 },
    { "lsi53c895a", QEMU_CAPS_SCSI_LSI },
    { "virtio-scsi-pci", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-s390", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-ccw", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-device", QEMU_CAPS_VIRTIO_SCSI },
    { "megasas", QEMU_CAPS_SCSI_MEGASAS },
    { "spicevmc", QEMU_CAPS_DEVICE_SPICEVMC },
    { "qxl", QEMU_CAPS_DEVICE_QXL },
    { "sga", QEMU_CAPS_SGA },
    { "scsi-block", QEMU_CAPS_SCSI_BLOCK },
    { "scsi-cd", QEMU_CAPS_SCSI_CD },
    { "ide-cd", QEMU_CAPS_IDE_CD },
    { "VGA", QEMU_CAPS_DEVICE_VGA },
    { "cirrus-vga", QEMU_CAPS_DEVICE_CIRRUS_VGA },
    { "vmware-svga", QEMU_CAPS_DEVICE_VMWARE_SVGA },
    { "usb-serial", QEMU_CAPS_DEVICE_USB_SERIAL },
    { "usb-net", QEMU_CAPS_DEVICE_USB_NET },
    { "virtio-rng-pci", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-s390", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-ccw", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-device", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "rng-random", QEMU_CAPS_OBJECT_RNG_RANDOM },
    { "rng-egd", QEMU_CAPS_OBJECT_RNG_EGD },
    { "spapr-nvram", QEMU_CAPS_DEVICE_NVRAM },
    { "pci-bridge", QEMU_CAPS_DEVICE_PCI_BRIDGE },
    { "vfio-pci", QEMU_CAPS_DEVICE_VFIO_PCI },
    { "scsi-generic", QEMU_CAPS_DEVICE_SCSI_GENERIC },
    { "i82801b11-bridge", QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE },
    { "usb-storage", QEMU_CAPS_DEVICE_USB_STORAGE },
    { "virtio-mmio", QEMU_CAPS_DEVICE_VIRTIO_MMIO },
    { "ich9-intel-hda", QEMU_CAPS_DEVICE_ICH9_INTEL_HDA },
    { "pvpanic", QEMU_CAPS_DEVICE_PANIC },
    { "usb-kbd", QEMU_CAPS_DEVICE_USB_KBD },
    { "memory-backend-ram", QEMU_CAPS_OBJECT_MEMORY_RAM },
    { "memory-backend-file", QEMU_CAPS_OBJECT_MEMORY_FILE },
    { "usb-audio", QEMU_CAPS_OBJECT_USB_AUDIO },
    { "iothread", QEMU_CAPS_OBJECT_IOTHREAD},
    { "ivshmem", QEMU_CAPS_DEVICE_IVSHMEM },
    { "pc-dimm", QEMU_CAPS_DEVICE_PC_DIMM },
    { "pci-serial", QEMU_CAPS_DEVICE_PCI_SERIAL },
    { "gpex-pcihost", QEMU_CAPS_OBJECT_GPEX},
    { "ioh3420", QEMU_CAPS_DEVICE_IOH3420 },
    { "x3130-upstream", QEMU_CAPS_DEVICE_X3130_UPSTREAM },
    { "xio3130-downstream", QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM },
    { "rtl8139", QEMU_CAPS_DEVICE_RTL8139 },
    { "e1000", QEMU_CAPS_DEVICE_E1000 },
    { "virtio-net-pci", QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-net-ccw", QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-net-s390", QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-net-device", QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-gpu-pci", QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "virtio-gpu-device", QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "virtio-vga", QEMU_CAPS_DEVICE_VIRTIO_VGA },
    { "virtio-keyboard-device", QEMU_CAPS_VIRTIO_KEYBOARD },
    { "virtio-keyboard-pci", QEMU_CAPS_VIRTIO_KEYBOARD },
    { "virtio-mouse-device", QEMU_CAPS_VIRTIO_MOUSE },
    { "virtio-mouse-pci", QEMU_CAPS_VIRTIO_MOUSE },
    { "virtio-tablet-device", QEMU_CAPS_VIRTIO_TABLET },
    { "virtio-tablet-pci", QEMU_CAPS_VIRTIO_TABLET },
    { "virtio-input-host-device", QEMU_CAPS_VIRTIO_INPUT_HOST },
    { "virtio-input-host-pci", QEMU_CAPS_VIRTIO_INPUT_HOST },
    { "mptsas1068", QEMU_CAPS_SCSI_MPTSAS1068 },
    { "secret", QEMU_CAPS_OBJECT_SECRET },
    { "pxb", QEMU_CAPS_DEVICE_PXB },
    { "pxb-pcie", QEMU_CAPS_DEVICE_PXB_PCIE },
    { "tls-creds-x509", QEMU_CAPS_OBJECT_TLS_CREDS_X509 },
    { "intel-iommu", QEMU_CAPS_DEVICE_INTEL_IOMMU },
    { "ivshmem-plain", QEMU_CAPS_DEVICE_IVSHMEM_PLAIN },
    { "ivshmem-doorbell", QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL },
    { "vhost-scsi", QEMU_CAPS_DEVICE_VHOST_SCSI },
    { "nvdimm", QEMU_CAPS_DEVICE_NVDIMM },
    { "pcie-root-port", QEMU_CAPS_DEVICE_PCIE_ROOT_PORT },
    { "qemu-xhci", QEMU_CAPS_DEVICE_QEMU_XHCI },
    { "spapr-pci-host-bridge", QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtioBalloon[] = {
    { "deflate-on-oom", QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtioBlk[] = {
    { "multifunction", QEMU_CAPS_PCI_MULTIFUNCTION },
    { "bootindex", QEMU_CAPS_BOOTINDEX },
    { "ioeventfd", QEMU_CAPS_VIRTIO_IOEVENTFD },
    { "event_idx", QEMU_CAPS_VIRTIO_BLK_EVENT_IDX },
    { "scsi", QEMU_CAPS_VIRTIO_BLK_SCSI },
    { "logical_block_size", QEMU_CAPS_BLOCKIO },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtioNet[] = {
    { "tx", QEMU_CAPS_VIRTIO_TX_ALG },
    { "event_idx", QEMU_CAPS_VIRTIO_NET_EVENT_IDX },
    { "rx_queue_size", QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE },
    { "tx_queue_size", QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE },
    { "host_mtu", QEMU_CAPS_VIRTIO_NET_HOST_MTU },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsSpaprPCIHostBridge[] = {
    { "numa_node", QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtioSCSI[] = {
    { "iothread", QEMU_CAPS_VIRTIO_SCSI_IOTHREAD },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsPCIAssign[] = {
    { "configfd", QEMU_CAPS_PCI_CONFIGFD },
    { "bootindex", QEMU_CAPS_PCI_BOOTINDEX },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVfioPCI[] = {
    { "bootindex", QEMU_CAPS_VFIO_PCI_BOOTINDEX },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsSCSIDisk[] = {
    { "channel", QEMU_CAPS_SCSI_DISK_CHANNEL },
    { "wwn", QEMU_CAPS_SCSI_DISK_WWN },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsIDEDrive[] = {
    { "wwn", QEMU_CAPS_IDE_DRIVE_WWN },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsPiix4PM[] = {
    { "disable_s3", QEMU_CAPS_PIIX_DISABLE_S3 },
    { "disable_s4", QEMU_CAPS_PIIX_DISABLE_S4 },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsUSBRedir[] = {
    { "filter", QEMU_CAPS_USB_REDIR_FILTER },
    { "bootindex", QEMU_CAPS_USB_REDIR_BOOTINDEX },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsUSBHost[] = {
    { "bootindex", QEMU_CAPS_USB_HOST_BOOTINDEX },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsSCSIGeneric[] = {
    { "bootindex", QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsI440FXPCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsQ35PCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_Q35_PCI_HOLE64_SIZE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsUSBStorage[] = {
    { "removable", QEMU_CAPS_USB_STORAGE_REMOVABLE },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsKVMPit[] = {
    { "lost_tick_policy", QEMU_CAPS_KVM_PIT_TICK_POLICY },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVGA[] = {
    { "vgamem_mb", QEMU_CAPS_VGA_VGAMEM },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVmwareSvga[] = {
    { "vgamem_mb", QEMU_CAPS_VMWARE_SVGA_VGAMEM },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsQxl[] = {
    { "vgamem_mb", QEMU_CAPS_QXL_VGAMEM },
    { "vram64_size_mb", QEMU_CAPS_QXL_VRAM64 },
    { "max_outputs", QEMU_CAPS_QXL_MAX_OUTPUTS },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtioGpu[] = {
    { "virgl", QEMU_CAPS_VIRTIO_GPU_VIRGL },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsICH9[] = {
    { "disable_s3", QEMU_CAPS_ICH9_DISABLE_S3 },
    { "disable_s4", QEMU_CAPS_ICH9_DISABLE_S4 },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsUSBNECXHCI[] = {
    { "p3", QEMU_CAPS_NEC_USB_XHCI_PORTS },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsIntelIOMMU[] = {
    { "intremap", QEMU_CAPS_INTEL_IOMMU_INTREMAP },
    { "caching-mode", QEMU_CAPS_INTEL_IOMMU_CACHING_MODE },
    { "eim", QEMU_CAPS_INTEL_IOMMU_EIM },
    { "device-iotlb", QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB },
};

/* see documentation for virQEMUCapsQMPSchemaGetByPath for the query format */
static struct virQEMUCapsStringFlags virQEMUCapsQMPSchemaQueries[] = {
    { "blockdev-add/arg-type/options/+gluster/debug-level", QEMU_CAPS_GLUSTER_DEBUG_LEVEL},
    { "blockdev-add/arg-type/+gluster/debug", QEMU_CAPS_GLUSTER_DEBUG_LEVEL},
};

struct virQEMUCapsObjectTypeProps {
    const char *type;
    struct virQEMUCapsStringFlags *props;
    size_t nprops;
    int capsCondition;
};

static struct virQEMUCapsObjectTypeProps virQEMUCapsObjectProps[] = {
    { "virtio-blk-pci", virQEMUCapsObjectPropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBlk),
      -1 },
    { "virtio-net-pci", virQEMUCapsObjectPropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioNet),
      -1 },
    { "virtio-scsi-pci", virQEMUCapsObjectPropsVirtioSCSI,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioSCSI),
      -1 },
    { "virtio-blk-ccw", virQEMUCapsObjectPropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBlk),
      -1 },
    { "virtio-net-ccw", virQEMUCapsObjectPropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioNet),
      -1 },
    { "virtio-scsi-ccw", virQEMUCapsObjectPropsVirtioSCSI,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioSCSI),
      -1 },
    { "virtio-blk-s390", virQEMUCapsObjectPropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBlk),
      -1 },
    { "virtio-net-s390", virQEMUCapsObjectPropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioNet),
      -1 },
    { "pci-assign", virQEMUCapsObjectPropsPCIAssign,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsPCIAssign),
      -1 },
    { "kvm-pci-assign", virQEMUCapsObjectPropsPCIAssign,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsPCIAssign),
      -1 },
    { "vfio-pci", virQEMUCapsObjectPropsVfioPCI,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVfioPCI),
      -1 },
    { "scsi-disk", virQEMUCapsObjectPropsSCSIDisk,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsSCSIDisk),
      -1 },
    { "ide-drive", virQEMUCapsObjectPropsIDEDrive,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsIDEDrive),
      -1 },
    { "PIIX4_PM", virQEMUCapsObjectPropsPiix4PM,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsPiix4PM),
      -1 },
    { "usb-redir", virQEMUCapsObjectPropsUSBRedir,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsUSBRedir),
      -1 },
    { "usb-host", virQEMUCapsObjectPropsUSBHost,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsUSBHost),
      -1 },
    { "scsi-generic", virQEMUCapsObjectPropsSCSIGeneric,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsSCSIGeneric),
      -1 },
    { "i440FX-pcihost", virQEMUCapsObjectPropsI440FXPCIHost,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsI440FXPCIHost),
      -1 },
    { "q35-pcihost", virQEMUCapsObjectPropsQ35PCIHost,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsQ35PCIHost),
      -1 },
    { "usb-storage", virQEMUCapsObjectPropsUSBStorage,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsUSBStorage),
      -1 },
    { "kvm-pit", virQEMUCapsObjectPropsKVMPit,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsKVMPit),
      -1 },
    { "VGA", virQEMUCapsObjectPropsVGA,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVGA),
      -1 },
    { "vmware-svga", virQEMUCapsObjectPropsVmwareSvga,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVmwareSvga),
      -1 },
    { "qxl", virQEMUCapsObjectPropsQxl,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsQxl),
      -1 },
    { "virtio-gpu-pci", virQEMUCapsObjectPropsVirtioGpu,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioGpu),
      -1 },
    { "virtio-gpu-device", virQEMUCapsObjectPropsVirtioGpu,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioGpu),
      -1 },
    { "ICH9-LPC", virQEMUCapsObjectPropsICH9,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsICH9),
      -1 },
    { "virtio-balloon-pci", virQEMUCapsObjectPropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBalloon),
      -1 },
    { "virtio-balloon-ccw", virQEMUCapsObjectPropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBalloon),
      -1 },
    { "virtio-balloon-device", virQEMUCapsObjectPropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtioBalloon),
      -1 },
    { "nec-usb-xhci", virQEMUCapsObjectPropsUSBNECXHCI,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsUSBNECXHCI),
      -1 },
    { "intel-iommu", virQEMUCapsObjectPropsIntelIOMMU,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsIntelIOMMU),
      QEMU_CAPS_DEVICE_INTEL_IOMMU },
    { "spapr-pci-host-bridge", virQEMUCapsObjectPropsSpaprPCIHostBridge,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsSpaprPCIHostBridge),
      QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE },
};

struct virQEMUCapsPropTypeObjects {
    const char *prop;
    int flag;
    const char **objects;
};

static const char *virQEMUCapsVirtioPCIObjects[] = {
     "virtio-balloon-pci",
     "virtio-blk-pci",
     "virtio-scsi-pci",
     "virtio-serial-pci",
     "virtio-9p-pci",
     "virtio-net-pci",
     "virtio-rng-pci",
     "virtio-gpu-pci",
     "virtio-input-host-pci",
     "virtio-keyboard-pci",
     "virtio-mouse-pci",
     "virtio-tablet-pci",
     NULL
};

static struct virQEMUCapsPropTypeObjects virQEMUCapsPropObjects[] = {
    { "disable-legacy",
      QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY,
      virQEMUCapsVirtioPCIObjects },
    { "iommu_platform",
      QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM,
      virQEMUCapsVirtioPCIObjects },
    { "ats",
      QEMU_CAPS_VIRTIO_PCI_ATS,
      virQEMUCapsVirtioPCIObjects },
};


static void
virQEMUCapsProcessStringFlags(virQEMUCapsPtr qemuCaps,
                              size_t nflags,
                              struct virQEMUCapsStringFlags *flags,
                              size_t nvalues,
                              char *const*values)
{
    size_t i, j;
    for (i = 0; i < nflags; i++) {
        for (j = 0; j < nvalues; j++) {
            if (STREQ(values[j], flags[i].value)) {
                virQEMUCapsSet(qemuCaps, flags[i].flag);
                break;
            }
        }
    }
}


static void
virQEMUCapsProcessProps(virQEMUCapsPtr qemuCaps,
                        size_t nprops,
                        struct virQEMUCapsPropTypeObjects *props,
                        const char *object,
                        size_t nvalues,
                        char *const*values)
{
    size_t i, j;

    for (i = 0; i < nprops; i++) {
        if (virQEMUCapsGet(qemuCaps, props[i].flag))
            continue;

        for (j = 0; j < nvalues; j++) {
            if (STREQ(values[j], props[i].prop)) {
                if (virStringListHasString(props[i].objects, object))
                    virQEMUCapsSet(qemuCaps, props[i].flag);
                break;
            }
        }
    }
}


#define OBJECT_TYPE_PREFIX "name \""

static int
virQEMUCapsParseDeviceStrObjectTypes(const char *str,
                                     char ***types)
{
    const char *tmp = str;
    int ret = -1;
    size_t ntypelist = 0;
    char **typelist = NULL;

    *types = NULL;

    while ((tmp = strstr(tmp, OBJECT_TYPE_PREFIX))) {
        char *end;
        tmp += strlen(OBJECT_TYPE_PREFIX);
        end = strstr(tmp, "\"");
        if (!end) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed QEMU device list string, missing quote"));
            goto cleanup;
        }

        if (VIR_EXPAND_N(typelist, ntypelist, 1) < 0)
            goto cleanup;
        if (VIR_STRNDUP(typelist[ntypelist - 1], tmp, end-tmp) < 0)
            goto cleanup;
    }

    *types = typelist;
    ret = ntypelist;

 cleanup:
    if (ret < 0)
        virStringListFreeCount(typelist, ntypelist);
    return ret;
}


static int
virQEMUCapsParseDeviceStrObjectProps(const char *str,
                                     const char *type,
                                     char ***props)
{
    const char *tmp = str;
    int ret = -1;
    size_t nproplist = 0;
    char **proplist = NULL;

    VIR_DEBUG("Extract type %s", type);
    *props = NULL;

    while ((tmp = strchr(tmp, '\n'))) {
        char *end;
        tmp += 1;

        if (*tmp == '\0')
            break;

        if (STRPREFIX(tmp, OBJECT_TYPE_PREFIX))
            continue;

        if (!STRPREFIX(tmp, type))
            continue;

        tmp += strlen(type);
        if (*tmp != '.')
            continue;
        tmp++;

        end = strstr(tmp, "=");
        if (!end) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed QEMU device list string, missing '='"));
            goto cleanup;
        }
        if (VIR_EXPAND_N(proplist, nproplist, 1) < 0)
            goto cleanup;
        if (VIR_STRNDUP(proplist[nproplist - 1], tmp, end-tmp) < 0)
            goto cleanup;
    }

    *props = proplist;
    ret = nproplist;

 cleanup:
    if (ret < 0)
        virStringListFreeCount(proplist, nproplist);
    return ret;
}


int
virQEMUCapsParseDeviceStr(virQEMUCapsPtr qemuCaps, const char *str)
{
    int nvalues;
    char **values;
    size_t i;

    if ((nvalues = virQEMUCapsParseDeviceStrObjectTypes(str, &values)) < 0)
        return -1;
    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsObjectTypes),
                                  virQEMUCapsObjectTypes,
                                  nvalues, values);
    virStringListFreeCount(values, nvalues);

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsObjectProps); i++) {
        const char *type = virQEMUCapsObjectProps[i].type;
        if ((nvalues = virQEMUCapsParseDeviceStrObjectProps(str,
                                                            type,
                                                            &values)) < 0)
            return -1;
        virQEMUCapsProcessStringFlags(qemuCaps,
                                      virQEMUCapsObjectProps[i].nprops,
                                      virQEMUCapsObjectProps[i].props,
                                      nvalues, values);
        virStringListFreeCount(values, nvalues);
    }

    /* Prefer -chardev spicevmc (detected earlier) over -device spicevmc */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEVMC))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_SPICEVMC);

    return 0;
}


static int
virQEMUCapsExtractDeviceStr(const char *qemu,
                            virQEMUCapsPtr qemuCaps,
                            uid_t runUid, gid_t runGid)
{
    char *output = NULL;
    virCommandPtr cmd;
    int ret = -1;

    /* Cram together all device-related queries into one invocation;
     * the output format makes it possible to distinguish what we
     * need.  With qemu 0.13.0 and later, unrecognized '-device
     * bogus,?' cause an error in isolation, but are silently ignored
     * in combination with '-device ?'.  Upstream qemu 0.12.x doesn't
     * understand '-device name,?', and always exits with status 1 for
     * the simpler '-device ?', so this function is really only useful
     * if -help includes "device driver,?".  */
    cmd = virQEMUCapsProbeCommand(qemu, qemuCaps, runUid, runGid);
    virCommandAddArgList(cmd,
                         "-device", "?",
                         "-device", "pci-assign,?",
                         "-device", "virtio-blk-pci,?",
                         "-device", "virtio-net-pci,?",
                         "-device", "scsi-disk,?",
                         "-device", "PIIX4_PM,?",
                         "-device", "usb-redir,?",
                         "-device", "ide-drive,?",
                         "-device", "usb-host,?",
                         "-device", "scsi-generic,?",
                         "-device", "usb-storage,?",
                         "-device", "VGA,?",
                         "-device", "vmware-svga,?",
                         "-device", "qxl,?",
                         "-device", "qxl-vga,?",
                         NULL);
    /* qemu -help goes to stdout, but qemu -device ? goes to stderr.  */
    virCommandSetErrorBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = virQEMUCapsParseDeviceStr(qemuCaps, output);

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}


int virQEMUCapsGetDefaultVersion(virCapsPtr caps,
                                 virFileCachePtr capsCache,
                                 unsigned int *version)
{
    virQEMUCapsPtr qemucaps;
    virArch hostarch;
    virCapsDomainDataPtr capsdata;

    if (*version > 0)
        return 0;

    hostarch = virArchFromHost();
    if (!(capsdata = virCapabilitiesDomainDataLookup(caps,
            VIR_DOMAIN_OSTYPE_HVM, hostarch, VIR_DOMAIN_VIRT_QEMU,
            NULL, NULL))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find suitable emulator for %s"),
                       virArchToString(hostarch));
        return -1;
    }

    qemucaps = virQEMUCapsCacheLookup(capsCache, capsdata->emulator);
    VIR_FREE(capsdata);
    if (!qemucaps)
        return -1;

    *version = virQEMUCapsGetVersion(qemucaps);
    virObjectUnref(qemucaps);
    return 0;
}




virQEMUCapsPtr
virQEMUCapsNew(void)
{
    virQEMUCapsPtr qemuCaps;

    if (virQEMUCapsInitialize() < 0)
        return NULL;

    if (!(qemuCaps = virObjectNew(virQEMUCapsClass)))
        return NULL;

    if (!(qemuCaps->flags = virBitmapNew(QEMU_CAPS_LAST)))
        goto error;

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}


static int
virQEMUCapsHostCPUDataCopy(virQEMUCapsHostCPUDataPtr dst,
                           virQEMUCapsHostCPUDataPtr src)
{
    if (src->info &&
        !(dst->info = qemuMonitorCPUModelInfoCopy(src->info)))
        return -1;

    if (src->reported &&
        !(dst->reported = virCPUDefCopy(src->reported)))
        return -1;

    if (src->migratable &&
        !(dst->migratable = virCPUDefCopy(src->migratable)))
        return -1;

    if (src->full &&
        !(dst->full = virCPUDefCopy(src->full)))
        return -1;

    return 0;
}


static void
virQEMUCapsHostCPUDataClear(virQEMUCapsHostCPUDataPtr cpuData)
{
    qemuMonitorCPUModelInfoFree(cpuData->info);
    virCPUDefFree(cpuData->reported);
    virCPUDefFree(cpuData->migratable);
    virCPUDefFree(cpuData->full);

    memset(cpuData, 0, sizeof(*cpuData));
}


virQEMUCapsPtr virQEMUCapsNewCopy(virQEMUCapsPtr qemuCaps)
{
    virQEMUCapsPtr ret = virQEMUCapsNew();
    size_t i;

    if (!ret)
        return NULL;

    ret->usedQMP = qemuCaps->usedQMP;

    if (VIR_STRDUP(ret->binary, qemuCaps->binary) < 0)
        goto error;

    ret->ctime = qemuCaps->ctime;

    virBitmapCopy(ret->flags, qemuCaps->flags);

    ret->version = qemuCaps->version;
    ret->kvmVersion = qemuCaps->kvmVersion;

    if (VIR_STRDUP(ret->package, qemuCaps->package) < 0)
        goto error;

    ret->arch = qemuCaps->arch;

    if (qemuCaps->kvmCPUModels) {
        ret->kvmCPUModels = virDomainCapsCPUModelsCopy(qemuCaps->kvmCPUModels);
        if (!ret->kvmCPUModels)
            goto error;
    }

    if (qemuCaps->tcgCPUModels) {
        ret->tcgCPUModels = virDomainCapsCPUModelsCopy(qemuCaps->tcgCPUModels);
        if (!ret->tcgCPUModels)
            goto error;
    }

    if (virQEMUCapsHostCPUDataCopy(&ret->kvmCPU, &qemuCaps->kvmCPU) < 0 ||
        virQEMUCapsHostCPUDataCopy(&ret->tcgCPU, &qemuCaps->tcgCPU) < 0)
        goto error;

    if (VIR_ALLOC_N(ret->machineTypes, qemuCaps->nmachineTypes) < 0)
        goto error;
    ret->nmachineTypes = qemuCaps->nmachineTypes;
    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (VIR_STRDUP(ret->machineTypes[i].name, qemuCaps->machineTypes[i].name) < 0 ||
            VIR_STRDUP(ret->machineTypes[i].alias, qemuCaps->machineTypes[i].alias) < 0)
            goto error;
        ret->machineTypes[i].maxCpus = qemuCaps->machineTypes[i].maxCpus;
        ret->machineTypes[i].hotplugCpus = qemuCaps->machineTypes[i].hotplugCpus;
    }

    if (VIR_ALLOC_N(ret->gicCapabilities, qemuCaps->ngicCapabilities) < 0)
        goto error;
    ret->ngicCapabilities = qemuCaps->ngicCapabilities;
    for (i = 0; i < qemuCaps->ngicCapabilities; i++)
        ret->gicCapabilities[i] = qemuCaps->gicCapabilities[i];

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


void virQEMUCapsDispose(void *obj)
{
    virQEMUCapsPtr qemuCaps = obj;
    size_t i;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        VIR_FREE(qemuCaps->machineTypes[i].name);
        VIR_FREE(qemuCaps->machineTypes[i].alias);
    }
    VIR_FREE(qemuCaps->machineTypes);

    virObjectUnref(qemuCaps->kvmCPUModels);
    virObjectUnref(qemuCaps->tcgCPUModels);

    virBitmapFree(qemuCaps->flags);

    VIR_FREE(qemuCaps->package);
    VIR_FREE(qemuCaps->binary);

    VIR_FREE(qemuCaps->gicCapabilities);

    virQEMUCapsHostCPUDataClear(&qemuCaps->kvmCPU);
    virQEMUCapsHostCPUDataClear(&qemuCaps->tcgCPU);
}

void
virQEMUCapsSet(virQEMUCapsPtr qemuCaps,
               virQEMUCapsFlags flag)
{
    ignore_value(virBitmapSetBit(qemuCaps->flags, flag));
}


void
virQEMUCapsSetList(virQEMUCapsPtr qemuCaps, ...)
{
    va_list list;
    int flag;

    va_start(list, qemuCaps);
    while ((flag = va_arg(list, int)) < QEMU_CAPS_LAST)
        ignore_value(virBitmapSetBit(qemuCaps->flags, flag));
    va_end(list);
}


void
virQEMUCapsClear(virQEMUCapsPtr qemuCaps,
                 virQEMUCapsFlags flag)
{
    ignore_value(virBitmapClearBit(qemuCaps->flags, flag));
}


char *virQEMUCapsFlagsString(virQEMUCapsPtr qemuCaps)
{
    return virBitmapString(qemuCaps->flags);
}


bool
virQEMUCapsGet(virQEMUCapsPtr qemuCaps,
               virQEMUCapsFlags flag)
{
    return qemuCaps && virBitmapIsBitSet(qemuCaps->flags, flag);
}


bool virQEMUCapsHasPCIMultiBus(virQEMUCapsPtr qemuCaps,
                               virDomainDefPtr def)
{
    /* x86_64 and i686 support PCI-multibus on all machine types
     * since forever */
    if (ARCH_IS_X86(qemuCaps->arch))
        return true;

    if (def->os.arch == VIR_ARCH_PPC ||
        ARCH_IS_PPC64(def->os.arch)) {
        /*
         * Usage of pci.0 naming:
         *
         *    ref405ep: no pci
         *       taihu: no pci
         *      bamboo: 1.1.0
         *       mac99: 2.0.0
         *     g3beige: 2.0.0
         *        prep: 1.4.0
         *     pseries: 2.0.0
         *   mpc8544ds: forever
         * virtex-m507: no pci
         *     ppce500: 1.6.0
         */

        if (qemuCaps->version >= 2000000)
            return true;

        if (qemuCaps->version >= 1006000 &&
            STREQ(def->os.machine, "ppce500"))
            return true;

        if (qemuCaps->version >= 1004000 &&
            STREQ(def->os.machine, "prep"))
            return true;

        if (qemuCaps->version >= 1001000 &&
            STREQ(def->os.machine, "bamboo"))
            return true;

        if (STREQ(def->os.machine, "mpc8544ds"))
            return true;

        return false;
    }

    /* If 'virt' supports PCI, it supports multibus.
     * No extra conditions here for simplicity.
     */
    if (qemuDomainIsVirt(def))
        return true;

    return false;
}


const char *virQEMUCapsGetBinary(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->binary;
}


void
virQEMUCapsSetArch(virQEMUCapsPtr qemuCaps,
                   virArch arch)
{
    qemuCaps->arch = arch;
}


virArch virQEMUCapsGetArch(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->arch;
}


void
virQEMUCapsSetVersion(virQEMUCapsPtr qemuCaps,
                      unsigned int version)
{
    qemuCaps->version = version;
}


unsigned int virQEMUCapsGetVersion(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->version;
}


unsigned int virQEMUCapsGetKVMVersion(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->kvmVersion;
}


const char *virQEMUCapsGetPackage(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->package;
}


int
virQEMUCapsAddCPUDefinitions(virQEMUCapsPtr qemuCaps,
                             virDomainVirtType type,
                             const char **name,
                             size_t count,
                             virDomainCapsCPUUsable usable)
{
    size_t i;
    virDomainCapsCPUModelsPtr cpus = NULL;

    if (type == VIR_DOMAIN_VIRT_KVM && qemuCaps->kvmCPUModels)
        cpus = qemuCaps->kvmCPUModels;
    else if (type == VIR_DOMAIN_VIRT_QEMU && qemuCaps->tcgCPUModels)
        cpus = qemuCaps->tcgCPUModels;

    if (!cpus) {
        if (!(cpus = virDomainCapsCPUModelsNew(count)))
            return -1;

        if (type == VIR_DOMAIN_VIRT_KVM)
            qemuCaps->kvmCPUModels = cpus;
        else
            qemuCaps->tcgCPUModels = cpus;
    }

    for (i = 0; i < count; i++) {
        if (virDomainCapsCPUModelsAdd(cpus, name[i], -1, usable) < 0)
            return -1;
    }

    return 0;
}


int
virQEMUCapsGetCPUDefinitions(virQEMUCapsPtr qemuCaps,
                             virDomainVirtType type,
                             char ***names,
                             size_t *count)
{
    size_t i;
    char **models = NULL;
    virDomainCapsCPUModelsPtr cpus;

    *count = 0;
    if (names)
        *names = NULL;

    if (type == VIR_DOMAIN_VIRT_KVM)
        cpus = qemuCaps->kvmCPUModels;
    else
        cpus = qemuCaps->tcgCPUModels;

    if (!cpus)
        return 0;

    if (names && VIR_ALLOC_N(models, cpus->nmodels) < 0)
        return -1;

    for (i = 0; i < cpus->nmodels; i++) {
        virDomainCapsCPUModelPtr cpu = cpus->models + i;
        if (models && VIR_STRDUP(models[i], cpu->name) < 0)
            goto error;
    }

    if (names)
        *names = models;
    *count = cpus->nmodels;
    return 0;

 error:
    virStringListFreeCount(models, i);
    return -1;
}


static virQEMUCapsHostCPUDataPtr
virQEMUCapsGetHostCPUData(virQEMUCapsPtr qemuCaps,
                          virDomainVirtType type)
{
    if (type == VIR_DOMAIN_VIRT_KVM)
        return &qemuCaps->kvmCPU;
    else
        return &qemuCaps->tcgCPU;
}


virCPUDefPtr
virQEMUCapsGetHostModel(virQEMUCapsPtr qemuCaps,
                        virDomainVirtType type,
                        virQEMUCapsHostCPUType cpuType)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);

    switch (cpuType) {
    case VIR_QEMU_CAPS_HOST_CPU_REPORTED:
        return cpuData->reported;

    case VIR_QEMU_CAPS_HOST_CPU_MIGRATABLE:
        return cpuData->migratable;

    case VIR_QEMU_CAPS_HOST_CPU_FULL:
        /* 'full' is non-NULL only if we have data from both QEMU and
         * virCPUGetHost */
        return cpuData->full ? cpuData->full : cpuData->reported;
    }

    return NULL;
}


static void
virQEMUCapsSetHostModel(virQEMUCapsPtr qemuCaps,
                        virDomainVirtType type,
                        virCPUDefPtr reported,
                        virCPUDefPtr migratable,
                        virCPUDefPtr full)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);

    cpuData->reported = reported;
    cpuData->migratable = migratable;
    cpuData->full = full;
}


bool
virQEMUCapsIsCPUModeSupported(virQEMUCapsPtr qemuCaps,
                              virCapsPtr caps,
                              virDomainVirtType type,
                              virCPUMode mode)
{
    virDomainCapsCPUModelsPtr cpus;

    switch (mode) {
    case VIR_CPU_MODE_HOST_PASSTHROUGH:
        return type == VIR_DOMAIN_VIRT_KVM &&
               virQEMUCapsGuestIsNative(caps->host.arch, qemuCaps->arch);

    case VIR_CPU_MODE_HOST_MODEL:
        return !!virQEMUCapsGetHostModel(qemuCaps, type,
                                         VIR_QEMU_CAPS_HOST_CPU_REPORTED);

    case VIR_CPU_MODE_CUSTOM:
        if (type == VIR_DOMAIN_VIRT_KVM)
            cpus = qemuCaps->kvmCPUModels;
        else
            cpus = qemuCaps->tcgCPUModels;
        return cpus && cpus->nmodels > 0;

    case VIR_CPU_MODE_LAST:
        break;
    }

    return false;
}


int virQEMUCapsGetMachineTypesCaps(virQEMUCapsPtr qemuCaps,
                                   size_t *nmachines,
                                   virCapsGuestMachinePtr **machines)
{
    size_t i;

    *machines = NULL;
    *nmachines = qemuCaps->nmachineTypes;

    if (*nmachines &&
        VIR_ALLOC_N(*machines, qemuCaps->nmachineTypes) < 0)
        goto error;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        virCapsGuestMachinePtr mach;
        if (VIR_ALLOC(mach) < 0)
            goto error;
        (*machines)[i] = mach;
        if (qemuCaps->machineTypes[i].alias) {
            if (VIR_STRDUP(mach->name, qemuCaps->machineTypes[i].alias) < 0 ||
                VIR_STRDUP(mach->canonical, qemuCaps->machineTypes[i].name) < 0)
                goto error;
        } else {
            if (VIR_STRDUP(mach->name, qemuCaps->machineTypes[i].name) < 0)
                goto error;
        }
        mach->maxCpus = qemuCaps->machineTypes[i].maxCpus;
    }

    /* Make sure all canonical machine types also have their own entry so that
     * /capabilities/guest/arch[@name='...']/machine/text() XPath selects all
     * supported machine types.
     */
    i = 0;
    while (i < *nmachines) {
        size_t j;
        bool found = false;
        virCapsGuestMachinePtr machine = (*machines)[i];

        if (!machine->canonical) {
            i++;
            continue;
        }

        for (j = 0; j < *nmachines; j++) {
            if (STREQ(machine->canonical, (*machines)[j]->name)) {
                found = true;
                break;
            }
        }

        if (!found) {
            virCapsGuestMachinePtr mach;
            if (VIR_ALLOC(mach) < 0)
                goto error;
            if (VIR_INSERT_ELEMENT_COPY(*machines, i, *nmachines, mach) < 0) {
                VIR_FREE(mach);
                goto error;
            }
            if (VIR_STRDUP(mach->name, machine->canonical) < 0)
                goto error;
            mach->maxCpus = machine->maxCpus;
            i++;
        }
        i++;
    }

    return 0;

 error:
    virCapabilitiesFreeMachines(*machines, *nmachines);
    *nmachines = 0;
    *machines = NULL;
    return -1;
}




const char *virQEMUCapsGetCanonicalMachine(virQEMUCapsPtr qemuCaps,
                                           const char *name)
{
    size_t i;

    if (!name)
        return NULL;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (!qemuCaps->machineTypes[i].alias)
            continue;
        if (STREQ(qemuCaps->machineTypes[i].alias, name))
            return qemuCaps->machineTypes[i].name;
    }

    return name;
}


int virQEMUCapsGetMachineMaxCpus(virQEMUCapsPtr qemuCaps,
                                 const char *name)
{
    size_t i;

    if (!name)
        return 0;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (!qemuCaps->machineTypes[i].maxCpus)
            continue;
        if (STREQ(qemuCaps->machineTypes[i].name, name))
            return qemuCaps->machineTypes[i].maxCpus;
    }

    return 0;
}


bool virQEMUCapsGetMachineHotplugCpus(virQEMUCapsPtr qemuCaps,
                                      const char *name)
{
    size_t i;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (STREQ_NULLABLE(qemuCaps->machineTypes[i].name, name))
            return qemuCaps->machineTypes[i].hotplugCpus;
    }

    return false;
}


/**
 * virQEMUCapsSetGICCapabilities:
 * @qemuCaps: QEMU capabilities
 * @capabilities: GIC capabilities
 * @ncapabilities: number of GIC capabilities
 *
 * Set the GIC capabilities for @qemuCaps.
 *
 * The ownership of @capabilities is taken away from the caller, ie. this
 * function will not make a copy of @capabilities, so releasing that memory
 * after it's been called is a bug.
 */
void
virQEMUCapsSetGICCapabilities(virQEMUCapsPtr qemuCaps,
                              virGICCapability *capabilities,
                              size_t ncapabilities)
{
    VIR_FREE(qemuCaps->gicCapabilities);

    qemuCaps->gicCapabilities = capabilities;
    qemuCaps->ngicCapabilities = ncapabilities;
}


static int
virQEMUCapsProbeQMPCommands(virQEMUCapsPtr qemuCaps,
                            qemuMonitorPtr mon)
{
    char **commands = NULL;
    int ncommands;

    if ((ncommands = qemuMonitorGetCommands(mon, &commands)) < 0)
        return -1;

    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsCommands),
                                  virQEMUCapsCommands,
                                  ncommands, commands);
    virStringListFreeCount(commands, ncommands);

    /* QMP add-fd was introduced in 1.2, but did not support
     * management control of set numbering, and did not have a
     * counterpart -add-fd command line option.  We require the
     * add-fd features from 1.3 or later.  */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_ADD_FD)) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to probe for add-fd"));
            return -1;
        }
        if (qemuMonitorAddFd(mon, 0, fd, "/dev/null") < 0)
            virQEMUCapsClear(qemuCaps, QEMU_CAPS_ADD_FD);
        VIR_FORCE_CLOSE(fd);
    }

    /* Probe for active commit of qemu 2.1 (for now, we are choosing
     * to ignore the fact that qemu 2.0 can also do active commit) */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCK_COMMIT) &&
        qemuMonitorSupportsActiveCommit(mon))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_ACTIVE_COMMIT);

    return 0;
}


static int
virQEMUCapsProbeQMPEvents(virQEMUCapsPtr qemuCaps,
                          qemuMonitorPtr mon)
{
    char **events = NULL;
    int nevents;

    if ((nevents = qemuMonitorGetEvents(mon, &events)) < 0)
        return -1;

    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsEvents),
                                  virQEMUCapsEvents,
                                  nevents, events);
    virStringListFreeCount(events, nevents);

    return 0;
}


static int
virQEMUCapsProbeQMPObjects(virQEMUCapsPtr qemuCaps,
                           qemuMonitorPtr mon)
{
    int nvalues;
    char **values;
    size_t i;

    if ((nvalues = qemuMonitorGetObjectTypes(mon, &values)) < 0)
        return -1;
    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsObjectTypes),
                                  virQEMUCapsObjectTypes,
                                  nvalues, values);
    virStringListFreeCount(values, nvalues);

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsObjectProps); i++) {
        const char *type = virQEMUCapsObjectProps[i].type;
        int cap = virQEMUCapsObjectProps[i].capsCondition;

        if (cap >= 0 && !virQEMUCapsGet(qemuCaps, cap))
            continue;

        if ((nvalues = qemuMonitorGetObjectProps(mon,
                                                 type,
                                                 &values)) < 0)
            return -1;
        virQEMUCapsProcessStringFlags(qemuCaps,
                                      virQEMUCapsObjectProps[i].nprops,
                                      virQEMUCapsObjectProps[i].props,
                                      nvalues, values);
        virQEMUCapsProcessProps(qemuCaps,
                                ARRAY_CARDINALITY(virQEMUCapsPropObjects),
                                virQEMUCapsPropObjects, type,
                                nvalues, values);
        virStringListFreeCount(values, nvalues);
    }

    /* Prefer -chardev spicevmc (detected earlier) over -device spicevmc */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEVMC))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_SPICEVMC);

    return 0;
}


static int
virQEMUCapsProbeQMPMachineTypes(virQEMUCapsPtr qemuCaps,
                                qemuMonitorPtr mon)
{
    qemuMonitorMachineInfoPtr *machines = NULL;
    int nmachines = 0;
    int ret = -1;
    size_t i;
    size_t defIdx = 0;

    if ((nmachines = qemuMonitorGetMachines(mon, &machines)) < 0)
        return -1;

    if (VIR_ALLOC_N(qemuCaps->machineTypes, nmachines) < 0)
        goto cleanup;

    for (i = 0; i < nmachines; i++) {
        struct virQEMUCapsMachineType *mach;
        if (STREQ(machines[i]->name, "none"))
            continue;

        mach = &(qemuCaps->machineTypes[qemuCaps->nmachineTypes++]);

        if (VIR_STRDUP(mach->alias, machines[i]->alias) < 0 ||
            VIR_STRDUP(mach->name, machines[i]->name) < 0)
            goto cleanup;

        mach->maxCpus = machines[i]->maxCpus;
        mach->hotplugCpus = machines[i]->hotplugCpus;

        if (machines[i]->isDefault)
            defIdx = qemuCaps->nmachineTypes - 1;
    }

    if (defIdx)
        virQEMUCapsSetDefaultMachine(qemuCaps, defIdx);

    ret = 0;

 cleanup:
    for (i = 0; i < nmachines; i++)
        qemuMonitorMachineInfoFree(machines[i]);
    VIR_FREE(machines);
    return ret;
}


static int
virQEMUCapsProbeQMPCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                  qemuMonitorPtr mon,
                                  bool tcg)
{
    virDomainCapsCPUModelsPtr models;
    qemuMonitorCPUDefInfoPtr *cpus;
    int ncpus;
    int ret = -1;
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_DEFINITIONS))
        return 0;

    if ((ncpus = qemuMonitorGetCPUDefinitions(mon, &cpus)) < 0)
        return -1;

    if (!(models = virDomainCapsCPUModelsNew(ncpus)))
        goto cleanup;

    if (tcg || !virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        qemuCaps->tcgCPUModels = models;
    else
        qemuCaps->kvmCPUModels = models;

    for (i = 0; i < ncpus; i++) {
        virDomainCapsCPUUsable usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;

        if (cpus[i]->usable == VIR_TRISTATE_BOOL_YES)
            usable = VIR_DOMCAPS_CPU_USABLE_YES;
        else if (cpus[i]->usable == VIR_TRISTATE_BOOL_NO)
            usable = VIR_DOMCAPS_CPU_USABLE_NO;

        if (virDomainCapsCPUModelsAddSteal(models, &cpus[i]->name, usable) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < ncpus; i++)
        qemuMonitorCPUDefInfoFree(cpus[i]);
    VIR_FREE(cpus);
    return ret;
}

static int
virQEMUCapsProbeQMPHostCPU(virQEMUCapsPtr qemuCaps,
                           qemuMonitorPtr mon,
                           bool tcg)
{
    qemuMonitorCPUModelInfoPtr modelInfo = NULL;
    qemuMonitorCPUModelInfoPtr nonMigratable = NULL;
    virHashTablePtr hash = NULL;
    const char *model;
    qemuMonitorCPUModelExpansionType type;
    virDomainVirtType virtType;
    virQEMUCapsHostCPUDataPtr cpuData;
    int ret = -1;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION))
        return 0;

    if (tcg || !virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        virtType = VIR_DOMAIN_VIRT_QEMU;
        model = "max";
    } else {
        virtType = VIR_DOMAIN_VIRT_KVM;
        model = "host";
    }

    cpuData = virQEMUCapsGetHostCPUData(qemuCaps, virtType);

    /* Some x86_64 features defined in cpu_map.xml use spelling which differ
     * from the one preferred by QEMU. Static expansion would give us only the
     * preferred spelling, thus we need to do a full expansion on the result of
     * the initial static expansion to get all variants of all features.
     */
    if (ARCH_IS_X86(qemuCaps->arch))
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL;
    else
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC;

    if (qemuMonitorGetCPUModelExpansion(mon, type, model, true, &modelInfo) < 0)
        goto cleanup;

    /* Try to check migratability of each feature. */
    if (modelInfo &&
        qemuMonitorGetCPUModelExpansion(mon, type, model, false,
                                        &nonMigratable) < 0)
        goto cleanup;

    if (nonMigratable) {
        qemuMonitorCPUPropertyPtr prop;
        qemuMonitorCPUPropertyPtr nmProp;
        size_t i;

        if (!(hash = virHashCreate(0, NULL)))
            goto cleanup;

        for (i = 0; i < modelInfo->nprops; i++) {
            prop = modelInfo->props + i;
            if (virHashAddEntry(hash, prop->name, prop) < 0)
                goto cleanup;
        }

        for (i = 0; i < nonMigratable->nprops; i++) {
            nmProp = nonMigratable->props + i;
            if (!(prop = virHashLookup(hash, nmProp->name)) ||
                prop->type != QEMU_MONITOR_CPU_PROPERTY_BOOLEAN ||
                prop->type != nmProp->type)
                continue;

            if (prop->value.boolean) {
                prop->migratable = VIR_TRISTATE_BOOL_YES;
            } else if (nmProp->value.boolean) {
                prop->value.boolean = true;
                prop->migratable = VIR_TRISTATE_BOOL_NO;
            }
        }

        modelInfo->migratability = true;
    }

    VIR_STEAL_PTR(cpuData->info, modelInfo);
    ret = 0;

 cleanup:
    virHashFree(hash);
    qemuMonitorCPUModelInfoFree(nonMigratable);
    qemuMonitorCPUModelInfoFree(modelInfo);

    return ret;
}

struct tpmTypeToCaps {
    int type;
    virQEMUCapsFlags caps;
};

static const struct tpmTypeToCaps virQEMUCapsTPMTypesToCaps[] = {
    {
        .type = VIR_DOMAIN_TPM_TYPE_PASSTHROUGH,
        .caps = QEMU_CAPS_DEVICE_TPM_PASSTHROUGH,
    },
};

const struct tpmTypeToCaps virQEMUCapsTPMModelsToCaps[] = {
    {
        .type = VIR_DOMAIN_TPM_MODEL_TIS,
        .caps = QEMU_CAPS_DEVICE_TPM_TIS,
    },
};

static int
virQEMUCapsProbeQMPTPM(virQEMUCapsPtr qemuCaps,
                       qemuMonitorPtr mon)
{
    int nentries;
    size_t i;
    char **entries = NULL;

    if ((nentries = qemuMonitorGetTPMModels(mon, &entries)) < 0)
        return -1;

    if (nentries > 0) {
        for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsTPMModelsToCaps); i++) {
            const char *needle = virDomainTPMModelTypeToString(
                virQEMUCapsTPMModelsToCaps[i].type);
            if (virStringListHasString((const char **) entries, needle))
                virQEMUCapsSet(qemuCaps,
                               virQEMUCapsTPMModelsToCaps[i].caps);
        }
    }
    virStringListFree(entries);

    if ((nentries = qemuMonitorGetTPMTypes(mon, &entries)) < 0)
        return -1;

    if (nentries > 0) {
        for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsTPMTypesToCaps); i++) {
            const char *needle = virDomainTPMBackendTypeToString(
                virQEMUCapsTPMTypesToCaps[i].type);
            if (virStringListHasString((const char **) entries, needle))
                virQEMUCapsSet(qemuCaps, virQEMUCapsTPMTypesToCaps[i].caps);
        }
    }
    virStringListFree(entries);

    return 0;
}


static int
virQEMUCapsProbeQMPKVMState(virQEMUCapsPtr qemuCaps,
                            qemuMonitorPtr mon)
{
    bool enabled = false;
    bool present = false;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        return 0;

    if (qemuMonitorGetKVMState(mon, &enabled, &present) < 0)
        return -1;

    /* The QEMU_CAPS_KVM flag was initially set according to the QEMU
     * reporting the recognition of 'query-kvm' QMP command. That merely
     * indicates existence of the command though, not whether KVM support
     * is actually available, nor whether it is enabled by default.
     *
     * If it is not present we need to clear the flag, and if it is
     * not enabled by default we need to change the flag.
     */
    if (!present) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_KVM);
    } else if (!enabled) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_KVM);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_ENABLE_KVM);
    }

    return 0;
}

struct virQEMUCapsCommandLineProps {
    const char *option;
    const char *param;
    int flag;
};

static struct virQEMUCapsCommandLineProps virQEMUCapsCommandLine[] = {
    { "machine", "mem-merge", QEMU_CAPS_MEM_MERGE },
    { "machine", "vmport", QEMU_CAPS_MACHINE_VMPORT_OPT },
    { "drive", "discard", QEMU_CAPS_DRIVE_DISCARD },
    { "drive", "detect-zeroes", QEMU_CAPS_DRIVE_DETECT_ZEROES },
    { "realtime", "mlock", QEMU_CAPS_REALTIME_MLOCK },
    { "boot-opts", "strict", QEMU_CAPS_BOOT_STRICT },
    { "boot-opts", "reboot-timeout", QEMU_CAPS_REBOOT_TIMEOUT },
    { "boot-opts", "splash-time", QEMU_CAPS_SPLASH_TIMEOUT },
    { "spice", "disable-agent-file-xfer", QEMU_CAPS_SPICE_FILE_XFER_DISABLE },
    { "msg", "timestamp", QEMU_CAPS_MSG_TIMESTAMP },
    { "numa", NULL, QEMU_CAPS_NUMA },
    { "drive", "throttling.bps-total-max", QEMU_CAPS_DRIVE_IOTUNE_MAX},
    { "machine", "aes-key-wrap", QEMU_CAPS_AES_KEY_WRAP },
    { "machine", "dea-key-wrap", QEMU_CAPS_DEA_KEY_WRAP },
    { "chardev", "append", QEMU_CAPS_CHARDEV_FILE_APPEND },
    { "spice", "gl", QEMU_CAPS_SPICE_GL },
    { "chardev", "logfile", QEMU_CAPS_CHARDEV_LOGFILE },
    { "name", "debug-threads", QEMU_CAPS_NAME_DEBUG_THREADS },
    { "name", "guest", QEMU_CAPS_NAME_GUEST },
    { "spice", "unix", QEMU_CAPS_SPICE_UNIX },
    { "drive", "throttling.bps-total-max-length", QEMU_CAPS_DRIVE_IOTUNE_MAX_LENGTH },
    { "drive", "throttling.group", QEMU_CAPS_DRIVE_IOTUNE_GROUP },
    { "spice", "rendernode", QEMU_CAPS_SPICE_RENDERNODE },
    { "machine", "kernel_irqchip", QEMU_CAPS_MACHINE_KERNEL_IRQCHIP },
    { "machine", "loadparm", QEMU_CAPS_LOADPARM },
    { "vnc", "vnc", QEMU_CAPS_VNC_MULTI_SERVERS },
};

static int
virQEMUCapsProbeQMPCommandLine(virQEMUCapsPtr qemuCaps,
                               qemuMonitorPtr mon)
{
    bool found = false;
    int nvalues;
    char **values;
    size_t i, j;

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsCommandLine); i++) {
        if ((nvalues = qemuMonitorGetCommandLineOptionParameters(mon,
                                                                 virQEMUCapsCommandLine[i].option,
                                                                 &values,
                                                                 &found)) < 0)
            return -1;

        if (found && !virQEMUCapsCommandLine[i].param)
            virQEMUCapsSet(qemuCaps, virQEMUCapsCommandLine[i].flag);

        for (j = 0; j < nvalues; j++) {
            if (STREQ_NULLABLE(virQEMUCapsCommandLine[i].param, values[j])) {
                virQEMUCapsSet(qemuCaps, virQEMUCapsCommandLine[i].flag);
                break;
            }
        }
        virStringListFree(values);
    }

    return 0;
}

static int
virQEMUCapsProbeQMPMigrationCapabilities(virQEMUCapsPtr qemuCaps,
                                         qemuMonitorPtr mon)
{
    char **caps = NULL;
    int ncaps;

    if ((ncaps = qemuMonitorGetMigrationCapabilities(mon, &caps)) < 0)
        return -1;

    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsMigration),
                                  virQEMUCapsMigration,
                                  ncaps, caps);
    virStringListFreeCount(caps, ncaps);

    return 0;
}

/**
 * virQEMUCapsProbeQMPGICCapabilities:
 * @qemuCaps: QEMU binary capabilities
 * @mon: QEMU monitor
 *
 * Use @mon to obtain information about the GIC capabilities for the
 * corresponding QEMU binary, and store them in @qemuCaps.
 *
 * Returns: 0 on success, <0 on failure
 */
static int
virQEMUCapsProbeQMPGICCapabilities(virQEMUCapsPtr qemuCaps,
                                   qemuMonitorPtr mon)
{
    virGICCapability *caps = NULL;
    int ncaps;

    if ((ncaps = qemuMonitorGetGICCapabilities(mon, &caps)) < 0)
        return -1;

    virQEMUCapsSetGICCapabilities(qemuCaps, caps, ncaps);

    return 0;
}


static bool
virQEMUCapsCPUFilterFeatures(const char *name,
                             void *opaque)
{
    virQEMUCapsPtr qemuCaps = opaque;

    if (!ARCH_IS_X86(qemuCaps->arch))
        return true;

    if (STREQ(name, "cmt") ||
        STREQ(name, "mbm_total") ||
        STREQ(name, "mbm_local"))
        return false;

    return true;
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to using virCapsPtr->host.cpu,
 *         -1 on error.
 */
static int
virQEMUCapsInitCPUModelS390(virQEMUCapsPtr qemuCaps,
                            qemuMonitorCPUModelInfoPtr modelInfo,
                            virCPUDefPtr cpu,
                            bool migratable)
{
    size_t i;

    if (!modelInfo) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing host CPU model info from QEMU capabilities "
                         "for binary %s"),
                       qemuCaps->binary);
        return -1;
    }

    if (VIR_STRDUP(cpu->model, modelInfo->name) < 0 ||
        VIR_ALLOC_N(cpu->features, modelInfo->nprops) < 0)
        return -1;

    cpu->nfeatures_max = modelInfo->nprops;
    cpu->nfeatures = 0;

    for (i = 0; i < modelInfo->nprops; i++) {
        virCPUFeatureDefPtr feature = cpu->features + cpu->nfeatures;
        qemuMonitorCPUPropertyPtr prop = modelInfo->props + i;

        if (prop->type != QEMU_MONITOR_CPU_PROPERTY_BOOLEAN)
            continue;

        if (VIR_STRDUP(feature->name, prop->name) < 0)
            return -1;

        if (!prop->value.boolean ||
            (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO))
            feature->policy = VIR_CPU_FEATURE_DISABLE;
        else
            feature->policy = VIR_CPU_FEATURE_REQUIRE;
        cpu->nfeatures++;
    }

    return 0;
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to using virCapsPtr->host.cpu,
 *         -1 on error.
 */
static int
virQEMUCapsInitCPUModelX86(virQEMUCapsPtr qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfoPtr model,
                           virCPUDefPtr cpu,
                           bool migratable)
{
    virCPUDataPtr data = NULL;
    unsigned long long sigFamily = 0;
    unsigned long long sigModel = 0;
    size_t nmodels = 0;
    char **models = NULL;
    int ret = -1;
    size_t i;

    if (!model)
        return 1;

    if (!(data = virCPUDataNew(VIR_ARCH_X86_64)))
        goto cleanup;

    for (i = 0; i < model->nprops; i++) {
        qemuMonitorCPUPropertyPtr prop = model->props + i;

        switch (prop->type) {
        case QEMU_MONITOR_CPU_PROPERTY_BOOLEAN:
            if (!prop->value.boolean ||
                (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO))
                continue;

            if (virCPUx86DataAddFeature(data, prop->name) < 0)
                goto cleanup;

            break;

        case QEMU_MONITOR_CPU_PROPERTY_STRING:
            if (STREQ(prop->name, "vendor") &&
                virCPUx86DataSetVendor(data, prop->value.string) < 0)
                goto cleanup;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_NUMBER:
            if (STREQ(prop->name, "family"))
                sigFamily = prop->value.number;
            else if (STREQ(prop->name, "model"))
                sigModel = prop->value.number;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_LAST:
            break;
        }
    }

    if (virCPUx86DataSetSignature(data, sigFamily, sigModel) < 0)
        goto cleanup;

    if (virQEMUCapsGetCPUDefinitions(qemuCaps, type, &models, &nmodels) < 0 ||
        cpuDecode(cpu, data, (const char **) models, nmodels, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCPUDataFree(data);
    virStringListFreeCount(models, nmodels);
    return ret;
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to other methods
 *         -1 on error.
 */
int
virQEMUCapsInitCPUModel(virQEMUCapsPtr qemuCaps,
                        virDomainVirtType type,
                        virCPUDefPtr cpu,
                        bool migratable)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);
    int ret = 1;

    if (migratable && cpuData->info && !cpuData->info->migratability)
        return 1;

    if (ARCH_IS_S390(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelS390(qemuCaps, cpuData->info,
                                          cpu, migratable);
    } else if (ARCH_IS_X86(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelX86(qemuCaps, type, cpuData->info,
                                         cpu, migratable);
    }

    if (ret == 0)
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    return ret;
}


static virCPUDefPtr
virQEMUCapsNewHostCPUModel(void)
{
    virCPUDefPtr cpu;

    if (VIR_ALLOC(cpu) < 0)
        return NULL;

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->mode = VIR_CPU_MODE_CUSTOM;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_ALLOW;

    return cpu;
}


void
virQEMUCapsInitHostCPUModel(virQEMUCapsPtr qemuCaps,
                            virArch hostArch,
                            virDomainVirtType type)
{
    virCPUDefPtr cpu = NULL;
    virCPUDefPtr migCPU = NULL;
    virCPUDefPtr hostCPU = NULL;
    virCPUDefPtr fullCPU = NULL;
    size_t i;
    int rc;

    if (!virQEMUCapsGuestIsNative(hostArch, qemuCaps->arch))
        return;

    if (!(cpu = virQEMUCapsNewHostCPUModel()))
        goto error;

    if ((rc = virQEMUCapsInitCPUModel(qemuCaps, type, cpu, false)) < 0) {
        goto error;
    } else if (rc == 1) {
        VIR_DEBUG("No host CPU model info from QEMU; probing host CPU directly");

        hostCPU = virQEMUCapsProbeHostCPUForEmulator(hostArch, qemuCaps, type);
        if (!hostCPU ||
            virCPUDefCopyModelFilter(cpu, hostCPU, true,
                                     virQEMUCapsCPUFilterFeatures,
                                     qemuCaps) < 0)
            goto error;
    } else if (type == VIR_DOMAIN_VIRT_KVM &&
               virCPUGetHostIsSupported(qemuCaps->arch)) {
        if (!(fullCPU = virCPUGetHost(qemuCaps->arch, VIR_CPU_TYPE_GUEST,
                                      NULL, NULL, 0)))
            goto error;

        for (i = 0; i < cpu->nfeatures; i++) {
            if (cpu->features[i].policy == VIR_CPU_FEATURE_REQUIRE &&
                virCPUDefUpdateFeature(fullCPU, cpu->features[i].name,
                                       VIR_CPU_FEATURE_REQUIRE) < 0)
                goto error;
        }
    }

    if (!(migCPU = virQEMUCapsNewHostCPUModel()))
        goto error;

    if ((rc = virQEMUCapsInitCPUModel(qemuCaps, type, migCPU, true)) < 0) {
        goto error;
    } else if (rc == 1) {
        VIR_DEBUG("CPU migratability not provided by QEMU");

        virCPUDefFree(migCPU);
        if (!(migCPU = virCPUCopyMigratable(qemuCaps->arch, cpu)))
            goto error;
    }

    virQEMUCapsSetHostModel(qemuCaps, type, cpu, migCPU, fullCPU);

 cleanup:
    virCPUDefFree(hostCPU);
    return;

 error:
    virCPUDefFree(cpu);
    virCPUDefFree(migCPU);
    virCPUDefFree(fullCPU);
    virResetLastError();
    goto cleanup;
}


void
virQEMUCapsSetCPUModelInfo(virQEMUCapsPtr qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfoPtr modelInfo)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);

    cpuData->info = modelInfo;
}


static int
virQEMUCapsLoadHostCPUModelInfo(virQEMUCapsPtr qemuCaps,
                                xmlXPathContextPtr ctxt,
                                virDomainVirtType virtType)
{
    char *str = NULL;
    xmlNodePtr hostCPUNode;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr oldnode = ctxt->node;
    qemuMonitorCPUModelInfoPtr hostCPU = NULL;
    int ret = -1;
    size_t i;
    int n;
    int val;

    if (virtType == VIR_DOMAIN_VIRT_KVM)
        hostCPUNode = virXPathNode("./hostCPU[@type='kvm']", ctxt);
    else
        hostCPUNode = virXPathNode("./hostCPU[@type='tcg']", ctxt);

    if (!hostCPUNode) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC(hostCPU) < 0)
        goto cleanup;

    if (!(hostCPU->name = virXMLPropString(hostCPUNode, "model"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing host CPU model name in QEMU "
                         "capabilities cache"));
        goto cleanup;
    }

    if (!(str = virXMLPropString(hostCPUNode, "migratability")) ||
        (val = virTristateBoolTypeFromString(str)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid migratability value for host CPU model"));
        goto cleanup;
    }
    hostCPU->migratability = val == VIR_TRISTATE_BOOL_YES;
    VIR_FREE(str);

    ctxt->node = hostCPUNode;

    if ((n = virXPathNodeSet("./property", ctxt, &nodes)) > 0) {
        if (VIR_ALLOC_N(hostCPU->props, n) < 0)
            goto cleanup;

        hostCPU->nprops = n;

        for (i = 0; i < n; i++) {
            qemuMonitorCPUPropertyPtr prop = hostCPU->props + i;

            ctxt->node = nodes[i];

            if (!(prop->name = virXMLPropString(ctxt->node, "name"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing 'name' attribute for a host CPU"
                                 " model property in QEMU capabilities cache"));
                goto cleanup;
            }

            if (!(str = virXMLPropString(ctxt->node, "type")) ||
                (val = qemuMonitorCPUPropertyTypeFromString(str)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing or invalid CPU model property type "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            VIR_FREE(str);

            prop->type = val;
            switch (prop->type) {
            case QEMU_MONITOR_CPU_PROPERTY_BOOLEAN:
                if (virXPathBoolean("./@value='true'", ctxt))
                    prop->value.boolean = true;
                break;

            case QEMU_MONITOR_CPU_PROPERTY_STRING:
                prop->value.string = virXMLPropString(ctxt->node, "value");
                if (!prop->value.string) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("invalid string value for '%s' host CPU "
                                     "model property in QEMU capabilities cache"),
                                   prop->name);
                    goto cleanup;
                }
                break;

            case QEMU_MONITOR_CPU_PROPERTY_NUMBER:
                if (virXPathLongLong("string(./@value)", ctxt,
                                     &prop->value.number) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("invalid number value for '%s' host CPU "
                                     "model property in QEMU capabilities cache"),
                                   prop->name);
                    goto cleanup;
                }
                break;

            case QEMU_MONITOR_CPU_PROPERTY_LAST:
                break;
            }

            if ((str = virXMLPropString(ctxt->node, "migratable"))) {
                if ((val = virTristateBoolTypeFromString(str)) <= 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unknown migratable value for '%s' host "
                                     "CPU model property"),
                                   prop->name);
                    goto cleanup;
                }

                prop->migratable = val;
                VIR_FREE(str);
            }
        }
    }

    virQEMUCapsSetCPUModelInfo(qemuCaps, virtType, hostCPU);
    hostCPU = NULL;
    ret = 0;

 cleanup:
    ctxt->node = oldnode;
    VIR_FREE(str);
    VIR_FREE(nodes);
    qemuMonitorCPUModelInfoFree(hostCPU);
    return ret;
}


static int
virQEMUCapsLoadCPUModels(virQEMUCapsPtr qemuCaps,
                         xmlXPathContextPtr ctxt,
                         virDomainVirtType type)
{
    virDomainCapsCPUModelsPtr cpus = NULL;
    xmlNodePtr *nodes = NULL;
    char *str = NULL;
    size_t i;
    int n;
    int ret = -1;

    if (type == VIR_DOMAIN_VIRT_KVM)
        n = virXPathNodeSet("./cpu[@type='kvm']", ctxt, &nodes);
    else
        n = virXPathNodeSet("./cpu[@type='tcg']", ctxt, &nodes);

    if (n < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities cpus"));
        goto cleanup;
    }

    if (n == 0) {
        ret = 0;
        goto cleanup;
    }

    if (!(cpus = virDomainCapsCPUModelsNew(n)))
        goto cleanup;

    if (type == VIR_DOMAIN_VIRT_KVM)
        qemuCaps->kvmCPUModels = cpus;
    else
        qemuCaps->tcgCPUModels = cpus;

    for (i = 0; i < n; i++) {
        int usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;

        if ((str = virXMLPropString(nodes[i], "usable")) &&
            (usable = virDomainCapsCPUUsableTypeFromString(str)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown value '%s' in attribute 'usable'"), str);
            goto cleanup;
        }
        VIR_FREE(str);

        if (!(str = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing cpu name in QEMU capabilities cache"));
            goto cleanup;
        }

        if (virDomainCapsCPUModelsAddSteal(cpus, &str, usable) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(str);
    return ret;
}


struct _virQEMUCapsCachePriv {
    char *libDir;
    uid_t runUid;
    gid_t runGid;
    virArch hostArch;
};
typedef struct _virQEMUCapsCachePriv virQEMUCapsCachePriv;
typedef virQEMUCapsCachePriv *virQEMUCapsCachePrivPtr;


static void
virQEMUCapsCachePrivFree(void *privData)
{
    virQEMUCapsCachePrivPtr priv = privData;

    VIR_FREE(priv->libDir);
    VIR_FREE(priv);
}


/*
 * Parsing a doc that looks like
 *
 * <qemuCaps>
 *   <qemuctime>234235253</qemuctime>
 *   <selfctime>234235253</selfctime>
 *   <selfvers>1002016</selfvers>
 *   <usedQMP/>
 *   <flag name='foo'/>
 *   <flag name='bar'/>
 *   ...
 *   <cpu name="pentium3"/>
 *   ...
 *   <machine name="pc-1.0" alias="pc" hotplugCpus='yes' maxCpus="4"/>
 *   ...
 * </qemuCaps>
 */
int
virQEMUCapsLoadCache(virArch hostArch,
                     virQEMUCapsPtr qemuCaps,
                     const char *filename)
{
    xmlDocPtr doc = NULL;
    int ret = -1;
    size_t i;
    int n;
    xmlNodePtr *nodes = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *str = NULL;
    long long int l;
    unsigned long lu;

    if (!(doc = virXMLParseFile(filename)))
        goto cleanup;

    if (!(ctxt = xmlXPathNewContext(doc))) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = xmlDocGetRootElement(doc);

    if (STRNEQ((const char *)ctxt->node->name, "qemuCaps")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <qemuCaps>"),
                       ctxt->node->name);
        goto cleanup;
    }

    if (virXPathLongLong("string(./qemuctime)", ctxt, &l) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing qemuctime in QEMU capabilities XML"));
        goto cleanup;
    }
    qemuCaps->ctime = (time_t)l;

    if (virXPathLongLong("string(./selfctime)", ctxt, &l) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing selfctime in QEMU capabilities XML"));
        goto cleanup;
    }
    qemuCaps->libvirtCtime = (time_t)l;

    qemuCaps->libvirtVersion = 0;
    if (virXPathULong("string(./selfvers)", ctxt, &lu) == 0)
        qemuCaps->libvirtVersion = lu;

    qemuCaps->usedQMP = virXPathBoolean("count(./usedQMP) > 0",
                                        ctxt) > 0;

    if ((n = virXPathNodeSet("./flag", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities flags"));
        goto cleanup;
    }
    VIR_DEBUG("Got flags %d", n);
    for (i = 0; i < n; i++) {
        int flag;
        if (!(str = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing flag name in QEMU capabilities cache"));
            goto cleanup;
        }
        flag = virQEMUCapsTypeFromString(str);
        if (flag < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown qemu capabilities flag %s"), str);
            goto cleanup;
        }
        VIR_FREE(str);
        virQEMUCapsSet(qemuCaps, flag);
    }
    VIR_FREE(nodes);

    if (virXPathUInt("string(./version)", ctxt, &qemuCaps->version) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing version in QEMU capabilities cache"));
        goto cleanup;
    }

    if (virXPathUInt("string(./kvmVersion)", ctxt, &qemuCaps->kvmVersion) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing version in QEMU capabilities cache"));
        goto cleanup;
    }

    if (virXPathBoolean("boolean(./package)", ctxt) > 0) {
        qemuCaps->package = virXPathString("string(./package)", ctxt);
        if (!qemuCaps->package &&
            VIR_STRDUP(qemuCaps->package, "") < 0)
            goto cleanup;
    }

    if (!(str = virXPathString("string(./arch)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing arch in QEMU capabilities cache"));
        goto cleanup;
    }
    if (!(qemuCaps->arch = virArchFromString(str))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown arch %s in QEMU capabilities cache"), str);
        goto cleanup;
    }
    VIR_FREE(str);

    if (virQEMUCapsLoadHostCPUModelInfo(qemuCaps, ctxt, VIR_DOMAIN_VIRT_KVM) < 0 ||
        virQEMUCapsLoadHostCPUModelInfo(qemuCaps, ctxt, VIR_DOMAIN_VIRT_QEMU) < 0)
        goto cleanup;

    if (virQEMUCapsLoadCPUModels(qemuCaps, ctxt, VIR_DOMAIN_VIRT_KVM) < 0 ||
        virQEMUCapsLoadCPUModels(qemuCaps, ctxt, VIR_DOMAIN_VIRT_QEMU) < 0)
        goto cleanup;

    if ((n = virXPathNodeSet("./machine", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities machines"));
        goto cleanup;
    }
    if (n > 0) {
        qemuCaps->nmachineTypes = n;
        if (VIR_ALLOC_N(qemuCaps->machineTypes, qemuCaps->nmachineTypes) < 0)
            goto cleanup;

        for (i = 0; i < n; i++) {
            if (!(qemuCaps->machineTypes[i].name = virXMLPropString(nodes[i], "name"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing machine name in QEMU capabilities cache"));
                goto cleanup;
            }
            qemuCaps->machineTypes[i].alias = virXMLPropString(nodes[i], "alias");

            str = virXMLPropString(nodes[i], "maxCpus");
            if (str &&
                virStrToLong_ui(str, NULL, 10, &(qemuCaps->machineTypes[i].maxCpus)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed machine cpu count in QEMU capabilities cache"));
                goto cleanup;
            }
            VIR_FREE(str);

            str = virXMLPropString(nodes[i], "hotplugCpus");
            if (STREQ_NULLABLE(str, "yes"))
                qemuCaps->machineTypes[i].hotplugCpus = true;
            VIR_FREE(str);
        }
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./gic", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities gic"));
        goto cleanup;
    }
    if (n > 0) {
        unsigned int uintValue;
        bool boolValue;

        qemuCaps->ngicCapabilities = n;
        if (VIR_ALLOC_N(qemuCaps->gicCapabilities, n) < 0)
            goto cleanup;

        for (i = 0; i < n; i++) {
            virGICCapabilityPtr cap = &qemuCaps->gicCapabilities[i];

            if (!(str = virXMLPropString(nodes[i], "version"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing GIC version "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            if (virStrToLong_ui(str, NULL, 10, &uintValue) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed GIC version "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            cap->version = uintValue;
            VIR_FREE(str);

            if (!(str = virXMLPropString(nodes[i], "kernel"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing in-kernel GIC information "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            if (!(boolValue = STREQ(str, "yes")) && STRNEQ(str, "no")) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed in-kernel GIC information "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            if (boolValue)
                cap->implementation |= VIR_GIC_IMPLEMENTATION_KERNEL;
            VIR_FREE(str);

            if (!(str = virXMLPropString(nodes[i], "emulated"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing emulated GIC information "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            if (!(boolValue = STREQ(str, "yes")) && STRNEQ(str, "no")) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed emulated GIC information "
                                 "in QEMU capabilities cache"));
                goto cleanup;
            }
            if (boolValue)
                cap->implementation |= VIR_GIC_IMPLEMENTATION_EMULATED;
            VIR_FREE(str);
        }
    }
    VIR_FREE(nodes);

    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_QEMU);

    ret = 0;
 cleanup:
    VIR_FREE(str);
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return ret;
}


static void
virQEMUCapsFormatHostCPUModelInfo(virQEMUCapsPtr qemuCaps,
                                  virBufferPtr buf,
                                  virDomainVirtType type)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);
    qemuMonitorCPUModelInfoPtr model = cpuData->info;
    const char *typeStr = type == VIR_DOMAIN_VIRT_KVM ? "kvm" : "tcg";
    size_t i;

    if (!model)
        return;

    virBufferAsprintf(buf,
                      "<hostCPU type='%s' model='%s' migratability='%s'>\n",
                      typeStr, model->name,
                      model->migratability ? "yes" : "no");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < model->nprops; i++) {
        qemuMonitorCPUPropertyPtr prop = model->props + i;

        virBufferAsprintf(buf, "<property name='%s' type='%s' ",
                          prop->name,
                          qemuMonitorCPUPropertyTypeToString(prop->type));

        switch (prop->type) {
        case QEMU_MONITOR_CPU_PROPERTY_BOOLEAN:
            virBufferAsprintf(buf, "value='%s'",
                              prop->value.boolean ? "true" : "false");
            break;

        case QEMU_MONITOR_CPU_PROPERTY_STRING:
            virBufferEscapeString(buf, "value='%s'", prop->value.string);
            break;

        case QEMU_MONITOR_CPU_PROPERTY_NUMBER:
            virBufferAsprintf(buf, "value='%lld'", prop->value.number);
            break;

        case QEMU_MONITOR_CPU_PROPERTY_LAST:
            break;
        }

        if (prop->migratable > 0)
            virBufferAsprintf(buf, " migratable='%s'",
                              virTristateBoolTypeToString(prop->migratable));

        virBufferAddLit(buf, "/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</hostCPU>\n");
}


static void
virQEMUCapsFormatCPUModels(virQEMUCapsPtr qemuCaps,
                           virBufferPtr buf,
                           virDomainVirtType type)
{
    virDomainCapsCPUModelsPtr cpus;
    const char *typeStr;
    size_t i;

    if (type == VIR_DOMAIN_VIRT_KVM) {
        typeStr = "kvm";
        cpus = qemuCaps->kvmCPUModels;
    } else {
        typeStr = "tcg";
        cpus = qemuCaps->tcgCPUModels;
    }

    if (!cpus)
        return;

    for (i = 0; i < cpus->nmodels; i++) {
        virDomainCapsCPUModelPtr cpu = cpus->models + i;

        virBufferAsprintf(buf, "<cpu type='%s' ", typeStr);
        virBufferEscapeString(buf, "name='%s'", cpu->name);
        if (cpu->usable) {
            virBufferAsprintf(buf, " usable='%s'",
                              virDomainCapsCPUUsableTypeToString(cpu->usable));
        }
        virBufferAddLit(buf, "/>\n");
    }
}


char *
virQEMUCapsFormatCache(virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;
    size_t i;

    virBufferAddLit(&buf, "<qemuCaps>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferAsprintf(&buf, "<qemuctime>%llu</qemuctime>\n",
                      (long long) qemuCaps->ctime);
    virBufferAsprintf(&buf, "<selfctime>%llu</selfctime>\n",
                      (long long) qemuCaps->libvirtCtime);
    virBufferAsprintf(&buf, "<selfvers>%lu</selfvers>\n",
                      (unsigned long) qemuCaps->libvirtVersion);

    if (qemuCaps->usedQMP)
        virBufferAddLit(&buf, "<usedQMP/>\n");

    for (i = 0; i < QEMU_CAPS_LAST; i++) {
        if (virQEMUCapsGet(qemuCaps, i)) {
            virBufferAsprintf(&buf, "<flag name='%s'/>\n",
                              virQEMUCapsTypeToString(i));
        }
    }

    virBufferAsprintf(&buf, "<version>%d</version>\n",
                      qemuCaps->version);

    virBufferAsprintf(&buf, "<kvmVersion>%d</kvmVersion>\n",
                      qemuCaps->kvmVersion);

    if (qemuCaps->package)
        virBufferAsprintf(&buf, "<package>%s</package>\n",
                          qemuCaps->package);

    virBufferAsprintf(&buf, "<arch>%s</arch>\n",
                      virArchToString(qemuCaps->arch));

    virQEMUCapsFormatHostCPUModelInfo(qemuCaps, &buf, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsFormatHostCPUModelInfo(qemuCaps, &buf, VIR_DOMAIN_VIRT_QEMU);

    virQEMUCapsFormatCPUModels(qemuCaps, &buf, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsFormatCPUModels(qemuCaps, &buf, VIR_DOMAIN_VIRT_QEMU);

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        virBufferEscapeString(&buf, "<machine name='%s'",
                              qemuCaps->machineTypes[i].name);
        if (qemuCaps->machineTypes[i].alias)
            virBufferEscapeString(&buf, " alias='%s'",
                              qemuCaps->machineTypes[i].alias);
        if (qemuCaps->machineTypes[i].hotplugCpus)
            virBufferAddLit(&buf, " hotplugCpus='yes'");
        virBufferAsprintf(&buf, " maxCpus='%u'/>\n",
                          qemuCaps->machineTypes[i].maxCpus);
    }

    for (i = 0; i < qemuCaps->ngicCapabilities; i++) {
        virGICCapabilityPtr cap;
        bool kernel;
        bool emulated;

        cap = &qemuCaps->gicCapabilities[i];
        kernel = (cap->implementation & VIR_GIC_IMPLEMENTATION_KERNEL);
        emulated = (cap->implementation & VIR_GIC_IMPLEMENTATION_EMULATED);

        virBufferAsprintf(&buf,
                          "<gic version='%d' kernel='%s' emulated='%s'/>\n",
                          cap->version,
                          kernel ? "yes" : "no",
                          emulated ? "yes" : "no");
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</qemuCaps>\n");

    if (virBufferCheckError(&buf) == 0)
        ret = virBufferContentAndReset(&buf);

    return ret;
}


static int
virQEMUCapsSaveFile(void *data,
                    const char *filename,
                    void *privData ATTRIBUTE_UNUSED)
{
    virQEMUCapsPtr qemuCaps = data;
    char *xml = NULL;
    int ret = -1;

    xml = virQEMUCapsFormatCache(qemuCaps);

    if (virFileWriteStr(filename, xml, 0600) < 0) {
        virReportSystemError(errno,
                             _("Failed to save '%s' for '%s'"),
                             filename, qemuCaps->binary);
        goto cleanup;
    }

    VIR_DEBUG("Saved caps '%s' for '%s' with (%lld, %lld)",
              filename, qemuCaps->binary,
              (long long)qemuCaps->ctime,
              (long long)qemuCaps->libvirtCtime);

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


static bool
virQEMUCapsIsValid(void *data,
                   void *privData)
{
    virQEMUCapsPtr qemuCaps = data;
    virQEMUCapsCachePrivPtr priv = privData;
    bool kvmUsable;
    struct stat sb;

    if (!qemuCaps->binary)
        return true;

    if (qemuCaps->libvirtCtime != virGetSelfLastChanged() ||
        qemuCaps->libvirtVersion != LIBVIR_VERSION_NUMBER) {
        VIR_DEBUG("Outdated capabilities for '%s': libvirt changed "
                  "(%lld vs %lld, %lu vs %lu)",
                  qemuCaps->binary,
                  (long long)qemuCaps->libvirtCtime,
                  (long long)virGetSelfLastChanged(),
                  (unsigned long)qemuCaps->libvirtVersion,
                  (unsigned long)LIBVIR_VERSION_NUMBER);
        return false;
    }

    if (stat(qemuCaps->binary, &sb) < 0) {
        char ebuf[1024];
        VIR_DEBUG("Failed to stat QEMU binary '%s': %s",
                  qemuCaps->binary,
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        return false;
    }

    if (sb.st_ctime != qemuCaps->ctime) {
        VIR_DEBUG("Outdated capabilities for '%s': QEMU binary changed "
                  "(%lld vs %lld)",
                  qemuCaps->binary,
                  (long long) sb.st_ctime, (long long) qemuCaps->ctime);
        return false;
    }

    kvmUsable = virFileAccessibleAs("/dev/kvm", R_OK | W_OK,
                                    priv->runUid, priv->runGid) == 0;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_ENABLE_KVM) &&
        kvmUsable) {
        VIR_DEBUG("KVM was not enabled when probing '%s', "
                  "but it should be usable now",
                  qemuCaps->binary);
        return false;
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
        !kvmUsable) {
        VIR_DEBUG("KVM was enabled when probing '%s', "
                  "but it is not available now",
                  qemuCaps->binary);
        return false;
    }

    return true;
}


#define QEMU_SYSTEM_PREFIX "qemu-system-"

static int
virQEMUCapsInitHelp(virQEMUCapsPtr qemuCaps, uid_t runUid, gid_t runGid, const char *qmperr)
{
    virCommandPtr cmd = NULL;
    bool is_kvm;
    char *help = NULL;
    int ret = -1;
    const char *tmp;

    VIR_DEBUG("qemuCaps=%p", qemuCaps);

    tmp = strstr(qemuCaps->binary, QEMU_SYSTEM_PREFIX);
    if (tmp) {
        tmp += strlen(QEMU_SYSTEM_PREFIX);

        qemuCaps->arch = virQEMUCapsArchFromString(tmp);
    } else {
        qemuCaps->arch = virArchFromHost();
    }

    cmd = virQEMUCapsProbeCommand(qemuCaps->binary, NULL, runUid, runGid);
    virCommandAddArgList(cmd, "-help", NULL);
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virQEMUCapsParseHelpStr(qemuCaps->binary,
                                help, qemuCaps,
                                &qemuCaps->version,
                                &is_kvm,
                                &qemuCaps->kvmVersion,
                                false,
                                qmperr) < 0)
        goto cleanup;

    /* Older QEMU versions reported -no-acpi in the output of -help even
     * though it was not supported by the architecture. The issue has since
     * been fixed, but to maintain compatibility with all release we still
     * need to filter out the capability for architectures that we know
     * don't support the feature, eg. anything but x86 and aarch64 */
    if (!ARCH_IS_X86(qemuCaps->arch) &&
        qemuCaps->arch != VIR_ARCH_AARCH64) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_NO_ACPI);
    }

    /* virQEMUCapsExtractDeviceStr will only set additional caps if qemu
     * understands the 0.13.0+ notion of "-device driver,".  */
    if (strstr(help, "-device driver,?") &&
        virQEMUCapsExtractDeviceStr(qemuCaps->binary,
                                    qemuCaps, runUid, runGid) < 0) {
        goto cleanup;
    }

    if (virQEMUCapsProbeCPUModels(qemuCaps, runUid, runGid) < 0)
        goto cleanup;

    if (virQEMUCapsProbeMachineTypes(qemuCaps, runUid, runGid) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    VIR_FREE(help);
    return ret;
}


static void virQEMUCapsMonitorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                     virDomainObjPtr vm ATTRIBUTE_UNUSED,
                                     void *opaque ATTRIBUTE_UNUSED)
{
}

static qemuMonitorCallbacks callbacks = {
    .eofNotify = virQEMUCapsMonitorNotify,
    .errorNotify = virQEMUCapsMonitorNotify,
};


/* Capabilities that we assume are always enabled
 * for QEMU >= 1.2.0
 */
static void
virQEMUCapsInitQMPBasic(virQEMUCapsPtr qemuCaps)
{
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_MEM_PATH);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_SERIAL);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_MONITOR_JSON);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_SDL);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_RTC);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_VHOST_NET);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NODEFCONFIG);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_BOOT_MENU);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NAME_PROCESS);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_SMBIOS_TYPE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_VGA_NONE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_AIO);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEVMC);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_SHUTDOWN);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_UNSAFE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV_READONLY);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_COPY_ON_READ);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_FSDEV_WRITEOUT);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DRIVE_IOTUNE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_WAKEUP);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_USER_CONFIG);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_NETDEV_BRIDGE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_SECCOMP_SANDBOX);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DTB);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_IPV6_MIGRATION);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_OPT);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DUMP_GUEST_CORE);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_VNC_SHARE_POLICY);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_HOST_PCI_MULTIDOMAIN);
    virQEMUCapsSet(qemuCaps, QEMU_CAPS_DISPLAY);
}


/**
 * virQEMUCapsInitQMPArch:
 * @qemuCaps: QEMU capabilities
 * @mon: QEMU monitor
 *
 * Initialize the architecture for @qemuCaps by asking @mon.
 *
 * Returns: 0 on success, <0 on failure
 */
static int
virQEMUCapsInitQMPArch(virQEMUCapsPtr qemuCaps,
                            qemuMonitorPtr mon)
{
    char *archstr = NULL;
    int ret = -1;

    if (!(archstr = qemuMonitorGetTargetArch(mon)))
        goto cleanup;

    if ((qemuCaps->arch = virQEMUCapsArchFromString(archstr)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown QEMU arch %s"), archstr);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(archstr);
    return ret;
}


/**
 * virQEMUCapsInitQMPBasicArch:
 * @qemuCaps: QEMU capabilities
 *
 * Initialize @qemuCaps with basic architecture-dependent capabilities.
 */
void
virQEMUCapsInitQMPBasicArch(virQEMUCapsPtr qemuCaps)
{
    /* ACPI only works on x86 and aarch64 */
    if (ARCH_IS_X86(qemuCaps->arch) ||
        qemuCaps->arch == VIR_ARCH_AARCH64) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_ACPI);
    }

    /* HPET and KVM PIT are x86 specific */
    if (ARCH_IS_X86(qemuCaps->arch)) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_HPET);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_KVM_PIT);
    }
}


/**
 * virQEMUCapsQMPSchemaObjectGetType:
 * @field: name of the object containing the requested type
 * @name: name of the requested type
 * @namefield: name of the object property holding @name
 *
 * Helper that selects the type of a QMP schema object member or it's variant
 * member. Returns the type string on success or NULL on error.
 */
static const char *
virQEMUCapsQMPSchemaObjectGetType(const char *field,
                                  const char *name,
                                  const char *namefield,
                                  virJSONValuePtr elem)
{
    virJSONValuePtr arr;
    virJSONValuePtr cur;
    const char *curname;
    const char *type;
    size_t i;

    if (!(arr = virJSONValueObjectGetArray(elem, field)))
        return NULL;

    for (i = 0; i < virJSONValueArraySize(arr); i++) {
        if (!(cur = virJSONValueArrayGet(arr, i)) ||
            !(curname = virJSONValueObjectGetString(cur, namefield)) ||
            !(type = virJSONValueObjectGetString(cur, "type")))
            continue;

        if (STREQ(name, curname))
            return type;
    }

    return NULL;
}


static virJSONValuePtr
virQEMUCapsQMPSchemaTraverse(const char *baseName,
                             char **query,
                             virHashTablePtr schema)
{
    virJSONValuePtr base;
    const char *metatype;

    do {
        if (!(base = virHashLookup(schema, baseName)))
            return NULL;

        if (!*query)
            return base;

        if (!(metatype = virJSONValueObjectGetString(base, "meta-type")))
            return NULL;

        /* flatten arrays by default */
        if (STREQ(metatype, "array")) {
            if (!(baseName = virJSONValueObjectGetString(base, "element-type")))
                return NULL;

            continue;
        } else if (STREQ(metatype, "object")) {
            if (**query == '+')
                baseName = virQEMUCapsQMPSchemaObjectGetType("variants",
                                                             *query + 1,
                                                             "case", base);
            else
                baseName = virQEMUCapsQMPSchemaObjectGetType("members",
                                                             *query,
                                                             "name", base);

            if (!baseName)
                return NULL;
        } else if (STREQ(metatype, "command") ||
                   STREQ(metatype, "event")) {
            if (!(baseName = virJSONValueObjectGetString(base, *query)))
                return NULL;
        } else {
            /* alternates, basic types and enums can't be entered */
            return NULL;
        }

        query++;
    } while (*query);

    return base;
}


/**
 * virQEMUCapsQMPSchemaGetByPath:
 * @query: string specifying the required data type (see below)
 * @schema: hash table containing the schema data
 * @entry: filled with the located schema object requested by @query
 *
 * Retrieves the requested schema entry specified by @query to @entry. The
 * @query parameter has the following syntax which is very closely tied to the
 * qemu schema syntax entries separated by slashes with a few special characters:
 *
 * "command_or_event/attribute/subattribute/+variant_discriminator/subattribute"
 *
 * command_or_event: name of the event or attribute to introspect
 * attribute: selects whether arguments or return type should be introspected
 *            ("arg-type" or "ret-type" for commands, "arg-type" for events)
 * subattribute: specifies member name of object types
 * +variant_discriminator: In the case of unionized objects, select a
 *                         specific case to introspect.
 *
 * Array types are automatically flattened to the singular type. Alternate
 * types are currently not supported.
 *
 * The above types can be chained arbitrarily using slashes to construct any
 * path into the schema tree.
 *
 * Returns 0 on success (including if the requested schema was not found) and
 * fills @entry appropriately. On failure returns -1 and sets an appropriate
 * error message.
 */
static int
virQEMUCapsQMPSchemaGetByPath(const char *query,
                              virHashTablePtr schema,
                              virJSONValuePtr *entry)
{
    char **elems = NULL;

    *entry = NULL;

    if (!(elems = virStringSplit(query, "/", 0)))
        return -1;

    if (!*elems) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("malformed query string"));
        virStringListFree(elems);
        return -1;
    }

    *entry = virQEMUCapsQMPSchemaTraverse(*elems, elems + 1, schema);

    virStringListFree(elems);
    return 0;
}


static bool
virQEMUCapsQMPSchemaQueryPath(const char *query,
                              virHashTablePtr schema)
{
    virJSONValuePtr entry;

    if (virQEMUCapsQMPSchemaGetByPath(query, schema, &entry))
        return false;

    return !!entry;
}


static int
virQEMUCapsProbeQMPSchemaCapabilities(virQEMUCapsPtr qemuCaps,
                                      qemuMonitorPtr mon)
{
    struct virQEMUCapsStringFlags *entry;
    virHashTablePtr schema;
    size_t i;

    if (!(schema = qemuMonitorQueryQMPSchema(mon)))
        return -1;

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsQMPSchemaQueries); i++) {
        entry = virQEMUCapsQMPSchemaQueries + i;

        if (virQEMUCapsQMPSchemaQueryPath(entry->value, schema))
            virQEMUCapsSet(qemuCaps, entry->flag);
    }

    virHashFree(schema);
    return 0;
}


int
virQEMUCapsInitQMPMonitor(virQEMUCapsPtr qemuCaps,
                          qemuMonitorPtr mon)
{
    int ret = -1;
    int major, minor, micro;
    char *package = NULL;

    /* @mon is supposed to be locked by callee */

    if (qemuMonitorSetCapabilities(mon) < 0) {
        VIR_DEBUG("Failed to set monitor capabilities %s",
                  virGetLastErrorMessage());
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorGetVersion(mon,
                              &major, &minor, &micro,
                              &package) < 0) {
        VIR_DEBUG("Failed to query monitor version %s",
                  virGetLastErrorMessage());
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Got version %d.%d.%d (%s)",
              major, minor, micro, NULLSTR(package));

    if (major < 1 || (major == 1 && minor < 2)) {
        VIR_DEBUG("Not new enough for QMP capabilities detection");
        ret = 0;
        goto cleanup;
    }

    qemuCaps->version = major * 1000000 + minor * 1000 + micro;
    qemuCaps->package = package;
    qemuCaps->usedQMP = true;

    virQEMUCapsInitQMPBasic(qemuCaps);

    if (virQEMUCapsInitQMPArch(qemuCaps, mon) < 0)
        goto cleanup;

    virQEMUCapsInitQMPBasicArch(qemuCaps);

    /* USB option is supported v1.3.0 onwards */
    if (qemuCaps->version >= 1003000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_USB_OPT);

    /* WebSockets were introduced between 1.3.0 and 1.3.1 */
    if (qemuCaps->version >= 1003001)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VNC_WEBSOCKET);

    /* -chardev spiceport is supported from 1.4.0, but usable through
     * qapi only since 1.5.0, however, it still cannot be queried
     * for as a capability */
    if (qemuCaps->version >= 1005000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEPORT);

    if (qemuCaps->version >= 1006000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);

    /* vmport option is supported v2.2.0 onwards */
    if (qemuCaps->version >= 2002000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_VMPORT_OPT);

    /* -cpu ...,aarch64=off supported in v2.3.0 and onwards. But it
       isn't detectable via qmp at this point */
    if (qemuCaps->arch == VIR_ARCH_AARCH64 &&
        qemuCaps->version >= 2003000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_AARCH64_OFF);

    /* vhost-user supports multi-queue from v2.4.0 onwards,
     * but there is no way to query for that capability */
    if (qemuCaps->version >= 2004000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VHOSTUSER_MULTIQUEUE);

    /* smm option is supported from v2.4.0 */
    if (qemuCaps->version >= 2004000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_SMM_OPT);

    /* Since 2.4.50 ARM virt machine supports gic-version option */
    if (qemuCaps->version >= 2004050)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACH_VIRT_GIC_VERSION);

    /* no way to query if -machine kernel_irqchip supports split */
    if (qemuCaps->version >= 2006000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT);

    if (virQEMUCapsProbeQMPCommands(qemuCaps, mon) < 0)
        goto cleanup;

    /* Some capabilities may differ depending on KVM state */
    if (virQEMUCapsProbeQMPKVMState(qemuCaps, mon) < 0)
        goto cleanup;

    if (virQEMUCapsProbeQMPEvents(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPObjects(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPMachineTypes(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, mon, false) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPTPM(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPCommandLine(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPMigrationCapabilities(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_QMP_SCHEMA) &&
        virQEMUCapsProbeQMPSchemaCapabilities(qemuCaps, mon) < 0)
        goto cleanup;
    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, mon, false) < 0)
        goto cleanup;

    /* 'intel-iommu' shows up as a device since 2.2.0, but can
     * not be used with -device until 2.7.0. Before that it
     * requires -machine iommu=on. So we must clear the device
     * capability we detected on older QEMUs
     */
    if (qemuCaps->version < 2007000 &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_INTEL_IOMMU)) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_INTEL_IOMMU);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_IOMMU);
    }

    /* GIC capabilities, eg. available GIC versions */
    if ((qemuCaps->arch == VIR_ARCH_AARCH64 ||
         qemuCaps->arch == VIR_ARCH_ARMV7L) &&
        virQEMUCapsProbeQMPGICCapabilities(qemuCaps, mon) < 0)
        goto cleanup;

    /* Prealloc on NVDIMMs is broken on older QEMUs leading to
     * user data corruption. If we are dealing with such version
     * of QEMU pretend we don't know how to NVDIMM. */
    if (qemuCaps->version < 2009000 &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM);

    if (ARCH_IS_X86(qemuCaps->arch) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_CACHE);

    ret = 0;
 cleanup:
    return ret;
}


int
virQEMUCapsInitQMPMonitorTCG(virQEMUCapsPtr qemuCaps ATTRIBUTE_UNUSED,
                             qemuMonitorPtr mon)
{
    int ret = -1;

    if (qemuMonitorSetCapabilities(mon) < 0) {
        VIR_DEBUG("Failed to set monitor capabilities %s",
                  virGetLastErrorMessage());
        ret = 0;
        goto cleanup;
    }

    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, mon, true) < 0)
        goto cleanup;

    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, mon, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}


typedef struct _virQEMUCapsInitQMPCommand virQEMUCapsInitQMPCommand;
typedef virQEMUCapsInitQMPCommand *virQEMUCapsInitQMPCommandPtr;
struct _virQEMUCapsInitQMPCommand {
    char *binary;
    uid_t runUid;
    gid_t runGid;
    char **qmperr;
    char *monarg;
    char *monpath;
    char *pidfile;
    virCommandPtr cmd;
    qemuMonitorPtr mon;
    virDomainChrSourceDef config;
    pid_t pid;
    virDomainObjPtr vm;
};


static void
virQEMUCapsInitQMPCommandAbort(virQEMUCapsInitQMPCommandPtr cmd)
{
    if (cmd->mon)
        virObjectUnlock(cmd->mon);
    qemuMonitorClose(cmd->mon);
    cmd->mon = NULL;

    virCommandAbort(cmd->cmd);
    virCommandFree(cmd->cmd);
    cmd->cmd = NULL;

    if (cmd->monpath)
        ignore_value(unlink(cmd->monpath));

    virDomainObjEndAPI(&cmd->vm);

    if (cmd->pid != 0) {
        char ebuf[1024];

        VIR_DEBUG("Killing QMP caps process %lld", (long long) cmd->pid);
        if (virProcessKill(cmd->pid, SIGKILL) < 0 && errno != ESRCH)
            VIR_ERROR(_("Failed to kill process %lld: %s"),
                      (long long) cmd->pid,
                      virStrerror(errno, ebuf, sizeof(ebuf)));

        VIR_FREE(*cmd->qmperr);
    }
    if (cmd->pidfile)
        unlink(cmd->pidfile);
    cmd->pid = 0;
}


static void
virQEMUCapsInitQMPCommandFree(virQEMUCapsInitQMPCommandPtr cmd)
{
    if (!cmd)
        return;

    virQEMUCapsInitQMPCommandAbort(cmd);
    VIR_FREE(cmd->binary);
    VIR_FREE(cmd->monpath);
    VIR_FREE(cmd->monarg);
    VIR_FREE(cmd->pidfile);
    VIR_FREE(cmd);
}


static virQEMUCapsInitQMPCommandPtr
virQEMUCapsInitQMPCommandNew(char *binary,
                             const char *libDir,
                             uid_t runUid,
                             gid_t runGid,
                             char **qmperr)
{
    virQEMUCapsInitQMPCommandPtr cmd = NULL;

    if (VIR_ALLOC(cmd) < 0)
        goto error;

    if (VIR_STRDUP(cmd->binary, binary) < 0)
        goto error;

    cmd->runUid = runUid;
    cmd->runGid = runGid;
    cmd->qmperr = qmperr;

    /* the ".sock" sufix is important to avoid a possible clash with a qemu
     * domain called "capabilities"
     */
    if (virAsprintf(&cmd->monpath, "%s/%s", libDir,
                    "capabilities.monitor.sock") < 0)
        goto error;
    if (virAsprintf(&cmd->monarg, "unix:%s,server,nowait", cmd->monpath) < 0)
        goto error;

    /* ".pidfile" suffix is used rather than ".pid" to avoid a possible clash
     * with a qemu domain called "capabilities"
     * Normally we'd use runDir for pid files, but because we're using
     * -daemonize we need QEMU to be allowed to create them, rather
     * than libvirtd. So we're using libDir which QEMU can write to
     */
    if (virAsprintf(&cmd->pidfile, "%s/%s", libDir, "capabilities.pidfile") < 0)
        goto error;

    virPidFileForceCleanupPath(cmd->pidfile);

    cmd->config.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    cmd->config.data.nix.path = cmd->monpath;
    cmd->config.data.nix.listen = false;

    return cmd;

 error:
    virQEMUCapsInitQMPCommandFree(cmd);
    return NULL;
}


/* Returns -1 on fatal error,
 *          0 on success,
 *          1 when probing QEMU failed
 */
static int
virQEMUCapsInitQMPCommandRun(virQEMUCapsInitQMPCommandPtr cmd,
                             bool forceTCG)
{
    virDomainXMLOptionPtr xmlopt = NULL;
    const char *machine;
    int status = 0;
    int ret = -1;

    if (forceTCG)
        machine = "none,accel=tcg";
    else
        machine = "none,accel=kvm:tcg";

    VIR_DEBUG("Try to probe capabilities of '%s' via QMP, machine %s",
              cmd->binary, machine);

    /*
     * We explicitly need to use -daemonize here, rather than
     * virCommandDaemonize, because we need to synchronize
     * with QEMU creating its monitor socket API. Using
     * daemonize guarantees control won't return to libvirt
     * until the socket is present.
     */
    cmd->cmd = virCommandNewArgList(cmd->binary,
                                    "-S",
                                    "-no-user-config",
                                    "-nodefaults",
                                    "-nographic",
                                    "-machine", machine,
                                    "-qmp", cmd->monarg,
                                    "-pidfile", cmd->pidfile,
                                    "-daemonize",
                                    NULL);
    virCommandAddEnvPassCommon(cmd->cmd);
    virCommandClearCaps(cmd->cmd);
    virCommandSetGID(cmd->cmd, cmd->runGid);
    virCommandSetUID(cmd->cmd, cmd->runUid);

    virCommandSetErrorBuffer(cmd->cmd, cmd->qmperr);

    /* Log, but otherwise ignore, non-zero status.  */
    if (virCommandRun(cmd->cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        VIR_DEBUG("QEMU %s exited with status %d: %s",
                  cmd->binary, status, *cmd->qmperr);
        goto ignore;
    }

    if (virPidFileReadPath(cmd->pidfile, &cmd->pid) < 0) {
        VIR_DEBUG("Failed to read pidfile %s", cmd->pidfile);
        goto ignore;
    }

    if (!(xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL, NULL, NULL)) ||
        !(cmd->vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    cmd->vm->pid = cmd->pid;

    if (!(cmd->mon = qemuMonitorOpen(cmd->vm, &cmd->config, true,
                                     0, &callbacks, NULL)))
        goto ignore;

    virObjectLock(cmd->mon);

    ret = 0;

 cleanup:
    if (!cmd->mon)
        virQEMUCapsInitQMPCommandAbort(cmd);
    virObjectUnref(xmlopt);

    return ret;

 ignore:
    ret = 1;
    goto cleanup;
}


static int
virQEMUCapsInitQMP(virQEMUCapsPtr qemuCaps,
                   const char *libDir,
                   uid_t runUid,
                   gid_t runGid,
                   char **qmperr)
{
    virQEMUCapsInitQMPCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (!(cmd = virQEMUCapsInitQMPCommandNew(qemuCaps->binary, libDir,
                                             runUid, runGid, qmperr)))
        goto cleanup;

    if ((rc = virQEMUCapsInitQMPCommandRun(cmd, false)) != 0) {
        if (rc == 1)
            ret = 0;
        goto cleanup;
    }

    if (virQEMUCapsInitQMPMonitor(qemuCaps, cmd->mon) < 0)
        goto cleanup;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        virQEMUCapsInitQMPCommandAbort(cmd);
        if ((rc = virQEMUCapsInitQMPCommandRun(cmd, true)) != 0) {
            if (rc == 1)
                ret = 0;
            goto cleanup;
        }

        if (virQEMUCapsInitQMPMonitorTCG(qemuCaps, cmd->mon) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virQEMUCapsInitQMPCommandFree(cmd);
    return ret;
}


#define MESSAGE_ID_CAPS_PROBE_FAILURE "8ae2f3fb-2dbe-498e-8fbd-012d40afa361"

static void
virQEMUCapsLogProbeFailure(const char *binary)
{
    virLogMetadata meta[] = {
        { .key = "MESSAGE_ID", .s = MESSAGE_ID_CAPS_PROBE_FAILURE, .iv = 0 },
        { .key = "LIBVIRT_QEMU_BINARY", .s = binary, .iv = 0 },
        { .key = NULL },
    };

    virLogMessage(&virLogSelf,
                  VIR_LOG_WARN,
                  __FILE__, __LINE__, __func__,
                  meta,
                  _("Failed to probe capabilities for %s: %s"),
                  binary, virGetLastErrorMessage());
}


virQEMUCapsPtr
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                bool qmpOnly)
{
    virQEMUCapsPtr qemuCaps;
    struct stat sb;
    char *qmperr = NULL;

    if (!(qemuCaps = virQEMUCapsNew()))
        goto error;

    if (VIR_STRDUP(qemuCaps->binary, binary) < 0)
        goto error;

    /* We would also want to check faccessat if we cared about ACLs,
     * but we don't.  */
    if (stat(binary, &sb) < 0) {
        virReportSystemError(errno, _("Cannot check QEMU binary %s"),
                             binary);
        goto error;
    }
    qemuCaps->ctime = sb.st_ctime;

    /* Make sure the binary we are about to try exec'ing exists.
     * Technically we could catch the exec() failure, but that's
     * in a sub-process so it's hard to feed back a useful error.
     */
    if (!virFileIsExecutable(binary)) {
        virReportSystemError(errno, _("QEMU binary %s is not executable"),
                             binary);
        goto error;
    }

    if (virQEMUCapsInitQMP(qemuCaps, libDir, runUid, runGid, &qmperr) < 0) {
        virQEMUCapsLogProbeFailure(binary);
        goto error;
    }

    if (qmpOnly && !qemuCaps->usedQMP) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to probe QEMU binary with QMP: %s"),
                       qmperr ? qmperr : _("unknown error"));
        virQEMUCapsLogProbeFailure(binary);
        goto error;
    }

    if (!qemuCaps->usedQMP &&
        virQEMUCapsInitHelp(qemuCaps, runUid, runGid, qmperr) < 0) {
        virQEMUCapsLogProbeFailure(binary);
        goto error;
    }

    qemuCaps->libvirtCtime = virGetSelfLastChanged();
    qemuCaps->libvirtVersion = LIBVIR_VERSION_NUMBER;

    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_QEMU);

 cleanup:
    VIR_FREE(qmperr);
    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    qemuCaps = NULL;
    goto cleanup;
}

static void *
virQEMUCapsNewData(const char *binary,
                   void *privData)
{
    virQEMUCapsCachePrivPtr priv = privData;

    return virQEMUCapsNewForBinaryInternal(priv->hostArch,
                                           binary,
                                           priv->libDir,
                                           priv->runUid,
                                           priv->runGid,
                                           false);
}


static void *
virQEMUCapsLoadFile(const char *filename,
                    const char *binary,
                    void *privData)
{
    virQEMUCapsPtr qemuCaps = virQEMUCapsNew();
    virQEMUCapsCachePrivPtr priv = privData;

    if (!qemuCaps)
        return NULL;

    if (VIR_STRDUP(qemuCaps->binary, binary) < 0)
        goto error;

    if (virQEMUCapsLoadCache(priv->hostArch, qemuCaps, filename) < 0)
        goto error;

 cleanup:
    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    qemuCaps = NULL;
    goto cleanup;
}


struct virQEMUCapsMachineTypeFilter {
    const char *machineType;
    virQEMUCapsFlags *flags;
    size_t nflags;
};

static const struct virQEMUCapsMachineTypeFilter virQEMUCapsMachineFilter[] = {
    /* { "blah", virQEMUCapsMachineBLAHFilter,
         ARRAY_CARDINALITY(virQEMUCapsMachineBLAHFilter) }, */
    { "", NULL, 0 },
};


void
virQEMUCapsFilterByMachineType(virQEMUCapsPtr qemuCaps,
                               const char *machineType)
{
    size_t i;

    if (!machineType)
        return;

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsMachineFilter); i++) {
        const struct virQEMUCapsMachineTypeFilter *filter = &virQEMUCapsMachineFilter[i];
        size_t j;

        if (STRNEQ(filter->machineType, machineType))
            continue;

        for (j = 0; j < filter->nflags; j++)
            virQEMUCapsClear(qemuCaps, filter->flags[j]);
    }

    if (!virQEMUCapsGetMachineHotplugCpus(qemuCaps, machineType))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);
}


virFileCacheHandlers qemuCapsCacheHandlers = {
    .isValid = virQEMUCapsIsValid,
    .newData = virQEMUCapsNewData,
    .loadFile = virQEMUCapsLoadFile,
    .saveFile = virQEMUCapsSaveFile,
    .privFree = virQEMUCapsCachePrivFree,
};


virFileCachePtr
virQEMUCapsCacheNew(const char *libDir,
                    const char *cacheDir,
                    uid_t runUid,
                    gid_t runGid)
{
    char *capsCacheDir = NULL;
    virFileCachePtr cache = NULL;
    virQEMUCapsCachePrivPtr priv = NULL;

    if (virAsprintf(&capsCacheDir, "%s/capabilities", cacheDir) < 0)
        goto error;

    if (!(cache = virFileCacheNew(capsCacheDir, "xml", &qemuCapsCacheHandlers)))
        goto error;

    if (VIR_ALLOC(priv) < 0)
        goto error;
    virFileCacheSetPriv(cache, priv);

    if (VIR_STRDUP(priv->libDir, libDir) < 0)
        goto error;

    priv->hostArch = virArchFromHost();

    priv->runUid = runUid;
    priv->runGid = runGid;

 cleanup:
    VIR_FREE(capsCacheDir);
    return cache;

 error:
    virObjectUnref(cache);
    cache = NULL;
    goto cleanup;
}


virQEMUCapsPtr
virQEMUCapsCacheLookup(virFileCachePtr cache,
                       const char *binary)
{
    virQEMUCapsPtr ret = NULL;

    ret = virFileCacheLookup(cache, binary);

    VIR_DEBUG("Returning caps %p for %s", ret, binary);
    return ret;
}


virQEMUCapsPtr
virQEMUCapsCacheLookupCopy(virFileCachePtr cache,
                           const char *binary,
                           const char *machineType)
{
    virQEMUCapsPtr qemuCaps = virQEMUCapsCacheLookup(cache, binary);
    virQEMUCapsPtr ret;

    if (!qemuCaps)
        return NULL;

    ret = virQEMUCapsNewCopy(qemuCaps);
    virObjectUnref(qemuCaps);

    if (!ret)
        return NULL;

    virQEMUCapsFilterByMachineType(ret, machineType);
    return ret;
}


static int
virQEMUCapsCompareArch(const void *payload,
                       const void *name ATTRIBUTE_UNUSED,
                       const void *opaque)
{
    struct virQEMUCapsSearchData *data = (struct virQEMUCapsSearchData *) opaque;
    const virQEMUCaps *qemuCaps = payload;

    return qemuCaps->arch == data->arch;
}


virQEMUCapsPtr
virQEMUCapsCacheLookupByArch(virFileCachePtr cache,
                             virArch arch)
{
    virQEMUCapsPtr ret = NULL;
    virArch target;
    struct virQEMUCapsSearchData data = { .arch = arch };

    ret = virFileCacheLookupByFunc(cache, virQEMUCapsCompareArch, &data);
    if (!ret) {
        /* If the first attempt at finding capabilities has failed, try
         * again using the QEMU target as lookup key instead */
        target = virQEMUCapsFindTarget(virArchFromHost(), data.arch);
        if (target != data.arch) {
            data.arch = target;
            ret = virFileCacheLookupByFunc(cache, virQEMUCapsCompareArch, &data);
        }
    }

    if (!ret) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unable to find any emulator to serve '%s' "
                         "architecture"), virArchToString(arch));
    }

    VIR_DEBUG("Returning caps %p for arch %s", ret, virArchToString(arch));

    return ret;
}


bool
virQEMUCapsSupportsVmport(virQEMUCapsPtr qemuCaps,
                          const virDomainDef *def)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_VMPORT_OPT))
        return false;

    return qemuDomainIsI440FX(def) ||
        qemuDomainIsQ35(def) ||
        STREQ(def->os.machine, "isapc");
}


bool
virQEMUCapsSupportsSMM(virQEMUCapsPtr qemuCaps,
                       const virDomainDef *def)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_SMM_OPT))
        return false;

    return qemuDomainIsQ35(def);
}


bool
virQEMUCapsIsMachineSupported(virQEMUCapsPtr qemuCaps,
                              const char *canonical_machine)
{
    size_t i;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (STREQ(canonical_machine, qemuCaps->machineTypes[i].name))
            return true;
    }
    return false;
}


const char *
virQEMUCapsGetDefaultMachine(virQEMUCapsPtr qemuCaps)
{
    if (!qemuCaps->nmachineTypes)
        return NULL;
    return qemuCaps->machineTypes[0].name;
}


static int
virQEMUCapsFillDomainLoaderCaps(virDomainCapsLoaderPtr capsLoader,
                                virFirmwarePtr *firmwares,
                                size_t nfirmwares)
{
    size_t i;

    capsLoader->supported = true;

    if (VIR_ALLOC_N(capsLoader->values.values, nfirmwares) < 0)
        return -1;

    for (i = 0; i < nfirmwares; i++) {
        const char *filename = firmwares[i]->name;

        if (!virFileExists(filename)) {
            VIR_DEBUG("loader filename=%s does not exist", filename);
            continue;
        }

        if (VIR_STRDUP(capsLoader->values.values[capsLoader->values.nvalues],
                       filename) < 0)
            return -1;
        capsLoader->values.nvalues++;
    }

    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->type,
                             VIR_DOMAIN_LOADER_TYPE_ROM);

    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->type,
                             VIR_DOMAIN_LOADER_TYPE_PFLASH);


    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->readonly,
                             VIR_TRISTATE_BOOL_YES,
                             VIR_TRISTATE_BOOL_NO);
    return 0;
}


static int
virQEMUCapsFillDomainOSCaps(virDomainCapsOSPtr os,
                            virFirmwarePtr *firmwares,
                            size_t nfirmwares)
{
    virDomainCapsLoaderPtr capsLoader = &os->loader;

    os->supported = true;
    if (virQEMUCapsFillDomainLoaderCaps(capsLoader, firmwares, nfirmwares) < 0)
        return -1;
    return 0;
}


static int
virQEMUCapsFillDomainCPUCaps(virCapsPtr caps,
                             virQEMUCapsPtr qemuCaps,
                             virDomainCapsPtr domCaps)
{
    if (virQEMUCapsIsCPUModeSupported(qemuCaps, caps, domCaps->virttype,
                                      VIR_CPU_MODE_HOST_PASSTHROUGH))
        domCaps->cpu.hostPassthrough = true;

    if (virQEMUCapsIsCPUModeSupported(qemuCaps, caps, domCaps->virttype,
                                      VIR_CPU_MODE_HOST_MODEL)) {
        virCPUDefPtr cpu = virQEMUCapsGetHostModel(qemuCaps, domCaps->virttype,
                                                   VIR_QEMU_CAPS_HOST_CPU_REPORTED);
        domCaps->cpu.hostModel = virCPUDefCopy(cpu);
    }

    if (virQEMUCapsIsCPUModeSupported(qemuCaps, caps, domCaps->virttype,
                                      VIR_CPU_MODE_CUSTOM)) {
        virDomainCapsCPUModelsPtr filtered = NULL;
        char **models = NULL;
        const char *blacklist[] = { "host", NULL };

        if (virCPUGetModels(domCaps->arch, &models) >= 0) {
            virDomainCapsCPUModelsPtr cpus;

            if (domCaps->virttype == VIR_DOMAIN_VIRT_KVM)
                cpus = qemuCaps->kvmCPUModels;
            else
                cpus = qemuCaps->tcgCPUModels;

            filtered = virDomainCapsCPUModelsFilter(cpus,
                                                    (const char **) models,
                                                    blacklist);
            virStringListFree(models);
        }
        domCaps->cpu.custom = filtered;
    }

    return 0;
}


static int
virQEMUCapsFillDomainDeviceDiskCaps(virQEMUCapsPtr qemuCaps,
                                    const char *machine,
                                    virDomainCapsDeviceDiskPtr disk)
{
    disk->supported = true;
    /* QEMU supports all of these */
    VIR_DOMAIN_CAPS_ENUM_SET(disk->diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM,
                             VIR_DOMAIN_DISK_DEVICE_LUN);

    /* PowerPC pseries based VMs do not support floppy device */
    if (!qemuDomainMachineIsPSeries(machine, qemuCaps->arch))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->diskDevice, VIR_DOMAIN_DISK_DEVICE_FLOPPY);

    if (qemuDomainMachineHasBuiltinIDE(machine))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_IDE);

    VIR_DOMAIN_CAPS_ENUM_SET(disk->bus,
                             VIR_DOMAIN_DISK_BUS_SCSI,
                             VIR_DOMAIN_DISK_BUS_VIRTIO,
                             /* VIR_DOMAIN_DISK_BUS_SD */);

    /* PowerPC pseries based VMs do not support floppy device */
    if (!qemuDomainMachineIsPSeries(machine, qemuCaps->arch))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_FDC);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_USB);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_AHCI))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_SATA);

    return 0;
}


static int
virQEMUCapsFillDomainDeviceGraphicsCaps(virQEMUCapsPtr qemuCaps,
                                        virDomainCapsDeviceGraphicsPtr dev)
{
    dev->supported = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SDL))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_SDL);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_VNC);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_SPICE);

    return 0;
}


static int
virQEMUCapsFillDomainDeviceVideoCaps(virQEMUCapsPtr qemuCaps,
                                     virDomainCapsDeviceVideoPtr dev)
{
    dev->supported = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VGA))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_VGA);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_CIRRUS_VGA))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_CIRRUS);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMWARE_SVGA))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_VMVGA);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_QXL))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_QXL);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_GPU))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_VIRTIO);

    return 0;
}


static int
virQEMUCapsFillDomainDeviceHostdevCaps(virQEMUCapsPtr qemuCaps,
                                       virDomainCapsDeviceHostdevPtr hostdev)
{
    bool supportsPassthroughKVM = qemuHostdevHostSupportsPassthroughLegacy();
    bool supportsPassthroughVFIO = qemuHostdevHostSupportsPassthroughVFIO();

    hostdev->supported = true;
    /* VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES is for containers only */
    VIR_DOMAIN_CAPS_ENUM_SET(hostdev->mode,
                             VIR_DOMAIN_HOSTDEV_MODE_SUBSYS);

    VIR_DOMAIN_CAPS_ENUM_SET(hostdev->startupPolicy,
                             VIR_DOMAIN_STARTUP_POLICY_DEFAULT,
                             VIR_DOMAIN_STARTUP_POLICY_MANDATORY,
                             VIR_DOMAIN_STARTUP_POLICY_REQUISITE,
                             VIR_DOMAIN_STARTUP_POLICY_OPTIONAL);

    VIR_DOMAIN_CAPS_ENUM_SET(hostdev->subsysType,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SCSI_GENERIC))
        VIR_DOMAIN_CAPS_ENUM_SET(hostdev->subsysType,
                                 VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI);

    /* No virDomainHostdevCapsType for QEMU */
    virDomainCapsEnumClear(&hostdev->capsType);

    virDomainCapsEnumClear(&hostdev->pciBackend);
    if (supportsPassthroughVFIO &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
        VIR_DOMAIN_CAPS_ENUM_SET(hostdev->pciBackend,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO);
    }

    if (supportsPassthroughKVM) {
        VIR_DOMAIN_CAPS_ENUM_SET(hostdev->pciBackend,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM);
    }
    return 0;
}


/**
 * virQEMUCapsSupportsGICVersion:
 * @qemuCaps: QEMU capabilities
 * @virtType: domain type
 * @version: GIC version
 *
 * Checks the QEMU binary with capabilities @qemuCaps supports a specific
 * GIC version for a domain of type @virtType.
 *
 * Returns: true if the binary supports the requested GIC version, false
 *          otherwise
 */
bool
virQEMUCapsSupportsGICVersion(virQEMUCapsPtr qemuCaps,
                              virDomainVirtType virtType,
                              virGICVersion version)
{
    size_t i;

    for (i = 0; i < qemuCaps->ngicCapabilities; i++) {
        virGICCapabilityPtr cap = &(qemuCaps->gicCapabilities[i]);

        if (cap->version != version)
            continue;

        if (virtType == VIR_DOMAIN_VIRT_KVM &&
            cap->implementation & VIR_GIC_IMPLEMENTATION_KERNEL)
            return true;

        if (virtType == VIR_DOMAIN_VIRT_QEMU &&
            cap->implementation & VIR_GIC_IMPLEMENTATION_EMULATED)
            return true;
    }

    return false;
}


/**
 * virQEMUCapsFillDomainFeatureGICCaps:
 * @qemuCaps: QEMU capabilities
 * @domCaps: domain capabilities
 *
 * Take the information about GIC capabilities that has been obtained
 * using the 'query-gic-capabilities' QMP command and stored in @qemuCaps
 * and convert it to a form suitable for @domCaps.
 *
 * @qemuCaps contains complete information about the GIC capabilities for
 * the corresponding QEMU binary, stored as custom objects; @domCaps, on
 * the other hand, should only contain information about the GIC versions
 * available for the specific combination of architecture, machine type
 * and virtualization type. Moreover, a common format is used to store
 * information about enumerations in @domCaps, so further processing is
 * required.
 *
 * Returns: 0 on success, <0 on failure
 */
static int
virQEMUCapsFillDomainFeatureGICCaps(virQEMUCapsPtr qemuCaps,
                                    virDomainCapsPtr domCaps)
{
    virDomainCapsFeatureGICPtr gic = &domCaps->gic;
    virGICVersion version;

    if (!qemuDomainMachineIsVirt(domCaps->machine, domCaps->arch))
        return 0;

    for (version = VIR_GIC_VERSION_LAST - 1;
         version > VIR_GIC_VERSION_NONE;
         version--) {
        if (!virQEMUCapsSupportsGICVersion(qemuCaps,
                                           domCaps->virttype,
                                           version))
            continue;

        gic->supported = true;
        VIR_DOMAIN_CAPS_ENUM_SET(gic->version,
                                 version);
    }

    return 0;
}


int
virQEMUCapsFillDomainCaps(virCapsPtr caps,
                          virDomainCapsPtr domCaps,
                          virQEMUCapsPtr qemuCaps,
                          virFirmwarePtr *firmwares,
                          size_t nfirmwares)
{
    virDomainCapsOSPtr os = &domCaps->os;
    virDomainCapsDeviceDiskPtr disk = &domCaps->disk;
    virDomainCapsDeviceHostdevPtr hostdev = &domCaps->hostdev;
    virDomainCapsDeviceGraphicsPtr graphics = &domCaps->graphics;
    virDomainCapsDeviceVideoPtr video = &domCaps->video;

    domCaps->maxvcpus = virQEMUCapsGetMachineMaxCpus(qemuCaps,
                                                     domCaps->machine);
    if (domCaps->virttype == VIR_DOMAIN_VIRT_KVM) {
        int hostmaxvcpus;

        if ((hostmaxvcpus = virHostCPUGetKVMMaxVCPUs()) < 0)
            return -1;

        domCaps->maxvcpus = MIN(domCaps->maxvcpus, hostmaxvcpus);
    }

    if (virQEMUCapsFillDomainOSCaps(os, firmwares, nfirmwares) < 0 ||
        virQEMUCapsFillDomainCPUCaps(caps, qemuCaps, domCaps) < 0 ||
        virQEMUCapsFillDomainDeviceDiskCaps(qemuCaps,
                                            domCaps->machine, disk) < 0 ||
        virQEMUCapsFillDomainDeviceGraphicsCaps(qemuCaps, graphics) < 0 ||
        virQEMUCapsFillDomainDeviceVideoCaps(qemuCaps, video) < 0 ||
        virQEMUCapsFillDomainDeviceHostdevCaps(qemuCaps, hostdev) < 0 ||
        virQEMUCapsFillDomainFeatureGICCaps(qemuCaps, domCaps) < 0)
        return -1;
    return 0;
}
