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
#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu_capspriv.h"
#include "qemu_qapi.h"
#include "qemu_process.h"
#include "qemu_firmware.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <sys/utsname.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_capabilities");

/* While not public, these strings must not change. They
 * are used in domain status files which are read on
 * daemon restarts
 */
VIR_ENUM_IMPL(virQEMUCaps,
              QEMU_CAPS_LAST, /* virQEMUCaps grouping marker */
              /* 0 */
              "vnc-colon",
              "no-reboot",
              "drive",
              "drive-boot",
              "name",

              /* 5 */
              "uuid",
              "domid",
              "vnet-hdr",
              "migrate-kvm-stdio",
              "migrate-qemu-tcp",

              /* 10 */
              "migrate-qemu-exec",
              "drive-cache-v2",
              "kvm",
              "drive-format",
              "vga",

              /* 15 */
              "0.10",
              "pci-device",
              "mem-path",
              "drive-serial",
              "xen-domid",

              /* 20 */
              "migrate-qemu-unix",
              "chardev",
              "enable-kvm",
              "monitor-json",
              "balloon",

              /* 25 */
              "device",
              "sdl",
              "smp-topology",
              "netdev",
              "rtc",

              /* 30 */
              "vhost-net",
              "rtc-td-hack",
              "no-hpet",
              "no-kvm-pit",
              "tdf",

              /* 35 */
              "pci-configfd",
              "nodefconfig",
              "boot-menu",
              "fsdev",
              "nesting",

              /* 40 */
              "name-process",
              "drive-readonly",
              "smbios-type",
              "vga-qxl",
              "spice",

              /* 45 */
              "vga-none",
              "migrate-qemu-fd",
              "boot-index",
              "hda-duplex",
              "drive-aio",

              /* 50 */
              "pci-multibus",
              "pci-bootindex",
              "ccid-emulated",
              "ccid-passthru",
              "chardev-spicevmc",

              /* 55 */
              "device-spicevmc",
              "virtio-tx-alg",
              "device-qxl-vga",
              "pci-multifunction",
              "virtio-blk-pci.ioeventfd",

              /* 60 */
              "sga",
              "virtio-blk-pci.event_idx",
              "virtio-net-pci.event_idx",
              "cache-directsync",
              "piix3-usb-uhci",

              /* 65 */
              "piix4-usb-uhci",
              "usb-ehci",
              "ich9-usb-ehci1",
              "vt82c686b-usb-uhci",
              "pci-ohci",

              /* 70 */
              "usb-redir",
              "usb-hub",
              "no-shutdown",
              "cache-unsafe",
              "rombar",

              /* 75 */
              "ich9-ahci",
              "no-acpi",
              "fsdev-readonly",
              "virtio-blk-pci.scsi",
              "blk-sg-io",

              /* 80 */
              "drive-copy-on-read",
              "cpu-host",
              "fsdev-writeout",
              "drive-iotune",
              "system_wakeup",

              /* 85 */
              "scsi-disk.channel",
              "scsi-block",
              "transaction",
              "block-job-sync",
              "block-job-async",

              /* 90 */
              "scsi-cd",
              "ide-cd",
              "no-user-config",
              "hda-micro",
              "dump-guest-memory",

              /* 95 */
              "nec-usb-xhci",
              "virtio-s390",
              "balloon-event",
              "bridge",
              "lsi",

              /* 100 */
              "virtio-scsi-pci",
              "blockio",
              "disable-s3",
              "disable-s4",
              "usb-redir.filter",

              /* 105 */
              "ide-drive.wwn",
              "scsi-disk.wwn",
              "seccomp-sandbox",
              "reboot-timeout",
              "dump-guest-core",

              /* 110 */
              "seamless-migration",
              "block-commit",
              "vnc",
              "drive-mirror",
              "usb-redir.bootindex",

              /* 115 */
              "usb-host.bootindex",
              "blockdev-snapshot-sync",
              "qxl",
              "VGA",
              "cirrus-vga",

              /* 120 */
              "vmware-svga",
              "device-video-primary",
              "s390-sclp",
              "usb-serial",
              "usb-net",

              /* 125 */
              "add-fd",
              "nbd-server",
              "virtio-rng",
              "rng-random",
              "rng-egd",

              /* 130 */
              "virtio-ccw",
              "dtb",
              "megasas",
              "ipv6-migration",
              "machine-opt",

              /* 135 */
              "machine-usb-opt",
              "tpm-passthrough",
              "tpm-tis",
              "nvram",
              "pci-bridge",

              /* 140 */
              "vfio-pci",
              "vfio-pci.bootindex",
              "scsi-generic",
              "scsi-generic.bootindex",
              "mem-merge",

              /* 145 */
              "vnc-websocket",
              "drive-discard",
              "mlock",
              "vnc-share-policy",
              "device-del-event",

              /* 150 */
              "dmi-to-pci-bridge",
              "i440fx-pci-hole64-size",
              "q35-pci-hole64-size",
              "usb-storage",
              "usb-storage.removable",

              /* 155 */
              "virtio-mmio",
              "ich9-intel-hda",
              "kvm-pit-lost-tick-policy",
              "boot-strict",
              "pvpanic",

              /* 160 */
              "enable-fips",
              "spice-file-xfer-disable",
              "spiceport",
              "usb-kbd",
              "host-pci-multidomain",

              /* 165 */
              "msg-timestamp",
              "active-commit",
              "change-backing-file",
              "memory-backend-ram",
              "numa",

              /* 170 */
              "memory-backend-file",
              "usb-audio",
              "rtc-reset-reinjection",
              "splash-timeout",
              "iothread",

              /* 175 */
              "migrate-rdma",
              "ivshmem",
              "drive-iotune-max",
              "VGA.vgamem_mb",
              "vmware-svga.vgamem_mb",

              /* 180 */
              "qxl.vgamem_mb",
              "qxl-vga.vgamem_mb",
              "pc-dimm",
              "machine-vmport-opt",
              "aes-key-wrap",

              /* 185 */
              "dea-key-wrap",
              "pci-serial",
              "aarch64-off",
              "vhost-user-multiqueue",
              "migration-event",

              /* 190 */
              "gpex-pcihost",
              "ioh3420",
              "x3130-upstream",
              "xio3130-downstream",
              "rtl8139",

              /* 195 */
              "e1000",
              "virtio-net",
              "gic-version",
              "incoming-defer",
              "virtio-gpu",

              /* 200 */
              "virtio-gpu.virgl",
              "virtio-keyboard",
              "virtio-mouse",
              "virtio-tablet",
              "virtio-input-host",

              /* 205 */
              "chardev-file-append",
              "ich9-disable-s3",
              "ich9-disable-s4",
              "vserport-change-event",
              "virtio-balloon-pci.deflate-on-oom",

              /* 210 */
              "mptsas1068",
              "spice-gl",
              "qxl.vram64_size_mb",
              "qxl-vga.vram64_size_mb",
              "chardev-logfile",

              /* 215 */
              "debug-threads",
              "secret",
              "pxb",
              "pxb-pcie",
              "device-tray-moved-event",

              /* 220 */
              "nec-usb-xhci-ports",
              "virtio-scsi-pci.iothread",
              "name-guest",
              "qxl.max_outputs",
              "qxl-vga.max_outputs",

              /* 225 */
              "spice-unix",
              "drive-detect-zeroes",
              "tls-creds-x509",
              "display",
              "intel-iommu",

              /* 230 */
              "smm",
              "virtio-pci-disable-legacy",
              "query-hotpluggable-cpus",
              "virtio-net.rx_queue_size",
              "machine-iommu",

              /* 235 */
              "virtio-vga",
              "drive-iotune-max-length",
              "ivshmem-plain",
              "ivshmem-doorbell",
              "query-qmp-schema",

              /* 240 */
              "gluster.debug_level",
              "vhost-scsi",
              "drive-iotune-group",
              "query-cpu-model-expansion",
              "virtio-net.host_mtu",

              /* 245 */
              "spice-rendernode",
              "nvdimm",
              "pcie-root-port",
              "query-cpu-definitions",
              "block-write-threshold",

              /* 250 */
              "query-named-block-nodes",
              "cpu-cache",
              "qemu-xhci",
              "kernel-irqchip",
              "kernel-irqchip.split",

              /* 255 */
              "intel-iommu.intremap",
              "intel-iommu.caching-mode",
              "intel-iommu.eim",
              "intel-iommu.device-iotlb",
              "virtio.iommu_platform",

              /* 260 */
              "virtio.ats",
              "loadparm",
              "spapr-pci-host-bridge",
              "spapr-pci-host-bridge.numa_node",
              "vnc-multi-servers",

              /* 265 */
              "virtio-net.tx_queue_size",
              "chardev-reconnect",
              "virtio-gpu.max_outputs",
              "vxhs",
              "virtio-blk.num-queues",

              /* 270 */
              "machine.pseries.resize-hpt",
              "vmcoreinfo",
              "spapr-vty",
              "sclplmconsole",
              "numa.dist",

              /* 275 */
              "disk-share-rw",
              "iscsi.password-secret",
              "isa-serial",
              "pl011",
              "machine.pseries.max-cpu-compat",

              /* 280 */
              "dump-completed",
              "virtio-gpu-ccw",
              "virtio-keyboard-ccw",
              "virtio-mouse-ccw",
              "virtio-tablet-ccw",

              /* 285 */
              "qcow2-luks",
              "pcie-pci-bridge",
              "seccomp-blacklist",
              "query-cpus-fast",
              "disk-write-cache",

              /* 290 */
              "nbd-tls",
              "tpm-crb",
              "pr-manager-helper",
              "qom-list-properties",
              "memory-backend-file.discard-data",

              /* 295 */
              "virtual-css-bridge",
              "virtual-css-bridge.cssid-unrestricted",
              "vfio-ccw",
              "sdl-gl",
              "screendump_device",

              /* 300 */
              "hda-output",
              "blockdev-del",
              "vmgenid",
              "vhost-vsock",
              "chardev-fd-pass",

              /* 305 */
              "tpm-emulator",
              "mch",
              "mch.extended-tseg-mbytes",
              "sev-guest",
              "machine.pseries.cap-hpt-max-page-size",

              /* 310 */
              "machine.pseries.cap-htm",
              "usb-storage.werror",
              "egl-headless",
              "vfio-pci.display",
              "blockdev",

              /* 315 */
              "vfio-ap",
              "zpci",
              "memory-backend-memfd",
              "memory-backend-memfd.hugetlb",
              "iothread.poll-max-ns",

              /* 320 */
              "machine.pseries.cap-nested-hv",
              "egl-headless.rendernode",
              "memory-backend-file.align",
              "memory-backend-file.pmem",
              "nvdimm.unarmed",

              /* 325 */
              "scsi-disk.device_id",
              "virtio-pci-non-transitional",
              "overcommit",
              "query-current-machine",
              "machine.virt.iommu",

              /* 330 */
              "bitmap-merge",
              "nbd-bitmap",
              "x86-max-cpu",
              "cpu-unavailable-features",
              "canonical-cpu-features",

              /* 335 */
              "bochs-display",
              "migration-file-drop-cache",
              "dbus-vmstate",
              "vhost-user-gpu",
              "vhost-user-vga",

              /* 340 */
              "incremental-backup",
              "query-cpu-model-baseline",
              "query-cpu-model-comparison",
    );


struct virQEMUCapsMachineType {
    char *name;
    char *alias;
    unsigned int maxCpus;
    bool hotplugCpus;
    bool qemuDefault;
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
    virObject parent;

    bool usedQMP;
    bool kvmSupportsNesting;

    char *binary;
    time_t ctime;
    time_t libvirtCtime;

    virBitmapPtr flags;

    unsigned int version;
    unsigned int kvmVersion;
    unsigned int libvirtVersion;
    unsigned int microcodeVersion;
    char *package;
    char *kernelVersion;

    virArch arch;

    virHashTablePtr domCapsCache;
    virDomainCapsCPUModelsPtr kvmCPUModels;
    virDomainCapsCPUModelsPtr tcgCPUModels;

    size_t nmachineTypes;
    struct virQEMUCapsMachineType *machineTypes;

    size_t ngicCapabilities;
    virGICCapability *gicCapabilities;

    virSEVCapability *sevCapabilities;

    virQEMUCapsHostCPUData kvmCPU;
    virQEMUCapsHostCPUData tcgCPU;
};

struct virQEMUCapsSearchData {
    virArch arch;
    const char *binaryFilter;
};


static virClassPtr virQEMUCapsClass;
static void virQEMUCapsDispose(void *obj);

static int virQEMUCapsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virQEMUCaps, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUCaps);

virArch virQEMUCapsArchFromString(const char *arch)
{
    if (STREQ(arch, "i386"))
        return VIR_ARCH_I686;
    if (STREQ(arch, "arm"))
        return VIR_ARCH_ARMV7L;
    if (STREQ(arch, "or32"))
        return VIR_ARCH_OR32;

    return virArchFromString(arch);
}


const char *virQEMUCapsArchToString(virArch arch)
{
    if (arch == VIR_ARCH_I686)
        return "i386";
    else if (arch == VIR_ARCH_ARMV6L || arch == VIR_ARCH_ARMV7L)
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
    /* host & guest arches match */
    if (host == guest)
        return true;

    /* hostarch is x86_64 and guest arch is i686 (needs -cpu qemu32) */
    if (host == VIR_ARCH_X86_64 && guest == VIR_ARCH_I686)
        return true;

    /* hostarch is aarch64 and guest arch is armv7l (needs -cpu aarch64=off) */
    if (host == VIR_ARCH_AARCH64 && guest == VIR_ARCH_ARMV7L)
        return true;

    /* hostarch and guestarch are both ppc64 */
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


static char *
virQEMUCapsFindBinary(const char *format,
                      const char *archstr)
{
    char *ret = NULL;
    char *binary = NULL;

    if (virAsprintf(&binary, format, archstr) < 0)
        return NULL;

    ret = virFindFileInPath(binary);
    VIR_FREE(binary);
    return ret;
}

static char *
virQEMUCapsFindBinaryForArch(virArch hostarch,
                             virArch guestarch)
{
    char *ret = NULL;
    const char *archstr;
    virArch target;

    /* armv7l guests can only take advantage of KVM on aarch64 hosts by
     * using the qemu-system-aarch64 binary, so look for that one first
     * to avoid using qemu-system-arm (and thus TCG) instead */
    if (hostarch == VIR_ARCH_AARCH64 && guestarch == VIR_ARCH_ARMV7L) {
        archstr = virQEMUCapsArchToString(hostarch);
        if ((ret = virQEMUCapsFindBinary("qemu-system-%s", archstr)) != NULL)
            goto out;
    }

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

 out:
    return ret;
}

static int
virQEMUCapsInitGuest(virCapsPtr caps,
                     virFileCachePtr cache,
                     virArch hostarch,
                     virArch guestarch)
{
    char *binary = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    int ret = -1;

    /* Check for existence of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = virQEMUCapsFindBinaryForArch(hostarch, guestarch);

    /* RHEL doesn't follow the usual naming for QEMU binaries and ships
     * a single binary named qemu-kvm outside of $PATH instead */
    if (virQEMUCapsGuestIsNative(hostarch, guestarch) && !binary) {
        if (VIR_STRDUP(binary, "/usr/libexec/qemu-kvm") < 0)
            return -1;
    }

    /* Ignore binary if extracting version info fails */
    if (binary) {
        if (!(qemuCaps = virQEMUCapsCacheLookup(cache, binary))) {
            virResetLastError();
            VIR_FREE(binary);
        }
    }

    ret = virQEMUCapsInitGuestFromBinary(caps,
                                         binary, qemuCaps,
                                         guestarch);

    VIR_FREE(binary);
    virObjectUnref(qemuCaps);

    return ret;
}

int
virQEMUCapsInitGuestFromBinary(virCapsPtr caps,
                               const char *binary,
                               virQEMUCapsPtr qemuCaps,
                               virArch guestarch)
{
    virCapsGuestPtr guest;
    virCapsGuestMachinePtr *machines = NULL;
    size_t nmachines = 0;
    int ret = -1;

    if (!binary)
        return 0;

    if (virQEMUCapsGetMachineTypesCaps(qemuCaps, &nmachines, &machines) < 0)
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

    if (!virCapabilitiesAddGuestFeature(guest, "deviceboot", true, false))
        goto cleanup;

    if (!virCapabilitiesAddGuestFeature(guest, "disksnapshot", true, false))
        goto cleanup;

    if (virCapabilitiesAddGuestDomain(guest,
                                      VIR_DOMAIN_VIRT_QEMU,
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto cleanup;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_KVM,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL) {
            goto cleanup;
        }
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
virQEMUCapsProbeHostCPU(virArch hostArch,
                        virDomainCapsCPUModelsPtr models)
{
    return virCPUGetHost(hostArch, VIR_CPU_TYPE_GUEST, NULL, models);
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

    /* Some machines have problematic NUMA topology causing
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

    /* Add IOMMU info */
    virCapabilitiesHostInitIOMMU(caps);

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


struct virQEMUCapsStringFlags {
    const char *value;
    int flag;
};


struct virQEMUCapsStringFlags virQEMUCapsCommands[] = {
    { "dump-guest-memory", QEMU_CAPS_DUMP_GUEST_MEMORY },
    { "query-spice", QEMU_CAPS_SPICE },
    { "query-vnc", QEMU_CAPS_VNC },
    { "nbd-server-start", QEMU_CAPS_NBD_SERVER },
    { "change-backing-file", QEMU_CAPS_CHANGE_BACKING_FILE },
    { "rtc-reset-reinjection", QEMU_CAPS_RTC_RESET_REINJECTION },
    { "migrate-incoming", QEMU_CAPS_INCOMING_DEFER },
    { "query-hotpluggable-cpus", QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS },
    { "query-qmp-schema", QEMU_CAPS_QUERY_QMP_SCHEMA },
    { "query-cpu-model-expansion", QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION },
    { "query-cpu-definitions", QEMU_CAPS_QUERY_CPU_DEFINITIONS },
    { "query-named-block-nodes", QEMU_CAPS_QUERY_NAMED_BLOCK_NODES },
    { "query-cpus-fast", QEMU_CAPS_QUERY_CPUS_FAST },
    { "qom-list-properties", QEMU_CAPS_QOM_LIST_PROPERTIES },
    { "blockdev-del", QEMU_CAPS_BLOCKDEV_DEL },
    { "query-current-machine", QEMU_CAPS_QUERY_CURRENT_MACHINE },
    { "block-dirty-bitmap-merge", QEMU_CAPS_BITMAP_MERGE },
    { "query-cpu-model-baseline", QEMU_CAPS_QUERY_CPU_MODEL_BASELINE },
    { "query-cpu-model-comparison", QEMU_CAPS_QUERY_CPU_MODEL_COMPARISON },
};

struct virQEMUCapsStringFlags virQEMUCapsMigration[] = {
    { "rdma-pin-all", QEMU_CAPS_MIGRATE_RDMA },
};

/* Use virQEMUCapsQMPSchemaQueries for querying parameters of events */
struct virQEMUCapsStringFlags virQEMUCapsEvents[] = {
    { "MIGRATION", QEMU_CAPS_MIGRATION_EVENT },
    { "VSERPORT_CHANGE", QEMU_CAPS_VSERPORT_CHANGE },
    { "BLOCK_WRITE_THRESHOLD", QEMU_CAPS_BLOCK_WRITE_THRESHOLD },
    { "DUMP_COMPLETED", QEMU_CAPS_DUMP_COMPLETED },
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
    { "sclpconsole", QEMU_CAPS_DEVICE_SCLPCONSOLE },
    { "lsi53c895a", QEMU_CAPS_SCSI_LSI },
    { "virtio-scsi-pci", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-s390", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-ccw", QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-scsi-device", QEMU_CAPS_VIRTIO_SCSI },
    { "megasas", QEMU_CAPS_SCSI_MEGASAS },
    { "qxl", QEMU_CAPS_DEVICE_QXL },
    { "sga", QEMU_CAPS_SGA },
    { "scsi-block", QEMU_CAPS_SCSI_BLOCK },
    { "VGA", QEMU_CAPS_DEVICE_VGA },
    { "cirrus-vga", QEMU_CAPS_DEVICE_CIRRUS_VGA },
    { "vmware-svga", QEMU_CAPS_DEVICE_VMWARE_SVGA },
    { "usb-serial", QEMU_CAPS_DEVICE_USB_SERIAL },
    { "virtio-rng-pci", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-s390", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-ccw", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "virtio-rng-device", QEMU_CAPS_DEVICE_VIRTIO_RNG },
    { "rng-random", QEMU_CAPS_OBJECT_RNG_RANDOM },
    { "rng-egd", QEMU_CAPS_OBJECT_RNG_EGD },
    { "spapr-nvram", QEMU_CAPS_DEVICE_NVRAM },
    { "pci-bridge", QEMU_CAPS_DEVICE_PCI_BRIDGE },
    { "vfio-pci", QEMU_CAPS_DEVICE_VFIO_PCI },
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
    { "vmcoreinfo", QEMU_CAPS_DEVICE_VMCOREINFO },
    { "spapr-vty", QEMU_CAPS_DEVICE_SPAPR_VTY },
    { "sclplmconsole", QEMU_CAPS_DEVICE_SCLPLMCONSOLE },
    { "isa-serial", QEMU_CAPS_DEVICE_ISA_SERIAL },
    { "pl011", QEMU_CAPS_DEVICE_PL011 },
    { "virtio-gpu-ccw", QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW },
    { "virtio-keyboard-ccw", QEMU_CAPS_DEVICE_VIRTIO_KEYBOARD_CCW },
    { "virtio-mouse-ccw", QEMU_CAPS_DEVICE_VIRTIO_MOUSE_CCW },
    { "virtio-tablet-ccw", QEMU_CAPS_DEVICE_VIRTIO_TABLET_CCW },
    { "pcie-pci-bridge", QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE },
    { "pr-manager-helper", QEMU_CAPS_PR_MANAGER_HELPER },
    { "virtual-css-bridge", QEMU_CAPS_CCW },
    { "vfio-ccw", QEMU_CAPS_DEVICE_VFIO_CCW },
    { "hda-output", QEMU_CAPS_HDA_OUTPUT },
    { "vmgenid", QEMU_CAPS_DEVICE_VMGENID },
    { "vhost-vsock-device", QEMU_CAPS_DEVICE_VHOST_VSOCK },
    { "mch", QEMU_CAPS_DEVICE_MCH },
    { "sev-guest", QEMU_CAPS_SEV_GUEST },
    { "vfio-ap", QEMU_CAPS_DEVICE_VFIO_AP },
    { "zpci", QEMU_CAPS_DEVICE_ZPCI },
    { "memory-backend-memfd", QEMU_CAPS_OBJECT_MEMORY_MEMFD },
    { "virtio-blk-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-blk-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-net-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-net-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "vhost-scsi-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "vhost-scsi-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-rng-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-rng-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-9p-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-9p-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-balloon-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-balloon-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "vhost-vsock-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "vhost-vsock-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-input-host-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-input-host-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-scsi-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-scsi-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-serial-pci-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "virtio-serial-pci-non-transitional", QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL },
    { "max-x86_64-cpu", QEMU_CAPS_X86_MAX_CPU },
    { "bochs-display", QEMU_CAPS_DEVICE_BOCHS_DISPLAY },
    { "dbus-vmstate", QEMU_CAPS_DBUS_VMSTATE },
    { "vhost-user-gpu", QEMU_CAPS_DEVICE_VHOST_USER_GPU },
    { "vhost-user-vga", QEMU_CAPS_DEVICE_VHOST_USER_VGA },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVirtioBalloon[] = {
    { "deflate-on-oom", QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVirtioBlk[] = {
    { "ioeventfd", QEMU_CAPS_VIRTIO_IOEVENTFD },
    { "event_idx", QEMU_CAPS_VIRTIO_BLK_EVENT_IDX },
    { "scsi", QEMU_CAPS_VIRTIO_BLK_SCSI },
    { "logical_block_size", QEMU_CAPS_BLOCKIO },
    { "num-queues", QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVirtioNet[] = {
    { "tx", QEMU_CAPS_VIRTIO_TX_ALG },
    { "event_idx", QEMU_CAPS_VIRTIO_NET_EVENT_IDX },
    { "rx_queue_size", QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE },
    { "tx_queue_size", QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE },
    { "host_mtu", QEMU_CAPS_VIRTIO_NET_HOST_MTU },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsSpaprPCIHostBridge[] = {
    { "numa_node", QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVirtioSCSI[] = {
    { "iothread", QEMU_CAPS_VIRTIO_SCSI_IOTHREAD },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVfioPCI[] = {
    { "display", QEMU_CAPS_VFIO_PCI_DISPLAY },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsSCSIDisk[] = {
    { "channel", QEMU_CAPS_SCSI_DISK_CHANNEL },
    { "wwn", QEMU_CAPS_SCSI_DISK_WWN },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE },
    { "device_id", QEMU_CAPS_SCSI_DISK_DEVICE_ID },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsIDEDrive[] = {
    { "wwn", QEMU_CAPS_IDE_DRIVE_WWN },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsPiix4PM[] = {
    { "disable_s3", QEMU_CAPS_PIIX_DISABLE_S3 },
    { "disable_s4", QEMU_CAPS_PIIX_DISABLE_S4 },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsUSBRedir[] = {
    { "filter", QEMU_CAPS_USB_REDIR_FILTER },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsI440FXPCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsQ35PCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_Q35_PCI_HOLE64_SIZE },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsUSBStorage[] = {
    { "removable", QEMU_CAPS_USB_STORAGE_REMOVABLE },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE },
    { "werror", QEMU_CAPS_USB_STORAGE_WERROR },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsKVMPit[] = {
    { "lost_tick_policy", QEMU_CAPS_KVM_PIT_TICK_POLICY },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVGA[] = {
    { "vgamem_mb", QEMU_CAPS_VGA_VGAMEM },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVmwareSvga[] = {
    { "vgamem_mb", QEMU_CAPS_VMWARE_SVGA_VGAMEM },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsQxl[] = {
    { "vgamem_mb", QEMU_CAPS_QXL_VGAMEM },
    { "vram64_size_mb", QEMU_CAPS_QXL_VRAM64 },
    { "max_outputs", QEMU_CAPS_QXL_MAX_OUTPUTS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsVirtioGpu[] = {
    { "virgl", QEMU_CAPS_VIRTIO_GPU_VIRGL },
    { "max_outputs", QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsICH9[] = {
    { "disable_s3", QEMU_CAPS_ICH9_DISABLE_S3 },
    { "disable_s4", QEMU_CAPS_ICH9_DISABLE_S4 },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsUSBNECXHCI[] = {
    { "p3", QEMU_CAPS_NEC_USB_XHCI_PORTS },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsIntelIOMMU[] = {
    { "intremap", QEMU_CAPS_INTEL_IOMMU_INTREMAP },
    { "caching-mode", QEMU_CAPS_INTEL_IOMMU_CACHING_MODE },
    { "eim", QEMU_CAPS_INTEL_IOMMU_EIM },
    { "device-iotlb", QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsVirtualCSSBridge[] = {
    { "cssid-unrestricted", QEMU_CAPS_CCW_CSSID_UNRESTRICTED },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsMCH[] = {
    { "extended-tseg-mbytes", QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES },
};

static struct virQEMUCapsStringFlags virQEMUCapsDevicePropsNVDIMM[] = {
    { "unarmed", QEMU_CAPS_DEVICE_NVDIMM_UNARMED },
};

/* see documentation for virQEMUQAPISchemaPathGet for the query format */
static struct virQEMUCapsStringFlags virQEMUCapsQMPSchemaQueries[] = {
    { "blockdev-add/arg-type/options/+gluster/debug-level", QEMU_CAPS_GLUSTER_DEBUG_LEVEL},
    { "blockdev-add/arg-type/+gluster/debug", QEMU_CAPS_GLUSTER_DEBUG_LEVEL},
    { "blockdev-add/arg-type/+vxhs", QEMU_CAPS_VXHS},
    { "blockdev-add/arg-type/+iscsi/password-secret", QEMU_CAPS_ISCSI_PASSWORD_SECRET },
    { "blockdev-add/arg-type/+qcow2/encrypt/+luks/key-secret", QEMU_CAPS_QCOW2_LUKS },
    { "nbd-server-start/arg-type/tls-creds", QEMU_CAPS_NBD_TLS },
    { "screendump/arg-type/device", QEMU_CAPS_SCREENDUMP_DEVICE },
    { "block-commit/arg-type/*top",  QEMU_CAPS_ACTIVE_COMMIT },
    { "query-iothreads/ret-type/poll-max-ns", QEMU_CAPS_IOTHREAD_POLLING },
    { "query-display-options/ret-type/+egl-headless/rendernode", QEMU_CAPS_EGL_HEADLESS_RENDERNODE },
    { "nbd-server-add/arg-type/bitmap", QEMU_CAPS_NBD_BITMAP },
    { "blockdev-add/arg-type/+file/drop-cache", QEMU_CAPS_MIGRATION_FILE_DROP_CACHE },
};

typedef struct _virQEMUCapsObjectTypeProps virQEMUCapsObjectTypeProps;
struct _virQEMUCapsObjectTypeProps {
    const char *type;
    struct virQEMUCapsStringFlags *props;
    size_t nprops;
    int capsCondition;
};

typedef int (*virQEMUCapsObjectTypePropsCB)(qemuMonitorPtr mon,
                                            const char *type,
                                            char ***props);

static virQEMUCapsObjectTypeProps virQEMUCapsDeviceProps[] = {
    { "virtio-blk-pci", virQEMUCapsDevicePropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBlk),
      -1 },
    { "virtio-net-pci", virQEMUCapsDevicePropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioNet),
      QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-scsi-pci", virQEMUCapsDevicePropsVirtioSCSI,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioSCSI),
      QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-blk-ccw", virQEMUCapsDevicePropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBlk),
      QEMU_CAPS_VIRTIO_CCW },
    { "virtio-net-ccw", virQEMUCapsDevicePropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioNet),
      QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-scsi-ccw", virQEMUCapsDevicePropsVirtioSCSI,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioSCSI),
      QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-blk-s390", virQEMUCapsDevicePropsVirtioBlk,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBlk),
      QEMU_CAPS_VIRTIO_S390 },
    { "virtio-net-s390", virQEMUCapsDevicePropsVirtioNet,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioNet),
      QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "vfio-pci", virQEMUCapsDevicePropsVfioPCI,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVfioPCI),
      QEMU_CAPS_DEVICE_VFIO_PCI },
    { "scsi-hd", virQEMUCapsDevicePropsSCSIDisk,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsSCSIDisk),
      -1 },
    { "ide-hd", virQEMUCapsDevicePropsIDEDrive,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsIDEDrive),
      -1 },
    { "PIIX4_PM", virQEMUCapsDevicePropsPiix4PM,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsPiix4PM),
      -1 },
    { "usb-redir", virQEMUCapsDevicePropsUSBRedir,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsUSBRedir),
      QEMU_CAPS_USB_REDIR },
    { "i440FX-pcihost", virQEMUCapsDevicePropsI440FXPCIHost,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsI440FXPCIHost),
      -1 },
    { "q35-pcihost", virQEMUCapsDevicePropsQ35PCIHost,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsQ35PCIHost),
      -1 },
    { "usb-storage", virQEMUCapsDevicePropsUSBStorage,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsUSBStorage),
      QEMU_CAPS_DEVICE_USB_STORAGE },
    { "kvm-pit", virQEMUCapsDevicePropsKVMPit,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsKVMPit),
      -1 },
    { "VGA", virQEMUCapsDevicePropsVGA,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVGA),
      QEMU_CAPS_DEVICE_VGA },
    { "vmware-svga", virQEMUCapsDevicePropsVmwareSvga,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVmwareSvga),
      QEMU_CAPS_DEVICE_VMWARE_SVGA },
    { "qxl", virQEMUCapsDevicePropsQxl,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsQxl),
      QEMU_CAPS_DEVICE_QXL },
    { "virtio-gpu-pci", virQEMUCapsDevicePropsVirtioGpu,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "virtio-gpu-device", virQEMUCapsDevicePropsVirtioGpu,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "ICH9-LPC", virQEMUCapsDevicePropsICH9,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsICH9),
      -1 },
    { "virtio-balloon-pci", virQEMUCapsDevicePropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "virtio-balloon-ccw", virQEMUCapsDevicePropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "virtio-balloon-device", virQEMUCapsDevicePropsVirtioBalloon,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "nec-usb-xhci", virQEMUCapsDevicePropsUSBNECXHCI,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsUSBNECXHCI),
      QEMU_CAPS_NEC_USB_XHCI },
    { "intel-iommu", virQEMUCapsDevicePropsIntelIOMMU,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsIntelIOMMU),
      QEMU_CAPS_DEVICE_INTEL_IOMMU },
    { "spapr-pci-host-bridge", virQEMUCapsDevicePropsSpaprPCIHostBridge,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsSpaprPCIHostBridge),
      QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE },
    { "virtio-gpu-ccw", virQEMUCapsDevicePropsVirtioGpu,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW },
    { "virtual-css-bridge", virQEMUCapsObjectPropsVirtualCSSBridge,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsVirtualCSSBridge),
      QEMU_CAPS_CCW },
    { "mch", virQEMUCapsDevicePropsMCH,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsMCH),
      QEMU_CAPS_DEVICE_MCH },
    { "nvdimm", virQEMUCapsDevicePropsNVDIMM,
      ARRAY_CARDINALITY(virQEMUCapsDevicePropsNVDIMM),
      QEMU_CAPS_DEVICE_NVDIMM },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMemoryBackendFile[] = {
    { "discard-data", QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD },
    { "align", QEMU_CAPS_OBJECT_MEMORY_FILE_ALIGN },
    { "pmem", QEMU_CAPS_OBJECT_MEMORY_FILE_PMEM },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMemoryBackendMemfd[] = {
    { "hugetlb", QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMaxX86CPU[] = {
    { "unavailable-features", QEMU_CAPS_CPU_UNAVAILABLE_FEATURES },
};

static virQEMUCapsObjectTypeProps virQEMUCapsObjectProps[] = {
    { "memory-backend-file", virQEMUCapsObjectPropsMemoryBackendFile,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsMemoryBackendFile),
      QEMU_CAPS_OBJECT_MEMORY_FILE },
    { "memory-backend-memfd", virQEMUCapsObjectPropsMemoryBackendMemfd,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsMemoryBackendMemfd),
      QEMU_CAPS_OBJECT_MEMORY_MEMFD },
    { "max-x86_64-cpu", virQEMUCapsObjectPropsMaxX86CPU,
      ARRAY_CARDINALITY(virQEMUCapsObjectPropsMaxX86CPU),
      QEMU_CAPS_X86_MAX_CPU },
};

static struct virQEMUCapsStringFlags virQEMUCapsMachinePropsPSeries[] = {
    { "cap-hpt-max-page-size", QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE },
    { "cap-htm", QEMU_CAPS_MACHINE_PSERIES_CAP_HTM },
    { "cap-nested-hv", QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV },
};

static struct virQEMUCapsStringFlags virQEMUCapsMachinePropsVirt[] = {
    { "iommu", QEMU_CAPS_MACHINE_VIRT_IOMMU },
};

static virQEMUCapsObjectTypeProps virQEMUCapsMachineProps[] = {
    { "pseries", virQEMUCapsMachinePropsPSeries,
      ARRAY_CARDINALITY(virQEMUCapsMachinePropsPSeries),
      -1 },
    { "virt", virQEMUCapsMachinePropsVirt,
      ARRAY_CARDINALITY(virQEMUCapsMachinePropsVirt),
      -1 },
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
        if (virQEMUCapsGet(qemuCaps, flags[i].flag))
            continue;

        for (j = 0; j < nvalues; j++) {
            if (STREQ(values[j], flags[i].value)) {
                virQEMUCapsSet(qemuCaps, flags[i].flag);
                break;
            }
        }
    }
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

    if (!(qemuCaps->domCapsCache = virHashCreate(5, virObjectFreeHashData)))
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


static int
virQEMUCapsSEVInfoCopy(virSEVCapabilityPtr *dst,
                       virSEVCapabilityPtr src)
{
    VIR_AUTOPTR(virSEVCapability) tmp = NULL;

    if (VIR_ALLOC(tmp) < 0 ||
        VIR_STRDUP(tmp->pdh, src->pdh) < 0 ||
        VIR_STRDUP(tmp->cert_chain, src->cert_chain) < 0)
        return -1;

    tmp->cbitpos = src->cbitpos;
    tmp->reduced_phys_bits = src->reduced_phys_bits;

    VIR_STEAL_PTR(*dst, tmp);
    return 0;
}


virQEMUCapsPtr virQEMUCapsNewCopy(virQEMUCapsPtr qemuCaps)
{
    virQEMUCapsPtr ret = virQEMUCapsNew();
    size_t i;

    if (!ret)
        return NULL;

    ret->usedQMP = qemuCaps->usedQMP;
    ret->kvmSupportsNesting = qemuCaps->kvmSupportsNesting;

    if (VIR_STRDUP(ret->binary, qemuCaps->binary) < 0)
        goto error;

    ret->ctime = qemuCaps->ctime;

    virBitmapCopy(ret->flags, qemuCaps->flags);

    ret->version = qemuCaps->version;
    ret->kvmVersion = qemuCaps->kvmVersion;
    ret->microcodeVersion = qemuCaps->microcodeVersion;

    if (VIR_STRDUP(ret->package, qemuCaps->package) < 0)
        goto error;

    if (VIR_STRDUP(ret->kernelVersion, qemuCaps->kernelVersion) < 0)
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
        ret->machineTypes[i].qemuDefault = qemuCaps->machineTypes[i].qemuDefault;

    }

    if (VIR_ALLOC_N(ret->gicCapabilities, qemuCaps->ngicCapabilities) < 0)
        goto error;
    ret->ngicCapabilities = qemuCaps->ngicCapabilities;
    for (i = 0; i < qemuCaps->ngicCapabilities; i++)
        ret->gicCapabilities[i] = qemuCaps->gicCapabilities[i];

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST) &&
        virQEMUCapsSEVInfoCopy(&ret->sevCapabilities,
                               qemuCaps->sevCapabilities) < 0)
        goto error;

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

    virHashFree(qemuCaps->domCapsCache);
    virObjectUnref(qemuCaps->kvmCPUModels);
    virObjectUnref(qemuCaps->tcgCPUModels);

    virBitmapFree(qemuCaps->flags);

    VIR_FREE(qemuCaps->package);
    VIR_FREE(qemuCaps->kernelVersion);
    VIR_FREE(qemuCaps->binary);

    VIR_FREE(qemuCaps->gicCapabilities);

    virSEVCapabilitiesFree(qemuCaps->sevCapabilities);

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
        virQEMUCapsSet(qemuCaps, flag);
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
    return virBitmapToString(qemuCaps->flags, true, false);
}


bool
virQEMUCapsGet(virQEMUCapsPtr qemuCaps,
               virQEMUCapsFlags flag)
{
    return qemuCaps && virBitmapIsBitSet(qemuCaps->flags, flag);
}


bool virQEMUCapsHasPCIMultiBus(virQEMUCapsPtr qemuCaps,
                               const virDomainDef *def)
{
    /* x86_64 and i686 support PCI-multibus on all machine types
     * since forever */
    if (ARCH_IS_X86(def->os.arch))
        return true;

    if (def->os.arch == VIR_ARCH_PPC ||
        ARCH_IS_PPC64(def->os.arch)) {
        /*
         * Usage of pci.0 naming:
         *
         *    ref405ep: no pci
         *       taihu: no pci
         *      bamboo: 1.1.0 (<= 1.5.0, so basically forever)
         *       mac99: 2.0.0
         *     g3beige: 2.0.0
         *        prep: 1.4.0 (<= 1.5.0, so basically forever)
         *     pseries: 2.0.0
         *   mpc8544ds: forever
         * virtex-m507: no pci
         *     ppce500: 1.6.0
         */

        /* We do not store the qemu version in domain status XML.
         * Hope the user is using a QEMU new enough to use 'pci.0',
         * otherwise the results of this function will be wrong
         * for domains already running at the time of daemon
         * restart */
        if (qemuCaps->version == 0)
            return true;

        if (qemuCaps->version >= 2000000)
            return true;

        if (qemuCaps->version >= 1006000 &&
            STREQ(def->os.machine, "ppce500"))
            return true;

        if (STREQ(def->os.machine, "bamboo") ||
            STREQ(def->os.machine, "mpc8544ds") ||
            STREQ(def->os.machine, "prep")) {
            return true;
        }

        return false;
    }

    /* S390 supports PCI-multibus. */
    if (ARCH_IS_S390(def->os.arch))
        return true;

    /* If the virt machine, both on ARM and RISC-V, supports PCI,
     * then it also supports multibus */
    if (qemuDomainIsARMVirt(def) ||
        qemuDomainIsRISCVVirt(def)) {
        return true;
    }

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


virHashTablePtr virQEMUCapsGetDomainCapsCache(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->domCapsCache;
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
        if (virDomainCapsCPUModelsAdd(cpus, name[i], -1, usable, NULL) < 0)
            return -1;
    }

    return 0;
}


virDomainCapsCPUModelsPtr
virQEMUCapsGetCPUDefinitions(virQEMUCapsPtr qemuCaps,
                             virDomainVirtType type)
{
    if (type == VIR_DOMAIN_VIRT_KVM)
        return qemuCaps->kvmCPUModels;
    else
        return qemuCaps->tcgCPUModels;
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


/**
 * virQEMUCapsGetCanonicalMachine:
 * @qemuCaps: qemu capabilities object
 * @name: machine name
 *
 * Resolves aliased machine names to the actual machine name. If qemuCaps isn't
 * present @name is returned.
 */
const char *virQEMUCapsGetCanonicalMachine(virQEMUCapsPtr qemuCaps,
                                           const char *name)
{
    size_t i;

    if (!name || !qemuCaps)
        return name;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (!qemuCaps->machineTypes[i].alias)
            continue;
        if (STREQ(qemuCaps->machineTypes[i].alias, name))
            return qemuCaps->machineTypes[i].name;
    }

    return name;
}

const char *
virQEMUCapsGetDefaultMachine(virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < qemuCaps->nmachineTypes; i++) {
        if (qemuCaps->machineTypes[i].qemuDefault)
            return qemuCaps->machineTypes[i].name;
    }

    return NULL;
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


virSEVCapabilityPtr
virQEMUCapsGetSEVCapabilities(virQEMUCapsPtr qemuCaps)
{
    return qemuCaps->sevCapabilities;
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

    /* Probe for active commit of qemu 2.1. We don't need to query directly
     * if we have QMP schema support */
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_QMP_SCHEMA) &&
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

    /* we can probe events also from the QMP schema so we can skip this here */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_QMP_SCHEMA))
        return 0;

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
virQEMUCapsProbeQMPGenericProps(virQEMUCapsPtr qemuCaps,
                                qemuMonitorPtr mon,
                                virQEMUCapsObjectTypeProps *props,
                                size_t nprops,
                                virQEMUCapsObjectTypePropsCB propsGetCB)
{
    int nvalues;
    char **values;
    size_t i;

    for (i = 0; i < nprops; i++) {
        const char *type = props[i].type;
        int cap = props[i].capsCondition;

        if (cap >= 0 && !virQEMUCapsGet(qemuCaps, cap))
            continue;

        if ((nvalues = propsGetCB(mon, type, &values)) < 0)
            return -1;
        virQEMUCapsProcessStringFlags(qemuCaps,
                                      props[i].nprops,
                                      props[i].props,
                                      nvalues, values);
        virStringListFreeCount(values, nvalues);
    }

    return 0;
}

static int
virQEMUCapsProbeQMPDevices(virQEMUCapsPtr qemuCaps,
                           qemuMonitorPtr mon)
{
    int nvalues;
    char **values;

    if ((nvalues = qemuMonitorGetObjectTypes(mon, &values)) < 0)
        return -1;
    virQEMUCapsProcessStringFlags(qemuCaps,
                                  ARRAY_CARDINALITY(virQEMUCapsObjectTypes),
                                  virQEMUCapsObjectTypes,
                                  nvalues, values);
    virStringListFreeCount(values, nvalues);

    if (virQEMUCapsProbeQMPGenericProps(qemuCaps,
                                        mon,
                                        virQEMUCapsDeviceProps,
                                        ARRAY_CARDINALITY(virQEMUCapsDeviceProps),
                                        qemuMonitorGetDeviceProps) < 0)
        return -1;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_QOM_LIST_PROPERTIES) &&
        virQEMUCapsProbeQMPGenericProps(qemuCaps,
                                        mon,
                                        virQEMUCapsObjectProps,
                                        ARRAY_CARDINALITY(virQEMUCapsObjectProps),
                                        qemuMonitorGetObjectProps) < 0)
        return -1;

    return 0;
}


/* Historically QEMU x86 targets defaulted to 'pc' machine type but
 * in future x86_64 might switch to 'q35'. Such a change is considered
 * an ABI break from libvirt's POV. Other QEMU targets may not declare
 * a default machine at all, causing libvirt to use the first reported
 * machine in the list.
 *
 * Here we record a preferred default machine for all arches, so
 * that we're not vulnerable to changes in QEMU defaults or machine
 * list ordering.
 */
static const char *preferredMachines[] =
{
    NULL, /* VIR_ARCH_NONE (not a real arch :) */
    "clipper", /* VIR_ARCH_ALPHA */
    "integratorcp", /* VIR_ARCH_ARMV6L */
    "integratorcp", /* VIR_ARCH_ARMV7L */
    "integratorcp", /* VIR_ARCH_ARMV7B */

    "integratorcp", /* VIR_ARCH_AARCH64 */
    "axis-dev88", /* VIR_ARCH_CRIS */
    "pc", /* VIR_ARCH_I686 */
    NULL, /* VIR_ARCH_ITANIUM (doesn't exist in QEMU any more) */
    "lm32-evr", /* VIR_ARCH_LM32 */

    "mcf5208evb", /* VIR_ARCH_M68K */
    "petalogix-s3adsp1800", /* VIR_ARCH_MICROBLAZE */
    "petalogix-s3adsp1800", /* VIR_ARCH_MICROBLAZEEL */
    "malta", /* VIR_ARCH_MIPS */
    "malta", /* VIR_ARCH_MIPSEL */

    "malta", /* VIR_ARCH_MIPS64 */
    "malta", /* VIR_ARCH_MIPS64EL */
    "or1k-sim", /* VIR_ARCH_OR32 */
    NULL, /* VIR_ARCH_PARISC (no QEMU impl) */
    NULL, /* VIR_ARCH_PARISC64 (no QEMU impl) */

    "g3beige", /* VIR_ARCH_PPC */
    "g3beige", /* VIR_ARCH_PPCLE */
    "pseries", /* VIR_ARCH_PPC64 */
    "pseries", /* VIR_ARCH_PPC64LE */
    "bamboo", /* VIR_ARCH_PPCEMB */

    "spike_v1.10", /* VIR_ARCH_RISCV32 */
    "spike_v1.10", /* VIR_ARCH_RISCV64 */
    NULL, /* VIR_ARCH_S390 (no QEMU impl) */
    "s390-ccw-virtio", /* VIR_ARCH_S390X */
    "shix", /* VIR_ARCH_SH4 */

    "shix", /* VIR_ARCH_SH4EB */
    "SS-5", /* VIR_ARCH_SPARC */
    "sun4u", /* VIR_ARCH_SPARC64 */
    "puv3", /* VIR_ARCH_UNICORE32 */
    "pc", /* VIR_ARCH_X86_64 */

    "sim", /* VIR_ARCH_XTENSA */
    "sim", /* VIR_ARCH_XTENSAEB */
};
verify(ARRAY_CARDINALITY(preferredMachines) == VIR_ARCH_LAST);


static int
virQEMUCapsProbeQMPMachineTypes(virQEMUCapsPtr qemuCaps,
                                qemuMonitorPtr mon)
{
    qemuMonitorMachineInfoPtr *machines = NULL;
    int nmachines = 0;
    int ret = -1;
    size_t i;
    ssize_t defIdx = -1;
    ssize_t preferredIdx = -1;
    const char *preferredMachine = preferredMachines[qemuCaps->arch];

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

        if (preferredMachine &&
            (STREQ_NULLABLE(mach->alias, preferredMachine) ||
             STREQ(mach->name, preferredMachine))) {
            preferredIdx = qemuCaps->nmachineTypes - 1;
        }

        if (machines[i]->isDefault) {
            mach->qemuDefault = true;
            defIdx = qemuCaps->nmachineTypes - 1;
        }
    }

    /*
     * We'll prefer to use our own historical default machine
     * to avoid mgmt apps seeing semantics changes when QEMU
     * alters its defaults.
     *
     * Our preferred machine might have been compiled out of
     * QEMU at build time though, so we still fallback to honouring
     * QEMU's reported default in that case
     */
    if (preferredIdx == -1)
        preferredIdx = defIdx;
    if (preferredIdx != -1)
        virQEMUCapsSetDefaultMachine(qemuCaps, preferredIdx);

    ret = 0;

 cleanup:
    for (i = 0; i < nmachines; i++)
        qemuMonitorMachineInfoFree(machines[i]);
    VIR_FREE(machines);
    return ret;
}


static int
virQEMUCapsProbeQMPMachineProps(virQEMUCapsPtr qemuCaps,
                                qemuMonitorPtr mon)
{
    char **values;
    int nvalues;
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QOM_LIST_PROPERTIES))
        return 0;

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsMachineProps); i++) {
        virQEMUCapsObjectTypeProps props = virQEMUCapsMachineProps[i];
        const char *canon = virQEMUCapsGetCanonicalMachine(qemuCaps, props.type);
        VIR_AUTOFREE(char *) type = NULL;

        if (!virQEMUCapsIsMachineSupported(qemuCaps, canon))
            continue;

        /* The QOM type for machine types is the machine type name
         * followed by the -machine suffix */
        if (virAsprintf(&type, "%s-machine", canon) < 0)
            return -1;

        if ((nvalues = qemuMonitorGetObjectProps(mon, type, &values)) < 0)
            return -1;

        virQEMUCapsProcessStringFlags(qemuCaps,
                                      props.nprops,
                                      props.props,
                                      nvalues, values);

        virStringListFreeCount(values, nvalues);
    }

    return 0;
}


virDomainCapsCPUModelsPtr
virQEMUCapsFetchCPUDefinitions(qemuMonitorPtr mon,
                               virArch arch)
{
    virDomainCapsCPUModelsPtr models = NULL;
    qemuMonitorCPUDefInfoPtr *cpus = NULL;
    int ncpus = 0;
    size_t i;

    if ((ncpus = qemuMonitorGetCPUDefinitions(mon, &cpus)) < 0)
        return NULL;

    /* QEMU 2.11 for Power renamed all CPU models to lower case, we need to
     * translate them back to libvirt's upper case model names. */
    if (ARCH_IS_PPC(arch)) {
        VIR_AUTOSTRINGLIST libvirtModels = NULL;
        char **name;

        if (virCPUGetModels(arch, &libvirtModels) < 0)
            goto error;

        for (name = libvirtModels; name && *name; name++) {
            for (i = 0; i < ncpus; i++) {
                if (STRCASENEQ(cpus[i]->name, *name))
                    continue;

                VIR_FREE(cpus[i]->name);
                if (VIR_STRDUP(cpus[i]->name, *name) < 0)
                    goto error;
            }
        }
    }

    if (!(models = virDomainCapsCPUModelsNew(ncpus)))
        goto error;

    for (i = 0; i < ncpus; i++) {
        virDomainCapsCPUUsable usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;

        if (cpus[i]->usable == VIR_TRISTATE_BOOL_YES)
            usable = VIR_DOMCAPS_CPU_USABLE_YES;
        else if (cpus[i]->usable == VIR_TRISTATE_BOOL_NO)
            usable = VIR_DOMCAPS_CPU_USABLE_NO;

        if (virDomainCapsCPUModelsAddSteal(models, &cpus[i]->name, usable,
                                           &cpus[i]->blockers) < 0)
            goto error;
    }

 cleanup:
    for (i = 0; i < ncpus; i++)
        qemuMonitorCPUDefInfoFree(cpus[i]);
    VIR_FREE(cpus);
    return models;

 error:
    virObjectUnref(models);
    models = NULL;
    goto cleanup;
}


int
virQEMUCapsProbeQMPCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                  qemuMonitorPtr mon,
                                  bool tcg)
{
    virDomainCapsCPUModelsPtr models = NULL;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_DEFINITIONS))
        return 0;

    if (!(models = virQEMUCapsFetchCPUDefinitions(mon, qemuCaps->arch)))
        return -1;

    if (tcg || !virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        qemuCaps->tcgCPUModels = models;
    else
        qemuCaps->kvmCPUModels = models;

    return 0;
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
    virCPUDefPtr cpu;
    qemuMonitorCPUModelExpansionType type;
    virDomainVirtType virtType;
    bool fail_no_props = true;
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

    if (VIR_ALLOC(cpu) < 0 || VIR_STRDUP(cpu->model, model) < 0)
        goto cleanup;

    /* Some x86_64 features defined in cpu_map.xml use spelling which differ
     * from the one preferred by QEMU. Static expansion would give us only the
     * preferred spelling. With new QEMU we always use the QEMU's canonical
     * names of all features and translate between them and our names. But for
     * older version of QEMU we need to do a full expansion on the result of
     * the initial static expansion to get all variants of feature names.
     */
    if (ARCH_IS_X86(qemuCaps->arch) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CANONICAL_CPU_FEATURES))
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL;
    else
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC;

    /* Older s390 models do not report a feature set */
    if (ARCH_IS_S390(qemuCaps->arch))
        fail_no_props = false;

    if (qemuMonitorGetCPUModelExpansion(mon, type, cpu, true, fail_no_props,
                                        &modelInfo) < 0)
        goto cleanup;

    /* Try to check migratability of each feature. */
    if (modelInfo &&
        qemuMonitorGetCPUModelExpansion(mon, type, cpu, false, fail_no_props,
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

    virQEMUCapsSetCPUModelInfo(qemuCaps, virtType, modelInfo);
    modelInfo = NULL;
    ret = 0;

 cleanup:
    virHashFree(hash);
    qemuMonitorCPUModelInfoFree(nonMigratable);
    qemuMonitorCPUModelInfoFree(modelInfo);
    virCPUDefFree(cpu);

    return ret;
}


/**
 * Get NULL terminated list of features supported by QEMU.
 *
 * Returns -1 on error,
 *          0 on success (@features will be NULL if QEMU does not support this),
 *          1 when @features is filled in, but migratability info is not available.
 */
int
virQEMUCapsGetCPUFeatures(virQEMUCapsPtr qemuCaps,
                          virDomainVirtType virtType,
                          bool migratable,
                          char ***features)
{
    qemuMonitorCPUModelInfoPtr modelInfo;
    char **list;
    size_t i;
    size_t n;
    int ret = -1;

    *features = NULL;
    modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, virtType);

    if (!modelInfo)
        return 0;

    if (VIR_ALLOC_N(list, modelInfo->nprops + 1) < 0)
        return -1;

    n = 0;
    for (i = 0; i < modelInfo->nprops; i++) {
        qemuMonitorCPUPropertyPtr prop = modelInfo->props + i;

        if (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO)
            continue;

        if (VIR_STRDUP(list[n++],
                       virQEMUCapsCPUFeatureFromQEMU(qemuCaps, prop->name)) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(*features, list);
    if (migratable && !modelInfo->migratability)
        ret = 1;
    else
        ret = 0;

 cleanup:
    virStringListFree(list);
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
    {
        .type = VIR_DOMAIN_TPM_TYPE_EMULATOR,
        .caps = QEMU_CAPS_DEVICE_TPM_EMULATOR,
    },
};

const struct tpmTypeToCaps virQEMUCapsTPMModelsToCaps[] = {
    {
        .type = VIR_DOMAIN_TPM_MODEL_TIS,
        .caps = QEMU_CAPS_DEVICE_TPM_TIS,
    },
    {
        .type = VIR_DOMAIN_TPM_MODEL_CRB,
        .caps = QEMU_CAPS_DEVICE_TPM_CRB,
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
            if (virStringListHasString((const char **)entries, needle))
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
            if (virStringListHasString((const char **)entries, needle))
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

    if (qemuMonitorGetKVMState(mon, &enabled, &present) < 0)
        return -1;

    if (present && enabled)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_KVM);

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
    { "chardev", "reconnect", QEMU_CAPS_CHARDEV_RECONNECT },
    { "sandbox", "enable", QEMU_CAPS_SECCOMP_SANDBOX },
    { "sandbox", "elevateprivileges", QEMU_CAPS_SECCOMP_BLACKLIST },
    { "chardev", "fd", QEMU_CAPS_CHARDEV_FD_PASS },
    { "overcommit", NULL, QEMU_CAPS_OVERCOMMIT },
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

    if (!(qemuCaps->arch == VIR_ARCH_AARCH64 ||
          qemuCaps->arch == VIR_ARCH_ARMV6L ||
          qemuCaps->arch == VIR_ARCH_ARMV7L))
        return 0;

    if ((ncaps = qemuMonitorGetGICCapabilities(mon, &caps)) < 0)
        return -1;

    virQEMUCapsSetGICCapabilities(qemuCaps, caps, ncaps);

    return 0;
}


static int
virQEMUCapsProbeQMPSEVCapabilities(virQEMUCapsPtr qemuCaps,
                                   qemuMonitorPtr mon)
{
    int rc = -1;
    virSEVCapability *caps = NULL;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST))
        return 0;

    if ((rc = qemuMonitorGetSEVCapabilities(mon, &caps)) < 0)
        return -1;

    /* SEV isn't actually supported */
    if (rc == 0) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_SEV_GUEST);
        return 0;
    }

    virSEVCapabilitiesFree(qemuCaps->sevCapabilities);
    qemuCaps->sevCapabilities = caps;
    return 0;
}


/*
 * Filter for features which should never be passed to QEMU. Either because
 * QEMU never supported them or they were dropped as they never did anything
 * useful.
 */
bool
virQEMUCapsCPUFilterFeatures(const char *name,
                             void *opaque)
{
    virArch *arch = opaque;

    if (!ARCH_IS_X86(*arch))
        return true;

    if (STREQ(name, "cmt") ||
        STREQ(name, "mbm_total") ||
        STREQ(name, "mbm_local") ||
        STREQ(name, "osxsave") ||
        STREQ(name, "ospke"))
        return false;

    return true;
}


typedef struct _virQEMUCapsCPUFeatureTranslationTable virQEMUCapsCPUFeatureTranslationTable;
typedef virQEMUCapsCPUFeatureTranslationTable *virQEMUCapsCPUFeatureTranslationTablePtr;
struct _virQEMUCapsCPUFeatureTranslationTable {
    const char *libvirt;
    const char *qemu;
};

virQEMUCapsCPUFeatureTranslationTable virQEMUCapsCPUFeaturesX86[] = {
    {"cmp_legacy", "cmp-legacy"},
    {"ds_cpl", "ds-cpl"},
    {"fxsr_opt", "fxsr-opt"},
    {"kvm_pv_eoi", "kvm-pv-eoi"},
    {"kvm_pv_unhalt", "kvm-pv-unhalt"},
    {"lahf_lm", "lahf-lm"},
    {"nodeid_msr", "nodeid-msr"},
    {"pclmuldq", "pclmulqdq"},
    {"perfctr_core", "perfctr-core"},
    {"perfctr_nb", "perfctr-nb"},
    {"tsc_adjust", "tsc-adjust"},
    {NULL, NULL}
};


static const char *
virQEMUCapsCPUFeatureTranslate(virQEMUCapsPtr qemuCaps,
                               const char *feature,
                               bool reversed)
{
    virQEMUCapsCPUFeatureTranslationTablePtr table = NULL;
    virQEMUCapsCPUFeatureTranslationTablePtr entry;

    if (ARCH_IS_X86(qemuCaps->arch))
        table = virQEMUCapsCPUFeaturesX86;

    if (!table ||
        !feature ||
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CANONICAL_CPU_FEATURES))
        return feature;

    for (entry = table; entry->libvirt; entry++) {
        const char *key = reversed ? entry->qemu : entry->libvirt;

        if (STREQ(feature, key))
            return reversed ? entry->libvirt : entry->qemu;
    }

    return feature;
}


const char *
virQEMUCapsCPUFeatureToQEMU(virQEMUCapsPtr qemuCaps,
                            const char *feature)
{
    return virQEMUCapsCPUFeatureTranslate(qemuCaps, feature, false);
}


const char *
virQEMUCapsCPUFeatureFromQEMU(virQEMUCapsPtr qemuCaps,
                              const char *feature)
{
    return virQEMUCapsCPUFeatureTranslate(qemuCaps, feature, true);
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to using virCapsPtr->host.cpu,
 *          2 when cpu model info is not supported for this configuration,
 *         -1 on error.
 */
static int
virQEMUCapsInitCPUModelS390(virQEMUCapsPtr qemuCaps,
                            virDomainVirtType type,
                            qemuMonitorCPUModelInfoPtr modelInfo,
                            virCPUDefPtr cpu,
                            bool migratable)
{
    size_t i;

    if (!modelInfo) {
        if (type == VIR_DOMAIN_VIRT_KVM) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing host CPU model info from QEMU "
                             "capabilities for binary %s"),
                           qemuCaps->binary);
            return -1;
        }
        return 2;
    }

    if (VIR_STRDUP(cpu->model, modelInfo->name) < 0 ||
        VIR_ALLOC_N(cpu->features, modelInfo->nprops) < 0)
        return -1;

    cpu->nfeatures_max = modelInfo->nprops;
    cpu->nfeatures = 0;

    for (i = 0; i < modelInfo->nprops; i++) {
        virCPUFeatureDefPtr feature = cpu->features + cpu->nfeatures;
        qemuMonitorCPUPropertyPtr prop = modelInfo->props + i;
        const char *name = virQEMUCapsCPUFeatureFromQEMU(qemuCaps, prop->name);

        if (prop->type != QEMU_MONITOR_CPU_PROPERTY_BOOLEAN)
            continue;

        if (VIR_STRDUP(feature->name, name) < 0)
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


virCPUDataPtr
virQEMUCapsGetCPUModelX86Data(virQEMUCapsPtr qemuCaps,
                              qemuMonitorCPUModelInfoPtr model,
                              bool migratable)
{
    unsigned long long sigFamily = 0;
    unsigned long long sigModel = 0;
    unsigned long long sigStepping = 0;
    virCPUDataPtr data = NULL;
    virCPUDataPtr ret = NULL;
    size_t i;

    if (!(data = virCPUDataNew(VIR_ARCH_X86_64)))
        goto cleanup;

    for (i = 0; i < model->nprops; i++) {
        qemuMonitorCPUPropertyPtr prop = model->props + i;
        const char *name = virQEMUCapsCPUFeatureFromQEMU(qemuCaps, prop->name);

        switch (prop->type) {
        case QEMU_MONITOR_CPU_PROPERTY_BOOLEAN:
            if (!prop->value.boolean ||
                (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO))
                continue;

            if (virCPUDataAddFeature(data, name) < 0)
                goto cleanup;

            break;

        case QEMU_MONITOR_CPU_PROPERTY_STRING:
            if (STREQ(name, "vendor") &&
                virCPUx86DataSetVendor(data, prop->value.string) < 0)
                goto cleanup;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_NUMBER:
            if (STREQ(name, "family"))
                sigFamily = prop->value.number;
            else if (STREQ(name, "model"))
                sigModel = prop->value.number;
            else if (STREQ(name, "stepping"))
                sigStepping = prop->value.number;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_LAST:
            break;
        }
    }

    if (virCPUx86DataSetSignature(data, sigFamily, sigModel, sigStepping) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, data);

 cleanup:
    virCPUDataFree(data);
    return ret;
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
    int ret = -1;

    if (!model)
        return 1;

    if (!(data = virQEMUCapsGetCPUModelX86Data(qemuCaps, model, migratable)))
        goto cleanup;

    if (cpuDecode(cpu, data, virQEMUCapsGetCPUDefinitions(qemuCaps, type)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCPUDataFree(data);
    return ret;
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to other methods,
 *          2 when cpu model info is not supported for this configuration,
 *         -1 on error.
 */
int
virQEMUCapsInitCPUModel(virQEMUCapsPtr qemuCaps,
                        virDomainVirtType type,
                        virCPUDefPtr cpu,
                        bool migratable)
{
    qemuMonitorCPUModelInfoPtr modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, type);
    int ret = 1;

    if (migratable && modelInfo && !modelInfo->migratability)
        return 1;

    if (ARCH_IS_S390(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelS390(qemuCaps, type, modelInfo,
                                          cpu, migratable);
    } else if (ARCH_IS_X86(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelX86(qemuCaps, type, modelInfo,
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
    virCPUDefPtr cpuExpanded = NULL;
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

        hostCPU = virQEMUCapsProbeHostCPU(hostArch,
                                          virQEMUCapsGetCPUDefinitions(qemuCaps, type));
        if (!hostCPU ||
            virCPUDefCopyModelFilter(cpu, hostCPU, true,
                                     virQEMUCapsCPUFilterFeatures,
                                     &qemuCaps->arch) < 0)
            goto error;
    } else if (rc == 2) {
        VIR_DEBUG("QEMU does not provide CPU model for arch=%s virttype=%s",
                  virArchToString(qemuCaps->arch),
                  virDomainVirtTypeToString(type));
        goto error;
    } else if (type == VIR_DOMAIN_VIRT_KVM &&
               virCPUGetHostIsSupported(qemuCaps->arch)) {
        if (!(fullCPU = virQEMUCapsProbeHostCPU(qemuCaps->arch, NULL)))
            goto error;

        if (!(cpuExpanded = virCPUDefCopy(cpu)) ||
            virCPUExpandFeatures(qemuCaps->arch, cpuExpanded) < 0)
            goto error;

        for (i = 0; i < cpuExpanded->nfeatures; i++) {
            if (cpuExpanded->features[i].policy == VIR_CPU_FEATURE_REQUIRE &&
                virCPUDefUpdateFeature(fullCPU, cpuExpanded->features[i].name,
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

    if (ARCH_IS_X86(qemuCaps->arch) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES)) {
        if (cpu &&
            virCPUDefFilterFeatures(cpu, virCPUx86FeatureFilterDropMSR, NULL) < 0)
            goto error;

        if (migCPU &&
            virCPUDefFilterFeatures(migCPU, virCPUx86FeatureFilterDropMSR, NULL) < 0)
            goto error;

        if (fullCPU &&
            virCPUDefFilterFeatures(fullCPU, virCPUx86FeatureFilterDropMSR, NULL) < 0)
            goto error;
    }

    virQEMUCapsSetHostModel(qemuCaps, type, cpu, migCPU, fullCPU);

 cleanup:
    virCPUDefFree(cpuExpanded);
    virCPUDefFree(hostCPU);
    return;

 error:
    virCPUDefFree(cpu);
    virCPUDefFree(migCPU);
    virCPUDefFree(fullCPU);
    virResetLastError();
    goto cleanup;
}


qemuMonitorCPUModelInfoPtr
virQEMUCapsGetCPUModelInfo(virQEMUCapsPtr qemuCaps,
                           virDomainVirtType type)
{
    virQEMUCapsHostCPUDataPtr cpuData = virQEMUCapsGetHostCPUData(qemuCaps, type);

    return cpuData->info;
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
    VIR_XPATH_NODE_AUTORESTORE(ctxt);
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
    xmlNodePtr node;
    xmlNodePtr *blockerNodes = NULL;
    char **blockers = NULL;
    int nblockers;

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

        node = ctxt->node;
        ctxt->node = nodes[i];
        nblockers = virXPathNodeSet("./blocker", ctxt, &blockerNodes);
        ctxt->node = node;

        if (nblockers < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse CPU blockers in QEMU capabilities"));
            goto cleanup;
        }

        if (nblockers > 0) {
            size_t j;

            if (VIR_ALLOC_N(blockers, nblockers + 1) < 0)
                goto cleanup;

            for (j = 0; j < nblockers; j++) {
                if (!(blockers[j] = virXMLPropString(blockerNodes[j], "name"))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("missing blocker name in QEMU "
                                     "capabilities cache"));
                    goto cleanup;
                }
            }
            VIR_FREE(blockerNodes);
        }

        if (virDomainCapsCPUModelsAddSteal(cpus, &str, usable, &blockers) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(str);
    VIR_FREE(blockerNodes);
    virStringListFree(blockers);
    return ret;
}


struct _virQEMUCapsCachePriv {
    char *libDir;
    uid_t runUid;
    gid_t runGid;
    virArch hostArch;
    unsigned int microcodeVersion;
    char *kernelVersion;

    /* cache whether /dev/kvm is usable as runUid:runGuid */
    virTristateBool kvmUsable;
    time_t kvmCtime;
};
typedef struct _virQEMUCapsCachePriv virQEMUCapsCachePriv;
typedef virQEMUCapsCachePriv *virQEMUCapsCachePrivPtr;


static void
virQEMUCapsCachePrivFree(void *privData)
{
    virQEMUCapsCachePrivPtr priv = privData;

    VIR_FREE(priv->libDir);
    VIR_FREE(priv->kernelVersion);
    VIR_FREE(priv);
}


static int
virQEMUCapsParseSEVInfo(virQEMUCapsPtr qemuCaps, xmlXPathContextPtr ctxt)
{
    VIR_AUTOPTR(virSEVCapability) sev = NULL;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST))
        return 0;

    if (virXPathBoolean("boolean(./sev)", ctxt) == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing SEV platform data in QEMU "
                         "capabilities cache"));
        return -1;
    }

    if (VIR_ALLOC(sev) < 0)
        return -1;

    if (virXPathUInt("string(./sev/cbitpos)", ctxt, &sev->cbitpos) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing or malformed SEV cbitpos information "
                         "in QEMU capabilities cache"));
        return -1;
    }

    if (virXPathUInt("string(./sev/reducedPhysBits)", ctxt,
                     &sev->reduced_phys_bits) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing or malformed SEV reducedPhysBits information "
                         "in QEMU capabilities cache"));
        return -1;
    }

    if (!(sev->pdh = virXPathString("string(./sev/pdh)", ctxt)))  {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing SEV pdh information "
                         "in QEMU capabilities cache"));
        return -1;
    }

    if (!(sev->cert_chain = virXPathString("string(./sev/certChain)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing SEV certChain information "
                         "in QEMU capabilities cache"));
        return -1;
    }

    VIR_STEAL_PTR(qemuCaps->sevCapabilities, sev);
    return 0;
}


/*
 * Parsing a doc that looks like
 *
 * <qemuCaps>
 *   <qemuctime>234235253</qemuctime>
 *   <selfctime>234235253</selfctime>
 *   <selfvers>1002016</selfvers>
 *   <flag name='foo'/>
 *   <flag name='bar'/>
 *   ...
 *   <cpu name="pentium3"/>
 *   ...
 *   <machine name="pc-1.0" alias="pc" hotplugCpus='yes' maxCpus="4" default="yes"/>
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

    if (!(ctxt = virXMLXPathContextNew(doc)))
        goto cleanup;

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

    if (virXPathUInt("string(./microcodeVersion)", ctxt,
                     &qemuCaps->microcodeVersion) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing microcode version in QEMU capabilities cache"));
        goto cleanup;
    }

    if (virXPathBoolean("boolean(./package)", ctxt) > 0) {
        qemuCaps->package = virXPathString("string(./package)", ctxt);
        if (!qemuCaps->package &&
            VIR_STRDUP(qemuCaps->package, "") < 0)
            goto cleanup;
    }

    if (virXPathBoolean("boolean(./kernelVersion)", ctxt) > 0) {
        qemuCaps->kernelVersion = virXPathString("string(./kernelVersion)", ctxt);
        if (!qemuCaps->kernelVersion)
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

            str = virXMLPropString(nodes[i], "default");
            if (STREQ_NULLABLE(str, "yes"))
                qemuCaps->machineTypes[i].qemuDefault = true;
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

    if (virQEMUCapsParseSEVInfo(qemuCaps, ctxt) < 0)
        goto cleanup;

    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_QEMU);

    if (virXPathBoolean("boolean(./kvmSupportsNesting)", ctxt) > 0)
        qemuCaps->kvmSupportsNesting = true;

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
    qemuMonitorCPUModelInfoPtr model = virQEMUCapsGetCPUModelInfo(qemuCaps, type);
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

        if (cpu->blockers) {
            size_t j;

            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);

            for (j = 0; cpu->blockers[j]; j++)
                virBufferAsprintf(buf, "<blocker name='%s'/>\n", cpu->blockers[j]);

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</cpu>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    }
}


static void
virQEMUCapsFormatSEVInfo(virQEMUCapsPtr qemuCaps, virBufferPtr buf)
{
    virSEVCapabilityPtr sev = virQEMUCapsGetSEVCapabilities(qemuCaps);

    virBufferAddLit(buf, "<sev>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<cbitpos>%u</cbitpos>\n", sev->cbitpos);
    virBufferAsprintf(buf, "<reducedPhysBits>%u</reducedPhysBits>\n",
                      sev->reduced_phys_bits);
    virBufferEscapeString(buf, "<pdh>%s</pdh>\n", sev->pdh);
    virBufferEscapeString(buf, "<certChain>%s</certChain>\n",
                          sev->cert_chain);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</sev>\n");
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
                      (long long)qemuCaps->ctime);
    virBufferAsprintf(&buf, "<selfctime>%llu</selfctime>\n",
                      (long long)qemuCaps->libvirtCtime);
    virBufferAsprintf(&buf, "<selfvers>%lu</selfvers>\n",
                      (unsigned long)qemuCaps->libvirtVersion);

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

    virBufferAsprintf(&buf, "<microcodeVersion>%u</microcodeVersion>\n",
                      qemuCaps->microcodeVersion);

    if (qemuCaps->package)
        virBufferAsprintf(&buf, "<package>%s</package>\n",
                          qemuCaps->package);

    if (qemuCaps->kernelVersion)
        virBufferAsprintf(&buf, "<kernelVersion>%s</kernelVersion>\n",
                          qemuCaps->kernelVersion);

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
        virBufferAsprintf(&buf, " maxCpus='%u'",
                          qemuCaps->machineTypes[i].maxCpus);
        if (qemuCaps->machineTypes[i].qemuDefault)
            virBufferAddLit(&buf, " default='yes'");
        virBufferAddLit(&buf, "/>\n");
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

    if (qemuCaps->sevCapabilities)
        virQEMUCapsFormatSEVInfo(qemuCaps, &buf);

    if (qemuCaps->kvmSupportsNesting)
        virBufferAddLit(&buf, "<kvmSupportsNesting/>\n");

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


/* Check the kernel module parameters 'nested' file to determine if enabled
 *
 *   Intel: 'kvm_intel' uses 'Y'
 *   AMD:   'kvm_amd' uses '1'
 *   PPC64: 'kvm_hv' uses 'Y'
 *   S390:  'kvm' uses '1'
 */
static bool
virQEMUCapsKVMSupportsNesting(void)
{
    static char const * const kmod[] = {"kvm_intel", "kvm_amd",
                                        "kvm_hv", "kvm"};
    VIR_AUTOFREE(char *) value = NULL;
    int rc;
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(kmod); i++) {
        VIR_FREE(value);
        rc = virFileReadValueString(&value, "/sys/module/%s/parameters/nested",
                                    kmod[i]);
        if (rc == -2)
            continue;
        if (rc < 0) {
            virResetLastError();
            return false;
        }

        if (value[0] == 'Y' || value[0] == 'y' || value[0] == '1')
            return true;
    }

    return false;
}


/* Determine whether '/dev/kvm' is usable as QEMU user:QEMU group. */
static bool
virQEMUCapsKVMUsable(virQEMUCapsCachePrivPtr priv)
{
    struct stat sb;
    static const char *kvm_device = "/dev/kvm";
    virTristateBool value;
    virTristateBool cached_value = priv->kvmUsable;
    time_t kvm_ctime;
    time_t cached_kvm_ctime = priv->kvmCtime;

    if (stat(kvm_device, &sb) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Failed to stat %s"), kvm_device);
        }
        return false;
    }
    kvm_ctime = sb.st_ctime;

    if (kvm_ctime != cached_kvm_ctime) {
        VIR_DEBUG("%s has changed (%lld vs %lld)", kvm_device,
                  (long long)kvm_ctime, (long long)cached_kvm_ctime);
        cached_value = VIR_TRISTATE_BOOL_ABSENT;
    }

    if (cached_value != VIR_TRISTATE_BOOL_ABSENT)
        return cached_value == VIR_TRISTATE_BOOL_YES;

    if (virFileAccessibleAs(kvm_device, R_OK | W_OK,
                            priv->runUid, priv->runGid) == 0) {
        value = VIR_TRISTATE_BOOL_YES;
    } else {
        value = VIR_TRISTATE_BOOL_NO;
    }

    /* There is a race window between 'stat' and
     * 'virFileAccessibleAs'. However, since we're only interested in
     * detecting changes *after* the virFileAccessibleAs check, we can
     * neglect this here.
     */
    priv->kvmCtime = kvm_ctime;
    priv->kvmUsable = value;

    return value == VIR_TRISTATE_BOOL_YES;
}


static bool
virQEMUCapsIsValid(void *data,
                   void *privData)
{
    virQEMUCapsPtr qemuCaps = data;
    virQEMUCapsCachePrivPtr priv = privData;
    bool kvmUsable;
    struct stat sb;
    bool kvmSupportsNesting;

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
                  (long long)sb.st_ctime, (long long)qemuCaps->ctime);
        return false;
    }

    if (!virQEMUCapsGuestIsNative(priv->hostArch, qemuCaps->arch)) {
        VIR_DEBUG("Guest arch (%s) is not native to host arch (%s), "
                  "skipping KVM-related checks",
                  virArchToString(qemuCaps->arch),
                  virArchToString(priv->hostArch));
        return true;
    }

    kvmUsable = virQEMUCapsKVMUsable(priv);

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
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

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        if (priv->microcodeVersion != qemuCaps->microcodeVersion) {
            VIR_DEBUG("Outdated capabilities for '%s': microcode version "
                      "changed (%u vs %u)",
                      qemuCaps->binary,
                      priv->microcodeVersion,
                      qemuCaps->microcodeVersion);
            return false;
        }

        if (STRNEQ_NULLABLE(priv->kernelVersion, qemuCaps->kernelVersion)) {
            VIR_DEBUG("Outdated capabilities for '%s': kernel version changed "
                      "('%s' vs '%s')",
                      qemuCaps->binary,
                      priv->kernelVersion,
                      qemuCaps->kernelVersion);
            return false;
        }

        kvmSupportsNesting = virQEMUCapsKVMSupportsNesting();
        if (kvmSupportsNesting != qemuCaps->kvmSupportsNesting) {
            VIR_DEBUG("Outdated capabilities for '%s': kvm kernel nested "
                      "value changed from %d",
                     qemuCaps->binary, qemuCaps->kvmSupportsNesting);
            return false;
        }
    }

    return true;
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

    /* HPET is x86 specific */
    if (ARCH_IS_X86(qemuCaps->arch))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_HPET);
}


/**
 * virQEMUCapsInitQMPVersionCaps:
 * @qemuCaps: QEMU capabilities
 *
 * Add all QEMU capabilities based on version of QEMU.
 */
static void
virQEMUCapsInitQMPVersionCaps(virQEMUCapsPtr qemuCaps)
{
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

    /* sdl -gl option is supported from v2.4.0 (qemu commit id 0b71a5d5) */
    if (qemuCaps->version >= 2004000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SDL_GL);

    /* Since 2.4.50 ARM virt machine supports gic-version option */
    if (qemuCaps->version >= 2004050)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACH_VIRT_GIC_VERSION);

    /* no way to query if -machine kernel_irqchip supports split */
    if (qemuCaps->version >= 2006000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT);

    /* HPT resizing is supported since QEMU 2.10 on ppc64; unfortunately
     * there's no sane way to probe for it */
    if (qemuCaps->version >= 2010000 &&
        ARCH_IS_PPC64(qemuCaps->arch)) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);
    }

    /* '-display egl-headless' cmdline option is supported since QEMU 2.10, but
     * there's no way to probe it */
    if (qemuCaps->version >= 2010000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_EGL_HEADLESS);

    /* no way to query for -numa dist */
    if (qemuCaps->version >= 2010000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NUMA_DIST);

    /* no way to query max-cpu-compat */
    if (qemuCaps->version >= 2010000 &&
        ARCH_IS_PPC64(qemuCaps->arch)) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_MAX_CPU_COMPAT);
    }
}


/**
 * virQEMUCapsInitProcessCaps:
 * @qemuCaps: QEMU capabilities
 *
 * Some capability bits are enabled or disabled according to specific logic.
 * This function collects all capability processing after the capabilities
 * are detected.
 */
static void
virQEMUCapsInitProcessCaps(virQEMUCapsPtr qemuCaps)
{
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

    /* Prealloc on NVDIMMs is broken on older QEMUs leading to
     * user data corruption. If we are dealing with such version
     * of QEMU pretend we don't know how to NVDIMM. */
    if (qemuCaps->version < 2009000 &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM);

    if (ARCH_IS_X86(qemuCaps->arch) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_CACHE);

    if (ARCH_IS_S390(qemuCaps->arch)) {
        /* Legacy assurance for QEMU_CAPS_CCW */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCW) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_CCW))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_CCW);
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCW_CSSID_UNRESTRICTED))
            virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_VFIO_CCW);
    }

    /* To avoid guest ABI regression, blockdev shall be enabled only when
     * we are able to pass the custom 'device_id' for SCSI disks and cdroms. */
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_DEVICE_ID))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_BLOCKDEV);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CANONICAL_CPU_FEATURES);
}


static int
virQEMUCapsProbeQMPSchemaCapabilities(virQEMUCapsPtr qemuCaps,
                                      qemuMonitorPtr mon)
{
    struct virQEMUCapsStringFlags *entry;
    virJSONValuePtr schemareply;
    virHashTablePtr schema = NULL;
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_QMP_SCHEMA))
        return 0;

    if (!(schemareply = qemuMonitorQueryQMPSchema(mon)))
        return -1;

    if (!(schema = virQEMUQAPISchemaConvert(schemareply)))
        return -1;
    schemareply = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsQMPSchemaQueries); i++) {
        entry = virQEMUCapsQMPSchemaQueries + i;

        if (virQEMUQAPISchemaPathExists(entry->value, schema))
            virQEMUCapsSet(qemuCaps, entry->flag);
    }

    /* probe also for basic event support */
    for (i = 0; i < ARRAY_CARDINALITY(virQEMUCapsEvents); i++) {
        entry = virQEMUCapsEvents + i;

        if (virQEMUQAPISchemaPathExists(entry->value, schema))
            virQEMUCapsSet(qemuCaps, entry->flag);
    }

    virHashFree(schema);
    return 0;
}

#define QEMU_MIN_MAJOR 1
#define QEMU_MIN_MINOR 5
#define QEMU_MIN_MICRO 0

int
virQEMUCapsInitQMPMonitor(virQEMUCapsPtr qemuCaps,
                          qemuMonitorPtr mon)
{
    int major, minor, micro;
    VIR_AUTOFREE(char *) package = NULL;

    /* @mon is supposed to be locked by callee */

    if (qemuMonitorGetVersion(mon, &major, &minor, &micro, &package) < 0)
        return -1;

    VIR_DEBUG("Got version %d.%d.%d (%s)",
              major, minor, micro, NULLSTR(package));

    if (major < QEMU_MIN_MAJOR ||
        (major == QEMU_MIN_MAJOR && minor < QEMU_MIN_MINOR)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("QEMU version >= %d.%d.%d is required, but %d.%d.%d found"),
                       QEMU_MIN_MAJOR, QEMU_MIN_MINOR, QEMU_MIN_MICRO,
                       major, minor, micro);
        return -1;
    }

    qemuCaps->version = major * 1000000 + minor * 1000 + micro;
    VIR_STEAL_PTR(qemuCaps->package, package);
    qemuCaps->usedQMP = true;

    if (virQEMUCapsInitQMPArch(qemuCaps, mon) < 0)
        return -1;

    virQEMUCapsInitQMPBasicArch(qemuCaps);

    /* initiate all capapbilities based on qemu version */
    virQEMUCapsInitQMPVersionCaps(qemuCaps);

    if (virQEMUCapsProbeQMPCommands(qemuCaps, mon) < 0)
        return -1;

    /* Some capabilities may differ depending on KVM state */
    if (virQEMUCapsProbeQMPKVMState(qemuCaps, mon) < 0)
        return -1;

    if (virQEMUCapsProbeQMPEvents(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPDevices(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMachineTypes(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMachineProps(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, mon, false) < 0)
        return -1;
    if (virQEMUCapsProbeQMPTPM(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPCommandLine(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMigrationCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPSchemaCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPGICCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPSEVCapabilities(qemuCaps, mon) < 0)
        return -1;

    virQEMUCapsInitProcessCaps(qemuCaps);

    /* The following probes rely on other previously probed capabilities.
     * No capabilities bits should be set below this point. */

    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, mon, false) < 0)
        return -1;

    return 0;
}


int
virQEMUCapsInitQMPMonitorTCG(virQEMUCapsPtr qemuCaps,
                             qemuMonitorPtr mon)
{
    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, mon, true) < 0)
        return -1;

    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, mon, true) < 0)
        return -1;

    return 0;
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


static int
virQEMUCapsInitQMPSingle(virQEMUCapsPtr qemuCaps,
                         const char *libDir,
                         uid_t runUid,
                         gid_t runGid,
                         bool onlyTCG)
{
    qemuProcessQMPPtr proc = NULL;
    int ret = -1;

    if (!(proc = qemuProcessQMPNew(qemuCaps->binary, libDir,
                                   runUid, runGid, onlyTCG)))
        goto cleanup;

    if (qemuProcessQMPStart(proc) < 0)
        goto cleanup;

    if (onlyTCG)
        ret = virQEMUCapsInitQMPMonitorTCG(qemuCaps, proc->mon);
    else
        ret = virQEMUCapsInitQMPMonitor(qemuCaps, proc->mon);

 cleanup:
    if (ret < 0)
        virQEMUCapsLogProbeFailure(qemuCaps->binary);

    qemuProcessQMPFree(proc);
    return ret;
}


static int
virQEMUCapsInitQMP(virQEMUCapsPtr qemuCaps,
                   const char *libDir,
                   uid_t runUid,
                   gid_t runGid)
{
    if (virQEMUCapsInitQMPSingle(qemuCaps, libDir, runUid, runGid, false) < 0)
        return -1;

    /*
     * If KVM was enabled during the first probe, we need to explicitly probe
     * for TCG capabilities by asking the same binary again and turning KVM
     * off.
     */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
        virQEMUCapsInitQMPSingle(qemuCaps, libDir, runUid, runGid, true) < 0)
        return -1;

    return 0;
}


virQEMUCapsPtr
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                unsigned int microcodeVersion,
                                const char *kernelVersion)
{
    virQEMUCapsPtr qemuCaps;
    struct stat sb;

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

    if (virQEMUCapsInitQMP(qemuCaps, libDir, runUid, runGid) < 0)
        goto error;

    qemuCaps->libvirtCtime = virGetSelfLastChanged();
    qemuCaps->libvirtVersion = LIBVIR_VERSION_NUMBER;

    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_QEMU);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        qemuCaps->microcodeVersion = microcodeVersion;

        if (VIR_STRDUP(qemuCaps->kernelVersion, kernelVersion) < 0)
            goto error;

        qemuCaps->kvmSupportsNesting = virQEMUCapsKVMSupportsNesting();
    }

 cleanup:
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
                                           virHostCPUGetMicrocodeVersion(),
                                           priv->kernelVersion);
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
    struct utsname uts;

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
    priv->kvmUsable = VIR_TRISTATE_BOOL_ABSENT;

    if (uname(&uts) == 0 &&
        virAsprintf(&priv->kernelVersion, "%s %s", uts.release, uts.version) < 0)
        goto error;

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
    virQEMUCapsCachePrivPtr priv = virFileCacheGetPriv(cache);
    virQEMUCapsPtr ret = NULL;

    priv->microcodeVersion = virHostCPUGetMicrocodeVersion();

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
    struct virQEMUCapsSearchData *data = (struct virQEMUCapsSearchData *)opaque;
    const virQEMUCaps *qemuCaps = payload;

    if (qemuCaps->arch != data->arch)
        return false;

    if (data->binaryFilter &&
        !strstr(qemuCaps->binary, data->binaryFilter)) {
        return false;
    }

    return true;
}


virQEMUCapsPtr
virQEMUCapsCacheLookupByArch(virFileCachePtr cache,
                             virArch arch)
{
    virQEMUCapsCachePrivPtr priv = virFileCacheGetPriv(cache);
    virQEMUCapsPtr ret = NULL;
    const char *binaryFilters[] = {
        "qemu-system-",
        NULL,
    };
    virArch archs[] = {
        arch,
        virQEMUCapsFindTarget(virArchFromHost(), arch),
    };
    size_t i;
    size_t j;

    priv->microcodeVersion = virHostCPUGetMicrocodeVersion();

    for (i = 0; i < ARRAY_CARDINALITY(binaryFilters); i++) {
        for (j = 0; j < ARRAY_CARDINALITY(archs); j++) {
            struct virQEMUCapsSearchData data = {
                .arch = archs[j],
                .binaryFilter = binaryFilters[i],
            };

            ret = virFileCacheLookupByFunc(cache, virQEMUCapsCompareArch, &data);
            if (ret)
                goto done;
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("unable to find any emulator to serve '%s' "
                     "architecture"), virArchToString(arch));

 done:
    VIR_DEBUG("Returning caps %p for arch %s", ret, virArchToString(arch));

    return ret;
}


/**
 * virQEMUCapsCacheLookupDefault:
 * @cache: QEMU capabilities cache
 * @binary: optional path to QEMU binary
 * @archStr: optional guest architecture
 * @virttypeStr: optional virt type
 * @machine: optional machine type
 * @retArch: if non-NULL, guest architecture will be returned here
 * @retVirttype: if non-NULL, domain virt type will be returned here
 * @retMachine: if non-NULL, canonical machine type will be returned here
 *
 * Looks up the QEMU binary specified by @binary and @archStr, checks it can
 * provide the required @virttypeStr and @machine and returns its capabilities.
 * Sensible defaults are used for any argument which is NULL (the function can
 * even be called with all NULL arguments).
 *
 * Returns QEMU capabilities matching the requirements, NULL on error.
 */
virQEMUCapsPtr
virQEMUCapsCacheLookupDefault(virFileCachePtr cache,
                              const char *binary,
                              const char *archStr,
                              const char *virttypeStr,
                              const char *machine,
                              virArch *retArch,
                              virDomainVirtType *retVirttype,
                              const char **retMachine)
{
    int virttype = VIR_DOMAIN_VIRT_NONE;
    int arch = virArchFromHost();
    virDomainVirtType capsType;
    virQEMUCapsPtr qemuCaps = NULL;
    virQEMUCapsPtr ret = NULL;

    if (virttypeStr &&
        (virttype = virDomainVirtTypeFromString(virttypeStr)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %s"), virttypeStr);
        goto cleanup;
    }

    if (archStr &&
        (arch = virArchFromString(archStr)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %s"), archStr);
        goto cleanup;
    }

    if (binary) {
        virArch arch_from_caps;

        if (!(qemuCaps = virQEMUCapsCacheLookup(cache, binary)))
            goto cleanup;

        arch_from_caps = virQEMUCapsGetArch(qemuCaps);

        if (arch_from_caps != arch &&
            !((ARCH_IS_X86(arch) && ARCH_IS_X86(arch_from_caps)) ||
              (ARCH_IS_PPC(arch) && ARCH_IS_PPC(arch_from_caps)) ||
              (ARCH_IS_ARM(arch) && ARCH_IS_ARM(arch_from_caps)) ||
              (ARCH_IS_S390(arch) && ARCH_IS_S390(arch_from_caps)))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("architecture from emulator '%s' doesn't "
                             "match given architecture '%s'"),
                           virArchToString(arch_from_caps),
                           virArchToString(arch));
            goto cleanup;
        }
    } else {
        if (!(qemuCaps = virQEMUCapsCacheLookupByArch(cache, arch)))
            goto cleanup;

        binary = virQEMUCapsGetBinary(qemuCaps);
    }

    if (machine) {
        /* Turn @machine into canonical name */
        machine = virQEMUCapsGetCanonicalMachine(qemuCaps, machine);

        if (!virQEMUCapsIsMachineSupported(qemuCaps, machine)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("the machine '%s' is not supported by emulator '%s'"),
                           machine, binary);
            goto cleanup;
        }
    } else {
        machine = virQEMUCapsGetPreferredMachine(qemuCaps);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        capsType = VIR_DOMAIN_VIRT_KVM;
    else
        capsType = VIR_DOMAIN_VIRT_QEMU;

    if (virttype == VIR_DOMAIN_VIRT_NONE)
        virttype = capsType;

    if (virttype == VIR_DOMAIN_VIRT_KVM && capsType == VIR_DOMAIN_VIRT_QEMU) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("KVM is not supported by '%s' on this host"),
                       binary);
        goto cleanup;
    }

    if (retArch)
        *retArch = arch;
    if (retVirttype)
        *retVirttype = virttype;
    if (retMachine)
        *retMachine = machine;

    VIR_STEAL_PTR(ret, qemuCaps);

 cleanup:
    virObjectUnref(qemuCaps);
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


/*
 * The preferred machine to use if none is listed explicitly
 * Note that this may differ from QEMU's own default machine
 */
const char *
virQEMUCapsGetPreferredMachine(virQEMUCapsPtr qemuCaps)
{
    if (!qemuCaps->nmachineTypes)
        return NULL;
    return qemuCaps->machineTypes[0].name;
}


static int
virQEMUCapsFillDomainLoaderCaps(virDomainCapsLoaderPtr capsLoader,
                                bool secure,
                                virFirmwarePtr *firmwares,
                                size_t nfirmwares)
{
    size_t i;

    capsLoader->supported = VIR_TRISTATE_BOOL_YES;
    capsLoader->type.report = true;
    capsLoader->readonly.report = true;
    capsLoader->secure.report = true;

    if (VIR_ALLOC_N(capsLoader->values.values, nfirmwares) < 0)
        return -1;

    for (i = 0; i < nfirmwares; i++) {
        const char *filename = firmwares[i]->name;
        size_t j;

        if (!virFileExists(filename)) {
            VIR_DEBUG("loader filename=%s does not exist", filename);
            continue;
        }

        /* Put only unique FW images onto the list */
        for (j = 0; j < capsLoader->values.nvalues; j++) {
            if (STREQ(filename, capsLoader->values.values[j]))
                break;
        }

        if (j != capsLoader->values.nvalues)
            continue;

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

    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->secure,
                             VIR_TRISTATE_BOOL_NO);

    if (secure)
        VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->secure,
                                 VIR_TRISTATE_BOOL_YES);

    return 0;
}


static int
virQEMUCapsFillDomainOSCaps(virDomainCapsOSPtr os,
                            const char *machine,
                            virArch arch,
                            bool privileged,
                            virFirmwarePtr *firmwares,
                            size_t nfirmwares)
{
    virDomainCapsLoaderPtr capsLoader = &os->loader;
    uint64_t autoFirmwares = 0;
    bool secure = false;
    virFirmwarePtr *firmwaresAlt = NULL;
    size_t nfirmwaresAlt = 0;
    int ret = -1;

    os->supported = VIR_TRISTATE_BOOL_YES;
    os->firmware.report = true;

    if (qemuFirmwareGetSupported(machine, arch, privileged,
                                 &autoFirmwares, &secure,
                                 &firmwaresAlt, &nfirmwaresAlt) < 0)
        return -1;

    if (autoFirmwares & (1ULL << VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS))
        VIR_DOMAIN_CAPS_ENUM_SET(os->firmware, VIR_DOMAIN_OS_DEF_FIRMWARE_BIOS);
    if (autoFirmwares & (1ULL << VIR_DOMAIN_OS_DEF_FIRMWARE_EFI))
        VIR_DOMAIN_CAPS_ENUM_SET(os->firmware, VIR_DOMAIN_OS_DEF_FIRMWARE_EFI);

    if (virQEMUCapsFillDomainLoaderCaps(capsLoader, secure,
                                        firmwaresAlt ? firmwaresAlt : firmwares,
                                        firmwaresAlt ? nfirmwaresAlt : nfirmwares) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virFirmwareFreeList(firmwaresAlt, nfirmwaresAlt);
    return ret;
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
                                                    (const char **)models,
                                                    blacklist);
            virStringListFree(models);
        }
        domCaps->cpu.custom = filtered;
    }

    return 0;
}


static int
virQEMUCapsFillDomainIOThreadCaps(virQEMUCapsPtr qemuCaps,
                                  virDomainCapsPtr domCaps)
{
    domCaps->iothreads = virTristateBoolFromBool(
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD));

    return 0;
}


static int
virQEMUCapsFillDomainDeviceDiskCaps(virQEMUCapsPtr qemuCaps,
                                    const char *machine,
                                    virDomainCapsDeviceDiskPtr disk)
{
    disk->supported = VIR_TRISTATE_BOOL_YES;
    disk->diskDevice.report = true;
    disk->bus.report = true;
    disk->model.report = true;

    /* QEMU supports all of these */
    VIR_DOMAIN_CAPS_ENUM_SET(disk->diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM,
                             VIR_DOMAIN_DISK_DEVICE_LUN);

    /* PowerPC pseries based VMs do not support floppy device */
    if (!qemuDomainMachineIsPSeries(machine, qemuCaps->arch)) {
        VIR_DOMAIN_CAPS_ENUM_SET(disk->diskDevice, VIR_DOMAIN_DISK_DEVICE_FLOPPY);
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_FDC);
    }

    if (qemuDomainMachineHasBuiltinIDE(machine, qemuCaps->arch))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_IDE);

    VIR_DOMAIN_CAPS_ENUM_SET(disk->bus,
                             VIR_DOMAIN_DISK_BUS_SCSI,
                             VIR_DOMAIN_DISK_BUS_VIRTIO,
                             /* VIR_DOMAIN_DISK_BUS_SD */);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_USB);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_AHCI))
        VIR_DOMAIN_CAPS_ENUM_SET(disk->bus, VIR_DOMAIN_DISK_BUS_SATA);

    /* disk->model values */
    VIR_DOMAIN_CAPS_ENUM_SET(disk->model, VIR_DOMAIN_DISK_MODEL_VIRTIO);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL)) {
        VIR_DOMAIN_CAPS_ENUM_SET(disk->model,
                                 VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL);
        VIR_DOMAIN_CAPS_ENUM_SET(disk->model,
                                 VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL);
    }

    return 0;
}


static int
virQEMUCapsFillDomainDeviceGraphicsCaps(virQEMUCapsPtr qemuCaps,
                                        virDomainCapsDeviceGraphicsPtr dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->type.report = true;

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
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->modelType.report = true;

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
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_BOCHS_DISPLAY))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_BOCHS);

    return 0;
}


static int
virQEMUCapsFillDomainDeviceHostdevCaps(virQEMUCapsPtr qemuCaps,
                                       virDomainCapsDeviceHostdevPtr hostdev)
{
    bool supportsPassthroughVFIO = qemuHostdevHostSupportsPassthroughVFIO();

    hostdev->supported = VIR_TRISTATE_BOOL_YES;
    hostdev->mode.report = true;
    hostdev->startupPolicy.report = true;
    hostdev->subsysType.report = true;
    hostdev->capsType.report = true;
    hostdev->pciBackend.report = true;

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
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI,
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

    return 0;
}


static int
virQEMUCapsFillDomainDeviceRNGCaps(virQEMUCapsPtr qemuCaps,
                                   virDomainCapsDeviceRNGPtr rng)
{
    rng->supported = VIR_TRISTATE_BOOL_YES;
    rng->model.report = true;
    rng->backendModel.report = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_RNG)) {
        VIR_DOMAIN_CAPS_ENUM_SET(rng->model, VIR_DOMAIN_RNG_MODEL_VIRTIO);

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL) ||
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY)) {
            VIR_DOMAIN_CAPS_ENUM_SET(rng->model,
                                     VIR_DOMAIN_RNG_MODEL_VIRTIO_TRANSITIONAL,
                                     VIR_DOMAIN_RNG_MODEL_VIRTIO_NON_TRANSITIONAL);
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_EGD))
        VIR_DOMAIN_CAPS_ENUM_SET(rng->backendModel, VIR_DOMAIN_RNG_BACKEND_EGD);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_RANDOM))
        VIR_DOMAIN_CAPS_ENUM_SET(rng->backendModel, VIR_DOMAIN_RNG_BACKEND_RANDOM);

    return 0;
}


/**
 * virQEMUCapsSupportsGICVersion:
 * @qemuCaps: QEMU capabilities
 * @virtType: domain type
 * @version: GIC version
 *
 * Checks the QEMU binary with capabilities @qemuCaps supports a specific
 * GIC version for a domain of type @virtType. If @qemuCaps is NULL, the GIC
 * @version is considered unsupported.
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

    if (!qemuCaps)
        return false;

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

    gic->supported = VIR_TRISTATE_BOOL_NO;

    if (!qemuDomainMachineIsARMVirt(domCaps->machine, domCaps->arch))
        return 0;

    for (version = VIR_GIC_VERSION_LAST - 1;
         version > VIR_GIC_VERSION_NONE;
         version--) {
        if (!virQEMUCapsSupportsGICVersion(qemuCaps,
                                           domCaps->virttype,
                                           version))
            continue;

        gic->supported = VIR_TRISTATE_BOOL_YES;
        gic->version.report = true;
        VIR_DOMAIN_CAPS_ENUM_SET(gic->version,
                                 version);
    }

    return 0;
}


/**
 * virQEMUCapsFillDomainFeatureSEVCaps:
 * @qemuCaps: QEMU capabilities
 * @domCaps: domain capabilities
 *
 * Take the information about SEV capabilities that has been obtained
 * using the 'query-sev-capabilities' QMP command and stored in @qemuCaps
 * and convert it to a form suitable for @domCaps.
 *
 * Returns: 0 on success, -1 on failure
 */
static int
virQEMUCapsFillDomainFeatureSEVCaps(virQEMUCapsPtr qemuCaps,
                                    virDomainCapsPtr domCaps)
{
    virSEVCapability *cap = qemuCaps->sevCapabilities;
    VIR_AUTOPTR(virSEVCapability) sev = NULL;

    if (!cap)
        return 0;

    if (VIR_ALLOC(sev) < 0)
        return -1;

    if (VIR_STRDUP(sev->pdh, cap->pdh) < 0)
        return -1;

    if (VIR_STRDUP(sev->cert_chain, cap->cert_chain) < 0)
        return -1;

    sev->cbitpos = cap->cbitpos;
    sev->reduced_phys_bits = cap->reduced_phys_bits;
    VIR_STEAL_PTR(domCaps->sev, sev);

    return 0;
}


int
virQEMUCapsFillDomainCaps(virCapsPtr caps,
                          virDomainCapsPtr domCaps,
                          virQEMUCapsPtr qemuCaps,
                          bool privileged,
                          virFirmwarePtr *firmwares,
                          size_t nfirmwares)
{
    virDomainCapsOSPtr os = &domCaps->os;
    virDomainCapsDeviceDiskPtr disk = &domCaps->disk;
    virDomainCapsDeviceHostdevPtr hostdev = &domCaps->hostdev;
    virDomainCapsDeviceGraphicsPtr graphics = &domCaps->graphics;
    virDomainCapsDeviceVideoPtr video = &domCaps->video;
    virDomainCapsDeviceRNGPtr rng = &domCaps->rng;

    domCaps->maxvcpus = virQEMUCapsGetMachineMaxCpus(qemuCaps,
                                                     domCaps->machine);
    if (domCaps->virttype == VIR_DOMAIN_VIRT_KVM) {
        int hostmaxvcpus;

        if ((hostmaxvcpus = virHostCPUGetKVMMaxVCPUs()) < 0)
            return -1;

        domCaps->maxvcpus = MIN(domCaps->maxvcpus, hostmaxvcpus);
    }

    domCaps->vmcoreinfo = virTristateBoolFromBool(
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMCOREINFO));

    domCaps->genid = virTristateBoolFromBool(
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMGENID));

    if (virQEMUCapsFillDomainOSCaps(os,
                                    domCaps->machine,
                                    domCaps->arch,
                                    privileged,
                                    firmwares, nfirmwares) < 0 ||
        virQEMUCapsFillDomainCPUCaps(caps, qemuCaps, domCaps) < 0 ||
        virQEMUCapsFillDomainIOThreadCaps(qemuCaps, domCaps) < 0 ||
        virQEMUCapsFillDomainDeviceDiskCaps(qemuCaps,
                                            domCaps->machine, disk) < 0 ||
        virQEMUCapsFillDomainDeviceGraphicsCaps(qemuCaps, graphics) < 0 ||
        virQEMUCapsFillDomainDeviceVideoCaps(qemuCaps, video) < 0 ||
        virQEMUCapsFillDomainDeviceHostdevCaps(qemuCaps, hostdev) < 0 ||
        virQEMUCapsFillDomainDeviceRNGCaps(qemuCaps, rng) < 0 ||
        virQEMUCapsFillDomainFeatureGICCaps(qemuCaps, domCaps) < 0 ||
        virQEMUCapsFillDomainFeatureSEVCaps(qemuCaps, domCaps) < 0)
        return -1;

    return 0;
}


void
virQEMUCapsSetMicrocodeVersion(virQEMUCapsPtr qemuCaps,
                               unsigned int microcodeVersion)
{
    qemuCaps->microcodeVersion = microcodeVersion;
}


/**
 * virQEMUCapsStripMachineAliases:
 * @qemuCaps: capabilities object to process
 *
 * Remove all aliases so that the tests depending on the latest capabilities
 * file can be stable when new files are added.
 */
void
virQEMUCapsStripMachineAliases(virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < qemuCaps->nmachineTypes; i++)
        VIR_FREE(qemuCaps->machineTypes[i].alias);
}
