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
#include "virarch.h"
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
#include "virutil.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
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
              "ramfb",
              "machine.pseries.cap-ccf-assist",

              /* 345 */
              "arm-max-cpu",
              "blockdev-file-dynamic-auto-read-only",
              "savevm-monitor-nodes",
              "drive-nvme",
              "smp-dies",

              /* 350 */
              "i8042",
              "rng-builtin",
              "virtio-net.failover",
              "tpm-spapr",
              "cpu.kvm-no-adjvtime",

              /* 355 */
              "vhost-user-fs",
              "query-named-block-nodes.flat",
              "blockdev-snapshot.allow-write-only-overlay",
              "blockdev-reopen",
              "storage.werror",

              /* 360 */
              "fsdev.multidevs",
              "virtio.packed",
              "pcie-root-port.hotplug",
              "aio.io_uring",
              "machine.pseries.cap-cfpc",

              /* 365 */
              "machine.pseries.cap-sbbc",
              "machine.pseries.cap-ibs",
              "tcg",
              "virtio-blk-pci.scsi.default.disabled",
              "pvscsi",

              /* 370 */
              "cpu.migratable",
              "query-cpu-model-expansion.migratable",
              "fw_cfg",
              "migration-param.bandwidth",
              "migration-param.downtime",

              /* 375 */
              "migration-param.xbzrle-cache-size",
              "intel-iommu.aw-bits",
              "spapr-tpm-proxy",
              "numa.hmat",
              "blockdev-hostdev-scsi",

              /* 380 */
              "usb-host.hostdevice",
              "virtio-balloon.free-page-reporting",
              "block-export-add",
              "netdev.vhost-vdpa",
              "fsdev.createmode",

              /* 385 */
              "ncr53c90",
              "dc390",
              "am53c974",
              "virtio-pmem-pci",
              "vhost-user-fs.bootindex",

              /* 390 */
              "vhost-user-blk",
              "cpu-max",
              "memory-backend-file.x-use-canonical-path-for-ramblock-id",
              "vnc-opts",
              "migration-param.block-bitmap-mapping",

              /* 395 */
              "vnc-power-control",
              "audiodev",
              "blockdev-backup",
              "object.qapified",
              "rotation-rate",

              /* 400 */
              "compat-deprecated",
              "acpi-index",
              "input-linux",
              "virtio-gpu-gl-pci",
              "virtio-vga-gl",

              /* 405 */
              "confidential-guest-support",
              "query-display-options",
              "s390-pv-guest",
    );


typedef struct _virQEMUCapsMachineType virQEMUCapsMachineType;
struct _virQEMUCapsMachineType {
    char *name;
    char *alias;
    unsigned int maxCpus;
    bool hotplugCpus;
    bool qemuDefault;
    char *defaultCPU;
    bool numaMemSupported;
    char *defaultRAMid;
    bool deprecated;
};

typedef struct _virQEMUCapsHostCPUData virQEMUCapsHostCPUData;
struct _virQEMUCapsHostCPUData {
    /* Only the "info" part is stored in the capabilities cache, the rest is
     * re-computed from other fields and external data sources every time we
     * probe QEMU or load the cache.
     */
    qemuMonitorCPUModelInfo *info;
    /* Host CPU definition reported in domain capabilities. */
    virCPUDef *reported;
    /* Migratable host CPU definition used for updating guest CPU. */
    virCPUDef *migratable;
    /* CPU definition with features detected by libvirt using virCPUGetHost
     * combined with features reported by QEMU. This is used for backward
     * compatible comparison between a guest CPU and a host CPU. */
    virCPUDef *full;
};

typedef struct _virQEMUCapsAccel virQEMUCapsAccel;
struct _virQEMUCapsAccel {
    size_t nmachineTypes;
    virQEMUCapsMachineType *machineTypes;
    virQEMUCapsHostCPUData hostCPU;
    qemuMonitorCPUDefs *cpuModels;
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

    bool kvmSupportsNesting;
    bool kvmSupportsSecureGuest;

    char *binary;
    time_t ctime;
    time_t libvirtCtime;
    time_t modDirMtime;
    bool invalidation;

    virBitmap *flags;

    unsigned int version;
    unsigned int kvmVersion;
    unsigned int libvirtVersion;
    unsigned int microcodeVersion;
    char *hostCPUSignature;
    char *package;
    char *kernelVersion;

    virArch arch;

    size_t ngicCapabilities;
    virGICCapability *gicCapabilities;

    virSEVCapability *sevCapabilities;

    /* Capabilities which may differ depending on the accelerator. */
    virQEMUCapsAccel kvm;
    virQEMUCapsAccel tcg;
};

struct virQEMUCapsSearchData {
    virArch arch;
    const char *binaryFilter;
};


static virClass *virQEMUCapsClass;
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


static virQEMUCapsAccel *
virQEMUCapsGetAccel(virQEMUCaps *qemuCaps,
                    virDomainVirtType type)
{
    if (type == VIR_DOMAIN_VIRT_KVM)
        return &qemuCaps->kvm;

    return &qemuCaps->tcg;
}


static void
virQEMUCapsSetDefaultMachine(virQEMUCapsAccel *caps,
                             size_t defIdx)
{
    virQEMUCapsMachineType tmp = caps->machineTypes[defIdx];

    memmove(caps->machineTypes + 1,
            caps->machineTypes,
            sizeof(caps->machineTypes[0]) * defIdx);

    caps->machineTypes[0] = tmp;
}


static char *
virQEMUCapsFindBinary(const char *format,
                      const char *archstr)
{
    char *ret = NULL;
    char *binary = NULL;

    binary = g_strdup_printf(format, archstr);

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
            return ret;
    }

    /* First attempt: try the guest architecture as it is */
    archstr = virQEMUCapsArchToString(guestarch);
    if ((ret = virQEMUCapsFindBinary("qemu-system-%s", archstr)) != NULL)
        return ret;

    /* Second attempt: try looking up by target instead */
    target = virQEMUCapsFindTarget(hostarch, guestarch);
    if (target != guestarch) {
        archstr = virQEMUCapsArchToString(target);
        if ((ret = virQEMUCapsFindBinary("qemu-system-%s", archstr)) != NULL)
            return ret;
    }

    return ret;
}


char *
virQEMUCapsGetDefaultEmulator(virArch hostarch,
                              virArch guestarch)
{
    char *binary = NULL;
    /* Check for existence of base emulator, or alternate base
     * which can be used with magic cpu choice
     */
    binary = virQEMUCapsFindBinaryForArch(hostarch, guestarch);

    /* RHEL doesn't follow the usual naming for QEMU binaries and ships
     * a single binary named qemu-kvm outside of $PATH instead */
    if (virQEMUCapsGuestIsNative(hostarch, guestarch) && !binary)
        binary = g_strdup("/usr/libexec/qemu-kvm");

    return binary;
}


static int
virQEMUCapsInitGuest(virCaps *caps,
                     virFileCache *cache,
                     virArch hostarch,
                     virArch guestarch)
{
    char *binary = NULL;
    virQEMUCaps *qemuCaps = NULL;
    int ret = -1;

    binary = virQEMUCapsGetDefaultEmulator(hostarch, guestarch);

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


static int
virQEMUCapsGetMachineTypesCaps(virQEMUCaps *qemuCaps,
                               size_t *nmachines,
                               virCapsGuestMachine ***machines)
{
    size_t i;
    virQEMUCapsAccel *accel;
    g_autoptr(GPtrArray) array = NULL;

    /* Guest capabilities do not report TCG vs. KVM caps separately. We just
     * take the set of machine types we probed first. */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        accel = &qemuCaps->kvm;
    else
        accel = &qemuCaps->tcg;

    *machines = NULL;
    *nmachines = accel->nmachineTypes;

    if (*nmachines == 0)
        return 0;

    array = g_ptr_array_sized_new(*nmachines);

    for (i = 0; i < accel->nmachineTypes; i++) {
        virCapsGuestMachine *mach = g_new0(virCapsGuestMachine, 1);
        if (accel->machineTypes[i].alias) {
            mach->name = g_strdup(accel->machineTypes[i].alias);
            mach->canonical = g_strdup(accel->machineTypes[i].name);
        } else {
            mach->name = g_strdup(accel->machineTypes[i].name);
        }
        mach->maxCpus = accel->machineTypes[i].maxCpus;
        mach->deprecated = accel->machineTypes[i].deprecated;
        g_ptr_array_add(array, mach);
    }

    /* Make sure all canonical machine types also have their own entry so that
     * /capabilities/guest/arch[@name='...']/machine/text() XPath selects all
     * supported machine types.
     */
    i = 0;
    while (i < array->len) {
        size_t j;
        bool found = false;
        virCapsGuestMachine *machine = g_ptr_array_index(array, i);

        if (!machine->canonical) {
            i++;
            continue;
        }

        for (j = 0; j < array->len; j++) {
            virCapsGuestMachine *mach = g_ptr_array_index(array, j);
            if (STREQ(machine->canonical, mach->name)) {
                found = true;
                break;
            }
        }

        if (!found) {
            virCapsGuestMachine *mach;
            mach = g_new0(virCapsGuestMachine, 1);
            mach->name = g_strdup(machine->canonical);
            mach->maxCpus = machine->maxCpus;
            mach->deprecated = machine->deprecated;
            g_ptr_array_insert(array, i, mach);
            i++;
        }
        i++;
    }

    *nmachines = array->len;
    *machines = g_new0(virCapsGuestMachine *, array->len);
    for (i = 0; i < array->len; ++i)
        (*machines)[i] = g_ptr_array_index(array, i);

    return 0;
}


int
virQEMUCapsInitGuestFromBinary(virCaps *caps,
                               const char *binary,
                               virQEMUCaps *qemuCaps,
                               virArch guestarch)
{
    virCapsGuest *guest;
    virCapsGuestMachine **machines = NULL;
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
    virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_CPUSELECTION);
    virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_DEVICEBOOT);
    virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_DISKSNAPSHOT,
                                             true, false);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_TCG)) {
        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_QEMU,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL) {
            goto cleanup;
        }
    }

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

    if ((ARCH_IS_X86(guestarch) || guestarch == VIR_ARCH_AARCH64))
        virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_ACPI,
                                                 true, true);

    if (ARCH_IS_X86(guestarch))
        virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_APIC,
                                                 true, false);

    if (guestarch == VIR_ARCH_I686) {
        virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_PAE);
        virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_NONPAE);
    }

    ret = 0;

 cleanup:

    virCapabilitiesFreeMachines(machines, nmachines);

    return ret;
}


virCPUDef *
virQEMUCapsProbeHostCPU(virArch hostArch,
                        virDomainCapsCPUModels *models)
{
    return virCPUGetHost(hostArch, VIR_CPU_TYPE_GUEST, NULL, models);
}


virCaps *
virQEMUCapsInit(virFileCache *cache)
{
    virCaps *caps;
    size_t i;
    virArch hostarch = virArchFromHost();

    if ((caps = virCapabilitiesNew(hostarch,
                                   true, true)) == NULL)
        goto error;

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

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
    { "block-export-add", QEMU_CAPS_BLOCK_EXPORT_ADD },
    { "query-display-options", QEMU_CAPS_QUERY_DISPLAY_OPTIONS },
    { "blockdev-reopen", QEMU_CAPS_BLOCKDEV_REOPEN },
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
    { "virtio-blk-ccw", QEMU_CAPS_VIRTIO_CCW },
    { "sclpconsole", QEMU_CAPS_DEVICE_SCLPCONSOLE },
    { "lsi53c895a", QEMU_CAPS_SCSI_LSI },
    { "virtio-scsi-pci", QEMU_CAPS_VIRTIO_SCSI },
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
    { "ramfb", QEMU_CAPS_DEVICE_RAMFB },
    { "max-arm-cpu", QEMU_CAPS_ARM_MAX_CPU },
    { "i8042", QEMU_CAPS_DEVICE_I8042 },
    { "rng-builtin", QEMU_CAPS_OBJECT_RNG_BUILTIN },
    { "tpm-spapr", QEMU_CAPS_DEVICE_TPM_SPAPR },
    { "vhost-user-fs-device", QEMU_CAPS_DEVICE_VHOST_USER_FS },
    { "tcg-accel", QEMU_CAPS_TCG },
    { "pvscsi", QEMU_CAPS_SCSI_PVSCSI },
    { "spapr-tpm-proxy", QEMU_CAPS_DEVICE_SPAPR_TPM_PROXY },
    { "vmport", QEMU_CAPS_MACHINE_VMPORT_OPT },
    /*
     * We don't probe 'esp' directly, because it is often reported
     * as present for all QEMU binaries, due to it being enabled
     * for built as a dependency of dc390/am53c974 PCI SCSI
     * controllers.
     *
     * The base 'esp' device is only used as a built-in device
     * and is not user-creatable. So we turn this cap on later
     * based on arch.
     *
     * { "esp", QEMU_CAPS_SCSI_NCR53C90 },
     */
    { "dc390", QEMU_CAPS_SCSI_DC390 },
    { "am53c974", QEMU_CAPS_SCSI_AM53C974 },
    { "virtio-pmem-pci", QEMU_CAPS_DEVICE_VIRTIO_PMEM_PCI },
    { "vhost-user-blk", QEMU_CAPS_DEVICE_VHOST_USER_BLK },
    { "input-linux", QEMU_CAPS_INPUT_LINUX },
    { "virtio-gpu-gl-pci", QEMU_CAPS_VIRTIO_GPU_GL_PCI },
    { "virtio-vga-gl", QEMU_CAPS_VIRTIO_VGA_GL },
    { "s390-pv-guest", QEMU_CAPS_S390_PV_GUEST },
};


struct virQEMUCapsDevicePropsFlags {
    const char *value;
    int flag;
    int (*cb)(virJSONValue *props, virQEMUCaps *caps);
};


static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVirtioBalloon[] = {
    { "deflate-on-oom", QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE, NULL },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, NULL },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, NULL },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS, NULL },
    { "packed", QEMU_CAPS_VIRTIO_PACKED_QUEUES, NULL },
    { "free-page-reporting", QEMU_CAPS_VIRTIO_BALLOON_FREE_PAGE_REPORTING, NULL },
    { "acpi-index", QEMU_CAPS_ACPI_INDEX, NULL },
};


static int
virQEMUCapsDevicePropsVirtioBlkSCSIDefault(virJSONValue *props,
                                           virQEMUCaps *qemuCaps)
{
    bool def = false;

    if (virJSONValueObjectGetBoolean(props, "default-value", &def) < 0)
        return 0;

    if (def == false)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_SCSI_DEFAULT_DISABLED);

    return 0;
}


static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVirtioBlk[] = {
    { "ioeventfd", QEMU_CAPS_VIRTIO_IOEVENTFD, NULL },
    { "event_idx", QEMU_CAPS_VIRTIO_BLK_EVENT_IDX, NULL },
    { "scsi", QEMU_CAPS_VIRTIO_BLK_SCSI, virQEMUCapsDevicePropsVirtioBlkSCSIDefault },
    { "logical_block_size", QEMU_CAPS_BLOCKIO, NULL },
    { "num-queues", QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES, NULL },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW, NULL },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, NULL },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, NULL },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS, NULL },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE, NULL },
    { "werror", QEMU_CAPS_STORAGE_WERROR, NULL },
    { "packed", QEMU_CAPS_VIRTIO_PACKED_QUEUES, NULL },
    { "acpi-index", QEMU_CAPS_ACPI_INDEX, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVirtioNet[] = {
    { "tx", QEMU_CAPS_VIRTIO_TX_ALG, NULL },
    { "event_idx", QEMU_CAPS_VIRTIO_NET_EVENT_IDX, NULL },
    { "rx_queue_size", QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE, NULL },
    { "tx_queue_size", QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE, NULL },
    { "host_mtu", QEMU_CAPS_VIRTIO_NET_HOST_MTU, NULL },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, NULL },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, NULL },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS, NULL },
    { "failover", QEMU_CAPS_VIRTIO_NET_FAILOVER, NULL },
    { "packed", QEMU_CAPS_VIRTIO_PACKED_QUEUES, NULL },
    { "acpi-index", QEMU_CAPS_ACPI_INDEX, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsPCIeRootPort[] = {
    { "hotplug", QEMU_CAPS_PCIE_ROOT_PORT_HOTPLUG, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsUSBHost[] = {
    { "hostdevice", QEMU_CAPS_USB_HOST_HOSTDEVICE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsSpaprPCIHostBridge[] = {
    { "numa_node", QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVirtioSCSI[] = {
    { "iothread", QEMU_CAPS_VIRTIO_SCSI_IOTHREAD, NULL },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, NULL },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, NULL },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS, NULL },
    { "packed", QEMU_CAPS_VIRTIO_PACKED_QUEUES, NULL },
    { "acpi-index", QEMU_CAPS_ACPI_INDEX, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVfioPCI[] = {
    { "display", QEMU_CAPS_VFIO_PCI_DISPLAY, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsSCSIDisk[] = {
    { "channel", QEMU_CAPS_SCSI_DISK_CHANNEL, NULL },
    { "wwn", QEMU_CAPS_SCSI_DISK_WWN, NULL },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW, NULL },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE, NULL },
    { "device_id", QEMU_CAPS_SCSI_DISK_DEVICE_ID, NULL },
    { "werror", QEMU_CAPS_STORAGE_WERROR, NULL },
    { "rotation_rate", QEMU_CAPS_ROTATION_RATE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsIDEDrive[] = {
    { "wwn", QEMU_CAPS_IDE_DRIVE_WWN, NULL },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW, NULL },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsPiix4PM[] = {
    { "disable_s3", QEMU_CAPS_PIIX_DISABLE_S3, NULL },
    { "disable_s4", QEMU_CAPS_PIIX_DISABLE_S4, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsUSBRedir[] = {
    { "filter", QEMU_CAPS_USB_REDIR_FILTER, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsI440FXPCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_I440FX_PCI_HOLE64_SIZE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsQ35PCIHost[] = {
    { "pci-hole64-size", QEMU_CAPS_Q35_PCI_HOLE64_SIZE, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsUSBStorage[] = {
    { "removable", QEMU_CAPS_USB_STORAGE_REMOVABLE, NULL },
    { "share-rw", QEMU_CAPS_DISK_SHARE_RW, NULL },
    { "write-cache", QEMU_CAPS_DISK_WRITE_CACHE, NULL },
    { "werror", QEMU_CAPS_USB_STORAGE_WERROR, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsKVMPit[] = {
    { "lost_tick_policy", QEMU_CAPS_KVM_PIT_TICK_POLICY, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVGA[] = {
    { "vgamem_mb", QEMU_CAPS_VGA_VGAMEM, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVmwareSvga[] = {
    { "vgamem_mb", QEMU_CAPS_VMWARE_SVGA_VGAMEM, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsQxl[] = {
    { "vgamem_mb", QEMU_CAPS_QXL_VGAMEM, NULL },
    { "vram64_size_mb", QEMU_CAPS_QXL_VRAM64, NULL },
    { "max_outputs", QEMU_CAPS_QXL_MAX_OUTPUTS, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVirtioGpu[] = {
    { "virgl", QEMU_CAPS_VIRTIO_GPU_VIRGL, NULL },
    { "max_outputs", QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS, NULL },
    { "disable-legacy", QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, NULL },
    { "iommu_platform", QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, NULL },
    { "ats", QEMU_CAPS_VIRTIO_PCI_ATS, NULL },
    { "packed", QEMU_CAPS_VIRTIO_PACKED_QUEUES, NULL },
    { "acpi-index", QEMU_CAPS_ACPI_INDEX, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsICH9[] = {
    { "disable_s3", QEMU_CAPS_ICH9_DISABLE_S3, NULL },
    { "disable_s4", QEMU_CAPS_ICH9_DISABLE_S4, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsUSBNECXHCI[] = {
    { "p3", QEMU_CAPS_NEC_USB_XHCI_PORTS, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsIntelIOMMU[] = {
    { "intremap", QEMU_CAPS_INTEL_IOMMU_INTREMAP, NULL },
    { "caching-mode", QEMU_CAPS_INTEL_IOMMU_CACHING_MODE, NULL },
    { "eim", QEMU_CAPS_INTEL_IOMMU_EIM, NULL },
    { "device-iotlb", QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB, NULL },
    { "aw-bits", QEMU_CAPS_INTEL_IOMMU_AW_BITS, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsObjectPropsVirtualCSSBridge[] = {
    { "cssid-unrestricted", QEMU_CAPS_CCW_CSSID_UNRESTRICTED, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsMCH[] = {
    { "extended-tseg-mbytes", QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsNVDIMM[] = {
    { "unarmed", QEMU_CAPS_DEVICE_NVDIMM_UNARMED, NULL },
};

static struct virQEMUCapsDevicePropsFlags virQEMUCapsDevicePropsVhostUserFS[] = {
    { "bootindex", QEMU_CAPS_VHOST_USER_FS_BOOTINDEX, NULL },
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
    { "blockdev-add/arg-type/+file/$dynamic-auto-read-only", QEMU_CAPS_BLOCK_FILE_AUTO_READONLY_DYNAMIC },
    { "human-monitor-command/$savevm-monitor-nodes", QEMU_CAPS_SAVEVM_MONITOR_NODES },
    { "blockdev-add/arg-type/+nvme", QEMU_CAPS_DRIVE_NVME },
    { "query-named-block-nodes/arg-type/flat", QEMU_CAPS_QMP_QUERY_NAMED_BLOCK_NODES_FLAT },
    { "blockdev-snapshot/$allow-write-only-overlay", QEMU_CAPS_BLOCKDEV_SNAPSHOT_ALLOW_WRITE_ONLY },
    { "blockdev-add/arg-type/+file/aio/^io_uring", QEMU_CAPS_AIO_IO_URING },
    { "migrate-set-parameters/arg-type/max-bandwidth", QEMU_CAPS_MIGRATION_PARAM_BANDWIDTH },
    { "migrate-set-parameters/arg-type/downtime-limit", QEMU_CAPS_MIGRATION_PARAM_DOWNTIME },
    { "migrate-set-parameters/arg-type/xbzrle-cache-size", QEMU_CAPS_MIGRATION_PARAM_XBZRLE_CACHE_SIZE },
    { "set-numa-node/arg-type/+hmat-lb", QEMU_CAPS_NUMA_HMAT },
    { "netdev_add/arg-type/+vhost-vdpa", QEMU_CAPS_NETDEV_VHOST_VDPA },
    { "migrate-set-parameters/arg-type/block-bitmap-mapping/bitmaps/transform",
      QEMU_CAPS_MIGRATION_PARAM_BLOCK_BITMAP_MAPPING },
    { "blockdev-backup", QEMU_CAPS_BLOCKDEV_BACKUP },
    { "object-add/arg-type/qom-type/^secret", QEMU_CAPS_OBJECT_QAPIFIED },
    { "query-display-options/ret-type/+sdl", QEMU_CAPS_SDL },
    { "query-display-options/ret-type/+egl-headless", QEMU_CAPS_EGL_HEADLESS },
};

typedef struct _virQEMUCapsObjectTypeProps virQEMUCapsObjectTypeProps;
struct _virQEMUCapsObjectTypeProps {
    const char *type;
    struct virQEMUCapsStringFlags *props;
    size_t nprops;
    int capsCondition;
};


typedef struct _virQEMUCapsDeviceTypeProps virQEMUCapsDeviceTypeProps;
struct _virQEMUCapsDeviceTypeProps {
    const char *type;
    struct virQEMUCapsDevicePropsFlags *props;
    size_t nprops;
    int capsCondition;
};


static virQEMUCapsDeviceTypeProps virQEMUCapsDeviceProps[] = {
    { "virtio-blk-pci", virQEMUCapsDevicePropsVirtioBlk,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioBlk),
      -1 },
    { "virtio-net-pci", virQEMUCapsDevicePropsVirtioNet,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioNet),
      QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-scsi-pci", virQEMUCapsDevicePropsVirtioSCSI,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioSCSI),
      QEMU_CAPS_VIRTIO_SCSI },
    { "virtio-blk-ccw", virQEMUCapsDevicePropsVirtioBlk,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioBlk),
      QEMU_CAPS_VIRTIO_CCW },
    { "virtio-net-ccw", virQEMUCapsDevicePropsVirtioNet,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioNet),
      QEMU_CAPS_DEVICE_VIRTIO_NET },
    { "virtio-scsi-ccw", virQEMUCapsDevicePropsVirtioSCSI,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioSCSI),
      QEMU_CAPS_VIRTIO_SCSI },
    { "vfio-pci", virQEMUCapsDevicePropsVfioPCI,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVfioPCI),
      QEMU_CAPS_DEVICE_VFIO_PCI },
    { "scsi-hd", virQEMUCapsDevicePropsSCSIDisk,
      G_N_ELEMENTS(virQEMUCapsDevicePropsSCSIDisk),
      -1 },
    { "ide-hd", virQEMUCapsDevicePropsIDEDrive,
      G_N_ELEMENTS(virQEMUCapsDevicePropsIDEDrive),
      -1 },
    { "PIIX4_PM", virQEMUCapsDevicePropsPiix4PM,
      G_N_ELEMENTS(virQEMUCapsDevicePropsPiix4PM),
      -1 },
    { "usb-redir", virQEMUCapsDevicePropsUSBRedir,
      G_N_ELEMENTS(virQEMUCapsDevicePropsUSBRedir),
      QEMU_CAPS_USB_REDIR },
    { "i440FX-pcihost", virQEMUCapsDevicePropsI440FXPCIHost,
      G_N_ELEMENTS(virQEMUCapsDevicePropsI440FXPCIHost),
      -1 },
    { "q35-pcihost", virQEMUCapsDevicePropsQ35PCIHost,
      G_N_ELEMENTS(virQEMUCapsDevicePropsQ35PCIHost),
      -1 },
    { "usb-storage", virQEMUCapsDevicePropsUSBStorage,
      G_N_ELEMENTS(virQEMUCapsDevicePropsUSBStorage),
      QEMU_CAPS_DEVICE_USB_STORAGE },
    { "kvm-pit", virQEMUCapsDevicePropsKVMPit,
      G_N_ELEMENTS(virQEMUCapsDevicePropsKVMPit),
      -1 },
    { "VGA", virQEMUCapsDevicePropsVGA,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVGA),
      QEMU_CAPS_DEVICE_VGA },
    { "vmware-svga", virQEMUCapsDevicePropsVmwareSvga,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVmwareSvga),
      QEMU_CAPS_DEVICE_VMWARE_SVGA },
    { "qxl", virQEMUCapsDevicePropsQxl,
      G_N_ELEMENTS(virQEMUCapsDevicePropsQxl),
      QEMU_CAPS_DEVICE_QXL },
    { "virtio-gpu-pci", virQEMUCapsDevicePropsVirtioGpu,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "virtio-gpu-device", virQEMUCapsDevicePropsVirtioGpu,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU },
    { "ICH9-LPC", virQEMUCapsDevicePropsICH9,
      G_N_ELEMENTS(virQEMUCapsDevicePropsICH9),
      -1 },
    { "virtio-balloon-pci", virQEMUCapsDevicePropsVirtioBalloon,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "virtio-balloon-ccw", virQEMUCapsDevicePropsVirtioBalloon,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "virtio-balloon-device", virQEMUCapsDevicePropsVirtioBalloon,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioBalloon),
      -1 },
    { "nec-usb-xhci", virQEMUCapsDevicePropsUSBNECXHCI,
      G_N_ELEMENTS(virQEMUCapsDevicePropsUSBNECXHCI),
      QEMU_CAPS_NEC_USB_XHCI },
    { "intel-iommu", virQEMUCapsDevicePropsIntelIOMMU,
      G_N_ELEMENTS(virQEMUCapsDevicePropsIntelIOMMU),
      QEMU_CAPS_DEVICE_INTEL_IOMMU },
    { "spapr-pci-host-bridge", virQEMUCapsDevicePropsSpaprPCIHostBridge,
      G_N_ELEMENTS(virQEMUCapsDevicePropsSpaprPCIHostBridge),
      QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE },
    { "virtio-gpu-ccw", virQEMUCapsDevicePropsVirtioGpu,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVirtioGpu),
      QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW },
    { "virtual-css-bridge", virQEMUCapsObjectPropsVirtualCSSBridge,
      G_N_ELEMENTS(virQEMUCapsObjectPropsVirtualCSSBridge),
      QEMU_CAPS_CCW },
    { "mch", virQEMUCapsDevicePropsMCH,
      G_N_ELEMENTS(virQEMUCapsDevicePropsMCH),
      QEMU_CAPS_DEVICE_MCH },
    { "nvdimm", virQEMUCapsDevicePropsNVDIMM,
      G_N_ELEMENTS(virQEMUCapsDevicePropsNVDIMM),
      QEMU_CAPS_DEVICE_NVDIMM },
    { "pcie-root-port", virQEMUCapsDevicePropsPCIeRootPort,
      G_N_ELEMENTS(virQEMUCapsDevicePropsPCIeRootPort),
      QEMU_CAPS_DEVICE_PCIE_ROOT_PORT },
    { "usb-host", virQEMUCapsDevicePropsUSBHost,
      G_N_ELEMENTS(virQEMUCapsDevicePropsUSBHost),
      -1 },
    { "vhost-user-fs-device", virQEMUCapsDevicePropsVhostUserFS,
      G_N_ELEMENTS(virQEMUCapsDevicePropsVhostUserFS),
      QEMU_CAPS_DEVICE_VHOST_USER_FS },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMemoryBackendFile[] = {
    { "discard-data", QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD },
    { "align", QEMU_CAPS_OBJECT_MEMORY_FILE_ALIGN },
    { "pmem", QEMU_CAPS_OBJECT_MEMORY_FILE_PMEM },
    /* As of QEMU commit 8db0b20415c129cf5e577a593a4a0372d90b7cc9 the
     * "x-use-canonical-path-for-ramblock-id" property is considered stable and
     * supported. The 'x-' prefix was kept for compatibility with already
     * released qemu versions. */
    { "x-use-canonical-path-for-ramblock-id", QEMU_CAPS_X_USE_CANONICAL_PATH_FOR_RAMBLOCK_ID },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMemoryBackendMemfd[] = {
    { "hugetlb", QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB },
};

static struct virQEMUCapsStringFlags virQEMUCapsObjectPropsMaxCPU[] = {
    { "unavailable-features", QEMU_CAPS_CPU_UNAVAILABLE_FEATURES },
    { "kvm-no-adjvtime", QEMU_CAPS_CPU_KVM_NO_ADJVTIME },
    { "migratable", QEMU_CAPS_CPU_MIGRATABLE },
};

static virQEMUCapsObjectTypeProps virQEMUCapsObjectProps[] = {
    { "memory-backend-file", virQEMUCapsObjectPropsMemoryBackendFile,
      G_N_ELEMENTS(virQEMUCapsObjectPropsMemoryBackendFile),
      QEMU_CAPS_OBJECT_MEMORY_FILE },
    { "memory-backend-memfd", virQEMUCapsObjectPropsMemoryBackendMemfd,
      G_N_ELEMENTS(virQEMUCapsObjectPropsMemoryBackendMemfd),
      QEMU_CAPS_OBJECT_MEMORY_MEMFD },
    { "max-x86_64-cpu", virQEMUCapsObjectPropsMaxCPU,
      G_N_ELEMENTS(virQEMUCapsObjectPropsMaxCPU),
      QEMU_CAPS_X86_MAX_CPU },
    { "max-arm-cpu", virQEMUCapsObjectPropsMaxCPU,
      G_N_ELEMENTS(virQEMUCapsObjectPropsMaxCPU),
      QEMU_CAPS_ARM_MAX_CPU },
};

static struct virQEMUCapsStringFlags virQEMUCapsMachinePropsPSeries[] = {
    { "cap-hpt-max-page-size", QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE },
    { "cap-htm", QEMU_CAPS_MACHINE_PSERIES_CAP_HTM },
    { "cap-nested-hv", QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV },
    { "cap-ccf-assist", QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST },
    { "cap-cfpc", QEMU_CAPS_MACHINE_PSERIES_CAP_CFPC },
    { "cap-sbbc", QEMU_CAPS_MACHINE_PSERIES_CAP_SBBC },
    { "cap-ibs", QEMU_CAPS_MACHINE_PSERIES_CAP_IBS },
};

static struct virQEMUCapsStringFlags virQEMUCapsMachinePropsVirt[] = {
    { "iommu", QEMU_CAPS_MACHINE_VIRT_IOMMU },
};

static struct virQEMUCapsStringFlags virQEMUCapsMachinePropsGeneric[] = {
    { "confidential-guest-support", QEMU_CAPS_MACHINE_CONFIDENTAL_GUEST_SUPPORT },
};

static virQEMUCapsObjectTypeProps virQEMUCapsMachineProps[] = {
    { "pseries", virQEMUCapsMachinePropsPSeries,
      G_N_ELEMENTS(virQEMUCapsMachinePropsPSeries),
      -1 },
    { "virt", virQEMUCapsMachinePropsVirt,
      G_N_ELEMENTS(virQEMUCapsMachinePropsVirt),
      -1 },
    { "none", virQEMUCapsMachinePropsGeneric,
      G_N_ELEMENTS(virQEMUCapsMachinePropsGeneric),
      -1 },
};

static void
virQEMUCapsProcessStringFlags(virQEMUCaps *qemuCaps,
                              size_t nflags,
                              struct virQEMUCapsStringFlags *flags,
                              char **values)
{
    size_t i;
    char **value;

    for (i = 0; i < nflags; i++) {
        if (virQEMUCapsGet(qemuCaps, flags[i].flag))
            continue;

        for (value = values; *value; value++) {
            if (STREQ(*value, flags[i].value)) {
                virQEMUCapsSet(qemuCaps, flags[i].flag);
                break;
            }
        }
    }
}


int virQEMUCapsGetDefaultVersion(virCaps *caps,
                                 virFileCache *capsCache,
                                 unsigned int *version)
{
    virQEMUCaps *qemucaps;
    virArch hostarch;
    virCapsDomainData *capsdata;

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


virQEMUCaps *
virQEMUCapsNew(void)
{
    virQEMUCaps *qemuCaps;

    if (virQEMUCapsInitialize() < 0)
        return NULL;

    if (!(qemuCaps = virObjectNew(virQEMUCapsClass)))
        return NULL;

    qemuCaps->invalidation = true;
    qemuCaps->flags = virBitmapNew(QEMU_CAPS_LAST);

    return qemuCaps;
}


virQEMUCaps *
virQEMUCapsNewBinary(const char *binary)
{
    virQEMUCaps *qemuCaps = virQEMUCapsNew();

    if (qemuCaps)
        qemuCaps->binary = g_strdup(binary);

    return qemuCaps;
}


static int
virQEMUCapsHostCPUDataCopy(virQEMUCapsHostCPUData *dst,
                           virQEMUCapsHostCPUData *src)
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
virQEMUCapsHostCPUDataClear(virQEMUCapsHostCPUData *cpuData)
{
    qemuMonitorCPUModelInfoFree(cpuData->info);
    virCPUDefFree(cpuData->reported);
    virCPUDefFree(cpuData->migratable);
    virCPUDefFree(cpuData->full);

    memset(cpuData, 0, sizeof(*cpuData));
}


static int
virQEMUCapsSEVInfoCopy(virSEVCapability **dst,
                       virSEVCapability *src)
{
    g_autoptr(virSEVCapability) tmp = NULL;

    tmp = g_new0(virSEVCapability, 1);

    tmp->pdh = g_strdup(src->pdh);
    tmp->cert_chain = g_strdup(src->cert_chain);

    tmp->cbitpos = src->cbitpos;
    tmp->reduced_phys_bits = src->reduced_phys_bits;

    *dst = g_steal_pointer(&tmp);
    return 0;
}


static void
virQEMUCapsAccelCopyMachineTypes(virQEMUCapsAccel *dst,
                                 virQEMUCapsAccel *src)
{
    size_t i;

    dst->machineTypes = g_new0(virQEMUCapsMachineType, src->nmachineTypes);

    dst->nmachineTypes = src->nmachineTypes;
    for (i = 0; i < src->nmachineTypes; i++) {
        dst->machineTypes[i].name = g_strdup(src->machineTypes[i].name);
        dst->machineTypes[i].alias = g_strdup(src->machineTypes[i].alias);
        dst->machineTypes[i].defaultCPU = g_strdup(src->machineTypes[i].defaultCPU);
        dst->machineTypes[i].maxCpus = src->machineTypes[i].maxCpus;
        dst->machineTypes[i].hotplugCpus = src->machineTypes[i].hotplugCpus;
        dst->machineTypes[i].qemuDefault = src->machineTypes[i].qemuDefault;
        dst->machineTypes[i].numaMemSupported = src->machineTypes[i].numaMemSupported;
        dst->machineTypes[i].defaultRAMid = g_strdup(src->machineTypes[i].defaultRAMid);
        dst->machineTypes[i].deprecated = src->machineTypes[i].deprecated;
    }
}


static int
virQEMUCapsAccelCopy(virQEMUCapsAccel *dst,
                     virQEMUCapsAccel *src)
{
    virQEMUCapsAccelCopyMachineTypes(dst, src);

    if (virQEMUCapsHostCPUDataCopy(&dst->hostCPU, &src->hostCPU) < 0)
        return -1;

    dst->cpuModels = qemuMonitorCPUDefsCopy(src->cpuModels);

    return 0;
}


virQEMUCaps *virQEMUCapsNewCopy(virQEMUCaps *qemuCaps)
{
    virQEMUCaps *ret = virQEMUCapsNewBinary(qemuCaps->binary);
    size_t i;

    if (!ret)
        return NULL;

    ret->invalidation = qemuCaps->invalidation;
    ret->kvmSupportsNesting = qemuCaps->kvmSupportsNesting;
    ret->kvmSupportsSecureGuest = qemuCaps->kvmSupportsSecureGuest;

    ret->ctime = qemuCaps->ctime;

    virBitmapFree(ret->flags);
    ret->flags = virBitmapNewCopy(qemuCaps->flags);

    ret->version = qemuCaps->version;
    ret->kvmVersion = qemuCaps->kvmVersion;
    ret->microcodeVersion = qemuCaps->microcodeVersion;
    ret->hostCPUSignature = g_strdup(qemuCaps->hostCPUSignature);

    ret->package = g_strdup(qemuCaps->package);
    ret->kernelVersion = g_strdup(qemuCaps->kernelVersion);

    ret->arch = qemuCaps->arch;

    if (virQEMUCapsAccelCopy(&ret->kvm, &qemuCaps->kvm) < 0 ||
        virQEMUCapsAccelCopy(&ret->tcg, &qemuCaps->tcg) < 0)
        goto error;

    ret->gicCapabilities = g_new0(virGICCapability, qemuCaps->ngicCapabilities);
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


static void
virQEMUCapsAccelClear(virQEMUCapsAccel *caps)
{
    size_t i;

    for (i = 0; i < caps->nmachineTypes; i++) {
        VIR_FREE(caps->machineTypes[i].name);
        VIR_FREE(caps->machineTypes[i].alias);
        VIR_FREE(caps->machineTypes[i].defaultCPU);
        VIR_FREE(caps->machineTypes[i].defaultRAMid);
    }
    VIR_FREE(caps->machineTypes);

    virQEMUCapsHostCPUDataClear(&caps->hostCPU);
    qemuMonitorCPUDefsFree(caps->cpuModels);
}


void virQEMUCapsDispose(void *obj)
{
    virQEMUCaps *qemuCaps = obj;

    virBitmapFree(qemuCaps->flags);

    g_free(qemuCaps->package);
    g_free(qemuCaps->kernelVersion);
    g_free(qemuCaps->binary);
    g_free(qemuCaps->hostCPUSignature);

    g_free(qemuCaps->gicCapabilities);

    virSEVCapabilitiesFree(qemuCaps->sevCapabilities);

    virQEMUCapsAccelClear(&qemuCaps->kvm);
    virQEMUCapsAccelClear(&qemuCaps->tcg);
}

void
virQEMUCapsSet(virQEMUCaps *qemuCaps,
               virQEMUCapsFlags flag)
{
    ignore_value(virBitmapSetBit(qemuCaps->flags, flag));
}


void
virQEMUCapsSetList(virQEMUCaps *qemuCaps, ...)
{
    va_list list;
    int flag;

    va_start(list, qemuCaps);
    while ((flag = va_arg(list, int)) < QEMU_CAPS_LAST)
        virQEMUCapsSet(qemuCaps, flag);
    va_end(list);
}


void
virQEMUCapsClear(virQEMUCaps *qemuCaps,
                 virQEMUCapsFlags flag)
{
    ignore_value(virBitmapClearBit(qemuCaps->flags, flag));
}


bool
virQEMUCapsGet(virQEMUCaps *qemuCaps,
               virQEMUCapsFlags flag)
{
    return qemuCaps && virBitmapIsBitSet(qemuCaps->flags, flag);
}


bool virQEMUCapsHasPCIMultiBus(const virDomainDef *def)
{
    /* x86_64 and i686 support PCI-multibus on all machine types
     * since forever */
    if (ARCH_IS_X86(def->os.arch))
        return true;

    /* PPC supports multibus on all machine types which have pci since qemu-2.0.0 */
    if (def->os.arch == VIR_ARCH_PPC ||
        ARCH_IS_PPC64(def->os.arch)) {
        return true;
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


const char *virQEMUCapsGetBinary(virQEMUCaps *qemuCaps)
{
    return qemuCaps->binary;
}


void
virQEMUCapsSetArch(virQEMUCaps *qemuCaps,
                   virArch arch)
{
    qemuCaps->arch = arch;
}


virArch virQEMUCapsGetArch(virQEMUCaps *qemuCaps)
{
    return qemuCaps->arch;
}


unsigned int virQEMUCapsGetVersion(virQEMUCaps *qemuCaps)
{
    return qemuCaps->version;
}


unsigned int virQEMUCapsGetKVMVersion(virQEMUCaps *qemuCaps)
{
    return qemuCaps->kvmVersion;
}


const char *virQEMUCapsGetPackage(virQEMUCaps *qemuCaps)
{
    return qemuCaps->package;
}


bool virQEMUCapsGetKVMSupportsSecureGuest(virQEMUCaps *qemuCaps)
{
    return qemuCaps->kvmSupportsSecureGuest;
}


int
virQEMUCapsAddCPUDefinitions(virQEMUCaps *qemuCaps,
                             virDomainVirtType type,
                             const char **name,
                             size_t count,
                             virDomainCapsCPUUsable usable)
{
    size_t i;
    size_t start;
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, type);
    qemuMonitorCPUDefs *defs = accel->cpuModels;

    if (defs) {
        start = defs->ncpus;

        VIR_EXPAND_N(defs->cpus, defs->ncpus, count);
    } else {
        start = 0;

        if (!(defs = qemuMonitorCPUDefsNew(count)))
            return -1;

        accel->cpuModels = defs;
    }

    for (i = 0; i < count; i++) {
        qemuMonitorCPUDefInfo *cpu = defs->cpus + start + i;

        cpu->usable = usable;
        cpu->name = g_strdup(name[i]);
    }

    return 0;
}


static virDomainCapsCPUModels *
virQEMUCapsCPUDefsToModels(qemuMonitorCPUDefs *defs,
                           const char **modelAllowed,
                           const char **modelForbidden)
{
    g_autoptr(virDomainCapsCPUModels) cpuModels = NULL;
    size_t i;

    if (!(cpuModels = virDomainCapsCPUModelsNew(defs->ncpus)))
        return NULL;

    for (i = 0; i < defs->ncpus; i++) {
        qemuMonitorCPUDefInfo *cpu = defs->cpus + i;

        if (modelAllowed && !g_strv_contains(modelAllowed, cpu->name))
            continue;

        if (modelForbidden && g_strv_contains(modelForbidden, cpu->name))
            continue;

        if (virDomainCapsCPUModelsAdd(cpuModels, cpu->name, cpu->usable,
                                      cpu->blockers, cpu->deprecated) < 0)
            return NULL;
    }

    return g_steal_pointer(&cpuModels);
}


virDomainCapsCPUModels *
virQEMUCapsGetCPUModels(virQEMUCaps *qemuCaps,
                        virDomainVirtType type,
                        const char **modelAllowed,
                        const char **modelForbidden)
{
    qemuMonitorCPUDefs *defs;

    if (!(defs = virQEMUCapsGetAccel(qemuCaps, type)->cpuModels))
        return NULL;

    return virQEMUCapsCPUDefsToModels(defs, modelAllowed, modelForbidden);
}


virCPUDef *
virQEMUCapsGetHostModel(virQEMUCaps *qemuCaps,
                        virDomainVirtType type,
                        virQEMUCapsHostCPUType cpuType)
{
    virQEMUCapsHostCPUData *cpuData;

    cpuData = &virQEMUCapsGetAccel(qemuCaps, type)->hostCPU;
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
virQEMUCapsSetHostModel(virQEMUCaps *qemuCaps,
                        virDomainVirtType type,
                        virCPUDef *reported,
                        virCPUDef *migratable,
                        virCPUDef *full)
{
    virQEMUCapsHostCPUData *cpuData;

    cpuData = &virQEMUCapsGetAccel(qemuCaps, type)->hostCPU;
    cpuData->reported = reported;
    cpuData->migratable = migratable;
    cpuData->full = full;
}


bool
virQEMUCapsIsArchSupported(virQEMUCaps *qemuCaps,
                           virArch arch)
{
    if (arch == qemuCaps->arch)
        return true;

    if (qemuCaps->arch == VIR_ARCH_X86_64 && arch == VIR_ARCH_I686)
        return true;

    if (qemuCaps->arch == VIR_ARCH_AARCH64 && arch == VIR_ARCH_ARMV7L)
        return true;

    if (qemuCaps->arch == VIR_ARCH_ARMV7L && arch == VIR_ARCH_ARMV6L)
        return true;

    if (qemuCaps->arch == VIR_ARCH_PPC64 && arch == VIR_ARCH_PPC64LE)
        return true;

    return false;
}


bool
virQEMUCapsIsVirtTypeSupported(virQEMUCaps *qemuCaps,
                               virDomainVirtType virtType)
{
    if (virtType == VIR_DOMAIN_VIRT_QEMU &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_TCG))
        return true;

    if (virtType == VIR_DOMAIN_VIRT_KVM &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        return true;

    return false;
}

const char *s390HostPassthroughOnlyMachines[] = {
    "s390-ccw-virtio-2.4",
    "s390-ccw-virtio-2.5",
    "s390-ccw-virtio-2.6",
    "s390-ccw-virtio-2.7",
    NULL
};

bool
virQEMUCapsIsCPUModeSupported(virQEMUCaps *qemuCaps,
                              virArch hostarch,
                              virDomainVirtType type,
                              virCPUMode mode,
                              const char *machineType)
{
    qemuMonitorCPUDefs *cpus;

    /* CPU models (except for "host") are not supported by QEMU for on s390
     * KVM domains with old machine types regardless on QEMU version. */
    if (ARCH_IS_S390(qemuCaps->arch) &&
        type == VIR_DOMAIN_VIRT_KVM &&
        mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
        machineType &&
        g_strv_contains(s390HostPassthroughOnlyMachines, machineType)) {
        return false;
    }

    switch (mode) {
    case VIR_CPU_MODE_HOST_PASSTHROUGH:
        return type == VIR_DOMAIN_VIRT_KVM &&
               virQEMUCapsGuestIsNative(hostarch, qemuCaps->arch);

    case VIR_CPU_MODE_HOST_MODEL:
        return !!virQEMUCapsGetHostModel(qemuCaps, type,
                                         VIR_QEMU_CAPS_HOST_CPU_REPORTED);

    case VIR_CPU_MODE_CUSTOM:
        cpus = virQEMUCapsGetAccel(qemuCaps, type)->cpuModels;
        return cpus && cpus->ncpus > 0;

    case VIR_CPU_MODE_MAXIMUM:
        return virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MAX);

    case VIR_CPU_MODE_LAST:
        break;
    }

    return false;
}


/**
 * virQEMUCapsGetCanonicalMachine:
 * @qemuCaps: qemu capabilities object
 * @name: machine name
 *
 * Resolves aliased machine names to the actual machine name. If qemuCaps isn't
 * present @name is returned.
 */
const char *
virQEMUCapsGetCanonicalMachine(virQEMUCaps *qemuCaps,
                               virDomainVirtType virtType,
                               const char *name)
{
    virQEMUCapsAccel *accel;
    size_t i;

    if (!name || !qemuCaps)
        return name;

    accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (!accel->machineTypes[i].alias)
            continue;
        if (STREQ(accel->machineTypes[i].alias, name))
            return accel->machineTypes[i].name;
    }

    return name;
}


int
virQEMUCapsGetMachineMaxCpus(virQEMUCaps *qemuCaps,
                             virDomainVirtType virtType,
                             const char *name)
{
    virQEMUCapsAccel *accel;
    size_t i;

    if (!name)
        return 0;

    accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (!accel->machineTypes[i].maxCpus)
            continue;
        if (STREQ(accel->machineTypes[i].name, name))
            return accel->machineTypes[i].maxCpus;
    }

    return 0;
}


bool
virQEMUCapsGetMachineHotplugCpus(virQEMUCaps *qemuCaps,
                                 virDomainVirtType virtType,
                                 const char *name)
{
    virQEMUCapsAccel *accel;
    size_t i;

    accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ_NULLABLE(accel->machineTypes[i].name, name))
            return accel->machineTypes[i].hotplugCpus;
    }

    return false;
}


const char *
virQEMUCapsGetMachineDefaultCPU(virQEMUCaps *qemuCaps,
                                const char *name,
                                virDomainVirtType type)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, type);
    qemuMonitorCPUDefs *defs = accel->cpuModels;
    const char *cpuType = NULL;
    size_t i;

    if (!name || !defs)
        return NULL;

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ(accel->machineTypes[i].name, name)) {
            cpuType = accel->machineTypes[i].defaultCPU;
            break;
        }
    }

    if (!cpuType)
        return NULL;

    for (i = 0; i < defs->ncpus; i++) {
        if (STREQ_NULLABLE(defs->cpus[i].type, cpuType))
            return defs->cpus[i].name;
    }

    return NULL;
}


bool
virQEMUCapsIsCPUDeprecated(virQEMUCaps *qemuCaps,
                           virDomainVirtType type,
                           const char *model)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, type);
    qemuMonitorCPUDefs *defs = accel->cpuModels;
    size_t i;

    for (i = 0; i < defs->ncpus; i++) {
        if (STREQ_NULLABLE(defs->cpus[i].name, model))
            return defs->cpus[i].deprecated;
    }
    return false;
}


bool
virQEMUCapsIsMachineDeprecated(virQEMUCaps *qemuCaps,
                               virDomainVirtType type,
                               const char *machine)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, type);
    size_t i;

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ_NULLABLE(accel->machineTypes[i].name, machine))
            return accel->machineTypes[i].deprecated;
    }
    return false;
}


bool
virQEMUCapsGetMachineNumaMemSupported(virQEMUCaps *qemuCaps,
                                      virDomainVirtType virtType,
                                      const char *name)
{
    virQEMUCapsAccel *accel;
    size_t i;

    accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ(accel->machineTypes[i].name, name))
            return accel->machineTypes[i].numaMemSupported;
    }

    return false;
}


const char *
virQEMUCapsGetMachineDefaultRAMid(virQEMUCaps *qemuCaps,
                                  virDomainVirtType virtType,
                                  const char *name)
{
    virQEMUCapsAccel *accel;
    size_t i;

    accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ(accel->machineTypes[i].name, name))
            return accel->machineTypes[i].defaultRAMid;
    }

    return NULL;
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
virQEMUCapsSetGICCapabilities(virQEMUCaps *qemuCaps,
                              virGICCapability *capabilities,
                              size_t ncapabilities)
{
    VIR_FREE(qemuCaps->gicCapabilities);

    qemuCaps->gicCapabilities = capabilities;
    qemuCaps->ngicCapabilities = ncapabilities;
}


virSEVCapability *
virQEMUCapsGetSEVCapabilities(virQEMUCaps *qemuCaps)
{
    return qemuCaps->sevCapabilities;
}


static int
virQEMUCapsProbeQMPCommands(virQEMUCaps *qemuCaps,
                            qemuMonitor *mon)
{
    g_auto(GStrv) commands = NULL;

    if (qemuMonitorGetCommands(mon, &commands) < 0)
        return -1;

    virQEMUCapsProcessStringFlags(qemuCaps,
                                  G_N_ELEMENTS(virQEMUCapsCommands),
                                  virQEMUCapsCommands,
                                  commands);

    return 0;
}


static int
virQEMUCapsProbeQMPObjectTypes(virQEMUCaps *qemuCaps,
                               qemuMonitor *mon)
{
    g_auto(GStrv) values = NULL;

    if (qemuMonitorGetObjectTypes(mon, &values) < 0)
        return -1;
    virQEMUCapsProcessStringFlags(qemuCaps,
                                  G_N_ELEMENTS(virQEMUCapsObjectTypes),
                                  virQEMUCapsObjectTypes,
                                  values);

    return 0;
}


static int
virQEMUCapsProbeQMPDeviceProperties(virQEMUCaps *qemuCaps,
                                    qemuMonitor *mon)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsDeviceProps); i++) {
        virQEMUCapsDeviceTypeProps *device = virQEMUCapsDeviceProps + i;
        g_autoptr(GHashTable) qemuprops = NULL;
        size_t j;

        if (device->capsCondition >= 0 &&
            !virQEMUCapsGet(qemuCaps, device->capsCondition))
            continue;

        if (!(qemuprops = qemuMonitorGetDeviceProps(mon, device->type)))
            return -1;

        for (j = 0; j < device->nprops; j++) {
            virJSONValue *entry = virHashLookup(qemuprops, device->props[j].value);

            if (!entry)
                continue;

            virQEMUCapsSet(qemuCaps, device->props[j].flag);

            if (device->props[j].cb &&
                device->props[j].cb(entry, qemuCaps) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virQEMUCapsProbeQMPObjectProperties(virQEMUCaps *qemuCaps,
                                    qemuMonitor *mon)
{
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QOM_LIST_PROPERTIES))
        return 0;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsObjectProps); i++) {
        virQEMUCapsObjectTypeProps *props = virQEMUCapsObjectProps + i;
        g_auto(GStrv) values = NULL;

        if (props->capsCondition >= 0 &&
            !virQEMUCapsGet(qemuCaps, props->capsCondition))
            continue;

        if (qemuMonitorGetObjectProps(mon, props->type, &values) < 0)
            return -1;

        virQEMUCapsProcessStringFlags(qemuCaps,
                                      props->nprops,
                                      props->props,
                                      values);
    }

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
G_STATIC_ASSERT(G_N_ELEMENTS(preferredMachines) == VIR_ARCH_LAST);


void
virQEMUCapsAddMachine(virQEMUCaps *qemuCaps,
                      virDomainVirtType virtType,
                      const char *name,
                      const char *alias,
                      const char *defaultCPU,
                      int maxCpus,
                      bool hotplugCpus,
                      bool isDefault,
                      bool numaMemSupported,
                      const char *defaultRAMid,
                      bool deprecated)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, virtType);
    virQEMUCapsMachineType *mach;

    accel->machineTypes = g_renew(virQEMUCapsMachineType,
                                  accel->machineTypes,
                                  ++accel->nmachineTypes);

    mach = &(accel->machineTypes[accel->nmachineTypes - 1]);

    mach->alias = g_strdup(alias);
    mach->name = g_strdup(name);
    mach->defaultCPU = g_strdup(defaultCPU);

    mach->maxCpus = maxCpus;
    mach->hotplugCpus = hotplugCpus;

    mach->qemuDefault = isDefault;

    mach->numaMemSupported = numaMemSupported;

    mach->defaultRAMid = g_strdup(defaultRAMid);
    mach->deprecated = deprecated;
}

/**
 * virQEMUCapsHasMachines:
 * @qemuCaps: qemu capabilities object
 *
 * Returns true if @qemuCaps has at least one machine type defined. This is
 * called by the test suite to figure out whether to populate fake machine types
 * into the list.
 */
bool
virQEMUCapsHasMachines(virQEMUCaps *qemuCaps)
{

    return !!qemuCaps->kvm.nmachineTypes || !!qemuCaps->tcg.nmachineTypes;
}


static int
virQEMUCapsProbeQMPMachineTypes(virQEMUCaps *qemuCaps,
                                virDomainVirtType virtType,
                                qemuMonitor *mon)
{
    qemuMonitorMachineInfo **machines = NULL;
    int nmachines = 0;
    size_t i;
    ssize_t defIdx = -1;
    ssize_t preferredIdx = -1;
    const char *preferredMachine = preferredMachines[qemuCaps->arch];
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    if ((nmachines = qemuMonitorGetMachines(mon, &machines)) < 0)
        return -1;

    for (i = 0; i < nmachines; i++) {
        if (STREQ(machines[i]->name, "none"))
            continue;

        virQEMUCapsAddMachine(qemuCaps,
                              virtType,
                              machines[i]->name,
                              machines[i]->alias,
                              machines[i]->defaultCPU,
                              machines[i]->maxCpus,
                              machines[i]->hotplugCpus,
                              machines[i]->isDefault,
                              machines[i]->numaMemSupported,
                              machines[i]->defaultRAMid,
                              machines[i]->deprecated);

        if (preferredMachine &&
            (STREQ_NULLABLE(machines[i]->alias, preferredMachine) ||
             STREQ(machines[i]->name, preferredMachine))) {
            preferredIdx = accel->nmachineTypes - 1;
        }

        if (machines[i]->isDefault)
            defIdx = accel->nmachineTypes - 1;
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
        virQEMUCapsSetDefaultMachine(accel, preferredIdx);

    for (i = 0; i < nmachines; i++)
        qemuMonitorMachineInfoFree(machines[i]);
    VIR_FREE(machines);
    return 0;
}


bool
virQEMUCapsIsMachineSupported(virQEMUCaps *qemuCaps,
                              virDomainVirtType virtType,
                              const char *canonical_machine)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, virtType);
    size_t i;

    for (i = 0; i < accel->nmachineTypes; i++) {
        if (STREQ(canonical_machine, accel->machineTypes[i].name))
            return true;
    }
    return false;
}


static int
virQEMUCapsProbeQMPMachineProps(virQEMUCaps *qemuCaps,
                                virDomainVirtType virtType,
                                qemuMonitor *mon)
{
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QOM_LIST_PROPERTIES))
        return 0;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsMachineProps); i++) {
        virQEMUCapsObjectTypeProps props = virQEMUCapsMachineProps[i];
        const char *canon = virQEMUCapsGetCanonicalMachine(qemuCaps, virtType, props.type);
        g_autofree char *type = NULL;
        g_auto(GStrv) values = NULL;

        if (STRNEQ(canon, "none") &&
            !virQEMUCapsIsMachineSupported(qemuCaps, virtType, canon)) {
            continue;
        }

        /* The QOM type for machine types is the machine type name
         * followed by the -machine suffix */
        type = g_strdup_printf("%s-machine", canon);

        if (qemuMonitorGetObjectProps(mon, type, &values) < 0)
            return -1;

        virQEMUCapsProcessStringFlags(qemuCaps,
                                      props.nprops,
                                      props.props,
                                      values);
    }

    return 0;
}


static int
virQEMUCapsFetchCPUDefinitions(qemuMonitor *mon,
                               virArch arch,
                               qemuMonitorCPUDefs **cpuDefs)
{
    g_autoptr(qemuMonitorCPUDefs) defs = NULL;
    size_t i;

    *cpuDefs = NULL;

    if (qemuMonitorGetCPUDefinitions(mon, &defs) < 0)
        return -1;

    if (!defs)
        return 0;

    /* QEMU 2.11 for Power renamed all CPU models to lower case, we need to
     * translate them back to libvirt's upper case model names. */
    if (ARCH_IS_PPC64(arch)) {
        g_auto(GStrv) libvirtModels = NULL;
        char **name;

        if (virCPUGetModels(arch, &libvirtModels) < 0)
            return -1;

        for (name = libvirtModels; name && *name; name++) {
            for (i = 0; i < defs->ncpus; i++) {
                if (STRCASENEQ(defs->cpus[i].name, *name))
                    continue;

                VIR_FREE(defs->cpus[i].name);
                defs->cpus[i].name = g_strdup(*name);
            }
        }
    }

    *cpuDefs = g_steal_pointer(&defs);
    return 0;
}


int
virQEMUCapsFetchCPUModels(qemuMonitor *mon,
                          virArch arch,
                          virDomainCapsCPUModels **cpuModels)
{
    g_autoptr(qemuMonitorCPUDefs) defs = NULL;

    *cpuModels = NULL;

    if (virQEMUCapsFetchCPUDefinitions(mon, arch, &defs) < 0)
        return -1;

    if (defs && !(*cpuModels = virQEMUCapsCPUDefsToModels(defs, NULL, NULL)))
        return -1;

    return 0;
}


static int
virQEMUCapsProbeQMPCPUDefinitions(virQEMUCaps *qemuCaps,
                                  virQEMUCapsAccel *accel,
                                  qemuMonitor *mon)
{
    qemuMonitorCPUDefs *defs;
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_DEFINITIONS))
        return 0;

    if (virQEMUCapsFetchCPUDefinitions(mon, qemuCaps->arch, &accel->cpuModels) < 0)
        return -1;

    defs = accel->cpuModels;
    for (i = 0; i < defs->ncpus; i++) {
        if (STREQ_NULLABLE(defs->cpus[i].name, "max")) {
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_MAX);
            break;
        }
    }

    return 0;
}


int
virQEMUCapsProbeCPUDefinitionsTest(virQEMUCaps *qemuCaps,
                                   qemuMonitor *mon)
{
    return virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, &qemuCaps->kvm, mon);
}


static int
virQEMUCapsProbeQMPHostCPU(virQEMUCaps *qemuCaps,
                           virQEMUCapsAccel *accel,
                           qemuMonitor *mon,
                           virDomainVirtType virtType)
{
    const char *model = virtType == VIR_DOMAIN_VIRT_KVM ? "host" : "max";
    qemuMonitorCPUModelInfo *modelInfo = NULL;
    qemuMonitorCPUModelInfo *nonMigratable = NULL;
    GHashTable *hash = NULL;
    virCPUDef *cpu;
    qemuMonitorCPUModelExpansionType type;
    bool fail_no_props = true;
    int ret = -1;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION))
        return 0;

    cpu = virCPUDefNew();

    cpu->model = g_strdup(model);

    /* Some x86_64 features defined in src/cpu_map/ use spelling which differ
     * from the one preferred by QEMU. Static expansion would give us only the
     * preferred spelling. With new QEMU we always use the QEMU's canonical
     * names of all features and translate between them and our names. But for
     * older version of QEMU we need to do a full expansion on the result of
     * the initial static expansion to get all variants of feature names.
     */
    if (ARCH_IS_X86(qemuCaps->arch) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CANONICAL_CPU_FEATURES)) {
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL;
    } else if (ARCH_IS_ARM(qemuCaps->arch)) {
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_FULL;
    } else {
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC;
    }

    /* Older s390 models do not report a feature set */
    if (ARCH_IS_S390(qemuCaps->arch))
        fail_no_props = false;

    if (qemuMonitorGetCPUModelExpansion(mon, type, cpu, true, fail_no_props,
                                        &modelInfo) < 0)
        goto cleanup;

    /* Try to check migratability of each feature. */
    if (modelInfo &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION_MIGRATABLE) &&
        qemuMonitorGetCPUModelExpansion(mon, type, cpu, false, fail_no_props,
                                        &nonMigratable) < 0)
        goto cleanup;

    if (nonMigratable) {
        qemuMonitorCPUProperty *prop;
        qemuMonitorCPUProperty *nmProp;
        size_t i;

        hash = virHashNew(NULL);

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

    accel->hostCPU.info = g_steal_pointer(&modelInfo);
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
virQEMUCapsGetCPUFeatures(virQEMUCaps *qemuCaps,
                          virDomainVirtType virtType,
                          bool migratable,
                          char ***features)
{
    qemuMonitorCPUModelInfo *modelInfo;
    char **list;
    size_t i;
    size_t n;
    int ret = -1;

    *features = NULL;
    modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, virtType);

    if (!modelInfo)
        return 0;

    list = g_new0(char *, modelInfo->nprops + 1);

    n = 0;
    for (i = 0; i < modelInfo->nprops; i++) {
        qemuMonitorCPUProperty *prop = modelInfo->props + i;

        if (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO)
            continue;

        list[n++] = g_strdup(virQEMUCapsCPUFeatureFromQEMU(qemuCaps, prop->name));
    }

    *features = g_steal_pointer(&list);
    if (migratable && !modelInfo->migratability)
        ret = 1;
    else
        ret = 0;

    g_strfreev(list);
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
    {
        .type = VIR_DOMAIN_TPM_MODEL_SPAPR,
        .caps = QEMU_CAPS_DEVICE_TPM_SPAPR,
    },
};

static int
virQEMUCapsProbeQMPTPM(virQEMUCaps *qemuCaps,
                       qemuMonitor *mon)
{
    g_auto(GStrv) models = NULL;
    g_auto(GStrv) types = NULL;
    size_t i;

    if (qemuMonitorGetTPMModels(mon, &models) < 0)
        return -1;

    if (!models)
        return 0;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsTPMModelsToCaps); i++) {
        const char *needle = virDomainTPMModelTypeToString(virQEMUCapsTPMModelsToCaps[i].type);
        if (g_strv_contains((const char **)models, needle))
            virQEMUCapsSet(qemuCaps, virQEMUCapsTPMModelsToCaps[i].caps);
    }

    if (qemuMonitorGetTPMTypes(mon, &types) < 0)
        return -1;

    if (!types)
        return 0;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsTPMTypesToCaps); i++) {
        const char *needle = virDomainTPMBackendTypeToString(virQEMUCapsTPMTypesToCaps[i].type);
        if (g_strv_contains((const char **)types, needle))
            virQEMUCapsSet(qemuCaps, virQEMUCapsTPMTypesToCaps[i].caps);
    }

    return 0;
}


static int
virQEMUCapsProbeQMPKVMState(virQEMUCaps *qemuCaps,
                            qemuMonitor *mon)
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
    { "smp-opts", "dies", QEMU_CAPS_SMP_DIES },
    { "fsdev", "multidevs", QEMU_CAPS_FSDEV_MULTIDEVS },
    { "fw_cfg", "file", QEMU_CAPS_FW_CFG },
    { "fsdev", "fmode", QEMU_CAPS_FSDEV_CREATEMODE }, /* Could have also checked fsdev->dmode */
    { "vnc", "display", QEMU_CAPS_VNC_OPTS },
    { "vnc", "power-control", QEMU_CAPS_VNC_POWER_CONTROL },
    { "vnc", "audiodev", QEMU_CAPS_AUDIODEV },
};

static int
virQEMUCapsProbeQMPCommandLine(virQEMUCaps *qemuCaps,
                               qemuMonitor *mon)
{
    g_autoptr(GHashTable) options = NULL;
    size_t i;

    if (!(options = qemuMonitorGetCommandLineOptions(mon)))
        return -1;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsCommandLine); i++) {
        virJSONValue *option = g_hash_table_lookup(options, virQEMUCapsCommandLine[i].option);
        size_t j;

        if (!option)
            continue;

        /* not looking for a specific argument */
        if (!virQEMUCapsCommandLine[i].param) {
            virQEMUCapsSet(qemuCaps, virQEMUCapsCommandLine[i].flag);
            continue;
        }

        for (j = 0; j < virJSONValueArraySize(option); j++) {
            virJSONValue *param = virJSONValueArrayGet(option, j);
            const char *paramname = virJSONValueObjectGetString(param, "name");

            if (STREQ_NULLABLE(virQEMUCapsCommandLine[i].param, paramname))
                virQEMUCapsSet(qemuCaps, virQEMUCapsCommandLine[i].flag);
        }
    }

    return 0;
}

static int
virQEMUCapsProbeQMPMigrationCapabilities(virQEMUCaps *qemuCaps,
                                         qemuMonitor *mon)
{
    g_auto(GStrv) caps = NULL;

    if (qemuMonitorGetMigrationCapabilities(mon, &caps) < 0)
        return -1;

    virQEMUCapsProcessStringFlags(qemuCaps,
                                  G_N_ELEMENTS(virQEMUCapsMigration),
                                  virQEMUCapsMigration,
                                  caps);

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
virQEMUCapsProbeQMPGICCapabilities(virQEMUCaps *qemuCaps,
                                   qemuMonitor *mon)
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
virQEMUCapsProbeQMPSEVCapabilities(virQEMUCaps *qemuCaps,
                                   qemuMonitor *mon)
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
                             virCPUFeaturePolicy policy G_GNUC_UNUSED,
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
virQEMUCapsCPUFeatureTranslate(virQEMUCaps *qemuCaps,
                               const char *feature,
                               bool reversed)
{
    virQEMUCapsCPUFeatureTranslationTable *table = NULL;
    virQEMUCapsCPUFeatureTranslationTable *entry;

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
virQEMUCapsCPUFeatureToQEMU(virQEMUCaps *qemuCaps,
                            const char *feature)
{
    return virQEMUCapsCPUFeatureTranslate(qemuCaps, feature, false);
}


const char *
virQEMUCapsCPUFeatureFromQEMU(virQEMUCaps *qemuCaps,
                              const char *feature)
{
    return virQEMUCapsCPUFeatureTranslate(qemuCaps, feature, true);
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to using virCaps *->host.cpu,
 *          2 when cpu model info is not supported for this configuration,
 *         -1 on error.
 */
static int
virQEMUCapsInitCPUModelS390(virQEMUCaps *qemuCaps,
                            virDomainVirtType type,
                            qemuMonitorCPUModelInfo *modelInfo,
                            virCPUDef *cpu,
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

    cpu->model = g_strdup(modelInfo->name);
    cpu->features = g_new0(virCPUFeatureDef, modelInfo->nprops);

    cpu->nfeatures_max = modelInfo->nprops;
    cpu->nfeatures = 0;

    for (i = 0; i < modelInfo->nprops; i++) {
        virCPUFeatureDef *feature = cpu->features + cpu->nfeatures;
        qemuMonitorCPUProperty *prop = modelInfo->props + i;
        const char *name = virQEMUCapsCPUFeatureFromQEMU(qemuCaps, prop->name);

        if (prop->type != QEMU_MONITOR_CPU_PROPERTY_BOOLEAN)
            continue;

        feature->name = g_strdup(name);

        if (!prop->value.boolean ||
            (migratable && prop->migratable == VIR_TRISTATE_BOOL_NO))
            feature->policy = VIR_CPU_FEATURE_DISABLE;
        else
            feature->policy = VIR_CPU_FEATURE_REQUIRE;
        cpu->nfeatures++;
    }

    return 0;
}


virCPUData *
virQEMUCapsGetCPUModelX86Data(virQEMUCaps *qemuCaps,
                              qemuMonitorCPUModelInfo *model,
                              bool migratable)
{
    unsigned long long sigFamily = 0;
    unsigned long long sigModel = 0;
    unsigned long long sigStepping = 0;
    virCPUData *data = NULL;
    virCPUData *ret = NULL;
    size_t i;

    if (!(data = virCPUDataNew(VIR_ARCH_X86_64)))
        goto cleanup;

    for (i = 0; i < model->nprops; i++) {
        qemuMonitorCPUProperty *prop = model->props + i;
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

    ret = g_steal_pointer(&data);

 cleanup:
    virCPUDataFree(data);
    return ret;
}


/**
 * Returns  0 when host CPU model provided by QEMU was filled in qemuCaps,
 *          1 when the caller should fall back to using virCaps *->host.cpu,
 *         -1 on error.
 */
static int
virQEMUCapsInitCPUModelX86(virQEMUCaps *qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfo *model,
                           virCPUDef *cpu,
                           bool migratable)
{
    g_autoptr(virDomainCapsCPUModels) cpuModels = NULL;
    virCPUData *data = NULL;
    int ret = -1;

    if (!model)
        return 1;

    if (!(data = virQEMUCapsGetCPUModelX86Data(qemuCaps, model, migratable)))
        goto cleanup;

    cpuModels = virQEMUCapsGetCPUModels(qemuCaps, type, NULL, NULL);

    if (cpuDecode(cpu, data, cpuModels) < 0)
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
virQEMUCapsInitCPUModel(virQEMUCaps *qemuCaps,
                        virDomainVirtType type,
                        virCPUDef *cpu,
                        bool migratable)
{
    qemuMonitorCPUModelInfo *modelInfo = virQEMUCapsGetCPUModelInfo(qemuCaps, type);
    int ret = 1;

    if (migratable && modelInfo && !modelInfo->migratability)
        return 1;

    if (ARCH_IS_S390(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelS390(qemuCaps, type, modelInfo,
                                          cpu, migratable);
    } else if (ARCH_IS_X86(qemuCaps->arch)) {
        ret = virQEMUCapsInitCPUModelX86(qemuCaps, type, modelInfo,
                                         cpu, migratable);
    } else if (ARCH_IS_ARM(qemuCaps->arch)) {
        ret = 2;
    }

    if (ret == 0)
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    return ret;
}


static virCPUDef *
virQEMUCapsNewHostCPUModel(void)
{
    virCPUDef *cpu = virCPUDefNew();

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->mode = VIR_CPU_MODE_CUSTOM;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_ALLOW;

    return cpu;
}


void
virQEMUCapsInitHostCPUModel(virQEMUCaps *qemuCaps,
                            virArch hostArch,
                            virDomainVirtType type)
{
    virCPUDef *cpu = NULL;
    virCPUDef *cpuExpanded = NULL;
    virCPUDef *migCPU = NULL;
    virCPUDef *hostCPU = NULL;
    virCPUDef *fullCPU = NULL;
    size_t i;
    int rc;

    if (!virQEMUCapsGuestIsNative(hostArch, qemuCaps->arch))
        return;

    if (!(cpu = virQEMUCapsNewHostCPUModel()))
        goto error;

    if ((rc = virQEMUCapsInitCPUModel(qemuCaps, type, cpu, false)) < 0) {
        goto error;
    } else if (rc == 1) {
        g_autoptr(virDomainCapsCPUModels) cpuModels = NULL;

        VIR_DEBUG("No host CPU model info from QEMU; probing host CPU directly");

        cpuModels = virQEMUCapsGetCPUModels(qemuCaps, type, NULL, NULL);
        hostCPU = virQEMUCapsProbeHostCPU(hostArch, cpuModels);

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


void
virQEMUCapsUpdateHostCPUModel(virQEMUCaps *qemuCaps,
                            virArch hostArch,
                            virDomainVirtType type)
{
    virQEMUCapsHostCPUDataClear(&virQEMUCapsGetAccel(qemuCaps, type)->hostCPU);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, type);
}

qemuMonitorCPUModelInfo *
virQEMUCapsGetCPUModelInfo(virQEMUCaps *qemuCaps,
                           virDomainVirtType type)
{
    return virQEMUCapsGetAccel(qemuCaps, type)->hostCPU.info;
}


void
virQEMUCapsSetCPUModelInfo(virQEMUCaps *qemuCaps,
                           virDomainVirtType type,
                           qemuMonitorCPUModelInfo *modelInfo)
{
    virQEMUCapsGetAccel(qemuCaps, type)->hostCPU.info = modelInfo;
}


static int
virQEMUCapsLoadHostCPUModelInfo(virQEMUCapsAccel *caps,
                                xmlXPathContextPtr ctxt,
                                const char *typeStr)
{
    char *str = NULL;
    xmlNodePtr hostCPUNode;
    xmlNodePtr *nodes = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    qemuMonitorCPUModelInfo *hostCPU = NULL;
    g_autofree char *xpath = g_strdup_printf("./hostCPU[@type='%s']", typeStr);
    int ret = -1;
    size_t i;
    int n;
    int val;

    if (!(hostCPUNode = virXPathNode(xpath, ctxt))) {
        ret = 0;
        goto cleanup;
    }

    hostCPU = g_new0(qemuMonitorCPUModelInfo, 1);

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
        hostCPU->props = g_new0(qemuMonitorCPUProperty, n);
        hostCPU->nprops = n;

        for (i = 0; i < n; i++) {
            qemuMonitorCPUProperty *prop = hostCPU->props + i;

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

    caps->hostCPU.info = g_steal_pointer(&hostCPU);
    ret = 0;

 cleanup:
    VIR_FREE(str);
    VIR_FREE(nodes);
    qemuMonitorCPUModelInfoFree(hostCPU);
    return ret;
}


static int
virQEMUCapsLoadCPUModels(virQEMUCapsAccel *caps,
                         xmlXPathContextPtr ctxt,
                         const char *typeStr)
{
    g_autoptr(qemuMonitorCPUDefs) defs = NULL;
    g_autofree xmlNodePtr * nodes = NULL;
    g_autofree char *xpath = g_strdup_printf("./cpu[@type='%s']", typeStr);
    size_t i;
    int n;
    xmlNodePtr node;

    if ((n = virXPathNodeSet(xpath, ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities cpus"));
        return -1;
    }

    if (n == 0)
        return 0;

    if (!(defs = qemuMonitorCPUDefsNew(n)))
        return -1;

    for (i = 0; i < n; i++) {
        qemuMonitorCPUDefInfo *cpu = defs->cpus + i;
        int usable = VIR_DOMCAPS_CPU_USABLE_UNKNOWN;
        g_autofree char * strUsable = NULL;
        g_autofree xmlNodePtr * blockerNodes = NULL;
        g_autofree char *deprecated = NULL;
        int nblockers;

        if ((strUsable = virXMLPropString(nodes[i], "usable")) &&
            (usable = virDomainCapsCPUUsableTypeFromString(strUsable)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown value '%s' in attribute 'usable'"),
                           strUsable);
            return -1;
        }
        cpu->usable = usable;

        if (!(cpu->name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing cpu name in QEMU capabilities cache"));
            return -1;
        }

        cpu->type = virXMLPropString(nodes[i], "typename");

        node = ctxt->node;
        ctxt->node = nodes[i];
        nblockers = virXPathNodeSet("./blocker", ctxt, &blockerNodes);
        ctxt->node = node;

        if (nblockers < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to parse CPU blockers in QEMU capabilities"));
            return -1;
        }

        if (nblockers > 0) {
            size_t j;

            cpu->blockers = g_new0(char *, nblockers + 1);

            for (j = 0; j < nblockers; j++) {
                if (!(cpu->blockers[j] = virXMLPropString(blockerNodes[j], "name"))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("missing blocker name in QEMU "
                                     "capabilities cache"));
                    return -1;
                }
            }
        }

        deprecated = virXMLPropString(nodes[i], "deprecated");
        if (deprecated &&
            STREQ(deprecated, "yes"))
            cpu->deprecated = true;
    }

    caps->cpuModels = g_steal_pointer(&defs);
    return 0;
}


static int
virQEMUCapsLoadMachines(virQEMUCapsAccel *caps,
                        xmlXPathContextPtr ctxt,
                        const char *typeStr)
{
    g_autofree char *xpath = g_strdup_printf("./machine[@type='%s']", typeStr);
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    if ((n = virXPathNodeSet(xpath, ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities machines"));
        return -1;
    }

    if (n == 0)
        return 0;

    caps->nmachineTypes = n;
    caps->machineTypes = g_new0(virQEMUCapsMachineType, caps->nmachineTypes);

    for (i = 0; i < n; i++) {
        g_autofree char *str = NULL;

        if (!(caps->machineTypes[i].name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing machine name in QEMU capabilities cache"));
            return -1;
        }
        caps->machineTypes[i].alias = virXMLPropString(nodes[i], "alias");

        str = virXMLPropString(nodes[i], "maxCpus");
        if (str &&
            virStrToLong_ui(str, NULL, 10, &(caps->machineTypes[i].maxCpus)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("malformed machine cpu count in QEMU capabilities cache"));
            return -1;
        }
        VIR_FREE(str);

        str = virXMLPropString(nodes[i], "hotplugCpus");
        if (STREQ_NULLABLE(str, "yes"))
            caps->machineTypes[i].hotplugCpus = true;
        VIR_FREE(str);

        str = virXMLPropString(nodes[i], "default");
        if (STREQ_NULLABLE(str, "yes"))
            caps->machineTypes[i].qemuDefault = true;
        VIR_FREE(str);

        str = virXMLPropString(nodes[i], "numaMemSupported");
        if (STREQ_NULLABLE(str, "yes"))
            caps->machineTypes[i].numaMemSupported = true;
        VIR_FREE(str);

        caps->machineTypes[i].defaultCPU = virXMLPropString(nodes[i], "defaultCPU");
        caps->machineTypes[i].defaultRAMid = virXMLPropString(nodes[i], "defaultRAMid");

        str = virXMLPropString(nodes[i], "deprecated");
        if (STREQ_NULLABLE(str, "yes"))
            caps->machineTypes[i].deprecated = true;
        VIR_FREE(str);
    }

    return 0;
}


static int
virQEMUCapsLoadAccel(virQEMUCaps *qemuCaps,
                     xmlXPathContextPtr ctxt,
                     virDomainVirtType type)
{
    virQEMUCapsAccel *caps = virQEMUCapsGetAccel(qemuCaps, type);
    const char *typeStr = type == VIR_DOMAIN_VIRT_KVM ? "kvm" : "tcg";

    if (virQEMUCapsLoadHostCPUModelInfo(caps, ctxt, typeStr) < 0)
        return -1;

    if (virQEMUCapsLoadCPUModels(caps, ctxt, typeStr) < 0)
        return -1;

    if (virQEMUCapsLoadMachines(caps, ctxt, typeStr) < 0)
        return -1;

    return 0;
}


struct _virQEMUCapsCachePriv {
    char *libDir;
    uid_t runUid;
    gid_t runGid;
    virArch hostArch;
    unsigned int microcodeVersion;
    char *kernelVersion;
    char *hostCPUSignature;

    /* cache whether /dev/kvm is usable as runUid:runGuid */
    virTristateBool kvmUsable;
    time_t kvmCtime;
};
typedef struct _virQEMUCapsCachePriv virQEMUCapsCachePriv;


static void
virQEMUCapsCachePrivFree(void *privData)
{
    virQEMUCapsCachePriv *priv = privData;

    g_free(priv->libDir);
    g_free(priv->kernelVersion);
    g_free(priv->hostCPUSignature);
    g_free(priv);
}


static int
virQEMUCapsParseSEVInfo(virQEMUCaps *qemuCaps, xmlXPathContextPtr ctxt)
{
    g_autoptr(virSEVCapability) sev = NULL;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST))
        return 0;

    if (virXPathBoolean("boolean(./sev)", ctxt) == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing SEV platform data in QEMU "
                         "capabilities cache"));
        return -1;
    }

    sev = g_new0(virSEVCapability, 1);

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

    qemuCaps->sevCapabilities = g_steal_pointer(&sev);
    return 0;
}


/*
 * Parsing a doc that looks like
 *
 * <qemuCaps>
 *   <emulator>/some/path</emulator>
 *   <qemuctime>234235253</qemuctime>
 *   <qemumoddirmtime>234235253</qemumoddirmtime>
 *   <selfctime>234235253</selfctime>
 *   <selfvers>1002016</selfvers>
 *   <flag name='foo'/>
 *   <flag name='bar'/>
 *   ...
 *   <cpu name="pentium3"/>
 *   ...
 *   <machine name='pc-1.0' alias='pc' hotplugCpus='yes' maxCpus='4' default='yes' numaMemSupported='yes'/>
 *   ...
 * </qemuCaps>
 *
 * Returns 0 on success, 1 if outdated, -1 on error
 */
int
virQEMUCapsLoadCache(virArch hostArch,
                     virQEMUCaps *qemuCaps,
                     const char *filename,
                     bool skipInvalidation)
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

    if (virXPathLongLong("string(./selfctime)", ctxt, &l) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing selfctime in QEMU capabilities XML"));
        goto cleanup;
    }
    qemuCaps->libvirtCtime = (time_t)l;

    qemuCaps->libvirtVersion = 0;
    if (virXPathULong("string(./selfvers)", ctxt, &lu) == 0)
        qemuCaps->libvirtVersion = lu;

    if (!skipInvalidation &&
        (qemuCaps->libvirtCtime != virGetSelfLastChanged() ||
         qemuCaps->libvirtVersion != LIBVIR_VERSION_NUMBER)) {
        VIR_DEBUG("Outdated capabilities in %s: libvirt changed "
                  "(%lld vs %lld, %lu vs %lu), stopping load",
                  qemuCaps->binary,
                  (long long)qemuCaps->libvirtCtime,
                  (long long)virGetSelfLastChanged(),
                  (unsigned long)qemuCaps->libvirtVersion,
                  (unsigned long)LIBVIR_VERSION_NUMBER);
        ret = 1;
        goto cleanup;
    }

    if (!(str = virXPathString("string(./emulator)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing emulator in QEMU capabilities cache"));
        goto cleanup;
    }
    if (STRNEQ(str, qemuCaps->binary)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expected caps for '%s' but saw '%s'"),
                       qemuCaps->binary, str);
        goto cleanup;
    }
    VIR_FREE(str);
    if (virXPathLongLong("string(./qemuctime)", ctxt, &l) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing qemuctime in QEMU capabilities XML"));
        goto cleanup;
    }
    qemuCaps->ctime = (time_t)l;

    if (virXPathLongLong("string(./qemumoddirmtime)", ctxt, &l) == 0)
        qemuCaps->modDirMtime = (time_t)l;

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

    qemuCaps->hostCPUSignature = virXPathString("string(./hostCPUSignature)", ctxt);

    if (virXPathBoolean("boolean(./package)", ctxt) > 0) {
        qemuCaps->package = virXPathString("string(./package)", ctxt);
        if (!qemuCaps->package)
            qemuCaps->package = g_strdup("");
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

    if (virQEMUCapsLoadAccel(qemuCaps, ctxt, VIR_DOMAIN_VIRT_KVM) < 0 ||
        virQEMUCapsLoadAccel(qemuCaps, ctxt, VIR_DOMAIN_VIRT_QEMU) < 0)
        goto cleanup;

    if ((n = virXPathNodeSet("./gic", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to parse qemu capabilities gic"));
        goto cleanup;
    }
    if (n > 0) {
        unsigned int uintValue;
        bool boolValue;

        qemuCaps->ngicCapabilities = n;
        qemuCaps->gicCapabilities = g_new0(virGICCapability, n);

        for (i = 0; i < n; i++) {
            virGICCapability *cap = &qemuCaps->gicCapabilities[i];

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

    if (virXPathBoolean("boolean(./kvmSupportsSecureGuest)", ctxt) > 0)
        qemuCaps->kvmSupportsSecureGuest = true;

    if (skipInvalidation)
        qemuCaps->invalidation = false;

    ret = 0;
 cleanup:
    VIR_FREE(str);
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return ret;
}


static void
virQEMUCapsFormatHostCPUModelInfo(virQEMUCapsAccel *caps,
                                  virBuffer *buf,
                                  const char *typeStr)
{
    qemuMonitorCPUModelInfo *model = caps->hostCPU.info;
    size_t i;

    if (!model)
        return;

    virBufferAsprintf(buf,
                      "<hostCPU type='%s' model='%s' migratability='%s'>\n",
                      typeStr, model->name,
                      model->migratability ? "yes" : "no");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < model->nprops; i++) {
        qemuMonitorCPUProperty *prop = model->props + i;

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
virQEMUCapsFormatCPUModels(virQEMUCapsAccel *caps,
                           virBuffer *buf,
                           const char *typeStr)
{
    qemuMonitorCPUDefs *defs = caps->cpuModels;
    size_t i;

    if (!defs)
        return;

    for (i = 0; i < defs->ncpus; i++) {
        qemuMonitorCPUDefInfo *cpu = defs->cpus + i;

        virBufferAsprintf(buf, "<cpu type='%s' ", typeStr);
        virBufferEscapeString(buf, "name='%s'", cpu->name);
        virBufferEscapeString(buf, " typename='%s'", cpu->type);
        if (cpu->usable) {
            virBufferAsprintf(buf, " usable='%s'",
                              virDomainCapsCPUUsableTypeToString(cpu->usable));
        }
        if (cpu->deprecated)
            virBufferAddLit(buf, " deprecated='yes'");

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
virQEMUCapsFormatMachines(virQEMUCapsAccel *caps,
                          virBuffer *buf,
                          const char *typeStr)
{
    size_t i;

    for (i = 0; i < caps->nmachineTypes; i++) {
        virBufferAsprintf(buf, "<machine type='%s'", typeStr);
        virBufferEscapeString(buf, " name='%s'",
                              caps->machineTypes[i].name);
        virBufferEscapeString(buf, " alias='%s'",
                              caps->machineTypes[i].alias);
        if (caps->machineTypes[i].hotplugCpus)
            virBufferAddLit(buf, " hotplugCpus='yes'");
        virBufferAsprintf(buf, " maxCpus='%u'",
                          caps->machineTypes[i].maxCpus);
        if (caps->machineTypes[i].qemuDefault)
            virBufferAddLit(buf, " default='yes'");
        virBufferEscapeString(buf, " defaultCPU='%s'",
                              caps->machineTypes[i].defaultCPU);
        if (caps->machineTypes[i].numaMemSupported)
            virBufferAddLit(buf, " numaMemSupported='yes'");
        virBufferEscapeString(buf, " defaultRAMid='%s'",
                              caps->machineTypes[i].defaultRAMid);
        if (caps->machineTypes[i].deprecated)
            virBufferAddLit(buf, " deprecated='yes'");
        virBufferAddLit(buf, "/>\n");
    }
}


static void
virQEMUCapsFormatAccel(virQEMUCaps *qemuCaps,
                       virBuffer *buf,
                       virDomainVirtType type)
{
    virQEMUCapsAccel *caps = virQEMUCapsGetAccel(qemuCaps, type);
    const char *typeStr = type == VIR_DOMAIN_VIRT_KVM ? "kvm" : "tcg";

    virQEMUCapsFormatHostCPUModelInfo(caps, buf, typeStr);
    virQEMUCapsFormatCPUModels(caps, buf, typeStr);
    virQEMUCapsFormatMachines(caps, buf, typeStr);

}


static void
virQEMUCapsFormatSEVInfo(virQEMUCaps *qemuCaps, virBuffer *buf)
{
    virSEVCapability *sev = virQEMUCapsGetSEVCapabilities(qemuCaps);

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
virQEMUCapsFormatCache(virQEMUCaps *qemuCaps)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAddLit(&buf, "<qemuCaps>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<emulator>%s</emulator>\n",
                          qemuCaps->binary);
    virBufferAsprintf(&buf, "<qemuctime>%llu</qemuctime>\n",
                      (long long)qemuCaps->ctime);
    if (qemuCaps->modDirMtime > 0) {
        virBufferAsprintf(&buf, "<qemumoddirmtime>%llu</qemumoddirmtime>\n",
                          (long long)qemuCaps->modDirMtime);
    }
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
    virBufferEscapeString(&buf, "<hostCPUSignature>%s</hostCPUSignature>\n",
                          qemuCaps->hostCPUSignature);

    if (qemuCaps->package)
        virBufferAsprintf(&buf, "<package>%s</package>\n",
                          qemuCaps->package);

    if (qemuCaps->kernelVersion)
        virBufferAsprintf(&buf, "<kernelVersion>%s</kernelVersion>\n",
                          qemuCaps->kernelVersion);

    virBufferAsprintf(&buf, "<arch>%s</arch>\n",
                      virArchToString(qemuCaps->arch));

    virQEMUCapsFormatAccel(qemuCaps, &buf, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsFormatAccel(qemuCaps, &buf, VIR_DOMAIN_VIRT_QEMU);

    for (i = 0; i < qemuCaps->ngicCapabilities; i++) {
        virGICCapability *cap;
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

    if (qemuCaps->kvmSupportsSecureGuest)
        virBufferAddLit(&buf, "<kvmSupportsSecureGuest/>\n");

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</qemuCaps>\n");

    return virBufferContentAndReset(&buf);
}


static int
virQEMUCapsSaveFile(void *data,
                    const char *filename,
                    void *privData G_GNUC_UNUSED)
{
    virQEMUCaps *qemuCaps = data;
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


/*
 * Check whether IBM Secure Execution (S390) is enabled
 */
static bool
virQEMUCapsKVMSupportsSecureGuestS390(void)
{

    g_autofree char *cmdline = NULL;
    static const char *kValues[] = {"y", "Y", "on", "ON", "oN", "On", "1"};

    if (!virFileIsDir("/sys/firmware/uv"))
        return false;

    if (virFileReadValueString(&cmdline, "/proc/cmdline") < 0)
        return false;

    /* we're prefix matching rather than equality matching here, because kernel
     * would treat even something like prot_virt='yFOO' as enabled */
    if (virKernelCmdlineMatchParam(cmdline, "prot_virt", kValues,
                                   G_N_ELEMENTS(kValues),
                                   VIR_KERNEL_CMDLINE_FLAGS_SEARCH_FIRST |
                                   VIR_KERNEL_CMDLINE_FLAGS_CMP_PREFIX))
        return true;

    return false;
}


/*
 * Check whether AMD Secure Encrypted Virtualization (x86) is enabled
 */
static bool
virQEMUCapsKVMSupportsSecureGuestAMD(void)
{
    g_autofree char *modValue = NULL;

    if (virFileReadValueString(&modValue, "/sys/module/kvm_amd/parameters/sev") < 0)
        return false;

    if (modValue[0] != '1')
        return false;

    if (virFileExists(QEMU_DEV_SEV))
        return true;

    return false;
}


/*
 * Check whether the secure guest functionality is enabled.
 * See the specific architecture function for details on the verifications made.
 */
static bool
virQEMUCapsKVMSupportsSecureGuest(void)
{
    virArch arch = virArchFromHost();

    if (ARCH_IS_S390(arch))
        return virQEMUCapsKVMSupportsSecureGuestS390();

    if (ARCH_IS_X86(arch))
        return virQEMUCapsKVMSupportsSecureGuestAMD();

    return false;
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
    g_autofree char *value = NULL;
    int rc;
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(kmod); i++) {
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
virQEMUCapsKVMUsable(virQEMUCapsCachePriv *priv)
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
    virQEMUCaps *qemuCaps = data;
    virQEMUCapsCachePriv *priv = privData;
    bool kvmUsable;
    struct stat sb;
    bool kvmSupportsNesting;

    if (!qemuCaps->invalidation)
        return true;

    if (!qemuCaps->binary)
        return true;

    if (virFileExists(QEMU_MODDIR)) {
        if (stat(QEMU_MODDIR, &sb) < 0) {
            VIR_DEBUG("Failed to stat QEMU module directory '%s': %s",
                      QEMU_MODDIR,
                      g_strerror(errno));
            return false;
        }

        if (sb.st_mtime != qemuCaps->modDirMtime) {
            VIR_DEBUG("Outdated capabilities for '%s': QEMU modules "
                      "directory '%s' changed (%lld vs %lld)",
                      qemuCaps->binary, QEMU_MODDIR,
                      (long long)sb.st_mtime, (long long)qemuCaps->modDirMtime);
            return false;
        }
    }

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
        VIR_DEBUG("Failed to stat QEMU binary '%s': %s",
                  qemuCaps->binary,
                  g_strerror(errno));
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
        if (STRNEQ_NULLABLE(priv->hostCPUSignature, qemuCaps->hostCPUSignature)) {
            VIR_DEBUG("Outdated capabilities for '%s': host CPU changed "
                      "('%s' vs '%s')",
                      qemuCaps->binary,
                      priv->hostCPUSignature,
                      qemuCaps->hostCPUSignature);
            return false;
        }

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

        if (virQEMUCapsKVMSupportsSecureGuest() != qemuCaps->kvmSupportsSecureGuest) {
            VIR_DEBUG("Outdated capabilities for '%s': kvm kernel secure guest "
                      "value changed from %d",
                      qemuCaps->binary, qemuCaps->kvmSupportsSecureGuest);
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
virQEMUCapsInitQMPArch(virQEMUCaps *qemuCaps,
                            qemuMonitor *mon)
{
    g_autofree char *archstr = NULL;

    if (!(archstr = qemuMonitorGetTargetArch(mon)))
        return -1;

    if ((qemuCaps->arch = virQEMUCapsArchFromString(archstr)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown QEMU arch %s"), archstr);
        return -1;
    }

    return 0;
}


/**
 * virQEMUCapsInitQMPBasicArch:
 * @qemuCaps: QEMU capabilities
 *
 * Initialize @qemuCaps with basic always present and architecture-dependent
 * capabilities.
 */
void
virQEMUCapsInitQMPBasicArch(virQEMUCaps *qemuCaps)
{
    switch (qemuCaps->arch) {
    case VIR_ARCH_I686:
    case VIR_ARCH_X86_64:
        /* ACPI only works on x86 and aarch64 */
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_ACPI);

        /* HPET is x86 specific */
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_HPET);
        break;

    case VIR_ARCH_AARCH64:
        /* ACPI only works on x86 and aarch64 */
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_NO_ACPI);

        /* -cpu ...,aarch64=off is not detectable via qmp at this point */
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_AARCH64_OFF);

        /* gic is arm specific */
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACH_VIRT_GIC_VERSION);
        break;

    case VIR_ARCH_PPC64:
    case VIR_ARCH_PPC64LE:
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_MAX_CPU_COMPAT);
        break;

    case VIR_ARCH_ALPHA:
    case VIR_ARCH_PPC:
    case VIR_ARCH_PPCEMB:
    case VIR_ARCH_SH4:
    case VIR_ARCH_SH4EB:
    case VIR_ARCH_RISCV32:
    case VIR_ARCH_RISCV64:
    case VIR_ARCH_S390:
    case VIR_ARCH_S390X:
    case VIR_ARCH_SPARC:
    case VIR_ARCH_SPARC64:
    case VIR_ARCH_ARMV6L:
    case VIR_ARCH_ARMV7L:
    case VIR_ARCH_ARMV7B:
    case VIR_ARCH_CRIS:
    case VIR_ARCH_ITANIUM:
    case VIR_ARCH_LM32:
    case VIR_ARCH_M68K:
    case VIR_ARCH_MICROBLAZE:
    case VIR_ARCH_MICROBLAZEEL:
    case VIR_ARCH_MIPS:
    case VIR_ARCH_MIPSEL:
    case VIR_ARCH_MIPS64:
    case VIR_ARCH_MIPS64EL:
    case VIR_ARCH_OR32:
    case VIR_ARCH_PARISC:
    case VIR_ARCH_PARISC64:
    case VIR_ARCH_PPCLE:
    case VIR_ARCH_UNICORE32:
    case VIR_ARCH_XTENSA:
    case VIR_ARCH_XTENSAEB:
    case VIR_ARCH_NONE:
    case VIR_ARCH_LAST:
    default:
        break;
    }
}


/**
 * virQEMUCapsInitQMPVersionCaps:
 * @qemuCaps: QEMU capabilities
 *
 * Add all QEMU capabilities based on version of QEMU.
 */
static void
virQEMUCapsInitQMPVersionCaps(virQEMUCaps *qemuCaps)
{
    /* -enable-fips is deprecated in QEMU 5.2.0, and QEMU
     * should be built with gcrypt to achieve FIPS compliance
     * automatically / implicitly
     */
    if (qemuCaps->version < 5002000)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_ENABLE_FIPS);
}


/**
 * virQEMUCapsInitProcessCapsInterlock:
 * @qemuCaps: QEMU capabilities
 *
 * A capability which requires a different capability being present in order
 * for libvirt to be able to drive it properly should be processed here.
 */
void
virQEMUCapsInitProcessCapsInterlock(virQEMUCaps *qemuCaps)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCKDEV))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_BLOCKDEV_BACKUP);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCKDEV_BACKUP) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_MIGRATION_PARAM_BLOCK_BITMAP_MAPPING))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_INCREMENTAL_BACKUP);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_STORAGE_WERROR)) {
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_STORAGE_WERROR);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCKDEV))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_BLOCKDEV_HOSTDEV_SCSI);

    /* The -compat qemu command line argument is implemented using a newer
     * method which doesn't show up in query-command-line-options. As we'll use
     * it only for development and testing purposes we can base the capability
     * on a not entirely related witness. */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_QAPIFIED))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_COMPAT_DEPRECATED);
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
virQEMUCapsInitProcessCaps(virQEMUCaps *qemuCaps)
{
    /* versions prior to the introduction of 'query-display-options' had SDL
     * mostly compiled in */
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_DISPLAY_OPTIONS)) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SDL);
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_EGL_HEADLESS);
    }

    if (ARCH_IS_X86(qemuCaps->arch) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION)) {
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CPU_CACHE);

        /* Old x86 QEMU supported migratable:false property in
         * query-cpu-model-expansion arguments even though it was not properly
         * advertised as a CPU property.
         */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MIGRATABLE) ||
            qemuCaps->version < 2012000)
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION_MIGRATABLE);
    }

    if (ARCH_IS_S390(qemuCaps->arch)) {
        /* Legacy assurance for QEMU_CAPS_CCW */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCW) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_CCW))
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_CCW);
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCW_CSSID_UNRESTRICTED))
            virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE_VFIO_CCW);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_UNAVAILABLE_FEATURES))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_CANONICAL_CPU_FEATURES);

    /* To avoid guest ABI regression, blockdev shall be enabled only when
     * we are able to pass the custom 'device_id' for SCSI disks and cdroms. */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCK_FILE_AUTO_READONLY_DYNAMIC) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_DEVICE_ID) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_SAVEVM_MONITOR_NODES))
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_BLOCKDEV);

    /* We can't probe "esp" as a type via virQEMUCapsObjectTypes
     * array as it is only usable when builtin to the machine type
     */
    if (qemuCaps->arch == VIR_ARCH_SPARC ||
        qemuCaps->arch == VIR_ARCH_M68K ||
        qemuCaps->arch == VIR_ARCH_MIPS)
        virQEMUCapsSet(qemuCaps, QEMU_CAPS_SCSI_NCR53C90);

    virQEMUCapsInitProcessCapsInterlock(qemuCaps);
}


static int
virQEMUCapsProbeQMPSchemaCapabilities(virQEMUCaps *qemuCaps,
                                      qemuMonitor *mon)
{
    struct virQEMUCapsStringFlags *entry;
    virJSONValue *schemareply;
    GHashTable *schema = NULL;
    size_t i;

    if (!(schemareply = qemuMonitorQueryQMPSchema(mon)))
        return -1;

    if (!(schema = virQEMUQAPISchemaConvert(schemareply)))
        return -1;
    schemareply = NULL;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsQMPSchemaQueries); i++) {
        entry = virQEMUCapsQMPSchemaQueries + i;

        if (virQEMUQAPISchemaPathExists(entry->value, schema))
            virQEMUCapsSet(qemuCaps, entry->flag);
    }

    /* probe also for basic event support */
    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsEvents); i++) {
        entry = virQEMUCapsEvents + i;

        if (virQEMUQAPISchemaPathExists(entry->value, schema))
            virQEMUCapsSet(qemuCaps, entry->flag);
    }

    virHashFree(schema);
    return 0;
}

#define QEMU_MIN_MAJOR 2
#define QEMU_MIN_MINOR 11
#define QEMU_MIN_MICRO 0

virDomainVirtType
virQEMUCapsGetVirtType(virQEMUCaps *qemuCaps)
{
    virDomainVirtType type;
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        type = VIR_DOMAIN_VIRT_KVM;
    else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_TCG))
        type = VIR_DOMAIN_VIRT_QEMU;
    else
        type = VIR_DOMAIN_VIRT_NONE;

    return type;
}

int
virQEMUCapsInitQMPMonitor(virQEMUCaps *qemuCaps,
                          qemuMonitor *mon)
{
    int major, minor, micro;
    g_autofree char *package = NULL;
    virQEMUCapsAccel *accel;
    virDomainVirtType type;

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
    qemuCaps->package = g_steal_pointer(&package);

    if (virQEMUCapsInitQMPArch(qemuCaps, mon) < 0)
        return -1;

    virQEMUCapsInitQMPBasicArch(qemuCaps);

    /* initiate all capabilities based on qemu version */
    virQEMUCapsInitQMPVersionCaps(qemuCaps);

    if (virQEMUCapsProbeQMPSchemaCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPCommands(qemuCaps, mon) < 0)
        return -1;

    /* Some capabilities may differ depending on KVM state */
    if (virQEMUCapsProbeQMPKVMState(qemuCaps, mon) < 0)
        return -1;

    type = virQEMUCapsGetVirtType(qemuCaps);
    accel = virQEMUCapsGetAccel(qemuCaps, type);

    if (virQEMUCapsProbeQMPObjectTypes(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPDeviceProperties(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPObjectProperties(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMachineTypes(qemuCaps, type, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMachineProps(qemuCaps, type, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, accel, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPTPM(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPCommandLine(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPMigrationCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPGICCapabilities(qemuCaps, mon) < 0)
        return -1;
    if (virQEMUCapsProbeQMPSEVCapabilities(qemuCaps, mon) < 0)
        return -1;

    virQEMUCapsInitProcessCaps(qemuCaps);

    /* The following probes rely on other previously probed capabilities.
     * No capabilities bits should be set below this point. */

    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, accel, mon, type) < 0)
        return -1;

    return 0;
}


int
virQEMUCapsInitQMPMonitorTCG(virQEMUCaps *qemuCaps,
                             qemuMonitor *mon)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, VIR_DOMAIN_VIRT_QEMU);

    if (virQEMUCapsProbeQMPCPUDefinitions(qemuCaps, accel, mon) < 0)
        return -1;

    if (virQEMUCapsProbeQMPHostCPU(qemuCaps, accel, mon, VIR_DOMAIN_VIRT_QEMU) < 0)
        return -1;

    if (virQEMUCapsProbeQMPMachineTypes(qemuCaps, VIR_DOMAIN_VIRT_QEMU, mon) < 0)
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
virQEMUCapsInitQMPSingle(virQEMUCaps *qemuCaps,
                         const char *libDir,
                         uid_t runUid,
                         gid_t runGid,
                         bool onlyTCG)
{
    g_autoptr(qemuProcessQMP) proc = NULL;
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

    return ret;
}


static int
virQEMUCapsInitQMP(virQEMUCaps *qemuCaps,
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
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_TCG) &&
        virQEMUCapsInitQMPSingle(qemuCaps, libDir, runUid, runGid, true) < 0)
        return -1;

    return 0;
}


virQEMUCaps *
virQEMUCapsNewForBinaryInternal(virArch hostArch,
                                const char *binary,
                                const char *libDir,
                                uid_t runUid,
                                gid_t runGid,
                                const char *hostCPUSignature,
                                unsigned int microcodeVersion,
                                const char *kernelVersion)
{
    virQEMUCaps *qemuCaps;
    struct stat sb;

    if (!(qemuCaps = virQEMUCapsNewBinary(binary)))
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

    if (virFileExists(QEMU_MODDIR)) {
        if (stat(QEMU_MODDIR, &sb) < 0) {
            virReportSystemError(errno, _("Cannot check QEMU module directory %s"),
                                 QEMU_MODDIR);
            goto error;
        }
        qemuCaps->modDirMtime = sb.st_mtime;
    }

    if (virQEMUCapsInitQMP(qemuCaps, libDir, runUid, runGid) < 0)
        goto error;

    qemuCaps->libvirtCtime = virGetSelfLastChanged();
    qemuCaps->libvirtVersion = LIBVIR_VERSION_NUMBER;

    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsInitHostCPUModel(qemuCaps, hostArch, VIR_DOMAIN_VIRT_QEMU);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
        qemuCaps->hostCPUSignature = g_strdup(hostCPUSignature);
        qemuCaps->microcodeVersion = microcodeVersion;

        qemuCaps->kernelVersion = g_strdup(kernelVersion);

        qemuCaps->kvmSupportsNesting = virQEMUCapsKVMSupportsNesting();

        qemuCaps->kvmSupportsSecureGuest = virQEMUCapsKVMSupportsSecureGuest();
    }

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}

static void *
virQEMUCapsNewData(const char *binary,
                   void *privData)
{
    virQEMUCapsCachePriv *priv = privData;

    return virQEMUCapsNewForBinaryInternal(priv->hostArch,
                                           binary,
                                           priv->libDir,
                                           priv->runUid,
                                           priv->runGid,
                                           priv->hostCPUSignature,
                                           virHostCPUGetMicrocodeVersion(priv->hostArch),
                                           priv->kernelVersion);
}


static void *
virQEMUCapsLoadFile(const char *filename,
                    const char *binary,
                    void *privData,
                    bool *outdated)
{
    virQEMUCaps *qemuCaps = virQEMUCapsNewBinary(binary);
    virQEMUCapsCachePriv *priv = privData;
    int ret;

    if (!qemuCaps)
        return NULL;

    ret = virQEMUCapsLoadCache(priv->hostArch, qemuCaps, filename, false);
    if (ret < 0)
        goto error;
    if (ret == 1) {
        *outdated = true;
        goto error;
    }

    return qemuCaps;

 error:
    virObjectUnref(qemuCaps);
    return NULL;
}


struct virQEMUCapsMachineTypeFilter {
    const char *machineType;
    virQEMUCapsFlags *flags;
    size_t nflags;
};

static const struct virQEMUCapsMachineTypeFilter virQEMUCapsMachineFilter[] = {
    /* { "blah", virQEMUCapsMachineBLAHFilter,
         G_N_ELEMENTS(virQEMUCapsMachineBLAHFilter) }, */
    { "", NULL, 0 },
};


void
virQEMUCapsFilterByMachineType(virQEMUCaps *qemuCaps,
                               virDomainVirtType virtType,
                               const char *machineType)
{
    size_t i;

    if (!machineType)
        return;

    for (i = 0; i < G_N_ELEMENTS(virQEMUCapsMachineFilter); i++) {
        const struct virQEMUCapsMachineTypeFilter *filter = &virQEMUCapsMachineFilter[i];
        size_t j;

        if (STRNEQ(filter->machineType, machineType))
            continue;

        for (j = 0; j < filter->nflags; j++)
            virQEMUCapsClear(qemuCaps, filter->flags[j]);
    }

    if (!virQEMUCapsGetMachineHotplugCpus(qemuCaps, virtType, machineType))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);
}


virFileCacheHandlers qemuCapsCacheHandlers = {
    .isValid = virQEMUCapsIsValid,
    .newData = virQEMUCapsNewData,
    .loadFile = virQEMUCapsLoadFile,
    .saveFile = virQEMUCapsSaveFile,
    .privFree = virQEMUCapsCachePrivFree,
};


virFileCache *
virQEMUCapsCacheNew(const char *libDir,
                    const char *cacheDir,
                    uid_t runUid,
                    gid_t runGid)
{
    char *capsCacheDir = NULL;
    virFileCache *cache = NULL;
    virQEMUCapsCachePriv *priv = NULL;
    struct utsname uts;

    capsCacheDir = g_strdup_printf("%s/capabilities", cacheDir);

    if (!(cache = virFileCacheNew(capsCacheDir, "xml", &qemuCapsCacheHandlers)))
        goto error;

    priv = g_new0(virQEMUCapsCachePriv, 1);
    virFileCacheSetPriv(cache, priv);

    priv->libDir = g_strdup(libDir);

    priv->hostArch = virArchFromHost();

    if (virHostCPUGetSignature(&priv->hostCPUSignature) < 0)
        goto error;

    priv->runUid = runUid;
    priv->runGid = runGid;
    priv->kvmUsable = VIR_TRISTATE_BOOL_ABSENT;

    if (uname(&uts) == 0)
        priv->kernelVersion = g_strdup_printf("%s %s", uts.release, uts.version);

 cleanup:
    VIR_FREE(capsCacheDir);
    return cache;

 error:
    virObjectUnref(cache);
    cache = NULL;
    goto cleanup;
}


virQEMUCaps *
virQEMUCapsCacheLookup(virFileCache *cache,
                       const char *binary)
{
    virQEMUCapsCachePriv *priv = virFileCacheGetPriv(cache);
    virQEMUCaps *ret = NULL;

    priv->microcodeVersion = virHostCPUGetMicrocodeVersion(priv->hostArch);

    ret = virFileCacheLookup(cache, binary);

    VIR_DEBUG("Returning caps %p for %s", ret, binary);
    return ret;
}


virQEMUCaps *
virQEMUCapsCacheLookupCopy(virFileCache *cache,
                           virDomainVirtType virtType,
                           const char *binary,
                           const char *machineType)
{
    virQEMUCaps *qemuCaps = virQEMUCapsCacheLookup(cache, binary);
    virQEMUCaps *ret;

    if (!qemuCaps)
        return NULL;

    ret = virQEMUCapsNewCopy(qemuCaps);
    virObjectUnref(qemuCaps);

    if (!ret)
        return NULL;

    virQEMUCapsFilterByMachineType(ret, virtType, machineType);
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
virQEMUCaps *
virQEMUCapsCacheLookupDefault(virFileCache *cache,
                              const char *binary,
                              const char *archStr,
                              const char *virttypeStr,
                              const char *machine,
                              virArch *retArch,
                              virDomainVirtType *retVirttype,
                              const char **retMachine)
{
    int virttype = VIR_DOMAIN_VIRT_NONE;
    virArch hostarch = virArchFromHost();
    virArch arch = hostarch;
    virDomainVirtType capsType;
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    virArch arch_from_caps;
    g_autofree char *probedbinary = NULL;

    if (virttypeStr &&
        (virttype = virDomainVirtTypeFromString(virttypeStr)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %s"), virttypeStr);
        return NULL;
    }

    if (archStr &&
        (arch = virArchFromString(archStr)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %s"), archStr);
        return NULL;
    }

    if (!binary) {
        probedbinary = virQEMUCapsGetDefaultEmulator(hostarch, arch);
        binary = probedbinary;
    }
    if (!binary) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unable to find any emulator to serve '%s' architecture"),
                       archStr);
        return NULL;
    }

    if (!(qemuCaps = virQEMUCapsCacheLookup(cache, binary)))
        return NULL;

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
        return NULL;
    }

    capsType = virQEMUCapsGetVirtType(qemuCaps);

    if (virttype == VIR_DOMAIN_VIRT_NONE)
        virttype = capsType;

    if (virttype == VIR_DOMAIN_VIRT_KVM && capsType == VIR_DOMAIN_VIRT_QEMU) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("KVM is not supported by '%s' on this host"),
                       binary);
        return NULL;
    }

    if (machine) {
        /* Turn @machine into canonical name */
        machine = virQEMUCapsGetCanonicalMachine(qemuCaps, virttype, machine);

        if (!virQEMUCapsIsMachineSupported(qemuCaps, virttype, machine)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("the machine '%s' is not supported by emulator '%s'"),
                           machine, binary);
            return NULL;
        }
    } else {
        machine = virQEMUCapsGetPreferredMachine(qemuCaps, virttype);
    }

    if (retArch)
        *retArch = arch;
    if (retVirttype)
        *retVirttype = virttype;
    if (retMachine)
        *retMachine = machine;

    return g_steal_pointer(&qemuCaps);
}

bool
virQEMUCapsSupportsVmport(virQEMUCaps *qemuCaps,
                          const virDomainDef *def)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_VMPORT_OPT))
        return false;

    return qemuDomainIsI440FX(def) ||
        qemuDomainIsQ35(def) ||
        STREQ(def->os.machine, "isapc");
}


/*
 * The preferred machine to use if none is listed explicitly
 * Note that this may differ from QEMU's own default machine
 */
const char *
virQEMUCapsGetPreferredMachine(virQEMUCaps *qemuCaps,
                               virDomainVirtType virtType)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, virtType);

    if (!accel->nmachineTypes)
        return NULL;
    return accel->machineTypes[0].name;
}


static int
virQEMUCapsFillDomainLoaderCaps(virDomainCapsLoader *capsLoader,
                                bool secure,
                                virFirmware **firmwares,
                                size_t nfirmwares)
{
    size_t i;

    capsLoader->supported = VIR_TRISTATE_BOOL_YES;
    capsLoader->type.report = true;
    capsLoader->readonly.report = true;
    capsLoader->secure.report = true;

    capsLoader->values.values = g_new0(char *, nfirmwares);

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

        capsLoader->values.values[capsLoader->values.nvalues] = g_strdup(filename);
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
virQEMUCapsFillDomainOSCaps(virDomainCapsOS *os,
                            const char *machine,
                            virArch arch,
                            bool privileged,
                            virFirmware **firmwares,
                            size_t nfirmwares)
{
    virDomainCapsLoader *capsLoader = &os->loader;
    uint64_t autoFirmwares = 0;
    bool secure = false;
    virFirmware **firmwaresAlt = NULL;
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


static void
virQEMUCapsFillDomainCPUCaps(virQEMUCaps *qemuCaps,
                             virArch hostarch,
                             virDomainCaps *domCaps)
{
    if (virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, domCaps->virttype,
                                      VIR_CPU_MODE_HOST_PASSTHROUGH,
                                      domCaps->machine)) {
        domCaps->cpu.hostPassthrough = true;

        domCaps->cpu.hostPassthroughMigratable.report = true;
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MIGRATABLE)) {
            VIR_DOMAIN_CAPS_ENUM_SET(domCaps->cpu.hostPassthroughMigratable,
                                     VIR_TRISTATE_SWITCH_ON);
        }
        VIR_DOMAIN_CAPS_ENUM_SET(domCaps->cpu.hostPassthroughMigratable,
                                 VIR_TRISTATE_SWITCH_OFF);
    }

    if (virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, domCaps->virttype,
                                      VIR_CPU_MODE_MAXIMUM,
                                      domCaps->machine)) {
        domCaps->cpu.maximum = true;

        domCaps->cpu.maximumMigratable.report = true;
        VIR_DOMAIN_CAPS_ENUM_SET(domCaps->cpu.maximumMigratable,
                                 VIR_TRISTATE_SWITCH_ON);
        VIR_DOMAIN_CAPS_ENUM_SET(domCaps->cpu.maximumMigratable,
                                 VIR_TRISTATE_SWITCH_OFF);
    }

    if (virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, domCaps->virttype,
                                      VIR_CPU_MODE_HOST_MODEL,
                                      domCaps->machine)) {
        virCPUDef *cpu = virQEMUCapsGetHostModel(qemuCaps, domCaps->virttype,
                                                   VIR_QEMU_CAPS_HOST_CPU_REPORTED);
        domCaps->cpu.hostModel = virCPUDefCopy(cpu);
    }

    if (virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, domCaps->virttype,
                                      VIR_CPU_MODE_CUSTOM,
                                      domCaps->machine)) {
        const char *forbidden[] = { "host", NULL };
        g_auto(GStrv) models = NULL;

        if (virCPUGetModels(domCaps->arch, &models) >= 0) {
            domCaps->cpu.custom = virQEMUCapsGetCPUModels(qemuCaps,
                                                          domCaps->virttype,
                                                          (const char **)models,
                                                          forbidden);
        } else {
            domCaps->cpu.custom = NULL;
        }
    }
}


struct virQEMUCapsDomainFeatureCapabilityTuple {
    virDomainCapsFeature domcap;
    virQEMUCapsFlags qemucap;
};

/**
 * This maps the qemu features to the entries in <features> of the domain
 * capability XML.
 * */
static const struct virQEMUCapsDomainFeatureCapabilityTuple domCapsTuples[] = {
    { VIR_DOMAIN_CAPS_FEATURE_IOTHREADS, QEMU_CAPS_OBJECT_IOTHREAD },
    { VIR_DOMAIN_CAPS_FEATURE_VMCOREINFO, QEMU_CAPS_DEVICE_VMCOREINFO },
    { VIR_DOMAIN_CAPS_FEATURE_GENID, QEMU_CAPS_DEVICE_VMGENID },
    { VIR_DOMAIN_CAPS_FEATURE_BACKING_STORE_INPUT, QEMU_CAPS_BLOCKDEV },
    { VIR_DOMAIN_CAPS_FEATURE_BACKUP, QEMU_CAPS_INCREMENTAL_BACKUP },
};


static void
virQEMUCapsFillDomainFeaturesFromQEMUCaps(virQEMUCaps *qemuCaps,
                                          virDomainCaps *domCaps)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(domCapsTuples); i++) {
        if (virQEMUCapsGet(qemuCaps, domCapsTuples[i].qemucap))
            domCaps->features[domCapsTuples[i].domcap] = VIR_TRISTATE_BOOL_YES;
        else
            domCaps->features[domCapsTuples[i].domcap] = VIR_TRISTATE_BOOL_NO;
    }
}


void
virQEMUCapsFillDomainMemoryBackingCaps(virQEMUCaps *qemuCaps,
                                  virDomainCapsMemoryBacking *memoryBacking)
{
    memoryBacking->supported = VIR_TRISTATE_BOOL_YES;
    memoryBacking->sourceType.report = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_MEMFD))
        VIR_DOMAIN_CAPS_ENUM_SET(memoryBacking->sourceType,
                                 VIR_DOMAIN_MEMORY_SOURCE_MEMFD);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE))
        VIR_DOMAIN_CAPS_ENUM_SET(memoryBacking->sourceType,
                                 VIR_DOMAIN_MEMORY_SOURCE_FILE);

    VIR_DOMAIN_CAPS_ENUM_SET(memoryBacking->sourceType,
                             VIR_DOMAIN_MEMORY_SOURCE_ANONYMOUS);
}


static void
virQEMUCapsFillDomainDeviceDiskCaps(virQEMUCaps *qemuCaps,
                                    const char *machine,
                                    virDomainCapsDeviceDisk *disk)
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
}


void
virQEMUCapsFillDomainDeviceGraphicsCaps(virQEMUCaps *qemuCaps,
                                        virDomainCapsDeviceGraphics *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->type.report = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SDL))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_SDL);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_VNC);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_SPICE);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_EGL_HEADLESS))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->type, VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS);
}


void
virQEMUCapsFillDomainDeviceVideoCaps(virQEMUCaps *qemuCaps,
                                     virDomainCapsDeviceVideo *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->modelType.report = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_NONE);
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
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_RAMFB))
        VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType, VIR_DOMAIN_VIDEO_TYPE_RAMFB);
}


static void
virQEMUCapsFillDomainDeviceHostdevCaps(virQEMUCaps *qemuCaps,
                                       virDomainCapsDeviceHostdev *hostdev)
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
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX3_USB_UHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX4_USB_UHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_EHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_USB_EHCI1) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_VT82C686B_USB_UHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_OHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_NEC_USB_XHCI) ||
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_QEMU_XHCI)) {
        VIR_DOMAIN_CAPS_ENUM_SET(hostdev->subsysType,
                                 VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB);
    }

    /* No virDomainHostdevCapsType for QEMU */
    virDomainCapsEnumClear(&hostdev->capsType);

    virDomainCapsEnumClear(&hostdev->pciBackend);
    if (supportsPassthroughVFIO &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
        VIR_DOMAIN_CAPS_ENUM_SET(hostdev->pciBackend,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                                 VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO);
    }
}


void
virQEMUCapsFillDomainDeviceRNGCaps(virQEMUCaps *qemuCaps,
                                   virDomainCapsDeviceRNG *rng)
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
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_BUILTIN))
        VIR_DOMAIN_CAPS_ENUM_SET(rng->backendModel, VIR_DOMAIN_RNG_BACKEND_BUILTIN);
}


void
virQEMUCapsFillDomainDeviceFSCaps(virQEMUCaps *qemuCaps,
                                  virDomainCapsDeviceFilesystem *filesystem)
{
    filesystem->supported = VIR_TRISTATE_BOOL_YES;
    filesystem->driverType.report = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_USER_FS))
        VIR_DOMAIN_CAPS_ENUM_SET(filesystem->driverType,
                                 VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS);

    VIR_DOMAIN_CAPS_ENUM_SET(filesystem->driverType,
                             VIR_DOMAIN_FS_DRIVER_TYPE_PATH,
                             VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE);
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
virQEMUCapsSupportsGICVersion(virQEMUCaps *qemuCaps,
                              virDomainVirtType virtType,
                              virGICVersion version)
{
    size_t i;

    if (!qemuCaps)
        return false;

    for (i = 0; i < qemuCaps->ngicCapabilities; i++) {
        virGICCapability *cap = &(qemuCaps->gicCapabilities[i]);

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
 */
static void
virQEMUCapsFillDomainFeatureGICCaps(virQEMUCaps *qemuCaps,
                                    virDomainCaps *domCaps)
{
    virDomainCapsFeatureGIC *gic = &domCaps->gic;
    virGICVersion version;

    gic->supported = VIR_TRISTATE_BOOL_NO;

    if (!qemuDomainMachineIsARMVirt(domCaps->machine, domCaps->arch))
        return;

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
}


/**
 * virQEMUCapsFillDomainFeatureSEVCaps:
 * @qemuCaps: QEMU capabilities
 * @domCaps: domain capabilities
 *
 * Take the information about SEV capabilities that has been obtained
 * using the 'query-sev-capabilities' QMP command and stored in @qemuCaps
 * and convert it to a form suitable for @domCaps.
 */
static void
virQEMUCapsFillDomainFeatureSEVCaps(virQEMUCaps *qemuCaps,
                                    virDomainCaps *domCaps)
{
    virSEVCapability *cap = qemuCaps->sevCapabilities;

    if (!cap)
        return;

    domCaps->sev = g_new0(virSEVCapability, 1);

    domCaps->sev->pdh = g_strdup(cap->pdh);
    domCaps->sev->cert_chain = g_strdup(cap->cert_chain);
    domCaps->sev->cbitpos = cap->cbitpos;
    domCaps->sev->reduced_phys_bits = cap->reduced_phys_bits;
}


static void
virQEMUCapsFillDomainFeatureS390PVCaps(virQEMUCaps *qemuCaps,
                                       virDomainCaps *domCaps)
{
    if (ARCH_IS_S390(qemuCaps->arch)) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_CONFIDENTAL_GUEST_SUPPORT) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_S390_PV_GUEST) &&
            virQEMUCapsGetKVMSupportsSecureGuest(qemuCaps))
            domCaps->features[VIR_DOMAIN_CAPS_FEATURE_S390_PV] = VIR_TRISTATE_BOOL_YES;
        else
            domCaps->features[VIR_DOMAIN_CAPS_FEATURE_S390_PV] = VIR_TRISTATE_BOOL_NO;
    }
}


int
virQEMUCapsFillDomainCaps(virQEMUCaps *qemuCaps,
                          virArch hostarch,
                          virDomainCaps *domCaps,
                          bool privileged,
                          virFirmware **firmwares,
                          size_t nfirmwares)
{
    virDomainCapsOS *os = &domCaps->os;
    virDomainCapsDeviceDisk *disk = &domCaps->disk;
    virDomainCapsDeviceHostdev *hostdev = &domCaps->hostdev;
    virDomainCapsDeviceGraphics *graphics = &domCaps->graphics;
    virDomainCapsDeviceVideo *video = &domCaps->video;
    virDomainCapsDeviceRNG *rng = &domCaps->rng;
    virDomainCapsDeviceFilesystem *filesystem = &domCaps->filesystem;
    virDomainCapsMemoryBacking *memoryBacking = &domCaps->memoryBacking;

    virQEMUCapsFillDomainFeaturesFromQEMUCaps(qemuCaps, domCaps);

    domCaps->maxvcpus = virQEMUCapsGetMachineMaxCpus(qemuCaps,
                                                     domCaps->virttype,
                                                     domCaps->machine);
    if (domCaps->virttype == VIR_DOMAIN_VIRT_KVM) {
        int hostmaxvcpus;

        if ((hostmaxvcpus = virHostCPUGetKVMMaxVCPUs()) < 0)
            return -1;

        domCaps->maxvcpus = MIN(domCaps->maxvcpus, hostmaxvcpus);
    }

    if (virQEMUCapsFillDomainOSCaps(os,
                                    domCaps->machine,
                                    domCaps->arch,
                                    privileged,
                                    firmwares, nfirmwares) < 0)
        return -1;

    virQEMUCapsFillDomainCPUCaps(qemuCaps, hostarch, domCaps);
    virQEMUCapsFillDomainMemoryBackingCaps(qemuCaps, memoryBacking);
    virQEMUCapsFillDomainDeviceDiskCaps(qemuCaps, domCaps->machine, disk);
    virQEMUCapsFillDomainDeviceGraphicsCaps(qemuCaps, graphics);
    virQEMUCapsFillDomainDeviceVideoCaps(qemuCaps, video);
    virQEMUCapsFillDomainDeviceHostdevCaps(qemuCaps, hostdev);
    virQEMUCapsFillDomainDeviceRNGCaps(qemuCaps, rng);
    virQEMUCapsFillDomainDeviceFSCaps(qemuCaps, filesystem);
    virQEMUCapsFillDomainFeatureGICCaps(qemuCaps, domCaps);
    virQEMUCapsFillDomainFeatureSEVCaps(qemuCaps, domCaps);
    virQEMUCapsFillDomainFeatureS390PVCaps(qemuCaps, domCaps);

    return 0;
}


void
virQEMUCapsSetMicrocodeVersion(virQEMUCaps *qemuCaps,
                               unsigned int microcodeVersion)
{
    qemuCaps->microcodeVersion = microcodeVersion;
}


static void
virQEMUCapsStripMachineAliasesForVirtType(virQEMUCaps *qemuCaps,
                                          virDomainVirtType virtType)
{
    virQEMUCapsAccel *accel = virQEMUCapsGetAccel(qemuCaps, virtType);
    size_t i;

    for (i = 0; i < accel->nmachineTypes; i++) {
        virQEMUCapsMachineType *mach = &accel->machineTypes[i];
        g_autofree char *name = g_steal_pointer(&mach->alias);

        if (name) {
            virQEMUCapsAddMachine(qemuCaps, virtType, name, NULL, mach->defaultCPU,
                                  mach->maxCpus, mach->hotplugCpus, mach->qemuDefault,
                                  mach->numaMemSupported, mach->defaultRAMid,
                                  mach->deprecated);
        }
    }
}


/**
 * virQEMUCapsStripMachineAliases:
 * @qemuCaps: capabilities object to process
 *
 * Replace all aliases by the copy of the machine type they point to without
 * actually having to modify the name. This allows us to add tests with the
 * aliased machine without having to change the output files all the time.
 *
 * Remove all aliases so that the tests depending on the latest capabilities
 * file can be stable when new files are added.
 */
void
virQEMUCapsStripMachineAliases(virQEMUCaps *qemuCaps)
{
    virQEMUCapsStripMachineAliasesForVirtType(qemuCaps, VIR_DOMAIN_VIRT_KVM);
    virQEMUCapsStripMachineAliasesForVirtType(qemuCaps, VIR_DOMAIN_VIRT_QEMU);
}
