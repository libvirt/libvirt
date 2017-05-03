/*
 * qemu_capabilities.h: QEMU capabilities generation
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

#ifndef __QEMU_CAPABILITIES_H__
# define __QEMU_CAPABILITIES_H__

# include "virobject.h"
# include "capabilities.h"
# include "vircommand.h"
# include "qemu_monitor.h"
# include "domain_capabilities.h"
# include "virfirmware.h"

/*
 * Internal flags to keep track of qemu command line capabilities
 *
 * As a general rule these flags must not be deleted / renamed, as
 * they are serialized in string format into the runtime XML file
 * for guests, and new libvirt needs to cope with reading flags
 * defined by old libvirt.
 *
 * The exception to this rule is when we drop support for running
 * with older QEMU versions entirely. When a flag is no longer needed
 * we temporarily give it an X_ prefix to indicate it should no
 * longer be used in code. Periodically we can then purge all the
 * X_ flags and re-group what's left.
 */
typedef enum {
    /* 0 */
    X_QEMU_CAPS_KQEMU, /* Whether KQEMU is compiled in */
    X_QEMU_CAPS_VNC_COLON, /* VNC takes or address + display */
    X_QEMU_CAPS_NO_REBOOT, /* Is the -no-reboot flag available */
    X_QEMU_CAPS_DRIVE, /* Is the new -drive arg available */
    QEMU_CAPS_DRIVE_BOOT, /* Does -drive support boot=on */

    /* 5 */
    X_QEMU_CAPS_NAME, /* Is the -name flag available */
    X_QEMU_CAPS_UUID, /* Is the -uuid flag available */
    X_QEMU_CAPS_DOMID, /* Xenner: -domid flag available */
    X_QEMU_CAPS_VNET_HDR,
    X_QEMU_CAPS_MIGRATE_KVM_STDIO, /* avoid kvm tcp migration bug */

    /* 10 */
    X_QEMU_CAPS_MIGRATE_QEMU_TCP, /* have qemu tcp migration */
    X_QEMU_CAPS_MIGRATE_QEMU_EXEC, /* have qemu exec migration */
    X_QEMU_CAPS_DRIVE_CACHE_V2, /* cache= flag wanting new v2 values */
    QEMU_CAPS_KVM, /* Whether KVM is enabled by default */
    X_QEMU_CAPS_DRIVE_FORMAT, /* Is -drive format= avail */

    /* 15 */
    X_QEMU_CAPS_VGA, /* Is -vga avail */
    X_QEMU_CAPS_0_10, /* features added in qemu-0.10.0 or later */
    X_QEMU_CAPS_PCIDEVICE, /* PCI device assignment supported */
    QEMU_CAPS_MEM_PATH, /* mmap'ped guest backing supported */
    QEMU_CAPS_DRIVE_SERIAL, /* -driver serial=  available */

    /* 20 */
    X_QEMU_CAPS_XEN_DOMID, /* -xen-domid */
    X_QEMU_CAPS_MIGRATE_QEMU_UNIX, /* qemu migration via unix sockets */
    QEMU_CAPS_CHARDEV, /* Is the new -chardev arg available */
    QEMU_CAPS_ENABLE_KVM, /* -enable-kvm flag */
    QEMU_CAPS_MONITOR_JSON, /* JSON mode for monitor */

    /* 25 */
    X_QEMU_CAPS_BALLOON, /* -balloon available */
    X_QEMU_CAPS_DEVICE, /* Is the -device arg available */
    QEMU_CAPS_SDL, /* Is the new -sdl arg available */
    X_QEMU_CAPS_SMP_TOPOLOGY, /* -smp has sockets/cores/threads */
    QEMU_CAPS_NETDEV, /* -netdev flag & netdev_add/remove */

    /* 30 */
    QEMU_CAPS_RTC, /* The -rtc flag for clock options */
    QEMU_CAPS_VHOST_NET, /* vhost-net support available */
    QEMU_CAPS_RTC_TD_HACK, /* -rtc-td-hack available */
    QEMU_CAPS_NO_HPET, /* -no-hpet flag is supported */
    QEMU_CAPS_NO_KVM_PIT, /* -no-kvm-pit-reinjection supported */

    /* 35 */
    QEMU_CAPS_TDF, /* -tdf flag (user-mode pit catchup) */
    QEMU_CAPS_PCI_CONFIGFD, /* pci-assign.configfd */
    QEMU_CAPS_NODEFCONFIG, /* -nodefconfig */
    QEMU_CAPS_BOOT_MENU, /* -boot menu=on support */
    X_QEMU_CAPS_ENABLE_KQEMU, /* -enable-kqemu flag */

    /* 40 */
    QEMU_CAPS_FSDEV, /* -fstype filesystem passthrough */
    QEMU_CAPS_NESTING, /* -enable-nesting (SVM/VMX) */
    QEMU_CAPS_NAME_PROCESS, /* Is -name process= available */
    X_QEMU_CAPS_DRIVE_READONLY, /* -drive readonly=on|off */
    QEMU_CAPS_SMBIOS_TYPE, /* Is -smbios type= available */

    /* 45 */
    X_QEMU_CAPS_VGA_QXL, /* The 'qxl' arg for '-vga' */
    QEMU_CAPS_SPICE, /* Is -spice avail */
    QEMU_CAPS_VGA_NONE, /* The 'none' arg for '-vga' */
    X_QEMU_CAPS_MIGRATE_QEMU_FD, /* -incoming fd:n */
    QEMU_CAPS_BOOTINDEX, /* -device bootindex property */

    /* 50 */
    QEMU_CAPS_HDA_DUPLEX, /* -device hda-duplex */
    QEMU_CAPS_DRIVE_AIO, /* -drive aio= supported */
    X_QEMU_CAPS_PCI_MULTIBUS, /* bus=pci.0 vs bus=pci */
    QEMU_CAPS_PCI_BOOTINDEX, /* pci-assign.bootindex */
    QEMU_CAPS_CCID_EMULATED, /* -device ccid-card-emulated */

    /* 55 */
    QEMU_CAPS_CCID_PASSTHRU, /* -device ccid-card-passthru */
    QEMU_CAPS_CHARDEV_SPICEVMC, /* newer -chardev spicevmc */
    QEMU_CAPS_DEVICE_SPICEVMC, /* older -device spicevmc*/
    QEMU_CAPS_VIRTIO_TX_ALG, /* -device virtio-net-pci,tx=string */
    X_QEMU_CAPS_DEVICE_QXL_VGA, /* primary qxl device named qxl-vga? */

    /* 60 */
    QEMU_CAPS_PCI_MULTIFUNCTION, /* -device multifunction=on|off */
    QEMU_CAPS_VIRTIO_IOEVENTFD, /* virtio-{net|blk}-pci.ioeventfd=on */
    QEMU_CAPS_SGA, /* Serial Graphics Adapter */
    QEMU_CAPS_VIRTIO_BLK_EVENT_IDX, /* virtio-blk-pci.event_idx */
    QEMU_CAPS_VIRTIO_NET_EVENT_IDX, /* virtio-net-pci.event_idx */

    /* 65 */
    QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC, /* Is cache=directsync supported? */
    QEMU_CAPS_PIIX3_USB_UHCI, /* -device piix3-usb-uhci */
    QEMU_CAPS_PIIX4_USB_UHCI, /* -device piix4-usb-uhci */
    QEMU_CAPS_USB_EHCI, /* -device usb-ehci */
    QEMU_CAPS_ICH9_USB_EHCI1, /* -device ich9-usb-ehci1 and friends */

    /* 70 */
    QEMU_CAPS_VT82C686B_USB_UHCI, /* -device vt82c686b-usb-uhci */
    QEMU_CAPS_PCI_OHCI, /* -device pci-ohci */
    QEMU_CAPS_USB_REDIR, /* -device usb-redir */
    QEMU_CAPS_USB_HUB, /* -device usb-hub */
    QEMU_CAPS_NO_SHUTDOWN, /* usable -no-shutdown */

    /* 75 */
    QEMU_CAPS_DRIVE_CACHE_UNSAFE, /* Is cache=unsafe supported? */
    X_QEMU_CAPS_PCI_ROMBAR, /* -device rombar=0|1 */
    QEMU_CAPS_ICH9_AHCI, /* -device ich9-ahci */
    QEMU_CAPS_NO_ACPI, /* -no-acpi */
    QEMU_CAPS_FSDEV_READONLY, /* -fsdev readonly supported */

    /* 80 */
    QEMU_CAPS_VIRTIO_BLK_SCSI, /* virtio-blk-pci.scsi */
    X_QEMU_CAPS_VIRTIO_BLK_SG_IO, /* SG_IO commands */
    QEMU_CAPS_DRIVE_COPY_ON_READ, /* -drive copy-on-read */
    X_QEMU_CAPS_CPU_HOST, /* support for -cpu host */
    QEMU_CAPS_FSDEV_WRITEOUT, /* -fsdev writeout supported */

    /* 85 */
    QEMU_CAPS_DRIVE_IOTUNE, /* -drive bps= and friends */
    QEMU_CAPS_WAKEUP, /* system_wakeup monitor command */
    QEMU_CAPS_SCSI_DISK_CHANNEL, /* Is scsi-disk.channel available? */
    QEMU_CAPS_SCSI_BLOCK, /* -device scsi-block */
    QEMU_CAPS_TRANSACTION, /* transaction monitor command */

    /* 90 */
    QEMU_CAPS_BLOCKJOB_SYNC, /* old block_job_cancel, block_stream */
    QEMU_CAPS_BLOCKJOB_ASYNC, /* new block-job-cancel, block-stream */
    QEMU_CAPS_SCSI_CD, /* -device scsi-cd */
    QEMU_CAPS_IDE_CD, /* -device ide-cd */
    QEMU_CAPS_NO_USER_CONFIG, /* -no-user-config */

    /* 95 */
    QEMU_CAPS_HDA_MICRO, /* -device hda-micro */
    QEMU_CAPS_DUMP_GUEST_MEMORY, /* dump-guest-memory command */
    QEMU_CAPS_NEC_USB_XHCI, /* -device nec-usb-xhci */
    QEMU_CAPS_VIRTIO_S390, /* -device virtio-*-s390 */
    QEMU_CAPS_BALLOON_EVENT, /* Async event for balloon changes */

    /* 100 */
    QEMU_CAPS_NETDEV_BRIDGE, /* bridge helper support */
    QEMU_CAPS_SCSI_LSI, /* -device lsi */
    QEMU_CAPS_VIRTIO_SCSI, /* -device virtio-scsi-* */
    QEMU_CAPS_BLOCKIO, /* -device ...logical_block_size & co */
    QEMU_CAPS_PIIX_DISABLE_S3, /* -M pc S3 BIOS Advertisement on/off */

    /* 105 */
    QEMU_CAPS_PIIX_DISABLE_S4, /* -M pc S4 BIOS Advertisement on/off */
    QEMU_CAPS_USB_REDIR_FILTER, /* usb-redir.filter */
    QEMU_CAPS_IDE_DRIVE_WWN, /* Is ide-drive.wwn available? */
    QEMU_CAPS_SCSI_DISK_WWN, /* Is scsi-disk.wwn available? */
    QEMU_CAPS_SECCOMP_SANDBOX, /* -sandbox */

    /* 110 */
    QEMU_CAPS_REBOOT_TIMEOUT, /* -boot reboot-timeout */
    QEMU_CAPS_DUMP_GUEST_CORE, /* dump-guest-core-parameter */
    QEMU_CAPS_SEAMLESS_MIGRATION, /* seamless-migration for SPICE */
    QEMU_CAPS_BLOCK_COMMIT, /* block-commit */
    QEMU_CAPS_VNC, /* Is -vnc available? */

    /* 115 */
    QEMU_CAPS_DRIVE_MIRROR, /* drive-mirror monitor command */
    QEMU_CAPS_USB_REDIR_BOOTINDEX, /* usb-redir.bootindex */
    QEMU_CAPS_USB_HOST_BOOTINDEX, /* usb-host.bootindex */
    QEMU_CAPS_DISK_SNAPSHOT, /* blockdev-snapshot-sync command */
    QEMU_CAPS_DEVICE_QXL, /* -device qxl */

    /* 120 */
    QEMU_CAPS_DEVICE_VGA, /* -device VGA */
    QEMU_CAPS_DEVICE_CIRRUS_VGA, /* -device cirrus-vga */
    QEMU_CAPS_DEVICE_VMWARE_SVGA, /* -device vmware-svga */
    QEMU_CAPS_DEVICE_VIDEO_PRIMARY, /* -device safe for primary video device */
    QEMU_CAPS_SCLP_S390, /* -device sclp* */

    /* 125 */
    QEMU_CAPS_DEVICE_USB_SERIAL, /* -device usb-serial */
    QEMU_CAPS_DEVICE_USB_NET, /* -device usb-net */
    QEMU_CAPS_ADD_FD, /* -add-fd */
    QEMU_CAPS_NBD_SERVER, /* nbd-server-start QMP command */
    QEMU_CAPS_DEVICE_VIRTIO_RNG, /* virtio-rng device */

    /* 130 */
    QEMU_CAPS_OBJECT_RNG_RANDOM, /* the rng-random backend for virtio rng */
    QEMU_CAPS_OBJECT_RNG_EGD, /* EGD protocol daemon for rng */
    QEMU_CAPS_VIRTIO_CCW, /* -device virtio-*-ccw */
    QEMU_CAPS_DTB, /* -dtb file */
    QEMU_CAPS_SCSI_MEGASAS, /* -device megasas */

    /* 135 */
    QEMU_CAPS_IPV6_MIGRATION, /* -incoming [::] */
    QEMU_CAPS_MACHINE_OPT, /* -machine xxxx*/
    QEMU_CAPS_MACHINE_USB_OPT, /* -machine xxx,usb=on/off */
    QEMU_CAPS_DEVICE_TPM_PASSTHROUGH, /* -tpmdev passthrough */
    QEMU_CAPS_DEVICE_TPM_TIS, /* -device tpm_tis */

    /* 140 */
    QEMU_CAPS_DEVICE_NVRAM, /* -global spapr-nvram.reg=xxxx */
    QEMU_CAPS_DEVICE_PCI_BRIDGE, /* -device pci-bridge */
    QEMU_CAPS_DEVICE_VFIO_PCI, /* -device vfio-pci */
    QEMU_CAPS_VFIO_PCI_BOOTINDEX, /* bootindex param for vfio-pci device */
    QEMU_CAPS_DEVICE_SCSI_GENERIC, /* -device scsi-generic */

    /* 145 */
    QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX, /* -device scsi-generic.bootindex */
    QEMU_CAPS_MEM_MERGE, /* -machine mem-merge */
    QEMU_CAPS_VNC_WEBSOCKET, /* -vnc x:y,websocket */
    QEMU_CAPS_DRIVE_DISCARD, /* -drive discard=off(ignore)|on(unmap) */
    QEMU_CAPS_REALTIME_MLOCK, /* -realtime mlock=on|off */

    /* 150 */
    QEMU_CAPS_VNC_SHARE_POLICY, /* set display sharing policy */
    QEMU_CAPS_DEVICE_DEL_EVENT, /* DEVICE_DELETED event */
    QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE, /* -device i82801b11-bridge */
    QEMU_CAPS_I440FX_PCI_HOLE64_SIZE, /* i440FX-pcihost.pci-hole64-size */
    QEMU_CAPS_Q35_PCI_HOLE64_SIZE, /* q35-pcihost.pci-hole64-size */

    /* 155 */
    QEMU_CAPS_DEVICE_USB_STORAGE, /* -device usb-storage */
    QEMU_CAPS_USB_STORAGE_REMOVABLE, /* usb-storage.removable */
    QEMU_CAPS_DEVICE_VIRTIO_MMIO, /* -device virtio-mmio */
    QEMU_CAPS_DEVICE_ICH9_INTEL_HDA, /* -device ich9-intel-hda */
    QEMU_CAPS_KVM_PIT_TICK_POLICY, /* kvm-pit.lost_tick_policy */

    /* 160 */
    QEMU_CAPS_BOOT_STRICT, /* -boot strict */
    QEMU_CAPS_DEVICE_PANIC, /* -device pvpanic */
    QEMU_CAPS_ENABLE_FIPS, /* -enable-fips */
    QEMU_CAPS_SPICE_FILE_XFER_DISABLE, /* -spice disable-agent-file-xfer */
    QEMU_CAPS_CHARDEV_SPICEPORT, /* -chardev spiceport */

    /* 165 */
    QEMU_CAPS_DEVICE_USB_KBD, /* -device usb-kbd */
    QEMU_CAPS_HOST_PCI_MULTIDOMAIN, /* support domain > 0 in host pci address */
    QEMU_CAPS_MSG_TIMESTAMP, /* -msg timestamp */
    QEMU_CAPS_ACTIVE_COMMIT, /* block-commit works without 'top' */
    QEMU_CAPS_CHANGE_BACKING_FILE, /* change name of backing file in metadata */

    /* 170 */
    QEMU_CAPS_OBJECT_MEMORY_RAM, /* -object memory-backend-ram */
    QEMU_CAPS_NUMA, /* newer -numa handling with disjoint cpu ranges */
    QEMU_CAPS_OBJECT_MEMORY_FILE, /* -object memory-backend-file */
    QEMU_CAPS_OBJECT_USB_AUDIO, /* usb-audio device support */
    QEMU_CAPS_RTC_RESET_REINJECTION, /* rtc-reset-reinjection monitor command */

    /* 175 */
    QEMU_CAPS_SPLASH_TIMEOUT, /* -boot splash-time */
    QEMU_CAPS_OBJECT_IOTHREAD, /* -object iothread */
    QEMU_CAPS_MIGRATE_RDMA, /* have rdma migration */
    QEMU_CAPS_DEVICE_IVSHMEM, /* -device ivshmem */
    QEMU_CAPS_DRIVE_IOTUNE_MAX, /* -drive bps_max= and friends */

    /* 180 */
    QEMU_CAPS_VGA_VGAMEM, /* -device VGA.vgamem_mb */
    QEMU_CAPS_VMWARE_SVGA_VGAMEM, /* -device vmware-svga.vgamem_mb */
    QEMU_CAPS_QXL_VGAMEM, /* -device qxl.vgamem_mb */
    X_QEMU_CAPS_QXL_VGA_VGAMEM, /* -device qxl-vga.vgamem_mb */
    QEMU_CAPS_DEVICE_PC_DIMM, /* pc-dimm device */

    /* 185 */
    QEMU_CAPS_MACHINE_VMPORT_OPT, /* -machine xxx,vmport=on/off/auto */
    QEMU_CAPS_AES_KEY_WRAP, /* -machine aes_key_wrap */
    QEMU_CAPS_DEA_KEY_WRAP, /* -machine dea_key_wrap */
    QEMU_CAPS_DEVICE_PCI_SERIAL, /* -device pci-serial */
    QEMU_CAPS_CPU_AARCH64_OFF, /* -cpu ...,aarch64=off */

    /* 190 */
    QEMU_CAPS_VHOSTUSER_MULTIQUEUE, /* vhost-user with -netdev queues= */
    QEMU_CAPS_MIGRATION_EVENT, /* MIGRATION event */
    QEMU_CAPS_OBJECT_GPEX, /* have generic PCI host controller */
    QEMU_CAPS_DEVICE_IOH3420, /* -device ioh3420 */
    QEMU_CAPS_DEVICE_X3130_UPSTREAM, /* -device x3130-upstream */

    /* 195 */
    QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM, /* -device xio3130-downstream */
    QEMU_CAPS_DEVICE_RTL8139, /* -device rtl8139 */
    QEMU_CAPS_DEVICE_E1000, /* -device e1000 */
    QEMU_CAPS_DEVICE_VIRTIO_NET, /* -device virtio-net-* */
    QEMU_CAPS_MACH_VIRT_GIC_VERSION, /* -machine virt,gic-version */

    /* 200 */
    QEMU_CAPS_INCOMING_DEFER, /* -incoming defer and migrate_incoming */
    QEMU_CAPS_DEVICE_VIRTIO_GPU, /* -device virtio-gpu-* */
    QEMU_CAPS_VIRTIO_GPU_VIRGL, /* -device virtio-gpu-*.virgl */
    QEMU_CAPS_VIRTIO_KEYBOARD, /* -device virtio-keyboard-{device,pci} */
    QEMU_CAPS_VIRTIO_MOUSE, /* -device virtio-mouse-{device,pci} */

    /* 205 */
    QEMU_CAPS_VIRTIO_TABLET, /* -device virtio-tablet-{device,pci} */
    QEMU_CAPS_VIRTIO_INPUT_HOST, /* -device virtio-input-host-{device,pci} */
    QEMU_CAPS_CHARDEV_FILE_APPEND, /* -chardev file,append=on|off */
    QEMU_CAPS_ICH9_DISABLE_S3, /* -M q35 S3 BIOS Advertisement on/off */
    QEMU_CAPS_ICH9_DISABLE_S4, /* -M q35 S4 BIOS Advertisement on/off */

    /* 210 */
    QEMU_CAPS_VSERPORT_CHANGE, /* VSERPORT_CHANGE event */
    QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE, /* virtio-balloon-{device,pci,ccw}.
                                           * deflate-on-oom */
    QEMU_CAPS_SCSI_MPTSAS1068, /* -device mptsas1068 */
    QEMU_CAPS_SPICE_GL, /* -spice gl */
    QEMU_CAPS_QXL_VRAM64, /* -device qxl.vram64_size_mb */

    /* 215 */
    X_QEMU_CAPS_QXL_VGA_VRAM64, /* -device qxl-vga.vram64_size_mb */
    QEMU_CAPS_CHARDEV_LOGFILE, /* -chardev logfile=xxxx */
    QEMU_CAPS_NAME_DEBUG_THREADS, /* Is -name debug-threads= available */
    QEMU_CAPS_OBJECT_SECRET, /* -object secret */
    QEMU_CAPS_DEVICE_PXB, /* -device pxb */

    /* 220 */
    QEMU_CAPS_DEVICE_PXB_PCIE, /* -device pxb-pcie */
    QEMU_CAPS_DEVICE_TRAY_MOVED, /* DEVICE_TRAY_MOVED event */
    QEMU_CAPS_NEC_USB_XHCI_PORTS, /* -device nec-usb-xhci.p3 ports setting */
    QEMU_CAPS_VIRTIO_SCSI_IOTHREAD, /* virtio-scsi-{pci,ccw}.iothread */
    QEMU_CAPS_NAME_GUEST, /* -name guest= */

    /* 225 */
    QEMU_CAPS_QXL_MAX_OUTPUTS, /* -device qxl,max-outputs= */
    X_QEMU_CAPS_QXL_VGA_MAX_OUTPUTS, /* -device qxl-vga,max-outputs= */
    QEMU_CAPS_SPICE_UNIX, /* -spice unix */
    QEMU_CAPS_DRIVE_DETECT_ZEROES, /* -drive detect-zeroes= */
    QEMU_CAPS_OBJECT_TLS_CREDS_X509, /* -object tls-creds-x509 */

    /* 230 */
    QEMU_CAPS_DISPLAY, /* -display */
    QEMU_CAPS_DEVICE_INTEL_IOMMU, /* -device intel-iommu */
    QEMU_CAPS_MACHINE_SMM_OPT, /* -machine xxx,smm=on/off/auto */
    QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY, /* virtio-*pci.disable-legacy */
    QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS, /* qmp command query-hotpluggable-cpus */

    /* 235 */
    QEMU_CAPS_VIRTIO_NET_RX_QUEUE_SIZE, /* virtio-net-*.rx_queue_size */
    QEMU_CAPS_MACHINE_IOMMU, /* -machine iommu=on */
    QEMU_CAPS_DEVICE_VIRTIO_VGA, /* -device virtio-vga */
    QEMU_CAPS_DRIVE_IOTUNE_MAX_LENGTH, /* -drive bps_max_length = and friends */
    QEMU_CAPS_DEVICE_IVSHMEM_PLAIN, /* -device ivshmem-plain */

    /* 240 */
    QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL, /* -device ivshmem-doorbell */
    QEMU_CAPS_QUERY_QMP_SCHEMA, /* query-qmp-schema command */
    QEMU_CAPS_GLUSTER_DEBUG_LEVEL, /* -drive gluster.debug_level={0..9} */
    QEMU_CAPS_DEVICE_VHOST_SCSI, /* -device vhost-scsi-{ccw,pci} */
    QEMU_CAPS_DRIVE_IOTUNE_GROUP, /* -drive throttling.group=<name> */

    /* 245 */
    QEMU_CAPS_QUERY_CPU_MODEL_EXPANSION, /* qmp query-cpu-model-expansion */
    QEMU_CAPS_VIRTIO_NET_HOST_MTU, /* virtio-net-*.host_mtu */
    QEMU_CAPS_SPICE_RENDERNODE, /* -spice rendernode */
    QEMU_CAPS_DEVICE_NVDIMM, /* -device nvdimm */
    QEMU_CAPS_DEVICE_PCIE_ROOT_PORT, /* -device pcie-root-port */

    /* 250 */
    QEMU_CAPS_QUERY_CPU_DEFINITIONS, /* qmp query-cpu-definitions */
    QEMU_CAPS_BLOCK_WRITE_THRESHOLD, /* BLOCK_WRITE_THRESHOLD event */
    QEMU_CAPS_QUERY_NAMED_BLOCK_NODES, /* qmp query-named-block-nodes */
    QEMU_CAPS_CPU_CACHE, /* -cpu supports host-cache-info and l3-cache properties */
    QEMU_CAPS_DEVICE_QEMU_XHCI, /* -device qemu-xhci */

    /* 255 */
    QEMU_CAPS_MACHINE_KERNEL_IRQCHIP, /* -machine kernel_irqchip */
    QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT, /* -machine kernel_irqchip=split */
    QEMU_CAPS_INTEL_IOMMU_INTREMAP, /* intel-iommu.intremap */

    QEMU_CAPS_LAST /* this must always be the last item */
} virQEMUCapsFlags;

typedef struct _virQEMUCaps virQEMUCaps;
typedef virQEMUCaps *virQEMUCapsPtr;

typedef struct _virQEMUCapsCache virQEMUCapsCache;
typedef virQEMUCapsCache *virQEMUCapsCachePtr;

virQEMUCapsPtr virQEMUCapsNew(void);

void virQEMUCapsSet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

void virQEMUCapsSetList(virQEMUCapsPtr qemuCaps, ...) ATTRIBUTE_NONNULL(1);

void virQEMUCapsClear(virQEMUCapsPtr qemuCaps,
                      virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

bool virQEMUCapsGet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag);

bool virQEMUCapsHasPCIMultiBus(virQEMUCapsPtr qemuCaps,
                               virDomainDefPtr def);

bool virQEMUCapsSupportsVmport(virQEMUCapsPtr qemuCaps,
                               const virDomainDef *def);

bool virQEMUCapsSupportsSMM(virQEMUCapsPtr qemuCaps,
                            const virDomainDef *def);

char *virQEMUCapsFlagsString(virQEMUCapsPtr qemuCaps);

const char *virQEMUCapsGetBinary(virQEMUCapsPtr qemuCaps);
virArch virQEMUCapsGetArch(virQEMUCapsPtr qemuCaps);
unsigned int virQEMUCapsGetVersion(virQEMUCapsPtr qemuCaps);
const char *virQEMUCapsGetPackage(virQEMUCapsPtr qemuCaps);
unsigned int virQEMUCapsGetKVMVersion(virQEMUCapsPtr qemuCaps);
int virQEMUCapsAddCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                 virDomainVirtType type,
                                 const char **name,
                                 size_t count,
                                 virDomainCapsCPUUsable usable);
int virQEMUCapsGetCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                 virDomainVirtType type,
                                 char ***names,
                                 size_t *count);

typedef enum {
    /* Host CPU definition reported in domain capabilities. */
    VIR_QEMU_CAPS_HOST_CPU_REPORTED,
    /* Migratable host CPU definition used for updating guest CPU. */
    VIR_QEMU_CAPS_HOST_CPU_MIGRATABLE,
    /* CPU definition with features detected by libvirt using virCPUGetHost
     * combined with features reported by QEMU. This is used for backward
     * compatible comparison between a guest CPU and a host CPU. */
    VIR_QEMU_CAPS_HOST_CPU_FULL,
} virQEMUCapsHostCPUType;

virCPUDefPtr virQEMUCapsGetHostModel(virQEMUCapsPtr qemuCaps,
                                     virDomainVirtType type,
                                     virQEMUCapsHostCPUType cpuType);

bool virQEMUCapsIsCPUModeSupported(virQEMUCapsPtr qemuCaps,
                                   virCapsPtr caps,
                                   virDomainVirtType type,
                                   virCPUMode mode);
const char *virQEMUCapsGetCanonicalMachine(virQEMUCapsPtr qemuCaps,
                                           const char *name);
int virQEMUCapsGetMachineMaxCpus(virQEMUCapsPtr qemuCaps,
                                 const char *name);
bool virQEMUCapsGetMachineHotplugCpus(virQEMUCapsPtr qemuCaps,
                                      const char *name);
int virQEMUCapsGetMachineTypesCaps(virQEMUCapsPtr qemuCaps,
                                   size_t *nmachines,
                                   virCapsGuestMachinePtr **machines);

bool virQEMUCapsIsValid(virQEMUCapsPtr qemuCaps,
                        time_t ctime,
                        uid_t runUid,
                        gid_t runGid);

void virQEMUCapsFilterByMachineType(virQEMUCapsPtr qemuCaps,
                                    const char *machineType);

virQEMUCapsCachePtr virQEMUCapsCacheNew(const char *libDir,
                                        const char *cacheDir,
                                        uid_t uid, gid_t gid);
virQEMUCapsPtr virQEMUCapsCacheLookup(virCapsPtr caps,
                                      virQEMUCapsCachePtr cache,
                                      const char *binary);
virQEMUCapsPtr virQEMUCapsCacheLookupCopy(virCapsPtr caps,
                                          virQEMUCapsCachePtr cache,
                                          const char *binary,
                                          const char *machineType);
virQEMUCapsPtr virQEMUCapsCacheLookupByArch(virCapsPtr caps,
                                            virQEMUCapsCachePtr cache,
                                            virArch arch);
void virQEMUCapsCacheFree(virQEMUCapsCachePtr cache);

virCapsPtr virQEMUCapsInit(virQEMUCapsCachePtr cache);

int virQEMUCapsGetDefaultVersion(virCapsPtr caps,
                                 virQEMUCapsCachePtr capsCache,
                                 unsigned int *version);

VIR_ENUM_DECL(virQEMUCaps);

bool virQEMUCapsSupportsChardev(const virDomainDef *def,
                                virQEMUCapsPtr qemuCaps,
                                virDomainChrDefPtr chr);

bool virQEMUCapsSupportsGICVersion(virQEMUCapsPtr qemuCaps,
                                   virDomainVirtType virtType,
                                   virGICVersion version);

bool virQEMUCapsIsMachineSupported(virQEMUCapsPtr qemuCaps,
                                   const char *canonical_machine);

const char *virQEMUCapsGetDefaultMachine(virQEMUCapsPtr qemuCaps);

int virQEMUCapsInitGuestFromBinary(virCapsPtr caps,
                                   const char *binary,
                                   virQEMUCapsPtr qemubinCaps,
                                   const char *kvmbin,
                                   virQEMUCapsPtr kvmbinCaps,
                                   virArch guestarch);

int virQEMUCapsFillDomainCaps(virCapsPtr caps,
                              virDomainCapsPtr domCaps,
                              virQEMUCapsPtr qemuCaps,
                              virFirmwarePtr *firmwares,
                              size_t nfirmwares);

#endif /* __QEMU_CAPABILITIES_H__*/
