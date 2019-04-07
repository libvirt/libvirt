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
 */

#ifndef LIBVIRT_QEMU_CAPABILITIES_H
# define LIBVIRT_QEMU_CAPABILITIES_H

# include "virobject.h"
# include "capabilities.h"
# include "vircommand.h"
# include "qemu_monitor.h"
# include "domain_capabilities.h"
# include "virfirmware.h"
# include "virfilecache.h"

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
typedef enum { /* virQEMUCapsFlags grouping marker for syntax-check */
    /* 0 */
    X_QEMU_CAPS_KQEMU, /* Whether KQEMU is compiled in */
    X_QEMU_CAPS_VNC_COLON, /* VNC takes or address + display */
    X_QEMU_CAPS_NO_REBOOT, /* Is the -no-reboot flag available */
    X_QEMU_CAPS_DRIVE, /* Is the new -drive arg available */
    X_QEMU_CAPS_DRIVE_BOOT, /* Does -drive support boot=on */

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
    QEMU_CAPS_KVM, /* Whether KVM is usable / was used during probing */
    X_QEMU_CAPS_DRIVE_FORMAT, /* Is -drive format= avail */

    /* 15 */
    X_QEMU_CAPS_VGA, /* Is -vga avail */
    X_QEMU_CAPS_0_10, /* features added in qemu-0.10.0 or later */
    X_QEMU_CAPS_PCIDEVICE, /* PCI device assignment supported */
    X_QEMU_CAPS_MEM_PATH, /* mmap'ped guest backing supported */
    X_QEMU_CAPS_DRIVE_SERIAL, /* -driver serial=  available */

    /* 20 */
    X_QEMU_CAPS_XEN_DOMID, /* -xen-domid */
    X_QEMU_CAPS_MIGRATE_QEMU_UNIX, /* qemu migration via unix sockets */
    X_QEMU_CAPS_CHARDEV, /* Is the new -chardev arg available */
    X_QEMU_CAPS_ENABLE_KVM, /* -enable-kvm flag */
    X_QEMU_CAPS_MONITOR_JSON, /* JSON mode for monitor */

    /* 25 */
    X_QEMU_CAPS_BALLOON, /* -balloon available */
    X_QEMU_CAPS_DEVICE, /* Is the -device arg available */
    X_QEMU_CAPS_SDL, /* Is the new -sdl arg available */
    X_QEMU_CAPS_SMP_TOPOLOGY, /* -smp has sockets/cores/threads */
    X_QEMU_CAPS_NETDEV, /* -netdev flag & netdev_add/remove */

    /* 30 */
    X_QEMU_CAPS_RTC, /* The -rtc flag for clock options */
    X_QEMU_CAPS_VHOST_NET, /* vhost-net support available */
    X_QEMU_CAPS_RTC_TD_HACK, /* -rtc-td-hack available */
    QEMU_CAPS_NO_HPET, /* -no-hpet flag is supported */
    X_QEMU_CAPS_NO_KVM_PIT, /* -no-kvm-pit-reinjection supported */

    /* 35 */
    X_QEMU_CAPS_TDF, /* -tdf flag (user-mode pit catchup) */
    X_QEMU_CAPS_PCI_CONFIGFD, /* pci-assign.configfd */
    X_QEMU_CAPS_NODEFCONFIG, /* -nodefconfig */
    X_QEMU_CAPS_BOOT_MENU, /* -boot menu=on support */
    X_QEMU_CAPS_ENABLE_KQEMU, /* -enable-kqemu flag */

    /* 40 */
    X_QEMU_CAPS_FSDEV, /* -fstype filesystem passthrough */
    X_QEMU_CAPS_NESTING, /* -enable-nesting (SVM/VMX) */
    X_QEMU_CAPS_NAME_PROCESS, /* Is -name process= available */
    X_QEMU_CAPS_DRIVE_READONLY, /* -drive readonly=on|off */
    X_QEMU_CAPS_SMBIOS_TYPE, /* Is -smbios type= available */

    /* 45 */
    X_QEMU_CAPS_VGA_QXL, /* The 'qxl' arg for '-vga' */
    QEMU_CAPS_SPICE, /* Is -spice avail */
    X_QEMU_CAPS_VGA_NONE, /* The 'none' arg for '-vga' */
    X_QEMU_CAPS_MIGRATE_QEMU_FD, /* -incoming fd:n */
    X_QEMU_CAPS_BOOTINDEX, /* -device bootindex property */

    /* 50 */
    QEMU_CAPS_HDA_DUPLEX, /* -device hda-duplex */
    X_QEMU_CAPS_DRIVE_AIO, /* -drive aio= supported */
    X_QEMU_CAPS_PCI_MULTIBUS, /* bus=pci.0 vs bus=pci */
    X_QEMU_CAPS_PCI_BOOTINDEX, /* pci-assign.bootindex */
    QEMU_CAPS_CCID_EMULATED, /* -device ccid-card-emulated */

    /* 55 */
    QEMU_CAPS_CCID_PASSTHRU, /* -device ccid-card-passthru */
    X_QEMU_CAPS_CHARDEV_SPICEVMC, /* newer -chardev spicevmc */
    X_QEMU_CAPS_DEVICE_SPICEVMC, /* older -device spicevmc*/
    QEMU_CAPS_VIRTIO_TX_ALG, /* -device virtio-net-pci,tx=string */
    X_QEMU_CAPS_DEVICE_QXL_VGA, /* primary qxl device named qxl-vga? */

    /* 60 */
    X_QEMU_CAPS_PCI_MULTIFUNCTION, /* -device multifunction=on|off */
    QEMU_CAPS_VIRTIO_IOEVENTFD, /* virtio-{net|blk}-pci.ioeventfd=on */
    QEMU_CAPS_SGA, /* Serial Graphics Adapter */
    QEMU_CAPS_VIRTIO_BLK_EVENT_IDX, /* virtio-blk-pci.event_idx */
    QEMU_CAPS_VIRTIO_NET_EVENT_IDX, /* virtio-net-pci.event_idx */

    /* 65 */
    X_QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC, /* Is cache=directsync supported? */
    QEMU_CAPS_PIIX3_USB_UHCI, /* -device piix3-usb-uhci */
    QEMU_CAPS_PIIX4_USB_UHCI, /* -device piix4-usb-uhci */
    QEMU_CAPS_USB_EHCI, /* -device usb-ehci */
    QEMU_CAPS_ICH9_USB_EHCI1, /* -device ich9-usb-ehci1 and friends */

    /* 70 */
    QEMU_CAPS_VT82C686B_USB_UHCI, /* -device vt82c686b-usb-uhci */
    QEMU_CAPS_PCI_OHCI, /* -device pci-ohci */
    QEMU_CAPS_USB_REDIR, /* -device usb-redir */
    QEMU_CAPS_USB_HUB, /* -device usb-hub */
    X_QEMU_CAPS_NO_SHUTDOWN, /* usable -no-shutdown */

    /* 75 */
    X_QEMU_CAPS_DRIVE_CACHE_UNSAFE, /* Is cache=unsafe supported? */
    X_QEMU_CAPS_PCI_ROMBAR, /* -device rombar=0|1 */
    QEMU_CAPS_ICH9_AHCI, /* -device ich9-ahci */
    QEMU_CAPS_NO_ACPI, /* -no-acpi */
    X_QEMU_CAPS_FSDEV_READONLY, /* -fsdev readonly supported */

    /* 80 */
    QEMU_CAPS_VIRTIO_BLK_SCSI, /* virtio-blk-pci.scsi */
    X_QEMU_CAPS_VIRTIO_BLK_SG_IO, /* SG_IO commands */
    X_QEMU_CAPS_DRIVE_COPY_ON_READ, /* -drive copy-on-read */
    X_QEMU_CAPS_CPU_HOST, /* support for -cpu host */
    X_QEMU_CAPS_FSDEV_WRITEOUT, /* -fsdev writeout supported */

    /* 85 */
    X_QEMU_CAPS_DRIVE_IOTUNE, /* -drive bps= and friends */
    X_QEMU_CAPS_WAKEUP, /* system_wakeup monitor command */
    QEMU_CAPS_SCSI_DISK_CHANNEL, /* Is scsi-disk.channel available? */
    QEMU_CAPS_SCSI_BLOCK, /* -device scsi-block */
    X_QEMU_CAPS_TRANSACTION, /* transaction monitor command */

    /* 90 */
    X_QEMU_CAPS_BLOCKJOB_SYNC, /* old block_job_cancel, block_stream */
    X_QEMU_CAPS_BLOCKJOB_ASYNC, /* new block-job-cancel, block-stream */
    X_QEMU_CAPS_SCSI_CD, /* -device scsi-cd */
    X_QEMU_CAPS_IDE_CD, /* -device ide-cd */
    X_QEMU_CAPS_NO_USER_CONFIG, /* -no-user-config */

    /* 95 */
    QEMU_CAPS_HDA_MICRO, /* -device hda-micro */
    QEMU_CAPS_DUMP_GUEST_MEMORY, /* dump-guest-memory command */
    QEMU_CAPS_NEC_USB_XHCI, /* -device nec-usb-xhci */
    QEMU_CAPS_VIRTIO_S390, /* -device virtio-*-s390 */
    X_QEMU_CAPS_BALLOON_EVENT, /* Async event for balloon changes */

    /* 100 */
    X_QEMU_CAPS_NETDEV_BRIDGE, /* bridge helper support */
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
    X_QEMU_CAPS_DUMP_GUEST_CORE, /* dump-guest-core-parameter */
    X_QEMU_CAPS_SEAMLESS_MIGRATION, /* seamless-migration for SPICE */
    X_QEMU_CAPS_BLOCK_COMMIT, /* block-commit */
    QEMU_CAPS_VNC, /* Is -vnc available? */

    /* 115 */
    X_QEMU_CAPS_DRIVE_MIRROR, /* drive-mirror monitor command */
    X_QEMU_CAPS_USB_REDIR_BOOTINDEX, /* usb-redir.bootindex */
    X_QEMU_CAPS_USB_HOST_BOOTINDEX, /* usb-host.bootindex */
    X_QEMU_CAPS_DISK_SNAPSHOT, /* blockdev-snapshot-sync command */
    QEMU_CAPS_DEVICE_QXL, /* -device qxl */

    /* 120 */
    QEMU_CAPS_DEVICE_VGA, /* -device VGA */
    QEMU_CAPS_DEVICE_CIRRUS_VGA, /* -device cirrus-vga */
    QEMU_CAPS_DEVICE_VMWARE_SVGA, /* -device vmware-svga */
    QEMU_CAPS_DEVICE_VIDEO_PRIMARY, /* -device safe for primary video device */
    QEMU_CAPS_DEVICE_SCLPCONSOLE, /* -device sclpconsole */

    /* 125 */
    QEMU_CAPS_DEVICE_USB_SERIAL, /* -device usb-serial */
    X_QEMU_CAPS_DEVICE_USB_NET, /* -device usb-net */
    X_QEMU_CAPS_ADD_FD, /* -add-fd */
    QEMU_CAPS_NBD_SERVER, /* nbd-server-start QMP command */
    QEMU_CAPS_DEVICE_VIRTIO_RNG, /* virtio-rng device */

    /* 130 */
    QEMU_CAPS_OBJECT_RNG_RANDOM, /* the rng-random backend for virtio rng */
    QEMU_CAPS_OBJECT_RNG_EGD, /* EGD protocol daemon for rng */
    QEMU_CAPS_VIRTIO_CCW, /* -device virtio-*-ccw */
    X_QEMU_CAPS_DTB, /* -dtb file */
    QEMU_CAPS_SCSI_MEGASAS, /* -device megasas */

    /* 135 */
    X_QEMU_CAPS_IPV6_MIGRATION, /* -incoming [::] */
    X_QEMU_CAPS_MACHINE_OPT, /* -machine xxxx*/
    X_QEMU_CAPS_MACHINE_USB_OPT, /* -machine xxx,usb=on/off */
    QEMU_CAPS_DEVICE_TPM_PASSTHROUGH, /* -tpmdev passthrough */
    QEMU_CAPS_DEVICE_TPM_TIS, /* -device tpm_tis */

    /* 140 */
    QEMU_CAPS_DEVICE_NVRAM, /* -global spapr-nvram.reg=xxxx */
    QEMU_CAPS_DEVICE_PCI_BRIDGE, /* -device pci-bridge */
    QEMU_CAPS_DEVICE_VFIO_PCI, /* -device vfio-pci */
    X_QEMU_CAPS_VFIO_PCI_BOOTINDEX, /* bootindex param for vfio-pci device */
    X_QEMU_CAPS_DEVICE_SCSI_GENERIC, /* -device scsi-generic */

    /* 145 */
    X_QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX, /* -device scsi-generic.bootindex */
    QEMU_CAPS_MEM_MERGE, /* -machine mem-merge */
    X_QEMU_CAPS_VNC_WEBSOCKET, /* -vnc x:y,websocket */
    QEMU_CAPS_DRIVE_DISCARD, /* -drive discard=off(ignore)|on(unmap) */
    QEMU_CAPS_REALTIME_MLOCK, /* -realtime mlock=on|off */

    /* 150 */
    X_QEMU_CAPS_VNC_SHARE_POLICY, /* set display sharing policy */
    X_QEMU_CAPS_DEVICE_DEL_EVENT, /* DEVICE_DELETED event */
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
    X_QEMU_CAPS_CHARDEV_SPICEPORT, /* -chardev spiceport */

    /* 165 */
    QEMU_CAPS_DEVICE_USB_KBD, /* -device usb-kbd */
    X_QEMU_CAPS_HOST_PCI_MULTIDOMAIN, /* support domain > 0 in host pci address */
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
    X_QEMU_CAPS_DEVICE_TRAY_MOVED, /* DEVICE_TRAY_MOVED event */
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
    X_QEMU_CAPS_DISPLAY, /* -display */
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
    QEMU_CAPS_INTEL_IOMMU_CACHING_MODE, /* intel-iommu.caching-mode */
    QEMU_CAPS_INTEL_IOMMU_EIM, /* intel-iommu.eim */

    /* 260 */
    QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB, /* intel-iommu.device-iotlb */
    QEMU_CAPS_VIRTIO_PCI_IOMMU_PLATFORM, /* virtio-*-pci.iommu_platform */
    QEMU_CAPS_VIRTIO_PCI_ATS, /* virtio-*-pci.ats */
    QEMU_CAPS_LOADPARM, /* -machine loadparm */
    QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE, /* -device spapr-pci-host-bridge */

    /* 265 */
    QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE, /* spapr-pci-host-bridge.numa_node= */
    QEMU_CAPS_VNC_MULTI_SERVERS, /* -vnc vnc=unix:/path */
    QEMU_CAPS_VIRTIO_NET_TX_QUEUE_SIZE, /* virtio-net-*.tx_queue_size */
    QEMU_CAPS_CHARDEV_RECONNECT, /* -chardev reconnect */
    QEMU_CAPS_VIRTIO_GPU_MAX_OUTPUTS, /* -device virtio-(vga|gpu-*),max-outputs= */

    /* 270 */
    QEMU_CAPS_VXHS, /* -drive file.driver=vxhs via query-qmp-schema */
    QEMU_CAPS_VIRTIO_BLK_NUM_QUEUES, /* virtio-blk-*.num-queues */
    QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT, /* -machine pseries,resize-hpt */
    QEMU_CAPS_DEVICE_VMCOREINFO, /* -device vmcoreinfo */
    QEMU_CAPS_DEVICE_SPAPR_VTY, /* -device spapr-vty */

    /* 275 */
    QEMU_CAPS_DEVICE_SCLPLMCONSOLE, /* -device sclplmconsole */
    QEMU_CAPS_NUMA_DIST, /* -numa dist */
    QEMU_CAPS_DISK_SHARE_RW, /* share-rw=on for concurrent disk access */
    QEMU_CAPS_ISCSI_PASSWORD_SECRET, /* -drive file.driver=iscsi,...,password-secret= */
    QEMU_CAPS_DEVICE_ISA_SERIAL, /* -device isa-serial */

    /* 280 */
    QEMU_CAPS_DEVICE_PL011, /* -device pl011 (not user-instantiable) */
    QEMU_CAPS_MACHINE_PSERIES_MAX_CPU_COMPAT, /* -machine pseries,max-cpu-compat= */
    QEMU_CAPS_DUMP_COMPLETED, /* DUMP_COMPLETED event */
    QEMU_CAPS_DEVICE_VIRTIO_GPU_CCW, /* -device virtio-gpu-ccw */
    QEMU_CAPS_DEVICE_VIRTIO_KEYBOARD_CCW, /* -device virtio-keyboard-ccw */

    /* 285 */
    QEMU_CAPS_DEVICE_VIRTIO_MOUSE_CCW, /* -device virtio-mouse-ccw */
    QEMU_CAPS_DEVICE_VIRTIO_TABLET_CCW, /* -device virtio-tablet-ccw */
    QEMU_CAPS_QCOW2_LUKS, /* qcow2 format support LUKS encryption */
    QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE, /* -device pcie-pci-bridge */
    QEMU_CAPS_SECCOMP_BLACKLIST, /* -sandbox.elevateprivileges */

    /* 290 */
    QEMU_CAPS_QUERY_CPUS_FAST, /* query-cpus-fast command */
    QEMU_CAPS_DISK_WRITE_CACHE, /* qemu block frontends support write-cache param */
    QEMU_CAPS_NBD_TLS, /* NBD server supports TLS transport */
    QEMU_CAPS_DEVICE_TPM_CRB, /* -device tpm-crb */
    QEMU_CAPS_PR_MANAGER_HELPER, /* -object pr-manager-helper */

    /* 295 */
    QEMU_CAPS_QOM_LIST_PROPERTIES, /* qom-list-properties monitor command */
    QEMU_CAPS_OBJECT_MEMORY_FILE_DISCARD, /* -object memory-backend-file,discard-data */
    QEMU_CAPS_CCW, /* -device virtual-css-bridge */
    QEMU_CAPS_CCW_CSSID_UNRESTRICTED, /* virtual-css-bridge.cssid-unrestricted= */
    QEMU_CAPS_DEVICE_VFIO_CCW, /* -device vfio-ccw */

    /* 300 */
    QEMU_CAPS_SDL_GL, /* -sdl gl */
    QEMU_CAPS_SCREENDUMP_DEVICE, /* screendump command accepts device & head */
    QEMU_CAPS_HDA_OUTPUT, /* -device hda-output */
    QEMU_CAPS_BLOCKDEV_DEL, /* blockdev-del is supported */
    QEMU_CAPS_DEVICE_VMGENID, /* -device vmgenid */

    /* 305 */
    QEMU_CAPS_DEVICE_VHOST_VSOCK, /* -device vhost-vsock-* */
    QEMU_CAPS_CHARDEV_FD_PASS, /* Passing pre-opened FDs for chardevs */
    QEMU_CAPS_DEVICE_TPM_EMULATOR, /* -tpmdev emulator */
    QEMU_CAPS_DEVICE_MCH, /* Northbridge in q35 machine types */
    QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES, /* -global mch.extended-tseg-mbytes */

    /* 310 */
    QEMU_CAPS_SEV_GUEST, /* -object sev-guest,... */
    QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE, /* -machine pseries.cap-hpt-max-page-size */
    QEMU_CAPS_MACHINE_PSERIES_CAP_HTM, /* -machine pseries.cap-htm */
    QEMU_CAPS_USB_STORAGE_WERROR, /* -device usb-storage,werror=..,rerror=.. */
    QEMU_CAPS_EGL_HEADLESS, /* -display egl-headless */

    /* 315 */
    QEMU_CAPS_VFIO_PCI_DISPLAY, /* -device vfio-pci.display */
    QEMU_CAPS_BLOCKDEV, /* -blockdev and blockdev-add are supported */
    QEMU_CAPS_DEVICE_VFIO_AP, /* -device vfio-ap */
    QEMU_CAPS_DEVICE_ZPCI, /* -device zpci */
    QEMU_CAPS_OBJECT_MEMORY_MEMFD, /* -object memory-backend-memfd */

    /* 320 */
    QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB, /* -object memory-backend-memfd.hugetlb */
    QEMU_CAPS_IOTHREAD_POLLING, /* -object iothread.poll-max-ns */
    QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV, /* -machine pseries.cap-nested-hv */
    QEMU_CAPS_EGL_HEADLESS_RENDERNODE, /* -display egl-headless,rendernode= */
    QEMU_CAPS_OBJECT_MEMORY_FILE_ALIGN, /* -object memory-backend-file,align= */

    /* 325 */
    QEMU_CAPS_OBJECT_MEMORY_FILE_PMEM, /* -object memory-backend-file,pmem= */
    QEMU_CAPS_DEVICE_NVDIMM_UNARMED, /* -device nvdimm,unarmed= */
    QEMU_CAPS_SCSI_DISK_DEVICE_ID, /* 'device_id' property of scsi disk */
    QEMU_CAPS_VIRTIO_PCI_TRANSITIONAL, /* virtio *-pci-{non-}transitional devices */

    QEMU_CAPS_LAST /* this must always be the last item */
} virQEMUCapsFlags;

typedef struct _virQEMUCaps virQEMUCaps;
typedef virQEMUCaps *virQEMUCapsPtr;

virQEMUCapsPtr virQEMUCapsNew(void);

void virQEMUCapsSet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

void virQEMUCapsSetList(virQEMUCapsPtr qemuCaps, ...) ATTRIBUTE_NONNULL(1);

void virQEMUCapsClear(virQEMUCapsPtr qemuCaps,
                      virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

bool virQEMUCapsGet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag);

bool virQEMUCapsHasPCIMultiBus(virQEMUCapsPtr qemuCaps,
                               const virDomainDef *def);

bool virQEMUCapsSupportsVmport(virQEMUCapsPtr qemuCaps,
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
virDomainCapsCPUModelsPtr virQEMUCapsGetCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                                       virDomainVirtType type);
virDomainCapsCPUModelsPtr virQEMUCapsFetchCPUDefinitions(qemuMonitorPtr mon);

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
int virQEMUCapsGetCPUFeatures(virQEMUCapsPtr qemuCaps,
                              virDomainVirtType virtType,
                              bool migratable,
                              char ***features);

bool virQEMUCapsIsCPUModeSupported(virQEMUCapsPtr qemuCaps,
                                   virCapsPtr caps,
                                   virDomainVirtType type,
                                   virCPUMode mode);
const char *virQEMUCapsGetCanonicalMachine(virQEMUCapsPtr qemuCaps,
                                           const char *name);
const char *virQEMUCapsGetDefaultMachine(virQEMUCapsPtr qemuCaps);
int virQEMUCapsGetMachineMaxCpus(virQEMUCapsPtr qemuCaps,
                                 const char *name);
bool virQEMUCapsGetMachineHotplugCpus(virQEMUCapsPtr qemuCaps,
                                      const char *name);
int virQEMUCapsGetMachineTypesCaps(virQEMUCapsPtr qemuCaps,
                                   size_t *nmachines,
                                   virCapsGuestMachinePtr **machines);

void virQEMUCapsFilterByMachineType(virQEMUCapsPtr qemuCaps,
                                    const char *machineType);

virFileCachePtr virQEMUCapsCacheNew(const char *libDir,
                                    const char *cacheDir,
                                    uid_t uid,
                                    gid_t gid,
                                    unsigned int microcodeVersion);
virQEMUCapsPtr virQEMUCapsCacheLookup(virFileCachePtr cache,
                                      const char *binary);
virQEMUCapsPtr virQEMUCapsCacheLookupCopy(virFileCachePtr cache,
                                          const char *binary,
                                          const char *machineType);
virQEMUCapsPtr virQEMUCapsCacheLookupByArch(virFileCachePtr cache,
                                            virArch arch);
virQEMUCapsPtr virQEMUCapsCacheLookupDefault(virFileCachePtr cache,
                                             const char *binary,
                                             const char *archStr,
                                             const char *virttypeStr,
                                             const char *machine,
                                             virArch *retArch,
                                             virDomainVirtType *retVirttype,
                                             const char **retMachine);

virCapsPtr virQEMUCapsInit(virFileCachePtr cache);

int virQEMUCapsGetDefaultVersion(virCapsPtr caps,
                                 virFileCachePtr capsCache,
                                 unsigned int *version);

VIR_ENUM_DECL(virQEMUCaps);

bool virQEMUCapsSupportsGICVersion(virQEMUCapsPtr qemuCaps,
                                   virDomainVirtType virtType,
                                   virGICVersion version);

bool virQEMUCapsIsMachineSupported(virQEMUCapsPtr qemuCaps,
                                   const char *canonical_machine);

const char *virQEMUCapsGetPreferredMachine(virQEMUCapsPtr qemuCaps);

int virQEMUCapsInitGuestFromBinary(virCapsPtr caps,
                                   const char *binary,
                                   virQEMUCapsPtr qemuCaps,
                                   virArch guestarch);

int virQEMUCapsFillDomainCaps(virCapsPtr caps,
                              virDomainCapsPtr domCaps,
                              virQEMUCapsPtr qemuCaps,
                              virFirmwarePtr *firmwares,
                              size_t nfirmwares);

bool virQEMUCapsGuestIsNative(virArch host,
                              virArch guest);

bool virQEMUCapsCPUFilterFeatures(const char *name,
                                  void *opaque);

virSEVCapabilityPtr
virQEMUCapsGetSEVCapabilities(virQEMUCapsPtr qemuCaps);

virArch virQEMUCapsArchFromString(const char *arch);
const char *virQEMUCapsArchToString(virArch arch);

#endif /* LIBVIRT_QEMU_CAPABILITIES_H */
