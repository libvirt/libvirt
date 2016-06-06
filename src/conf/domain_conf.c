/*
 * domain_conf.c: domain XML processing
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "configmake.h"
#include "internal.h"
#include "virerror.h"
#include "datatypes.h"
#include "domain_addr.h"
#include "domain_conf.h"
#include "snapshot_conf.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virlog.h"
#include "nwfilter_conf.h"
#include "storage_conf.h"
#include "virstoragefile.h"
#include "virfile.h"
#include "virbitmap.h"
#include "count-one-bits.h"
#include "secret_conf.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "device_conf.h"
#include "network_conf.h"
#include "virtpm.h"
#include "virstring.h"
#include "virnetdev.h"
#include "virnetdevmacvlan.h"
#include "virhostdev.h"
#include "virmdev.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_conf");

/* This structure holds various callbacks and data needed
 * while parsing and creating domain XMLs */
struct _virDomainXMLOption {
    virObject parent;

    /* XML parser callbacks and defaults */
    virDomainDefParserConfig config;

    /* domain private data management callbacks */
    virDomainXMLPrivateDataCallbacks privateData;

    /* XML namespace callbacks */
    virDomainXMLNamespace ns;

    /* ABI stability callbacks */
    virDomainABIStability abi;

    /* Private data for save image stored in snapshot XML */
    virSaveCookieCallbacks saveCookie;
};

#define VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS             \
    (VIR_DOMAIN_DEF_FORMAT_SECURE |                    \
     VIR_DOMAIN_DEF_FORMAT_INACTIVE |                  \
     VIR_DOMAIN_DEF_FORMAT_UPDATE_CPU |                \
     VIR_DOMAIN_DEF_FORMAT_MIGRATABLE)

VIR_ENUM_IMPL(virDomainTaint, VIR_DOMAIN_TAINT_LAST,
              "custom-argv",
              "custom-monitor",
              "high-privileges",
              "shell-scripts",
              "disk-probing",
              "external-launch",
              "host-cpu",
              "hook-script",
              "cdrom-passthrough",
              "custom-dtb");

VIR_ENUM_IMPL(virDomainVirt, VIR_DOMAIN_VIRT_LAST,
              "none",
              "qemu",
              "kqemu",
              "kvm",
              "xen",
              "lxc",
              "uml",
              "openvz",
              "test",
              "vmware",
              "hyperv",
              "vbox",
              "phyp",
              "parallels",
              "bhyve",
              "vz")

VIR_ENUM_IMPL(virDomainOS, VIR_DOMAIN_OSTYPE_LAST,
              "hvm",
              "xen",
              "linux",
              "exe",
              "uml")

VIR_ENUM_IMPL(virDomainBoot, VIR_DOMAIN_BOOT_LAST,
              "fd",
              "cdrom",
              "hd",
              "network")

VIR_ENUM_IMPL(virDomainFeature, VIR_DOMAIN_FEATURE_LAST,
              "acpi",
              "apic",
              "pae",
              "hap",
              "viridian",
              "privnet",
              "hyperv",
              "kvm",
              "pvspinlock",
              "capabilities",
              "pmu",
              "vmport",
              "gic",
              "smm",
              "ioapic")

VIR_ENUM_IMPL(virDomainCapabilitiesPolicy, VIR_DOMAIN_CAPABILITIES_POLICY_LAST,
              "default",
              "allow",
              "deny")

VIR_ENUM_IMPL(virDomainHyperv, VIR_DOMAIN_HYPERV_LAST,
              "relaxed",
              "vapic",
              "spinlocks",
              "vpindex",
              "runtime",
              "synic",
              "stimer",
              "reset",
              "vendor_id")

VIR_ENUM_IMPL(virDomainKVM, VIR_DOMAIN_KVM_LAST,
              "hidden")

VIR_ENUM_IMPL(virDomainCapsFeature, VIR_DOMAIN_CAPS_FEATURE_LAST,
              "audit_control",
              "audit_write",
              "block_suspend",
              "chown",
              "dac_override",
              "dac_read_search",
              "fowner",
              "fsetid",
              "ipc_lock",
              "ipc_owner",
              "kill",
              "lease",
              "linux_immutable",
              "mac_admin",
              "mac_override",
              "mknod",
              "net_admin",
              "net_bind_service",
              "net_broadcast",
              "net_raw",
              "setgid",
              "setfcap",
              "setpcap",
              "setuid",
              "sys_admin",
              "sys_boot",
              "sys_chroot",
              "sys_module",
              "sys_nice",
              "sys_pacct",
              "sys_ptrace",
              "sys_rawio",
              "sys_resource",
              "sys_time",
              "sys_tty_config",
              "syslog",
              "wake_alarm")

VIR_ENUM_IMPL(virDomainLifecycle, VIR_DOMAIN_LIFECYCLE_LAST,
              "destroy",
              "restart",
              "rename-restart",
              "preserve")

VIR_ENUM_IMPL(virDomainLifecycleCrash, VIR_DOMAIN_LIFECYCLE_CRASH_LAST,
              "destroy",
              "restart",
              "rename-restart",
              "preserve",
              "coredump-destroy",
              "coredump-restart")

VIR_ENUM_IMPL(virDomainLockFailure, VIR_DOMAIN_LOCK_FAILURE_LAST,
              "default",
              "poweroff",
              "restart",
              "pause",
              "ignore")

VIR_ENUM_IMPL(virDomainDevice, VIR_DOMAIN_DEVICE_LAST,
              "none",
              "disk",
              "lease",
              "filesystem",
              "interface",
              "input",
              "sound",
              "video",
              "hostdev",
              "watchdog",
              "controller",
              "graphics",
              "hub",
              "redirdev",
              "smartcard",
              "chr",
              "memballoon",
              "nvram",
              "rng",
              "shmem",
              "tpm",
              "panic",
              "memory",
              "iommu")

VIR_ENUM_IMPL(virDomainDeviceAddress, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST,
              "none",
              "pci",
              "drive",
              "virtio-serial",
              "ccid",
              "usb",
              "spapr-vio",
              "virtio-s390",
              "ccw",
              "virtio-mmio",
              "isa",
              "dimm")

VIR_ENUM_IMPL(virDomainDiskDevice, VIR_DOMAIN_DISK_DEVICE_LAST,
              "disk",
              "cdrom",
              "floppy",
              "lun")

VIR_ENUM_IMPL(virDomainDiskGeometryTrans, VIR_DOMAIN_DISK_TRANS_LAST,
              "default",
              "none",
              "auto",
              "lba")

VIR_ENUM_IMPL(virDomainDiskBus, VIR_DOMAIN_DISK_BUS_LAST,
              "ide",
              "fdc",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml",
              "sata",
              "sd")

VIR_ENUM_IMPL(virDomainDiskCache, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback",
              "directsync",
              "unsafe")

VIR_ENUM_IMPL(virDomainDiskErrorPolicy, VIR_DOMAIN_DISK_ERROR_POLICY_LAST,
              "default",
              "stop",
              "report",
              "ignore",
              "enospace")

VIR_ENUM_IMPL(virDomainDiskIo, VIR_DOMAIN_DISK_IO_LAST,
              "default",
              "native",
              "threads")

VIR_ENUM_IMPL(virDomainDeviceSGIO, VIR_DOMAIN_DEVICE_SGIO_LAST,
              "default",
              "filtered",
              "unfiltered")

VIR_ENUM_IMPL(virDomainController, VIR_DOMAIN_CONTROLLER_TYPE_LAST,
              "ide",
              "fdc",
              "scsi",
              "sata",
              "virtio-serial",
              "ccid",
              "usb",
              "pci")

VIR_ENUM_IMPL(virDomainControllerModelPCI, VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST,
              "pci-root",
              "pcie-root",
              "pci-bridge",
              "dmi-to-pci-bridge",
              "pcie-root-port",
              "pcie-switch-upstream-port",
              "pcie-switch-downstream-port",
              "pci-expander-bus",
              "pcie-expander-bus")

VIR_ENUM_IMPL(virDomainControllerPCIModelName,
              VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_LAST,
              "none",
              "pci-bridge",
              "i82801b11-bridge",
              "ioh3420",
              "x3130-upstream",
              "xio3130-downstream",
              "pxb",
              "pxb-pcie",
              "pcie-root-port",
);

VIR_ENUM_IMPL(virDomainControllerModelSCSI, VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST,
              "auto",
              "buslogic",
              "lsilogic",
              "lsisas1068",
              "vmpvscsi",
              "ibmvscsi",
              "virtio-scsi",
              "lsisas1078");

VIR_ENUM_IMPL(virDomainControllerModelUSB, VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST,
              "piix3-uhci",
              "piix4-uhci",
              "ehci",
              "ich9-ehci1",
              "ich9-uhci1",
              "ich9-uhci2",
              "ich9-uhci3",
              "vt82c686b-uhci",
              "pci-ohci",
              "nec-xhci",
              "qusb1",
              "qusb2",
              "qemu-xhci",
              "none")

VIR_ENUM_IMPL(virDomainFS, VIR_DOMAIN_FS_TYPE_LAST,
              "mount",
              "block",
              "file",
              "template",
              "ram",
              "bind",
              "volume")

VIR_ENUM_IMPL(virDomainFSDriver, VIR_DOMAIN_FS_DRIVER_TYPE_LAST,
              "default",
              "path",
              "handle",
              "loop",
              "nbd",
              "ploop")

VIR_ENUM_IMPL(virDomainFSAccessMode, VIR_DOMAIN_FS_ACCESSMODE_LAST,
              "passthrough",
              "mapped",
              "squash")

VIR_ENUM_IMPL(virDomainFSWrpolicy, VIR_DOMAIN_FS_WRPOLICY_LAST,
              "default",
              "immediate")

VIR_ENUM_IMPL(virDomainNet, VIR_DOMAIN_NET_TYPE_LAST,
              "user",
              "ethernet",
              "vhostuser",
              "server",
              "client",
              "mcast",
              "network",
              "bridge",
              "internal",
              "direct",
              "hostdev",
              "udp")

VIR_ENUM_IMPL(virDomainNetBackend, VIR_DOMAIN_NET_BACKEND_TYPE_LAST,
              "default",
              "qemu",
              "vhost")

VIR_ENUM_IMPL(virDomainNetVirtioTxMode, VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST,
              "default",
              "iothread",
              "timer")

VIR_ENUM_IMPL(virDomainNetInterfaceLinkState, VIR_DOMAIN_NET_INTERFACE_LINK_STATE_LAST,
              "default",
              "up",
              "down")

VIR_ENUM_IMPL(virDomainChrDeviceState, VIR_DOMAIN_CHR_DEVICE_STATE_LAST,
              "default",
              "connected",
              "disconnected");

VIR_ENUM_IMPL(virDomainChrSerialTarget,
              VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST,
              "isa-serial",
              "usb-serial",
              "pci-serial")

VIR_ENUM_IMPL(virDomainChrChannelTarget,
              VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST,
              "none",
              "guestfwd",
              "virtio",
              "xen")

VIR_ENUM_IMPL(virDomainChrConsoleTarget,
              VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LAST,
              "none",
              "serial",
              "xen",
              "uml",
              "virtio",
              "lxc",
              "openvz",
              "sclp",
              "sclplm")

VIR_ENUM_IMPL(virDomainChrDevice, VIR_DOMAIN_CHR_DEVICE_TYPE_LAST,
              "parallel",
              "serial",
              "console",
              "channel")

VIR_ENUM_IMPL(virDomainChr, VIR_DOMAIN_CHR_TYPE_LAST,
              "null",
              "vc",
              "pty",
              "dev",
              "file",
              "pipe",
              "stdio",
              "udp",
              "tcp",
              "unix",
              "spicevmc",
              "spiceport",
              "nmdm")

VIR_ENUM_IMPL(virDomainChrTcpProtocol, VIR_DOMAIN_CHR_TCP_PROTOCOL_LAST,
              "raw",
              "telnet",
              "telnets",
              "tls")

VIR_ENUM_IMPL(virDomainChrSpicevmc, VIR_DOMAIN_CHR_SPICEVMC_LAST,
              "vdagent",
              "smartcard",
              "usbredir")

VIR_ENUM_IMPL(virDomainSmartcard, VIR_DOMAIN_SMARTCARD_TYPE_LAST,
              "host",
              "host-certificates",
              "passthrough")

VIR_ENUM_IMPL(virDomainSoundCodec, VIR_DOMAIN_SOUND_CODEC_TYPE_LAST,
              "duplex",
              "micro")

VIR_ENUM_IMPL(virDomainSoundModel, VIR_DOMAIN_SOUND_MODEL_LAST,
              "sb16",
              "es1370",
              "pcspk",
              "ac97",
              "ich6",
              "ich9",
              "usb")

VIR_ENUM_IMPL(virDomainKeyWrapCipherName,
              VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_LAST,
              "aes",
              "dea")

VIR_ENUM_IMPL(virDomainMemballoonModel, VIR_DOMAIN_MEMBALLOON_MODEL_LAST,
              "virtio",
              "xen",
              "none")

VIR_ENUM_IMPL(virDomainSmbiosMode, VIR_DOMAIN_SMBIOS_LAST,
              "none",
              "emulate",
              "host",
              "sysinfo")

VIR_ENUM_IMPL(virDomainWatchdogModel, VIR_DOMAIN_WATCHDOG_MODEL_LAST,
              "i6300esb",
              "ib700",
              "diag288")

VIR_ENUM_IMPL(virDomainWatchdogAction, VIR_DOMAIN_WATCHDOG_ACTION_LAST,
              "reset",
              "shutdown",
              "poweroff",
              "pause",
              "dump",
              "none",
              "inject-nmi")

VIR_ENUM_IMPL(virDomainPanicModel, VIR_DOMAIN_PANIC_MODEL_LAST,
              "default",
              "isa",
              "pseries",
              "hyperv",
              "s390")

VIR_ENUM_IMPL(virDomainVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "vga",
              "cirrus",
              "vmvga",
              "xen",
              "vbox",
              "qxl",
              "parallels",
              "virtio",
              "gop")

VIR_ENUM_IMPL(virDomainInput, VIR_DOMAIN_INPUT_TYPE_LAST,
              "mouse",
              "tablet",
              "keyboard",
              "passthrough")

VIR_ENUM_IMPL(virDomainInputBus, VIR_DOMAIN_INPUT_BUS_LAST,
              "ps2",
              "usb",
              "xen",
              "parallels",
              "virtio")

VIR_ENUM_IMPL(virDomainGraphics, VIR_DOMAIN_GRAPHICS_TYPE_LAST,
              "sdl",
              "vnc",
              "rdp",
              "desktop",
              "spice")

VIR_ENUM_IMPL(virDomainGraphicsListen, VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST,
              "none",
              "address",
              "network",
              "socket")

VIR_ENUM_IMPL(virDomainGraphicsAuthConnected,
              VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_LAST,
              "default",
              "fail",
              "disconnect",
              "keep")

VIR_ENUM_IMPL(virDomainGraphicsVNCSharePolicy,
              VIR_DOMAIN_GRAPHICS_VNC_SHARE_LAST,
              "default",
              "allow-exclusive",
              "force-shared",
              "ignore")

VIR_ENUM_IMPL(virDomainGraphicsSpiceChannelName,
              VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST,
              "main",
              "display",
              "inputs",
              "cursor",
              "playback",
              "record",
              "smartcard",
              "usbredir");

VIR_ENUM_IMPL(virDomainGraphicsSpiceChannelMode,
              VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_LAST,
              "any",
              "secure",
              "insecure");

VIR_ENUM_IMPL(virDomainGraphicsSpiceImageCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LAST,
              "default",
              "auto_glz",
              "auto_lz",
              "quic",
              "glz",
              "lz",
              "off");

VIR_ENUM_IMPL(virDomainGraphicsSpiceJpegCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_LAST,
              "default",
              "auto",
              "never",
              "always");

VIR_ENUM_IMPL(virDomainGraphicsSpiceZlibCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_LAST,
              "default",
              "auto",
              "never",
              "always");

VIR_ENUM_IMPL(virDomainGraphicsSpiceMouseMode,
              VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_LAST,
              "default",
              "server",
              "client");

VIR_ENUM_IMPL(virDomainGraphicsSpiceStreamingMode,
              VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_LAST,
              "default",
              "filter",
              "all",
              "off");

VIR_ENUM_IMPL(virDomainHostdevMode, VIR_DOMAIN_HOSTDEV_MODE_LAST,
              "subsystem",
              "capabilities")

VIR_ENUM_IMPL(virDomainHostdevSubsys, VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST,
              "usb",
              "pci",
              "scsi",
              "scsi_host",
              "mdev")

VIR_ENUM_IMPL(virDomainHostdevSubsysPCIBackend,
              VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST,
              "default",
              "kvm",
              "vfio",
              "xen")

VIR_ENUM_IMPL(virDomainHostdevSubsysSCSIProtocol,
              VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST,
              "adapter",
              "iscsi")

VIR_ENUM_IMPL(virDomainHostdevSubsysSCSIHostProtocol,
              VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_LAST,
              "none",
              "vhost")

VIR_ENUM_IMPL(virDomainHostdevCaps, VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST,
              "storage",
              "misc",
              "net")

VIR_ENUM_IMPL(virDomainHub, VIR_DOMAIN_HUB_TYPE_LAST,
              "usb")

VIR_ENUM_IMPL(virDomainRedirdevBus, VIR_DOMAIN_REDIRDEV_BUS_LAST,
              "usb")

VIR_ENUM_IMPL(virDomainState, VIR_DOMAIN_LAST,
              "nostate",
              "running",
              "blocked",
              "paused",
              "shutdown",
              "shutoff",
              "crashed",
              "pmsuspended")

VIR_ENUM_IMPL(virDomainNostateReason, VIR_DOMAIN_NOSTATE_LAST,
              "unknown")

VIR_ENUM_IMPL(virDomainRunningReason, VIR_DOMAIN_RUNNING_LAST,
              "unknown",
              "booted",
              "migrated",
              "restored",
              "from snapshot",
              "unpaused",
              "migration canceled",
              "save canceled",
              "wakeup",
              "crashed",
              "post-copy")

VIR_ENUM_IMPL(virDomainBlockedReason, VIR_DOMAIN_BLOCKED_LAST,
              "unknown")

VIR_ENUM_IMPL(virDomainPausedReason, VIR_DOMAIN_PAUSED_LAST,
              "unknown",
              "user",
              "migration",
              "save",
              "dump",
              "ioerror",
              "watchdog",
              "from snapshot",
              "shutdown",
              "snapshot",
              "panicked",
              "starting up",
              "post-copy",
              "post-copy failed")

VIR_ENUM_IMPL(virDomainShutdownReason, VIR_DOMAIN_SHUTDOWN_LAST,
              "unknown",
              "user")

VIR_ENUM_IMPL(virDomainShutoffReason, VIR_DOMAIN_SHUTOFF_LAST,
              "unknown",
              "shutdown",
              "destroyed",
              "crashed",
              "migrated",
              "saved",
              "failed",
              "from snapshot")

VIR_ENUM_IMPL(virDomainCrashedReason, VIR_DOMAIN_CRASHED_LAST,
              "unknown",
              "panicked")

VIR_ENUM_IMPL(virDomainPMSuspendedReason, VIR_DOMAIN_PMSUSPENDED_LAST,
              "unknown")

VIR_ENUM_IMPL(virDomainSeclabel, VIR_DOMAIN_SECLABEL_LAST,
              "default",
              "none",
              "dynamic",
              "static")

VIR_ENUM_IMPL(virDomainClockOffset, VIR_DOMAIN_CLOCK_OFFSET_LAST,
              "utc",
              "localtime",
              "variable",
              "timezone");

VIR_ENUM_IMPL(virDomainClockBasis, VIR_DOMAIN_CLOCK_BASIS_LAST,
              "utc",
              "localtime");

VIR_ENUM_IMPL(virDomainTimerName, VIR_DOMAIN_TIMER_NAME_LAST,
              "platform",
              "pit",
              "rtc",
              "hpet",
              "tsc",
              "kvmclock",
              "hypervclock");

VIR_ENUM_IMPL(virDomainTimerTrack, VIR_DOMAIN_TIMER_TRACK_LAST,
              "boot",
              "guest",
              "wall");

VIR_ENUM_IMPL(virDomainTimerTickpolicy, VIR_DOMAIN_TIMER_TICKPOLICY_LAST,
              "delay",
              "catchup",
              "merge",
              "discard");

VIR_ENUM_IMPL(virDomainTimerMode, VIR_DOMAIN_TIMER_MODE_LAST,
              "auto",
              "native",
              "emulate",
              "paravirt",
              "smpsafe");

VIR_ENUM_IMPL(virDomainStartupPolicy, VIR_DOMAIN_STARTUP_POLICY_LAST,
              "default",
              "mandatory",
              "requisite",
              "optional");

VIR_ENUM_IMPL(virDomainCpuPlacementMode, VIR_DOMAIN_CPU_PLACEMENT_MODE_LAST,
              "static",
              "auto");

VIR_ENUM_IMPL(virDomainDiskTray, VIR_DOMAIN_DISK_TRAY_LAST,
              "closed",
              "open");

VIR_ENUM_IMPL(virDomainRNGModel,
              VIR_DOMAIN_RNG_MODEL_LAST,
              "virtio");

VIR_ENUM_IMPL(virDomainRNGBackend,
              VIR_DOMAIN_RNG_BACKEND_LAST,
              "random",
              "egd");

VIR_ENUM_IMPL(virDomainTPMModel, VIR_DOMAIN_TPM_MODEL_LAST,
              "tpm-tis")

VIR_ENUM_IMPL(virDomainTPMBackend, VIR_DOMAIN_TPM_TYPE_LAST,
              "passthrough")

VIR_ENUM_IMPL(virDomainIOMMUModel, VIR_DOMAIN_IOMMU_MODEL_LAST,
              "intel")

VIR_ENUM_IMPL(virDomainDiskDiscard, VIR_DOMAIN_DISK_DISCARD_LAST,
              "default",
              "unmap",
              "ignore")

VIR_ENUM_IMPL(virDomainDiskDetectZeroes, VIR_DOMAIN_DISK_DETECT_ZEROES_LAST,
              "default",
              "off",
              "on",
              "unmap")

VIR_ENUM_IMPL(virDomainDiskMirrorState, VIR_DOMAIN_DISK_MIRROR_STATE_LAST,
              "none",
              "yes",
              "abort",
              "pivot")

VIR_ENUM_IMPL(virDomainMemorySource, VIR_DOMAIN_MEMORY_SOURCE_LAST,
              "none",
              "file",
              "anonymous")

VIR_ENUM_IMPL(virDomainMemoryAllocation, VIR_DOMAIN_MEMORY_ALLOCATION_LAST,
              "none",
              "immediate",
              "ondemand")

VIR_ENUM_IMPL(virDomainLoader,
              VIR_DOMAIN_LOADER_TYPE_LAST,
              "rom",
              "pflash")

VIR_ENUM_IMPL(virDomainIOAPIC,
              VIR_DOMAIN_IOAPIC_LAST,
              "qemu",
              "kvm")

/* Internal mapping: subset of block job types that can be present in
 * <mirror> XML (remaining types are not two-phase). */
VIR_ENUM_DECL(virDomainBlockJob)
VIR_ENUM_IMPL(virDomainBlockJob, VIR_DOMAIN_BLOCK_JOB_TYPE_LAST,
              "", "", "copy", "", "active-commit")

VIR_ENUM_IMPL(virDomainMemoryModel,
              VIR_DOMAIN_MEMORY_MODEL_LAST,
              "",
              "dimm",
              "nvdimm")

VIR_ENUM_IMPL(virDomainShmemModel, VIR_DOMAIN_SHMEM_MODEL_LAST,
              "ivshmem",
              "ivshmem-plain",
              "ivshmem-doorbell")

static virClassPtr virDomainObjClass;
static virClassPtr virDomainXMLOptionClass;
static void virDomainObjDispose(void *obj);
static void virDomainXMLOptionClassDispose(void *obj);

static int virDomainObjOnceInit(void)
{
    if (!(virDomainObjClass = virClassNew(virClassForObjectLockable(),
                                          "virDomainObj",
                                          sizeof(virDomainObj),
                                          virDomainObjDispose)))
        return -1;

    if (!(virDomainXMLOptionClass = virClassNew(virClassForObject(),
                                                "virDomainXMLOption",
                                                sizeof(virDomainXMLOption),
                                                virDomainXMLOptionClassDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainObj)


static void
virDomainXMLOptionClassDispose(void *obj)
{
    virDomainXMLOptionPtr xmlopt = obj;

    if (xmlopt->config.privFree)
        (xmlopt->config.privFree)(xmlopt->config.priv);
}

/**
 * virDomainKeyWrapCipherDefParseXML:
 *
 * @def  Domain definition
 * @node An XML cipher node
 * @ctxt The XML context
 *
 * Parse the attributes from the cipher node and store the state
 * attribute in @def.
 *
 * A cipher node has the form of
 *
 *   <cipher name='aes|dea' state='on|off'/>
 *
 * Returns: 0 if the parse succeeded
 *         -1 otherwise
 */
static int
virDomainKeyWrapCipherDefParseXML(virDomainKeyWrapDefPtr keywrap,
                                  xmlNodePtr node,
                                  xmlXPathContextPtr ctxt)
{

    char *name = NULL;
    char *state = NULL;
    int state_type;
    int name_type;
    int ret = -1;
    xmlNodePtr oldnode = ctxt->node;

    ctxt->node = node;
    if (!(name = virXPathString("string(./@name)", ctxt))) {
        virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                       _("missing name for cipher"));
        goto cleanup;
    }

    if ((name_type = virDomainKeyWrapCipherNameTypeFromString(name)) < 0) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s is not a supported cipher name"), name);
        goto cleanup;
    }

    if (!(state = virXPathString("string(./@state)", ctxt))) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("missing state for cipher named %s"), name);
        goto cleanup;
    }

    if ((state_type = virTristateSwitchTypeFromString(state)) < 0) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s is not a supported cipher state"), state);
        goto cleanup;
    }

    switch ((virDomainKeyWrapCipherName) name_type) {
    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_AES:
        if (keywrap->aes != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("A domain definition can have no more than "
                             "one cipher node with name %s"),
                           virDomainKeyWrapCipherNameTypeToString(name_type));

            goto cleanup;
        }
        keywrap->aes = state_type;
        break;

    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_DEA:
        if (keywrap->dea != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("A domain definition can have no more than "
                             "one cipher node with name %s"),
                           virDomainKeyWrapCipherNameTypeToString(name_type));

            goto cleanup;
        }
        keywrap->dea = state_type;
        break;

    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_LAST:
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(name);
    VIR_FREE(state);
    ctxt->node = oldnode;
    return ret;
}

static int
virDomainKeyWrapDefParseXML(virDomainDefPtr def, xmlXPathContextPtr ctxt)
{
    size_t i;
    int ret = -1;
    xmlNodePtr *nodes = NULL;
    int n;

    if ((n = virXPathNodeSet("./keywrap/cipher", ctxt, &nodes)) < 0)
        return n;

    if (VIR_ALLOC(def->keywrap) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        if (virDomainKeyWrapCipherDefParseXML(def->keywrap, nodes[i], ctxt) < 0)
            goto cleanup;
    }

    if (!def->keywrap->aes &&
        !def->keywrap->dea)
        VIR_FREE(def->keywrap);

    ret = 0;

 cleanup:
    if (ret < 0)
        VIR_FREE(def->keywrap);
    VIR_FREE(nodes);
    return ret;
}


/**
 * virDomainXMLOptionNew:
 *
 * Allocate a new domain XML configuration
 */
virDomainXMLOptionPtr
virDomainXMLOptionNew(virDomainDefParserConfigPtr config,
                      virDomainXMLPrivateDataCallbacksPtr priv,
                      virDomainXMLNamespacePtr xmlns,
                      virDomainABIStabilityPtr abi,
                      virSaveCookieCallbacksPtr saveCookie)
{
    virDomainXMLOptionPtr xmlopt;

    if (virDomainObjInitialize() < 0)
        return NULL;

    if (!(xmlopt = virObjectNew(virDomainXMLOptionClass)))
        return NULL;

    if (priv)
        xmlopt->privateData = *priv;

    if (config)
        xmlopt->config = *config;

    if (xmlns)
        xmlopt->ns = *xmlns;

    if (abi)
        xmlopt->abi = *abi;

    if (saveCookie)
        xmlopt->saveCookie = *saveCookie;

    /* Technically this forbids to use one of Xerox's MAC address prefixes in
     * our hypervisor drivers. This shouldn't ever be a problem.
     *
     * Use the KVM prefix as default as it's in the privately administered
     * range */
    if (xmlopt->config.macPrefix[0] == 0 &&
        xmlopt->config.macPrefix[1] == 0 &&
        xmlopt->config.macPrefix[2] == 0) {
        xmlopt->config.macPrefix[0] = 0x52;
        xmlopt->config.macPrefix[1] = 0x54;
    }

    return xmlopt;
}

/**
 * virDomainXMLOptionGetNamespace:
 *
 * @xmlopt: XML parser configuration object
 *
 * Returns a pointer to the stored namespace structure.
 * The lifetime of the pointer is equal to @xmlopt;
 */
virDomainXMLNamespacePtr
virDomainXMLOptionGetNamespace(virDomainXMLOptionPtr xmlopt)
{
    return &xmlopt->ns;
}

static int
virDomainVirtioOptionsParseXML(xmlXPathContextPtr ctxt,
                               virDomainVirtioOptionsPtr *virtio)
{
    char *str = NULL;
    int ret = -1;
    int val;
    virDomainVirtioOptionsPtr res;

    if (VIR_ALLOC(*virtio) < 0)
        return -1;

    res = *virtio;

    if ((str = virXPathString("string(./driver/@iommu)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid iommu value"));
            goto cleanup;
        }
        res->iommu = val;
    }
    VIR_FREE(str);

    if ((str = virXPathString("string(./driver/@ats)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid ats value"));
            goto cleanup;
        }
        res->ats = val;
    }

    ret = 0;

 cleanup:
    VIR_FREE(str);
    return ret;
}


virSaveCookieCallbacksPtr
virDomainXMLOptionGetSaveCookie(virDomainXMLOptionPtr xmlopt)
{
    return &xmlopt->saveCookie;
}


void
virBlkioDeviceArrayClear(virBlkioDevicePtr devices,
                         int ndevices)
{
    size_t i;

    for (i = 0; i < ndevices; i++)
        VIR_FREE(devices[i].path);
}

/**
 * virDomainBlkioDeviceParseXML
 *
 * this function parses a XML node:
 *
 *   <device>
 *     <path>/fully/qualified/device/path</path>
 *     <weight>weight</weight>
 *     <read_bytes_sec>bps</read_bytes_sec>
 *     <write_bytes_sec>bps</write_bytes_sec>
 *     <read_iops_sec>iops</read_iops_sec>
 *     <write_iops_sec>iops</write_iops_sec>
 *   </device>
 *
 * and fills a virBlkioDevicePtr struct.
 */
static int
virDomainBlkioDeviceParseXML(xmlNodePtr root,
                             virBlkioDevicePtr dev)
{
    char *c = NULL;
    xmlNodePtr node;

    node = root->children;
    while (node) {
        if (node->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(node->name, BAD_CAST "path") && !dev->path) {
                dev->path = (char *)xmlNodeGetContent(node);
            } else if (xmlStrEqual(node->name, BAD_CAST "weight")) {
                c = (char *)xmlNodeGetContent(node);
                if (virStrToLong_ui(c, NULL, 10, &dev->weight) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("could not parse weight %s"),
                                   c);
                        goto error;
                }
                VIR_FREE(c);
            } else if (xmlStrEqual(node->name, BAD_CAST "read_bytes_sec")) {
                c = (char *)xmlNodeGetContent(node);
                if (virStrToLong_ull(c, NULL, 10, &dev->rbps) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("could not parse read bytes sec %s"),
                                   c);
                    goto error;
                }
                VIR_FREE(c);
            } else if (xmlStrEqual(node->name, BAD_CAST "write_bytes_sec")) {
                c = (char *)xmlNodeGetContent(node);
                if (virStrToLong_ull(c, NULL, 10, &dev->wbps) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("could not parse write bytes sec %s"),
                                   c);
                    goto error;
                }
                VIR_FREE(c);
            } else if (xmlStrEqual(node->name, BAD_CAST "read_iops_sec")) {
                c = (char *)xmlNodeGetContent(node);
                if (virStrToLong_ui(c, NULL, 10, &dev->riops) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("could not parse read iops sec %s"),
                                   c);
                    goto error;
                }
                VIR_FREE(c);
            } else if (xmlStrEqual(node->name, BAD_CAST "write_iops_sec")) {
                c = (char *)xmlNodeGetContent(node);
                if (virStrToLong_ui(c, NULL, 10, &dev->wiops) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("could not parse write iops sec %s"),
                                   c);
                    goto error;
                }
                VIR_FREE(c);
            }
        }
        node = node->next;
    }
    if (!dev->path) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing per-device path"));
        return -1;
    }

    return 0;

 error:
    VIR_FREE(c);
    VIR_FREE(dev->path);
    return -1;
}


/**
 * virDomainDefCheckUnsupportedMemoryHotplug:
 * @def: domain definition
 *
 * Returns -1 if the domain definition would enable memory hotplug via the
 * <maxMemory> tunable and reports an error. Otherwise returns 0.
 */
static int
virDomainDefCheckUnsupportedMemoryHotplug(virDomainDefPtr def)
{
    /* memory hotplug tunables are not supported by this driver */
    if (virDomainDefHasMemoryHotplug(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory hotplug tunables <maxMemory> are not "
                         "supported by this hypervisor driver"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDeviceDefCheckUnsupportedMemoryDevice:
 * @dev: device definition
 *
 * Returns -1 if the device definition describes a memory device and reports an
 * error. Otherwise returns 0.
 */
static int
virDomainDeviceDefCheckUnsupportedMemoryDevice(virDomainDeviceDefPtr dev)
{
    /* This driver doesn't yet know how to handle memory devices */
    if (dev->type == VIR_DOMAIN_DEVICE_MEMORY) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory devices are not supported by this driver"));
        return -1;
    }

    return 0;
}


bool virDomainObjTaint(virDomainObjPtr obj,
                       virDomainTaintFlags taint)
{
    unsigned int flag = (1 << taint);

    if (obj->taint & flag)
        return false;

    obj->taint |= flag;
    return true;
}

static void
virDomainDeviceInfoFree(virDomainDeviceInfoPtr info)
{
    if (info) {
        virDomainDeviceInfoClear(info);
        VIR_FREE(info);
    }
}


static void
virDomainGraphicsAuthDefClear(virDomainGraphicsAuthDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->passwd);

    /* Don't free def */
}

static void
virDomainGraphicsListenDefClear(virDomainGraphicsListenDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->address);
    VIR_FREE(def->network);
    VIR_FREE(def->socket);
    return;
}


void virDomainGraphicsDefFree(virDomainGraphicsDefPtr def)
{
    size_t i;

    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        VIR_FREE(def->data.vnc.keymap);
        virDomainGraphicsAuthDefClear(&def->data.vnc.auth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        VIR_FREE(def->data.sdl.display);
        VIR_FREE(def->data.sdl.xauth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        VIR_FREE(def->data.desktop.display);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        VIR_FREE(def->data.spice.rendernode);
        VIR_FREE(def->data.spice.keymap);
        virDomainGraphicsAuthDefClear(&def->data.spice.auth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    for (i = 0; i < def->nListens; i++)
        virDomainGraphicsListenDefClear(&def->listens[i]);
    VIR_FREE(def->listens);

    VIR_FREE(def);
}

void virDomainInputDefFree(virDomainInputDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def->source.evdev);
    VIR_FREE(def);
}

void virDomainLeaseDefFree(virDomainLeaseDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->lockspace);
    VIR_FREE(def->key);
    VIR_FREE(def->path);

    VIR_FREE(def);
}


static virDomainVcpuDefPtr
virDomainVcpuDefNew(virDomainXMLOptionPtr xmlopt)
{
    virObjectPtr priv = NULL;
    virDomainVcpuDefPtr ret = NULL;

    if (xmlopt && xmlopt->privateData.vcpuNew &&
        !(priv = xmlopt->privateData.vcpuNew()))
        goto cleanup;

    if (VIR_ALLOC(ret) < 0)
        goto cleanup;

    ret->privateData = priv;
    priv = NULL;

 cleanup:
    virObjectUnref(priv);
    return ret;
}


static void
virDomainVcpuDefFree(virDomainVcpuDefPtr info)
{
    if (!info)
        return;

    virBitmapFree(info->cpumask);
    info->cpumask = NULL;
    virObjectUnref(info->privateData);
    VIR_FREE(info);
}


int
virDomainDefSetVcpusMax(virDomainDefPtr def,
                        unsigned int maxvcpus,
                        virDomainXMLOptionPtr xmlopt)
{
    size_t oldmax = def->maxvcpus;
    size_t i;

    if (def->maxvcpus == maxvcpus)
        return 0;

    if (def->maxvcpus < maxvcpus) {
        if (VIR_EXPAND_N(def->vcpus, def->maxvcpus, maxvcpus - def->maxvcpus) < 0)
            return -1;

        for (i = oldmax; i < def->maxvcpus; i++) {
            if (!(def->vcpus[i] = virDomainVcpuDefNew(xmlopt)))
                return -1;
        }
    } else {
        for (i = maxvcpus; i < def->maxvcpus; i++)
            virDomainVcpuDefFree(def->vcpus[i]);

        VIR_SHRINK_N(def->vcpus, def->maxvcpus, def->maxvcpus - maxvcpus);
    }

    return 0;
}


bool
virDomainDefHasVcpusOffline(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->maxvcpus; i++) {
        if (!def->vcpus[i]->online)
            return true;
    }

    return false;
}


unsigned int
virDomainDefGetVcpusMax(const virDomainDef *def)
{
    return def->maxvcpus;
}


int
virDomainDefSetVcpus(virDomainDefPtr def,
                     unsigned int vcpus)
{
    size_t i;

    if (vcpus > def->maxvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("maxvcpus must not be less than current vcpus (%u < %zu)"),
                       vcpus, def->maxvcpus);
        return -1;
    }

    for (i = 0; i < vcpus; i++)
        def->vcpus[i]->online = true;

    for (i = vcpus; i < def->maxvcpus; i++)
        def->vcpus[i]->online = false;

    return 0;
}


unsigned int
virDomainDefGetVcpus(const virDomainDef *def)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < def->maxvcpus; i++) {
        if (def->vcpus[i]->online)
            ret++;
    }

    return ret;
}


/**
 * virDomainDefGetOnlineVcpumap:
 * @def: domain definition
 *
 * Returns a bitmap representing state of individual vcpus.
 */
virBitmapPtr
virDomainDefGetOnlineVcpumap(const virDomainDef *def)
{
    virBitmapPtr ret = NULL;
    size_t i;

    if (!(ret = virBitmapNew(def->maxvcpus)))
        return NULL;

    for (i = 0; i < def->maxvcpus; i++) {
        if (def->vcpus[i]->online)
            ignore_value(virBitmapSetBit(ret, i));
    }

    return ret;
}


virDomainVcpuDefPtr
virDomainDefGetVcpu(virDomainDefPtr def,
                    unsigned int vcpu)
{
    if (vcpu >= def->maxvcpus)
        return NULL;

    return def->vcpus[vcpu];
}


static virDomainThreadSchedParamPtr
virDomainDefGetVcpuSched(virDomainDefPtr def,
                         unsigned int vcpu)
{
    virDomainVcpuDefPtr vcpuinfo;

    if (!(vcpuinfo = virDomainDefGetVcpu(def, vcpu))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vCPU '%u' is not present in domain definition"),
                       vcpu);
        return NULL;
    }

    return &vcpuinfo->sched;
}


/**
 * virDomainDefHasVcpuPin:
 * @def: domain definition
 *
 * This helper returns true if any of the domain's vcpus has cpu pinning set
 */
static bool
virDomainDefHasVcpuPin(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->maxvcpus; i++) {
        if (def->vcpus[i]->cpumask)
            return true;
    }

    return false;
}


/**
 * virDomainDefGetVcpuPinInfoHelper:
 * @def: domain definition
 * @maplen: length of one cpumap passed from caller (@cpumaps)
 * @ncpumaps: count of cpumaps of @maplen length in @cpumaps
 * @cpumaps: array of pinning information bitmaps to be filled
 * @hostcpus: number of cpus in the host
 * @autoCpuset: Cpu pinning bitmap used in case of automatic cpu pinning
 *
 * Fills the @cpumaps array as documented by the virDomainGetVcpuPinInfo API.
 * In case when automatic cpu pinning is supported, the bitmap should be passed
 * as @autoCpuset. If @hostcpus is < 0 no error is reported (to pass through
 * error message).
 *
 * Returns number of filled entries or -1 on error.
 */
int
virDomainDefGetVcpuPinInfoHelper(virDomainDefPtr def,
                                 int maplen,
                                 int ncpumaps,
                                 unsigned char *cpumaps,
                                 int hostcpus,
                                 virBitmapPtr autoCpuset)
{
    int maxvcpus = virDomainDefGetVcpusMax(def);
    virBitmapPtr allcpumap = NULL;
    size_t i;

    if (hostcpus < 0)
        return -1;

    if (!(allcpumap = virBitmapNew(hostcpus)))
        return -1;

    virBitmapSetAll(allcpumap);

    for (i = 0; i < maxvcpus && i < ncpumaps; i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(def, i);
        virBitmapPtr bitmap = NULL;

        if (vcpu && vcpu->cpumask)
            bitmap = vcpu->cpumask;
        else if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
                 autoCpuset)
            bitmap = autoCpuset;
        else if (def->cpumask)
            bitmap = def->cpumask;
        else
            bitmap = allcpumap;

        virBitmapToDataBuf(bitmap, VIR_GET_CPUMAP(cpumaps, maplen, i), maplen);
    }

    virBitmapFree(allcpumap);
    return i;
}


/**
 * virDomainDeGetVcpusTopology:
 * @def: domain definition
 * @maxvcpus: optionally filled with number of vcpus the domain topology describes
 *
 * Calculates and validates that the vcpu topology is in sane bounds and
 * optionally returns the total number of vcpus described by given topology.
 *
 * Returns 0 on success, 1 if topology is not configured and -1 on error.
 */
int
virDomainDefGetVcpusTopology(const virDomainDef *def,
                             unsigned int *maxvcpus)
{
    unsigned long long tmp;

    if (!def->cpu || def->cpu->sockets == 0)
        return 1;

    tmp = def->cpu->sockets;

    /* multiplication of 32bit numbers fits into a 64bit variable */
    if ((tmp *= def->cpu->cores) > UINT_MAX ||
        (tmp *= def->cpu->threads) > UINT_MAX) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cpu topology results in more than %u cpus"), UINT_MAX);
        return -1;
    }

    if (maxvcpus)
        *maxvcpus = tmp;

    return 0;
}


virDomainDiskDefPtr
virDomainDiskDefNew(virDomainXMLOptionPtr xmlopt)
{
    virDomainDiskDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_ALLOC(ret->src) < 0)
        goto error;

    if (xmlopt &&
        xmlopt->privateData.diskNew &&
        !(ret->privateData = xmlopt->privateData.diskNew()))
        goto error;

    return ret;

 error:
    virDomainDiskDefFree(ret);
    return NULL;
}


void
virDomainDiskDefFree(virDomainDiskDefPtr def)
{
    if (!def)
        return;

    virStorageSourceFree(def->src);
    VIR_FREE(def->serial);
    VIR_FREE(def->dst);
    virStorageSourceFree(def->mirror);
    VIR_FREE(def->wwn);
    VIR_FREE(def->vendor);
    VIR_FREE(def->product);
    VIR_FREE(def->domain_name);
    VIR_FREE(def->blkdeviotune.group_name);
    VIR_FREE(def->virtio);
    virDomainDeviceInfoClear(&def->info);
    virObjectUnref(def->privateData);

    VIR_FREE(def);
}


int
virDomainDiskGetType(virDomainDiskDefPtr def)
{
    return def->src->type;
}


void
virDomainDiskSetType(virDomainDiskDefPtr def, int type)
{
    def->src->type = type;
}


const char *
virDomainDiskGetSource(virDomainDiskDef const *def)
{
    return def->src->path;
}


int
virDomainDiskSetSource(virDomainDiskDefPtr def, const char *src)
{
    int ret;
    char *tmp = def->src->path;

    ret = VIR_STRDUP(def->src->path, src);
    if (ret < 0)
        def->src->path = tmp;
    else
        VIR_FREE(tmp);
    return ret;
}


void
virDomainDiskEmptySource(virDomainDiskDefPtr def)
{
    virStorageSourcePtr src = def->src;
    bool readonly = src->readonly;

    virStorageSourceClear(src);
    src->type = VIR_STORAGE_TYPE_FILE;
    /* readonly property is necessary for CDROMs and thus can't be cleared */
    src->readonly = readonly;
}


const char *
virDomainDiskGetDriver(virDomainDiskDefPtr def)
{
    return def->src->driverName;
}


int
virDomainDiskSetDriver(virDomainDiskDefPtr def, const char *name)
{
    int ret;
    char *tmp = def->src->driverName;

    ret = VIR_STRDUP(def->src->driverName, name);
    if (ret < 0)
        def->src->driverName = tmp;
    else
        VIR_FREE(tmp);
    return ret;
}


int
virDomainDiskGetFormat(virDomainDiskDefPtr def)
{
    return def->src->format;
}


void
virDomainDiskSetFormat(virDomainDiskDefPtr def, int format)
{
    def->src->format = format;
}


virDomainControllerDefPtr
virDomainControllerDefNew(virDomainControllerType type)
{
    virDomainControllerDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->type = type;

    /* initialize anything that has a non-0 default */
    def->model = -1;
    def->idx = -1;

    switch ((virDomainControllerType) def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        def->opts.vioserial.ports = -1;
        def->opts.vioserial.vectors = -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        def->opts.usbopts.ports = -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        def->opts.pciopts.chassisNr = -1;
        def->opts.pciopts.chassis = -1;
        def->opts.pciopts.port = -1;
        def->opts.pciopts.busNr = -1;
        def->opts.pciopts.numaNode = -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        break;
    }

    return def;
}


void virDomainControllerDefFree(virDomainControllerDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def->virtio);

    VIR_FREE(def);
}

virDomainFSDefPtr
virDomainFSDefNew(void)
{
    virDomainFSDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_ALLOC(ret->src) < 0)
        goto cleanup;

    return ret;

 cleanup:
    virDomainFSDefFree(ret);
    return NULL;

}

void virDomainFSDefFree(virDomainFSDefPtr def)
{
    if (!def)
        return;

    virStorageSourceFree(def->src);
    VIR_FREE(def->dst);
    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def->virtio);

    VIR_FREE(def);
}

void
virDomainActualNetDefFree(virDomainActualNetDefPtr def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        VIR_FREE(def->data.bridge.brname);
        break;
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        VIR_FREE(def->data.direct.linkdev);
        break;
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        virDomainHostdevDefClear(&def->data.hostdev.def);
        break;
    default:
        break;
    }

    VIR_FREE(def->virtPortProfile);
    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    VIR_FREE(def);
}

void
virDomainNetDefClear(virDomainNetDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->model);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        virDomainChrSourceDefFree(def->data.vhostuser);
        def->data.vhostuser = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
        VIR_FREE(def->data.socket.address);
        VIR_FREE(def->data.socket.localaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
        VIR_FREE(def->data.network.name);
        VIR_FREE(def->data.network.portgroup);
        virDomainActualNetDefFree(def->data.network.actual);
        def->data.network.actual = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        VIR_FREE(def->data.bridge.brname);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        VIR_FREE(def->data.internal.name);
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        VIR_FREE(def->data.direct.linkdev);
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        virDomainHostdevDefClear(&def->data.hostdev.def);
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    VIR_FREE(def->backend.tap);
    VIR_FREE(def->backend.vhost);
    VIR_FREE(def->virtPortProfile);
    VIR_FREE(def->script);
    VIR_FREE(def->domain_name);
    VIR_FREE(def->ifname);
    VIR_FREE(def->ifname_guest);
    VIR_FREE(def->ifname_guest_actual);
    VIR_FREE(def->virtio);

    virNetDevIPInfoClear(&def->guestIP);
    virNetDevIPInfoClear(&def->hostIP);
    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def->filter);
    virNWFilterHashTableFree(def->filterparams);
    def->filterparams = NULL;

    virNetDevBandwidthFree(def->bandwidth);
    def->bandwidth = NULL;
    virNetDevVlanClear(&def->vlan);
}

void
virDomainNetDefFree(virDomainNetDefPtr def)
{
    if (!def)
        return;
    virDomainNetDefClear(def);
    VIR_FREE(def);
}

void ATTRIBUTE_NONNULL(1)
virDomainChrSourceDefClear(virDomainChrSourceDefPtr def)
{
    switch (def->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        VIR_FREE(def->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        VIR_FREE(def->data.nmdm.master);
        VIR_FREE(def->data.nmdm.slave);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        VIR_FREE(def->data.udp.bindHost);
        VIR_FREE(def->data.udp.bindService);
        VIR_FREE(def->data.udp.connectHost);
        VIR_FREE(def->data.udp.connectService);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        VIR_FREE(def->data.tcp.host);
        VIR_FREE(def->data.tcp.service);
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        VIR_FREE(def->data.nix.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        VIR_FREE(def->data.spiceport.channel);
        break;
    }

    VIR_FREE(def->logfile);
}

/* Deep copies the contents of src into dest.  Return -1 and report
 * error on failure.  */
int
virDomainChrSourceDefCopy(virDomainChrSourceDefPtr dest,
                          virDomainChrSourceDefPtr src)
{
    if (!dest || !src)
        return -1;

    virDomainChrSourceDefClear(dest);

    switch (src->type) {
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (src->type == VIR_DOMAIN_CHR_TYPE_FILE)
            dest->data.file.append = src->data.file.append;
        if (VIR_STRDUP(dest->data.file.path, src->data.file.path) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (VIR_STRDUP(dest->data.udp.bindHost, src->data.udp.bindHost) < 0)
            return -1;

        if (VIR_STRDUP(dest->data.udp.bindService, src->data.udp.bindService) < 0)
            return -1;

        if (VIR_STRDUP(dest->data.udp.connectHost, src->data.udp.connectHost) < 0)
            return -1;

        if (VIR_STRDUP(dest->data.udp.connectService, src->data.udp.connectService) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (VIR_STRDUP(dest->data.tcp.host, src->data.tcp.host) < 0)
            return -1;

        if (VIR_STRDUP(dest->data.tcp.service, src->data.tcp.service) < 0)
            return -1;

        dest->data.tcp.haveTLS = src->data.tcp.haveTLS;
        dest->data.tcp.tlsFromConfig = src->data.tcp.tlsFromConfig;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (VIR_STRDUP(dest->data.nix.path, src->data.nix.path) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        if (VIR_STRDUP(dest->data.nmdm.master, src->data.nmdm.master) < 0)
            return -1;
        if (VIR_STRDUP(dest->data.nmdm.slave, src->data.nmdm.slave) < 0)
            return -1;

        break;
    }

    dest->type = src->type;

    return 0;
}

void virDomainChrSourceDefFree(virDomainChrSourceDefPtr def)
{
    if (!def)
        return;

    virDomainChrSourceDefClear(def);
    virObjectUnref(def->privateData);

    VIR_FREE(def);
}

/* virDomainChrSourceDefIsEqual:
 * @src: Source
 * @tgt: Target
 *
 * Compares source and target if they contain
 * the same information.
 */
static bool
virDomainChrSourceDefIsEqual(const virDomainChrSourceDef *src,
                             const virDomainChrSourceDef *tgt)
{
    if (tgt->type != src->type)
        return false;

    switch ((virDomainChrType)src->type) {
    case VIR_DOMAIN_CHR_TYPE_FILE:
        return src->data.file.append == tgt->data.file.append &&
            STREQ_NULLABLE(src->data.file.path, tgt->data.file.path);
        break;
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        return STREQ_NULLABLE(src->data.file.path, tgt->data.file.path);
        break;
    case VIR_DOMAIN_CHR_TYPE_NMDM:
        return STREQ_NULLABLE(src->data.nmdm.master, tgt->data.nmdm.master) &&
            STREQ_NULLABLE(src->data.nmdm.slave, tgt->data.nmdm.slave);
        break;
    case VIR_DOMAIN_CHR_TYPE_UDP:
        return STREQ_NULLABLE(src->data.udp.bindHost, tgt->data.udp.bindHost) &&
            STREQ_NULLABLE(src->data.udp.bindService, tgt->data.udp.bindService) &&
            STREQ_NULLABLE(src->data.udp.connectHost, tgt->data.udp.connectHost) &&
            STREQ_NULLABLE(src->data.udp.connectService, tgt->data.udp.connectService);
        break;
    case VIR_DOMAIN_CHR_TYPE_TCP:
        return src->data.tcp.listen == tgt->data.tcp.listen &&
            src->data.tcp.protocol == tgt->data.tcp.protocol &&
            STREQ_NULLABLE(src->data.tcp.host, tgt->data.tcp.host) &&
            STREQ_NULLABLE(src->data.tcp.service, tgt->data.tcp.service);
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        return src->data.nix.listen == tgt->data.nix.listen &&
            STREQ_NULLABLE(src->data.nix.path, tgt->data.nix.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        return STREQ_NULLABLE(src->data.spiceport.channel,
                              tgt->data.spiceport.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        return src->data.spicevmc == tgt->data.spicevmc;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    return true;
}

void virDomainChrDefFree(virDomainChrDefPtr def)
{
    size_t i;

    if (!def)
        return;

    switch (def->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        switch (def->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            VIR_FREE(def->target.addr);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            VIR_FREE(def->target.name);
            break;
        }
        break;

    default:
        break;
    }

    virDomainChrSourceDefFree(def->source);
    virDomainDeviceInfoClear(&def->info);

    if (def->seclabels) {
        for (i = 0; i < def->nseclabels; i++)
            virSecurityDeviceLabelDefFree(def->seclabels[i]);
        VIR_FREE(def->seclabels);
    }

    VIR_FREE(def);
}

void virDomainSmartcardDefFree(virDomainSmartcardDefPtr def)
{
    size_t i;
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        for (i = 0; i < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; i++)
            VIR_FREE(def->data.cert.file[i]);
        VIR_FREE(def->data.cert.database);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        virDomainChrSourceDefFree(def->data.passthru);
        break;

    default:
        break;
    }

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainSoundCodecDefFree(virDomainSoundCodecDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def);
}

void virDomainSoundDefFree(virDomainSoundDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    size_t i;
    for (i = 0; i < def->ncodecs; i++)
        virDomainSoundCodecDefFree(def->codecs[i]);
    VIR_FREE(def->codecs);

    VIR_FREE(def);
}

void virDomainMemballoonDefFree(virDomainMemballoonDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def->virtio);

    VIR_FREE(def);
}

void virDomainNVRAMDefFree(virDomainNVRAMDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainWatchdogDefFree(virDomainWatchdogDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainShmemDefFree(virDomainShmemDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    virDomainChrSourceDefClear(&def->server.chr);
    VIR_FREE(def->name);
    VIR_FREE(def);
}

void virDomainVideoDefFree(virDomainVideoDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def->accel);
    VIR_FREE(def->virtio);
    VIR_FREE(def);
}


virDomainHostdevDefPtr
virDomainHostdevDefAlloc(virDomainXMLOptionPtr xmlopt)
{
    virDomainHostdevDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0 ||
        VIR_ALLOC(def->info) < 0) {
        VIR_FREE(def);
        return NULL;
    }

    if (xmlopt &&
        xmlopt->privateData.hostdevNew &&
        !(def->privateData = xmlopt->privateData.hostdevNew()))
        goto error;

    return def;

 error:
    VIR_FREE(def->info);
    VIR_FREE(def);
    return NULL;
}


static void
virDomainHostdevSubsysSCSIiSCSIClear(virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc)
{
    if (!iscsisrc)
        return;
    VIR_FREE(iscsisrc->path);
    virStorageNetHostDefFree(iscsisrc->nhosts, iscsisrc->hosts);
    virStorageAuthDefFree(iscsisrc->auth);
    iscsisrc->auth = NULL;
}


static void
virDomainHostdevSubsysSCSIClear(virDomainHostdevSubsysSCSIPtr scsisrc)
{
    if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        virDomainHostdevSubsysSCSIiSCSIClear(&scsisrc->u.iscsi);
    else
        VIR_FREE(scsisrc->u.host.adapter);
}


void virDomainHostdevDefClear(virDomainHostdevDefPtr def)
{
    if (!def)
        return;

    /* Free all resources in the hostdevdef. Currently the only
     * such resource is the virDomainDeviceInfo.
     */

    /* If there is a parent device object, it will handle freeing
     * def->info.
     */
    if (def->parent.type == VIR_DOMAIN_DEVICE_NONE)
        virDomainDeviceInfoFree(def->info);

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        switch ((virDomainHostdevCapsType) def->source.caps.type) {
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
            VIR_FREE(def->source.caps.u.storage.block);
            break;
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
            VIR_FREE(def->source.caps.u.misc.chardev);
            break;
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
            VIR_FREE(def->source.caps.u.net.ifname);
            virNetDevIPInfoClear(&def->source.caps.u.net.ip);
            break;
        case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
            break;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        switch ((virDomainHostdevSubsysType) def->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            virDomainHostdevSubsysSCSIClear(&def->source.subsys.u.scsi);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            VIR_FREE(def->source.subsys.u.scsi_host.wwpn);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
        break;
    }

    virObjectUnref(def->privateData);
    def->privateData = NULL;
}

void virDomainTPMDefFree(virDomainTPMDefPtr def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        VIR_FREE(def->data.passthrough.source.data.file.path);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def);
}

void virDomainHostdevDefFree(virDomainHostdevDefPtr def)
{
    if (!def)
        return;

    /* free all subordinate objects */
    virDomainHostdevDefClear(def);

    /* If there is a parent device object, it will handle freeing
     * the memory.
     */
    if (def->parent.type == VIR_DOMAIN_DEVICE_NONE)
        VIR_FREE(def);
}

void virDomainHubDefFree(virDomainHubDefPtr def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def);
}

void virDomainRedirdevDefFree(virDomainRedirdevDefPtr def)
{
    if (!def)
        return;

    virDomainChrSourceDefFree(def->source);
    virDomainDeviceInfoClear(&def->info);

    VIR_FREE(def);
}

void virDomainRedirFilterDefFree(virDomainRedirFilterDefPtr def)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < def->nusbdevs; i++)
        VIR_FREE(def->usbdevs[i]);

    VIR_FREE(def->usbdevs);
    VIR_FREE(def);
}

void virDomainMemoryDefFree(virDomainMemoryDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->nvdimmPath);
    virBitmapFree(def->sourceNodes);
    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def);
}

void virDomainDeviceDefFree(virDomainDeviceDefPtr def)
{
    if (!def)
        return;

    switch ((virDomainDeviceType) def->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        virDomainDiskDefFree(def->data.disk);
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        virDomainLeaseDefFree(def->data.lease);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        virDomainNetDefFree(def->data.net);
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        virDomainInputDefFree(def->data.input);
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        virDomainSoundDefFree(def->data.sound);
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        virDomainVideoDefFree(def->data.video);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        virDomainHostdevDefFree(def->data.hostdev);
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        virDomainWatchdogDefFree(def->data.watchdog);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        virDomainControllerDefFree(def->data.controller);
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        virDomainGraphicsDefFree(def->data.graphics);
        break;
    case VIR_DOMAIN_DEVICE_HUB:
        virDomainHubDefFree(def->data.hub);
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        virDomainRedirdevDefFree(def->data.redirdev);
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        virDomainRNGDefFree(def->data.rng);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        virDomainChrDefFree(def->data.chr);
        break;
    case VIR_DOMAIN_DEVICE_FS:
        virDomainFSDefFree(def->data.fs);
        break;
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        virDomainSmartcardDefFree(def->data.smartcard);
        break;
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        virDomainMemballoonDefFree(def->data.memballoon);
        break;
    case VIR_DOMAIN_DEVICE_NVRAM:
        virDomainNVRAMDefFree(def->data.nvram);
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        virDomainShmemDefFree(def->data.shmem);
        break;
    case VIR_DOMAIN_DEVICE_TPM:
        virDomainTPMDefFree(def->data.tpm);
        break;
    case VIR_DOMAIN_DEVICE_PANIC:
        virDomainPanicDefFree(def->data.panic);
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        virDomainMemoryDefFree(def->data.memory);
        break;
    case VIR_DOMAIN_DEVICE_IOMMU:
        VIR_FREE(def->data.iommu);
        break;
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
        break;
    }

    VIR_FREE(def);
}

static void
virDomainClockDefClear(virDomainClockDefPtr def)
{
    if (def->offset == VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE)
        VIR_FREE(def->data.timezone);

    size_t i;
    for (i = 0; i < def->ntimers; i++)
        VIR_FREE(def->timers[i]);
    VIR_FREE(def->timers);
}


static bool
virDomainIOThreadIDArrayHasPin(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->niothreadids; i++) {
        if (def->iothreadids[i]->cpumask)
            return true;
    }
    return false;
}


void
virDomainIOThreadIDDefFree(virDomainIOThreadIDDefPtr def)
{
    if (!def)
        return;
    virBitmapFree(def->cpumask);
    VIR_FREE(def);
}


static void
virDomainIOThreadIDDefArrayFree(virDomainIOThreadIDDefPtr *def,
                                int nids)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < nids; i++)
        virDomainIOThreadIDDefFree(def[i]);

    VIR_FREE(def);
}


static int
virDomainIOThreadIDDefArrayInit(virDomainDefPtr def,
                                unsigned int iothreads)
{
    int retval = -1;
    size_t i;
    ssize_t nxt = -1;
    virDomainIOThreadIDDefPtr iothrid = NULL;
    virBitmapPtr thrmap = NULL;

    /* Same value (either 0 or some number), then we have none to fill in or
     * the iothreadid array was filled from the XML
     */
    if (iothreads == def->niothreadids)
        return 0;

    /* iothread's are numbered starting at 1, account for that */
    if (!(thrmap = virBitmapNew(iothreads + 1)))
        goto error;
    virBitmapSetAll(thrmap);

    /* Clear 0 since we don't use it, then mark those which are
     * already provided by the user */
    ignore_value(virBitmapClearBit(thrmap, 0));
    for (i = 0; i < def->niothreadids; i++)
        ignore_value(virBitmapClearBit(thrmap,
                                       def->iothreadids[i]->iothread_id));

    /* resize array */
    if (VIR_REALLOC_N(def->iothreadids, iothreads) < 0)
        goto error;

    /* Populate iothreadids[] using the set bit number from thrmap */
    while (def->niothreadids < iothreads) {
        if ((nxt = virBitmapNextSetBit(thrmap, nxt)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to populate iothreadids"));
            goto error;
        }
        if (VIR_ALLOC(iothrid) < 0)
            goto error;
        iothrid->iothread_id = nxt;
        iothrid->autofill = true;
        def->iothreadids[def->niothreadids++] = iothrid;
    }

    retval = 0;

 error:
    virBitmapFree(thrmap);
    return retval;
}


void
virDomainResourceDefFree(virDomainResourceDefPtr resource)
{
    if (!resource)
        return;

    VIR_FREE(resource->partition);
    VIR_FREE(resource);
}

void
virDomainPanicDefFree(virDomainPanicDefPtr panic)
{
    if (!panic)
        return;

    virDomainDeviceInfoClear(&panic->info);
    VIR_FREE(panic);
}

void
virDomainLoaderDefFree(virDomainLoaderDefPtr loader)
{
    if (!loader)
        return;

    VIR_FREE(loader->path);
    VIR_FREE(loader->nvram);
    VIR_FREE(loader->templt);
    VIR_FREE(loader);
}

void virDomainDefFree(virDomainDefPtr def)
{
    size_t i;

    if (!def)
        return;

    virDomainResourceDefFree(def->resource);

    for (i = 0; i < def->maxvcpus; i++)
        virDomainVcpuDefFree(def->vcpus[i]);
    VIR_FREE(def->vcpus);

    /* hostdevs must be freed before nets (or any future "intelligent
     * hostdevs") because the pointer to the hostdev is really
     * pointing into the middle of the higher level device's object,
     * so the original object must still be available during the call
     * to virDomainHostdevDefFree().
     */
    for (i = 0; i < def->nhostdevs; i++)
        virDomainHostdevDefFree(def->hostdevs[i]);
    VIR_FREE(def->hostdevs);

    for (i = 0; i < def->nleases; i++)
        virDomainLeaseDefFree(def->leases[i]);
    VIR_FREE(def->leases);

    for (i = 0; i < def->ngraphics; i++)
        virDomainGraphicsDefFree(def->graphics[i]);
    VIR_FREE(def->graphics);

    for (i = 0; i < def->ninputs; i++)
        virDomainInputDefFree(def->inputs[i]);
    VIR_FREE(def->inputs);

    for (i = 0; i < def->ndisks; i++)
        virDomainDiskDefFree(def->disks[i]);
    VIR_FREE(def->disks);

    for (i = 0; i < def->ncontrollers; i++)
        virDomainControllerDefFree(def->controllers[i]);
    VIR_FREE(def->controllers);

    for (i = 0; i < def->nfss; i++)
        virDomainFSDefFree(def->fss[i]);
    VIR_FREE(def->fss);

    for (i = 0; i < def->nnets; i++)
        virDomainNetDefFree(def->nets[i]);
    VIR_FREE(def->nets);

    for (i = 0; i < def->nsmartcards; i++)
        virDomainSmartcardDefFree(def->smartcards[i]);
    VIR_FREE(def->smartcards);

    for (i = 0; i < def->nserials; i++)
        virDomainChrDefFree(def->serials[i]);
    VIR_FREE(def->serials);

    for (i = 0; i < def->nparallels; i++)
        virDomainChrDefFree(def->parallels[i]);
    VIR_FREE(def->parallels);

    for (i = 0; i < def->nchannels; i++)
        virDomainChrDefFree(def->channels[i]);
    VIR_FREE(def->channels);

    for (i = 0; i < def->nconsoles; i++)
        virDomainChrDefFree(def->consoles[i]);
    VIR_FREE(def->consoles);

    for (i = 0; i < def->nsounds; i++)
        virDomainSoundDefFree(def->sounds[i]);
    VIR_FREE(def->sounds);

    for (i = 0; i < def->nvideos; i++)
        virDomainVideoDefFree(def->videos[i]);
    VIR_FREE(def->videos);

    for (i = 0; i < def->nhubs; i++)
        virDomainHubDefFree(def->hubs[i]);
    VIR_FREE(def->hubs);

    for (i = 0; i < def->nredirdevs; i++)
        virDomainRedirdevDefFree(def->redirdevs[i]);
    VIR_FREE(def->redirdevs);

    for (i = 0; i < def->nrngs; i++)
        virDomainRNGDefFree(def->rngs[i]);
    VIR_FREE(def->rngs);

    for (i = 0; i < def->nmems; i++)
        virDomainMemoryDefFree(def->mems[i]);
    VIR_FREE(def->mems);

    virDomainTPMDefFree(def->tpm);

    for (i = 0; i < def->npanics; i++)
        virDomainPanicDefFree(def->panics[i]);
    VIR_FREE(def->panics);

    VIR_FREE(def->iommu);

    VIR_FREE(def->idmap.uidmap);
    VIR_FREE(def->idmap.gidmap);

    VIR_FREE(def->os.machine);
    VIR_FREE(def->os.init);
    for (i = 0; def->os.initargv && def->os.initargv[i]; i++)
        VIR_FREE(def->os.initargv[i]);
    VIR_FREE(def->os.initargv);
    VIR_FREE(def->os.kernel);
    VIR_FREE(def->os.initrd);
    VIR_FREE(def->os.cmdline);
    VIR_FREE(def->os.dtb);
    VIR_FREE(def->os.root);
    VIR_FREE(def->os.slic_table);
    virDomainLoaderDefFree(def->os.loader);
    VIR_FREE(def->os.bootloader);
    VIR_FREE(def->os.bootloaderArgs);

    virDomainClockDefClear(&def->clock);

    VIR_FREE(def->name);
    virBitmapFree(def->cpumask);
    VIR_FREE(def->emulator);
    VIR_FREE(def->description);
    VIR_FREE(def->title);
    VIR_FREE(def->hyperv_vendor_id);

    virBlkioDeviceArrayClear(def->blkio.devices,
                             def->blkio.ndevices);
    VIR_FREE(def->blkio.devices);

    virDomainWatchdogDefFree(def->watchdog);

    virDomainMemballoonDefFree(def->memballoon);
    virDomainNVRAMDefFree(def->nvram);

    for (i = 0; i < def->mem.nhugepages; i++)
        virBitmapFree(def->mem.hugepages[i].nodemask);
    VIR_FREE(def->mem.hugepages);

    for (i = 0; i < def->nseclabels; i++)
        virSecurityLabelDefFree(def->seclabels[i]);
    VIR_FREE(def->seclabels);

    virCPUDefFree(def->cpu);

    virDomainIOThreadIDDefArrayFree(def->iothreadids, def->niothreadids);

    virBitmapFree(def->cputune.emulatorpin);

    virDomainNumaFree(def->numa);

    virSysinfoDefFree(def->sysinfo);

    virDomainRedirFilterDefFree(def->redirfilter);

    for (i = 0; i < def->nshmems; i++)
        virDomainShmemDefFree(def->shmems[i]);
    VIR_FREE(def->shmems);

    VIR_FREE(def->keywrap);

    if (def->namespaceData && def->ns.free)
        (def->ns.free)(def->namespaceData);

    xmlFreeNode(def->metadata);

    VIR_FREE(def);
}

static void virDomainObjDispose(void *obj)
{
    virDomainObjPtr dom = obj;

    VIR_DEBUG("obj=%p", dom);
    virCondDestroy(&dom->cond);
    virDomainDefFree(dom->def);
    virDomainDefFree(dom->newDef);

    if (dom->privateDataFreeFunc)
        (dom->privateDataFreeFunc)(dom->privateData);

    virDomainSnapshotObjListFree(dom->snapshots);
}

virDomainObjPtr
virDomainObjNew(virDomainXMLOptionPtr xmlopt)
{
    virDomainObjPtr domain;

    if (virDomainObjInitialize() < 0)
        return NULL;

    if (!(domain = virObjectLockableNew(virDomainObjClass)))
        return NULL;

    if (virCondInit(&domain->cond) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to initialize domain condition"));
        goto error;
    }

    if (xmlopt->privateData.alloc) {
        if (!(domain->privateData = (xmlopt->privateData.alloc)()))
            goto error;
        domain->privateDataFreeFunc = xmlopt->privateData.free;
    }

    if (!(domain->snapshots = virDomainSnapshotObjListNew()))
        goto error;

    virObjectLock(domain);
    virDomainObjSetState(domain, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_UNKNOWN);

    VIR_DEBUG("obj=%p", domain);
    return domain;

 error:
    virObjectUnref(domain);
    return NULL;
}


virDomainDefPtr
virDomainDefNew(void)
{
    virDomainDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (!(ret->numa = virDomainNumaNew()))
        goto error;

    ret->mem.hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    ret->mem.soft_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    ret->mem.swap_hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return ret;

 error:
    virDomainDefFree(ret);
    return NULL;
}


virDomainDefPtr
virDomainDefNewFull(const char *name,
                    const unsigned char *uuid,
                    int id)
{
    virDomainDefPtr def;

    if (!(def = virDomainDefNew()))
        return NULL;

    if (VIR_STRDUP(def->name, name) < 0) {
        VIR_FREE(def);
        return NULL;
    }

    memcpy(def->uuid, uuid, VIR_UUID_BUFLEN);
    def->id = id;

    return def;
}


void virDomainObjAssignDef(virDomainObjPtr domain,
                           virDomainDefPtr def,
                           bool live,
                           virDomainDefPtr *oldDef)
{
    if (oldDef)
        *oldDef = NULL;
    if (virDomainObjIsActive(domain)) {
        if (oldDef)
            *oldDef = domain->newDef;
        else
            virDomainDefFree(domain->newDef);
        domain->newDef = def;
    } else {
        if (live) {
            /* save current configuration to be restored on domain shutdown */
            if (!domain->newDef)
                domain->newDef = domain->def;
            else
                virDomainDefFree(domain->def);
            domain->def = def;
        } else {
            if (oldDef)
                *oldDef = domain->def;
            else
                virDomainDefFree(domain->def);
            domain->def = def;
        }
    }
}


/**
 * virDomainObjEndAPI:
 * @vm: domain object
 *
 * Finish working with a domain object in an API.  This function
 * clears whatever was left of a domain that was gathered using
 * virDomainObjListFindByUUIDRef(). Currently that means only unlocking and
 * decrementing the reference counter of that domain.  And in order to
 * make sure the caller does not access the domain, the pointer is
 * cleared.
 */
void
virDomainObjEndAPI(virDomainObjPtr *vm)
{
    if (!*vm)
        return;

    virObjectUnlock(*vm);
    virObjectUnref(*vm);
    *vm = NULL;
}


void
virDomainObjBroadcast(virDomainObjPtr vm)
{
    virCondBroadcast(&vm->cond);
}


int
virDomainObjWait(virDomainObjPtr vm)
{
    if (virCondWait(&vm->cond, &vm->parent.lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to wait for domain condition"));
        return -1;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("domain is not running"));
        return -1;
    }

    return 0;
}


/**
 * Waits for domain condition to be triggered for a specific period of time.
 *
 * Returns:
 *  -1 in case of error
 *  0 on success
 *  1 on timeout
 */
int
virDomainObjWaitUntil(virDomainObjPtr vm,
                      unsigned long long whenms)
{
    if (virCondWaitUntil(&vm->cond, &vm->parent.lock, whenms) < 0) {
        if (errno != ETIMEDOUT) {
            virReportSystemError(errno, "%s",
                                 _("failed to wait for domain condition"));
            return -1;
        }
        return 1;
    }
    return 0;
}


/*
 * Mark the current VM config as transient. Ensures transient hotplug
 * operations do not persist past shutdown.
 *
 * @param caps pointer to capabilities info
 * @param xmlopt pointer to XML parser configuration object
 * @param domain domain object pointer
 * @return 0 on success, -1 on failure
 */
int
virDomainObjSetDefTransient(virCapsPtr caps,
                            virDomainXMLOptionPtr xmlopt,
                            virDomainObjPtr domain)
{
    int ret = -1;

    if (!domain->persistent)
        return 0;

    if (domain->newDef)
        return 0;

    if (!(domain->newDef = virDomainDefCopy(domain->def, caps, xmlopt, NULL, false)))
        goto out;

    ret = 0;
 out:
    return ret;
}


/*
 * Remove the running configuration and replace it with the persistent one.
 *
 * @param domain domain object pointer
 */
void
virDomainObjRemoveTransientDef(virDomainObjPtr domain)
{
    if (!domain->newDef)
        return;

    virDomainDefFree(domain->def);
    domain->def = domain->newDef;
    domain->def->id = -1;
    domain->newDef = NULL;
}


/*
 * Return the persistent domain configuration. If domain is transient,
 * return the running config.
 *
 * @param caps pointer to capabilities info
 * @param xmlopt pointer to XML parser configuration object
 * @param domain domain object pointer
 * @return NULL on error, virDOmainDefPtr on success
 */
virDomainDefPtr
virDomainObjGetPersistentDef(virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt,
                             virDomainObjPtr domain)
{
    if (virDomainObjIsActive(domain) &&
        virDomainObjSetDefTransient(caps, xmlopt, domain) < 0)
        return NULL;

    if (domain->newDef)
        return domain->newDef;
    else
        return domain->def;
}


/**
 * virDomainObjUpdateModificationImpact:
 *
 * @vm: domain object
 * @flags: flags to update the modification impact on
 *
 * Resolves virDomainModificationImpact flags in @flags so that they correctly
 * apply to the actual state of @vm. @flags may be modified after call to this
 * function.
 *
 * Returns 0 on success if @flags point to a valid combination for @vm or -1 on
 * error.
 */
int
virDomainObjUpdateModificationImpact(virDomainObjPtr vm,
                                     unsigned int *flags)
{
    bool isActive = virDomainObjIsActive(vm);

    if ((*flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG)) ==
        VIR_DOMAIN_AFFECT_CURRENT) {
        if (isActive)
            *flags |= VIR_DOMAIN_AFFECT_LIVE;
        else
            *flags |= VIR_DOMAIN_AFFECT_CONFIG;
    }

    if (!isActive && (*flags & VIR_DOMAIN_AFFECT_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        return -1;
    }

    if (!vm->persistent && (*flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domains do not have any "
                         "persistent config"));
        return -1;
    }

    return 0;
}


/**
 * virDomainObjGetDefs:
 *
 * @vm: domain object
 * @flags: for virDomainModificationImpact
 * @liveDef: Set to the pointer to the live definition of @vm.
 * @persDef: Set to the pointer to the config definition of @vm.
 *
 * Helper function to resolve @flags and retrieve correct domain pointer
 * objects. This function should be used only when the hypervisor driver always
 * creates vm->newDef once the vm is started. (qemu driver does that)
 *
 * If @liveDef or @persDef are set it implies that @flags request modification
 * of thereof.
 *
 * Returns 0 on success and sets @liveDef and @persDef; -1 if @flags are
 * inappropriate.
 */
int
virDomainObjGetDefs(virDomainObjPtr vm,
                    unsigned int flags,
                    virDomainDefPtr *liveDef,
                    virDomainDefPtr *persDef)
{
    if (liveDef)
        *liveDef = NULL;

    if (persDef)
        *persDef = NULL;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        return -1;

    if (virDomainObjIsActive(vm)) {
        if (liveDef && (flags & VIR_DOMAIN_AFFECT_LIVE))
            *liveDef = vm->def;

        if (persDef && (flags & VIR_DOMAIN_AFFECT_CONFIG))
            *persDef = vm->newDef;
    } else {
        if (persDef)
            *persDef = vm->def;
    }

    return 0;
}


/**
 * virDomainObjGetOneDefState:
 *
 * @vm: Domain object
 * @flags: for virDomainModificationImpact
 * @live: set to true if live config was returned (may be omitted)
 *
 * Helper function to resolve @flags and return the correct domain pointer
 * object. This function returns one of @vm->def or @vm->persistentDef
 * according to @flags. @live is set to true if the live vm config will be
 * returned. This helper should be used only in APIs that guarantee
 * that @flags contains exactly one of VIR_DOMAIN_AFFECT_LIVE or
 * VIR_DOMAIN_AFFECT_CONFIG and not both.
 *
 * Returns the correct definition pointer or NULL on error.
 */
virDomainDefPtr
virDomainObjGetOneDefState(virDomainObjPtr vm,
                           unsigned int flags,
                           bool *live)
{
    if (flags & VIR_DOMAIN_AFFECT_LIVE && flags & VIR_DOMAIN_AFFECT_CONFIG) {
            virReportInvalidArg(ctl, "%s",
                                _("Flags 'VIR_DOMAIN_AFFECT_LIVE' and "
                                  "'VIR_DOMAIN_AFFECT_CONFIG' are mutually "
                                  "exclusive"));
            return NULL;
    }

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        return NULL;

    if (live) {
        if (flags & VIR_DOMAIN_AFFECT_LIVE)
            *live = true;
        else
            *live = false;
    }

    if (virDomainObjIsActive(vm) && flags & VIR_DOMAIN_AFFECT_CONFIG)
        return vm->newDef;
    else
        return vm->def;
}


/**
 * virDomainObjGetOneDef:
 *
 * @vm: Domain object
 * @flags: for virDomainModificationImpact
 *
 * Helper function to resolve @flags and return the correct domain pointer
 * object. This function returns one of @vm->def or @vm->persistentDef
 * according to @flags. This helper should be used only in APIs that guarantee
 * that @flags contains exactly one of VIR_DOMAIN_AFFECT_LIVE or
 * VIR_DOMAIN_AFFECT_CONFIG and not both.
 *
 * Returns the correct definition pointer or NULL on error.
 */
virDomainDefPtr
virDomainObjGetOneDef(virDomainObjPtr vm,
                      unsigned int flags)
{
    return virDomainObjGetOneDefState(vm, flags, NULL);
}


static int
virDomainDeviceCCWAddressIsValid(virDomainDeviceCCWAddressPtr addr)
{
    return addr->cssid <= VIR_DOMAIN_DEVICE_CCW_MAX_CSSID &&
        addr->ssid <= VIR_DOMAIN_DEVICE_CCW_MAX_SSID &&
        addr->devno <= VIR_DOMAIN_DEVICE_CCW_MAX_DEVNO;
}

int virDomainDeviceAddressIsValid(virDomainDeviceInfoPtr info,
                                  int type)
{
    if (info->type != type)
        return 0;

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        return virPCIDeviceAddressIsValid(&info->addr.pci, false);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        return 1;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        return 1;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        return virDomainDeviceCCWAddressIsValid(&info->addr.ccw);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        return 1;
    }

    return 0;
}

virDomainDeviceInfoPtr
virDomainDeviceGetInfo(virDomainDeviceDefPtr device)
{
    switch ((virDomainDeviceType) device->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        return &device->data.disk->info;
    case VIR_DOMAIN_DEVICE_FS:
        return &device->data.fs->info;
    case VIR_DOMAIN_DEVICE_NET:
        return &device->data.net->info;
    case VIR_DOMAIN_DEVICE_INPUT:
        return &device->data.input->info;
    case VIR_DOMAIN_DEVICE_SOUND:
        return &device->data.sound->info;
    case VIR_DOMAIN_DEVICE_VIDEO:
        return &device->data.video->info;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        return device->data.hostdev->info;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        return &device->data.watchdog->info;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        return &device->data.controller->info;
    case VIR_DOMAIN_DEVICE_HUB:
        return &device->data.hub->info;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        return &device->data.redirdev->info;
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        return &device->data.smartcard->info;
    case VIR_DOMAIN_DEVICE_CHR:
        return &device->data.chr->info;
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        return &device->data.memballoon->info;
    case VIR_DOMAIN_DEVICE_NVRAM:
        return &device->data.nvram->info;
    case VIR_DOMAIN_DEVICE_SHMEM:
        return &device->data.shmem->info;
    case VIR_DOMAIN_DEVICE_RNG:
        return &device->data.rng->info;
    case VIR_DOMAIN_DEVICE_TPM:
        return &device->data.tpm->info;
    case VIR_DOMAIN_DEVICE_PANIC:
        return &device->data.panic->info;
    case VIR_DOMAIN_DEVICE_MEMORY:
        return &device->data.memory->info;

    /* The following devices do not contain virDomainDeviceInfo */
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
        break;
    }
    return NULL;
}

static bool
virDomainDeviceInfoNeedsFormat(virDomainDeviceInfoPtr info, unsigned int flags)
{
    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return true;
    if (info->alias && !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
        return true;
    if (info->mastertype != VIR_DOMAIN_CONTROLLER_MASTER_NONE)
        return true;
    if ((info->rombar != VIR_TRISTATE_SWITCH_ABSENT) ||
        info->romfile)
        return true;
    if (info->bootIndex)
        return true;
    return false;
}

bool
virDomainDeviceInfoAddressIsEqual(const virDomainDeviceInfo *a,
                                  const virDomainDeviceInfo *b)
{
    if (a->type != b->type)
        return false;

    switch ((virDomainDeviceAddressType) a->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    /* address types below don't have any specific data */
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        /* the 'multi' field shouldn't be checked */
        if (a->addr.pci.domain != b->addr.pci.domain ||
            a->addr.pci.bus != b->addr.pci.bus ||
            a->addr.pci.slot != b->addr.pci.slot ||
            a->addr.pci.function != b->addr.pci.function)
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (memcmp(&a->addr.drive, &b->addr.drive, sizeof(a->addr.drive)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        if (memcmp(&a->addr.vioserial, &b->addr.vioserial, sizeof(a->addr.vioserial)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        if (memcmp(&a->addr.ccid, &b->addr.ccid, sizeof(a->addr.ccid)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        if (memcmp(&a->addr.usb, &b->addr.usb, sizeof(a->addr.usb)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (memcmp(&a->addr.spaprvio, &b->addr.spaprvio, sizeof(a->addr.spaprvio)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        /* the 'assigned' field denotes that the address was generated */
        if (a->addr.ccw.cssid != b->addr.ccw.cssid ||
            a->addr.ccw.ssid != b->addr.ccw.ssid ||
            a->addr.ccw.devno != b->addr.ccw.devno)
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (memcmp(&a->addr.isa, &b->addr.isa, sizeof(a->addr.isa)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (memcmp(&a->addr.dimm, &b->addr.dimm, sizeof(a->addr.dimm)))
            return false;
        break;
    }

    return true;
}


static int
virDomainDefHasDeviceAddressIterator(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                     virDomainDeviceDefPtr dev ATTRIBUTE_UNUSED,
                                     virDomainDeviceInfoPtr info,
                                     void *opaque)
{
    virDomainDeviceInfoPtr needle = opaque;

    /* break iteration if the info was found */
    if (virDomainDeviceInfoAddressIsEqual(info, needle))
        return -1;

    return 0;
}


int
virDomainDeviceInfoCopy(virDomainDeviceInfoPtr dst,
                        virDomainDeviceInfoPtr src)
{
    /* Assume that dst is already cleared */

    /* first a shallow copy of *everything* */
    *dst = *src;

    /* then redo the two fields that are pointers */
    dst->alias = NULL;
    dst->romfile = NULL;

    if (VIR_STRDUP(dst->alias, src->alias) < 0 ||
        VIR_STRDUP(dst->romfile, src->romfile) < 0)
        return -1;
    return 0;
}

void virDomainDeviceInfoClear(virDomainDeviceInfoPtr info)
{
    VIR_FREE(info->alias);
    memset(&info->addr, 0, sizeof(info->addr));
    info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
    VIR_FREE(info->romfile);
}


static bool
virDomainSkipBackcompatConsole(virDomainDefPtr def,
                               size_t idx,
                               bool all)
{
    virDomainChrDefPtr console = def->consoles[idx];

    if (!all && idx == 0 &&
        (console->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
         console->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE) &&
        def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        return true;
    }

    return false;
}


static int
virDomainDeviceInfoIterateInternal(virDomainDefPtr def,
                                   virDomainDeviceInfoCallback cb,
                                   bool all,
                                   void *opaque)
{
    size_t i;
    virDomainDeviceDef device;

    device.type = VIR_DOMAIN_DEVICE_DISK;
    for (i = 0; i < def->ndisks; i++) {
        device.data.disk = def->disks[i];
        if (cb(def, &device, &def->disks[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_NET;
    for (i = 0; i < def->nnets; i++) {
        device.data.net = def->nets[i];
        if (cb(def, &device, &def->nets[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_SOUND;
    for (i = 0; i < def->nsounds; i++) {
        device.data.sound = def->sounds[i];
        if (cb(def, &device, &def->sounds[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_HOSTDEV;
    for (i = 0; i < def->nhostdevs; i++) {
        device.data.hostdev = def->hostdevs[i];
        if (cb(def, &device, def->hostdevs[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_VIDEO;
    for (i = 0; i < def->nvideos; i++) {
        device.data.video = def->videos[i];
        if (cb(def, &device, &def->videos[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_CONTROLLER;
    for (i = 0; i < def->ncontrollers; i++) {
        device.data.controller = def->controllers[i];
        if (cb(def, &device, &def->controllers[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_SMARTCARD;
    for (i = 0; i < def->nsmartcards; i++) {
        device.data.smartcard = def->smartcards[i];
        if (cb(def, &device, &def->smartcards[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_CHR;
    for (i = 0; i < def->nserials; i++) {
        device.data.chr = def->serials[i];
        if (cb(def, &device, &def->serials[i]->info, opaque) < 0)
            return -1;
    }
    for (i = 0; i < def->nparallels; i++) {
        device.data.chr = def->parallels[i];
        if (cb(def, &device, &def->parallels[i]->info, opaque) < 0)
            return -1;
    }
    for (i = 0; i < def->nchannels; i++) {
        device.data.chr = def->channels[i];
        if (cb(def, &device, &def->channels[i]->info, opaque) < 0)
            return -1;
    }
    for (i = 0; i < def->nconsoles; i++) {
        if (virDomainSkipBackcompatConsole(def, i, all))
            continue;
        device.data.chr = def->consoles[i];
        if (cb(def, &device, &def->consoles[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_INPUT;
    for (i = 0; i < def->ninputs; i++) {
        device.data.input = def->inputs[i];
        if (cb(def, &device, &def->inputs[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_FS;
    for (i = 0; i < def->nfss; i++) {
        device.data.fs = def->fss[i];
        if (cb(def, &device, &def->fss[i]->info, opaque) < 0)
            return -1;
    }
    if (def->watchdog) {
        device.type = VIR_DOMAIN_DEVICE_WATCHDOG;
        device.data.watchdog = def->watchdog;
        if (cb(def, &device, &def->watchdog->info, opaque) < 0)
            return -1;
    }
    if (def->memballoon) {
        device.type = VIR_DOMAIN_DEVICE_MEMBALLOON;
        device.data.memballoon = def->memballoon;
        if (cb(def, &device, &def->memballoon->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_RNG;
    for (i = 0; i < def->nrngs; i++) {
        device.data.rng = def->rngs[i];
        if (cb(def, &device, &def->rngs[i]->info, opaque) < 0)
            return -1;
    }
    if (def->nvram) {
        device.type = VIR_DOMAIN_DEVICE_NVRAM;
        device.data.nvram = def->nvram;
        if (cb(def, &device, &def->nvram->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_HUB;
    for (i = 0; i < def->nhubs; i++) {
        device.data.hub = def->hubs[i];
        if (cb(def, &device, &def->hubs[i]->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_SHMEM;
    for (i = 0; i < def->nshmems; i++) {
        device.data.shmem = def->shmems[i];
        if (cb(def, &device, &def->shmems[i]->info, opaque) < 0)
            return -1;
    }
    if (def->tpm) {
        device.type = VIR_DOMAIN_DEVICE_TPM;
        device.data.tpm = def->tpm;
        if (cb(def, &device, &def->tpm->info, opaque) < 0)
            return -1;
    }
    device.type = VIR_DOMAIN_DEVICE_PANIC;
    for (i = 0; i < def->npanics; i++) {
        device.data.panic = def->panics[i];
        if (cb(def, &device, &def->panics[i]->info, opaque) < 0)
            return -1;
    }

    device.type = VIR_DOMAIN_DEVICE_MEMORY;
    for (i = 0; i < def->nmems; i++) {
        device.data.memory = def->mems[i];
        if (cb(def, &device, &def->mems[i]->info, opaque) < 0)
            return -1;
    }

    device.type = VIR_DOMAIN_DEVICE_REDIRDEV;
    for (i = 0; i < def->nredirdevs; i++) {
        device.data.redirdev = def->redirdevs[i];
        if (cb(def, &device, &def->redirdevs[i]->info, opaque) < 0)
            return -1;
    }

    /* Coverity is not very happy with this - all dead_error_condition */
#if !STATIC_ANALYSIS
    /* This switch statement is here to trigger compiler warning when adding
     * a new device type. When you are adding a new field to the switch you
     * also have to add an iteration statement above. Otherwise the switch
     * statement has no real function here and should be optimized out by the
     * compiler. */
    i = VIR_DOMAIN_DEVICE_LAST;
    switch ((virDomainDeviceType) i) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
        break;
    }
#endif

    return 0;
}


int
virDomainDeviceInfoIterate(virDomainDefPtr def,
                           virDomainDeviceInfoCallback cb,
                           void *opaque)
{
    return virDomainDeviceInfoIterateInternal(def, cb, false, opaque);
}


bool
virDomainDefHasDeviceAddress(virDomainDefPtr def,
                             virDomainDeviceInfoPtr info)
{
    if (virDomainDeviceInfoIterateInternal(def,
                                           virDomainDefHasDeviceAddressIterator,
                                           true,
                                           info) < 0)
        return true;

    return false;
}


static int
virDomainDefRejectDuplicateControllers(virDomainDefPtr def)
{
    int max_idx[VIR_DOMAIN_CONTROLLER_TYPE_LAST];
    virBitmapPtr bitmaps[VIR_DOMAIN_CONTROLLER_TYPE_LAST] = { NULL };
    virDomainControllerDefPtr cont;
    size_t nbitmaps = 0;
    int ret = -1;
    size_t i;

    memset(max_idx, -1, sizeof(max_idx));

    for (i = 0; i < def->ncontrollers; i++) {
        cont = def->controllers[i];
        if (cont->idx > max_idx[cont->type])
            max_idx[cont->type] = cont->idx;
    }

    /* multiple USB controllers with the same index are allowed */
    max_idx[VIR_DOMAIN_CONTROLLER_TYPE_USB] = -1;

    for (i = 0; i < VIR_DOMAIN_CONTROLLER_TYPE_LAST; i++) {
        if (max_idx[i] >= 0 && !(bitmaps[i] = virBitmapNew(max_idx[i] + 1)))
            goto cleanup;
        nbitmaps++;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        cont = def->controllers[i];

        if (max_idx[cont->type] == -1)
            continue;

        if (virBitmapIsBitSet(bitmaps[cont->type], cont->idx)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple '%s' controllers with index '%d'"),
                           virDomainControllerTypeToString(cont->type),
                           cont->idx);
            goto cleanup;
        }
        ignore_value(virBitmapSetBit(bitmaps[cont->type], cont->idx));
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nbitmaps; i++)
        virBitmapFree(bitmaps[i]);
    return ret;
}

static int
virDomainDefRejectDuplicatePanics(virDomainDefPtr def)
{
    bool exists[VIR_DOMAIN_PANIC_MODEL_LAST];
    size_t i;

    for (i = 0; i < VIR_DOMAIN_PANIC_MODEL_LAST; i++)
         exists[i] = false;

    for (i = 0; i < def->npanics; i++) {
        virDomainPanicModel model = def->panics[i]->model;
        if (exists[model]) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple panic devices with model '%s'"),
                           virDomainPanicModelTypeToString(model));
            return -1;
        }
        exists[model] = true;
    }

    return 0;
}


static int
virDomainDefPostParseMemory(virDomainDefPtr def,
                            unsigned int parseFlags)
{
    size_t i;
    unsigned long long numaMemory = 0;
    unsigned long long hotplugMemory = 0;

    /* Attempt to infer the initial memory size from the sum NUMA memory sizes
     * in case ABI updates are allowed or the <memory> element wasn't specified */
    if (def->mem.total_memory == 0 ||
        parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE ||
        parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE_MIGRATION)
        numaMemory = virDomainNumaGetMemorySize(def->numa);

    /* calculate the sizes of hotplug memory */
    for (i = 0; i < def->nmems; i++)
        hotplugMemory += def->mems[i]->size;

    if (numaMemory) {
        /* update the sizes in XML if nothing was set in the XML or ABI update
         * is supported*/
        virDomainDefSetMemoryTotal(def, numaMemory + hotplugMemory);
    } else {
        /* verify that the sum of memory modules doesn't exceed the total
         * memory. This is necessary for virDomainDefGetMemoryInitial to work
         * properly. */
        if (hotplugMemory > def->mem.total_memory) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Total size of memory devices exceeds the total "
                             "memory size"));
            return -1;
        }
    }

    if (virDomainDefGetMemoryInitial(def) == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Memory size must be specified via <memory> or in the "
                         "<numa> configuration"));
        return -1;
    }

    if (def->mem.cur_balloon > virDomainDefGetMemoryTotal(def) ||
        def->mem.cur_balloon == 0)
        def->mem.cur_balloon = virDomainDefGetMemoryTotal(def);

    if ((def->mem.max_memory || def->mem.memory_slots) &&
        !(def->mem.max_memory && def->mem.memory_slots)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("both maximum memory size and "
                         "memory slot count must be specified"));
        return -1;
    }

    if (def->mem.max_memory &&
        def->mem.max_memory < virDomainDefGetMemoryTotal(def)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("maximum memory size must be equal or greater than "
                         "the actual memory size"));
        return -1;
    }

    return 0;
}


static int
virDomainDefAddConsoleCompat(virDomainDefPtr def)
{
    size_t i;

    /*
     * Some really crazy backcompat stuff for consoles
     *
     * Historically the first (and only) '<console>' element in an HVM guest
     * was treated as being an alias for a <serial> device.
     *
     * So if we see that this console device should be a serial device, then we
     * move the config over to def->serials[0] (or discard it if that already
     * exists). However, given console can already be filled with aliased data
     * of def->serials[0]. Keep it then.
     *
     * We then fill def->consoles[0] with a stub just so we get sequencing
     * correct for consoles > 0
     */

    /* Only the first console (if there are any) can be of type serial,
     * verify that no other console is of type serial
     */
    for (i = 1; i < def->nconsoles; i++) {
        virDomainChrDefPtr cons = def->consoles[i];

        if (cons->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only the first console can be a serial port"));
            return -1;
        }
    }
    if (def->nconsoles > 0 && def->os.type == VIR_DOMAIN_OSTYPE_HVM &&
        (def->consoles[0]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
         def->consoles[0]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)) {

        /* If there isn't a corresponding serial port:
         *  - create one and set, the console to be an alias for it
         *
         * If there is a corresponding serial port:
         * - Check if the source definition is equal:
         *    - if yes: leave it as-is
         *    - if no: change the console to be alias of the serial port
         */

        /* create the serial port definition from the console definition */
        if (def->nserials == 0) {
            if (VIR_APPEND_ELEMENT(def->serials,
                                   def->nserials,
                                   def->consoles[0]) < 0)
                return -1;

            /* modify it to be a serial port */
            def->serials[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
            def->serials[0]->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA;
            def->serials[0]->target.port = 0;
        } else {
            /* if the console source doesn't match */
            if (!virDomainChrSourceDefIsEqual(def->serials[0]->source,
                                              def->consoles[0]->source)) {
                virDomainChrDefFree(def->consoles[0]);
                def->consoles[0] = NULL;
            }
        }

        if (!def->consoles[0]) {
            /* allocate a new console type for the stolen one */
            if (!(def->consoles[0] = virDomainChrDefNew(NULL)))
                return -1;

            /* Create an console alias for the serial port */
            def->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
            def->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
        }
    } else if (def->os.type == VIR_DOMAIN_OSTYPE_HVM && def->nserials > 0 &&
               def->serials[0]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
               def->serials[0]->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA) {
        /* Create a stub console to match the serial port.
         * console[0] either does not exist
         *                or has a different type than SERIAL or NONE.
         */
        virDomainChrDefPtr chr;
        if (!(chr = virDomainChrDefNew(NULL)))
            return -1;

        if (VIR_INSERT_ELEMENT(def->consoles,
                               0,
                               def->nconsoles,
                               chr) < 0) {
            virDomainChrDefFree(chr);
            return -1;
        }

        def->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    }

    return 0;
}


static int
virDomainDefPostParseTimer(virDomainDefPtr def)
{
    size_t i;

    /* verify settings of guest timers */
    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDefPtr timer = def->clock.timers[i];

        if (timer->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK ||
            timer->name == VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK) {
            if (timer->tickpolicy != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %s doesn't support setting of "
                                 "timer tickpolicy"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }
        }

        if (timer->tickpolicy != VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP &&
            (timer->catchup.threshold != 0 ||
             timer->catchup.limit != 0 ||
             timer->catchup.slew != 0)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("setting of timer catchup policies is only "
                             "supported with tickpolicy='catchup'"));
            return -1;
        }

        if (timer->name != VIR_DOMAIN_TIMER_NAME_TSC) {
            if (timer->frequency != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %s doesn't support setting of "
                                 "timer frequency"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
             }

            if (timer->mode != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %s doesn't support setting of "
                                 "timer mode"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
             }
        }

        if (timer->name != VIR_DOMAIN_TIMER_NAME_PLATFORM &&
            timer->name != VIR_DOMAIN_TIMER_NAME_RTC) {
            if (timer->track != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("timer %s doesn't support setting of "
                                 "timer track"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }
        }
    }

    return 0;
}


static void
virDomainDefPostParseGraphics(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDefPtr graphics = def->graphics[i];

        /* If spice graphics is configured without ports and with autoport='no'
         * then we start qemu with Spice to not listen anywhere.  Let's convert
         * this configuration to the new listen type='none' which does the
         * same. */
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            virDomainGraphicsListenDefPtr glisten = &graphics->listens[0];

            if (glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS &&
                graphics->data.spice.port == 0 &&
                graphics->data.spice.tlsPort == 0 &&
                !graphics->data.spice.autoport) {
                VIR_FREE(glisten->address);
                glisten->type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE;
            }
        }
    }
}


/**
 * virDomainDriveAddressIsUsedByDisk:
 * @def: domain definition containing the disks to check
 * @bus_type: bus type
 * @addr: address to check for duplicates
 *
 * Return true if any disk is already using the given address on the
 * given bus, false otherwise.
 */
static bool
virDomainDriveAddressIsUsedByDisk(const virDomainDef *def,
                                  virDomainDiskBus bus_type,
                                  const virDomainDeviceDriveAddress *addr)
{
    virDomainDiskDefPtr disk;
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        disk = def->disks[i];

        if (disk->bus != bus_type ||
            disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        if (disk->info.addr.drive.controller == addr->controller &&
            disk->info.addr.drive.unit == addr->unit &&
            disk->info.addr.drive.bus == addr->bus &&
            disk->info.addr.drive.target == addr->target)
            return true;
    }

    return false;
}


/**
 * virDomainDriveAddressIsUsedByHostdev:
 * @def: domain definition containing the hostdevs to check
 * @type: bus type
 * @addr: address to check for duplicates
 *
 * Return true if any hostdev is already using the given address on the
 * given bus, false otherwise.
 */
static bool
virDomainDriveAddressIsUsedByHostdev(const virDomainDef *def,
                                     virDomainHostdevSubsysType type,
                                     const virDomainDeviceDriveAddress *addr)
{
    virDomainHostdevDefPtr hostdev;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->source.subsys.type != type ||
            hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        if (hostdev->info->addr.drive.controller == addr->controller &&
            hostdev->info->addr.drive.unit == addr->unit &&
            hostdev->info->addr.drive.bus == addr->bus &&
            hostdev->info->addr.drive.target == addr->target)
            return true;
    }

    return false;
}


/**
 * virDomainSCSIDriveAddressIsUsed:
 * @def: domain definition to check against
 * @addr: address to check for duplicates
 *
 * Return true if the SCSI drive address is already in use, false
 * otherwise.
 */
static bool
virDomainSCSIDriveAddressIsUsed(const virDomainDef *def,
                                const virDomainDeviceDriveAddress *addr)
{
    /* In current implementation, the maximum unit number of a controller
     * is either 16 or 7 (narrow SCSI bus), and if the maximum unit number
     * is 16, the controller itself is on unit 7 */
    if (addr->unit == 7)
        return true;

    if (virDomainDriveAddressIsUsedByDisk(def, VIR_DOMAIN_DISK_BUS_SCSI,
                                          addr) ||
        virDomainDriveAddressIsUsedByHostdev(def,
                                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI,
                                             addr))
        return true;

    return false;
}


/* Find out the next usable "unit" of a specific controller */
static int
virDomainControllerSCSINextUnit(const virDomainDef *def,
                                unsigned int max_unit,
                                unsigned int controller)
{
    size_t i;

    for (i = 0; i < max_unit; i++) {
        /* Default to assigning addresses using bus = target = 0 */
        const virDomainDeviceDriveAddress addr = {controller, 0, 0, i};

        if (!virDomainSCSIDriveAddressIsUsed(def, &addr))
            return i;
    }

    return -1;
}


#define SCSI_WIDE_BUS_MAX_CONT_UNIT 16
#define SCSI_NARROW_BUS_MAX_CONT_UNIT 7

static int
virDomainHostdevAssignAddress(virDomainXMLOptionPtr xmlopt,
                              const virDomainDef *def,
                              virDomainHostdevDefPtr hostdev)
{
    int next_unit = 0;
    unsigned controller = 0;
    unsigned int max_unit;
    size_t i;
    int ret;

    if (xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_WIDE_SCSI)
        max_unit = SCSI_WIDE_BUS_MAX_CONT_UNIT;
    else
        max_unit = SCSI_NARROW_BUS_MAX_CONT_UNIT;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        controller++;
        ret = virDomainControllerSCSINextUnit(def, max_unit,
                                              def->controllers[i]->idx);
        if (ret >= 0) {
            next_unit = ret;
            controller = def->controllers[i]->idx;
            break;
        }
    }

    /* NB: Do not attempt calling virDomainDefMaybeAddController to
     * automagically add a "new" controller. Doing so will result in
     * qemuDomainFindOrCreateSCSIDiskController "finding" the controller
     * in the domain def list and thus not hotplugging the controller as
     * well as the hostdev in the event that there are either no SCSI
     * controllers defined or there was no space on an existing one.
     */

    hostdev->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
    hostdev->info->addr.drive.controller = controller;
    hostdev->info->addr.drive.bus = 0;
    hostdev->info->addr.drive.target = 0;
    hostdev->info->addr.drive.unit = next_unit;

    return 0;
}


static int
virDomainHostdevDefPostParse(virDomainHostdevDefPtr dev,
                             const virDomainDef *def,
                             virDomainXMLOptionPtr xmlopt)
{
    if (dev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (dev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (dev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            virDomainHostdevAssignAddress(xmlopt, def, dev) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Cannot assign SCSI host device address"));
            return -1;
        } else {
            /* Ensure provided address doesn't conflict with existing
             * scsi disk drive address
             */
            virDomainDeviceDriveAddressPtr addr = &dev->info->addr.drive;
            if (virDomainDriveAddressIsUsedByDisk(def,
                                                  VIR_DOMAIN_DISK_BUS_SCSI,
                                                  addr)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("SCSI host address controller='%u' "
                                 "bus='%u' target='%u' unit='%u' in "
                                 "use by a SCSI disk"),
                               addr->controller, addr->bus,
                               addr->target, addr->unit);
                return -1;
            }
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV: {
        int model = dev->source.subsys.u.mdev.model;

        if (dev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            return 0;

        if (model == VIR_MDEV_MODEL_TYPE_VFIO_PCI &&
            dev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Unsupported address type '%s' with mediated "
                             "device model '%s'"),
                           virDomainDeviceAddressTypeToString(dev->info->type),
                           virMediatedDeviceModelTypeToString(model));
            return -1;
        }
    }

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        break;
    }

    return 0;
}


static int
virDomainCheckVirtioOptions(virDomainVirtioOptionsPtr virtio)
{
    if (!virtio)
        return 0;

    if (virtio->iommu != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu driver option is only supported "
                         "for virtio devices"));
        return -1;
    }
    if (virtio->ats != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ats driver option is only supported "
                         "for virtio devices"));
        return -1;
    }
    return 0;
}


static int
virDomainDeviceDefPostParseInternal(virDomainDeviceDefPtr dev,
                                    const virDomainDef *def,
                                    virCapsPtr caps ATTRIBUTE_UNUSED,
                                    unsigned int parseFlags ATTRIBUTE_UNUSED,
                                    virDomainXMLOptionPtr xmlopt)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR) {
        virDomainChrDefPtr chr = dev->data.chr;
        const virDomainChrDef **arrPtr;
        size_t i, cnt;

        virDomainChrGetDomainPtrs(def, chr->deviceType, &arrPtr, &cnt);

        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)
            chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;

        if (chr->target.port == -1 &&
            (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL ||
             chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL ||
             chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE)) {
            int maxport = -1;

            for (i = 0; i < cnt; i++) {
                if (arrPtr[i]->target.port > maxport)
                    maxport = arrPtr[i]->target.port;
            }

            chr->target.port = maxport + 1;
        }
    }

    /* set default path for virtio-rng "random" backend to /dev/random */
    if (dev->type == VIR_DOMAIN_DEVICE_RNG &&
        dev->data.rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM &&
        !dev->data.rng->source.file) {
        if (VIR_STRDUP(dev->data.rng->source.file, "/dev/random") < 0)
            return -1;
    }

    /* verify disk source */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDefPtr disk = dev->data.disk;

        /* internal snapshots and config files are currently supported
         * only with rbd: */
        if (virStorageSourceGetActualType(disk->src) != VIR_STORAGE_TYPE_NETWORK &&
            disk->src->protocol != VIR_STORAGE_NET_PROTOCOL_RBD) {
            if (disk->src->snapshot) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("<snapshot> element is currently supported "
                                 "only with 'rbd' disks"));
                return -1;
            }

            if (disk->src->configFile) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("<config> element is currently supported "
                                 "only with 'rbd' disks"));
                return -1;
            }
        }

        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO &&
            virDomainCheckVirtioOptions(disk->virtio) < 0)
            return -1;

        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            virDomainDiskDefAssignAddress(xmlopt, disk, def) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO) {
        virDomainVideoDefPtr video = dev->data.video;
        /* Fill out (V)RAM if the driver-specific callback did not do so */
        if (video->ram == 0 && video->type == VIR_DOMAIN_VIDEO_TYPE_QXL)
            video->ram = virDomainVideoDefaultRAM(def, video->type);
        if (video->vram == 0)
            video->vram = virDomainVideoDefaultRAM(def, video->type);

        video->ram = VIR_ROUND_UP_POWER_OF_TWO(video->ram);
        video->vram = VIR_ROUND_UP_POWER_OF_TWO(video->vram);
    }

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        virDomainHostdevDefPostParse(dev->data.hostdev, def, xmlopt) < 0)
        return -1;

    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        virDomainControllerDefPtr cdev = dev->data.controller;

        if (cdev->iothread &&
            cdev->model != VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("'iothread' attribute only supported for "
                             "controller model '%s'"),
                           virDomainControllerModelSCSITypeToString(VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI));
            return -1;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        virDomainNetDefPtr net = dev->data.net;
        if (STRNEQ_NULLABLE(net->model, "virtio") &&
            virDomainCheckVirtioOptions(net->virtio) < 0)
            return -1;
    }

    return 0;
}


/**
 * virDomainDefRemoveOfflineVcpuPin:
 * @def: domain definition
 *
 * This function removes vcpu pinning information from offline vcpus. This is
 * designed to be used for drivers which don't support offline vcpupin.
 */
static void
virDomainDefRemoveOfflineVcpuPin(virDomainDefPtr def)
{
    size_t i;
    virDomainVcpuDefPtr vcpu;

    for (i = 0; i < virDomainDefGetVcpusMax(def); i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        if (vcpu && !vcpu->online && vcpu->cpumask) {
            virBitmapFree(vcpu->cpumask);
            vcpu->cpumask = NULL;

            VIR_WARN("Ignoring unsupported vcpupin for offline vcpu '%zu'", i);
        }
    }
}


static void
virDomainAssignControllerIndexes(virDomainDefPtr def)
{
    /* the index attribute of a controller is optional in the XML, but
     * is required to be valid at any time after parse. When no index
     * is provided for a controller, assign one automatically by
     * looking at what indexes are already used for that controller
     * type in the domain - the unindexed controller gets the lowest
     * unused index.
     */
    size_t outer;

    for (outer = 0; outer < def->ncontrollers; outer++) {
        virDomainControllerDefPtr cont = def->controllers[outer];
        virDomainControllerDefPtr prev = NULL;
        size_t inner;

        if (cont->idx != -1)
            continue;

        if (outer > 0 && IS_USB2_CONTROLLER(cont)) {
            /* USB2 controllers are the only exception to the simple
             * "assign the lowest unused index". A group of USB2
             * "companions" should all be at the same index as other
             * USB2 controllers in the group, but only do this
             * automatically if it appears to be the intent. To prove
             * intent: the USB controller on the list just prior to
             * this one must also be a USB2 controller, and there must
             * not yet be a controller with the exact same model of
             * this one and the same index as the previously added
             * controller (e.g., if this controller is a UHCI1, then
             * the previous controller must be an EHCI1 or a UHCI[23],
             * and there must not already be a UHCI1 controller with
             * the same index as the previous controller). If all of
             * these are satisfied, set this controller to the same
             * index as the previous controller.
             */
            int prevIdx;

            prevIdx = outer - 1;
            while (prevIdx >= 0 &&
                   def->controllers[prevIdx]->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
                prevIdx--;
            if (prevIdx >= 0)
                prev = def->controllers[prevIdx];
            /* if the last USB controller isn't USB2, that breaks
             * the chain, so we need a new index for this new
             * controller
             */
            if (prev && !IS_USB2_CONTROLLER(prev))
                prev = NULL;

            /* if prev != NULL, we've found a potential index to
             * use. Make sure this index isn't already used by an
             * existing USB2 controller of the same model as the new
             * one.
             */
            for (inner = 0; prev && inner < def->ncontrollers; inner++) {
                if (def->controllers[inner]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                    def->controllers[inner]->idx == prev->idx &&
                    def->controllers[inner]->model == cont->model) {
                    /* we already have a controller of this model with
                     * the proposed index, so we need to move to a new
                     * index for this controller
                     */
                    prev = NULL;
                }
            }
            if (prev)
                cont->idx = prev->idx;
        }
        /* if none of the above applied, prev will be NULL */
        if (!prev)
            cont->idx = virDomainControllerFindUnusedIndex(def, cont->type);
    }
}


#define UNSUPPORTED(FEATURE) (!((FEATURE) & xmlopt->config.features))
/**
 * virDomainDefPostParseCheckFeatures:
 * @def: domain definition
 * @xmlopt: XML parser option object
 *
 * This function checks that the domain configuration is supported according to
 * the supported features for a given hypervisor. See virDomainDefFeatures and
 * virDomainDefParserConfig.
 *
 * Returns 0 on success and -1 on error with an appropriate libvirt error.
 */
static int
virDomainDefPostParseCheckFeatures(virDomainDefPtr def,
                                   virDomainXMLOptionPtr xmlopt)
{
    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG) &&
        virDomainDefCheckUnsupportedMemoryHotplug(def) < 0)
        return -1;

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_OFFLINE_VCPUPIN))
        virDomainDefRemoveOfflineVcpuPin(def);

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_NAME_SLASH)) {
        if (def->name && strchr(def->name, '/')) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("name %s cannot contain '/'"), def->name);
            return -1;
        }
    }

    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS) &&
        def->individualvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("individual CPU state configuration is not supported"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDeviceDefPostParseCheckFeatures:
 * @dev: device definition
 * @xmlopt: XML parser option object
 *
 * This function checks that the device configuration is supported according to
 * the supported features for a given hypervisor. See virDomainDefFeatures and
 * virDomainDefParserConfig.
 *
 * Returns 0 on success and -1 on error with an appropriate libvirt error.
 */
static int
virDomainDeviceDefPostParseCheckFeatures(virDomainDeviceDefPtr dev,
                                         virDomainXMLOptionPtr xmlopt)
{
    if (UNSUPPORTED(VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG) &&
        virDomainDeviceDefCheckUnsupportedMemoryDevice(dev) < 0)
        return -1;

    return 0;
}
#undef UNSUPPORTED


static int
virDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                            const virDomainDef *def,
                            virCapsPtr caps,
                            unsigned int flags,
                            virDomainXMLOptionPtr xmlopt,
                            void *parseOpaque)
{
    int ret;

    if (xmlopt->config.devicesPostParseCallback) {
        ret = xmlopt->config.devicesPostParseCallback(dev, def, caps, flags,
                                                      xmlopt->config.priv,
                                                      parseOpaque);
        if (ret < 0)
            return ret;
    }

    if ((ret = virDomainDeviceDefPostParseInternal(dev, def, caps, flags, xmlopt)) < 0)
        return ret;

    if (virDomainDeviceDefPostParseCheckFeatures(dev, xmlopt) < 0)
        return -1;

    return 0;
}


struct virDomainDefPostParseDeviceIteratorData {
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    void *parseOpaque;
    unsigned int parseFlags;
};


static int
virDomainDefPostParseDeviceIterator(virDomainDefPtr def,
                                    virDomainDeviceDefPtr dev,
                                    virDomainDeviceInfoPtr info ATTRIBUTE_UNUSED,
                                    void *opaque)
{
    struct virDomainDefPostParseDeviceIteratorData *data = opaque;
    return virDomainDeviceDefPostParse(dev, def, data->caps,
                                       data->parseFlags, data->xmlopt,
                                       data->parseOpaque);
}


static int
virDomainVcpuDefPostParse(virDomainDefPtr def)
{
    virDomainVcpuDefPtr vcpu;
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        /* impossible but some compilers don't like it */
        if (!vcpu)
            continue;

        switch (vcpu->hotpluggable) {
        case VIR_TRISTATE_BOOL_ABSENT:
            if (vcpu->online)
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_NO;
            else
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_YES;
            break;

        case VIR_TRISTATE_BOOL_NO:
            if (!vcpu->online) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vcpu '%zu' is both offline and not "
                                 "hotpluggable"), i);
                return -1;
            }
            break;

        case VIR_TRISTATE_BOOL_YES:
        case VIR_TRISTATE_BOOL_LAST:
            break;
        }
    }

    return 0;
}


static int
virDomainDefPostParseCPU(virDomainDefPtr def)
{
    if (!def->cpu)
        return 0;

    if (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
        !def->cpu->model &&
        def->cpu->check != VIR_CPU_CHECK_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("check attribute specified for CPU with no model"));
        return -1;
    }

    return 0;
}


static int
virDomainDefPostParseInternal(virDomainDefPtr def,
                              struct virDomainDefPostParseDeviceIteratorData *data)
{
    /* verify init path for container based domains */
    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE && !def->os.init) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("init binary must be specified"));
        return -1;
    }

    if (virDomainVcpuDefPostParse(def) < 0)
        return -1;

    if (virDomainDefPostParseMemory(def, data->parseFlags) < 0)
        return -1;

    if (virDomainDefRejectDuplicateControllers(def) < 0)
        return -1;

    if (virDomainDefRejectDuplicatePanics(def) < 0)
        return -1;

    if (virDomainDefPostParseTimer(def) < 0)
        return -1;

    if (virDomainDefAddImplicitDevices(def) < 0)
        return -1;

    if (def->nvideos != 0) {
        virDomainDeviceDef device = {
            .type = VIR_DOMAIN_DEVICE_VIDEO,
            .data.video = def->videos[0],
        };

        /* Mark the first video as primary. If the user specified primary="yes",
         * the parser already inserted the device at def->videos[0] */
        def->videos[0]->primary = true;

        /* videos[0] might have been added in AddImplicitDevices, after we've
         * done the per-device post-parse */
        if (virDomainDefPostParseDeviceIterator(def, &device, NULL, data) < 0)
            return -1;
    }

    /* clean up possibly duplicated metadata entries */
    virXMLNodeSanitizeNamespaces(def->metadata);

    virDomainDefPostParseGraphics(def);

    if (virDomainDefPostParseCPU(def) < 0)
        return -1;

    return 0;
}


int
virDomainDefPostParse(virDomainDefPtr def,
                      virCapsPtr caps,
                      unsigned int parseFlags,
                      virDomainXMLOptionPtr xmlopt,
                      void *parseOpaque)
{
    int ret;
    struct virDomainDefPostParseDeviceIteratorData data = {
        .caps = caps,
        .xmlopt = xmlopt,
        .parseFlags = parseFlags,
        .parseOpaque = parseOpaque,
    };

    /* this must be done before the hypervisor-specific callback,
     * in case presence of a controller at a specific index is checked
     */
    virDomainAssignControllerIndexes(def);

    /* call the domain config callback */
    if (xmlopt->config.domainPostParseCallback) {
        ret = xmlopt->config.domainPostParseCallback(def, caps, parseFlags,
                                                     xmlopt->config.priv,
                                                     parseOpaque);
        if (ret < 0)
            return ret;
    }

    /* iterate the devices */
    if ((ret = virDomainDeviceInfoIterateInternal(def,
                                                  virDomainDefPostParseDeviceIterator,
                                                  true,
                                                  &data)) < 0)
        return ret;


    if ((ret = virDomainDefPostParseInternal(def, &data)) < 0)
        return ret;

    if (xmlopt->config.assignAddressesCallback) {
        ret = xmlopt->config.assignAddressesCallback(def, caps, parseFlags,
                                                     xmlopt->config.priv,
                                                     parseOpaque);
        if (ret < 0)
            return ret;
    }

    if (virDomainDefPostParseCheckFeatures(def, xmlopt) < 0)
        return -1;

    return 0;
}


/**
 * virDomainDiskAddressDiskBusCompatibility:
 * @bus: disk bus type
 * @addressType: disk address type
 *
 * Check if the specified disk address type @addressType is compatible
 * with the specified disk bus type @bus. This function checks
 * compatibility with the bus types SATA, SCSI, FDC, and IDE only,
 * because only these are handled in common code.
 *
 * Returns true if compatible or can't be decided in common code,
 *         false if known to be not compatible.
 */
static bool
virDomainDiskAddressDiskBusCompatibility(virDomainDiskBus bus,
                                         virDomainDeviceAddressType addressType)
{
    if (addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return true;

    switch (bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_SATA:
        return addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
        return true;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("unexpected bus type '%d'"),
                   bus);
    return true;
}


static int
virDomainDiskDefValidate(const virDomainDiskDef *disk)
{
    /* Validate LUN configuration */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* volumes haven't been translated at this point, so accept them */
        if (!(disk->src->type == VIR_STORAGE_TYPE_BLOCK ||
              disk->src->type == VIR_STORAGE_TYPE_VOLUME ||
              (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
               disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' improperly configured for a "
                             "device='lun'"), disk->dst);
            return -1;
        }
    }

    /* Reject disks with a bus type that is not compatible with the
     * given address type. The function considers only buses that are
     * handled in common code. For other bus types it's not possible
     * to decide compatibility in common code.
     */
    if (!virDomainDiskAddressDiskBusCompatibility(disk->bus, disk->info.type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid address type '%s' for the disk '%s' with the bus type '%s'"),
                       virDomainDeviceAddressTypeToString(disk->info.type),
                       disk->dst,
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    return 0;
}

static bool
virDomainDefHasUSB(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            def->controllers[i]->model != VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            return true;
    }

    return false;
}

static int
virDomainRedirdevDefValidate(const virDomainDef *def,
                             const virDomainRedirdevDef *redirdev)
{
    if (redirdev->bus == VIR_DOMAIN_REDIRDEV_BUS_USB &&
        !virDomainDefHasUSB(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cannot add redirected USB device: "
                         "USB is disabled for this domain"));
        return -1;
    }

    return 0;
}


static int
virDomainNetDefValidate(const virDomainNetDef *net)
{
    if ((net->hostIP.nroutes || net->hostIP.nips) &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid attempt to set network interface "
                         "host-side IP route and/or address info on "
                         "interface of type '%s'. This is only supported "
                         "on interfaces of type 'ethernet'"),
                       virDomainNetTypeToString(net->type));
        return -1;
    }
    return 0;
}


static int
virDomainControllerDefValidate(const virDomainControllerDef *controller)
{
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
        if (controller->idx > 255) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("PCI controller index %d too high, maximum is 255"),
                           controller->idx);
            return -1;
        }
    }
    return 0;
}


static int
virDomainDeviceDefValidateInternal(const virDomainDeviceDef *dev,
                                   const virDomainDef *def)
{
    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        return virDomainDiskDefValidate(dev->data.disk);

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        return virDomainRedirdevDefValidate(def, dev->data.redirdev);

    case VIR_DOMAIN_DEVICE_NET:
        return virDomainNetDefValidate(dev->data.net);

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        return virDomainControllerDefValidate(dev->data.controller);

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    return 0;
}


static int
virDomainDeviceDefValidate(const virDomainDeviceDef *dev,
                           const virDomainDef *def,
                           unsigned int parseFlags,
                           virDomainXMLOptionPtr xmlopt)
{
    /* validate configuration only in certain places */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)
        return 0;

    if (xmlopt->config.deviceValidateCallback &&
        xmlopt->config.deviceValidateCallback(dev, def, xmlopt->config.priv))
        return -1;

    if (virDomainDeviceDefValidateInternal(dev, def) < 0)
        return -1;

    return 0;
}


static int
virDomainDefValidateDeviceIterator(virDomainDefPtr def,
                                   virDomainDeviceDefPtr dev,
                                   virDomainDeviceInfoPtr info ATTRIBUTE_UNUSED,
                                   void *opaque)
{
    struct virDomainDefPostParseDeviceIteratorData *data = opaque;
    return virDomainDeviceDefValidate(dev, def,
                                      data->parseFlags, data->xmlopt);
}


static int
virDomainDefCheckDuplicateDiskInfo(const virDomainDef *def)
{
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        for (j = i + 1; j < def->ndisks; j++) {
            if (virDomainDiskDefCheckDuplicateInfo(def->disks[i],
                                                   def->disks[j]) < 0)
                return -1;
        }
    }

    return 0;
}

/**
 * virDomainDefCheckDuplicateDriveAddresses:
 * @def: domain definition to check against
 *
 * This function checks @def for duplicate drive addresses. Drive
 * addresses are only in use for disks and hostdevs at the moment.
 *
 * Returns 0 in case of there are no duplicate drive addresses, -1
 * otherwise.
 */
static int
virDomainDefCheckDuplicateDriveAddresses(const virDomainDef *def)
{
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk_i = def->disks[i];
        virDomainDeviceInfoPtr disk_info_i = &disk_i->info;

        if (disk_info_i->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        for (j = i + 1; j < def->ndisks; j++) {
            virDomainDiskDefPtr disk_j = def->disks[j];
            virDomainDeviceInfoPtr disk_info_j = &disk_j->info;

            if (disk_i->bus != disk_j->bus)
                continue;

            if (disk_info_j->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
                continue;

            if (virDomainDeviceInfoAddressIsEqual(disk_info_i, disk_info_j)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Found duplicate drive address for disk with "
                                 "target name '%s' controller='%u' bus='%u' "
                                 "target='%u' unit='%u'"),
                               disk_i->dst,
                               disk_info_i->addr.drive.controller,
                               disk_info_i->addr.drive.bus,
                               disk_info_i->addr.drive.target,
                               disk_info_i->addr.drive.unit);
                return -1;
            }
        }

        /* Note: There is no need to check for conflicts with SCSI
         * hostdevs above, because conflicts with hostdevs are checked
         * in the next loop.
         */
    }

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hdev_i = def->hostdevs[i];
        virDomainDeviceInfoPtr hdev_info_i = hdev_i->info;
        virDomainDeviceDriveAddressPtr hdev_addr_i;

        if (!virHostdevIsSCSIDevice(hdev_i))
            continue;

        if (hdev_i->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        hdev_addr_i = &hdev_info_i->addr.drive;
        for (j = i + 1; j < def->nhostdevs; j++) {
            virDomainHostdevDefPtr hdev_j = def->hostdevs[j];
            virDomainDeviceInfoPtr hdev_info_j = hdev_j->info;

            if (!virHostdevIsSCSIDevice(hdev_j))
                continue;

            /* Address type check for hdev_j will be done implicitly
             * in virDomainDeviceInfoAddressIsEqual() */

            if (virDomainDeviceInfoAddressIsEqual(hdev_info_i, hdev_info_j)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("SCSI host address controller='%u' "
                                 "bus='%u' target='%u' unit='%u' in "
                                 "use by another SCSI host device"),
                               hdev_addr_i->bus,
                               hdev_addr_i->controller,
                               hdev_addr_i->target,
                               hdev_addr_i->unit);
                return -1;
            }
        }

        if (virDomainDriveAddressIsUsedByDisk(def, VIR_DOMAIN_DISK_BUS_SCSI,
                                              hdev_addr_i)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("SCSI host address controller='%u' "
                             "bus='%u' target='%u' unit='%u' in "
                             "use by another SCSI disk"),
                           hdev_addr_i->bus,
                           hdev_addr_i->controller,
                           hdev_addr_i->target,
                           hdev_addr_i->unit);
            return -1;
        }
    }

    return 0;
}


static int
virDomainDefValidateInternal(const virDomainDef *def)
{
    if (virDomainDefCheckDuplicateDiskInfo(def) < 0)
        return -1;

    if (virDomainDefCheckDuplicateDriveAddresses(def) < 0)
        return -1;

    if (virDomainDefGetVcpusTopology(def, NULL) < 0)
        return -1;

    return 0;
}


/**
 * virDomainDefValidate:
 * @def: domain definition
 * @caps: driver capabilities object
 * @parseFlags: virDomainDefParseFlags
 * @xmlopt: XML parser option object
 *
 * This validation function is designed to take checks of globally invalid
 * configurations that the parser needs to accept so that VMs don't vanish upon
 * daemon restart. Such definition can be rejected upon startup or define, where
 * this function shall be called.
 *
 * Returns 0 if domain definition is valid, -1 on error and reports an
 * appropriate message.
 */
int
virDomainDefValidate(virDomainDefPtr def,
                     virCapsPtr caps,
                     unsigned int parseFlags,
                     virDomainXMLOptionPtr xmlopt)
{
    struct virDomainDefPostParseDeviceIteratorData data = {
        .caps = caps,
        .xmlopt = xmlopt,
        .parseFlags = parseFlags,
    };

    /* validate configuration only in certain places */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)
        return 0;

    /* call the domain config callback */
    if (xmlopt->config.domainValidateCallback &&
        xmlopt->config.domainValidateCallback(def, caps, xmlopt->config.priv) < 0)
        return -1;

    /* iterate the devices */
    if (virDomainDeviceInfoIterateInternal(def,
                                           virDomainDefValidateDeviceIterator,
                                           true, &data) < 0)
        return -1;

    if (virDomainDefValidateInternal(def) < 0)
        return -1;

    return 0;
}


static void
virDomainVirtioOptionsFormat(virBufferPtr buf,
                             virDomainVirtioOptionsPtr virtio)
{
    if (!virtio)
        return;

    if (virtio->iommu != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " iommu='%s'",
                          virTristateSwitchTypeToString(virtio->iommu));
    }
    if (virtio->ats != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " ats='%s'",
                          virTristateSwitchTypeToString(virtio->ats));
    }
}


/* Generate a string representation of a device address
 * @info address Device address to stringify
 */
static int ATTRIBUTE_NONNULL(2)
virDomainDeviceInfoFormat(virBufferPtr buf,
                          virDomainDeviceInfoPtr info,
                          unsigned int flags)
{
    if ((flags & VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT) && info->bootIndex)
        virBufferAsprintf(buf, "<boot order='%u'/>\n", info->bootIndex);

    if (info->alias &&
        !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)) {
        virBufferAsprintf(buf, "<alias name='%s'/>\n", info->alias);
    }

    if (info->mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB) {
        virBufferAsprintf(buf, "<master startport='%d'/>\n",
                          info->master.usb.startport);
    }

    if ((flags & VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM) &&
        (info->rombar || info->romfile)) {

        virBufferAddLit(buf, "<rom");
        if (info->rombar) {

            const char *rombar = virTristateSwitchTypeToString(info->rombar);

            if (!rombar) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected rom bar value %d"),
                               info->rombar);
                return -1;
            }
            virBufferAsprintf(buf, " bar='%s'", rombar);
        }
        if (info->romfile)
            virBufferEscapeString(buf, " file='%s'", info->romfile);
        virBufferAddLit(buf, "/>\n");
    }

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
        return 0;

    /* We'll be in domain/devices/[device type]/ so 3 level indent */
    virBufferAsprintf(buf, "<address type='%s'",
                      virDomainDeviceAddressTypeToString(info->type));

    switch ((virDomainDeviceAddressType) info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (!virPCIDeviceAddressIsEmpty(&info->addr.pci)) {
            virBufferAsprintf(buf, " domain='0x%.4x' bus='0x%.2x' "
                              "slot='0x%.2x' function='0x%.1x'",
                              info->addr.pci.domain,
                              info->addr.pci.bus,
                              info->addr.pci.slot,
                              info->addr.pci.function);
        }
        if (info->addr.pci.multi) {
           virBufferAsprintf(buf, " multifunction='%s'",
                             virTristateSwitchTypeToString(info->addr.pci.multi));
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        virBufferAsprintf(buf, " controller='%d' bus='%d' target='%d' unit='%d'",
                          info->addr.drive.controller,
                          info->addr.drive.bus,
                          info->addr.drive.target,
                          info->addr.drive.unit);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        virBufferAsprintf(buf, " controller='%d' bus='%d' port='%d'",
                          info->addr.vioserial.controller,
                          info->addr.vioserial.bus,
                          info->addr.vioserial.port);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        virBufferAsprintf(buf, " controller='%d' slot='%d'",
                          info->addr.ccid.controller,
                          info->addr.ccid.slot);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        virBufferAsprintf(buf, " bus='%d'", info->addr.usb.bus);
        if (virDomainUSBAddressPortIsValid(info->addr.usb.port)) {
            virBufferAddLit(buf, " port='");
            virDomainUSBAddressPortFormatBuf(buf, info->addr.usb.port);
            virBufferAddLit(buf, "'");
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (info->addr.spaprvio.has_reg)
            virBufferAsprintf(buf, " reg='0x%llx'", info->addr.spaprvio.reg);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        virBufferAsprintf(buf, " cssid='0x%x' ssid='0x%x' devno='0x%04x'",
                          info->addr.ccw.cssid,
                          info->addr.ccw.ssid,
                          info->addr.ccw.devno);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (info->addr.isa.iobase > 0)
            virBufferAsprintf(buf, " iobase='0x%x'", info->addr.isa.iobase);
        if (info->addr.isa.irq > 0)
            virBufferAsprintf(buf, " irq='0x%x'", info->addr.isa.irq);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        virBufferAsprintf(buf, " slot='%u'", info->addr.dimm.slot);
        if (info->addr.dimm.base)
            virBufferAsprintf(buf, " base='0x%llx'", info->addr.dimm.base);

        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    virBufferAddLit(buf, "/>\n");
    return 0;
}

static int
virDomainDeviceDriveAddressParseXML(xmlNodePtr node,
                                    virDomainDeviceDriveAddressPtr addr)
{
    char *bus, *unit, *controller, *target;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    bus = virXMLPropString(node, "bus");
    target = virXMLPropString(node, "target");
    unit = virXMLPropString(node, "unit");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (target &&
        virStrToLong_uip(target, NULL, 10, &addr->target) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'target' attribute"));
        goto cleanup;
    }

    if (unit &&
        virStrToLong_uip(unit, NULL, 10, &addr->unit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'unit' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(bus);
    VIR_FREE(target);
    VIR_FREE(unit);
    return ret;
}


static int
virDomainDeviceVirtioSerialAddressParseXML(
    xmlNodePtr node,
    virDomainDeviceVirtioSerialAddressPtr addr
)
{
    char *controller, *bus, *port;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    bus = virXMLPropString(node, "bus");
    port = virXMLPropString(node, "port");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (port &&
        virStrToLong_uip(port, NULL, 10, &addr->port) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'port' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(bus);
    VIR_FREE(port);
    return ret;
}

static int
virDomainDeviceCCWAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceCCWAddressPtr addr)
{
    int   ret = -1;
    char *cssid;
    char *ssid;
    char *devno;

    memset(addr, 0, sizeof(*addr));

    cssid = virXMLPropString(node, "cssid");
    ssid = virXMLPropString(node, "ssid");
    devno = virXMLPropString(node, "devno");

    if (cssid && ssid && devno) {
        if (cssid &&
            virStrToLong_uip(cssid, NULL, 0, &addr->cssid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'cssid' attribute"));
            goto cleanup;
        }
        if (ssid &&
            virStrToLong_uip(ssid, NULL, 0, &addr->ssid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'ssid' attribute"));
            goto cleanup;
        }
        if (devno &&
            virStrToLong_uip(devno, NULL, 0, &addr->devno) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'devno' attribute"));
            goto cleanup;
        }
        if (!virDomainDeviceCCWAddressIsValid(addr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid specification for virtio ccw"
                             " address: cssid='%s' ssid='%s' devno='%s'"),
                           cssid, ssid, devno);
            goto cleanup;
        }
        addr->assigned = true;
    } else if (cssid || ssid || devno) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid partial specification for virtio ccw"
                         " address"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cssid);
    VIR_FREE(ssid);
    VIR_FREE(devno);
    return ret;
}

static int
virDomainDeviceCcidAddressParseXML(xmlNodePtr node,
                                   virDomainDeviceCcidAddressPtr addr)
{
    char *controller, *slot;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    slot = virXMLPropString(node, "slot");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (slot &&
        virStrToLong_uip(slot, NULL, 10, &addr->slot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'slot' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(slot);
    return ret;
}

static int
virDomainDeviceUSBAddressParsePort(virDomainDeviceUSBAddressPtr addr,
                                   char *port)
{
    char *tmp = port;
    size_t i;

    for (i = 0; i < VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH; i++) {
        if (virStrToLong_uip(tmp, &tmp, 10, &addr->port[i]) < 0)
            break;

        if (*tmp == '\0')
            return 0;

        if (*tmp == '.')
            tmp++;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Cannot parse <address> 'port' attribute"));
    return -1;
}

static int
virDomainDeviceUSBAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceUSBAddressPtr addr)
{
    char *port, *bus;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    port = virXMLPropString(node, "port");
    bus = virXMLPropString(node, "bus");

    if (port && virDomainDeviceUSBAddressParsePort(addr, port) < 0)
        goto cleanup;

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(bus);
    VIR_FREE(port);
    return ret;
}

static int
virDomainDeviceSpaprVioAddressParseXML(xmlNodePtr node,
                                      virDomainDeviceSpaprVioAddressPtr addr)
{
    char *reg;
    int ret;

    memset(addr, 0, sizeof(*addr));

    reg = virXMLPropString(node, "reg");
    if (reg) {
        if (virStrToLong_ull(reg, NULL, 16, &addr->reg) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'reg' attribute"));
            ret = -1;
            goto cleanup;
        }

        addr->has_reg = true;
    }

    ret = 0;
 cleanup:
    VIR_FREE(reg);
    return ret;
}

static int
virDomainDeviceUSBMasterParseXML(xmlNodePtr node,
                                 virDomainDeviceUSBMasterPtr master)
{
    char *startport;
    int ret = -1;

    memset(master, 0, sizeof(*master));

    startport = virXMLPropString(node, "startport");

    if (startport &&
        virStrToLong_ui(startport, NULL, 10, &master->startport) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <master> 'startport' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(startport);
    return ret;
}

static int
virDomainDeviceBootParseXML(xmlNodePtr node,
                            virDomainDeviceInfoPtr info,
                            virHashTablePtr bootHash)
{
    char *order;
    int ret = -1;

    if (!(order = virXMLPropString(node, "order"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing boot order attribute"));
        goto cleanup;
    }

    if (virStrToLong_uip(order, NULL, 10, &info->bootIndex) < 0 ||
        info->bootIndex == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("incorrect boot order '%s', expecting positive integer"),
                       order);
        goto cleanup;
    }

    if (bootHash) {
        if (virHashLookup(bootHash, order)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("boot order '%s' used for more than one device"),
                           order);
            goto cleanup;
        }

        if (virHashAddEntry(bootHash, order, (void *) 1) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(order);
    return ret;
}

static int
virDomainDeviceISAAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceISAAddressPtr addr)
{
    int ret = -1;
    char *iobase;
    char *irq;

    memset(addr, 0, sizeof(*addr));

    iobase = virXMLPropString(node, "iobase");
    irq = virXMLPropString(node, "irq");

    if (iobase &&
        virStrToLong_uip(iobase, NULL, 16, &addr->iobase) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <address> 'iobase' attribute"));
        goto cleanup;
    }

    if (irq &&
        virStrToLong_uip(irq, NULL, 16, &addr->irq) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Cannot parse <address> 'irq' attribute"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(iobase);
    VIR_FREE(irq);
    return ret;
}


static int
virDomainDeviceDimmAddressParseXML(xmlNodePtr node,
                                   virDomainDeviceDimmAddressPtr addr)
{
    int ret = -1;
    char *tmp = NULL;

    if (!(tmp = virXMLPropString(node, "slot")) ||
        virStrToLong_uip(tmp, NULL, 10, &addr->slot) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid or missing dimm slot id '%s'"),
                       NULLSTR(tmp));
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(node, "base"))) {
        if (virStrToLong_ullp(tmp, NULL, 16, &addr->base) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid dimm base address '%s'"), tmp);
            goto cleanup;
        }

        VIR_FREE(tmp);
    }

    ret = 0;

 cleanup:
    VIR_FREE(tmp);

    return ret;
}


/* Parse the XML definition for a device address
 * @param node XML nodeset to parse for device address definition
 */
static int
virDomainDeviceInfoParseXML(xmlNodePtr node,
                            virHashTablePtr bootHash,
                            virDomainDeviceInfoPtr info,
                            unsigned int flags)
{
    xmlNodePtr cur;
    xmlNodePtr address = NULL;
    xmlNodePtr master = NULL;
    xmlNodePtr alias = NULL;
    xmlNodePtr boot = NULL;
    xmlNodePtr rom = NULL;
    char *type = NULL;
    int ret = -1;

    virDomainDeviceInfoClear(info);

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (alias == NULL &&
                !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
                xmlStrEqual(cur->name, BAD_CAST "alias")) {
                alias = cur;
            } else if (address == NULL &&
                       xmlStrEqual(cur->name, BAD_CAST "address")) {
                address = cur;
            } else if (master == NULL &&
                       xmlStrEqual(cur->name, BAD_CAST "master")) {
                master = cur;
            } else if (boot == NULL &&
                       (flags & VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) &&
                       xmlStrEqual(cur->name, BAD_CAST "boot")) {
                boot = cur;
            } else if (rom == NULL &&
                       (flags & VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) &&
                       xmlStrEqual(cur->name, BAD_CAST "rom")) {
                rom = cur;
            }
        }
        cur = cur->next;
    }

    if (alias)
        info->alias = virXMLPropString(alias, "name");

    if (master) {
        info->mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
        if (virDomainDeviceUSBMasterParseXML(master, &info->master.usb) < 0)
            goto cleanup;
    }

    if (boot) {
        if (virDomainDeviceBootParseXML(boot, info, bootHash))
            goto cleanup;
    }

    if (rom) {
        char *rombar = virXMLPropString(rom, "bar");
        if (rombar &&
            ((info->rombar = virTristateSwitchTypeFromString(rombar)) <= 0)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown rom bar value '%s'"), rombar);
            VIR_FREE(rombar);
            goto cleanup;
        }
        VIR_FREE(rombar);
        info->romfile = virXMLPropString(rom, "file");
    }

    if (!address)
        return 0;

    type = virXMLPropString(address, "type");

    if (type) {
        if ((info->type = virDomainDeviceAddressTypeFromString(type)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown address type '%s'"), type);
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("No type specified for device address"));
        goto cleanup;
    }

    switch ((virDomainDeviceAddressType) info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (virPCIDeviceAddressParseXML(address, &info->addr.pci) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (virDomainDeviceDriveAddressParseXML(address, &info->addr.drive) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        if (virDomainDeviceVirtioSerialAddressParseXML
                (address, &info->addr.vioserial) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        if (virDomainDeviceCcidAddressParseXML(address, &info->addr.ccid) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        if (virDomainDeviceUSBAddressParseXML(address, &info->addr.usb) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (virDomainDeviceSpaprVioAddressParseXML(address, &info->addr.spaprvio) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        if (virDomainDeviceCCWAddressParseXML
                (address, &info->addr.ccw) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (virDomainDeviceISAAddressParseXML(address, &info->addr.isa) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("virtio-s390 bus doesn't have an address"));
        goto cleanup;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (virDomainDeviceDimmAddressParseXML(address, &info->addr.dimm) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    ret = 0;

 cleanup:
    if (ret == -1)
        VIR_FREE(info->alias);
    VIR_FREE(type);
    return ret;
}

static int
virDomainParseLegacyDeviceAddress(char *devaddr,
                                  virPCIDeviceAddressPtr pci)
{
    char *tmp;

    /* expected format: <domain>:<bus>:<slot> */
    if (/* domain */
        virStrToLong_ui(devaddr, &tmp, 16, &pci->domain) < 0 || *tmp != ':' ||
        /* bus */
        virStrToLong_ui(tmp + 1, &tmp, 16, &pci->bus) < 0 || *tmp != ':' ||
        /* slot */
        virStrToLong_ui(tmp + 1, NULL, 16, &pci->slot) < 0)
        return -1;

    return 0;
}

static int
virDomainHostdevSubsysUSBDefParseXML(xmlNodePtr node,
                                     virDomainHostdevDefPtr def)
{

    int ret = -1;
    bool got_product, got_vendor;
    xmlNodePtr cur;
    char *startupPolicy = NULL;
    char *autoAddress;
    virDomainHostdevSubsysUSBPtr usbsrc = &def->source.subsys.u.usb;

    if ((startupPolicy = virXMLPropString(node, "startupPolicy"))) {
        def->startupPolicy =
            virDomainStartupPolicyTypeFromString(startupPolicy);
        if (def->startupPolicy <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown startup policy '%s'"),
                           startupPolicy);
            VIR_FREE(startupPolicy);
            goto out;
        }
        VIR_FREE(startupPolicy);
    }

    if ((autoAddress = virXMLPropString(node, "autoAddress"))) {
        if (STREQ(autoAddress, "yes"))
            usbsrc->autoAddress = true;
        VIR_FREE(autoAddress);
    }

    /* Product can validly be 0, so we need some extra help to determine
     * if it is uninitialized*/
    got_product = false;
    got_vendor = false;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "vendor")) {
                char *vendor = virXMLPropString(cur, "id");

                if (vendor) {
                    got_vendor = true;
                    if (virStrToLong_ui(vendor, NULL, 0, &usbsrc->vendor) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse vendor id %s"), vendor);
                        VIR_FREE(vendor);
                        goto out;
                    }
                    VIR_FREE(vendor);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("usb vendor needs id"));
                    goto out;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "product")) {
                char* product = virXMLPropString(cur, "id");

                if (product) {
                    got_product = true;
                    if (virStrToLong_ui(product, NULL, 0,
                                        &usbsrc->product) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse product %s"),
                                       product);
                        VIR_FREE(product);
                        goto out;
                    }
                    VIR_FREE(product);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("usb product needs id"));
                    goto out;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "address")) {
                char *bus, *device;

                bus = virXMLPropString(cur, "bus");
                if (bus) {
                    if (virStrToLong_ui(bus, NULL, 0, &usbsrc->bus) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse bus %s"), bus);
                        VIR_FREE(bus);
                        goto out;
                    }
                    VIR_FREE(bus);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("usb address needs bus id"));
                    goto out;
                }

                device = virXMLPropString(cur, "device");
                if (device) {
                    if (virStrToLong_ui(device, NULL, 0, &usbsrc->device) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse device %s"),
                                       device);
                        VIR_FREE(device);
                        goto out;
                    }
                    VIR_FREE(device);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("usb address needs device id"));
                    goto out;
                }
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown usb source type '%s'"),
                               cur->name);
                goto out;
            }
        }
        cur = cur->next;
    }

    if (got_vendor && usbsrc->vendor == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("vendor cannot be 0."));
        goto out;
    }

    if (!got_vendor && got_product) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing vendor"));
        goto out;
    }
    if (got_vendor && !got_product) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing product"));
        goto out;
    }

    ret = 0;
 out:
    return ret;
}

/* The internal XML for host PCI device's original states:
 *
 * <origstates>
 *   <unbind/>
 *   <removeslot/>
 *   <reprobe/>
 * </origstates>
 */
static int
virDomainHostdevSubsysPCIOrigStatesDefParseXML(xmlNodePtr node,
                                               virDomainHostdevOrigStatesPtr def)
{
    xmlNodePtr cur;
    cur = node->children;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "unbind")) {
                def->states.pci.unbind_from_stub = true;
            } else if (xmlStrEqual(cur->name, BAD_CAST "removeslot")) {
                def->states.pci.remove_slot = true;
            } else if (xmlStrEqual(cur->name, BAD_CAST "reprobe")) {
                def->states.pci.reprobe = true;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported element '%s' of 'origstates'"),
                               cur->name);
                return -1;
            }
        }
        cur = cur->next;
    }

    return 0;
}

static int
virDomainHostdevSubsysPCIDefParseXML(xmlNodePtr node,
                                     virDomainHostdevDefPtr def,
                                     unsigned int flags)
{
    int ret = -1;
    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "address")) {
                virPCIDeviceAddressPtr addr =
                    &def->source.subsys.u.pci.addr;

                if (virPCIDeviceAddressParseXML(cur, addr) < 0)
                    goto out;
            } else if ((flags & VIR_DOMAIN_DEF_PARSE_STATUS) &&
                       xmlStrEqual(cur->name, BAD_CAST "state")) {
                /* Legacy back-compat. Don't add any more attributes here */
                char *devaddr = virXMLPropString(cur, "devaddr");
                if (devaddr &&
                    virDomainParseLegacyDeviceAddress(devaddr,
                                                      &def->info->addr.pci) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to parse devaddr parameter '%s'"),
                                   devaddr);
                    VIR_FREE(devaddr);
                    goto out;
                }
                def->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            } else if ((flags & VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES) &&
                       xmlStrEqual(cur->name, BAD_CAST "origstates")) {
                virDomainHostdevOrigStatesPtr states = &def->origstates;
                if (virDomainHostdevSubsysPCIOrigStatesDefParseXML(cur, states) < 0)
                    goto out;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown pci source type '%s'"),
                               cur->name);
                goto out;
            }
        }
        cur = cur->next;
    }

    ret = 0;
 out:
    return ret;
}

static int
virDomainStorageHostParse(xmlNodePtr node,
                          virStorageNetHostDefPtr *hosts,
                          size_t *nhosts)
{
    int ret = -1;
    xmlNodePtr child;
    char *transport = NULL;
    virStorageNetHostDef host;

    memset(&host, 0, sizeof(host));

    child = node->children;
    while (child != NULL) {
        if (child->type == XML_ELEMENT_NODE &&
            xmlStrEqual(child->name, BAD_CAST "host")) {

            host.transport = VIR_STORAGE_NET_HOST_TRANS_TCP;

            /* transport can be tcp (default), unix or rdma.  */
            if ((transport = virXMLPropString(child, "transport"))) {
                host.transport = virStorageNetHostTransportTypeFromString(transport);
                if (host.transport < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown protocol transport type '%s'"),
                                   transport);
                    goto cleanup;
                }
            }

            host.socket = virXMLPropString(child, "socket");

            if (host.transport == VIR_STORAGE_NET_HOST_TRANS_UNIX &&
                host.socket == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing socket for unix transport"));
                goto cleanup;
            }

            if (host.transport != VIR_STORAGE_NET_HOST_TRANS_UNIX &&
                host.socket != NULL) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("transport '%s' does not support "
                                 "socket attribute"),
                               transport);
                goto cleanup;
            }

            VIR_FREE(transport);

            if (host.transport != VIR_STORAGE_NET_HOST_TRANS_UNIX) {
                if (!(host.name = virXMLPropString(child, "name"))) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("missing name for host"));
                    goto cleanup;
                }

                host.port = virXMLPropString(child, "port");
            }

            if (VIR_APPEND_ELEMENT(*hosts, *nhosts, host) < 0)
                goto cleanup;
        }
        child = child->next;
    }
    ret = 0;

 cleanup:
    virStorageNetHostDefClear(&host);
    VIR_FREE(transport);
    return ret;
}

static int
virDomainHostdevSubsysSCSIHostDefParseXML(xmlNodePtr sourcenode,
                                          virDomainHostdevSubsysSCSIPtr scsisrc)
{
    int ret = -1;
    bool got_address = false, got_adapter = false;
    xmlNodePtr cur;
    char *bus = NULL, *target = NULL, *unit = NULL;
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;

    cur = sourcenode->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "address")) {
                if (got_address) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("more than one source addresses is "
                                     "specified for scsi hostdev"));
                    goto cleanup;
                }

                if (!(bus = virXMLPropString(cur, "bus")) ||
                    !(target = virXMLPropString(cur, "target")) ||
                    !(unit = virXMLPropString(cur, "unit"))) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("'bus', 'target', and 'unit' must be specified "
                                     "for scsi hostdev source address"));
                    goto cleanup;
                }

                if (virStrToLong_uip(bus, NULL, 0, &scsihostsrc->bus) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot parse bus '%s'"), bus);
                    goto cleanup;
                }

                if (virStrToLong_uip(target, NULL, 0,
                                    &scsihostsrc->target) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot parse target '%s'"), target);
                    goto cleanup;
                }

                if (virStrToLong_ullp(unit, NULL, 0, &scsihostsrc->unit) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot parse unit '%s'"), unit);
                    goto cleanup;
                }

                got_address = true;
            } else if (xmlStrEqual(cur->name, BAD_CAST "adapter")) {
                if (got_adapter) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("more than one adapters is specified "
                                     "for scsi hostdev source"));
                    goto cleanup;
                }
                if (!(scsihostsrc->adapter = virXMLPropString(cur, "name"))) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("'adapter' must be specified for scsi hostdev source"));
                    goto cleanup;
                }

                got_adapter = true;
            } else {
                virReportError(VIR_ERR_XML_ERROR,
                               _("unsupported element '%s' of scsi hostdev source"),
                               cur->name);
                goto cleanup;
            }
        }
        cur = cur->next;
    }

    if (!got_address || !got_adapter) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'adapter' and 'address' must be specified for scsi "
                         "hostdev source"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(bus);
    VIR_FREE(target);
    VIR_FREE(unit);
    return ret;
}

static int
virDomainHostdevSubsysSCSIiSCSIDefParseXML(xmlNodePtr sourcenode,
                                           virDomainHostdevSubsysSCSIPtr def)
{
    int ret = -1;
    int auth_secret_usage = -1;
    xmlNodePtr cur;
    virStorageAuthDefPtr authdef = NULL;
    virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &def->u.iscsi;

    /* Similar to virDomainDiskSourceParse for a VIR_STORAGE_TYPE_NETWORK */

    if (!(iscsisrc->path = virXMLPropString(sourcenode, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing iSCSI hostdev source path name"));
        goto cleanup;
    }

    if (virDomainStorageHostParse(sourcenode, &iscsisrc->hosts,
                                  &iscsisrc->nhosts) < 0)
        goto cleanup;

    if (iscsisrc->nhosts < 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing the host address for the iSCSI hostdev"));
        goto cleanup;
    }
    if (iscsisrc->nhosts > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one source host address may be specified "
                         "for the iSCSI hostdev"));
        goto cleanup;
    }

    cur = sourcenode->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "auth")) {
            if (!(authdef = virStorageAuthDefParse(sourcenode->doc, cur)))
                goto cleanup;
            if ((auth_secret_usage =
                 virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid secret type %s"),
                               authdef->secrettype);
                goto cleanup;
            }
            if (auth_secret_usage != VIR_SECRET_USAGE_TYPE_ISCSI) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("hostdev invalid secret type '%s'"),
                               authdef->secrettype);
                goto cleanup;
            }
            iscsisrc->auth = authdef;
            authdef = NULL;
        }
        cur = cur->next;
    }
    ret = 0;

 cleanup:
    virStorageAuthDefFree(authdef);
    return ret;
}

static int
virDomainHostdevSubsysSCSIDefParseXML(xmlNodePtr sourcenode,
                                      virDomainHostdevSubsysSCSIPtr scsisrc)
{
    char *protocol = NULL;
    int ret = -1;

    if ((protocol = virXMLPropString(sourcenode, "protocol"))) {
        scsisrc->protocol =
            virDomainHostdevSubsysSCSIProtocolTypeFromString(protocol);
        if (scsisrc->protocol < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown SCSI subsystem protocol '%s'"),
                           protocol);
            goto cleanup;
        }
    }

    if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
        ret = virDomainHostdevSubsysSCSIiSCSIDefParseXML(sourcenode, scsisrc);
    else
        ret = virDomainHostdevSubsysSCSIHostDefParseXML(sourcenode, scsisrc);

 cleanup:
    VIR_FREE(protocol);
    return ret;
}

static int
virDomainHostdevSubsysSCSIVHostDefParseXML(xmlNodePtr sourcenode,
                                           virDomainHostdevDefPtr def)
{
    char *protocol = NULL;
    char *wwpn = NULL;
    virDomainHostdevSubsysSCSIVHostPtr hostsrc = &def->source.subsys.u.scsi_host;
    int ret = -1;

    if (!(protocol = virXMLPropString(sourcenode, "protocol"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing scsi_host subsystem protocol"));
        return ret;
    }

    if ((hostsrc->protocol =
         virDomainHostdevSubsysSCSIHostProtocolTypeFromString(protocol)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown scsi_host subsystem protocol '%s'"),
                       protocol);
        goto cleanup;
    }

    switch ((virDomainHostdevSubsysSCSIHostProtocolType) hostsrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST:
        if (!(wwpn = virXMLPropString(sourcenode, "wwpn"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing vhost-scsi hostdev source wwpn"));
            goto cleanup;
        }

        if (!STRPREFIX(wwpn, "naa.") ||
            !virValidateWWN(wwpn + 4)) {
            virReportError(VIR_ERR_XML_ERROR, "%s", _("malformed 'wwpn' value"));
            goto cleanup;
        }
        hostsrc->wwpn = wwpn;
        wwpn = NULL;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_NONE:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_LAST:
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid hostdev protocol '%s'"),
                       virDomainHostdevSubsysSCSIHostProtocolTypeToString(hostsrc->protocol));
        goto cleanup;
        break;
    }

    ret = 0;
 cleanup:
    VIR_FREE(wwpn);
    VIR_FREE(protocol);
    return ret;
}

static int
virDomainHostdevSubsysMediatedDevDefParseXML(virDomainHostdevDefPtr def,
                                             xmlXPathContextPtr ctxt)
{
    int ret = -1;
    unsigned char uuid[VIR_UUID_BUFLEN] = {0};
    char *uuidxml = NULL;
    xmlNodePtr node = NULL;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &def->source.subsys.u.mdev;

    if (!(node = virXPathNode("./source/address", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing <address> element"));
        goto cleanup;
    }

    if (!(uuidxml = virXMLPropString(node, "uuid"))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing 'uuid' attribute for element <address>"));
        goto cleanup;
    }

    if (virUUIDParse(uuidxml, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Cannot parse uuid attribute of element <address>"));
        goto cleanup;
    }

    virUUIDFormat(uuid, mdevsrc->uuidstr);
    ret = 0;
 cleanup:
    VIR_FREE(uuidxml);
    return ret;
}

static int
virDomainHostdevDefParseXMLSubsys(xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  const char *type,
                                  virDomainHostdevDefPtr def,
                                  unsigned int flags)
{
    xmlNodePtr sourcenode;
    char *managed = NULL;
    char *sgio = NULL;
    char *rawio = NULL;
    char *backendStr = NULL;
    char *model = NULL;
    int backend;
    int ret = -1;
    virDomainHostdevSubsysPCIPtr pcisrc = &def->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &def->source.subsys.u.mdev;

    /* @managed can be read from the xml document - it is always an
     * attribute of the toplevel element, no matter what type of
     * element that might be (pure hostdev, or higher level device
     * (e.g. <interface>) with type='hostdev')
     */
    if ((managed = virXMLPropString(node, "managed")) != NULL) {
        if (STREQ(managed, "yes"))
            def->managed = true;
    }

    sgio = virXMLPropString(node, "sgio");
    rawio = virXMLPropString(node, "rawio");
    model = virXMLPropString(node, "model");

    /* @type is passed in from the caller rather than read from the
     * xml document, because it is specified in different places for
     * different kinds of defs - it is an attribute of
     * <source>/<address> for an intelligent hostdev (<interface>),
     * but an attribute of the toplevel element for a standard
     * <hostdev>.  (the functions we're going to call expect address
     * type to already be known).
     */
    if (type) {
        if ((def->source.subsys.type
             = virDomainHostdevSubsysTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown host device source address type '%s'"),
                           type);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("missing source address type"));
        goto error;
    }

    if (!(sourcenode = virXPathNode("./source", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <source> element in hostdev device"));
        goto error;
    }

    if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
        virXPathBoolean("boolean(./source/@startupPolicy)", ctxt)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting startupPolicy is only allowed for USB"
                         " devices"));
        goto error;
    }

    if (sgio) {
        if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("sgio is only supported for scsi host device"));
            goto error;
        }

        if ((scsisrc->sgio = virDomainDeviceSGIOTypeFromString(sgio)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown sgio mode '%s'"), sgio);
            goto error;
        }
    }

    if (rawio) {
        if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("rawio is only supported for scsi host device"));
            goto error;
        }

        if ((scsisrc->rawio = virTristateBoolTypeFromString(rawio)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown hostdev rawio setting '%s'"),
                           rawio);
            goto error;
        }
    }

    if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV) {
        if (model) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'model' attribute in <hostdev> is only supported "
                             "when type='mdev'"));
            goto error;
        }
    } else {
        if (!model) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'model' attribute in mediated device's "
                             "<hostdev> element"));
            goto error;
        }

        if ((mdevsrc->model = virMediatedDeviceModelTypeFromString(model)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown hostdev model '%s'"),
                           model);
            goto error;
        }
    }

    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (virDomainHostdevSubsysPCIDefParseXML(sourcenode, def, flags) < 0)
            goto error;

        backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT;
        if ((backendStr = virXPathString("string(./driver/@name)", ctxt)) &&
            (((backend = virDomainHostdevSubsysPCIBackendTypeFromString(backendStr)) < 0) ||
             backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown PCI device <driver name='%s'/> "
                             "has been specified"), backendStr);
            goto error;
        }
        pcisrc->backend = backend;

        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (virDomainHostdevSubsysUSBDefParseXML(sourcenode, def) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (virDomainHostdevSubsysSCSIDefParseXML(sourcenode, scsisrc) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        if (virDomainHostdevSubsysSCSIVHostDefParseXML(sourcenode, def) < 0)
            goto error;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        if (virDomainHostdevSubsysMediatedDevDefParseXML(def, ctxt) < 0)
            goto error;
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("address type='%s' not supported in hostdev interfaces"),
                       virDomainHostdevSubsysTypeToString(def->source.subsys.type));
        goto error;
    }

    ret = 0;
 error:
    VIR_FREE(managed);
    VIR_FREE(sgio);
    VIR_FREE(rawio);
    VIR_FREE(backendStr);
    VIR_FREE(model);
    return ret;
}

static virNetDevIPAddrPtr
virDomainNetIPParseXML(xmlNodePtr node)
{
    /* Parse the prefix in every case */
    virNetDevIPAddrPtr ip = NULL, ret = NULL;
    char *prefixStr = NULL;
    unsigned int prefixValue = 0;
    char *familyStr = NULL;
    int family = AF_UNSPEC;
    char *address = NULL, *peer = NULL;

    if (!(address = virXMLPropString(node, "address"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing required address in <ip>"));
        goto cleanup;
    }

    familyStr = virXMLPropString(node, "family");
    if (familyStr && STREQ(familyStr, "ipv4"))
        family = AF_INET;
    else if (familyStr && STREQ(familyStr, "ipv6"))
        family = AF_INET6;
    else
        family = virSocketAddrNumericFamily(address);

    if (VIR_ALLOC(ip) < 0)
        goto cleanup;

    if (virSocketAddrParse(&ip->address, address, family) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid address '%s' in <ip>"),
                       address);
        goto cleanup;
    }

    prefixStr = virXMLPropString(node, "prefix");
    if (prefixStr &&
        ((virStrToLong_ui(prefixStr, NULL, 10, &prefixValue) < 0) ||
         (family == AF_INET6 && prefixValue > 128) ||
         (family == AF_INET && prefixValue > 32))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid prefix value '%s' in <ip>"),
                       prefixStr);
        goto cleanup;
    }
    ip->prefix = prefixValue;

    if ((peer = virXMLPropString(node, "peer")) != NULL &&
        virSocketAddrParse(&ip->peer, peer, family) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid peer '%s' in <ip>"), peer);
        goto cleanup;
    }

    ret = ip;
    ip = NULL;

 cleanup:
    VIR_FREE(prefixStr);
    VIR_FREE(familyStr);
    VIR_FREE(address);
    VIR_FREE(peer);
    VIR_FREE(ip);
    return ret;
}


/* fill in a virNetDevIPInfoPtr from the <route> and <ip>
 * elements found in the given XML context.
 *
 * return 0 on success (including none found) and -1 on failure.
 */
static int
virDomainNetIPInfoParseXML(const char *source,
                           xmlXPathContextPtr ctxt,
                           virNetDevIPInfoPtr def)
{
    xmlNodePtr *nodes = NULL;
    virNetDevIPAddrPtr ip = NULL;
    virNetDevIPRoutePtr route = NULL;
    int nnodes;
    int ret = -1;
    size_t i;

    if ((nnodes = virXPathNodeSet("./ip", ctxt, &nodes)) < 0)
        goto cleanup;

    for (i = 0; i < nnodes; i++) {
        if (!(ip = virDomainNetIPParseXML(nodes[i])) ||
            VIR_APPEND_ELEMENT(def->ips, def->nips, ip) < 0)
            goto cleanup;
    }
    VIR_FREE(nodes);

    if ((nnodes = virXPathNodeSet("./route", ctxt, &nodes)) < 0)
        goto cleanup;

    for (i = 0; i < nnodes; i++) {
        if (!(route = virNetDevIPRouteParseXML(source, nodes[i], ctxt)) ||
            VIR_APPEND_ELEMENT(def->routes, def->nroutes, route) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    if (ret < 0)
        virNetDevIPInfoClear(def);
    VIR_FREE(ip);
    virNetDevIPRouteFree(route);
    VIR_FREE(nodes);
    return ret;
}


static virNetDevCoalescePtr
virDomainNetDefCoalesceParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt)
{
    virNetDevCoalescePtr ret = NULL;
    xmlNodePtr save = NULL;
    char *str = NULL;
    unsigned long long tmp = 0;

    save = ctxt->node;
    ctxt->node = node;

    str = virXPathString("string(./rx/frames/@max)", ctxt);
    if (!str)
        goto cleanup;

    if (VIR_ALLOC(ret) < 0)
        goto cleanup;

    if (virStrToLong_ullp(str, NULL, 10, &tmp) < 0) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("cannot parse value '%s' for coalesce parameter"),
                       str);
        VIR_FREE(str);
        goto error;
    }
    VIR_FREE(str);

    if (tmp > UINT32_MAX) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("value '%llu' is too big for coalesce "
                         "parameter, maximum is '%lu'"),
                       tmp, (unsigned long) UINT32_MAX);
        goto error;
    }
    ret->rx_max_coalesced_frames = tmp;

 cleanup:
    VIR_FREE(str);
    ctxt->node = save;
    return ret;

 error:
    VIR_FREE(ret);
    goto cleanup;
}

static void
virDomainNetDefCoalesceFormatXML(virBufferPtr buf,
                                 virNetDevCoalescePtr coalesce)
{
    if (!coalesce || !coalesce->rx_max_coalesced_frames)
        return;

    virBufferAddLit(buf, "<coalesce>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAddLit(buf, "<rx>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<frames max='%u'/>\n",
                      coalesce->rx_max_coalesced_frames);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</rx>\n");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</coalesce>\n");
}


static int
virDomainHostdevDefParseXMLCaps(xmlNodePtr node ATTRIBUTE_UNUSED,
                                xmlXPathContextPtr ctxt,
                                const char *type,
                                virDomainHostdevDefPtr def)
{
    xmlNodePtr sourcenode;
    int ret = -1;

    /* @type is passed in from the caller rather than read from the
     * xml document, because it is specified in different places for
     * different kinds of defs - it is an attribute of
     * <source>/<address> for an intelligent hostdev (<interface>),
     * but an attribute of the toplevel element for a standard
     * <hostdev>.  (the functions we're going to call expect address
     * type to already be known).
     */
    if (type) {
        if ((def->source.caps.type
             = virDomainHostdevCapsTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown host device source address type '%s'"),
                           type);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("missing source address type"));
        goto error;
    }

    if (!(sourcenode = virXPathNode("./source", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <source> element in hostdev device"));
        goto error;
    }

    switch (def->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        if (!(def->source.caps.u.storage.block =
              virXPathString("string(./source/block[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <block> element in hostdev storage device"));
            goto error;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        if (!(def->source.caps.u.misc.chardev =
              virXPathString("string(./source/char[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <char> element in hostdev character device"));
            goto error;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        if (!(def->source.caps.u.net.ifname =
              virXPathString("string(./source/interface[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <interface> element in hostdev net device"));
            goto error;
        }
        if (virDomainNetIPInfoParseXML(_("Domain hostdev device"),
                                       ctxt, &def->source.caps.u.net.ip) < 0)
            goto error;
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("address type='%s' not supported in hostdev interfaces"),
                       virDomainHostdevCapsTypeToString(def->source.caps.type));
        goto error;
    }
    ret = 0;
 error:
    return ret;
}

int
virDomainDeviceFindControllerModel(const virDomainDef *def,
                                   virDomainDeviceInfoPtr info,
                                   int controllerType)
{
    int model = -1;
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == controllerType &&
            def->controllers[i]->idx == info->addr.drive.controller)
            model = def->controllers[i]->model;
    }

    return model;
}

virDomainDiskDefPtr
virDomainDiskFindByBusAndDst(virDomainDefPtr def,
                             int bus,
                             char *dst)
{
    size_t i;

    if (!dst)
        return NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->bus == bus &&
            STREQ(def->disks[i]->dst, dst)) {
            return def->disks[i];
        }
    }

    return NULL;
}


int
virDomainDiskDefAssignAddress(virDomainXMLOptionPtr xmlopt,
                              virDomainDiskDefPtr def,
                              const virDomainDef *vmdef)
{
    int idx = virDiskNameToIndex(def->dst);
    if (idx < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unknown disk name '%s' and no address specified"),
                       def->dst);
        return -1;
    }

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI: {
        virDomainDeviceDriveAddress addr = {0, 0, 0, 0};
        unsigned int controller;
        unsigned int unit;

        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        if (xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_WIDE_SCSI) {
            /* For a wide SCSI bus we define the default mapping to be
             * 16 units per bus, 1 bus per controller, many controllers.
             * Unit 7 is the SCSI controller itself. Therefore unit 7
             * cannot be assigned to disks and is skipped.
             */
            controller = idx / 15;
            unit = idx % 15;

            /* Skip the SCSI controller at unit 7 */
            if (unit >= 7)
                ++unit;
        } else {
            /* For a narrow SCSI bus we define the default mapping to be
             * 7 units per bus, 1 bus per controller, many controllers */
            controller = idx / 7;
            unit = idx % 7;
        }

        addr.controller = controller;
        addr.unit = unit;

        if (virDomainDriveAddressIsUsedByHostdev(vmdef,
                                                 VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI,
                                                 &addr)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("using disk target name '%s' conflicts with "
                             "SCSI host device address controller='%u' "
                             "bus='%u' target='%u' unit='%u"),
                           def->dst, controller, 0, 0, unit);
            return -1;
        }

        memcpy(&def->info.addr.drive, &addr, sizeof(addr));
        break;
    }

    case VIR_DOMAIN_DISK_BUS_IDE:
        /* For IDE we define the default mapping to be 2 units
         * per bus, 2 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 4;
        def->info.addr.drive.bus = (idx % 4) / 2;
        def->info.addr.drive.unit = (idx % 2);
        break;

    case VIR_DOMAIN_DISK_BUS_SATA:
        /* For SATA we define the default mapping to be 6 units
         * per bus, 1 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 6;
        def->info.addr.drive.bus = 0;
        def->info.addr.drive.unit = idx % 6;
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        /* For FDC we define the default mapping to be 2 units
         * per bus, 1 bus per controller, many controllers */
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
        def->info.addr.drive.controller = idx / 2;
        def->info.addr.drive.bus = 0;
        def->info.addr.drive.unit = idx % 2;
        break;

    default:
        /* Other disk bus's aren't controller based */
        break;
    }

    return 0;
}

static virSecurityLabelDefPtr
virSecurityLabelDefParseXML(xmlXPathContextPtr ctxt,
                            unsigned int flags)
{
    char *p;
    virSecurityLabelDefPtr seclabel = NULL;

    p = virXPathStringLimit("string(./@model)",
                            VIR_SECURITY_MODEL_BUFLEN - 1, ctxt);

    if (!(seclabel = virSecurityLabelDefNew(p)))
        goto error;
    VIR_FREE(p);

    /* set default value */
    seclabel->type = VIR_DOMAIN_SECLABEL_DYNAMIC;

    p = virXPathStringLimit("string(./@type)",
                            VIR_SECURITY_LABEL_BUFLEN - 1, ctxt);
    if (p) {
        seclabel->type = virDomainSeclabelTypeFromString(p);
        if (seclabel->type <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid security type '%s'"), p);
            goto error;
        }
    }

    if (seclabel->type == VIR_DOMAIN_SECLABEL_STATIC ||
        seclabel->type == VIR_DOMAIN_SECLABEL_NONE)
        seclabel->relabel = false;

    VIR_FREE(p);
    p = virXPathStringLimit("string(./@relabel)",
                            VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
    if (p) {
        if (STREQ(p, "yes")) {
            seclabel->relabel = true;
        } else if (STREQ(p, "no")) {
            seclabel->relabel = false;
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid security relabel value %s"), p);
            goto error;
        }
    }
    VIR_FREE(p);

    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        !seclabel->relabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("dynamic label type must use resource relabeling"));
        goto error;
    }
    if (seclabel->type == VIR_DOMAIN_SECLABEL_NONE &&
        seclabel->relabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("resource relabeling is not compatible with 'none' label type"));
        goto error;
    }

    /* For the model 'none' none of the following labels is going to be
     * present. Hence, return now. */

    if (STREQ_NULLABLE(seclabel->model, "none")) {
        if (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) {
            /* Fix older configurations */
            seclabel->type = VIR_DOMAIN_SECLABEL_NONE;
            seclabel->relabel = false;
        } else {
            if (seclabel->type != VIR_DOMAIN_SECLABEL_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported type='%s' to model 'none'"),
                               virDomainSeclabelTypeToString(seclabel->type));
                goto error;
            }
            /* combination of relabel='yes' and type='static'
             * is checked a few lines above. */
        }
        return seclabel;
    }

    /* Only parse label, if using static labels, or
     * if the 'live' VM XML is requested
     */
    if (seclabel->type == VIR_DOMAIN_SECLABEL_STATIC ||
        (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
         seclabel->type != VIR_DOMAIN_SECLABEL_NONE)) {
        p = virXPathStringLimit("string(./label[1])",
                                VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        if (p == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("security label is missing"));
            goto error;
        }

        seclabel->label = p;
        p = NULL;
    }

    /* Only parse imagelabel, if requested live XML with relabeling */
    if (seclabel->relabel &&
        (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
         seclabel->type != VIR_DOMAIN_SECLABEL_NONE)) {
        p = virXPathStringLimit("string(./imagelabel[1])",
                                VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        if (p == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("security imagelabel is missing"));
            goto error;
        }
        seclabel->imagelabel = p;
        p = NULL;
    }

    /* Only parse baselabel for dynamic label type */
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        p = virXPathStringLimit("string(./baselabel[1])",
                                VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        seclabel->baselabel = p;
        p = NULL;
    }

    return seclabel;

 error:
    VIR_FREE(p);
    virSecurityLabelDefFree(seclabel);
    return NULL;
}

static int
virSecurityLabelDefsParseXML(virDomainDefPtr def,
                             xmlXPathContextPtr ctxt,
                             virCapsPtr caps,
                             unsigned int flags)
{
    size_t i = 0, j;
    int n;
    xmlNodePtr *list = NULL, saved_node;
    virCapsHostPtr host = &caps->host;

    /* Check args and save context */
    if (def == NULL || ctxt == NULL)
        return 0;
    saved_node = ctxt->node;

    /* Allocate a security labels based on XML */
    if ((n = virXPathNodeSet("./seclabel", ctxt, &list)) < 0)
        goto error;
    if (n == 0)
        return 0;

    if (VIR_ALLOC_N(def->seclabels, n) < 0)
        goto error;

    /* Parse each "seclabel" tag */
    for (i = 0; i < n; i++) {
        virSecurityLabelDefPtr seclabel;

        ctxt->node = list[i];
        if (!(seclabel = virSecurityLabelDefParseXML(ctxt, flags)))
            goto error;

        for (j = 0; j < i; j++) {
            if (STREQ_NULLABLE(seclabel->model, def->seclabels[j]->model)) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("seclabel for model %s is already provided"),
                               seclabel->model);
                virSecurityLabelDefFree(seclabel);
                goto error;
            }
        }

        def->seclabels[i] = seclabel;
    }
    def->nseclabels = n;
    ctxt->node = saved_node;
    VIR_FREE(list);

    /* libvirt versions prior to 0.10.0 support just a single seclabel element
     * in guest's XML and model attribute can be suppressed if type is none or
     * type is dynamic, baselabel is not defined and INACTIVE flag is set.
     *
     * To avoid compatibility issues, for this specific case the first model
     * defined in host's capabilities is used as model for the seclabel.
     */
    if (def->nseclabels == 1 &&
        !def->seclabels[0]->model &&
        host->nsecModels > 0) {
        if (def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_NONE ||
            (def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
             !def->seclabels[0]->baselabel &&
             (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
            /* Copy model from host. */
            VIR_DEBUG("Found seclabel without a model, using '%s'",
                      host->secModels[0].model);
            if (VIR_STRDUP(def->seclabels[0]->model, host->secModels[0].model) < 0)
                goto error;

            if (STREQ(def->seclabels[0]->model, "none") &&
                flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) {
                /* Fix older configurations */
                def->seclabels[0]->type = VIR_DOMAIN_SECLABEL_NONE;
                def->seclabels[0]->relabel = false;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing security model in domain seclabel"));
            goto error;
        }
    }

    /* Checking missing model information */
    if (def->nseclabels > 1) {
        for (; n; n--) {
            if (def->seclabels[n - 1]->model == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing security model "
                                 "when using multiple labels"));
                goto error;
            }
        }
    }

    return 0;

 error:
    ctxt->node = saved_node;
    for (; i > 0; i--)
        virSecurityLabelDefFree(def->seclabels[i - 1]);
    VIR_FREE(def->seclabels);
    def->nseclabels = 0;
    VIR_FREE(list);
    return -1;
}

/* Parse the <seclabel> from a disk or character device. */
static int
virSecurityDeviceLabelDefParseXML(virSecurityDeviceLabelDefPtr **seclabels_rtn,
                                  size_t *nseclabels_rtn,
                                  virSecurityLabelDefPtr *vmSeclabels,
                                  int nvmSeclabels, xmlXPathContextPtr ctxt,
                                  unsigned int flags)
{
    virSecurityDeviceLabelDefPtr *seclabels = NULL;
    size_t nseclabels = 0;
    int n;
    size_t i, j;
    xmlNodePtr *list = NULL;
    virSecurityLabelDefPtr vmDef = NULL;
    char *model, *relabel, *label, *labelskip;

    if ((n = virXPathNodeSet("./seclabel", ctxt, &list)) < 0)
        goto error;
    if (n == 0)
        return 0;

    if (VIR_ALLOC_N(seclabels, n) < 0)
        goto error;
    nseclabels = n;
    for (i = 0; i < n; i++) {
        if (VIR_ALLOC(seclabels[i]) < 0)
            goto error;
    }

    for (i = 0; i < n; i++) {
        /* get model associated to this override */
        model = virXMLPropString(list[i], "model");
        if (model) {
            /* find the security label that it's being overridden */
            for (j = 0; j < nvmSeclabels; j++) {
                if (STREQ(vmSeclabels[j]->model, model)) {
                    vmDef = vmSeclabels[j];
                    break;
                }
            }

            /* check for duplicate seclabels */
            for (j = 0; j < i; j++) {
                if (STREQ_NULLABLE(model, seclabels[j]->model)) {
                    virReportError(VIR_ERR_XML_DETAIL,
                                   _("seclabel for model %s is already provided"), model);
                    goto error;
                }
            }
            seclabels[i]->model = model;
        }

        /* Can't use overrides if top-level doesn't allow relabeling.  */
        if (vmDef && !vmDef->relabel) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("label overrides require relabeling to be "
                             "enabled at the domain level"));
            goto error;
        }

        relabel = virXMLPropString(list[i], "relabel");
        if (relabel != NULL) {
            if (STREQ(relabel, "yes")) {
                seclabels[i]->relabel = true;
            } else if (STREQ(relabel, "no")) {
                seclabels[i]->relabel = false;
            } else {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid security relabel value %s"),
                               relabel);
                VIR_FREE(relabel);
                goto error;
            }
            VIR_FREE(relabel);
        } else {
            seclabels[i]->relabel = true;
        }

        /* labelskip is only parsed on live images */
        labelskip = virXMLPropString(list[i], "labelskip");
        seclabels[i]->labelskip = false;
        if (labelskip && !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
            seclabels[i]->labelskip = STREQ(labelskip, "yes");
        VIR_FREE(labelskip);

        ctxt->node = list[i];
        label = virXPathStringLimit("string(./label)",
                                    VIR_SECURITY_LABEL_BUFLEN-1, ctxt);
        seclabels[i]->label = label;

        if (label && !seclabels[i]->relabel) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot specify a label if relabelling is "
                             "turned off. model=%s"),
                             NULLSTR(seclabels[i]->model));
            goto error;
        }
    }
    VIR_FREE(list);

    *nseclabels_rtn = nseclabels;
    *seclabels_rtn = seclabels;

    return 0;

 error:
    for (i = 0; i < nseclabels; i++)
        virSecurityDeviceLabelDefFree(seclabels[i]);
    VIR_FREE(seclabels);
    VIR_FREE(list);
    return -1;
}


/* Parse the XML definition for a lease
 */
static virDomainLeaseDefPtr
virDomainLeaseDefParseXML(xmlNodePtr node)
{
    virDomainLeaseDefPtr def;
    xmlNodePtr cur;
    char *lockspace = NULL;
    char *key = NULL;
    char *path = NULL;
    char *offset = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!key && xmlStrEqual(cur->name, BAD_CAST "key")) {
                key = (char *)xmlNodeGetContent(cur);
            } else if (!lockspace &&
                       xmlStrEqual(cur->name, BAD_CAST "lockspace")) {
                lockspace = (char *)xmlNodeGetContent(cur);
            } else if (!path &&
                       xmlStrEqual(cur->name, BAD_CAST "target")) {
                path = virXMLPropString(cur, "path");
                offset = virXMLPropString(cur, "offset");
            }
        }
        cur = cur->next;
    }

    if (!key) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'key' element for lease"));
        goto error;
    }
    if (!path) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'target' element for lease"));
        goto error;
    }

    if (offset &&
        virStrToLong_ull(offset, NULL, 10, &def->offset) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Malformed lease target offset %s"), offset);
        goto error;
    }

    def->key = key;
    def->lockspace = lockspace;
    def->path = path;
    path = key = lockspace = NULL;

 cleanup:
    VIR_FREE(lockspace);
    VIR_FREE(key);
    VIR_FREE(path);
    VIR_FREE(offset);

    return def;

 error:
    virDomainLeaseDefFree(def);
    def = NULL;
    goto cleanup;
}

static int
virDomainDiskSourcePoolDefParse(xmlNodePtr node,
                                virStorageSourcePoolDefPtr *srcpool)
{
    char *mode = NULL;
    virStorageSourcePoolDefPtr source;
    int ret = -1;

    *srcpool = NULL;

    if (VIR_ALLOC(source) < 0)
        return -1;

    source->pool = virXMLPropString(node, "pool");
    source->volume = virXMLPropString(node, "volume");
    mode = virXMLPropString(node, "mode");

    /* CD-ROM and Floppy allows no source */
    if (!source->pool && !source->volume) {
        ret = 0;
        goto cleanup;
    }

    if (!source->pool || !source->volume) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'pool' and 'volume' must be specified together "
                         "for 'pool' type source"));
        goto cleanup;
    }

    if (mode &&
        (source->mode = virStorageSourcePoolModeTypeFromString(mode)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown source mode '%s' for volume type disk"),
                       mode);
        goto cleanup;
    }

    *srcpool = source;
    source = NULL;
    ret = 0;

 cleanup:
    virStorageSourcePoolDefFree(source);
    VIR_FREE(mode);
    return ret;
}


int
virDomainDiskSourceParse(xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virStorageSourcePtr src)
{
    int ret = -1;
    char *protocol = NULL;
    xmlNodePtr saveNode = ctxt->node;

    ctxt->node = node;

    switch ((virStorageType)src->type) {
    case VIR_STORAGE_TYPE_FILE:
        src->path = virXMLPropString(node, "file");
        break;
    case VIR_STORAGE_TYPE_BLOCK:
        src->path = virXMLPropString(node, "dev");
        break;
    case VIR_STORAGE_TYPE_DIR:
        src->path = virXMLPropString(node, "dir");
        break;
    case VIR_STORAGE_TYPE_NETWORK:
        if (!(protocol = virXMLPropString(node, "protocol"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing network source protocol type"));
            goto cleanup;
        }

        if ((src->protocol = virStorageNetProtocolTypeFromString(protocol)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown protocol type '%s'"), protocol);
            goto cleanup;
        }

        if (!(src->path = virXMLPropString(node, "name")) &&
            src->protocol != VIR_STORAGE_NET_PROTOCOL_NBD) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing name for disk source"));
            goto cleanup;
        }

        /* for historical reasons the volume name for gluster volume is stored
         * as a part of the path. This is hard to work with when dealing with
         * relative names. Split out the volume into a separate variable */
        if (src->path && src->protocol == VIR_STORAGE_NET_PROTOCOL_GLUSTER) {
            char *tmp;
            if (!(tmp = strchr(src->path, '/')) ||
                tmp == src->path) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("missing volume name or file name in "
                                 "gluster source path '%s'"), src->path);
                goto cleanup;
            }

            src->volume = src->path;

            if (VIR_STRDUP(src->path, tmp) < 0)
                goto cleanup;

            tmp[0] = '\0';
        }

        /* snapshot currently works only for remote disks */
        src->snapshot = virXPathString("string(./snapshot/@name)", ctxt);

        /* config file currently only works with remote disks */
        src->configFile = virXPathString("string(./config/@file)", ctxt);

        if (virDomainStorageHostParse(node, &src->hosts, &src->nhosts) < 0)
            goto cleanup;
        break;
    case VIR_STORAGE_TYPE_VOLUME:
        if (virDomainDiskSourcePoolDefParse(node, &src->srcpool) < 0)
            goto cleanup;
        break;
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk type %s"),
                       virStorageTypeToString(src->type));
        goto cleanup;
    }

    /* People sometimes pass a bogus '' source path when they mean to omit the
     * source element completely (e.g. CDROM without media). This is just a
     * little compatibility check to help those broken apps */
    if (src->path && !*src->path)
        VIR_FREE(src->path);

    ret = 0;

 cleanup:
    VIR_FREE(protocol);
    ctxt->node = saveNode;
    return ret;
}


static int
virDomainDiskBackingStoreParse(xmlXPathContextPtr ctxt,
                               virStorageSourcePtr src)
{
    virStorageSourcePtr backingStore = NULL;
    xmlNodePtr save_ctxt = ctxt->node;
    xmlNodePtr source;
    char *type = NULL;
    char *format = NULL;
    int ret = -1;

    if (!(ctxt->node = virXPathNode("./backingStore[*]", ctxt))) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC(backingStore) < 0)
        goto cleanup;

    if (!(type = virXMLPropString(ctxt->node, "type"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing disk backing store type"));
        goto cleanup;
    }

    backingStore->type = virStorageTypeFromString(type);
    if (backingStore->type <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk backing store type '%s'"), type);
        goto cleanup;
    }

    if (!(format = virXPathString("string(./format/@type)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing disk backing store format"));
        goto cleanup;
    }

    backingStore->format = virStorageFileFormatTypeFromString(format);
    if (backingStore->format <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk backing store format '%s'"), format);
        goto cleanup;
    }

    if (!(source = virXPathNode("./source", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing disk backing store source"));
        goto cleanup;
    }

    if (virDomainDiskSourceParse(source, ctxt, backingStore) < 0 ||
        virDomainDiskBackingStoreParse(ctxt, backingStore) < 0)
        goto cleanup;

    src->backingStore = backingStore;
    ret = 0;

 cleanup:
    if (ret < 0)
        virStorageSourceFree(backingStore);
    VIR_FREE(type);
    VIR_FREE(format);
    ctxt->node = save_ctxt;
    return ret;
}

#define PARSE_IOTUNE(val)                                                      \
    if (virXPathULongLong("string(./iotune/" #val ")",                         \
                          ctxt, &def->blkdeviotune.val) == -2) {               \
        virReportError(VIR_ERR_XML_ERROR,                                      \
                       _("disk iotune field '%s' must be an integer"), #val);  \
        return -1;                                                             \
    }

static int
virDomainDiskDefIotuneParse(virDomainDiskDefPtr def,
                            xmlXPathContextPtr ctxt)
{
    PARSE_IOTUNE(total_bytes_sec);
    PARSE_IOTUNE(read_bytes_sec);
    PARSE_IOTUNE(write_bytes_sec);
    PARSE_IOTUNE(total_iops_sec);
    PARSE_IOTUNE(read_iops_sec);
    PARSE_IOTUNE(write_iops_sec);

    PARSE_IOTUNE(total_bytes_sec_max);
    PARSE_IOTUNE(read_bytes_sec_max);
    PARSE_IOTUNE(write_bytes_sec_max);
    PARSE_IOTUNE(total_iops_sec_max);
    PARSE_IOTUNE(read_iops_sec_max);
    PARSE_IOTUNE(write_iops_sec_max);

    PARSE_IOTUNE(size_iops_sec);

    PARSE_IOTUNE(total_bytes_sec_max_length);
    PARSE_IOTUNE(read_bytes_sec_max_length);
    PARSE_IOTUNE(write_bytes_sec_max_length);
    PARSE_IOTUNE(total_iops_sec_max_length);
    PARSE_IOTUNE(read_iops_sec_max_length);
    PARSE_IOTUNE(write_iops_sec_max_length);

    def->blkdeviotune.group_name =
        virXPathString("string(./iotune/group_name)", ctxt);

    if ((def->blkdeviotune.total_bytes_sec &&
         def->blkdeviotune.read_bytes_sec) ||
        (def->blkdeviotune.total_bytes_sec &&
         def->blkdeviotune.write_bytes_sec)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("total and read/write bytes_sec "
                         "cannot be set at the same time"));
        return -1;
    }

    if ((def->blkdeviotune.total_iops_sec &&
         def->blkdeviotune.read_iops_sec) ||
        (def->blkdeviotune.total_iops_sec &&
         def->blkdeviotune.write_iops_sec)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("total and read/write iops_sec "
                         "cannot be set at the same time"));
        return -1;
    }

    if ((def->blkdeviotune.total_bytes_sec_max &&
         def->blkdeviotune.read_bytes_sec_max) ||
        (def->blkdeviotune.total_bytes_sec_max &&
         def->blkdeviotune.write_bytes_sec_max)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("total and read/write bytes_sec_max "
                         "cannot be set at the same time"));
        return -1;
    }

    if ((def->blkdeviotune.total_iops_sec_max &&
         def->blkdeviotune.read_iops_sec_max) ||
        (def->blkdeviotune.total_iops_sec_max &&
         def->blkdeviotune.write_iops_sec_max)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("total and read/write iops_sec_max "
                         "cannot be set at the same time"));
        return -1;
    }

    return 0;
}
#undef PARSE_IOTUNE


static int
virDomainDiskDefMirrorParse(virDomainDiskDefPtr def,
                            xmlNodePtr cur,
                            xmlXPathContextPtr ctxt)
{
    xmlNodePtr mirrorNode;
    char *mirrorFormat = NULL;
    char *mirrorType = NULL;
    char *ready = NULL;
    char *blockJob = NULL;
    int ret = -1;

    if (VIR_ALLOC(def->mirror) < 0)
        goto cleanup;

    if ((blockJob = virXMLPropString(cur, "job"))) {
        if ((def->mirrorJob = virDomainBlockJobTypeFromString(blockJob)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown mirror job type '%s'"), blockJob);
            goto cleanup;
        }
    } else {
        def->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    }

    if ((mirrorType = virXMLPropString(cur, "type"))) {
        if ((def->mirror->type = virStorageTypeFromString(mirrorType)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown mirror backing store type '%s'"),
                           mirrorType);
            goto cleanup;
        }

        mirrorFormat = virXPathString("string(./mirror/format/@type)", ctxt);

        if (!(mirrorNode = virXPathNode("./mirror/source", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror requires source element"));
            goto cleanup;
        }

        if (virDomainDiskSourceParse(mirrorNode, ctxt, def->mirror) < 0)
            goto cleanup;
    } else {
        /* For back-compat reasons, we handle a file name
         * encoded as attributes, even though we prefer
         * modern output in the style of backingStore */
        def->mirror->type = VIR_STORAGE_TYPE_FILE;
        def->mirror->path = virXMLPropString(cur, "file");
        if (!def->mirror->path) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror requires file name"));
            goto cleanup;
        }
        if (def->mirrorJob != VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror without type only supported "
                             "by copy job"));
            goto cleanup;
        }
        mirrorFormat = virXMLPropString(cur, "format");
    }

    if (mirrorFormat) {
        def->mirror->format = virStorageFileFormatTypeFromString(mirrorFormat);
        if (def->mirror->format <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown mirror format value '%s'"), mirrorFormat);
            goto cleanup;
        }
    }

    if ((ready = virXMLPropString(cur, "ready")) &&
        (def->mirrorState = virDomainDiskMirrorStateTypeFromString(ready)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown mirror ready state %s"), ready);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(ready);
    VIR_FREE(blockJob);
    VIR_FREE(mirrorType);
    VIR_FREE(mirrorFormat);
    return ret;
}


static int
virDomainDiskDefGeometryParse(virDomainDiskDefPtr def,
                              xmlNodePtr cur,
                              xmlXPathContextPtr ctxt)
{
    char *trans;

    if (virXPathUInt("string(./geometry/@cyls)",
                     ctxt, &def->geometry.cylinders) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid geometry settings (cyls)"));
        return -1;
    }

    if (virXPathUInt("string(./geometry/@heads)",
                     ctxt, &def->geometry.heads) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid geometry settings (heads)"));
        return -1;
    }

    if (virXPathUInt("string(./geometry/@secs)",
                     ctxt, &def->geometry.sectors) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid geometry settings (secs)"));
        return -1;
    }

    trans = virXMLPropString(cur, "trans");
    if (trans) {
        def->geometry.trans = virDomainDiskGeometryTransTypeFromString(trans);
        if (def->geometry.trans <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid translation value '%s'"),
                           trans);
            VIR_FREE(trans);
            return -1;
        }
        VIR_FREE(trans);
    }

    return 0;
}


static int
virDomainDiskDefParseValidate(const virDomainDiskDef *def)
{
    if (def->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
        if (def->event_idx != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk event_idx mode supported only for virtio bus"));
            return -1;
        }

        if (def->ioeventfd != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk ioeventfd mode supported only for virtio bus"));
            return -1;
        }
    }

    if (def->device != VIR_DOMAIN_DISK_DEVICE_LUN) {
        if (def->rawio != VIR_TRISTATE_BOOL_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("rawio can be used only with device='lun'"));
            return -1;
        }

        if (def->sgio != VIR_DOMAIN_DEVICE_SGIO_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("sgio can be used only with device='lun'"));
            return -1;
        }
    }

    if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        def->bus != VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for floppy disk"),
                       virDomainDiskBusTypeToString(def->bus));
        return -1;
    }

    if (def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        def->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for disk"),
                       virDomainDiskBusTypeToString(def->bus));
        return -1;
    }

    if (def->removable != VIR_TRISTATE_SWITCH_ABSENT &&
        def->bus != VIR_DOMAIN_DISK_BUS_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("removable is only valid for usb disks"));
        return -1;
    }

    if (def->startupPolicy != VIR_DOMAIN_STARTUP_POLICY_DEFAULT) {
        if (def->src->type == VIR_STORAGE_TYPE_NETWORK) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Setting disk %s is not allowed for "
                             "disk of network type"),
                           virDomainStartupPolicyTypeToString(def->startupPolicy));
            return -1;
        }

        if (def->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
            def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            def->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Setting disk 'requisite' is allowed only for "
                             "cdrom or floppy"));
            return -1;
        }
    }

    return 0;
}


static int
virDomainDiskDefDriverParseXML(virDomainDiskDefPtr def,
                               xmlNodePtr cur)
{
    char *tmp = NULL;
    int ret = -1;

    def->src->driverName = virXMLPropString(cur, "name");

    if ((tmp = virXMLPropString(cur, "cache")) &&
        (def->cachemode = virDomainDiskCacheTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk cache mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "error_policy")) &&
        (def->error_policy = virDomainDiskErrorPolicyTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk error policy '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "rerror_policy")) &&
        (((def->rerror_policy = virDomainDiskErrorPolicyTypeFromString(tmp)) <= 0) ||
         (def->rerror_policy == VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk read error policy '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "io")) &&
        (def->iomode = virDomainDiskIoTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk io mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "ioeventfd")) &&
        (def->ioeventfd = virTristateSwitchTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk ioeventfd mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "event_idx")) &&
        (def->event_idx = virTristateSwitchTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk event_idx mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "copy_on_read")) &&
        (def->copy_on_read = virTristateSwitchTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk copy_on_read mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "discard")) &&
        (def->discard = virDomainDiskDiscardTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk discard mode '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "iothread")) &&
        (virStrToLong_uip(tmp, NULL, 10, &def->iothread) < 0 ||
         def->iothread == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid iothread attribute in disk driver element: %s"),
                       tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(cur, "type"))) {
        if (STREQ(tmp, "aio")) {
            /* Xen back-compat */
            def->src->format = VIR_STORAGE_FILE_RAW;
        } else {
            if ((def->src->format = virStorageFileFormatTypeFromString(tmp)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown driver format value '%s'"), tmp);
                goto cleanup;
            }
        }

        VIR_FREE(tmp);
    }

    if ((tmp = virXMLPropString(cur, "detect_zeroes")) &&
        (def->detect_zeroes = virDomainDiskDetectZeroesTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown driver detect_zeroes value '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    ret = 0;

 cleanup:
    VIR_FREE(tmp);

    return ret;
}


#define VENDOR_LEN  8
#define PRODUCT_LEN 16

/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainDiskDefPtr
virDomainDiskDefParseXML(virDomainXMLOptionPtr xmlopt,
                         xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virHashTablePtr bootHash,
                         virSecurityLabelDefPtr* vmSeclabels,
                         int nvmSeclabels,
                         unsigned int flags)
{
    virDomainDiskDefPtr def;
    xmlNodePtr sourceNode = NULL;
    xmlNodePtr cur;
    xmlNodePtr save_ctxt = ctxt->node;
    char *tmp = NULL;
    char *snapshot = NULL;
    char *rawio = NULL;
    char *sgio = NULL;
    bool source = false;
    char *target = NULL;
    char *bus = NULL;
    char *devaddr = NULL;
    virStorageEncryptionPtr encryption = NULL;
    char *serial = NULL;
    char *startupPolicy = NULL;
    virStorageAuthDefPtr authdef = NULL;
    char *tray = NULL;
    char *removable = NULL;
    char *logical_block_size = NULL;
    char *physical_block_size = NULL;
    char *wwn = NULL;
    char *vendor = NULL;
    char *product = NULL;
    char *domain_name = NULL;
    int expected_secret_usage = -1;
    int auth_secret_usage = -1;

    if (!(def = virDomainDiskDefNew(xmlopt)))
        return NULL;

    ctxt->node = node;

    /* defaults */
    def->src->type = VIR_STORAGE_TYPE_FILE;
    def->device = VIR_DOMAIN_DISK_DEVICE_DISK;

    if ((tmp = virXMLPropString(node, "type")) &&
        (def->src->type = virStorageTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk type '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(node, "device")) &&
        (def->device = virDomainDiskDeviceTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown disk device '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    snapshot = virXMLPropString(node, "snapshot");

    rawio = virXMLPropString(node, "rawio");
    sgio = virXMLPropString(node, "sgio");

    for (cur = node->children; cur != NULL; cur = cur->next) {
        if (cur->type != XML_ELEMENT_NODE)
            continue;

        if (!source && xmlStrEqual(cur->name, BAD_CAST "source")) {
            sourceNode = cur;

            if (virDomainDiskSourceParse(cur, ctxt, def->src) < 0)
                goto error;

            source = true;

            if (def->src->type == VIR_STORAGE_TYPE_NETWORK) {
                if (def->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI)
                    expected_secret_usage = VIR_SECRET_USAGE_TYPE_ISCSI;
                else if (def->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD)
                    expected_secret_usage = VIR_SECRET_USAGE_TYPE_CEPH;
            }

            startupPolicy = virXMLPropString(cur, "startupPolicy");

        } else if (!target &&
                   xmlStrEqual(cur->name, BAD_CAST "target")) {
            target = virXMLPropString(cur, "dev");
            bus = virXMLPropString(cur, "bus");
            tray = virXMLPropString(cur, "tray");
            removable = virXMLPropString(cur, "removable");

            /* HACK: Work around for compat with Xen
             * driver in previous libvirt releases */
            if (target &&
                STRPREFIX(target, "ioemu:"))
                memmove(target, target+6, strlen(target)-5);
        } else if (!domain_name &&
                   xmlStrEqual(cur->name, BAD_CAST "backenddomain")) {
            domain_name = virXMLPropString(cur, "name");
        } else if (xmlStrEqual(cur->name, BAD_CAST "geometry")) {
            if (virDomainDiskDefGeometryParse(def, cur, ctxt) < 0)
                goto error;
        } else if (xmlStrEqual(cur->name, BAD_CAST "blockio")) {
            logical_block_size =
                virXMLPropString(cur, "logical_block_size");
            if (logical_block_size &&
                virStrToLong_ui(logical_block_size, NULL, 0,
                                &def->blockio.logical_block_size) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid logical block size '%s'"),
                               logical_block_size);
                goto error;
            }
            physical_block_size =
                virXMLPropString(cur, "physical_block_size");
            if (physical_block_size &&
                virStrToLong_ui(physical_block_size, NULL, 0,
                                &def->blockio.physical_block_size) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("invalid physical block size '%s'"),
                               physical_block_size);
                goto error;
            }
        } else if (!def->src->driverName &&
                   xmlStrEqual(cur->name, BAD_CAST "driver")) {
            if (virDomainDiskDefDriverParseXML(def, cur) < 0)
                goto error;
        } else if (!def->mirror &&
                   xmlStrEqual(cur->name, BAD_CAST "mirror") &&
                   !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
            if (virDomainDiskDefMirrorParse(def, cur, ctxt) < 0)
                goto error;
        } else if (!authdef &&
                   xmlStrEqual(cur->name, BAD_CAST "auth")) {
            if (!(authdef = virStorageAuthDefParse(node->doc, cur)))
                goto error;
            /* Disk volume types won't have the secrettype filled in until
             * after virStorageTranslateDiskSourcePool is run
             */
            if (def->src->type != VIR_STORAGE_TYPE_VOLUME &&
                (auth_secret_usage =
                 virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid secret type %s"),
                               authdef->secrettype);
                goto error;
            }
        } else if (xmlStrEqual(cur->name, BAD_CAST "iotune")) {
            if (virDomainDiskDefIotuneParse(def, ctxt) < 0)
                goto error;
        } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
            def->src->readonly = true;
        } else if (xmlStrEqual(cur->name, BAD_CAST "shareable")) {
            def->src->shared = true;
        } else if (xmlStrEqual(cur->name, BAD_CAST "transient")) {
            def->transient = true;
        } else if ((flags & VIR_DOMAIN_DEF_PARSE_STATUS) &&
                   xmlStrEqual(cur->name, BAD_CAST "state")) {
            /* Legacy back-compat. Don't add any more attributes here */
            devaddr = virXMLPropString(cur, "devaddr");
        } else if (encryption == NULL &&
                   xmlStrEqual(cur->name, BAD_CAST "encryption")) {
            encryption = virStorageEncryptionParseNode(node->doc,
                                                       cur);
            if (encryption == NULL)
                goto error;
        } else if (!serial &&
                   xmlStrEqual(cur->name, BAD_CAST "serial")) {
            serial = (char *)xmlNodeGetContent(cur);
        } else if (!wwn &&
                   xmlStrEqual(cur->name, BAD_CAST "wwn")) {
            wwn = (char *)xmlNodeGetContent(cur);

            if (!virValidateWWN(wwn))
                goto error;
        } else if (!vendor &&
                   xmlStrEqual(cur->name, BAD_CAST "vendor")) {
            vendor = (char *)xmlNodeGetContent(cur);

            if (strlen(vendor) > VENDOR_LEN) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("disk vendor is more than 8 characters"));
                goto error;
            }

            if (!virStringIsPrintable(vendor)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("disk vendor is not printable string"));
                goto error;
            }
        } else if (!product &&
                   xmlStrEqual(cur->name, BAD_CAST "product")) {
            product = (char *)xmlNodeGetContent(cur);

            if (strlen(product) > PRODUCT_LEN) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("disk product is more than 16 characters"));
                goto error;
            }

            if (!virStringIsPrintable(product)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("disk product is not printable string"));
                goto error;
            }
        } else if (xmlStrEqual(cur->name, BAD_CAST "boot")) {
            /* boot is parsed as part of virDomainDeviceInfoParseXML */
        }
    }

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

    /* Disk volume types will have authentication information handled in
     * virStorageTranslateDiskSourcePool
     */
    if (def->src->type != VIR_STORAGE_TYPE_VOLUME &&
        auth_secret_usage != -1 && auth_secret_usage != expected_secret_usage) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid secret type '%s'"),
                       virSecretUsageTypeToString(auth_secret_usage));
        goto error;
    }


    /* Only CDROM and Floppy devices are allowed missing source path
     * to indicate no media present. LUN is for raw access CD-ROMs
     * that are not attached to a physical device presently */
    if (virStorageSourceIsEmpty(def->src) &&
        (def->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
         (flags & VIR_DOMAIN_DEF_PARSE_DISK_SOURCE))) {
        virReportError(VIR_ERR_NO_SOURCE,
                       target ? "%s" : NULL, target);
        goto error;
    }

    /* If source is present, check for an optional seclabel override.  */
    if (sourceNode) {
        xmlNodePtr saved_node = ctxt->node;
        ctxt->node = sourceNode;
        if (virSecurityDeviceLabelDefParseXML(&def->src->seclabels,
                                              &def->src->nseclabels,
                                              vmSeclabels,
                                              nvmSeclabels,
                                              ctxt,
                                              flags) < 0)
            goto error;
        ctxt->node = saved_node;
    }

    if (!target && !(flags & VIR_DOMAIN_DEF_PARSE_DISK_SOURCE)) {
        if (def->src->srcpool) {
            if (virAsprintf(&tmp, "pool = '%s', volume = '%s'",
                def->src->srcpool->pool, def->src->srcpool->volume) < 0)
                goto error;

            virReportError(VIR_ERR_NO_TARGET, "%s", tmp);
            VIR_FREE(tmp);
        } else {
            virReportError(VIR_ERR_NO_TARGET, def->src->path ? "%s" : NULL, def->src->path);
        }
        goto error;
    }

    if (!(flags & VIR_DOMAIN_DEF_PARSE_DISK_SOURCE)) {
        if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            !STRPREFIX(target, "fd")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid floppy device name: %s"), target);
            goto error;
        }

        /* Force CDROM to be listed as read only */
        if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
            def->src->readonly = true;

        if ((def->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
             def->device == VIR_DOMAIN_DISK_DEVICE_LUN) &&
            !STRPREFIX((const char *)target, "hd") &&
            !STRPREFIX((const char *)target, "sd") &&
            !STRPREFIX((const char *)target, "vd") &&
            !STRPREFIX((const char *)target, "xvd") &&
            !STRPREFIX((const char *)target, "ubd")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid harddisk device name: %s"), target);
            goto error;
        }
    }

    if (snapshot) {
        def->snapshot = virDomainSnapshotLocationTypeFromString(snapshot);
        if (def->snapshot <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk snapshot setting '%s'"),
                           snapshot);
            goto error;
        }
    } else if (def->src->readonly) {
        def->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
    }

    if (rawio) {
        if ((def->rawio = virTristateBoolTypeFromString(rawio)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown disk rawio setting '%s'"),
                           rawio);
            goto error;
        }
    }

    if (sgio) {
        if ((def->sgio = virDomainDeviceSGIOTypeFromString(sgio)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk sgio mode '%s'"), sgio);
            goto error;
        }
    }

    if (bus) {
        if ((def->bus = virDomainDiskBusTypeFromString(bus)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk bus type '%s'"), bus);
            goto error;
        }
    } else {
        if (def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            def->bus = VIR_DOMAIN_DISK_BUS_FDC;
        } else if (!(flags & VIR_DOMAIN_DEF_PARSE_DISK_SOURCE)) {
            if (STRPREFIX(target, "hd"))
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STRPREFIX(target, "sd"))
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else if (STRPREFIX(target, "vd"))
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            else if (STRPREFIX(target, "xvd"))
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(target, "ubd"))
                def->bus = VIR_DOMAIN_DISK_BUS_UML;
            else
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
        }
    }

    if (tray) {
        if ((def->tray_status = virDomainDiskTrayTypeFromString(tray)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk tray status '%s'"), tray);
            goto error;
        }

        if (def->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            def->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("tray is only valid for cdrom and floppy"));
            goto error;
        }
    }

    if (removable) {
        if ((def->removable = virTristateSwitchTypeFromString(removable)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk removable status '%s'"), removable);
            goto error;
        }
    }

    if (devaddr) {
        if (virDomainParseLegacyDeviceAddress(devaddr,
                                              &def->info.addr.pci) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse devaddr parameter '%s'"),
                           devaddr);
            goto error;
        }
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    } else {
        if (virDomainDeviceInfoParseXML(node, bootHash, &def->info,
                                        flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) < 0)
            goto error;
    }

    if (startupPolicy) {
        int val;

        if ((val = virDomainStartupPolicyTypeFromString(startupPolicy)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown startupPolicy value '%s'"),
                           startupPolicy);
            goto error;
        }
        def->startupPolicy = val;
    }

    if (encryption) {
        if (encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
            encryption->encinfo.cipher_name) {

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("supplying the <cipher> for a domain is "
                             "unnecessary"));
            goto error;
        }
    }

    def->dst = target;
    target = NULL;
    def->src->auth = authdef;
    authdef = NULL;
    def->src->encryption = encryption;
    encryption = NULL;
    def->domain_name = domain_name;
    domain_name = NULL;
    def->serial = serial;
    serial = NULL;
    def->wwn = wwn;
    wwn = NULL;
    def->vendor = vendor;
    vendor = NULL;
    def->product = product;
    product = NULL;

    if (!(flags & VIR_DOMAIN_DEF_PARSE_DISK_SOURCE)) {
        if (virDomainDiskBackingStoreParse(ctxt, def->src) < 0)
            goto error;
    }

    if (virDomainDiskDefParseValidate(def) < 0)
        goto error;

 cleanup:
    VIR_FREE(tmp);
    VIR_FREE(bus);
    VIR_FREE(snapshot);
    VIR_FREE(rawio);
    VIR_FREE(sgio);
    VIR_FREE(target);
    VIR_FREE(tray);
    VIR_FREE(removable);
    virStorageAuthDefFree(authdef);
    VIR_FREE(devaddr);
    VIR_FREE(serial);
    virStorageEncryptionFree(encryption);
    VIR_FREE(startupPolicy);
    VIR_FREE(logical_block_size);
    VIR_FREE(physical_block_size);
    VIR_FREE(wwn);
    VIR_FREE(vendor);
    VIR_FREE(product);
    VIR_FREE(domain_name);

    ctxt->node = save_ctxt;
    return def;

 error:
    virDomainDiskDefFree(def);
    def = NULL;
    goto cleanup;
}

/**
 * virDomainParseScaledValue:
 * @xpath: XPath to memory amount
 * @units_xpath: XPath to units attribute
 * @ctxt: XPath context
 * @val: scaled value is stored here
 * @scale: default scale for @val
 * @max: maximal @val allowed
 * @required: is the value required?
 *
 * Parse a value located at @xpath within @ctxt, and store the
 * result into @val. The value is scaled by units located at
 * @units_xpath (or the 'unit' attribute under @xpath if
 * @units_xpath is NULL). If units are not present, the default
 * @scale is used. If @required is set, then the value must
 * exist; otherwise, the value is optional. The resulting value
 * is in bytes.
 *
 * Returns 1 on success,
 *         0 if the value was not present and !@required,
 *         -1 on failure after issuing error.
 */
static int
virDomainParseScaledValue(const char *xpath,
                          const char *units_xpath,
                          xmlXPathContextPtr ctxt,
                          unsigned long long *val,
                          unsigned long long scale,
                          unsigned long long max,
                          bool required)
{
    char *xpath_full = NULL;
    char *unit = NULL;
    char *bytes_str = NULL;
    int ret = -1;
    unsigned long long bytes;

    *val = 0;
    if (virAsprintf(&xpath_full, "string(%s)", xpath) < 0)
        goto cleanup;

    bytes_str = virXPathString(xpath_full, ctxt);
    if (!bytes_str) {
        if (!required) {
            ret = 0;
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing element or attribute '%s'"),
                           xpath);
        }
        goto cleanup;
    }
    VIR_FREE(xpath_full);

    if (virStrToLong_ullp(bytes_str, NULL, 10, &bytes) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value '%s' for element or attribute '%s'"),
                       bytes_str, xpath);
        goto cleanup;
    }

    if ((units_xpath &&
         virAsprintf(&xpath_full, "string(%s)", units_xpath) < 0) ||
        (!units_xpath &&
         virAsprintf(&xpath_full, "string(%s/@unit)", xpath) < 0))
        goto cleanup;
    unit = virXPathString(xpath_full, ctxt);

    if (virScaleInteger(&bytes, unit, scale, max) < 0)
        goto cleanup;

    *val = bytes;
    ret = 1;
 cleanup:
    VIR_FREE(bytes_str);
    VIR_FREE(xpath_full);
    VIR_FREE(unit);
    return ret;
}


/**
 * virDomainParseMemory:
 * @xpath: XPath to memory amount
 * @units_xpath: XPath to units attribute
 * @ctxt: XPath context
 * @mem: scaled memory amount is stored here
 * @required: whether value is required
 * @capped: whether scaled value must fit within unsigned long
 *
 * Parse a memory element or attribute located at @xpath within
 * @ctxt, and store the result into @mem, in blocks of 1024. The
 * value is scaled by units located at @units_xpath (or the
 * 'unit' attribute under @xpath if @units_xpath is NULL). If
 * units are not present, he default scale of 1024 is used. If
 * @required is set, then the value must exist; otherwise, the
 * value is optional.  The value must not exceed
 * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED once scaled; additionally,
 * if @capped is true, the value must fit within an unsigned long
 * (only matters on 32-bit platforms).
 *
 * Return 0 on success, -1 on failure after issuing error.
 */
int
virDomainParseMemory(const char *xpath,
                     const char *units_xpath,
                     xmlXPathContextPtr ctxt,
                     unsigned long long *mem,
                     bool required,
                     bool capped)
{
    unsigned long long bytes, max;

    max = virMemoryMaxValue(capped);

    if (virDomainParseScaledValue(xpath, units_xpath, ctxt,
                                  &bytes, 1024, max, required) < 0)
        return -1;

    /* Yes, we really do use kibibytes for our internal sizing.  */
    *mem = VIR_DIV_UP(bytes, 1024);

    if (*mem >= VIR_DIV_UP(max, 1024)) {
        virReportError(VIR_ERR_OVERFLOW, "%s", _("size value too large"));
        return -1;
    }
    return 0;
}


/**
 * virDomainParseMemoryLimit:
 *
 * @xpath: XPath to memory amount
 * @units_xpath: XPath to units attribute
 * @ctxt: XPath context
 * @mem: scaled memory amount is stored here
 *
 * Parse a memory element or attribute located at @xpath within @ctxt, and
 * store the result into @mem, in blocks of 1024.  The  value is scaled by
 * units located at @units_xpath (or the 'unit' attribute under @xpath if
 * @units_xpath is NULL).  If units are not present, he default scale of 1024
 * is used.  The value must not exceed VIR_DOMAIN_MEMORY_PARAM_UNLIMITED
 * once scaled.
 *
 * This helper should be used only on *_limit memory elements.
 *
 * Return 0 on success, -1 on failure after issuing error.
 */
static int
virDomainParseMemoryLimit(const char *xpath,
                          const char *units_xpath,
                          xmlXPathContextPtr ctxt,
                          unsigned long long *mem)
{
    int ret;
    unsigned long long bytes;

    ret = virDomainParseScaledValue(xpath, units_xpath, ctxt, &bytes, 1024,
                                    VIR_DOMAIN_MEMORY_PARAM_UNLIMITED << 10,
                                    false);

    if (ret < 0)
        return -1;

    if (ret == 0)
        *mem = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    else
        *mem = virMemoryLimitTruncate(VIR_DIV_UP(bytes, 1024));

    return 0;
}


bool
virDomainDefHasMemoryHotplug(const virDomainDef *def)
{
    return def->mem.memory_slots > 0 || def->mem.max_memory > 0;
}


/**
 * virDomainDefGetMemoryInitial:
 * @def: domain definition
 *
 * Returns the size of the initial amount of guest memory. The initial amount
 * is the memory size excluding possible memory modules.
 */
unsigned long long
virDomainDefGetMemoryInitial(const virDomainDef *def)
{
    size_t i;
    unsigned long long ret = def->mem.total_memory;

    for (i = 0; i < def->nmems; i++)
        ret -= def->mems[i]->size;

    return ret;
}


/**
 * virDomainDefSetMemoryTotal:
 * @def: domain definition
 * @size: size to set
 *
 * Sets the total memory size in @def. This value needs to include possible
 * additional memory modules.
 */
void
virDomainDefSetMemoryTotal(virDomainDefPtr def,
                           unsigned long long size)
{
    def->mem.total_memory = size;
}


/**
 * virDomainDefGetMemoryTotal:
 * @def: domain definition
 *
 * Returns the current maximum memory size usable by the domain described by
 * @def. This size includes possible additional memory devices.
 */
unsigned long long
virDomainDefGetMemoryTotal(const virDomainDef *def)
{
    return def->mem.total_memory;
}


static int
virDomainControllerModelTypeFromString(const virDomainControllerDef *def,
                                       const char *model)
{
    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
        return virDomainControllerModelSCSITypeFromString(model);
    else if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_USB)
        return virDomainControllerModelUSBTypeFromString(model);
    else if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI)
        return virDomainControllerModelPCITypeFromString(model);

    return -1;
}


static const char *
virDomainControllerModelTypeToString(virDomainControllerDefPtr def,
                                     int model)
{
    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
        return virDomainControllerModelSCSITypeToString(model);
    else if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_USB)
        return virDomainControllerModelUSBTypeToString(model);
    else if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI)
        return virDomainControllerModelPCITypeToString(model);

    return NULL;
}


/* Parse the XML definition for a controller
 * @param node XML nodeset to parse for controller definition
 */
static virDomainControllerDefPtr
virDomainControllerDefParseXML(xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    virDomainControllerDefPtr def = NULL;
    int type = 0;
    xmlNodePtr cur = NULL;
    char *typeStr = NULL;
    char *idx = NULL;
    char *model = NULL;
    char *queues = NULL;
    char *cmd_per_lun = NULL;
    char *max_sectors = NULL;
    bool processedModel = false;
    char *modelName = NULL;
    bool processedTarget = false;
    char *chassisNr = NULL;
    char *chassis = NULL;
    char *port = NULL;
    char *busNr = NULL;
    int numaNode = -1;
    char *ioeventfd = NULL;
    char *portsStr = NULL;
    int ports = -1;
    char *iothread = NULL;
    xmlNodePtr saved = ctxt->node;
    int rc;

    ctxt->node = node;

    typeStr = virXMLPropString(node, "type");
    if (typeStr) {
        if ((type = virDomainControllerTypeFromString(typeStr)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown controller type '%s'"), typeStr);
            goto error;
        }
    }

    if (!(def = virDomainControllerDefNew(type)))
        goto error;

    model = virXMLPropString(node, "model");
    if (model) {
        if ((def->model = virDomainControllerModelTypeFromString(def, model)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown model type '%s'"), model);
            goto error;
        }
    }

    idx = virXMLPropString(node, "index");
    if (idx) {
        unsigned int idxVal;
        if (virStrToLong_ui(idx, NULL, 10, &idxVal) < 0 ||
            idxVal > INT_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse controller index %s"), idx);
            goto error;
        }
        def->idx = idxVal;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "driver")) {
                queues = virXMLPropString(cur, "queues");
                cmd_per_lun = virXMLPropString(cur, "cmd_per_lun");
                max_sectors = virXMLPropString(cur, "max_sectors");
                ioeventfd = virXMLPropString(cur, "ioeventfd");
                iothread = virXMLPropString(cur, "iothread");
            } else if (xmlStrEqual(cur->name, BAD_CAST "model")) {
                if (processedModel) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("Multiple <model> elements in "
                                     "controller definition not allowed"));
                    goto error;
                }
                modelName = virXMLPropString(cur, "name");
                processedModel = true;
            } else if (xmlStrEqual(cur->name, BAD_CAST "target")) {
                if (processedTarget) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("Multiple <target> elements in "
                                     "controller definition not allowed"));
                    goto error;
                }
                chassisNr = virXMLPropString(cur, "chassisNr");
                chassis = virXMLPropString(cur, "chassis");
                port = virXMLPropString(cur, "port");
                busNr = virXMLPropString(cur, "busNr");
                processedTarget = true;
            }
        }
        cur = cur->next;
    }

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

    /* node is parsed differently from target attributes because
     * someone thought it should be a subelement instead...
     */
    rc = virXPathInt("string(./target/node)", ctxt, &numaNode);
    if (rc == -2 || (rc == 0 && numaNode < 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid NUMA node in target"));
        goto error;
    }

    if (queues && virStrToLong_ui(queues, NULL, 10, &def->queues) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Malformed 'queues' value '%s'"), queues);
        goto error;
    }

    if (cmd_per_lun && virStrToLong_ui(cmd_per_lun, NULL, 10, &def->cmd_per_lun) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Malformed 'cmd_per_lun' value '%s'"), cmd_per_lun);
        goto error;
    }

    if (max_sectors && virStrToLong_ui(max_sectors, NULL, 10, &def->max_sectors) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Malformed 'max_sectors' value %s"), max_sectors);
        goto error;
    }

    if (ioeventfd &&
        (def->ioeventfd = virTristateSwitchTypeFromString(ioeventfd)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Malformed 'ioeventfd' value %s"), ioeventfd);
        goto error;
    }

    if (iothread) {
        if (virStrToLong_uip(iothread, NULL, 10, &def->iothread) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid 'iothread' value '%s'"), iothread);
            goto error;
        }
    }

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
        def->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
        VIR_DEBUG("Ignoring device address for none model usb controller");
    } else if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0) {
        goto error;
    }

    portsStr = virXMLPropString(node, "ports");
    if (portsStr) {
        int r = virStrToLong_i(portsStr, NULL, 10, &ports);
        if (r != 0 || ports < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid ports: %s"), portsStr);
            goto error;
        }
    }

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL: {
        def->opts.vioserial.ports = ports;

        char *vectors = virXMLPropString(node, "vectors");
        if (vectors) {
            int r = virStrToLong_i(vectors, NULL, 10,
                                   &def->opts.vioserial.vectors);
            if (r != 0 || def->opts.vioserial.vectors < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid vectors: %s"), vectors);
                VIR_FREE(vectors);
                goto error;
            }
        }
        VIR_FREE(vectors);
        break;
    }
    case VIR_DOMAIN_CONTROLLER_TYPE_USB: {
        /* If the XML has a uhci1, uhci2, uhci3 controller and no
         * master port was given, we should set a sensible one */
        int masterPort = -1;
        switch (def->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
            masterPort = 0;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
            masterPort = 2;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
            masterPort = 4;
            break;
        }
        if (masterPort != -1 &&
            def->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_NONE) {
            def->info.mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
            def->info.master.usb.startport = masterPort;
        }

        def->opts.usbopts.ports = ports;
        break;
    }
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        switch ((virDomainControllerModelPCI) def->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT: {
            unsigned long long bytes;
            if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("pci-root and pcie-root controllers should not "
                                 "have an address"));
                goto error;
            }
            if (def->idx > 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("pci-root and pcie-root controllers "
                                 "should have index 0"));
                goto error;
            }
            if ((rc = virDomainParseScaledValue("./pcihole64", NULL,
                                                ctxt, &bytes, 1024,
                                                1024ULL * ULONG_MAX, false)) < 0)
                goto error;

            if (rc == 1)
                def->opts.pciopts.pcihole64 = true;
            def->opts.pciopts.pcihole64size = VIR_DIV_UP(bytes, 1024);
        }
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
            /* Other controller models don't require extra checks */
            break;
        }
        if (modelName &&
            (def->opts.pciopts.modelName
             = virDomainControllerPCIModelNameTypeFromString(modelName)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown PCI controller model name '%s'"),
                           modelName);
            goto error;
        }
        if (chassisNr) {
            if (virStrToLong_i(chassisNr, NULL, 0,
                               &def->opts.pciopts.chassisNr) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid chassisNr '%s' in PCI controller"),
                               chassisNr);
                goto error;
            }
            if (def->opts.pciopts.chassisNr < 1 ||
                def->opts.pciopts.chassisNr > 255) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("PCI controller chassisNr '%s' out of range "
                                 "- must be 1-255"),
                               chassisNr);
                goto error;
            }
        }
        if (chassis) {
            if (virStrToLong_i(chassis, NULL, 0,
                               &def->opts.pciopts.chassis) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid chassis '%s' in PCI controller"),
                               chassis);
                goto error;
            }
            if (def->opts.pciopts.chassis < 0 ||
                def->opts.pciopts.chassis > 255) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("PCI controller chassis '%s' out of range "
                                 "- must be 0-255"),
                               chassis);
                goto error;
            }
        }
        if (port) {
            if (virStrToLong_i(port, NULL, 0,
                               &def->opts.pciopts.port) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid port '%s' in PCI controller"),
                               port);
                goto error;
            }
            if (def->opts.pciopts.port < 0 ||
                def->opts.pciopts.port > 255) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("PCI controller port '%s' out of range "
                                 "- must be 0-255"),
                               port);
                goto error;
            }
        }
        if (busNr) {
            if (virStrToLong_i(busNr, NULL, 0,
                               &def->opts.pciopts.busNr) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid busNr '%s' in PCI controller"),
                               busNr);
                goto error;
            }
            if (def->opts.pciopts.busNr < 1 ||
                def->opts.pciopts.busNr > 254) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("PCI controller busNr '%s' out of range "
                                 "- must be 1-254"),
                               busNr);
                goto error;
            }
        }
        if (numaNode >= 0)
            def->opts.pciopts.numaNode = numaNode;
        break;

    default:
        break;
    }

 cleanup:
    ctxt->node = saved;
    VIR_FREE(typeStr);
    VIR_FREE(idx);
    VIR_FREE(model);
    VIR_FREE(queues);
    VIR_FREE(cmd_per_lun);
    VIR_FREE(max_sectors);
    VIR_FREE(modelName);
    VIR_FREE(chassisNr);
    VIR_FREE(chassis);
    VIR_FREE(port);
    VIR_FREE(busNr);
    VIR_FREE(ioeventfd);
    VIR_FREE(portsStr);
    VIR_FREE(iothread);

    return def;

 error:
    virDomainControllerDefFree(def);
    def = NULL;
    goto cleanup;
}


void
virDomainNetGenerateMAC(virDomainXMLOptionPtr xmlopt,
                        virMacAddrPtr mac)
{
    virMacAddrGenerate(xmlopt->config.macPrefix, mac);
}


/* Parse the XML definition for a disk
 * @param node XML nodeset to parse for disk definition
 */
static virDomainFSDefPtr
virDomainFSDefParseXML(xmlNodePtr node,
                       xmlXPathContextPtr ctxt,
                       unsigned int flags)
{
    virDomainFSDefPtr def;
    xmlNodePtr cur, save_node = ctxt->node;
    char *type = NULL;
    char *fsdriver = NULL;
    char *source = NULL;
    char *target = NULL;
    char *format = NULL;
    char *accessmode = NULL;
    char *wrpolicy = NULL;
    char *usage = NULL;
    char *units = NULL;

    ctxt->node = node;

    if (!(def = virDomainFSDefNew()))
        return NULL;

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->type = virDomainFSTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown filesystem type '%s'"), type);
            goto error;
        }
    } else {
        def->type = VIR_DOMAIN_FS_TYPE_MOUNT;
    }

    accessmode = virXMLPropString(node, "accessmode");
    if (accessmode) {
        if ((def->accessmode = virDomainFSAccessModeTypeFromString(accessmode)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown accessmode '%s'"), accessmode);
            goto error;
        }
    } else {
        def->accessmode = VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH;
    }

    if (virDomainParseScaledValue("./space_hard_limit[1]",
                                  NULL, ctxt, &def->space_hard_limit,
                                  1, ULLONG_MAX, false) < 0)
        goto error;

    if (virDomainParseScaledValue("./space_soft_limit[1]",
                                  NULL, ctxt, &def->space_soft_limit,
                                  1, ULLONG_MAX, false) < 0)
        goto error;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!source &&
                xmlStrEqual(cur->name, BAD_CAST "source")) {

                if (def->type == VIR_DOMAIN_FS_TYPE_MOUNT ||
                    def->type == VIR_DOMAIN_FS_TYPE_BIND) {
                    source = virXMLPropString(cur, "dir");
                } else if (def->type == VIR_DOMAIN_FS_TYPE_FILE) {
                    source = virXMLPropString(cur, "file");
                } else if (def->type == VIR_DOMAIN_FS_TYPE_BLOCK) {
                    source = virXMLPropString(cur, "dev");
                } else if (def->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
                    source = virXMLPropString(cur, "name");
                } else if (def->type == VIR_DOMAIN_FS_TYPE_RAM) {
                    usage = virXMLPropString(cur, "usage");
                    units = virXMLPropString(cur, "units");
                } else if (def->type == VIR_DOMAIN_FS_TYPE_VOLUME) {
                    def->src->type = VIR_STORAGE_TYPE_VOLUME;
                    if (virDomainDiskSourcePoolDefParse(cur, &def->src->srcpool) < 0)
                        goto error;
                }
            } else if (!target &&
                       xmlStrEqual(cur->name, BAD_CAST "target")) {
                target = virXMLPropString(cur, "dir");
            } else if (xmlStrEqual(cur->name, BAD_CAST "readonly")) {
                def->readonly = true;
            } else if (xmlStrEqual(cur->name, BAD_CAST "driver")) {
                if (!fsdriver)
                    fsdriver = virXMLPropString(cur, "type");
                if (!wrpolicy)
                    wrpolicy = virXMLPropString(cur, "wrpolicy");
                if (!format)
                    format = virXMLPropString(cur, "format");
            }
        }
        cur = cur->next;
    }

    if (fsdriver) {
        if ((def->fsdriver = virDomainFSDriverTypeFromString(fsdriver)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown fs driver type '%s'"), fsdriver);
            goto error;
        }
    }

    if (format) {
        if ((def->format = virStorageFileFormatTypeFromString(format)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown driver format value '%s'"), format);
            goto error;
        }
    }

    if (wrpolicy) {
        if ((def->wrpolicy = virDomainFSWrpolicyTypeFromString(wrpolicy)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown filesystem write policy '%s'"), wrpolicy);
            goto error;
        }
    } else {
        def->wrpolicy = VIR_DOMAIN_FS_WRPOLICY_DEFAULT;
    }

    if (source == NULL && def->type != VIR_DOMAIN_FS_TYPE_RAM
        && def->type != VIR_DOMAIN_FS_TYPE_VOLUME) {
        virReportError(VIR_ERR_NO_SOURCE,
                       target ? "%s" : NULL, target);
        goto error;
    }

    if (target == NULL) {
        virReportError(VIR_ERR_NO_TARGET,
                       source ? "%s" : NULL, source);
        goto error;
    }

    if (def->type == VIR_DOMAIN_FS_TYPE_RAM) {
        if (!usage) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing 'usage' attribute for RAM filesystem"));
            goto error;
        }
        if (virStrToLong_ull(usage, NULL, 10, &def->usage) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse usage '%s' for RAM filesystem"),
                           usage);
            goto error;
        }
        if (virScaleInteger(&def->usage, units,
                            1024, ULLONG_MAX) < 0)
            goto error;
    }

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

    def->src->path = source;
    source = NULL;
    def->dst = target;
    target = NULL;

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

 cleanup:
    ctxt->node = save_node;
    VIR_FREE(type);
    VIR_FREE(fsdriver);
    VIR_FREE(target);
    VIR_FREE(source);
    VIR_FREE(accessmode);
    VIR_FREE(wrpolicy);
    VIR_FREE(usage);
    VIR_FREE(units);
    VIR_FREE(format);

    return def;

 error:
    virDomainFSDefFree(def);
    def = NULL;
    goto cleanup;
}

static int
virDomainActualNetDefParseXML(xmlNodePtr node,
                              xmlXPathContextPtr ctxt,
                              virDomainNetDefPtr parent,
                              virDomainActualNetDefPtr *def,
                              unsigned int flags)
{
    virDomainActualNetDefPtr actual = NULL;
    int ret = -1;
    xmlNodePtr save_ctxt = ctxt->node;
    xmlNodePtr bandwidth_node = NULL;
    xmlNodePtr vlanNode;
    xmlNodePtr virtPortNode;
    char *type = NULL;
    char *mode = NULL;
    char *addrtype = NULL;
    char *trustGuestRxFilters = NULL;
    char *macTableManager = NULL;

    if (VIR_ALLOC(actual) < 0)
        return -1;

    ctxt->node = node;

    type = virXMLPropString(node, "type");
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing type attribute in interface's <actual> element"));
        goto error;
    }
    if ((actual->type = virDomainNetTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown type '%s' in interface's <actual> element"), type);
        goto error;
    }
    if (actual->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        actual->type != VIR_DOMAIN_NET_TYPE_DIRECT &&
        actual->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        actual->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported type '%s' in interface's <actual> element"),
                       type);
        goto error;
    }

    trustGuestRxFilters = virXMLPropString(node, "trustGuestRxFilters");
    if (trustGuestRxFilters &&
        ((actual->trustGuestRxFilters
          = virTristateBoolTypeFromString(trustGuestRxFilters)) <= 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown trustGuestRxFilters value '%s'"),
                       trustGuestRxFilters);
        goto error;
    }

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode) {
        if (actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
            actual->type == VIR_DOMAIN_NET_TYPE_DIRECT ||
            actual->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
            /* the virtualport in <actual> should always already
             * have an instanceid/interfaceid if its required,
             * so don't let the parser generate one */
            if (!(actual->virtPortProfile
                  = virNetDevVPortProfileParse(virtPortNode,
                                               VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES |
                                               VIR_VPORT_XML_REQUIRE_TYPE))) {
                goto error;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("<virtualport> element unsupported for type='%s'"
                             " in interface's <actual> element"), type);
            goto error;
        }
    }

    if (actual->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        actual->data.direct.linkdev = virXPathString("string(./source[1]/@dev)", ctxt);

        mode = virXPathString("string(./source[1]/@mode)", ctxt);
        if (mode) {
            int m;
            if ((m = virNetDevMacVLanModeTypeFromString(mode)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unknown mode '%s' in interface <actual> element"),
                               mode);
                goto error;
            }
            actual->data.direct.mode = m;
        }
    } else if (actual->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virDomainHostdevDefPtr hostdev = &actual->data.hostdev.def;

        hostdev->parent.type = VIR_DOMAIN_DEVICE_NET;
        hostdev->parent.data.net = parent;
        hostdev->info = &parent->info;
        /* The helper function expects type to already be found and
         * passed in as a string, since it is in a different place in
         * NetDef vs HostdevDef.
         */
        addrtype = virXPathString("string(./source/address/@type)", ctxt);
        /* if not explicitly stated, source/vendor implies usb device */
        if (!addrtype && virXPathNode("./source/vendor", ctxt) &&
            VIR_STRDUP(addrtype, "usb") < 0)
            goto error;
        hostdev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, addrtype,
                                              hostdev, flags) < 0) {
            goto error;
        }
    } else if (actual->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        char *class_id = virXPathString("string(./class/@id)", ctxt);
        if (class_id &&
            virStrToLong_ui(class_id, NULL, 10, &actual->class_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse class id '%s'"),
                           class_id);
            VIR_FREE(class_id);
            goto error;
        }
        VIR_FREE(class_id);
    }
    if (actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        actual->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        char *brname = virXPathString("string(./source/@bridge)", ctxt);

        if (!brname && actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing <source> element with bridge name in "
                             "interface's <actual> element"));
            goto error;
        }
        actual->data.bridge.brname = brname;
        macTableManager = virXPathString("string(./source/@macTableManager)", ctxt);
        if (macTableManager &&
            (actual->data.bridge.macTableManager
             = virNetworkBridgeMACTableManagerTypeFromString(macTableManager)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid macTableManager setting '%s' "
                             "in domain interface's <actual> element"),
                           macTableManager);
            goto error;
        }
    }

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        virNetDevBandwidthParse(&actual->bandwidth,
                                bandwidth_node,
                                actual->type) < 0)
        goto error;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &actual->vlan) < 0)
        goto error;

    *def = actual;
    actual = NULL;
    ret = 0;
 error:
    VIR_FREE(type);
    VIR_FREE(mode);
    VIR_FREE(addrtype);
    VIR_FREE(trustGuestRxFilters);
    VIR_FREE(macTableManager);
    virDomainActualNetDefFree(actual);

    ctxt->node = save_ctxt;
    return ret;
}

#define NET_MODEL_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


int
virDomainNetAppendIPAddress(virDomainNetDefPtr def,
                            const char *address,
                            int family,
                            unsigned int prefix)
{
    virNetDevIPAddrPtr ipDef = NULL;
    if (VIR_ALLOC(ipDef) < 0)
        return -1;

    if (virSocketAddrParse(&ipDef->address, address, family) < 0)
        goto error;
    ipDef->prefix = prefix;

    if (VIR_APPEND_ELEMENT(def->guestIP.ips, def->guestIP.nips, ipDef) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(ipDef);
    return -1;
}

/* Parse the XML definition for a network interface
 * @param node XML nodeset to parse for net definition
 * @return 0 on success, -1 on failure
 */
static virDomainNetDefPtr
virDomainNetDefParseXML(virDomainXMLOptionPtr xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        virHashTablePtr bootHash,
                        char *prefix,
                        unsigned int flags)
{
    virDomainNetDefPtr def;
    virDomainHostdevDefPtr hostdev;
    xmlNodePtr cur;
    char *macaddr = NULL;
    char *type = NULL;
    char *network = NULL;
    char *portgroup = NULL;
    char *bridge = NULL;
    char *dev = NULL;
    char *ifname = NULL;
    char *ifname_guest = NULL;
    char *ifname_guest_actual = NULL;
    char *script = NULL;
    char *address = NULL;
    char *port = NULL;
    char *localaddr = NULL;
    char *localport = NULL;
    char *model = NULL;
    char *backend = NULL;
    char *txmode = NULL;
    char *ioeventfd = NULL;
    char *event_idx = NULL;
    char *queues = NULL;
    char *rx_queue_size = NULL;
    char *str = NULL;
    char *filter = NULL;
    char *internal = NULL;
    char *devaddr = NULL;
    char *mode = NULL;
    char *linkstate = NULL;
    char *addrtype = NULL;
    char *domain_name = NULL;
    char *vhostuser_mode = NULL;
    char *vhostuser_path = NULL;
    char *vhostuser_type = NULL;
    char *trustGuestRxFilters = NULL;
    char *vhost_path = NULL;
    virNWFilterHashTablePtr filterparams = NULL;
    virDomainActualNetDefPtr actual = NULL;
    xmlNodePtr oldnode = ctxt->node;
    int rv, val;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    ctxt->node = node;

    type = virXMLPropString(node, "type");
    if (type != NULL) {
        if ((int)(def->type = virDomainNetTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown interface type '%s'"), type);
            goto error;
        }
    } else {
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    }

    trustGuestRxFilters = virXMLPropString(node, "trustGuestRxFilters");
    if (trustGuestRxFilters &&
        ((def->trustGuestRxFilters
          = virTristateBoolTypeFromString(trustGuestRxFilters)) <= 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown trustGuestRxFilters value '%s'"),
                       trustGuestRxFilters);
        goto error;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                xmlNodePtr tmpnode = ctxt->node;

                ctxt->node = cur;
                if (virDomainNetIPInfoParseXML(_("interface host IP"),
                                               ctxt, &def->hostIP) < 0)
                    goto error;
                ctxt->node = tmpnode;
            }
            if (!macaddr && xmlStrEqual(cur->name, BAD_CAST "mac")) {
                macaddr = virXMLPropString(cur, "address");
            } else if (!network &&
                       def->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                network = virXMLPropString(cur, "network");
                portgroup = virXMLPropString(cur, "portgroup");
            } else if (!internal &&
                       def->type == VIR_DOMAIN_NET_TYPE_INTERNAL &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                internal = virXMLPropString(cur, "name");
            } else if (!bridge &&
                       def->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                bridge = virXMLPropString(cur, "bridge");
            } else if (!dev && def->type == VIR_DOMAIN_NET_TYPE_DIRECT &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                dev  = virXMLPropString(cur, "dev");
                mode = virXMLPropString(cur, "mode");
            } else if (!dev && def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                /* This clause is only necessary because from 2010 to
                 * 2016 it was possible (but never documented) to
                 * configure the name of the guest-side interface of
                 * an openvz domain with <source dev='blah'/>.  That
                 * was blatant misuse of <source>, so was likely
                 * (hopefully) never used, but just in case there was
                 * somebody using it, we need to generate an error. If
                 * the openvz driver is ever deprecated, this clause
                 * can be removed from here.
                 */
                if ((dev = virXMLPropString(cur, "dev"))) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("Invalid attempt to set <interface type='ethernet'> "
                                     "device name with <source dev='%s'/>. "
                                     "Use <target dev='%s'/> (for host-side) "
                                     "or <guest dev='%s'/> (for guest-side) instead."),
                                   dev, dev, dev);
                    goto error;
                }
            } else if (!vhostuser_path && !vhostuser_mode && !vhostuser_type
                       && def->type == VIR_DOMAIN_NET_TYPE_VHOSTUSER &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                vhostuser_type = virXMLPropString(cur, "type");
                vhostuser_path = virXMLPropString(cur, "path");
                vhostuser_mode = virXMLPropString(cur, "mode");
            } else if (!def->virtPortProfile
                       && xmlStrEqual(cur->name, BAD_CAST "virtualport")) {
                if (def->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                    if (!(def->virtPortProfile
                          = virNetDevVPortProfileParse(cur,
                                                       VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS))) {
                        goto error;
                    }
                } else if (def->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
                           def->type == VIR_DOMAIN_NET_TYPE_DIRECT ||
                           def->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
                    if (!(def->virtPortProfile
                          = virNetDevVPortProfileParse(cur,
                                                       VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS|
                                                       VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES|
                                                       VIR_VPORT_XML_REQUIRE_TYPE))) {
                        goto error;
                    }
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("<virtualport> element unsupported for"
                                     " <interface type='%s'>"), type);
                    goto error;
                }
            } else if (!address &&
                       (def->type == VIR_DOMAIN_NET_TYPE_SERVER ||
                        def->type == VIR_DOMAIN_NET_TYPE_CLIENT ||
                        def->type == VIR_DOMAIN_NET_TYPE_MCAST ||
                        def->type == VIR_DOMAIN_NET_TYPE_UDP) &&
                       xmlStrEqual(cur->name, BAD_CAST "source")) {
                address = virXMLPropString(cur, "address");
                port = virXMLPropString(cur, "port");
                if (!localaddr && def->type == VIR_DOMAIN_NET_TYPE_UDP) {
                    xmlNodePtr tmpnode = ctxt->node;
                    ctxt->node = cur;
                    localaddr = virXPathString("string(./local/@address)", ctxt);
                    localport = virXPathString("string(./local/@port)", ctxt);
                    ctxt->node = tmpnode;
                }
            } else if (!ifname &&
                       xmlStrEqual(cur->name, BAD_CAST "target")) {
                ifname = virXMLPropString(cur, "dev");
                if (ifname &&
                    (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
                    (STRPREFIX(ifname, VIR_NET_GENERATED_TAP_PREFIX) ||
                     (prefix && STRPREFIX(ifname, prefix)))) {
                    /* An auto-generated target name, blank it out */
                    VIR_FREE(ifname);
                }
            } else if ((!ifname_guest || !ifname_guest_actual) &&
                       xmlStrEqual(cur->name, BAD_CAST "guest")) {
                ifname_guest = virXMLPropString(cur, "dev");
                ifname_guest_actual = virXMLPropString(cur, "actual");
            } else if (!linkstate &&
                       xmlStrEqual(cur->name, BAD_CAST "link")) {
                linkstate = virXMLPropString(cur, "state");
            } else if (!script &&
                       xmlStrEqual(cur->name, BAD_CAST "script")) {
                script = virXMLPropString(cur, "path");
            } else if (!domain_name &&
                       xmlStrEqual(cur->name, BAD_CAST "backenddomain")) {
                domain_name = virXMLPropString(cur, "name");
            } else if (xmlStrEqual(cur->name, BAD_CAST "model")) {
                model = virXMLPropString(cur, "type");
            } else if (xmlStrEqual(cur->name, BAD_CAST "driver")) {
                backend = virXMLPropString(cur, "name");
                txmode = virXMLPropString(cur, "txmode");
                ioeventfd = virXMLPropString(cur, "ioeventfd");
                event_idx = virXMLPropString(cur, "event_idx");
                queues = virXMLPropString(cur, "queues");
                rx_queue_size = virXMLPropString(cur, "rx_queue_size");
            } else if (xmlStrEqual(cur->name, BAD_CAST "filterref")) {
                if (filter) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("Invalid specification of multiple <filterref>s "
                                     "in a single <interface>"));
                    goto error;
                }
                filter = virXMLPropString(cur, "filter");
                virNWFilterHashTableFree(filterparams);
                filterparams = virNWFilterParseParamAttributes(cur);
            } else if ((flags & VIR_DOMAIN_DEF_PARSE_STATUS) &&
                       xmlStrEqual(cur->name, BAD_CAST "state")) {
                /* Legacy back-compat. Don't add any more attributes here */
                devaddr = virXMLPropString(cur, "devaddr");
            } else if (xmlStrEqual(cur->name, BAD_CAST "boot")) {
                /* boot is parsed as part of virDomainDeviceInfoParseXML */
            } else if (!actual &&
                       (flags & VIR_DOMAIN_DEF_PARSE_ACTUAL_NET) &&
                       def->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
                       xmlStrEqual(cur->name, BAD_CAST "actual")) {
                if (virDomainActualNetDefParseXML(cur, ctxt, def,
                                                  &actual, flags) < 0) {
                    goto error;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "bandwidth")) {
                if (virNetDevBandwidthParse(&def->bandwidth,
                                            cur,
                                            def->type) < 0)
                    goto error;
            } else if (xmlStrEqual(cur->name, BAD_CAST "vlan")) {
                if (virNetDevVlanParse(cur, ctxt, &def->vlan) < 0)
                    goto error;
            } else if (xmlStrEqual(cur->name, BAD_CAST "backend")) {
                char *tmp = NULL;

                if ((tmp = virXMLPropString(cur, "tap")))
                    def->backend.tap = virFileSanitizePath(tmp);
                VIR_FREE(tmp);

                if (!vhost_path && (tmp = virXMLPropString(cur, "vhost")))
                    vhost_path = virFileSanitizePath(tmp);
                VIR_FREE(tmp);
            }
        }
        cur = cur->next;
    }

    if (macaddr) {
        if (virMacAddrParse((const char *)macaddr, &def->mac) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unable to parse mac address '%s'"),
                           (const char *)macaddr);
            goto error;
        }
        if (virMacAddrIsMulticast(&def->mac)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("expected unicast mac address, found multicast '%s'"),
                           (const char *)macaddr);
            goto error;
        }
    } else {
        virDomainNetGenerateMAC(xmlopt, &def->mac);
    }

    if (devaddr) {
        if (virDomainParseLegacyDeviceAddress(devaddr,
                                              &def->info.addr.pci) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse devaddr parameter '%s'"),
                           devaddr);
            goto error;
        }
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    } else {
        if (virDomainDeviceInfoParseXML(node, bootHash, &def->info,
                                        flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT
                                        | VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) < 0)
            goto error;
    }

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (network == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'network' attribute "
                             "specified with <interface type='network'/>"));
            goto error;
        }
        def->data.network.name = network;
        network = NULL;
        def->data.network.portgroup = portgroup;
        portgroup = NULL;
        def->data.network.actual = actual;
        actual = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        if (STRNEQ_NULLABLE(model, "virtio")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Wrong or no <model> 'type' attribute "
                             "specified with <interface type='vhostuser'/>. "
                             "vhostuser requires the virtio-net* frontend"));
            goto error;
        }

        if (STRNEQ_NULLABLE(vhostuser_type, "unix")) {
            if (vhostuser_type)
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Type='%s' unsupported for"
                                 " <interface type='vhostuser'>"),
                               vhostuser_type);
            else
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("No <source> 'type' attribute "
                                 "specified for <interface "
                                 "type='vhostuser'>"));
            goto error;
        }

        if (vhostuser_path == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'path' attribute "
                             "specified with <interface "
                             "type='vhostuser'/>"));
            goto error;
        }

        if (vhostuser_mode == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'mode' attribute "
                             "specified with <interface "
                             "type='vhostuser'/>"));
            goto error;
        }

        if (VIR_ALLOC(def->data.vhostuser) < 0)
            goto error;

        def->data.vhostuser->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        def->data.vhostuser->data.nix.path = vhostuser_path;
        vhostuser_path = NULL;

        if (STREQ(vhostuser_mode, "server")) {
            def->data.vhostuser->data.nix.listen = true;
        } else if (STREQ(vhostuser_mode, "client")) {
            def->data.vhostuser->data.nix.listen = false;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Wrong <source> 'mode' attribute "
                             "specified with <interface "
                             "type='vhostuser'/>"));
            goto error;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (bridge == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'bridge' attribute "
                             "specified with <interface type='bridge'/>"));
            goto error;
        }
        def->data.bridge.brname = bridge;
        bridge = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
        if (port == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'port' attribute "
                             "specified with socket interface"));
            goto error;
        }
        if (virStrToLong_i(port, NULL, 10, &def->data.socket.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <source> 'port' attribute "
                             "with socket interface"));
            goto error;
        }

        if (address == NULL) {
            if (def->type == VIR_DOMAIN_NET_TYPE_CLIENT ||
                def->type == VIR_DOMAIN_NET_TYPE_MCAST ||
                def->type == VIR_DOMAIN_NET_TYPE_UDP) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("No <source> 'address' attribute "
                                 "specified with socket interface"));
                goto error;
            }
        } else {
            def->data.socket.address = address;
            address = NULL;
        }

        if (def->type != VIR_DOMAIN_NET_TYPE_UDP)
            break;

        if (localport == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <local> 'port' attribute "
                             "specified with socket interface"));
            goto error;
        }
        if (virStrToLong_i(localport, NULL, 10, &def->data.socket.localport) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <local> 'port' attribute "
                             "with socket interface"));
            goto error;
        }

        if (localaddr == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <local> 'address' attribute "
                             "specified with socket interface"));
            goto error;
        } else {
            def->data.socket.localaddr = localaddr;
            localaddr = NULL;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        if (internal == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'name' attribute specified "
                             "with <interface type='internal'/>"));
            goto error;
        }
        def->data.internal.name = internal;
        internal = NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        if (dev == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No <source> 'dev' attribute specified "
                             "with <interface type='direct'/>"));
            goto error;
        }

        if (mode != NULL) {
            if ((val = virNetDevMacVLanModeTypeFromString(mode)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Unknown mode has been specified"));
                goto error;
            }
            def->data.direct.mode = val;
        } else {
            def->data.direct.mode = VIR_NETDEV_MACVLAN_MODE_VEPA;
        }

        def->data.direct.linkdev = dev;
        dev = NULL;

        if (ifname &&
            flags & VIR_DOMAIN_DEF_PARSE_INACTIVE &&
            (STRPREFIX(ifname, VIR_NET_GENERATED_MACVTAP_PREFIX) ||
             STRPREFIX(ifname, VIR_NET_GENERATED_MACVLAN_PREFIX))) {
            VIR_FREE(ifname);
        }

        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        hostdev = &def->data.hostdev.def;
        hostdev->parent.type = VIR_DOMAIN_DEVICE_NET;
        hostdev->parent.data.net = def;
        hostdev->info = &def->info;
        /* The helper function expects type to already be found and
         * passed in as a string, since it is in a different place in
         * NetDef vs HostdevDef.
         */
        addrtype = virXPathString("string(./source/address/@type)", ctxt);
        /* if not explicitly stated, source/vendor implies usb device */
        if (!addrtype && virXPathNode("./source/vendor", ctxt) &&
            VIR_STRDUP(addrtype, "usb") < 0)
            goto error;
        hostdev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, addrtype,
                                              hostdev, flags) < 0) {
            goto error;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    if (virDomainNetIPInfoParseXML(_("guest interface"),
                                   ctxt, &def->guestIP) < 0)
        goto error;

    if (script != NULL) {
        def->script = script;
        script = NULL;
    }
    if (domain_name != NULL) {
        def->domain_name = domain_name;
        domain_name = NULL;
    }
    if (ifname != NULL) {
        def->ifname = ifname;
        ifname = NULL;
    }
    if (ifname_guest != NULL) {
        def->ifname_guest = ifname_guest;
        ifname_guest = NULL;
    }
    if (ifname_guest_actual != NULL) {
        def->ifname_guest_actual = ifname_guest_actual;
        ifname_guest_actual = NULL;
    }

    /* NIC model (see -net nic,model=?).  We only check that it looks
     * reasonable, not that it is a supported NIC type.  FWIW kvm
     * supports these types as of April 2008:
     * i82551 i82557b i82559er ne2k_pci pcnet rtl8139 e1000 virtio
     * QEMU PPC64 supports spapr-vlan
     */
    if (model != NULL) {
        if (strspn(model, NET_MODEL_CHARS) < strlen(model)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Model name contains invalid characters"));
            goto error;
        }
        def->model = model;
        model = NULL;
    }

    if (def->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        STREQ_NULLABLE(def->model, "virtio")) {
        if (backend != NULL) {
            if ((val = virDomainNetBackendTypeFromString(backend)) < 0 ||
                val == VIR_DOMAIN_NET_BACKEND_TYPE_DEFAULT) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unknown interface <driver name='%s'> "
                                 "has been specified"),
                               backend);
                goto error;
            }
            def->driver.virtio.name = val;
        }
        if (txmode != NULL) {
            if ((val = virDomainNetVirtioTxModeTypeFromString(txmode)) < 0 ||
                val == VIR_DOMAIN_NET_VIRTIO_TX_MODE_DEFAULT) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unknown interface <driver txmode='%s'> "
                                 "has been specified"),
                               txmode);
                goto error;
            }
            def->driver.virtio.txmode = val;
        }
        if (ioeventfd) {
            if ((val = virTristateSwitchTypeFromString(ioeventfd)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown interface ioeventfd mode '%s'"),
                               ioeventfd);
                goto error;
            }
            def->driver.virtio.ioeventfd = val;
        }
        if (event_idx) {
            if ((val = virTristateSwitchTypeFromString(event_idx)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown interface event_idx mode '%s'"),
                               event_idx);
                goto error;
            }
            def->driver.virtio.event_idx = val;
        }
        if (queues) {
            unsigned int q;
            if (virStrToLong_uip(queues, NULL, 10, &q) < 0) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("'queues' attribute must be positive number: %s"),
                               queues);
                goto error;
            }
            if (q > 1)
                def->driver.virtio.queues = q;
        }
        if (rx_queue_size) {
            unsigned int q;
            if (virStrToLong_uip(rx_queue_size, NULL, 10, &q) < 0) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("'rx_queue_size' attribute must be positive number: %s"),
                               rx_queue_size);
                goto error;
            }
            def->driver.virtio.rx_queue_size = q;
        }
        if ((str = virXPathString("string(./driver/host/@csum)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host csum mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.csum = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@gso)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host gso mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.gso = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@tso4)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host tso4 mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.tso4 = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@tso6)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host tso6 mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.tso6 = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@ecn)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host ecn mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.ecn = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@ufo)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host ufo mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.ufo = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/host/@mrg_rxbuf)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown host mrg_rxbuf mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.host.mrg_rxbuf = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/guest/@csum)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown guest csum mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.guest.csum = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/guest/@tso4)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown guest tso4 mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.guest.tso4 = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/guest/@tso6)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown guest tso6 mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.guest.tso6 = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/guest/@ecn)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown guest ecn mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.guest.ecn = val;
        }
        VIR_FREE(str);
        if ((str = virXPathString("string(./driver/guest/@ufo)", ctxt))) {
            if ((val = virTristateSwitchTypeFromString(str)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown guest ufo mode '%s'"),
                               str);
                goto error;
            }
            def->driver.virtio.guest.ufo = val;
        }
        def->backend.vhost = vhost_path;
        vhost_path = NULL;
    }

    def->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DEFAULT;
    if (linkstate != NULL) {
        if ((def->linkstate = virDomainNetInterfaceLinkStateTypeFromString(linkstate)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown interface link state '%s'"),
                           linkstate);
            goto error;
        }
    }

    if (filter != NULL) {
        switch (def->type) {
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            def->filter = filter;
            filter = NULL;
            def->filterparams = filterparams;
            filterparams = NULL;
            break;
        default:
            break;
        }
    }

    rv = virXPathULong("string(./tune/sndbuf)", ctxt, &def->tune.sndbuf);
    if (rv >= 0) {
        def->tune.sndbuf_specified = true;
    } else if (rv == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("sndbuf must be a positive integer"));
        goto error;
    }

    if (virXPathUInt("string(./mtu/@size)", ctxt, &def->mtu) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("malformed mtu size"));
        goto error;
    }

    node = virXPathNode("./coalesce", ctxt);
    if (node) {
        def->coalesce = virDomainNetDefCoalesceParseXML(node, ctxt);
        if (!def->coalesce)
            goto error;
    }

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

 cleanup:
    ctxt->node = oldnode;
    VIR_FREE(macaddr);
    VIR_FREE(network);
    VIR_FREE(portgroup);
    VIR_FREE(address);
    VIR_FREE(port);
    VIR_FREE(vhostuser_type);
    VIR_FREE(vhostuser_path);
    VIR_FREE(vhostuser_mode);
    VIR_FREE(ifname);
    VIR_FREE(ifname_guest);
    VIR_FREE(ifname_guest_actual);
    VIR_FREE(dev);
    virDomainActualNetDefFree(actual);
    VIR_FREE(script);
    VIR_FREE(bridge);
    VIR_FREE(model);
    VIR_FREE(backend);
    VIR_FREE(txmode);
    VIR_FREE(ioeventfd);
    VIR_FREE(event_idx);
    VIR_FREE(queues);
    VIR_FREE(rx_queue_size);
    VIR_FREE(str);
    VIR_FREE(filter);
    VIR_FREE(type);
    VIR_FREE(internal);
    VIR_FREE(devaddr);
    VIR_FREE(mode);
    VIR_FREE(linkstate);
    VIR_FREE(addrtype);
    VIR_FREE(domain_name);
    VIR_FREE(trustGuestRxFilters);
    VIR_FREE(vhost_path);
    VIR_FREE(localaddr);
    VIR_FREE(localport);
    virNWFilterHashTableFree(filterparams);

    return def;

 error:
    virDomainNetDefFree(def);
    def = NULL;
    goto cleanup;
}

static int
virDomainChrDefaultTargetType(int devtype)
{
    switch ((virDomainChrDeviceType) devtype) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        virReportError(VIR_ERR_XML_ERROR,
                       _("target type must be specified for %s device"),
                       virDomainChrDeviceTypeToString(devtype));
        return -1;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* No target type yet*/
        break;
    }

    return 0;
}

static int
virDomainChrTargetTypeFromString(virDomainChrDefPtr def,
                                 int devtype,
                                 const char *targetType)
{
    int ret = -1;

    if (!targetType)
        return virDomainChrDefaultTargetType(devtype);

    switch ((virDomainChrDeviceType) devtype) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        ret = virDomainChrChannelTargetTypeFromString(targetType);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        ret = virDomainChrConsoleTargetTypeFromString(targetType);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        ret = virDomainChrSerialTargetTypeFromString(targetType);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* No target type yet*/
        ret = 0;
        break;
    }

    def->targetTypeAttr = true;

    return ret;
}

static int
virDomainChrDefParseTargetXML(virDomainChrDefPtr def,
                              xmlNodePtr cur,
                              unsigned int flags)
{
    int ret = -1;
    unsigned int port;
    char *targetType = virXMLPropString(cur, "type");
    char *addrStr = NULL;
    char *portStr = NULL;
    char *stateStr = NULL;

    if ((def->targetType =
         virDomainChrTargetTypeFromString(def, def->deviceType,
                                          targetType)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown target type '%s' specified for character device"),
                       targetType);
        goto error;
    }

    switch (def->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        switch (def->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            addrStr = virXMLPropString(cur, "address");
            portStr = virXMLPropString(cur, "port");

            if (VIR_ALLOC(def->target.addr) < 0)
                goto error;

            if (addrStr == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("guestfwd channel does not "
                                 "define a target address"));
                goto error;
            }

            if (virSocketAddrParse(def->target.addr, addrStr, AF_UNSPEC) < 0)
                goto error;

            if (def->target.addr->data.stor.ss_family != AF_INET) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("guestfwd channel only supports "
                                       "IPv4 addresses"));
                goto error;
            }

            if (portStr == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("guestfwd channel does "
                                 "not define a target port"));
                goto error;
            }

            if (virStrToLong_ui(portStr, NULL, 10, &port) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid port number: %s"),
                               portStr);
                goto error;
            }

            virSocketAddrSetPort(def->target.addr, port);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            def->target.name = virXMLPropString(cur, "name");

            if (def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
                !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
                (stateStr = virXMLPropString(cur, "state"))) {
                int tmp;

                if ((tmp = virDomainChrDeviceStateTypeFromString(stateStr)) <= 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("invalid channel state value '%s'"),
                                   stateStr);
                    goto error;
                }

                def->state = tmp;
            }
            break;
        }
        break;

    default:
        portStr = virXMLPropString(cur, "port");
        if (portStr == NULL) {
            /* Set to negative value to indicate we should set it later */
            def->target.port = -1;
            break;
        }

        if (virStrToLong_ui(portStr, NULL, 10, &port) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid port number: %s"),
                           portStr);
            goto error;
        }
        def->target.port = port;
        break;
    }


    ret = 0;
 error:
    VIR_FREE(targetType);
    VIR_FREE(addrStr);
    VIR_FREE(portStr);
    VIR_FREE(stateStr);

    return ret;
}

#define SERIAL_CHANNEL_NAME_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."

/* Parse the source half of the XML definition for a character device,
 * where node is the first element of node->children of the parent
 * element.  def->type must already be valid.  Return -1 on failure,
 * otherwise the number of ignored children (this intentionally skips
 * <target>, which is used by <serial> but not <smartcard>). */
static int
virDomainChrSourceDefParseXML(virDomainChrSourceDefPtr def,
                              xmlNodePtr cur, unsigned int flags,
                              virDomainChrDefPtr chr_def,
                              xmlXPathContextPtr ctxt,
                              virSecurityLabelDefPtr* vmSeclabels,
                              int nvmSeclabels)
{
    char *bindHost = NULL;
    char *bindService = NULL;
    char *connectHost = NULL;
    char *connectService = NULL;
    char *path = NULL;
    char *logfile = NULL;
    char *logappend = NULL;
    char *mode = NULL;
    char *protocol = NULL;
    char *channel = NULL;
    char *master = NULL;
    char *slave = NULL;
    char *append = NULL;
    char *haveTLS = NULL;
    char *tlsFromConfig = NULL;
    int remaining = 0;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                if (!mode)
                    mode = virXMLPropString(cur, "mode");
                if (!haveTLS)
                    haveTLS = virXMLPropString(cur, "tls");
                if (!tlsFromConfig)
                    tlsFromConfig = virXMLPropString(cur, "tlsFromConfig");

                switch ((virDomainChrType) def->type) {
                case VIR_DOMAIN_CHR_TYPE_FILE:
                case VIR_DOMAIN_CHR_TYPE_PTY:
                case VIR_DOMAIN_CHR_TYPE_DEV:
                case VIR_DOMAIN_CHR_TYPE_PIPE:
                case VIR_DOMAIN_CHR_TYPE_UNIX:
                    if (!append && def->type == VIR_DOMAIN_CHR_TYPE_FILE)
                        append = virXMLPropString(cur, "append");
                    /* PTY path is only parsed from live xml.  */
                    if (!path  &&
                        (def->type != VIR_DOMAIN_CHR_TYPE_PTY ||
                         !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)))
                        path = virXMLPropString(cur, "path");

                    break;

                case VIR_DOMAIN_CHR_TYPE_UDP:
                case VIR_DOMAIN_CHR_TYPE_TCP:
                    if (!mode || STREQ(mode, "connect")) {
                        if (!connectHost)
                            connectHost = virXMLPropString(cur, "host");
                        if (!connectService)
                            connectService = virXMLPropString(cur, "service");
                    } else if (STREQ(mode, "bind")) {
                        if (!bindHost)
                            bindHost = virXMLPropString(cur, "host");
                        if (!bindService)
                            bindService = virXMLPropString(cur, "service");
                    } else {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Unknown source mode '%s'"), mode);
                        goto error;
                    }

                    if (def->type == VIR_DOMAIN_CHR_TYPE_UDP)
                        VIR_FREE(mode);
                    break;

                case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
                    if (!channel)
                        channel = virXMLPropString(cur, "channel");
                    break;

                case VIR_DOMAIN_CHR_TYPE_NMDM:
                    if (!master)
                        master = virXMLPropString(cur, "master");
                    if (!slave)
                        slave = virXMLPropString(cur, "slave");
                    break;

                case VIR_DOMAIN_CHR_TYPE_LAST:
                case VIR_DOMAIN_CHR_TYPE_NULL:
                case VIR_DOMAIN_CHR_TYPE_VC:
                case VIR_DOMAIN_CHR_TYPE_STDIO:
                case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
                    break;
                }

                /* Check for an optional seclabel override in <source/>. */
                if (chr_def) {
                    xmlNodePtr saved_node = ctxt->node;
                    ctxt->node = cur;
                    if (virSecurityDeviceLabelDefParseXML(&chr_def->seclabels,
                                                          &chr_def->nseclabels,
                                                          vmSeclabels,
                                                          nvmSeclabels,
                                                          ctxt,
                                                          flags) < 0) {
                        ctxt->node = saved_node;
                        goto error;
                    }
                    ctxt->node = saved_node;
                }
            } else if (xmlStrEqual(cur->name, BAD_CAST "log")) {
                if (!logfile)
                    logfile = virXMLPropString(cur, "file");
                if (!logappend)
                    logappend = virXMLPropString(cur, "append");
            } else if (xmlStrEqual(cur->name, BAD_CAST "protocol")) {
                if (!protocol)
                    protocol = virXMLPropString(cur, "type");
            } else {
                remaining++;
            }
        }
        cur = cur->next;
    }

    switch ((virDomainChrType) def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (append && def->type == VIR_DOMAIN_CHR_TYPE_FILE &&
            (def->data.file.append = virTristateSwitchTypeFromString(append)) <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid append attribute value '%s'"), append);
            goto error;
        }
        if (!path &&
            def->type != VIR_DOMAIN_CHR_TYPE_PTY) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source path attribute for char device"));
            goto error;
        }

        def->data.file.path = path;
        path = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        if (!master) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing master path attribute for nmdm device"));
            goto error;
        }

        if (!slave) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing slave path attribute for nmdm device"));
            goto error;
        }

        def->data.nmdm.master = master;
        def->data.nmdm.slave = slave;
        master = NULL;
        slave = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (!mode || STREQ(mode, "connect")) {
            if (!connectHost) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing source host attribute for char device"));
                goto error;
            }

            if (!connectService) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing source service attribute for char device"));
                goto error;
            }

            def->data.tcp.host = connectHost;
            connectHost = NULL;
            def->data.tcp.service = connectService;
            connectService = NULL;
            def->data.tcp.listen = false;
        } else {
            if (!bindHost) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing source host attribute for char device"));
                goto error;
            }

            if (!bindService) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing source service attribute for char device"));
                goto error;
            }

            def->data.tcp.host = bindHost;
            bindHost = NULL;
            def->data.tcp.service = bindService;
            bindService = NULL;
            def->data.tcp.listen = true;
        }

        if (haveTLS &&
            (def->data.tcp.haveTLS =
             virTristateBoolTypeFromString(haveTLS)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown chardev 'tls' setting '%s'"),
                           haveTLS);
            goto error;
        }

        if (tlsFromConfig &&
            flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
            int tmp;
            if (virStrToLong_i(tlsFromConfig, NULL, 10, &tmp) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid tlsFromConfig value: %s"),
                               tlsFromConfig);
                goto error;
            }
            def->data.tcp.tlsFromConfig = !!tmp;
        }

        if (!protocol)
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW;
        else if ((def->data.tcp.protocol =
                  virDomainChrTcpProtocolTypeFromString(protocol)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown protocol '%s'"), protocol);
            goto error;
        }

        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (!connectService) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source service attribute for char device"));
            goto error;
        }

        def->data.udp.connectHost = connectHost;
        connectHost = NULL;
        def->data.udp.connectService = connectService;
        connectService = NULL;

        def->data.udp.bindHost = bindHost;
        bindHost = NULL;
        def->data.udp.bindService = bindService;
        bindService = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        /* path can be auto generated */
        if (!path &&
            (!chr_def ||
             (chr_def->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN &&
              chr_def->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source path attribute for char device"));
            goto error;
        }

        def->data.nix.listen = mode != NULL && STRNEQ(mode, "connect");

        def->data.nix.path = path;
        path = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        if (!channel) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing source channel attribute for char device"));
            goto error;
        }
        if (strspn(channel, SERIAL_CHANNEL_NAME_CHARS) < strlen(channel)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Invalid character in source channel for char device"));
            goto error;
        }
        def->data.spiceport.channel = channel;
        channel = NULL;
        break;
    }

    def->logfile = logfile;
    logfile = NULL;

    if (logappend != NULL &&
        (def->logappend = virTristateSwitchTypeFromString(logappend)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid append attribute value '%s'"), logappend);
        goto error;
    }

 cleanup:
    VIR_FREE(mode);
    VIR_FREE(protocol);
    VIR_FREE(bindHost);
    VIR_FREE(bindService);
    VIR_FREE(connectHost);
    VIR_FREE(connectService);
    VIR_FREE(path);
    VIR_FREE(channel);
    VIR_FREE(append);
    VIR_FREE(logappend);
    VIR_FREE(logfile);
    VIR_FREE(haveTLS);
    VIR_FREE(tlsFromConfig);

    return remaining;

 error:
    virDomainChrSourceDefClear(def);
    remaining = -1;
    goto cleanup;
}


static virDomainChrSourceDefPtr
virDomainChrSourceDefNew(virDomainXMLOptionPtr xmlopt)
{
    virDomainChrSourceDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (xmlopt && xmlopt->privateData.chrSourceNew &&
        !(def->privateData = xmlopt->privateData.chrSourceNew()))
        VIR_FREE(def);

    return def;
}


/* Create a new character device definition and set
 * default port.
 */
virDomainChrDefPtr
virDomainChrDefNew(virDomainXMLOptionPtr xmlopt)
{
    virDomainChrDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->target.port = -1;

    if (!(def->source = virDomainChrSourceDefNew(xmlopt)))
        VIR_FREE(def);

    return def;
}

/* Parse the XML definition for a character device
 * @param node XML nodeset to parse for net definition
 *
 * The XML we're dealing with looks like
 *
 * <serial type="pty">
 *   <source path="/dev/pts/3"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="dev">
 *   <source path="/dev/ttyS0"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="tcp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 *   <protocol type='raw'/>
 * </serial>
 *
 * <serial type="udp">
 *   <source mode="bind" host="0.0.0.0" service="2445"/>
 *   <source mode="connect" host="0.0.0.0" service="2445"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="unix">
 *   <source mode="bind" path="/tmp/foo"/>
 *   <target port="1"/>
 * </serial>
 *
 * <serial type="nmdm">
 *   <source master="/dev/nmdm0A" slave="/dev/nmdm0B"/>
 *   <target port="1">
 * </serial>
 *
 */
static virDomainChrDefPtr
virDomainChrDefParseXML(virDomainXMLOptionPtr xmlopt,
                        xmlXPathContextPtr ctxt,
                        xmlNodePtr node,
                        virSecurityLabelDefPtr* vmSeclabels,
                        int nvmSeclabels,
                        unsigned int flags)
{
    xmlNodePtr cur;
    char *type = NULL;
    const char *nodeName;
    virDomainChrDefPtr def;
    bool seenTarget = false;

    if (!(def = virDomainChrDefNew(xmlopt)))
        return NULL;

    type = virXMLPropString(node, "type");
    if (type == NULL) {
        def->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if ((def->source->type = virDomainChrTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown type presented to host for character device: %s"),
                       type);
        goto error;
    }

    nodeName = (const char *) node->name;
    if ((def->deviceType = virDomainChrDeviceTypeFromString(nodeName)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown character device type: %s"),
                       nodeName);
        goto error;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "target")) {
                seenTarget = true;
                if (virDomainChrDefParseTargetXML(def, cur, flags) < 0)
                    goto error;
            }
        }
        cur = cur->next;
    }

    if (!seenTarget &&
        ((def->targetType = virDomainChrDefaultTargetType(def->deviceType)) < 0))
        goto error;

    if (virDomainChrSourceDefParseXML(def->source, node->children, flags, def,
                                      ctxt, vmSeclabels, nvmSeclabels) < 0)
        goto error;

    if (def->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
        if (def->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spicevmc device type only supports "
                             "virtio"));
            goto error;
        } else {
            def->source->data.spicevmc = VIR_DOMAIN_CHR_SPICEVMC_VDAGENT;
        }
    }

    if (def->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD) {
        VIR_DEBUG("Ignoring device address for gustfwd channel");
    } else if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0) {
        goto error;
    }


    if (def->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        def->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb-serial requires address of usb type"));
        goto error;
    }

 cleanup:
    VIR_FREE(type);

    return def;

 error:
    virDomainChrDefFree(def);
    def = NULL;
    goto cleanup;
}

static virDomainSmartcardDefPtr
virDomainSmartcardDefParseXML(virDomainXMLOptionPtr xmlopt,
                              xmlNodePtr node,
                              unsigned int flags)
{
    xmlNodePtr cur;
    char *mode = NULL;
    char *type = NULL;
    virDomainSmartcardDefPtr def;
    size_t i;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    mode = virXMLPropString(node, "mode");
    if (mode == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing smartcard device mode"));
        goto error;
    }
    if ((def->type = virDomainSmartcardTypeFromString(mode)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown smartcard device mode: %s"),
                       mode);
        goto error;
    }

    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        i = 0;
        cur = node->children;
        while (cur) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "certificate")) {
                if (i == 3) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("host-certificates mode needs "
                                     "exactly three certificates"));
                    goto error;
                }
                def->data.cert.file[i] = (char *)xmlNodeGetContent(cur);
                if (!def->data.cert.file[i]) {
                    virReportOOMError();
                    goto error;
                }
                i++;
            } else if (cur->type == XML_ELEMENT_NODE &&
                       xmlStrEqual(cur->name, BAD_CAST "database") &&
                       !def->data.cert.database) {
                def->data.cert.database = (char *)xmlNodeGetContent(cur);
                if (!def->data.cert.database) {
                    virReportOOMError();
                    goto error;
                }
                if (*def->data.cert.database != '/') {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("expecting absolute path: %s"),
                                   def->data.cert.database);
                    goto error;
                }
            }
            cur = cur->next;
        }
        if (i < 3) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("host-certificates mode needs "
                             "exactly three certificates"));
            goto error;
        }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        type = virXMLPropString(node, "type");
        if (type == NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("passthrough mode requires a character "
                             "device type attribute"));
            goto error;
        }

        if (!(def->data.passthru = virDomainChrSourceDefNew(xmlopt)))
            goto error;

        if ((def->data.passthru->type = virDomainChrTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown type presented to host for "
                             "character device: %s"), type);
            goto error;
        }

        cur = node->children;
        if (virDomainChrSourceDefParseXML(def->data.passthru, cur, flags,
                                          NULL, NULL, NULL, 0) < 0)
            goto error;

        if (def->data.passthru->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
            def->data.passthru->data.spicevmc
                = VIR_DOMAIN_CHR_SPICEVMC_SMARTCARD;
        }

        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unknown smartcard mode"));
        goto error;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;
    if (def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Controllers must use the 'ccid' address type"));
        goto error;
    }

 cleanup:
    VIR_FREE(mode);
    VIR_FREE(type);

    return def;

 error:
    virDomainSmartcardDefFree(def);
    def = NULL;
    goto cleanup;
}

/* Parse the XML definition for a TPM device
 *
 * The XML looks like this:
 *
 * <tpm model='tpm-tis'>
 *   <backend type='passthrough'>
 *     <device path='/dev/tpm0'/>
 *   </backend>
 * </tpm>
 *
 */
static virDomainTPMDefPtr
virDomainTPMDefParseXML(xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    char *type = NULL;
    char *path = NULL;
    char *model = NULL;
    char *backend = NULL;
    virDomainTPMDefPtr def;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr *backends = NULL;
    int nbackends;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    model = virXMLPropString(node, "model");
    if (model != NULL &&
        (int)(def->model = virDomainTPMModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown TPM frontend model '%s'"), model);
        goto error;
    } else {
        def->model = VIR_DOMAIN_TPM_MODEL_TIS;
    }

    ctxt->node = node;

    if ((nbackends = virXPathNodeSet("./backend", ctxt, &backends)) < 0)
        goto error;

    if (nbackends > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one TPM backend is supported"));
        goto error;
    }

    if (nbackends == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing TPM device backend"));
        goto error;
    }

    if (!(backend = virXMLPropString(backends[0], "type"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing TPM device backend type"));
        goto error;
    }

    if ((int)(def->type = virDomainTPMBackendTypeFromString(backend)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown TPM backend type '%s'"),
                       backend);
        goto error;
    }

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        path = virXPathString("string(./backend/device/@path)", ctxt);
        if (!path && VIR_STRDUP(path, VIR_DOMAIN_TPM_DEFAULT_DEVICE) < 0)
            goto error;
        def->data.passthrough.source.data.file.path = path;
        def->data.passthrough.source.type = VIR_DOMAIN_CHR_TYPE_DEV;
        path = NULL;
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        goto error;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(type);
    VIR_FREE(path);
    VIR_FREE(model);
    VIR_FREE(backend);
    VIR_FREE(backends);
    ctxt->node = save;
    return def;

 error:
    virDomainTPMDefFree(def);
    def = NULL;
    goto cleanup;
}

static virDomainPanicDefPtr
virDomainPanicDefParseXML(xmlNodePtr node,
                          unsigned int flags)
{
    virDomainPanicDefPtr panic;
    char *model = NULL;

    if (VIR_ALLOC(panic) < 0)
        return NULL;

    if (virDomainDeviceInfoParseXML(node, NULL, &panic->info, flags) < 0)
        goto error;

    model = virXMLPropString(node, "model");
    if (model != NULL &&
        (panic->model = virDomainPanicModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown panic model '%s'"), model);
        goto error;
    }

 cleanup:
    VIR_FREE(model);
    return panic;

 error:
    virDomainPanicDefFree(panic);
    panic = NULL;
    goto cleanup;
}

/* Parse the XML definition for an input device */
static virDomainInputDefPtr
virDomainInputDefParseXML(const virDomainDef *dom,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    xmlNodePtr save = ctxt->node;
    virDomainInputDefPtr def;
    char *evdev = NULL;
    char *type = NULL;
    char *bus = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    ctxt->node = node;

    type = virXMLPropString(node, "type");
    bus = virXMLPropString(node, "bus");

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing input device type"));
        goto error;
    }

    if ((def->type = virDomainInputTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown input device type '%s'"), type);
        goto error;
    }

    if (bus) {
        if ((def->bus = virDomainInputBusTypeFromString(bus)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown input bus type '%s'"), bus);
            goto error;
        }

        if (dom->os.type == VIR_DOMAIN_OSTYPE_HVM) {
            if (def->bus == VIR_DOMAIN_INPUT_BUS_PS2 &&
                def->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
                def->type != VIR_DOMAIN_INPUT_TYPE_KBD) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("ps2 bus does not support %s input device"),
                               type);
                goto error;
            }
            if (def->bus == VIR_DOMAIN_INPUT_BUS_XEN) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported input bus %s"),
                               bus);
                goto error;
            }
        } else if (dom->os.type == VIR_DOMAIN_OSTYPE_XEN) {
            if (def->bus != VIR_DOMAIN_INPUT_BUS_XEN) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported input bus %s"),
                               bus);
                goto error;
            }
            if (def->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
                def->type != VIR_DOMAIN_INPUT_TYPE_KBD) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("xen bus does not support %s input device"),
                               type);
                goto error;
            }
        } else {
            if (dom->virtType == VIR_DOMAIN_VIRT_VZ ||
                dom->virtType == VIR_DOMAIN_VIRT_PARALLELS) {
                if (def->bus != VIR_DOMAIN_INPUT_BUS_PARALLELS) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("parallels containers don't support "
                                     "input bus %s"),
                                   bus);
                    goto error;
                }

                if (def->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
                    def->type != VIR_DOMAIN_INPUT_TYPE_KBD) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("parallels bus does not support "
                                     "%s input device"),
                                   type);
                    goto error;
                }
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Input devices are not supported by this "
                                 "virtualization driver."));
                goto error;
            }
        }
    } else {
        if (dom->os.type == VIR_DOMAIN_OSTYPE_HVM) {
            if ((def->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ||
                def->type == VIR_DOMAIN_INPUT_TYPE_KBD) &&
                (ARCH_IS_X86(dom->os.arch) || dom->os.arch == VIR_ARCH_NONE)) {
                def->bus = VIR_DOMAIN_INPUT_BUS_PS2;
            } else {
                def->bus = VIR_DOMAIN_INPUT_BUS_USB;
            }
        } else if (dom->os.type == VIR_DOMAIN_OSTYPE_XEN) {
            def->bus = VIR_DOMAIN_INPUT_BUS_XEN;
        } else {
            if ((dom->virtType == VIR_DOMAIN_VIRT_VZ ||
                 dom->virtType == VIR_DOMAIN_VIRT_PARALLELS))
                def->bus = VIR_DOMAIN_INPUT_BUS_PARALLELS;
        }
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

    if (def->bus == VIR_DOMAIN_INPUT_BUS_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid address for a USB device"));
        goto error;
    }

    if ((evdev = virXPathString("string(./source/@evdev)", ctxt)))
        def->source.evdev = virFileSanitizePath(evdev);
    if (def->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH && !def->source.evdev) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing evdev path for input device passthrough"));
        goto error;
    }

 cleanup:
    VIR_FREE(evdev);
    VIR_FREE(type);
    VIR_FREE(bus);

    ctxt->node = save;
    return def;

 error:
    virDomainInputDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a hub device */
static virDomainHubDefPtr
virDomainHubDefParseXML(xmlNodePtr node, unsigned int flags)
{
    virDomainHubDefPtr def;
    char *type = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    type = virXMLPropString(node, "type");

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing hub device type"));
        goto error;
    }

    if ((def->type = virDomainHubTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown hub device type '%s'"), type);
        goto error;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(type);

    return def;

 error:
    virDomainHubDefFree(def);
    def = NULL;
    goto cleanup;
}


/* Parse the XML definition for a clock timer */
static virDomainTimerDefPtr
virDomainTimerDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    char *name = NULL;
    char *present = NULL;
    char *tickpolicy = NULL;
    char *track = NULL;
    char *mode = NULL;

    virDomainTimerDefPtr def;
    xmlNodePtr oldnode = ctxt->node;
    xmlNodePtr catchup;
    int ret;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    ctxt->node = node;

    name = virXMLPropString(node, "name");
    if (name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing timer name"));
        goto error;
    }
    if ((def->name = virDomainTimerNameTypeFromString(name)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown timer name '%s'"), name);
        goto error;
    }

    def->present = -1; /* unspecified */
    if ((present = virXMLPropString(node, "present")) != NULL) {
        if (STREQ(present, "yes")) {
            def->present = 1;
        } else if (STREQ(present, "no")) {
            def->present = 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown timer present value '%s'"), present);
            goto error;
        }
    }

    def->tickpolicy = -1;
    tickpolicy = virXMLPropString(node, "tickpolicy");
    if (tickpolicy != NULL) {
        if ((def->tickpolicy = virDomainTimerTickpolicyTypeFromString(tickpolicy)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown timer tickpolicy '%s'"), tickpolicy);
            goto error;
        }
    }

    def->track = -1;
    track = virXMLPropString(node, "track");
    if (track != NULL) {
        if ((def->track = virDomainTimerTrackTypeFromString(track)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown timer track '%s'"), track);
            goto error;
        }
    }

    ret = virXPathULong("string(./@frequency)", ctxt, &def->frequency);
    if (ret == -1) {
        def->frequency = 0;
    } else if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid timer frequency"));
        goto error;
    }

    def->mode = -1;
    mode = virXMLPropString(node, "mode");
    if (mode != NULL) {
        if ((def->mode = virDomainTimerModeTypeFromString(mode)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown timer mode '%s'"), mode);
            goto error;
        }
    }

    catchup = virXPathNode("./catchup", ctxt);
    if (catchup != NULL) {
        ret = virXPathULong("string(./catchup/@threshold)", ctxt,
                            &def->catchup.threshold);
        if (ret == -1) {
            def->catchup.threshold = 0;
        } else if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("invalid catchup threshold"));
            goto error;
        }

        ret = virXPathULong("string(./catchup/@slew)", ctxt, &def->catchup.slew);
        if (ret == -1) {
            def->catchup.slew = 0;
        } else if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("invalid catchup slew"));
            goto error;
        }

        ret = virXPathULong("string(./catchup/@limit)", ctxt, &def->catchup.limit);
        if (ret == -1) {
            def->catchup.limit = 0;
        } else if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("invalid catchup limit"));
            goto error;
        }
    }

 cleanup:
    VIR_FREE(name);
    VIR_FREE(present);
    VIR_FREE(tickpolicy);
    VIR_FREE(track);
    VIR_FREE(mode);
    ctxt->node = oldnode;

    return def;

 error:
    VIR_FREE(def);
    goto cleanup;
}


static int
virDomainGraphicsAuthDefParseXML(xmlNodePtr node,
                                 virDomainGraphicsAuthDefPtr def,
                                 int type)
{
    char *validTo = NULL;
    char *connected = virXMLPropString(node, "connected");

    def->passwd = virXMLPropString(node, "passwd");

    if (!def->passwd)
        return 0;

    validTo = virXMLPropString(node, "passwdValidTo");
    if (validTo) {
        char *tmp;
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        /* Expect: YYYY-MM-DDTHH:MM:SS (%d-%d-%dT%d:%d:%d)  eg 2010-11-28T14:29:01 */
        if (/* year */
            virStrToLong_i(validTo, &tmp, 10, &tm.tm_year) < 0 || *tmp != '-' ||
            /* month */
            virStrToLong_i(tmp+1, &tmp, 10, &tm.tm_mon) < 0 || *tmp != '-' ||
            /* day */
            virStrToLong_i(tmp+1, &tmp, 10, &tm.tm_mday) < 0 || *tmp != 'T' ||
            /* hour */
            virStrToLong_i(tmp+1, &tmp, 10, &tm.tm_hour) < 0 || *tmp != ':' ||
            /* minute */
            virStrToLong_i(tmp+1, &tmp, 10, &tm.tm_min) < 0 || *tmp != ':' ||
            /* second */
            virStrToLong_i(tmp+1, &tmp, 10, &tm.tm_sec) < 0 || *tmp != '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse password validity time '%s', expect YYYY-MM-DDTHH:MM:SS"),
                           validTo);
            VIR_FREE(validTo);
            VIR_FREE(def->passwd);
            return -1;
        }
        VIR_FREE(validTo);

        tm.tm_year -= 1900; /* Human epoch starts at 0 BC, not 1900BC */
        tm.tm_mon--; /* Humans start months at 1, computers at 0 */

        def->validTo = timegm(&tm);
        def->expires = true;
    }

    if (connected) {
        int action = virDomainGraphicsAuthConnectedTypeFromString(connected);
        if (action <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown connected value %s"),
                           connected);
            VIR_FREE(connected);
            return -1;
        }
        VIR_FREE(connected);

        /* VNC supports connected='keep' only */
        if (type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            action != VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_KEEP) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VNC supports connected='keep' only"));
            return -1;
        }

        def->connected = action;
    }

    return 0;
}


/**
 * virDomainGraphicsListenDefParseXML:
 * @def: listen def pointer to be filled
 * @graphics: graphics def pointer
 * @node: xml node of <listen/> element
 * @parent: xml node of <graphics/> element
 * @flags: bit-wise or of VIR_DOMAIN_DEF_PARSE_*
 *
 * Parses current <listen/> element from @node to @def.  For backward
 * compatibility the @parent element should contain node of <graphics/> element
 * for the first <listen/> element in order to validate attributes from both
 * elements.
 */
static int
virDomainGraphicsListenDefParseXML(virDomainGraphicsListenDefPtr def,
                                   virDomainGraphicsDefPtr graphics,
                                   xmlNodePtr node,
                                   xmlNodePtr parent,
                                   unsigned int flags)
{
    int ret = -1;
    char *type = virXMLPropString(node, "type");
    char *address = virXMLPropString(node, "address");
    char *network = virXMLPropString(node, "network");
    char *socketPath = virXMLPropString(node, "socket");
    char *fromConfig = virXMLPropString(node, "fromConfig");
    char *autoGenerated = virXMLPropString(node, "autoGenerated");
    char *addressCompat = NULL;
    char *socketCompat = NULL;
    const char *graphicsType = virDomainGraphicsTypeToString(graphics->type);
    int tmp, typeVal;

    if (parent) {
        addressCompat = virXMLPropString(parent, "listen");
        socketCompat = virXMLPropString(parent, "socket");
    }

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("graphics listen type must be specified"));
        goto error;
    }

    if ((typeVal = virDomainGraphicsListenTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown graphics listen type '%s'"), type);
        goto error;
    }
    def->type = typeVal;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
        if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("listen type 'socket' is not available for "
                             "graphics type '%s'"), graphicsType);
            goto error;
        }
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
            graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("listen type 'none' is not available for "
                             "graphics type '%s'"), graphicsType);
            goto error;
        }
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        break;
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS) {
        if (address && addressCompat && STRNEQ(address, addressCompat)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("graphics 'listen' attribute '%s' must match "
                             "'address' attribute of first listen element "
                             "(found '%s')"), addressCompat, address);
            goto error;
        }

        if (!address) {
            address = addressCompat;
            addressCompat = NULL;
        }
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET) {
        if (socketPath && socketCompat && STRNEQ(socketPath, socketCompat)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("graphics 'socket' attribute '%s' must match "
                             "'socket' attribute of first listen element "
                             "(found '%s')"), socketCompat, socketPath);
            goto error;
        }

        if (!socketPath) {
            socketPath = socketCompat;
            socketCompat = NULL;
        }
    }

    if (address && address[0] &&
        (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS ||
         (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK &&
          !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)))) {
        def->address = address;
        address = NULL;
    }

    if (network && network[0]) {
        if (def->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'network' attribute is valid only for listen "
                             "type 'network'"));
            goto error;
        }
        def->network = network;
        network = NULL;
    }

    if (socketPath && socketPath[0]) {
        if (def->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'socket' attribute is valid only for listen "
                             "type 'socket'"));
            goto error;
        }
        def->socket = socketPath;
        socketPath = NULL;
    }

    if (fromConfig &&
        flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        if (virStrToLong_i(fromConfig, NULL, 10, &tmp) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid fromConfig value: %s"),
                           fromConfig);
            goto error;
        }
        def->fromConfig = tmp != 0;
    }

    if (autoGenerated &&
        flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        if (STREQ(autoGenerated, "yes")) {
            def->autoGenerated = true;
        } else if (STRNEQ(autoGenerated, "no")) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid autoGenerated value: %s"),
                           autoGenerated);
            goto error;
        }
    }

    ret = 0;
 error:
    if (ret < 0)
        virDomainGraphicsListenDefClear(def);
    VIR_FREE(type);
    VIR_FREE(address);
    VIR_FREE(network);
    VIR_FREE(socketPath);
    VIR_FREE(fromConfig);
    VIR_FREE(autoGenerated);
    VIR_FREE(addressCompat);
    VIR_FREE(socketCompat);
    return ret;
}


static int
virDomainGraphicsListensParseXML(virDomainGraphicsDefPtr def,
                                 xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 unsigned int flags)
{
    xmlNodePtr *listenNodes = NULL;
    xmlNodePtr save = ctxt->node;
    virDomainGraphicsListenDef newListen = {0};
    char *socketPath = NULL;
    int nListens;
    int ret = -1;

    ctxt->node = node;

    /* parse the <listen> subelements for graphics types that support it */
    nListens = virXPathNodeSet("./listen", ctxt, &listenNodes);
    if (nListens < 0)
        goto cleanup;

    if (nListens > 0) {
        size_t i;

        if (VIR_ALLOC_N(def->listens, nListens) < 0)
            goto cleanup;

        for (i = 0; i < nListens; i++) {
            if (virDomainGraphicsListenDefParseXML(&def->listens[i], def,
                                                   listenNodes[i],
                                                   i == 0 ? node : NULL,
                                                   flags) < 0)
                goto cleanup;

            def->nListens++;
        }
        VIR_FREE(listenNodes);
    }

    /* If no <listen/> element was found in XML for backward compatibility
     * we should try to parse 'listen' or 'socket' attribute from <graphics/>
     * element. */
    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        socketPath = virXMLPropString(node, "socket");

    if (socketPath) {
        newListen.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;
        newListen.socket = socketPath;
        socketPath = NULL;
    } else {
        newListen.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;
        newListen.address = virXMLPropString(node, "listen");
        if (STREQ_NULLABLE(newListen.address, ""))
            VIR_FREE(newListen.address);
    }

    /* If no <listen/> element was found add a new one created by parsing
     * <graphics/> element. */
    if (def->nListens == 0) {
        if (VIR_APPEND_ELEMENT(def->listens, def->nListens, newListen) < 0)
            goto cleanup;
    } else {
        virDomainGraphicsListenDefPtr glisten = &def->listens[0];

        /* If the first <listen/> element is 'address' or 'network' and we found
         * 'socket' attribute inside <graphics/> element for backward
         * compatibility we need to replace the first listen by
         * <listen type='socket' .../> element based on the 'socket' attribute. */
        if ((glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS ||
             glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK) &&
            newListen.type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET) {
            virDomainGraphicsListenDefClear(glisten);
            *glisten = newListen;
            memset(&newListen, 0, sizeof(newListen));
        }
    }

    ret = 0;
 cleanup:
    virDomainGraphicsListenDefClear(&newListen);
    VIR_FREE(listenNodes);
    VIR_FREE(socketPath);
    ctxt->node = save;
    return ret;
}


static int
virDomainGraphicsDefParseXMLVNC(virDomainGraphicsDefPtr def,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                unsigned int flags)
{
    char *port = virXMLPropString(node, "port");
    char *websocket = virXMLPropString(node, "websocket");
    char *sharePolicy = virXMLPropString(node, "sharePolicy");
    char *autoport = virXMLPropString(node, "autoport");
    int ret = -1;

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        goto error;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &def->data.vnc.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse vnc port %s"), port);
            goto error;
        }
        /* Legacy compat syntax, used -1 for auto-port */
        if (def->data.vnc.port == -1) {
            if (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)
                def->data.vnc.port = 0;
            def->data.vnc.autoport = true;
        }
    } else {
        def->data.vnc.port = 0;
        def->data.vnc.autoport = true;
    }

    if (autoport) {
        if (STREQ(autoport, "yes")) {
            if (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)
                def->data.vnc.port = 0;
            def->data.vnc.autoport = true;
        } else {
            def->data.vnc.autoport = false;
        }
    }

    if (websocket) {
        if (virStrToLong_i(websocket,
                           NULL, 10,
                           &def->data.vnc.websocket) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse vnc WebSocket port %s"), websocket);
            goto error;
        }
    }

    if (sharePolicy) {
        int policy =
           virDomainGraphicsVNCSharePolicyTypeFromString(sharePolicy);

        if (policy < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown vnc display sharing policy '%s'"),
                           sharePolicy);
            goto error;
        } else {
            def->data.vnc.sharePolicy = policy;
        }
    }

    def->data.vnc.keymap = virXMLPropString(node, "keymap");

    if (virDomainGraphicsAuthDefParseXML(node, &def->data.vnc.auth,
                                         def->type) < 0)
        goto error;

    ret = 0;
 error:
    VIR_FREE(port);
    VIR_FREE(autoport);
    VIR_FREE(websocket);
    VIR_FREE(sharePolicy);
    return ret;
}


static int
virDomainGraphicsDefParseXMLSDL(virDomainGraphicsDefPtr def,
                                xmlNodePtr node)
{
    char *fullscreen = virXMLPropString(node, "fullscreen");
    int ret = -1;

    if (fullscreen != NULL) {
        if (STREQ(fullscreen, "yes")) {
            def->data.sdl.fullscreen = true;
        } else if (STREQ(fullscreen, "no")) {
            def->data.sdl.fullscreen = false;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown fullscreen value '%s'"), fullscreen);
            goto cleanup;
        }
    } else {
        def->data.sdl.fullscreen = false;
    }

    def->data.sdl.xauth = virXMLPropString(node, "xauth");
    def->data.sdl.display = virXMLPropString(node, "display");

    ret = 0;
 cleanup:
    VIR_FREE(fullscreen);
    return ret;
}


static int
virDomainGraphicsDefParseXMLRDP(virDomainGraphicsDefPtr def,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                unsigned int flags)
{
    char *port = virXMLPropString(node, "port");
    char *autoport = virXMLPropString(node, "autoport");
    char *replaceUser = virXMLPropString(node, "replaceUser");
    char *multiUser = virXMLPropString(node, "multiUser");
    int ret = -1;

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        goto error;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &def->data.rdp.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse rdp port %s"), port);
            goto error;
        }
        /* Legacy compat syntax, used -1 for auto-port */
        if (def->data.rdp.port == -1)
            def->data.rdp.autoport = true;

    } else {
        def->data.rdp.port = 0;
        def->data.rdp.autoport = true;
    }

    if (STREQ_NULLABLE(autoport, "yes"))
        def->data.rdp.autoport = true;

    if (def->data.rdp.autoport && (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
        def->data.rdp.port = 0;

    if (STREQ_NULLABLE(replaceUser, "yes"))
        def->data.rdp.replaceUser = true;

    if (STREQ_NULLABLE(multiUser, "yes"))
        def->data.rdp.multiUser = true;

    ret = 0;
 error:
    VIR_FREE(port);
    VIR_FREE(autoport);
    VIR_FREE(replaceUser);
    VIR_FREE(multiUser);
    return ret;
}


static int
virDomainGraphicsDefParseXMLDesktop(virDomainGraphicsDefPtr def,
                                    xmlNodePtr node)
{
    char *fullscreen = virXMLPropString(node, "fullscreen");
    int ret = -1;

    if (fullscreen != NULL) {
        if (STREQ(fullscreen, "yes")) {
            def->data.desktop.fullscreen = true;
        } else if (STREQ(fullscreen, "no")) {
            def->data.desktop.fullscreen = false;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown fullscreen value '%s'"), fullscreen);
            goto cleanup;
        }
    } else {
        def->data.desktop.fullscreen = false;
    }

    def->data.desktop.display = virXMLPropString(node, "display");

    ret = 0;
 cleanup:
    VIR_FREE(fullscreen);
    return ret;
}


static int
virDomainGraphicsDefParseXMLSpice(virDomainGraphicsDefPtr def,
                                  xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  unsigned int flags)
{
    xmlNodePtr cur;
    char *port = virXMLPropString(node, "port");
    char *tlsPort = virXMLPropString(node, "tlsPort");
    char *autoport = virXMLPropString(node, "autoport");
    char *defaultMode = virXMLPropString(node, "defaultMode");
    int defaultModeVal;
    int ret = -1;

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        goto error;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &def->data.spice.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse spice port %s"), port);
            goto error;
        }
    } else {
        def->data.spice.port = 0;
    }

    if (tlsPort) {
        if (virStrToLong_i(tlsPort, NULL, 10, &def->data.spice.tlsPort) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse spice tlsPort %s"), tlsPort);
            goto error;
        }
    } else {
        def->data.spice.tlsPort = 0;
    }

    if (STREQ_NULLABLE(autoport, "yes"))
        def->data.spice.autoport = true;

    def->data.spice.defaultMode = VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY;

    if (defaultMode) {
        if ((defaultModeVal = virDomainGraphicsSpiceChannelModeTypeFromString(defaultMode)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown default spice channel mode %s"),
                           defaultMode);
            goto error;
        }
        def->data.spice.defaultMode = defaultModeVal;
    }

    if (def->data.spice.port == -1 && def->data.spice.tlsPort == -1) {
        /* Legacy compat syntax, used -1 for auto-port */
        def->data.spice.autoport = true;
    }

    if (def->data.spice.autoport && (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
        def->data.spice.port = 0;
        def->data.spice.tlsPort = 0;
    }

    def->data.spice.keymap = virXMLPropString(node, "keymap");

    if (virDomainGraphicsAuthDefParseXML(node, &def->data.spice.auth,
                                         def->type) < 0)
        goto error;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "channel")) {
                char *name, *mode;
                int nameval, modeval;
                name = virXMLPropString(cur, "name");
                mode = virXMLPropString(cur, "mode");

                if (!name || !mode) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("spice channel missing name/mode"));
                    VIR_FREE(name);
                    VIR_FREE(mode);
                    goto error;
                }

                if ((nameval = virDomainGraphicsSpiceChannelNameTypeFromString(name)) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown spice channel name %s"),
                                   name);
                    VIR_FREE(name);
                    VIR_FREE(mode);
                    goto error;
                }
                if ((modeval = virDomainGraphicsSpiceChannelModeTypeFromString(mode)) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown spice channel mode %s"),
                                   mode);
                    VIR_FREE(name);
                    VIR_FREE(mode);
                    goto error;
                }
                VIR_FREE(name);
                VIR_FREE(mode);

                def->data.spice.channels[nameval] = modeval;
            } else if (xmlStrEqual(cur->name, BAD_CAST "image")) {
                char *compression = virXMLPropString(cur, "compression");
                int compressionVal;

                if (!compression) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("spice image missing compression"));
                    goto error;
                }

                if ((compressionVal =
                     virDomainGraphicsSpiceImageCompressionTypeFromString(compression)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown spice image compression %s"),
                                   compression);
                    VIR_FREE(compression);
                    goto error;
                }
                VIR_FREE(compression);

                def->data.spice.image = compressionVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "jpeg")) {
                char *compression = virXMLPropString(cur, "compression");
                int compressionVal;

                if (!compression) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("spice jpeg missing compression"));
                    goto error;
                }

                if ((compressionVal =
                     virDomainGraphicsSpiceJpegCompressionTypeFromString(compression)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown spice jpeg compression %s"),
                                   compression);
                    VIR_FREE(compression);
                    goto error;
                }
                VIR_FREE(compression);

                def->data.spice.jpeg = compressionVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "zlib")) {
                char *compression = virXMLPropString(cur, "compression");
                int compressionVal;

                if (!compression) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("spice zlib missing compression"));
                    goto error;
                }

                if ((compressionVal =
                     virDomainGraphicsSpiceZlibCompressionTypeFromString(compression)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown spice zlib compression %s"),
                                   compression);
                    VIR_FREE(compression);
                    goto error;
                }
                VIR_FREE(compression);

                def->data.spice.zlib = compressionVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "playback")) {
                char *compression = virXMLPropString(cur, "compression");
                int compressionVal;

                if (!compression) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("spice playback missing compression"));
                    goto error;
                }

                if ((compressionVal =
                     virTristateSwitchTypeFromString(compression)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("unknown spice playback compression"));
                    VIR_FREE(compression);
                    goto error;

                }
                VIR_FREE(compression);

                def->data.spice.playback = compressionVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "streaming")) {
                char *mode = virXMLPropString(cur, "mode");
                int modeVal;

                if (!mode) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("spice streaming missing mode"));
                    goto error;
                }
                if ((modeVal =
                     virDomainGraphicsSpiceStreamingModeTypeFromString(mode)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("unknown spice streaming mode"));
                    VIR_FREE(mode);
                    goto error;

                }
                VIR_FREE(mode);

                def->data.spice.streaming = modeVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "clipboard")) {
                char *copypaste = virXMLPropString(cur, "copypaste");
                int copypasteVal;

                if (!copypaste) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("spice clipboard missing copypaste"));
                    goto error;
                }

                if ((copypasteVal =
                     virTristateBoolTypeFromString(copypaste)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown copypaste value '%s'"), copypaste);
                    VIR_FREE(copypaste);
                    goto error;
                }
                VIR_FREE(copypaste);

                def->data.spice.copypaste = copypasteVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "filetransfer")) {
                char *enable = virXMLPropString(cur, "enable");
                int enableVal;

                if (!enable) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("spice filetransfer missing enable"));
                    goto error;
                }

                if ((enableVal =
                     virTristateBoolTypeFromString(enable)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown enable value '%s'"), enable);
                    VIR_FREE(enable);
                    goto error;
                }
                VIR_FREE(enable);

                def->data.spice.filetransfer = enableVal;
            } else if (xmlStrEqual(cur->name, BAD_CAST "gl")) {
                char *enable = virXMLPropString(cur, "enable");
                char *rendernode = virXMLPropString(cur, "rendernode");
                int enableVal;

                if (!enable) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("spice gl element missing enable"));
                    VIR_FREE(rendernode);
                    goto error;
                }

                if ((enableVal =
                     virTristateBoolTypeFromString(enable)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown enable value '%s'"), enable);
                    VIR_FREE(enable);
                    VIR_FREE(rendernode);
                    goto error;
                }
                VIR_FREE(enable);

                def->data.spice.gl = enableVal;
                def->data.spice.rendernode = rendernode;

            } else if (xmlStrEqual(cur->name, BAD_CAST "mouse")) {
                char *mode = virXMLPropString(cur, "mode");
                int modeVal;

                if (!mode) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("spice mouse missing mode"));
                    goto error;
                }

                if ((modeVal = virDomainGraphicsSpiceMouseModeTypeFromString(mode)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown mouse mode value '%s'"),
                                   mode);
                    VIR_FREE(mode);
                    goto error;
                }
                VIR_FREE(mode);

                def->data.spice.mousemode = modeVal;
            }
        }
        cur = cur->next;
    }

    ret = 0;
 error:
    VIR_FREE(port);
    VIR_FREE(tlsPort);
    VIR_FREE(autoport);
    VIR_FREE(defaultMode);
    return ret;
}


/* Parse the XML definition for a graphics device */
static virDomainGraphicsDefPtr
virDomainGraphicsDefParseXML(xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             unsigned int flags)
{
    virDomainGraphicsDefPtr def;
    char *type = NULL;
    int typeVal;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    type = virXMLPropString(node, "type");
    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing graphics device type"));
        goto error;
    }

    if ((typeVal = virDomainGraphicsTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown graphics device type '%s'"), type);
        goto error;
    }
    def->type = typeVal;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (virDomainGraphicsDefParseXMLVNC(def, node, ctxt, flags) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        if (virDomainGraphicsDefParseXMLSDL(def, node) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        if (virDomainGraphicsDefParseXMLRDP(def, node, ctxt, flags) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        if (virDomainGraphicsDefParseXMLDesktop(def, node) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (virDomainGraphicsDefParseXMLSpice(def, node, ctxt, flags) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

 cleanup:
    VIR_FREE(type);

    return def;

 error:
    virDomainGraphicsDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainSoundCodecDefPtr
virDomainSoundCodecDefParseXML(xmlNodePtr node)
{
    char *type;
    virDomainSoundCodecDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    type = virXMLPropString(node, "type");
    if ((def->type = virDomainSoundCodecTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown codec type '%s'"), type);
        goto error;
    }

 cleanup:
    VIR_FREE(type);

    return def;

 error:
    virDomainSoundCodecDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainSoundDefPtr
virDomainSoundDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    char *model;
    virDomainSoundDefPtr def;
    xmlNodePtr save = ctxt->node;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    ctxt->node = node;

    model = virXMLPropString(node, "model");
    if ((def->model = virDomainSoundModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown sound model '%s'"), model);
        goto error;
    }

    if (def->model == VIR_DOMAIN_SOUND_MODEL_ICH6 ||
        def->model == VIR_DOMAIN_SOUND_MODEL_ICH9) {
        int ncodecs;
        xmlNodePtr *codecNodes = NULL;

        /* parse the <codec> subelements for sound models that support it */
        ncodecs = virXPathNodeSet("./codec", ctxt, &codecNodes);
        if (ncodecs < 0)
            goto error;

        if (ncodecs > 0) {
            size_t i;

            if (VIR_ALLOC_N(def->codecs, ncodecs) < 0) {
                VIR_FREE(codecNodes);
                goto error;
            }

            for (i = 0; i < ncodecs; i++) {
                virDomainSoundCodecDefPtr codec = virDomainSoundCodecDefParseXML(codecNodes[i]);
                if (codec == NULL) {
                    VIR_FREE(codecNodes);
                    goto error;
                }

                codec->cad = def->ncodecs; /* that will do for now */
                def->codecs[def->ncodecs++] = codec;
            }
            VIR_FREE(codecNodes);
        }
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(model);

    ctxt->node = save;
    return def;

 error:
    virDomainSoundDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainWatchdogDefPtr
virDomainWatchdogDefParseXML(xmlNodePtr node,
                             unsigned int flags)
{

    char *model = NULL;
    char *action = NULL;
    virDomainWatchdogDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    model = virXMLPropString(node, "model");
    if (model == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("watchdog must contain model name"));
        goto error;
    }
    def->model = virDomainWatchdogModelTypeFromString(model);
    if (def->model < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown watchdog model '%s'"), model);
        goto error;
    }

    action = virXMLPropString(node, "action");
    if (action == NULL) {
        def->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;
    } else {
        def->action = virDomainWatchdogActionTypeFromString(action);
        if (def->action < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown watchdog action '%s'"), action);
            goto error;
        }
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(action);
    VIR_FREE(model);

    return def;

 error:
    virDomainWatchdogDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainRNGDefPtr
virDomainRNGDefParseXML(virDomainXMLOptionPtr xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    char *model = NULL;
    char *backend = NULL;
    char *type = NULL;
    virDomainRNGDefPtr def;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr *backends = NULL;
    int nbackends;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (!(model = virXMLPropString(node, "model"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing RNG device model"));
        goto error;
    }

    if ((def->model = virDomainRNGModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("unknown RNG model '%s'"), model);
        goto error;
    }

    ctxt->node = node;

    if (virXPathUInt("string(./rate/@bytes)", ctxt, &def->rate) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid RNG rate bytes value"));
        goto error;
    }

    if (def->rate > 0 &&
        virXPathUInt("string(./rate/@period)", ctxt, &def->period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid RNG rate period value"));
        goto error;
    }

    if ((nbackends = virXPathNodeSet("./backend", ctxt, &backends)) < 0)
        goto error;

    if (nbackends != 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one RNG backend is supported"));
        goto error;
    }

    if (!(backend = virXMLPropString(backends[0], "model"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing RNG device backend model"));
        goto error;
    }

    if ((def->backend = virDomainRNGBackendTypeFromString(backend)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown RNG backend model '%s'"), backend);
        goto error;
    }

    switch ((virDomainRNGBackend) def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        def->source.file = virXPathString("string(./backend)", ctxt);
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (!(type = virXMLPropString(backends[0], "type"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing EGD backend type"));
            goto error;
        }

        if (!(def->source.chardev = virDomainChrSourceDefNew(xmlopt)))
            goto error;

        def->source.chardev->type = virDomainChrTypeFromString(type);
        if (def->source.chardev->type < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown backend type '%s' for egd"),
                           type);
            goto error;
        }

        if (virDomainChrSourceDefParseXML(def->source.chardev,
                                          backends[0]->children, flags,
                                          NULL, ctxt, NULL, 0) < 0)
            goto error;
        break;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

 cleanup:
    VIR_FREE(model);
    VIR_FREE(backend);
    VIR_FREE(type);
    VIR_FREE(backends);
    ctxt->node = save;
    return def;

 error:
    virDomainRNGDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainMemballoonDefPtr
virDomainMemballoonDefParseXML(xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    char *model;
    char *deflate = NULL;
    virDomainMemballoonDefPtr def;
    xmlNodePtr save = ctxt->node;
    unsigned int period = 0;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    model = virXMLPropString(node, "model");
    if (model == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("balloon memory must contain model name"));
        goto error;
    }

    if ((def->model = virDomainMemballoonModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown memory balloon model '%s'"), model);
        goto error;
    }

    if ((deflate = virXMLPropString(node, "autodeflate")) &&
        (def->autodeflate = virTristateSwitchTypeFromString(deflate)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid autodeflate attribute value '%s'"), deflate);
        goto error;
    }

    ctxt->node = node;
    if (virXPathUInt("string(./stats/@period)", ctxt, &period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid statistics collection period"));
        goto error;
    }

    def->period = period;
    if (def->period < 0)
        def->period = 0;

    if (def->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE)
        VIR_DEBUG("Ignoring device address for none model Memballoon");
    else if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

 cleanup:
    VIR_FREE(model);
    VIR_FREE(deflate);

    ctxt->node = save;
    return def;

 error:
    virDomainMemballoonDefFree(def);
    def = NULL;
    goto cleanup;
}

static virDomainNVRAMDefPtr
virDomainNVRAMDefParseXML(xmlNodePtr node,
                          unsigned int flags)
{
   virDomainNVRAMDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

    return def;

 error:
    virDomainNVRAMDefFree(def);
    return NULL;
}

static virDomainShmemDefPtr
virDomainShmemDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    char *tmp = NULL;
    virDomainShmemDefPtr def = NULL;
    virDomainShmemDefPtr ret = NULL;
    xmlNodePtr msi = NULL;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr server = NULL;


    if (VIR_ALLOC(def) < 0)
        return NULL;

    ctxt->node = node;

    tmp = virXPathString("string(./model/@type)", ctxt);
    if (tmp) {
        /* If there's none, we will automatically have the first one
         * (as default).  Unfortunately this has to be done for
         * compatibility reasons. */
        if ((def->model = virDomainShmemModelTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Unknown shmem model type '%s'"), tmp);
            goto cleanup;
        }

        VIR_FREE(tmp);
    }

    if (!(def->name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("shmem element must contain 'name' attribute"));
        goto cleanup;
    }

    if (virDomainParseScaledValue("./size[1]", NULL, ctxt,
                                  &def->size, 1, ULLONG_MAX, false) < 0)
        goto cleanup;

    if ((server = virXPathNode("./server[1]", ctxt))) {
        def->server.enabled = true;

        def->server.chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
        def->server.chr.data.nix.listen = false;
        if ((tmp = virXMLPropString(server, "path")))
            def->server.chr.data.nix.path = virFileSanitizePath(tmp);
        VIR_FREE(tmp);
    }

    if ((msi = virXPathNode("./msi[1]", ctxt))) {
        def->msi.enabled = true;

        if ((tmp = virXMLPropString(msi, "vectors")) &&
            virStrToLong_uip(tmp, NULL, 0, &def->msi.vectors) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid number of vectors for shmem: '%s'"),
                           tmp);
            goto cleanup;
        }
        VIR_FREE(tmp);

        if ((tmp = virXMLPropString(msi, "ioeventfd"))) {
            int val;

            if ((val = virTristateSwitchTypeFromString(tmp)) <= 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid msi ioeventfd setting for shmem: '%s'"),
                               tmp);
                goto cleanup;
            }
            def->msi.ioeventfd = val;
        }
        VIR_FREE(tmp);
    }

    /* msi option is only relevant with a server */
    if (def->msi.enabled && !def->server.enabled) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("msi option is only supported with a server"));
        goto cleanup;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto cleanup;


    ret = def;
    def = NULL;
 cleanup:
    ctxt->node = save;
    VIR_FREE(tmp);
    virDomainShmemDefFree(def);
    return ret;
}

static int
virSysinfoBIOSParseXML(xmlNodePtr node,
                       xmlXPathContextPtr ctxt,
                       virSysinfoBIOSDefPtr *bios)
{
    int ret = -1;
    virSysinfoBIOSDefPtr def;

    if (!xmlStrEqual(node->name, BAD_CAST "bios")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'bios' element"));
        return ret;
    }

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    def->vendor = virXPathString("string(entry[@name='vendor'])", ctxt);
    def->version = virXPathString("string(entry[@name='version'])", ctxt);
    def->date = virXPathString("string(entry[@name='date'])", ctxt);
    def->release = virXPathString("string(entry[@name='release'])", ctxt);
    if (def->date != NULL) {
        char *ptr;
        int month, day, year;

        /* Validate just the format of the date
         * Expect mm/dd/yyyy or mm/dd/yy,
         * where yy must be 00->99 and would be assumed to be 19xx
         * a yyyy date should be 1900 and beyond
         */
        if (virStrToLong_i(def->date, &ptr, 10, &month) < 0 ||
            *ptr != '/' ||
            virStrToLong_i(ptr + 1, &ptr, 10, &day) < 0 ||
            *ptr != '/' ||
            virStrToLong_i(ptr + 1, &ptr, 10, &year) < 0 ||
            *ptr != '\0' ||
            (month < 1 || month > 12) ||
            (day < 1 || day > 31) ||
            (year < 0 || (year >= 100 && year < 1900))) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("Invalid BIOS 'date' format"));
            goto cleanup;
        }
    }

    if (!def->vendor && !def->version &&
        !def->date && !def->release) {
        virSysinfoBIOSDefFree(def);
        def = NULL;
    }

    *bios = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoBIOSDefFree(def);
    return ret;
}

static int
virSysinfoSystemParseXML(xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virSysinfoSystemDefPtr *sysdef,
                         unsigned char *domUUID,
                         bool uuid_generated)
{
    int ret = -1;
    virSysinfoSystemDefPtr def;
    char *tmpUUID = NULL;

    if (!xmlStrEqual(node->name, BAD_CAST "system")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'system' element"));
        return ret;
    }

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    def->manufacturer =
        virXPathString("string(entry[@name='manufacturer'])", ctxt);
    def->product =
        virXPathString("string(entry[@name='product'])", ctxt);
    def->version =
        virXPathString("string(entry[@name='version'])", ctxt);
    def->serial =
        virXPathString("string(entry[@name='serial'])", ctxt);
    tmpUUID = virXPathString("string(entry[@name='uuid'])", ctxt);
    if (tmpUUID) {
        unsigned char uuidbuf[VIR_UUID_BUFLEN];
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        if (virUUIDParse(tmpUUID, uuidbuf) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           "%s", _("malformed <sysinfo> uuid element"));
            goto cleanup;
        }
        if (uuid_generated) {
            memcpy(domUUID, uuidbuf, VIR_UUID_BUFLEN);
        } else if (memcmp(domUUID, uuidbuf, VIR_UUID_BUFLEN) != 0) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("UUID mismatch between <uuid> and "
                             "<sysinfo>"));
            goto cleanup;
        }
        /* Although we've validated the UUID as good, virUUIDParse() is
         * lax with respect to allowing extraneous "-" and " ", but the
         * underlying hypervisor may be less forgiving. Use virUUIDFormat()
         * to validate format in xml is right. If not, then format it
         * properly so that it's used correctly later.
         */
        virUUIDFormat(uuidbuf, uuidstr);
        if (VIR_STRDUP(def->uuid, uuidstr) < 0)
            goto cleanup;
    }
    def->sku =
        virXPathString("string(entry[@name='sku'])", ctxt);
    def->family =
        virXPathString("string(entry[@name='family'])", ctxt);

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family) {
        virSysinfoSystemDefFree(def);
        def = NULL;
    }

    *sysdef = def;
    def = NULL;
    ret = 0;
 cleanup:
    virSysinfoSystemDefFree(def);
    VIR_FREE(tmpUUID);
    return ret;
}

static int
virSysinfoBaseBoardParseXML(xmlXPathContextPtr ctxt,
                            virSysinfoBaseBoardDefPtr *baseBoard,
                            size_t *nbaseBoard)
{
    int ret = -1;
    virSysinfoBaseBoardDefPtr boards = NULL;
    size_t i, nboards = 0;
    xmlNodePtr *nodes = NULL, oldnode = ctxt->node;
    int n;

    if ((n = virXPathNodeSet("./baseBoard", ctxt, &nodes)) < 0)
        return ret;

    if (n && VIR_ALLOC_N(boards, n) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virSysinfoBaseBoardDefPtr def = boards + nboards;

        ctxt->node = nodes[i];

        def->manufacturer =
            virXPathString("string(entry[@name='manufacturer'])", ctxt);
        def->product =
            virXPathString("string(entry[@name='product'])", ctxt);
        def->version =
            virXPathString("string(entry[@name='version'])", ctxt);
        def->serial =
            virXPathString("string(entry[@name='serial'])", ctxt);
        def->asset =
            virXPathString("string(entry[@name='asset'])", ctxt);
        def->location =
            virXPathString("string(entry[@name='location'])", ctxt);

        if (!def->manufacturer && !def->product && !def->version &&
            !def->serial && !def->asset && !def->location) {
            /* nada */
        } else {
            nboards++;
        }
    }

    *baseBoard = boards;
    *nbaseBoard = nboards;
    boards = NULL;
    ret = 0;
 cleanup:
    VIR_FREE(boards);
    VIR_FREE(nodes);
    ctxt->node = oldnode;
    return ret;
}

static virSysinfoDefPtr
virSysinfoParseXML(xmlNodePtr node,
                  xmlXPathContextPtr ctxt,
                  unsigned char *domUUID,
                  bool uuid_generated)
{
    virSysinfoDefPtr def;
    xmlNodePtr oldnode, tmpnode;
    char *type;

    if (!xmlStrEqual(node->name, BAD_CAST "sysinfo")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'sysinfo' element"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        return NULL;

    type = virXMLPropString(node, "type");
    if (type == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("sysinfo must contain a type attribute"));
        goto error;
    }
    if ((def->type = virSysinfoTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown sysinfo type '%s'"), type);
        goto error;
    }

    /* Extract BIOS related metadata */
    if ((tmpnode = virXPathNode("./bios[1]", ctxt)) != NULL) {
        oldnode = ctxt->node;
        ctxt->node = tmpnode;
        if (virSysinfoBIOSParseXML(tmpnode, ctxt, &def->bios) < 0) {
            ctxt->node = oldnode;
            goto error;
        }
        ctxt->node = oldnode;
    }

    /* Extract system related metadata */
    if ((tmpnode = virXPathNode("./system[1]", ctxt)) != NULL) {
        oldnode = ctxt->node;
        ctxt->node = tmpnode;
        if (virSysinfoSystemParseXML(tmpnode, ctxt, &def->system,
                                     domUUID, uuid_generated) < 0) {
            ctxt->node = oldnode;
            goto error;
        }
        ctxt->node = oldnode;
    }

    /* Extract system base board metadata */
    if (virSysinfoBaseBoardParseXML(ctxt, &def->baseBoard, &def->nbaseBoard) < 0)
        goto error;

 cleanup:
    VIR_FREE(type);
    return def;

 error:
    virSysinfoDefFree(def);
    def = NULL;
    goto cleanup;
}

unsigned int
virDomainVideoDefaultRAM(const virDomainDef *def,
                         const virDomainVideoType type)
{
    switch (type) {
    case VIR_DOMAIN_VIDEO_TYPE_VGA:
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        if (def->virtType == VIR_DOMAIN_VIRT_VBOX)
            return 8 * 1024;
        else if (def->virtType == VIR_DOMAIN_VIRT_VMWARE)
            return 4 * 1024;
        else
            return 16 * 1024;
        break;

    case VIR_DOMAIN_VIDEO_TYPE_XEN:
        /* Original Xen PVFB hardcoded to 4 MB */
        return 4 * 1024;

    case VIR_DOMAIN_VIDEO_TYPE_QXL:
        /* QEMU use 64M as the minimal video memory for qxl device */
        return 64 * 1024;

    default:
        return 0;
    }
}


int
virDomainVideoDefaultType(const virDomainDef *def)
{
    switch (def->virtType) {
    case VIR_DOMAIN_VIRT_TEST:
    case VIR_DOMAIN_VIRT_QEMU:
    case VIR_DOMAIN_VIRT_KQEMU:
    case VIR_DOMAIN_VIRT_KVM:
    case VIR_DOMAIN_VIRT_XEN:
        if (def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
            def->os.type == VIR_DOMAIN_OSTYPE_LINUX)
            return VIR_DOMAIN_VIDEO_TYPE_XEN;
        else if ARCH_IS_PPC64(def->os.arch)
            return VIR_DOMAIN_VIDEO_TYPE_VGA;
        else
            return VIR_DOMAIN_VIDEO_TYPE_CIRRUS;

    case VIR_DOMAIN_VIRT_VBOX:
        return VIR_DOMAIN_VIDEO_TYPE_VBOX;

    case VIR_DOMAIN_VIRT_VMWARE:
        return VIR_DOMAIN_VIDEO_TYPE_VMVGA;

    case VIR_DOMAIN_VIRT_VZ:
    case VIR_DOMAIN_VIRT_PARALLELS:
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM)
            return VIR_DOMAIN_VIDEO_TYPE_VGA;
        else
            return VIR_DOMAIN_VIDEO_TYPE_PARALLELS;
    case VIR_DOMAIN_VIRT_BHYVE:
        return VIR_DOMAIN_VIDEO_TYPE_GOP;
    default:
        return -1;
    }
}

static virDomainVideoAccelDefPtr
virDomainVideoAccelDefParseXML(xmlNodePtr node)
{
    xmlNodePtr cur;
    virDomainVideoAccelDefPtr def;
    char *accel2d = NULL;
    char *accel3d = NULL;
    int val;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!accel3d && !accel2d &&
                xmlStrEqual(cur->name, BAD_CAST "acceleration")) {
                accel3d = virXMLPropString(cur, "accel3d");
                accel2d = virXMLPropString(cur, "accel2d");
            }
        }
        cur = cur->next;
    }

    if (!accel3d && !accel2d)
        return NULL;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    if (accel3d) {
        if ((val = virTristateBoolTypeFromString(accel3d)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown accel3d value '%s'"), accel3d);
            goto cleanup;
        }
        def->accel3d = val;
    }

    if (accel2d) {
        if ((val = virTristateBoolTypeFromString(accel2d)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown accel2d value '%s'"), accel2d);
            goto cleanup;
        }
        def->accel2d = val;
    }

 cleanup:
    VIR_FREE(accel2d);
    VIR_FREE(accel3d);
    return def;
}

static virDomainVideoDefPtr
virDomainVideoDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          const virDomainDef *dom,
                          unsigned int flags)
{
    virDomainVideoDefPtr def;
    xmlNodePtr cur;
    xmlNodePtr saved = ctxt->node;
    char *type = NULL;
    char *heads = NULL;
    char *vram = NULL;
    char *vram64 = NULL;
    char *ram = NULL;
    char *vgamem = NULL;
    char *primary = NULL;

    ctxt->node = node;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (!type && !vram && !ram && !heads &&
                xmlStrEqual(cur->name, BAD_CAST "model")) {
                type = virXMLPropString(cur, "type");
                ram = virXMLPropString(cur, "ram");
                vram = virXMLPropString(cur, "vram");
                vram64 = virXMLPropString(cur, "vram64");
                vgamem = virXMLPropString(cur, "vgamem");
                heads = virXMLPropString(cur, "heads");

                if ((primary = virXMLPropString(cur, "primary")) != NULL) {
                    if (STREQ(primary, "yes"))
                        def->primary = true;
                    VIR_FREE(primary);
                }

                def->accel = virDomainVideoAccelDefParseXML(cur);
            }
        }
        cur = cur->next;
    }

    if (type) {
        if ((def->type = virDomainVideoTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown video model '%s'"), type);
            goto error;
        }
    } else {
        if ((def->type = virDomainVideoDefaultType(dom)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing video model and cannot determine default"));
            goto error;
        }
    }

    if (ram) {
        if (def->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("ram attribute only supported for type of qxl"));
            goto error;
        }
        if (virStrToLong_uip(ram, NULL, 10, &def->ram) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse video ram '%s'"), ram);
            goto error;
        }
    }

    if (vram) {
        if (virStrToLong_uip(vram, NULL, 10, &def->vram) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse video vram '%s'"), vram);
            goto error;
        }
    }

    if (vram64) {
        if (def->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("vram64 attribute only supported for type of qxl"));
            goto error;
        }
        if (virStrToLong_uip(vram64, NULL, 10, &def->vram64) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse video vram64 '%s'"), vram64);
            goto error;
        }
    }

    if (vgamem) {
        if (def->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("vgamem attribute only supported for type of qxl"));
            goto error;
        }
        if (virStrToLong_uip(vgamem, NULL, 10, &def->vgamem) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse video vgamem '%s'"), vgamem);
            goto error;
        }
    }

    if (heads) {
        if (virStrToLong_uip(heads, NULL, 10, &def->heads) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse video heads '%s'"), heads);
            goto error;
        }
    } else {
        def->heads = 1;
    }

    if (virDomainDeviceInfoParseXML(node, NULL, &def->info, flags) < 0)
        goto error;

    if (virDomainVirtioOptionsParseXML(ctxt, &def->virtio) < 0)
        goto error;

 cleanup:
    ctxt->node = saved;

    VIR_FREE(type);
    VIR_FREE(ram);
    VIR_FREE(vram);
    VIR_FREE(vram64);
    VIR_FREE(vgamem);
    VIR_FREE(heads);

    return def;

 error:
    virDomainVideoDefFree(def);
    def = NULL;
    goto cleanup;
}

static virDomainHostdevDefPtr
virDomainHostdevDefParseXML(virDomainXMLOptionPtr xmlopt,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            virHashTablePtr bootHash,
                            unsigned int flags)
{
    virDomainHostdevDefPtr def;
    xmlNodePtr save = ctxt->node;
    char *mode = virXMLPropString(node, "mode");
    char *type = virXMLPropString(node, "type");

    ctxt->node = node;

    if (!(def = virDomainHostdevDefAlloc(xmlopt)))
        goto error;

    if (mode) {
        if ((def->mode = virDomainHostdevModeTypeFromString(mode)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown hostdev mode '%s'"), mode);
            goto error;
        }
    } else {
        def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    }

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        /* parse managed/mode/type, and the <source> element */
        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, type, def, flags) < 0)
            goto error;
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        /* parse managed/mode/type, and the <source> element */
        if (virDomainHostdevDefParseXMLCaps(node, ctxt, type, def) < 0)
            goto error;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected hostdev mode %d"), def->mode);
        goto error;
    }

    if (def->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainDeviceInfoParseXML(node, bootHash, def->info,
                                        flags  | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT
                                        | VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) < 0)
            goto error;
    }

    if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        switch ((virDomainHostdevSubsysType) def->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            if (def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("PCI host devices must use 'pci' address type"));
                goto error;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            if (def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("SCSI host device must use 'drive' "
                                 "address type"));
                goto error;
            }
            if (virXPathBoolean("boolean(./readonly)", ctxt))
                def->readonly = true;
            if (virXPathBoolean("boolean(./shareable)", ctxt))
                def->shareable = true;
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            if (def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
                def->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("SCSI_host host device must use 'pci' "
                                 "or 'ccw' address type"));
                goto error;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
    }

 cleanup:
    VIR_FREE(type);
    VIR_FREE(mode);
    ctxt->node = save;
    return def;

 error:
    virDomainHostdevDefFree(def);
    def = NULL;
    goto cleanup;
}


static virDomainRedirdevDefPtr
virDomainRedirdevDefParseXML(virDomainXMLOptionPtr xmlopt,
                             xmlNodePtr node,
                             virHashTablePtr bootHash,
                             unsigned int flags)
{
    xmlNodePtr cur;
    virDomainRedirdevDefPtr def;
    char *bus = NULL, *type = NULL;
    int remaining;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (!(def->source = virDomainChrSourceDefNew(xmlopt)))
        goto error;

    bus = virXMLPropString(node, "bus");
    if (bus) {
        if ((def->bus = virDomainRedirdevBusTypeFromString(bus)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown redirdev bus '%s'"), bus);
            goto error;
        }
    } else {
        def->bus = VIR_DOMAIN_REDIRDEV_BUS_USB;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->source->type = virDomainChrTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown redirdev character device type '%s'"), type);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing type in redirdev"));
        goto error;
    }

    cur = node->children;
    /* boot gets parsed in virDomainDeviceInfoParseXML
     * source gets parsed in virDomainChrSourceDefParseXML
     * we don't know any of the elements that might remain */
    remaining = virDomainChrSourceDefParseXML(def->source, cur, flags,
                                              NULL, NULL, NULL, 0);
    if (remaining < 0)
        goto error;

    if (def->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC)
        def->source->data.spicevmc = VIR_DOMAIN_CHR_SPICEVMC_USBREDIR;

    if (virDomainDeviceInfoParseXML(node, bootHash, &def->info,
                                    flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) < 0)
        goto error;

    if (def->bus == VIR_DOMAIN_REDIRDEV_BUS_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid address for a USB device"));
        goto error;
    }


 cleanup:
    VIR_FREE(bus);
    VIR_FREE(type);
    return def;

 error:
    virDomainRedirdevDefFree(def);
    def = NULL;
    goto cleanup;
}

/*
 * This is the helper function to convert USB device version from a
 * format of JJ.MN to a format of 0xJJMN where JJ is the major
 * version number, M is the minor version number and N is the
 * sub minor version number.
 * e.g. USB version 2.0 is reported as 0x0200,
 *      USB version 4.07 as 0x0407
 */
static int
virDomainRedirFilterUSBVersionHelper(const char *version,
                                     virDomainRedirFilterUSBDevDefPtr def)
{
    unsigned int major, minor;
    char *s = NULL;

    if ((virStrToLong_ui(version, &s, 10, &major)) < 0 ||
        *s++ != '.' ||
        (virStrToLong_ui(s, NULL, 10, &minor)) < 0)
        goto error;

    if (major >= 100 || minor >= 100)
        goto error;

    /* Treat JJ.M as JJ.M0, not JJ.0M */
    if (strlen(s) == 1)
        minor *= 10;

    def->version = (major / 10) << 12 | (major % 10) << 8 |
                   (minor / 10) << 4 | (minor % 10) << 0;

    return 0;

 error:
    virReportError(VIR_ERR_XML_ERROR,
                   _("Cannot parse USB device version %s"), version);
    return -1;
}

static virDomainRedirFilterUSBDevDefPtr
virDomainRedirFilterUSBDevDefParseXML(xmlNodePtr node)
{
    char *class;
    char *vendor = NULL, *product = NULL;
    char *version = NULL, *allow = NULL;
    virDomainRedirFilterUSBDevDefPtr def;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    class = virXMLPropString(node, "class");
    if (class) {
        if ((virStrToLong_i(class, NULL, 0, &def->usbClass)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot parse USB Class code %s"), class);
            goto error;
        }

        if (def->usbClass != -1 && def->usbClass &~ 0xFF) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid USB Class code %s"), class);
            goto error;
        }
    } else {
        def->usbClass = -1;
    }

    vendor = virXMLPropString(node, "vendor");
    if (vendor) {
        if ((virStrToLong_i(vendor, NULL, 0, &def->vendor)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot parse USB vendor ID %s"), vendor);
            goto error;
        }
    } else {
        def->vendor = -1;
    }

    product = virXMLPropString(node, "product");
    if (product) {
        if ((virStrToLong_i(product, NULL, 0, &def->product)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot parse USB product ID %s"), product);
            goto error;
        }
    } else {
        def->product = -1;
    }

    version = virXMLPropString(node, "version");
    if (version) {
        if (STREQ(version, "-1"))
            def->version = -1;
        else if ((virDomainRedirFilterUSBVersionHelper(version, def)) < 0)
            goto error;
    } else {
        def->version = -1;
    }

    allow = virXMLPropString(node, "allow");
    if (allow) {
        if (STREQ(allow, "yes")) {
            def->allow = true;
        } else if (STREQ(allow, "no")) {
            def->allow = false;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid allow value, either 'yes' or 'no'"));
            goto error;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing allow attribute for USB redirection filter"));
        goto error;
    }

 cleanup:
    VIR_FREE(class);
    VIR_FREE(vendor);
    VIR_FREE(product);
    VIR_FREE(version);
    VIR_FREE(allow);
    return def;

 error:
    VIR_FREE(def);
    def = NULL;
    goto cleanup;
}

static virDomainRedirFilterDefPtr
virDomainRedirFilterDefParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt)
{
    int n;
    size_t i;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr save = ctxt->node;
    virDomainRedirFilterDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0)
        goto error;

    ctxt->node = node;
    if ((n = virXPathNodeSet("./usbdev", ctxt, &nodes)) < 0)
        goto error;

    if (n && VIR_ALLOC_N(def->usbdevs, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainRedirFilterUSBDevDefPtr usbdev =
            virDomainRedirFilterUSBDevDefParseXML(nodes[i]);

        if (!usbdev)
            goto error;
        def->usbdevs[def->nusbdevs++] = usbdev;
    }
    VIR_FREE(nodes);

    ctxt->node = save;
    return def;

 error:
    VIR_FREE(nodes);
    virDomainRedirFilterDefFree(def);
    return NULL;
}

static int
virDomainEventActionParseXML(xmlXPathContextPtr ctxt,
                             const char *name,
                             const char *xpath,
                             int *val,
                             int defaultVal,
                             virEventActionFromStringFunc convFunc)
{
    char *tmp = virXPathString(xpath, ctxt);
    if (tmp == NULL) {
        *val = defaultVal;
    } else {
        *val = convFunc(tmp);
        if (*val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown %s action: %s"), name, tmp);
            VIR_FREE(tmp);
            return -1;
        }
        VIR_FREE(tmp);
    }
    return 0;
}

static int
virDomainPMStateParseXML(xmlXPathContextPtr ctxt,
                         const char *xpath,
                         int *val)
{
    int ret = -1;
    char *tmp = virXPathString(xpath, ctxt);
    if (tmp) {
        *val = virTristateBoolTypeFromString(tmp);
        if (*val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown PM state value %s"), tmp);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(tmp);
    return ret;
}


static int
virDomainPerfEventDefParseXML(virDomainPerfDefPtr perf,
                              xmlNodePtr node)
{
    char *name = NULL;
    char *enabled = NULL;
    int event;
    int ret = -1;

    if (!(name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing perf event name"));
        goto cleanup;
    }

    if ((event = virPerfEventTypeFromString(name)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("'unsupported perf event '%s'"), name);
        goto cleanup;
    }

    if (perf->events[event] != VIR_TRISTATE_BOOL_ABSENT) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("perf event '%s' was already specified"), name);
        goto cleanup;
    }

    if (!(enabled = virXMLPropString(node, "enabled"))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("missing state of perf event '%s'"), name);
        goto cleanup;
    }

    if ((perf->events[event] = virTristateBoolTypeFromString(enabled)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid state '%s' of perf event '%s'"),
                       enabled, name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(name);
    VIR_FREE(enabled);
    return ret;
}

static int
virDomainPerfDefParseXML(virDomainDefPtr def,
                         xmlXPathContextPtr ctxt)
{
    size_t i;
    int ret = -1;
    xmlNodePtr *nodes = NULL;
    int n;

    if ((n = virXPathNodeSet("./perf/event", ctxt, &nodes)) < 0)
        return n;

    for (i = 0; i < n; i++) {
        if (virDomainPerfEventDefParseXML(&def->perf, nodes[i]) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    return ret;
}

static int
virDomainMemorySourceDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainMemoryDefPtr def)
{
    int ret = -1;
    char *nodemask = NULL;
    xmlNodePtr save = ctxt->node;
    ctxt->node = node;

    switch ((virDomainMemoryModel) def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        if (virDomainParseMemory("./pagesize", "./pagesize/@unit", ctxt,
                                 &def->pagesize, false, false) < 0)
            goto cleanup;

        if ((nodemask = virXPathString("string(./nodemask)", ctxt))) {
            if (virBitmapParse(nodemask, &def->sourceNodes,
                               VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto cleanup;

            if (virBitmapIsAllClear(def->sourceNodes)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'nodemask': %s"), nodemask);
                goto cleanup;
            }
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (!(def->nvdimmPath = virXPathString("string(./path)", ctxt))) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("path is required for model 'nvdimm'"));
            goto cleanup;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodemask);
    ctxt->node = save;
    return ret;
}


static int
virDomainMemoryTargetDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainMemoryDefPtr def)
{
    int ret = -1;
    xmlNodePtr save = ctxt->node;
    ctxt->node = node;
    int rv;

    /* initialize to value which marks that the user didn't specify it */
    def->targetNode = -1;

    if ((rv = virXPathInt("string(./node)", ctxt, &def->targetNode)) == -2 ||
        (rv == 0 && def->targetNode < 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid value of memory device node"));
        goto cleanup;
    }

    if (virDomainParseMemory("./size", "./size/@unit", ctxt,
                             &def->size, true, false) < 0)
        goto cleanup;

    if (def->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM) {
        if (virDomainParseMemory("./label/size", "./label/size/@unit", ctxt,
                                 &def->labelsize, false, false) < 0)
            goto cleanup;

        if (def->labelsize && def->labelsize < 128) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("nvdimm label must be at least 128KiB"));
            goto cleanup;
        }

        if (def->labelsize >= def->size) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("label size must be smaller than NVDIMM size"));
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    ctxt->node = save;
    return ret;
}


static virDomainMemoryDefPtr
virDomainMemoryDefParseXML(xmlNodePtr memdevNode,
                           xmlXPathContextPtr ctxt,
                           unsigned int flags)
{
    char *tmp = NULL;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr node;
    virDomainMemoryDefPtr def;
    int val;

    ctxt->node = memdevNode;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (!(tmp = virXMLPropString(memdevNode, "model"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing memory model"));
        goto error;
    }

    if ((def->model = virDomainMemoryModelTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid memory model '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    if ((tmp = virXMLPropString(memdevNode, "access"))) {
        if ((val = virDomainMemoryAccessTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid access mode '%s'"), tmp);
            goto error;
        }

        def->access = val;
    }
    VIR_FREE(tmp);

    /* source */
    if ((node = virXPathNode("./source", ctxt)) &&
        virDomainMemorySourceDefParseXML(node, ctxt, def) < 0)
        goto error;

    /* target */
    if (!(node = virXPathNode("./target", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing <target> element for <memory> device"));
        goto error;
    }

    if (virDomainMemoryTargetDefParseXML(node, ctxt, def) < 0)
        goto error;

    if (virDomainDeviceInfoParseXML(memdevNode, NULL, &def->info, flags) < 0)
        goto error;

    ctxt->node = save;
    return def;

 error:
    VIR_FREE(tmp);
    virDomainMemoryDefFree(def);
    ctxt->node = save;
    return NULL;
}


static virDomainIOMMUDefPtr
virDomainIOMMUDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    virDomainIOMMUDefPtr iommu = NULL, ret = NULL;
    xmlNodePtr save = ctxt->node;
    char *tmp = NULL;
    int val;

    ctxt->node = node;

    if (VIR_ALLOC(iommu) < 0)
        goto cleanup;

    if (!(tmp = virXMLPropString(node, "model"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing model for IOMMU device"));
        goto cleanup;
    }

    if ((val = virDomainIOMMUModelTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_XML_ERROR, _("unknown IOMMU model: %s"), tmp);
        goto cleanup;
    }

    iommu->model = val;

    VIR_FREE(tmp);
    if ((tmp = virXPathString("string(./driver/@intremap)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, _("unknown intremap value: %s"), tmp);
            goto cleanup;
        }
        iommu->intremap = val;
    }

    VIR_FREE(tmp);
    if ((tmp = virXPathString("string(./driver/@caching_mode)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, _("unknown caching_mode value: %s"), tmp);
            goto cleanup;
        }
        iommu->caching_mode = val;
    }
    VIR_FREE(tmp);
    if ((tmp = virXPathString("string(./driver/@iotlb)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, _("unknown iotlb value: %s"), tmp);
            goto cleanup;
        }
        iommu->iotlb = val;
    }

    VIR_FREE(tmp);
    if ((tmp = virXPathString("string(./driver/@eim)", ctxt))) {
        if ((val = virTristateSwitchTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, _("unknown eim value: %s"), tmp);
            goto cleanup;
        }
        iommu->eim = val;
    }

    ret = iommu;
    iommu = NULL;

 cleanup:
    ctxt->node = save;
    VIR_FREE(iommu);
    VIR_FREE(tmp);
    return ret;
}


virDomainDeviceDefPtr
virDomainDeviceDefParse(const char *xmlStr,
                        const virDomainDef *def,
                        virCapsPtr caps,
                        virDomainXMLOptionPtr xmlopt,
                        unsigned int flags)
{
    xmlDocPtr xml;
    xmlNodePtr node;
    xmlXPathContextPtr ctxt = NULL;
    virDomainDeviceDefPtr dev = NULL;
    char *netprefix;

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("(device_definition)"), &ctxt)))
        goto error;

    node = ctxt->node;

    if (VIR_ALLOC(dev) < 0)
        goto error;

    if ((dev->type = virDomainDeviceTypeFromString((const char *) node->name)) < 0) {
        /* Some crazy mapping of serial, parallel, console and channel to
         * VIR_DOMAIN_DEVICE_CHR. */
        if (xmlStrEqual(node->name, BAD_CAST "channel") ||
            xmlStrEqual(node->name, BAD_CAST "console") ||
            xmlStrEqual(node->name, BAD_CAST "parallel") ||
            xmlStrEqual(node->name, BAD_CAST "serial")) {
            dev->type = VIR_DOMAIN_DEVICE_CHR;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown device type '%s'"),
                           node->name);
            goto error;
        }
    }

    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (!(dev->data.disk = virDomainDiskDefParseXML(xmlopt, node, ctxt,
                                                        NULL, def->seclabels,
                                                        def->nseclabels,
                                                        flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        if (!(dev->data.lease = virDomainLeaseDefParseXML(node)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_FS:
        if (!(dev->data.fs = virDomainFSDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_NET:
        netprefix = caps->host.netprefix;
        if (!(dev->data.net = virDomainNetDefParseXML(xmlopt, node, ctxt,
                                                      NULL, netprefix, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        if (!(dev->data.input = virDomainInputDefParseXML(def, node,
                                                          ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        if (!(dev->data.sound = virDomainSoundDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        if (!(dev->data.watchdog = virDomainWatchdogDefParseXML(node, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        if (!(dev->data.video = virDomainVideoDefParseXML(node, ctxt, def, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (!(dev->data.hostdev = virDomainHostdevDefParseXML(xmlopt, node,
                                                              ctxt, NULL,
                                                              flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        if (!(dev->data.controller = virDomainControllerDefParseXML(node, ctxt,
                                                                    flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if (!(dev->data.graphics = virDomainGraphicsDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_HUB:
        if (!(dev->data.hub = virDomainHubDefParseXML(node, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        if (!(dev->data.redirdev = virDomainRedirdevDefParseXML(xmlopt, node,
                                                                NULL, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        if (!(dev->data.rng = virDomainRNGDefParseXML(xmlopt, node,
                                                      ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        if (!(dev->data.chr = virDomainChrDefParseXML(xmlopt,
                                                      ctxt,
                                                      node,
                                                      def->seclabels,
                                                      def->nseclabels,
                                                      flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        if (!(dev->data.smartcard = virDomainSmartcardDefParseXML(xmlopt, node,
                                                                  flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        if (!(dev->data.memballoon = virDomainMemballoonDefParseXML(node,
                                                                    ctxt,
                                                                    flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_NVRAM:
        if (!(dev->data.nvram = virDomainNVRAMDefParseXML(node, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        if (!(dev->data.shmem = virDomainShmemDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_TPM:
        if (!(dev->data.tpm = virDomainTPMDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_PANIC:
        if (!(dev->data.panic = virDomainPanicDefParseXML(node, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        if (!(dev->data.memory = virDomainMemoryDefParseXML(node, ctxt, flags)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_IOMMU:
        if (!(dev->data.iommu = virDomainIOMMUDefParseXML(node, ctxt)))
            goto error;
        break;
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    /* callback to fill driver specific device aspects */
    if (virDomainDeviceDefPostParse(dev, def, caps, flags, xmlopt, NULL) < 0)
        goto error;

    /* validate the configuration */
    if (virDomainDeviceDefValidate(dev, def, flags, xmlopt) < 0)
        goto error;

 cleanup:
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return dev;

 error:
    VIR_FREE(dev);
    goto cleanup;
}


virStorageSourcePtr
virDomainDiskDefSourceParse(const char *xmlStr,
                            const virDomainDef *def,
                            virDomainXMLOptionPtr xmlopt,
                            unsigned int flags)
{
    xmlDocPtr xml;
    xmlNodePtr node;
    xmlXPathContextPtr ctxt = NULL;
    virDomainDiskDefPtr disk = NULL;
    virStorageSourcePtr ret = NULL;

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("(disk_definition)"), &ctxt)))
        goto cleanup;
    node = ctxt->node;

    if (!xmlStrEqual(node->name, BAD_CAST "disk")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("expecting root element of 'disk', not '%s'"),
                       node->name);
        goto cleanup;
    }

    flags |= VIR_DOMAIN_DEF_PARSE_DISK_SOURCE;
    if (!(disk = virDomainDiskDefParseXML(xmlopt, node, ctxt,
                                          NULL, def->seclabels,
                                          def->nseclabels,
                                          flags)))
        goto cleanup;

    ret = disk->src;
    disk->src = NULL;

 cleanup:
    virDomainDiskDefFree(disk);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return ret;
}


static const char *
virDomainChrTargetTypeToString(int deviceType,
                               int targetType)
{
    const char *type = NULL;

    switch (deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        type = virDomainChrChannelTargetTypeToString(targetType);
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        type = virDomainChrConsoleTargetTypeToString(targetType);
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        type = virDomainChrSerialTargetTypeToString(targetType);
        break;
    default:
        break;
    }

    return type;
}

int
virDomainHostdevInsert(virDomainDefPtr def, virDomainHostdevDefPtr hostdev)
{

    return VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev);
}

virDomainHostdevDefPtr
virDomainHostdevRemove(virDomainDefPtr def, size_t i)
{
    virDomainHostdevDefPtr hostdev = def->hostdevs[i];

    VIR_DELETE_ELEMENT(def->hostdevs, i, def->nhostdevs);
    return hostdev;
}


static int
virDomainHostdevMatchSubsysUSB(virDomainHostdevDefPtr first,
                               virDomainHostdevDefPtr second)
{
    virDomainHostdevSubsysUSBPtr first_usbsrc = &first->source.subsys.u.usb;
    virDomainHostdevSubsysUSBPtr second_usbsrc = &second->source.subsys.u.usb;

    if (first_usbsrc->bus && first_usbsrc->device) {
        /* specified by bus location on host */
        if (first_usbsrc->bus == second_usbsrc->bus &&
            first_usbsrc->device == second_usbsrc->device)
            return 1;
    } else {
        /* specified by product & vendor id */
        if (first_usbsrc->product == second_usbsrc->product &&
            first_usbsrc->vendor == second_usbsrc->vendor)
            return 1;
    }
    return 0;
}

static int
virDomainHostdevMatchSubsysPCI(virDomainHostdevDefPtr first,
                               virDomainHostdevDefPtr second)
{
    virDomainHostdevSubsysPCIPtr first_pcisrc = &first->source.subsys.u.pci;
    virDomainHostdevSubsysPCIPtr second_pcisrc = &second->source.subsys.u.pci;

    if (first_pcisrc->addr.domain == second_pcisrc->addr.domain &&
        first_pcisrc->addr.bus == second_pcisrc->addr.bus &&
        first_pcisrc->addr.slot == second_pcisrc->addr.slot &&
        first_pcisrc->addr.function == second_pcisrc->addr.function)
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysSCSIHost(virDomainHostdevDefPtr first,
                                    virDomainHostdevDefPtr second)
{
    virDomainHostdevSubsysSCSIHostPtr first_scsihostsrc =
        &first->source.subsys.u.scsi.u.host;
    virDomainHostdevSubsysSCSIHostPtr second_scsihostsrc =
        &second->source.subsys.u.scsi.u.host;

    if (STREQ(first_scsihostsrc->adapter, second_scsihostsrc->adapter) &&
        first_scsihostsrc->bus == second_scsihostsrc->bus &&
        first_scsihostsrc->target == second_scsihostsrc->target &&
        first_scsihostsrc->unit == second_scsihostsrc->unit)
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysSCSIiSCSI(virDomainHostdevDefPtr first,
                                     virDomainHostdevDefPtr second)
{
    virDomainHostdevSubsysSCSIiSCSIPtr first_iscsisrc =
        &first->source.subsys.u.scsi.u.iscsi;
    virDomainHostdevSubsysSCSIiSCSIPtr second_iscsisrc =
        &second->source.subsys.u.scsi.u.iscsi;

    if (STREQ(first_iscsisrc->hosts[0].name, second_iscsisrc->hosts[0].name) &&
        STREQ(first_iscsisrc->hosts[0].port, second_iscsisrc->hosts[0].port) &&
        STREQ(first_iscsisrc->path, second_iscsisrc->path))
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysMediatedDev(virDomainHostdevDefPtr a,
                                       virDomainHostdevDefPtr b)
{
    virDomainHostdevSubsysMediatedDevPtr src_a = &a->source.subsys.u.mdev;
    virDomainHostdevSubsysMediatedDevPtr src_b = &b->source.subsys.u.mdev;

    if (STREQ(src_a->uuidstr, src_b->uuidstr))
        return 1;

    return 0;
}

static int
virDomainHostdevMatchSubsys(virDomainHostdevDefPtr a,
                            virDomainHostdevDefPtr b)
{
    if (a->source.subsys.type != b->source.subsys.type)
        return 0;

    switch ((virDomainHostdevSubsysType) a->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        return virDomainHostdevMatchSubsysPCI(a, b);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return virDomainHostdevMatchSubsysUSB(a, b);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (a->source.subsys.u.scsi.protocol !=
            b->source.subsys.u.scsi.protocol)
            return 0;
        if (a->source.subsys.u.scsi.protocol ==
            VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
            return virDomainHostdevMatchSubsysSCSIiSCSI(a, b);
        else
            return virDomainHostdevMatchSubsysSCSIHost(a, b);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        if (a->source.subsys.u.scsi_host.protocol !=
            b->source.subsys.u.scsi_host.protocol)
            return 0;
        if (STREQ(a->source.subsys.u.scsi_host.wwpn,
                  b->source.subsys.u.scsi_host.wwpn))
            return 1;
        else
            return 0;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        return virDomainHostdevMatchSubsysMediatedDev(a, b);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        return 0;
    }
    return 0;
}


static int
virDomainHostdevMatchCapsStorage(virDomainHostdevDefPtr a,
                                 virDomainHostdevDefPtr b)
{
    return STREQ_NULLABLE(a->source.caps.u.storage.block,
                          b->source.caps.u.storage.block);
}


static int
virDomainHostdevMatchCapsMisc(virDomainHostdevDefPtr a,
                              virDomainHostdevDefPtr b)
{
    return STREQ_NULLABLE(a->source.caps.u.misc.chardev,
                          b->source.caps.u.misc.chardev);
}

static int
virDomainHostdevMatchCapsNet(virDomainHostdevDefPtr a,
                              virDomainHostdevDefPtr b)
{
    return STREQ_NULLABLE(a->source.caps.u.net.ifname,
                          b->source.caps.u.net.ifname);
}


static int
virDomainHostdevMatchCaps(virDomainHostdevDefPtr a,
                          virDomainHostdevDefPtr b)
{
    if (a->source.caps.type != b->source.caps.type)
        return 0;

    switch (a->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return virDomainHostdevMatchCapsStorage(a, b);
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return virDomainHostdevMatchCapsMisc(a, b);
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        return virDomainHostdevMatchCapsNet(a, b);
    }
    return 0;
}


static int
virDomainHostdevMatch(virDomainHostdevDefPtr a,
                      virDomainHostdevDefPtr b)
{
    if (a->mode != b->mode)
        return 0;

    switch (a->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return virDomainHostdevMatchSubsys(a, b);
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return virDomainHostdevMatchCaps(a, b);
    }
    return 0;
}

/* Find an entry in hostdevs that matches the source spec in
 * @match. return pointer to the entry in @found (if found is
 * non-NULL). Returns index (within hostdevs) of matched entry, or -1
 * if no match was found.
 */
int
virDomainHostdevFind(virDomainDefPtr def,
                     virDomainHostdevDefPtr match,
                     virDomainHostdevDefPtr *found)
{
    virDomainHostdevDefPtr local_found;
    size_t i;

    if (!found)
        found = &local_found;
    *found = NULL;

    for (i = 0; i < def->nhostdevs; i++) {
        if (virDomainHostdevMatch(match, def->hostdevs[i])) {
            *found = def->hostdevs[i];
            break;
        }
    }
    return *found ? i : -1;
}

static bool
virDomainDiskControllerMatch(int controller_type, int disk_bus)
{
    if (controller_type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
        disk_bus == VIR_DOMAIN_DISK_BUS_SCSI)
        return true;

    if (controller_type == VIR_DOMAIN_CONTROLLER_TYPE_FDC &&
        disk_bus == VIR_DOMAIN_DISK_BUS_FDC)
        return true;

    if (controller_type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
        disk_bus == VIR_DOMAIN_DISK_BUS_IDE)
        return true;

    if (controller_type == VIR_DOMAIN_CONTROLLER_TYPE_SATA &&
        disk_bus == VIR_DOMAIN_DISK_BUS_SATA)
        return true;

    return false;
}


int
virDomainDiskIndexByAddress(virDomainDefPtr def,
                            virPCIDeviceAddressPtr pci_address,
                            unsigned int bus, unsigned int target,
                            unsigned int unit)
{
    virDomainDiskDefPtr vdisk;
    virDomainControllerDefPtr controller = NULL;
    size_t i;
    int cidx;

    if ((cidx = virDomainControllerFindByPCIAddress(def, pci_address)) >= 0)
        controller = def->controllers[cidx];

    for (i = 0; i < def->ndisks; i++) {
        vdisk = def->disks[i];
        if (vdisk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            virPCIDeviceAddressEqual(&vdisk->info.addr.pci, pci_address))
            return i;
        if (vdisk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virDomainDeviceDriveAddressPtr drive = &vdisk->info.addr.drive;
            if (controller &&
                virDomainDiskControllerMatch(controller->type, vdisk->bus) &&
                drive->controller == controller->idx &&
                drive->bus == bus && drive->target == target &&
                drive->unit == unit)
                return i;
        }
    }
    return -1;
}

virDomainDiskDefPtr
virDomainDiskByAddress(virDomainDefPtr def,
                       virPCIDeviceAddressPtr pci_address,
                       unsigned int bus,
                       unsigned int target,
                       unsigned int unit)
{
    int idx = virDomainDiskIndexByAddress(def, pci_address, bus, target, unit);
    return idx < 0 ? NULL : def->disks[idx];
}

int
virDomainDiskIndexByName(virDomainDefPtr def, const char *name,
                         bool allow_ambiguous)
{
    virDomainDiskDefPtr vdisk;
    size_t i;
    int candidate = -1;

    /* We prefer the <target dev='name'/> name (it's shorter, required
     * for all disks, and should be unambiguous), but also support
     * <source file='name'/> (if unambiguous).  Assume dst if there is
     * no leading slash, source name otherwise.  */
    for (i = 0; i < def->ndisks; i++) {
        vdisk = def->disks[i];
        if (*name != '/') {
            if (STREQ(vdisk->dst, name))
                return i;
        } else if (STREQ_NULLABLE(virDomainDiskGetSource(vdisk), name)) {
            if (allow_ambiguous)
                return i;
            if (candidate >= 0)
                return -1;
            candidate = i;
        }
    }
    return candidate;
}

/* Return the path to a disk image if a string identifies at least one
 * disk belonging to the domain (both device strings 'vda' and paths
 * '/path/to/file' are converted into '/path/to/file').  */
const char *
virDomainDiskPathByName(virDomainDefPtr def, const char *name)
{
    int idx = virDomainDiskIndexByName(def, name, true);

    return idx < 0 ? NULL : virDomainDiskGetSource(def->disks[idx]);
}

virDomainDiskDefPtr
virDomainDiskByName(virDomainDefPtr def,
                    const char *name,
                    bool allow_ambiguous)
{
    int idx = virDomainDiskIndexByName(def, name, allow_ambiguous);
    return idx < 0 ? NULL : def->disks[idx];
}

int virDomainDiskInsert(virDomainDefPtr def,
                        virDomainDiskDefPtr disk)
{

    if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
        return -1;

    virDomainDiskInsertPreAlloced(def, disk);

    return 0;
}

void virDomainDiskInsertPreAlloced(virDomainDefPtr def,
                                   virDomainDiskDefPtr disk)
{
    int idx;
    /* Tentatively plan to insert disk at the end. */
    int insertAt = -1;

    /* Then work backwards looking for disks on
     * the same bus. If we find a disk with a drive
     * index greater than the new one, insert at
     * that position
     */
    for (idx = (def->ndisks - 1); idx >= 0; idx--) {
        /* If bus matches and current disk is after
         * new disk, then new disk should go here */
        if (def->disks[idx]->bus == disk->bus &&
            (virDiskNameToIndex(def->disks[idx]->dst) >
             virDiskNameToIndex(disk->dst))) {
            insertAt = idx;
        } else if (def->disks[idx]->bus == disk->bus &&
                   insertAt == -1) {
            /* Last disk with match bus is before the
             * new disk, then put new disk just after
             */
            insertAt = idx + 1;
        }
    }

    /* VIR_INSERT_ELEMENT_INPLACE will never return an error here. */
    ignore_value(VIR_INSERT_ELEMENT_INPLACE(def->disks, insertAt,
                                            def->ndisks, disk));
}


virDomainDiskDefPtr
virDomainDiskRemove(virDomainDefPtr def, size_t i)
{
    virDomainDiskDefPtr disk = def->disks[i];

    VIR_DELETE_ELEMENT(def->disks, i, def->ndisks);
    return disk;
}

virDomainDiskDefPtr
virDomainDiskRemoveByName(virDomainDefPtr def, const char *name)
{
    int idx = virDomainDiskIndexByName(def, name, false);
    if (idx < 0)
        return NULL;
    return virDomainDiskRemove(def, idx);
}

int virDomainNetInsert(virDomainDefPtr def, virDomainNetDefPtr net)
{
    /* hostdev net devices must also exist in the hostdevs array */
    if (net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        virDomainHostdevInsert(def, &net->data.hostdev.def) < 0)
        return -1;

    if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0) {
        /* virDomainHostdevInsert just appends new hostdevs, so we are sure
         * that the hostdev we've added a few lines above is at the end of
         * array. Although, devices are indexed from zero ... */
        virDomainHostdevRemove(def, def->nhostdevs - 1);
        return -1;
    }
    return 0;
}

/* virDomainNetFindIdx: search according to mac address and guest side
 *                      PCI address (if specified)
 *
 * Return: index of match if unique match found
 *         -1 otherwise and an error is logged
 */
int
virDomainNetFindIdx(virDomainDefPtr def, virDomainNetDefPtr net)
{
    size_t i;
    int matchidx = -1;
    char mac[VIR_MAC_STRING_BUFLEN];
    bool PCIAddrSpecified = virDomainDeviceAddressIsValid(&net->info,
                                                          VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI);

    for (i = 0; i < def->nnets; i++) {
        if (virMacAddrCmp(&def->nets[i]->mac, &net->mac))
            continue;

        if ((matchidx >= 0) && !PCIAddrSpecified) {
            /* there were multiple matches on mac address, and no
             * qualifying guest-side PCI address was given, so we must
             * fail (NB: a USB address isn't adequate, since it may
             * specify only vendor and product ID, and there may be
             * multiples of those.
             */
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("multiple devices matching mac address %s found"),
                           virMacAddrFormat(&net->mac, mac));
            return -1;
        }
        if (PCIAddrSpecified) {
            if (virPCIDeviceAddressEqual(&def->nets[i]->info.addr.pci,
                                         &net->info.addr.pci)) {
                /* exit early if the pci address was specified and
                 * it matches, as this guarantees no duplicates.
                 */
                matchidx = i;
                break;
            }
        } else {
            /* no PCI address given, so there may be multiple matches */
            matchidx = i;
        }
    }
    if (matchidx < 0) {
        if (PCIAddrSpecified) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("no device matching mac address %s found on "
                             "%.4x:%.2x:%.2x.%.1x"),
                           virMacAddrFormat(&net->mac, mac),
                           net->info.addr.pci.domain,
                           net->info.addr.pci.bus,
                           net->info.addr.pci.slot,
                           net->info.addr.pci.function);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("no device matching mac address %s found"),
                           virMacAddrFormat(&net->mac, mac));
        }
    }
    return matchidx;
}

bool
virDomainHasNet(virDomainDefPtr def, virDomainNetDefPtr net)
{
    size_t i;
    bool PCIAddrSpecified = virDomainDeviceAddressIsValid(&net->info,
                                                          VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI);

    for (i = 0; i < def->nnets; i++) {
        if (virMacAddrCmp(&def->nets[i]->mac, &net->mac))
            continue;

        if (PCIAddrSpecified) {
            if (virPCIDeviceAddressEqual(&def->nets[i]->info.addr.pci,
                                         &net->info.addr.pci))
                return true;
        } else {
            return true;
        }
    }
    return false;
}

void
virDomainNetRemoveHostdev(virDomainDefPtr def,
                          virDomainNetDefPtr net)
{
    /* hostdev net devices are normally in the hostdevs array, but
     * might have already been removed by the time we get here */
    virDomainHostdevDefPtr hostdev = virDomainNetGetActualHostdev(net);
    size_t i;

    if (hostdev) {
        for (i = 0; i < def->nhostdevs; i++) {
            if (def->hostdevs[i] == hostdev) {
                virDomainHostdevRemove(def, i);
                break;
            }
        }
    }
}


virDomainNetDefPtr
virDomainNetRemove(virDomainDefPtr def, size_t i)
{
    virDomainNetDefPtr net = def->nets[i];

    virDomainNetRemoveHostdev(def, net);
    VIR_DELETE_ELEMENT(def->nets, i, def->nnets);
    return net;
}

int virDomainControllerInsert(virDomainDefPtr def,
                              virDomainControllerDefPtr controller)
{

    if (VIR_REALLOC_N(def->controllers, def->ncontrollers+1) < 0)
        return -1;

    virDomainControllerInsertPreAlloced(def, controller);

    return 0;
}

void virDomainControllerInsertPreAlloced(virDomainDefPtr def,
                                         virDomainControllerDefPtr controller)
{
    int idx;
    /* Tentatively plan to insert controller at the end. */
    int insertAt = -1;
    virDomainControllerDefPtr current = NULL;

    /* Then work backwards looking for controllers of
     * the same type. If we find a controller with a
     * index greater than the new one, insert at
     * that position
     */
    for (idx = (def->ncontrollers - 1); idx >= 0; idx--) {
        current = def->controllers[idx];
        if (current->type == controller->type) {
            if (controller->idx == -1) {
                /* If the new controller doesn't have an index set
                 * yet, put it just past this controller, which until
                 * now was the last controller of this type.
                 */
                insertAt = idx + 1;
                break;
            }
            if (current->idx > controller->idx) {
                /* If bus matches and current controller is after
                 * new controller, then new controller should go here
                 * */
                insertAt = idx;
            } else if (controller->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_NONE &&
                       current->info.mastertype != VIR_DOMAIN_CONTROLLER_MASTER_NONE &&
                       current->idx == controller->idx) {
                /* If bus matches and index matches and new controller is
                 * master and current isn't a master, then new controller
                 * should go here to be placed before its companion
                 */
                insertAt = idx;
            } else if (insertAt == -1) {
                /* Last controller with match bus is before the
                 * new controller, then put new controller just after
                 */
                insertAt = idx + 1;
            }
        }
    }

    /* VIR_INSERT_ELEMENT_INPLACE will never return an error here. */
    ignore_value(VIR_INSERT_ELEMENT_INPLACE(def->controllers, insertAt,
                                            def->ncontrollers, controller));
}

int
virDomainControllerFind(const virDomainDef *def,
                        int type,
                        int idx)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if ((def->controllers[i]->type == type) &&
            (def->controllers[i]->idx == idx)) {
            return i;
        }
    }

    return -1;
}


int
virDomainControllerFindUnusedIndex(virDomainDef const *def, int type)
{
    int idx = 0;

    while (virDomainControllerFind(def, type, idx) >= 0)
        idx++;

    return idx;
}


const char *
virDomainControllerAliasFind(const virDomainDef *def,
                             int type,
                             int idx)
{
    int contIndex;
    const char *contTypeStr = virDomainControllerTypeToString(type);

    if (!contTypeStr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown controller type %d"),
                       type);
        return NULL;
    }

    contIndex = virDomainControllerFind(def, type, idx);
    if (contIndex < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find %s controller with index %d "
                         "required for device"),
                       contTypeStr, idx);
        return NULL;
    }
    if (!def->controllers[contIndex]->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device alias was not set for %s controller "
                         "with index %d "),
                       contTypeStr, idx);
        return NULL;
    }
    return def->controllers[contIndex]->info.alias;
}


int
virDomainControllerFindByType(virDomainDefPtr def,
                              int type)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == type)
            return i;
    }

    return -1;
}

int
virDomainControllerFindByPCIAddress(virDomainDefPtr def,
                                    virPCIDeviceAddressPtr addr)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainDeviceInfoPtr info = &def->controllers[i]->info;

        if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            virPCIDeviceAddressEqual(&info->addr.pci, addr))
            return i;
    }

    return -1;
}

virDomainControllerDefPtr
virDomainControllerRemove(virDomainDefPtr def, size_t i)
{
    virDomainControllerDefPtr controller = def->controllers[i];

    VIR_DELETE_ELEMENT(def->controllers, i, def->ncontrollers);
    return controller;
}

int virDomainLeaseIndex(virDomainDefPtr def,
                        virDomainLeaseDefPtr lease)
{
    virDomainLeaseDefPtr vlease;
    size_t i;

    for (i = 0; i < def->nleases; i++) {
        vlease = def->leases[i];
        /* Either both must have lockspaces present which match.. */
        if (vlease->lockspace && lease->lockspace) {
            if (STRNEQ(vlease->lockspace, lease->lockspace))
                continue;
        /* ...or neither must have a lockspace present */
        } else if (vlease->lockspace || lease->lockspace) {
            continue;
        }

        if (STREQ(vlease->key, lease->key))
            return i;
    }
    return -1;
}


int virDomainLeaseInsertPreAlloc(virDomainDefPtr def)
{
    return VIR_EXPAND_N(def->leases, def->nleases, 1);
}

int virDomainLeaseInsert(virDomainDefPtr def,
                         virDomainLeaseDefPtr lease)
{
    if (virDomainLeaseInsertPreAlloc(def) < 0)
        return -1;

    virDomainLeaseInsertPreAlloced(def, lease);
    return 0;
}


void virDomainLeaseInsertPreAlloced(virDomainDefPtr def,
                                    virDomainLeaseDefPtr lease)
{
    if (lease == NULL)
        VIR_SHRINK_N(def->leases, def->nleases, 1);
    else
        def->leases[def->nleases-1] = lease;
}


virDomainLeaseDefPtr
virDomainLeaseRemoveAt(virDomainDefPtr def, size_t i)
{

    virDomainLeaseDefPtr lease = def->leases[i];

    VIR_DELETE_ELEMENT(def->leases, i, def->nleases);
    return lease;
}


virDomainLeaseDefPtr
virDomainLeaseRemove(virDomainDefPtr def,
                     virDomainLeaseDefPtr lease)
{
    int idx = virDomainLeaseIndex(def, lease);
    if (idx < 0)
        return NULL;
    return virDomainLeaseRemoveAt(def, idx);
}

bool
virDomainChrEquals(virDomainChrDefPtr src,
                   virDomainChrDefPtr tgt)
{
    if (!src || !tgt)
        return src == tgt;

    if (src->deviceType != tgt->deviceType ||
        !virDomainChrSourceDefIsEqual(src->source, tgt->source))
        return false;

    switch ((virDomainChrDeviceType) src->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        if (src->targetType != tgt->targetType)
            return false;
        switch ((virDomainChrChannelTargetType) src->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            return STREQ_NULLABLE(src->target.name, tgt->target.name);
            break;
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!src->target.addr || !tgt->target.addr)
                return src->target.addr == tgt->target.addr;
            return memcmp(src->target.addr, tgt->target.addr,
                          sizeof(*src->target.addr)) == 0;
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST:
            /* shouldn't happen */
            break;
        }
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        if (src->targetTypeAttr != tgt->targetTypeAttr)
            return false;

        ATTRIBUTE_FALLTHROUGH;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        return src->target.port == tgt->target.port;
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* shouldn't happen */
        break;
    }
    return false;
}

virDomainChrDefPtr
virDomainChrFind(virDomainDefPtr def,
                 virDomainChrDefPtr target)
{
    virDomainChrDefPtr chr;
    const virDomainChrDef **arrPtr;
    size_t i, cnt;

    virDomainChrGetDomainPtrs(def, target->deviceType, &arrPtr, &cnt);

    for (i = 0; i < cnt; i++) {
        /* Cast away const */
        chr = (virDomainChrDefPtr) arrPtr[i];
        if (virDomainChrEquals(chr, target))
            return chr;
    }
    return NULL;
}


/* Return the address within vmdef to be modified when working with a
 * chrdefptr of the given type.  */
static int ATTRIBUTE_RETURN_CHECK
virDomainChrGetDomainPtrsInternal(virDomainDefPtr vmdef,
                                  virDomainChrDeviceType type,
                                  virDomainChrDefPtr ***arrPtr,
                                  size_t **cntPtr)
{
    switch (type) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        *arrPtr = &vmdef->parallels;
        *cntPtr = &vmdef->nparallels;
        return 0;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        *arrPtr = &vmdef->serials;
        *cntPtr = &vmdef->nserials;
        return 0;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        *arrPtr = &vmdef->consoles;
        *cntPtr = &vmdef->nconsoles;
        return 0;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        *arrPtr = &vmdef->channels;
        *cntPtr = &vmdef->nchannels;
        return 0;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        break;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unknown char device type: %d"), type);
    return -1;
}


/* Return the array within vmdef that can contain a chrdefptr of the
 * given type.  */
void
virDomainChrGetDomainPtrs(const virDomainDef *vmdef,
                          virDomainChrDeviceType type,
                          const virDomainChrDef ***arrPtr,
                          size_t *cntPtr)
{
    virDomainChrDef ***arrVar = NULL;
    size_t *cntVar = NULL;

    /* Cast away const; we add it back in the final assignment.  */
    if (virDomainChrGetDomainPtrsInternal((virDomainDefPtr) vmdef, type,
                                          &arrVar, &cntVar) < 0) {
        *arrPtr = NULL;
        *cntPtr = 0;
    } else {
        *arrPtr = (const virDomainChrDef **) *arrVar;
        *cntPtr = *cntVar;
    }
}


int
virDomainChrPreAlloc(virDomainDefPtr vmdef,
                     virDomainChrDefPtr chr)
{
    virDomainChrDefPtr **arrPtr = NULL;
    size_t *cntPtr = NULL;

    if (virDomainChrGetDomainPtrsInternal(vmdef, chr->deviceType,
                                          &arrPtr, &cntPtr) < 0)
        return -1;

    return VIR_REALLOC_N(*arrPtr, *cntPtr + 1);
}

void
virDomainChrInsertPreAlloced(virDomainDefPtr vmdef,
                             virDomainChrDefPtr chr)
{
    virDomainChrDefPtr **arrPtr = NULL;
    size_t *cntPtr = NULL;

    if (virDomainChrGetDomainPtrsInternal(vmdef, chr->deviceType,
                                          &arrPtr, &cntPtr) < 0)
        return;

    VIR_APPEND_ELEMENT_INPLACE(*arrPtr, *cntPtr, chr);
}

virDomainChrDefPtr
virDomainChrRemove(virDomainDefPtr vmdef,
                   virDomainChrDefPtr chr)
{
    virDomainChrDefPtr ret = NULL, **arrPtr = NULL;
    size_t i, *cntPtr = NULL;

    if (virDomainChrGetDomainPtrsInternal(vmdef, chr->deviceType,
                                          &arrPtr, &cntPtr) < 0)
        return NULL;

    for (i = 0; i < *cntPtr; i++) {
        ret = (*arrPtr)[i];

        if (virDomainChrEquals(ret, chr))
            break;
    }

    if (i == *cntPtr)
        return NULL;

    VIR_DELETE_ELEMENT(*arrPtr, i, *cntPtr);
    return ret;
}


ssize_t
virDomainRNGFind(virDomainDefPtr def,
                 virDomainRNGDefPtr rng)
{
    size_t i;

    for (i = 0; i < def->nrngs; i++) {
        virDomainRNGDefPtr tmp = def->rngs[i];

        if (rng->model != tmp->model || rng->backend != tmp->backend)
            continue;

        if (rng->rate != tmp->rate || rng->period != tmp->period)
            continue;

        switch ((virDomainRNGBackend) rng->backend) {
        case VIR_DOMAIN_RNG_BACKEND_RANDOM:
            if (STRNEQ_NULLABLE(rng->source.file, tmp->source.file))
                continue;
            break;

        case VIR_DOMAIN_RNG_BACKEND_EGD:
            if (!virDomainChrSourceDefIsEqual(rng->source.chardev,
                                              tmp->source.chardev))
                continue;
            break;

        case VIR_DOMAIN_RNG_BACKEND_LAST:
            break;
        }

        if (rng->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            !virDomainDeviceInfoAddressIsEqual(&rng->info, &tmp->info))
            continue;

        break;
    }

    if (i < def->nrngs)
        return i;

    return -1;
}


virDomainRNGDefPtr
virDomainRNGRemove(virDomainDefPtr def,
                   size_t idx)
{
    virDomainRNGDefPtr ret = def->rngs[idx];

    VIR_DELETE_ELEMENT(def->rngs, idx, def->nrngs);

    return ret;
}


static int
virDomainMemoryFindByDefInternal(virDomainDefPtr def,
                                 virDomainMemoryDefPtr mem,
                                 bool allowAddressFallback)
{
    size_t i;

    for (i = 0; i < def->nmems; i++) {
        virDomainMemoryDefPtr tmp = def->mems[i];

        /* address, if present */
        if (allowAddressFallback) {
            if (tmp->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                continue;
        } else {
            if (mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                !virDomainDeviceInfoAddressIsEqual(&tmp->info, &mem->info))
                continue;
        }

        /* alias, if present */
        if (mem->info.alias &&
            STRNEQ_NULLABLE(tmp->info.alias, mem->info.alias))
            continue;

        /* target info -> always present */
        if (tmp->model != mem->model ||
            tmp->targetNode != mem->targetNode ||
            tmp->size != mem->size)
            continue;

        switch ((virDomainMemoryModel) mem->model) {
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
            /* source stuff -> match with device */
            if (tmp->pagesize != mem->pagesize)
                continue;

            if (!virBitmapEqual(tmp->sourceNodes, mem->sourceNodes))
                continue;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
            if (STRNEQ(tmp->nvdimmPath, mem->nvdimmPath))
                continue;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            break;
        }

        break;
    }

    if (i == def->nmems)
        return -1;

    return i;
}


int
virDomainMemoryFindByDef(virDomainDefPtr def,
                         virDomainMemoryDefPtr mem)
{
    return virDomainMemoryFindByDefInternal(def, mem, false);
}


int
virDomainMemoryFindInactiveByDef(virDomainDefPtr def,
                                 virDomainMemoryDefPtr mem)
{
    int ret;

    if ((ret = virDomainMemoryFindByDefInternal(def, mem, false)) < 0)
        ret = virDomainMemoryFindByDefInternal(def, mem, true);

    return ret;
}


/**
 * virDomainMemoryInsert:
 *
 * Inserts a memory device definition into the domain definition. This helper
 * should be used only in hot/cold-plug cases as it's blindly modifying the
 * total memory size.
 */
int
virDomainMemoryInsert(virDomainDefPtr def,
                      virDomainMemoryDefPtr mem)
{
    unsigned long long memory = virDomainDefGetMemoryTotal(def);
    int id = def->nmems;

    if (mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        virDomainDefHasDeviceAddress(def, &mem->info)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain already contains a device with the same "
                         "address"));
        return -1;
    }

    if (VIR_APPEND_ELEMENT_COPY(def->mems, def->nmems, mem) < 0)
        return -1;

    virDomainDefSetMemoryTotal(def, memory + mem->size);

    return id;
}


/**
 * virDomainMemoryRemove:
 *
 * Removes a memory device definition from the domain definition. This helper
 * should be used only in hot/cold-plug cases as it's blindly modifying the
 * total memory size.
 */
virDomainMemoryDefPtr
virDomainMemoryRemove(virDomainDefPtr def,
                      int idx)
{
    unsigned long long memory = virDomainDefGetMemoryTotal(def);
    virDomainMemoryDefPtr ret = def->mems[idx];

    VIR_DELETE_ELEMENT(def->mems, idx, def->nmems);

    /* fix total memory size of the domain */
    virDomainDefSetMemoryTotal(def, memory - ret->size);

    return ret;
}


ssize_t
virDomainRedirdevDefFind(virDomainDefPtr def,
                         virDomainRedirdevDefPtr redirdev)
{
    size_t i;

    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDefPtr tmp = def->redirdevs[i];

        if (redirdev->bus != tmp->bus)
            continue;

        if (!virDomainChrSourceDefIsEqual(redirdev->source, tmp->source))
            continue;

        if (redirdev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            !virDomainDeviceInfoAddressIsEqual(&redirdev->info, &tmp->info))
            continue;

        if (redirdev->info.alias &&
            STRNEQ_NULLABLE(redirdev->info.alias, tmp->info.alias))
            continue;

        return i;
    }

    return -1;
}


virDomainRedirdevDefPtr
virDomainRedirdevDefRemove(virDomainDefPtr def, size_t idx)
{
    virDomainRedirdevDefPtr ret = def->redirdevs[idx];

    VIR_DELETE_ELEMENT(def->redirdevs, idx, def->nredirdevs);

    return ret;
}


int
virDomainShmemDefInsert(virDomainDefPtr def,
                        virDomainShmemDefPtr shmem)
{
    return VIR_APPEND_ELEMENT(def->shmems, def->nshmems, shmem);
}


bool
virDomainShmemDefEquals(virDomainShmemDefPtr src,
                        virDomainShmemDefPtr dst)
{
    if (STRNEQ_NULLABLE(src->name, dst->name))
        return false;

    if (src->size != dst->size)
        return false;

    if (src->model != dst->model)
        return false;

    if (src->server.enabled != dst->server.enabled)
        return false;

    if (src->server.enabled) {
        if (STRNEQ_NULLABLE(src->server.chr.data.nix.path,
                            dst->server.chr.data.nix.path))
            return false;
    }

    if (src->msi.enabled != dst->msi.enabled)
        return false;

    if (src->msi.enabled) {
        if (src->msi.vectors != dst->msi.vectors)
            return false;
        if (src->msi.ioeventfd != dst->msi.ioeventfd)
            return false;
    }

    if (src->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        !virDomainDeviceInfoAddressIsEqual(&src->info, &dst->info))
        return false;

    return true;
}


ssize_t
virDomainShmemDefFind(virDomainDefPtr def,
                      virDomainShmemDefPtr shmem)
{
    size_t i;

    for (i = 0; i < def->nshmems; i++) {
        if (virDomainShmemDefEquals(shmem, def->shmems[i]))
            return i;
    }

    return -1;
}


virDomainShmemDefPtr
virDomainShmemDefRemove(virDomainDefPtr def,
                        size_t idx)
{
    virDomainShmemDefPtr ret = def->shmems[idx];

    VIR_DELETE_ELEMENT(def->shmems, idx, def->nshmems);

    return ret;
}


char *
virDomainDefGetDefaultEmulator(virDomainDefPtr def,
                               virCapsPtr caps)
{
    char *retemu;
    virCapsDomainDataPtr capsdata;

    if (!(capsdata = virCapabilitiesDomainDataLookup(caps, def->os.type,
            def->os.arch, def->virtType, NULL, NULL)))
        return NULL;

    if (VIR_STRDUP(retemu, capsdata->emulator) < 0) {
        VIR_FREE(capsdata);
        return NULL;
    }
    VIR_FREE(capsdata);
    return retemu;
}

static int
virDomainDefParseBootXML(xmlXPathContextPtr ctxt,
                         virDomainDefPtr def)
{
    xmlNodePtr *nodes = NULL;
    size_t i;
    int n;
    char *tmp = NULL;
    int ret = -1;
    unsigned long deviceBoot, serialPorts;

    if (virXPathULong("count(./devices/disk[boot]"
                      "|./devices/interface[boot]"
                      "|./devices/hostdev[boot]"
                      "|./devices/redirdev[boot])", ctxt, &deviceBoot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot count boot devices"));
        goto cleanup;
    }

    /* analysis of the boot devices */
    if ((n = virXPathNodeSet("./os/boot", ctxt, &nodes)) < 0)
        goto cleanup;

    if (n > 0 && deviceBoot) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("per-device boot elements cannot be used"
                         " together with os/boot elements"));
        goto cleanup;
    }

    for (i = 0; i < n && i < VIR_DOMAIN_BOOT_LAST; i++) {
        int val;
        char *dev = virXMLPropString(nodes[i], "dev");
        if (!dev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing boot device"));
            goto cleanup;
        }
        if ((val = virDomainBootTypeFromString(dev)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown boot device '%s'"),
                           dev);
            VIR_FREE(dev);
            goto cleanup;
        }
        VIR_FREE(dev);
        def->os.bootDevs[def->os.nBootDevs++] = val;
    }
    if (def->os.nBootDevs == 0 && !deviceBoot) {
        def->os.nBootDevs = 1;
        def->os.bootDevs[0] = VIR_DOMAIN_BOOT_DISK;
    }

    tmp = virXPathString("string(./os/bootmenu[1]/@enable)", ctxt);
    if (tmp) {
        def->os.bootmenu = virTristateBoolTypeFromString(tmp);
        if (def->os.bootmenu <= 0) {
            /* In order not to break misconfigured machines, this
             * should not emit an error, but rather set the bootmenu
             * to disabled */
            VIR_WARN("disabling bootmenu due to unknown option '%s'",
                     tmp);
            def->os.bootmenu = VIR_TRISTATE_BOOL_NO;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./os/bootmenu[1]/@timeout)", ctxt);
    if (tmp && def->os.bootmenu == VIR_TRISTATE_BOOL_YES) {
        if (virStrToLong_uip(tmp, NULL, 0, &def->os.bm_timeout) < 0 ||
            def->os.bm_timeout > 65535) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("invalid value for boot menu timeout, "
                             "must be in range [0,65535]"));
            goto cleanup;
        }
        def->os.bm_timeout_set = true;
    }
    VIR_FREE(tmp);

    tmp = virXPathString("string(./os/bios[1]/@useserial)", ctxt);
    if (tmp) {
        if (STREQ(tmp, "yes")) {
            if (virXPathULong("count(./devices/serial)",
                              ctxt, &serialPorts) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("need at least one serial port "
                                 "for useserial"));
                goto cleanup;
            }
            def->os.bios.useserial = VIR_TRISTATE_BOOL_YES;
        } else {
            def->os.bios.useserial = VIR_TRISTATE_BOOL_NO;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./os/bios[1]/@rebootTimeout)", ctxt);
    if (tmp) {
        /* that was really just for the check if it is there */

        if (virStrToLong_i(tmp, NULL, 0, &def->os.bios.rt_delay) < 0 ||
            def->os.bios.rt_delay < -1 || def->os.bios.rt_delay > 65535) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("invalid value for rebootTimeout, "
                             "must be in range [-1,65535]"));
            goto cleanup;
        }
        def->os.bios.rt_set = true;
    }

    ret = 0;

 cleanup:
    VIR_FREE(tmp);
    VIR_FREE(nodes);
    return ret;
}


static int virDomainIdMapEntrySort(const void *a, const void *b)
{
    const virDomainIdMapEntry *entrya = a;
    const virDomainIdMapEntry *entryb = b;

    if (entrya->start > entryb->start)
        return 1;
    else if (entrya->start < entryb->start)
        return -1;
    else
        return 0;
}

/* Parse the XML definition for user namespace id map.
 *
 * idmap has the form of
 *
 *   <uid start='0' target='1000' count='10'/>
 *   <gid start='0' target='1000' count='10'/>
 */
static virDomainIdMapEntryPtr
virDomainIdmapDefParseXML(xmlXPathContextPtr ctxt,
                          xmlNodePtr *node,
                          size_t num)
{
    size_t i;
    virDomainIdMapEntryPtr idmap = NULL;
    xmlNodePtr save_ctxt = ctxt->node;

    if (VIR_ALLOC_N(idmap, num) < 0)
        goto cleanup;

    for (i = 0; i < num; i++) {
        ctxt->node = node[i];
        if (virXPathUInt("string(./@start)", ctxt, &idmap[i].start) < 0 ||
            virXPathUInt("string(./@target)", ctxt, &idmap[i].target) < 0 ||
            virXPathUInt("string(./@count)", ctxt, &idmap[i].count) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid idmap start/target/count settings"));
            VIR_FREE(idmap);
            goto cleanup;
        }
    }

    qsort(idmap, num, sizeof(idmap[0]), virDomainIdMapEntrySort);

    if (idmap[0].start != 0) {
        /* Root user of container hasn't been mapped to any user of host,
         * return error. */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("You must map the root user of container"));
        VIR_FREE(idmap);
        goto cleanup;
    }

 cleanup:
    ctxt->node = save_ctxt;
    return idmap;
}

/* Parse the XML definition for an IOThread ID
 *
 * Format is :
 *
 *     <iothreads>4</iothreads>
 *     <iothreadids>
 *       <iothread id='1'/>
 *       <iothread id='3'/>
 *       <iothread id='5'/>
 *       <iothread id='7'/>
 *     </iothreadids>
 */
static virDomainIOThreadIDDefPtr
virDomainIOThreadIDDefParseXML(xmlNodePtr node,
                               xmlXPathContextPtr ctxt)
{
    virDomainIOThreadIDDefPtr iothrid;
    xmlNodePtr oldnode = ctxt->node;
    char *tmp = NULL;

    if (VIR_ALLOC(iothrid) < 0)
        return NULL;

    ctxt->node = node;

    if (!(tmp = virXPathString("string(./@id)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'id' attribute in <iothread> element"));
        goto error;
    }
    if (virStrToLong_uip(tmp, NULL, 10, &iothrid->iothread_id) < 0 ||
        iothrid->iothread_id == 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid iothread 'id' value '%s'"), tmp);
        goto error;
    }

 cleanup:
    VIR_FREE(tmp);
    ctxt->node = oldnode;
    return iothrid;

 error:
    virDomainIOThreadIDDefFree(iothrid);
    iothrid = NULL;
    goto cleanup;
}


static int
virDomainDefParseIOThreads(virDomainDefPtr def,
                           xmlXPathContextPtr ctxt)
{
    size_t i;
    char *tmp;
    int n = 0;
    unsigned int iothreads = 0;
    xmlNodePtr *nodes = NULL;

    tmp = virXPathString("string(./iothreads[1])", ctxt);
    if (tmp && virStrToLong_uip(tmp, NULL, 10, &iothreads) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid iothreads count '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    /* Extract any iothread id's defined */
    if ((n = virXPathNodeSet("./iothreadids/iothread", ctxt, &nodes)) < 0)
        goto error;

    if (n > iothreads)
        iothreads = n;

    if (n && VIR_ALLOC_N(def->iothreadids, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainIOThreadIDDefPtr iothrid = NULL;
        if (!(iothrid = virDomainIOThreadIDDefParseXML(nodes[i], ctxt)))
            goto error;

        if (virDomainIOThreadIDFind(def, iothrid->iothread_id)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("duplicate iothread id '%u' found"),
                           iothrid->iothread_id);
            virDomainIOThreadIDDefFree(iothrid);
            goto error;
        }
        def->iothreadids[def->niothreadids++] = iothrid;
    }
    VIR_FREE(nodes);

    if (virDomainIOThreadIDDefArrayInit(def, iothreads) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(nodes);
    return -1;
}


/* Parse the XML definition for a vcpupin
 *
 * vcpupin has the form of
 *   <vcpupin vcpu='0' cpuset='0'/>
 */
static int
virDomainVcpuPinDefParseXML(virDomainDefPtr def,
                            xmlNodePtr node)
{
    virDomainVcpuDefPtr vcpu;
    unsigned int vcpuid;
    char *tmp = NULL;
    int ret = -1;

    if (!(tmp = virXMLPropString(node, "vcpu"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing vcpu id in vcpupin"));
        goto cleanup;
    }

    if (virStrToLong_uip(tmp, NULL, 10, &vcpuid) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid setting for vcpu '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if (!(vcpu = virDomainDefGetVcpu(def, vcpuid))) {
        VIR_WARN("Ignoring vcpupin for missing vcpus");
        ret = 0;
        goto cleanup;
    }

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for vcpupin"));
        goto cleanup;
    }

    if (vcpu->cpumask) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("duplicate vcpupin for vcpu '%d'"), vcpuid);
        goto cleanup;
    }

    if (virBitmapParse(tmp, &vcpu->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto cleanup;

    if (virBitmapIsAllClear(vcpu->cpumask)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %s"), tmp);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(tmp);
    return ret;
}


/* Parse the XML definition for a iothreadpin
 * and an iothreadspin has the form
 *   <iothreadpin iothread='1' cpuset='2'/>
 */
static int
virDomainIOThreadPinDefParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virDomainDefPtr def)
{
    int ret = -1;
    virDomainIOThreadIDDefPtr iothrid;
    virBitmapPtr cpumask = NULL;
    xmlNodePtr oldnode = ctxt->node;
    unsigned int iothreadid;
    char *tmp = NULL;

    ctxt->node = node;

    if (!(tmp = virXPathString("string(./@iothread)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing iothread id in iothreadpin"));
        goto cleanup;
    }

    if (virStrToLong_uip(tmp, NULL, 10, &iothreadid) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid setting for iothread '%s'"), tmp);
        goto cleanup;
    }
    VIR_FREE(tmp);

    if (iothreadid == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("zero is an invalid iothread id value"));
        goto cleanup;
    }

    if (!(iothrid = virDomainIOThreadIDFind(def, iothreadid))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot find 'iothread' : %u"),
                       iothreadid);
        goto cleanup;
    }

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for iothreadpin"));
        goto cleanup;
    }

    if (virBitmapParse(tmp, &cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto cleanup;

    if (virBitmapIsAllClear(cpumask)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %s"),
                       tmp);
        goto cleanup;
    }

    if (iothrid->cpumask) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("duplicate iothreadpin for same iothread '%u'"),
                       iothreadid);
        goto cleanup;
    }

    iothrid->cpumask = cpumask;
    cpumask = NULL;
    ret = 0;

 cleanup:
    VIR_FREE(tmp);
    virBitmapFree(cpumask);
    ctxt->node = oldnode;
    return ret;
}


/* Parse the XML definition for emulatorpin.
 * emulatorpin has the form of
 *   <emulatorpin cpuset='0'/>
 */
static virBitmapPtr
virDomainEmulatorPinDefParseXML(xmlNodePtr node)
{
    virBitmapPtr def = NULL;
    char *tmp = NULL;

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for emulatorpin"));
        return NULL;
    }

    if (virBitmapParse(tmp, &def, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto cleanup;

    if (virBitmapIsAllClear(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %s"), tmp);
        virBitmapFree(def);
        def = NULL;
        goto cleanup;
    }

 cleanup:
    VIR_FREE(tmp);
    return def;
}


virDomainControllerDefPtr
virDomainDefAddController(virDomainDefPtr def, int type, int idx, int model)
{
    virDomainControllerDefPtr cont;

    if (!(cont = virDomainControllerDefNew(type)))
        return NULL;

    if (idx < 0)
        idx = virDomainControllerFindUnusedIndex(def, type);

    cont->idx = idx;
    cont->model = model;

    if (VIR_APPEND_ELEMENT_COPY(def->controllers, def->ncontrollers, cont) < 0) {
        VIR_FREE(cont);
        return NULL;
    }

    return cont;
}


/**
 * virDomainDefAddUSBController:
 * @def:   the domain
 * @idx:   index for new controller (or -1 for "lowest unused index")
 * @model: VIR_DOMAIN_CONTROLLER_MODEL_USB_* or -1
 *
 * Add a USB controller of the specified model (or default model for
 * current machinetype if model == -1). If model is ich9-usb-ehci,
 * also add companion uhci1, uhci2, and uhci3 controllers at the same
 * index.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virDomainDefAddUSBController(virDomainDefPtr def, int idx, int model)
{
    virDomainControllerDefPtr cont; /* this is a *copy* of the DefPtr */

    cont = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                     idx, model);
    if (!cont)
        return -1;

    if (model != VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1)
        return 0;

    /* When the initial controller is ich9-usb-ehci, also add the
     * companion controllers
     */

    idx = cont->idx; /* in case original request was "-1" */

    if (!(cont = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                           idx, VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1)))
        return -1;
    cont->info.mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
    cont->info.master.usb.startport = 0;

    if (!(cont = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                           idx, VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2)))
        return -1;
    cont->info.mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
    cont->info.master.usb.startport = 2;

    if (!(cont = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                           idx, VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3)))
        return -1;
    cont->info.mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
    cont->info.master.usb.startport = 4;

    return 0;
}


int
virDomainDefMaybeAddController(virDomainDefPtr def,
                               int type,
                               int idx,
                               int model)
{
    /* skip if a specific index was given and it is already
     * in use for that type of controller
     */
    if (idx >= 0 && virDomainControllerFind(def, type, idx) >= 0)
        return 0;

    if (virDomainDefAddController(def, type, idx, model))
        return 1;
    return -1;
}


int
virDomainDefMaybeAddInput(virDomainDefPtr def,
                          int type,
                          int bus)
{
    size_t i;
    virDomainInputDefPtr input;

    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->type == type &&
            def->inputs[i]->bus == bus)
            return 0;
    }

    if (VIR_ALLOC(input) < 0)
        return -1;

    input->type = type;
    input->bus = bus;

    if (VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input) < 0) {
        VIR_FREE(input);
        return -1;
    }

    return 0;
}


static int
virDomainHugepagesParseXML(xmlNodePtr node,
                           xmlXPathContextPtr ctxt,
                           virDomainHugePagePtr hugepage)
{
    int ret = -1;
    xmlNodePtr oldnode = ctxt->node;
    char *unit = NULL, *nodeset = NULL;

    ctxt->node = node;

    if (virDomainParseMemory("./@size", "./@unit", ctxt,
                             &hugepage->size, true, false) < 0)
        goto cleanup;

    if (!hugepage->size) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("hugepage size can't be zero"));
        goto cleanup;
    }

    if ((nodeset = virXMLPropString(node, "nodeset"))) {
        if (virBitmapParse(nodeset, &hugepage->nodemask,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;

        if (virBitmapIsAllClear(hugepage->nodemask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value of 'nodeset': %s"), nodeset);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(unit);
    VIR_FREE(nodeset);
    ctxt->node = oldnode;
    return ret;
}


static virDomainResourceDefPtr
virDomainResourceDefParse(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    virDomainResourceDefPtr def = NULL;
    xmlNodePtr tmp = ctxt->node;

    ctxt->node = node;

    if (VIR_ALLOC(def) < 0)
        goto error;

    /* Find out what type of virtualization to use */
    if (!(def->partition = virXPathString("string(./partition)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing resource partition attribute"));
        goto error;
    }

    ctxt->node = tmp;
    return def;

 error:
    ctxt->node = tmp;
    virDomainResourceDefFree(def);
    return NULL;
}

static int
virDomainDefMaybeAddHostdevSCSIcontroller(virDomainDefPtr def)
{
    /* Look for any hostdev scsi dev */
    size_t i;
    int maxController = -1;
    virDomainHostdevDefPtr hostdev;

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];
        if (virHostdevIsSCSIDevice(hostdev) &&
            (int)hostdev->info->addr.drive.controller > maxController) {
            maxController = hostdev->info->addr.drive.controller;
        }
    }

    if (maxController == -1)
        return 0;

    for (i = 0; i <= maxController; i++) {
        if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_SCSI, i, -1) < 0)
            return -1;
    }

    return 0;
}

static int
virDomainLoaderDefParseXML(xmlNodePtr node,
                           virDomainLoaderDefPtr loader)
{
    int ret = -1;
    char *readonly_str = NULL;
    char *secure_str = NULL;
    char *type_str = NULL;

    readonly_str = virXMLPropString(node, "readonly");
    secure_str = virXMLPropString(node, "secure");
    type_str = virXMLPropString(node, "type");
    loader->path = (char *) xmlNodeGetContent(node);

    if (readonly_str &&
        (loader->readonly = virTristateBoolTypeFromString(readonly_str)) <= 0) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("unknown readonly value: %s"), readonly_str);
        goto cleanup;
    }

    if (secure_str &&
        (loader->secure = virTristateBoolTypeFromString(secure_str)) <= 0) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("unknown secure value: %s"), secure_str);
        goto cleanup;
    }

    if (type_str) {
        int type;
        if ((type = virDomainLoaderTypeFromString(type_str)) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("unknown type value: %s"), type_str);
            goto cleanup;
        }
        loader->type = type;
    }

    ret = 0;
 cleanup:
    VIR_FREE(readonly_str);
    VIR_FREE(secure_str);
    VIR_FREE(type_str);
    return ret;
}


static virBitmapPtr
virDomainSchedulerParse(xmlNodePtr node,
                        const char *name,
                        virProcessSchedPolicy *policy,
                        int *priority)
{
    virBitmapPtr ret = NULL;
    char *tmp = NULL;
    int pol = 0;

    if (!(tmp = virXMLPropString(node, name))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing attribute '%s' in element '%sched'"),
                       name, name);
        goto error;
    }

    if (virBitmapParse(tmp, &ret, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto error;

    if (virBitmapIsAllClear(ret)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("'%s' scheduler bitmap '%s' is empty"),
                       name, tmp);
        goto error;
    }

    VIR_FREE(tmp);

    if (!(tmp = virXMLPropString(node, "scheduler"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing scheduler attribute"));
        goto error;
    }

    if ((pol = virProcessSchedPolicyTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid scheduler attribute: '%s'"), tmp);
        goto error;
    }
    *policy = pol;

    VIR_FREE(tmp);

    if (pol == VIR_PROC_POLICY_FIFO ||
        pol == VIR_PROC_POLICY_RR) {
        if (!(tmp = virXMLPropString(node, "priority"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing scheduler priority"));
            goto error;
        }

        if (virStrToLong_i(tmp, NULL, 10, priority) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid value for element priority"));
            goto error;
        }
        VIR_FREE(tmp);
    }

    return ret;

 error:
    VIR_FREE(tmp);
    virBitmapFree(ret);
    return NULL;
}


static int
virDomainThreadSchedParseHelper(xmlNodePtr node,
                                const char *name,
                                virDomainThreadSchedParamPtr (*func)(virDomainDefPtr, unsigned int),
                                virDomainDefPtr def)
{
    ssize_t next = -1;
    virBitmapPtr map = NULL;
    virDomainThreadSchedParamPtr sched;
    virProcessSchedPolicy policy;
    int priority;
    int ret = -1;

    if (!(map = virDomainSchedulerParse(node, name, &policy, &priority)))
        goto cleanup;

    while ((next = virBitmapNextSetBit(map, next)) > -1) {
        if (!(sched = func(def, next)))
            goto cleanup;

        if (sched->policy != VIR_PROC_POLICY_NONE) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("%ssched attributes 'vcpus' must not overlap"),
                           name);
            goto cleanup;
        }

        sched->policy = policy;
        sched->priority = priority;
    }

    ret = 0;

 cleanup:
    virBitmapFree(map);
    return ret;
}


static int
virDomainVcpuThreadSchedParse(xmlNodePtr node,
                              virDomainDefPtr def)
{
    return virDomainThreadSchedParseHelper(node, "vcpus",
                                           virDomainDefGetVcpuSched,
                                           def);
}


static virDomainThreadSchedParamPtr
virDomainDefGetIOThreadSched(virDomainDefPtr def,
                             unsigned int iothread)
{
    virDomainIOThreadIDDefPtr iothrinfo;

    if (!(iothrinfo = virDomainIOThreadIDFind(def, iothread))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot find 'iothread' : %u"),
                       iothread);
        return NULL;
    }

    return &iothrinfo->sched;
}


static int
virDomainIOThreadSchedParse(xmlNodePtr node,
                            virDomainDefPtr def)
{
    return virDomainThreadSchedParseHelper(node, "iothreads",
                                           virDomainDefGetIOThreadSched,
                                           def);
}


static int
virDomainVcpuParse(virDomainDefPtr def,
                   xmlXPathContextPtr ctxt,
                   virDomainXMLOptionPtr xmlopt)
{
    int n;
    xmlNodePtr *nodes = NULL;
    size_t i;
    char *tmp = NULL;
    unsigned int maxvcpus;
    unsigned int vcpus;
    int ret = -1;

    if ((n = virXPathUInt("string(./vcpu[1])", ctxt, &maxvcpus)) < 0) {
        if (n == -2) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("maximum vcpus count must be an integer"));
            goto cleanup;
        }

        maxvcpus = 1;
    }

    if (virDomainDefSetVcpusMax(def, maxvcpus, xmlopt) < 0)
        goto cleanup;

    if ((n = virXPathUInt("string(./vcpu[1]/@current)", ctxt, &vcpus)) < 0) {
        if (n == -2) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("current vcpus count must be an integer"));
            goto cleanup;
        }

        vcpus = maxvcpus;
    }


    tmp = virXPathString("string(./vcpu[1]/@placement)", ctxt);
    if (tmp) {
        if ((def->placement_mode =
             virDomainCpuPlacementModeTypeFromString(tmp)) < 0) {
             virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Unsupported CPU placement mode '%s'"),
                            tmp);
             goto cleanup;
        }
        VIR_FREE(tmp);
    } else {
        def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC;
    }

    if (def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        tmp = virXPathString("string(./vcpu[1]/@cpuset)", ctxt);
        if (tmp) {
            if (virBitmapParse(tmp, &def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto cleanup;

            if (virBitmapIsAllClear(def->cpumask)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'cpuset': %s"), tmp);
                goto cleanup;
            }

            VIR_FREE(tmp);
        }
    }

    if ((n = virXPathNodeSet("./vcpus/vcpu", ctxt, &nodes)) < 0)
        goto cleanup;

    if (n) {
        /* if individual vcpu states are provided take them as master */
        def->individualvcpus = true;

        for (i = 0; i < n; i++) {
            virDomainVcpuDefPtr vcpu;
            int state;
            unsigned int id;
            unsigned int order;

            if (!(tmp = virXMLPropString(nodes[i], "id")) ||
                virStrToLong_uip(tmp, NULL, 10, &id) < 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing or invalid vcpu id"));
                goto cleanup;
            }

            VIR_FREE(tmp);

            if (id >= def->maxvcpus) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("vcpu id '%u' is out of range of maximum "
                                 "vcpu count"), id);
                goto cleanup;
            }

            vcpu = virDomainDefGetVcpu(def, id);

            if (!(tmp = virXMLPropString(nodes[i], "enabled"))) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing vcpu enabled state"));
                goto cleanup;
            }

            if ((state = virTristateBoolTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid vcpu 'enabled' value '%s'"), tmp);
                goto cleanup;
            }
            VIR_FREE(tmp);

            vcpu->online = state == VIR_TRISTATE_BOOL_YES;

            if ((tmp = virXMLPropString(nodes[i], "hotpluggable"))) {
                int hotpluggable;
                if ((hotpluggable = virTristateBoolTypeFromString(tmp)) < 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("invalid vcpu 'hotpluggable' value '%s'"), tmp);
                    goto cleanup;
                }
                vcpu->hotpluggable = hotpluggable;
                VIR_FREE(tmp);
            }

            if ((tmp = virXMLPropString(nodes[i], "order"))) {
                if (virStrToLong_uip(tmp, NULL, 10, &order) < 0) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("invalid vcpu order"));
                    goto cleanup;
                }
                vcpu->order = order;
                VIR_FREE(tmp);
            }
        }
    } else {
        if (virDomainDefSetVcpus(def, vcpus) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(tmp);

    return ret;
}


static int
virDomainDefParseBootOptions(virDomainDefPtr def,
                             xmlXPathContextPtr ctxt,
                             virHashTablePtr *bootHash)
{
    xmlNodePtr *nodes = NULL;
    xmlNodePtr oldnode;
    char *tmp = NULL;
    int ret = -1;
    size_t i;
    int n;

    /*
     * Booting options for different OS types....
     *
     *   - A bootloader (and optional kernel+initrd)  (xen)
     *   - A kernel + initrd                          (xen)
     *   - A boot device (and optional kernel+initrd) (hvm)
     *   - An init script                             (exe)
     */

    if (def->os.type == VIR_DOMAIN_OSTYPE_EXE) {
        def->os.init = virXPathString("string(./os/init[1])", ctxt);
        def->os.cmdline = virXPathString("string(./os/cmdline[1])", ctxt);

        if ((n = virXPathNodeSet("./os/initarg", ctxt, &nodes)) < 0)
            goto error;

        if (VIR_ALLOC_N(def->os.initargv, n+1) < 0)
            goto error;
        for (i = 0; i < n; i++) {
            if (!nodes[i]->children ||
                !nodes[i]->children->content) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("No data supplied for <initarg> element"));
                goto error;
            }
            if (VIR_STRDUP(def->os.initargv[i],
                           (const char*) nodes[i]->children->content) < 0)
                goto error;
        }
        def->os.initargv[n] = NULL;
        VIR_FREE(nodes);
    }

    if (def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_HVM ||
        def->os.type == VIR_DOMAIN_OSTYPE_UML) {
        xmlNodePtr loader_node;

        def->os.kernel = virXPathString("string(./os/kernel[1])", ctxt);
        def->os.initrd = virXPathString("string(./os/initrd[1])", ctxt);
        def->os.cmdline = virXPathString("string(./os/cmdline[1])", ctxt);
        def->os.dtb = virXPathString("string(./os/dtb[1])", ctxt);
        def->os.root = virXPathString("string(./os/root[1])", ctxt);
        if ((loader_node = virXPathNode("./os/loader[1]", ctxt))) {
            if (VIR_ALLOC(def->os.loader) < 0)
                goto error;

            if (virDomainLoaderDefParseXML(loader_node, def->os.loader) < 0)
                goto error;

            def->os.loader->nvram = virXPathString("string(./os/nvram[1])", ctxt);
            def->os.loader->templt = virXPathString("string(./os/nvram[1]/@template)", ctxt);
        }
    }

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if ((n = virXPathNodeSet("./os/acpi/table", ctxt, &nodes)) < 0)
            goto error;

        if (n > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Only one acpi table is supported"));
            goto error;
        }

        if (n == 1) {
            oldnode = ctxt->node;
            ctxt->node = nodes[0];
            tmp = virXPathString("string(./@type)", ctxt);

            if (!tmp) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Missing acpi table type"));
                goto error;
            }

            if (STREQ_NULLABLE(tmp, "slic")) {
                VIR_FREE(tmp);
                tmp = virXPathString("string(.)", ctxt);
                def->os.slic_table = virFileSanitizePath(tmp);
                VIR_FREE(tmp);
            } else {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Unknown acpi table type: %s"),
                               tmp);
                goto error;
            }
            ctxt->node = oldnode;
        }

        if (virDomainDefParseBootXML(ctxt, def) < 0)
            goto error;
        if (!(*bootHash = virHashCreate(5, NULL)))
            goto error;
    }

    ret = 0;

 error:
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    return ret;
}


static virDomainDefPtr
virDomainDefParseXML(xmlDocPtr xml,
                     xmlNodePtr root,
                     xmlXPathContextPtr ctxt,
                     virCapsPtr caps,
                     virDomainXMLOptionPtr xmlopt,
                     void *parseOpaque,
                     unsigned int flags)
{
    xmlNodePtr *nodes = NULL, node = NULL;
    char *tmp = NULL;
    size_t i, j;
    int n, virtType, gic_version;
    long id = -1;
    virDomainDefPtr def;
    bool uuid_generated = false;
    virHashTablePtr bootHash = NULL;
    bool usb_none = false;
    bool usb_other = false;
    bool usb_master = false;
    char *netprefix = NULL;

    if (flags & VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA) {
        char *schema = virFileFindResource("domain.rng",
                                           abs_topsrcdir "/docs/schemas",
                                           PKGDATADIR "/schemas");
        if (!schema)
            return NULL;
        if (virXMLValidateAgainstSchema(schema, xml) < 0) {
            VIR_FREE(schema);
            return NULL;
        }
        VIR_FREE(schema);
    }

    if (!(def = virDomainDefNew()))
        return NULL;

    if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
        if (virXPathLong("string(./@id)", ctxt, &id) < 0)
            id = -1;
    def->id = (int)id;

    /* Find out what type of virtualization to use */
    if (!(tmp = virXPathString("string(./@type)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing domain type attribute"));
        goto error;
    }

    if ((virtType = virDomainVirtTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid domain type %s"), tmp);
        goto error;
    }
    def->virtType = virtType;
    VIR_FREE(tmp);

    def->os.bootloader = virXPathString("string(./bootloader)", ctxt);
    def->os.bootloaderArgs = virXPathString("string(./bootloader_args)", ctxt);

    tmp = virXPathString("string(./os/type[1])", ctxt);
    if (!tmp) {
        if (def->os.bootloader) {
            def->os.type = VIR_DOMAIN_OSTYPE_XEN;
        } else {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("an os <type> must be specified"));
            goto error;
        }
    } else {
        if ((def->os.type = virDomainOSTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown OS type '%s'"), tmp);
            goto error;
        }
        VIR_FREE(tmp);
    }

    /*
     * HACK: For xen driver we previously used bogus 'linux' as the
     * os type for paravirt, whereas capabilities declare it to
     * be 'xen'. So we accept the former and convert
     */
    if (def->os.type == VIR_DOMAIN_OSTYPE_LINUX &&
        def->virtType == VIR_DOMAIN_VIRT_XEN) {
        def->os.type = VIR_DOMAIN_OSTYPE_XEN;
    }

    tmp = virXPathString("string(./os/type[1]/@arch)", ctxt);
    if (tmp && !(def->os.arch = virArchFromString(tmp))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown architecture %s"),
                       tmp);
        goto error;
    }
    VIR_FREE(tmp);

    def->os.machine = virXPathString("string(./os/type[1]/@machine)", ctxt);
    def->emulator = virXPathString("string(./devices/emulator[1])", ctxt);

    if (!(flags & VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS)) {
        /* If the logic here seems fairly arbitrary, that's because it is :)
         * This is duplicating how the code worked before
         * CapabilitiesDomainDataLookup was added. We can simplify this,
         * but it would take a bit of work because the test suite fails
         * in numerous minor ways. */
        bool use_virttype = ((def->os.arch == VIR_ARCH_NONE) ||
            !def->os.machine);
        virCapsDomainDataPtr capsdata = NULL;

        if (!(capsdata = virCapabilitiesDomainDataLookup(caps, def->os.type,
                def->os.arch, use_virttype ? def->virtType : VIR_DOMAIN_VIRT_NONE,
                NULL, NULL)))
            goto error;

        if (!def->os.arch)
            def->os.arch = capsdata->arch;
        if ((!def->os.machine &&
             VIR_STRDUP(def->os.machine, capsdata->machinetype) < 0)) {
            VIR_FREE(capsdata);
            goto error;
        }
        VIR_FREE(capsdata);
    }

    /* Extract domain name */
    if (!(def->name = virXPathString("string(./name[1])", ctxt))) {
        virReportError(VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract domain uuid. If both uuid and sysinfo/system/entry/uuid
     * exist, they must match; and if only the latter exists, it can
     * also serve as the uuid. */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        if (virUUIDGenerate(def->uuid)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            goto error;
        }
        uuid_generated = true;
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
    }

    /* Extract short description of domain (title) */
    def->title = virXPathString("string(./title[1])", ctxt);
    if (def->title && strchr(def->title, '\n')) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Domain title can't contain newlines"));
        goto error;
    }

    /* Extract documentation if present */
    def->description = virXPathString("string(./description[1])", ctxt);

    /* analysis of security label, done early even though we format it
     * late, so devices can refer to this for defaults */
    if (!(flags & VIR_DOMAIN_DEF_PARSE_SKIP_SECLABEL)) {
        if (virSecurityLabelDefsParseXML(def, ctxt, caps, flags) == -1)
            goto error;
    }

    /* Extract domain memory */
    if (virDomainParseMemory("./memory[1]", NULL, ctxt,
                             &def->mem.total_memory, false, true) < 0)
        goto error;

    if (virDomainParseMemory("./currentMemory[1]", NULL, ctxt,
                             &def->mem.cur_balloon, false, true) < 0)
        goto error;

    if (virDomainParseMemory("./maxMemory[1]", NULL, ctxt,
                             &def->mem.max_memory, false, false) < 0)
        goto error;

    if (virXPathUInt("string(./maxMemory[1]/@slots)", ctxt, &def->mem.memory_slots) == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Failed to parse memory slot count"));
        goto error;
    }

    /* and info about it */
    if ((tmp = virXPathString("string(./memory[1]/@dumpCore)", ctxt)) &&
        (def->mem.dump_core = virTristateSwitchTypeFromString(tmp)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid memory core dump attribute value '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    tmp = virXPathString("string(./memoryBacking/source/@type)", ctxt);
    if (tmp) {
        if ((def->mem.source = virDomainMemorySourceTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/source/type '%s'"), tmp);
            goto error;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./memoryBacking/access/@mode)", ctxt);
    if (tmp) {
        if ((def->mem.access = virDomainMemoryAccessTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/access/mode '%s'"), tmp);
            goto error;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./memoryBacking/allocation/@mode)", ctxt);
    if (tmp) {
        if ((def->mem.allocation = virDomainMemoryAllocationTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/allocation/mode '%s'"), tmp);
            goto error;
        }
        VIR_FREE(tmp);
    }

    if (virXPathNode("./memoryBacking/hugepages", ctxt)) {
        /* hugepages will be used */

        if (def->mem.allocation == VIR_DOMAIN_MEMORY_ALLOCATION_ONDEMAND) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("hugepages are not allowed with memory allocation ondemand"));
            goto error;
        }

        if (def->mem.source == VIR_DOMAIN_MEMORY_SOURCE_ANONYMOUS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("hugepages are not allowed with anonymous memory source"));
            goto error;
        }

        if ((n = virXPathNodeSet("./memoryBacking/hugepages/page", ctxt, &nodes)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot extract hugepages nodes"));
            goto error;
        }

        if (n) {
            if (VIR_ALLOC_N(def->mem.hugepages, n) < 0)
                goto error;

            for (i = 0; i < n; i++) {
                if (virDomainHugepagesParseXML(nodes[i], ctxt,
                                               &def->mem.hugepages[i]) < 0)
                    goto error;
                def->mem.nhugepages++;

                for (j = 0; j < i; j++) {
                    if (def->mem.hugepages[i].nodemask &&
                        def->mem.hugepages[j].nodemask &&
                        virBitmapOverlaps(def->mem.hugepages[i].nodemask,
                                          def->mem.hugepages[j].nodemask)) {
                        virReportError(VIR_ERR_XML_DETAIL,
                                       _("nodeset attribute of hugepages "
                                         "of sizes %llu and %llu intersect"),
                                       def->mem.hugepages[i].size,
                                       def->mem.hugepages[j].size);
                        goto error;
                    } else if (!def->mem.hugepages[i].nodemask &&
                               !def->mem.hugepages[j].nodemask) {
                        virReportError(VIR_ERR_XML_DETAIL,
                                       _("two master hugepages detected: "
                                         "%llu and %llu"),
                                       def->mem.hugepages[i].size,
                                       def->mem.hugepages[j].size);
                        goto error;
                    }
                }
            }

            VIR_FREE(nodes);
        } else {
            /* no hugepage pages */
            if (VIR_ALLOC(def->mem.hugepages) < 0)
                goto error;

            def->mem.nhugepages = 1;
        }
    }

    if ((node = virXPathNode("./memoryBacking/nosharepages", ctxt)))
        def->mem.nosharepages = true;

    if (virXPathBoolean("boolean(./memoryBacking/locked)", ctxt))
        def->mem.locked = true;

    /* Extract blkio cgroup tunables */
    if (virXPathUInt("string(./blkiotune/weight)", ctxt,
                     &def->blkio.weight) < 0)
        def->blkio.weight = 0;

    if ((n = virXPathNodeSet("./blkiotune/device", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract blkiotune nodes"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->blkio.devices, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        if (virDomainBlkioDeviceParseXML(nodes[i],
                                         &def->blkio.devices[i]) < 0)
            goto error;
        def->blkio.ndevices++;
        for (j = 0; j < i; j++) {
            if (STREQ(def->blkio.devices[j].path,
                      def->blkio.devices[i].path)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("duplicate blkio device path '%s'"),
                               def->blkio.devices[i].path);
                goto error;
            }
        }
    }
    VIR_FREE(nodes);

    /* Extract other memory tunables */
    if (virDomainParseMemoryLimit("./memtune/hard_limit[1]", NULL, ctxt,
                                  &def->mem.hard_limit) < 0)
        goto error;

    if (virDomainParseMemoryLimit("./memtune/soft_limit[1]", NULL, ctxt,
                                  &def->mem.soft_limit) < 0)
        goto error;

    if (virDomainParseMemory("./memtune/min_guarantee[1]", NULL, ctxt,
                             &def->mem.min_guarantee, false, false) < 0)
        goto error;

    if (virDomainParseMemoryLimit("./memtune/swap_hard_limit[1]", NULL, ctxt,
                                  &def->mem.swap_hard_limit) < 0)
        goto error;

    if (virDomainVcpuParse(def, ctxt, xmlopt) < 0)
        goto error;

    if (virDomainDefParseIOThreads(def, ctxt) < 0)
        goto error;

    /* Extract cpu tunables. */
    if ((n = virXPathULongLong("string(./cputune/shares[1])", ctxt,
                               &def->cputune.shares)) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune shares value"));
        goto error;
    } else if (n == 0) {
        def->cputune.sharesSpecified = true;
    }

    if (virXPathULongLong("string(./cputune/period[1])", ctxt,
                          &def->cputune.period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune period value"));
        goto error;
    }

    if (def->cputune.period > 0 &&
        (def->cputune.period < 1000 || def->cputune.period > 1000000)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune period must be in range "
                         "[1000, 1000000]"));
        goto error;
    }

    if (virXPathLongLong("string(./cputune/quota[1])", ctxt,
                         &def->cputune.quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune quota value"));
        goto error;
    }

    if (def->cputune.quota > 0 &&
        (def->cputune.quota < 1000 ||
         def->cputune.quota > 18446744073709551LL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune quota must be in range "
                         "[1000, 18446744073709551]"));
        goto error;
    }

    if (virXPathULongLong("string(./cputune/global_period[1])", ctxt,
                          &def->cputune.global_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune global period value"));
        goto error;
    }

    if (def->cputune.global_period > 0 &&
        (def->cputune.global_period < 1000 || def->cputune.global_period > 1000000)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune global period must be in range "
                         "[1000, 1000000]"));
        goto error;
    }

    if (virXPathLongLong("string(./cputune/global_quota[1])", ctxt,
                         &def->cputune.global_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune global quota value"));
        goto error;
    }

    if (def->cputune.global_quota > 0 &&
        (def->cputune.global_quota < 1000 ||
         def->cputune.global_quota > 18446744073709551LL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune global quota must be in range "
                         "[1000, 18446744073709551]"));
        goto error;
    }

    if (virXPathULongLong("string(./cputune/emulator_period[1])", ctxt,
                          &def->cputune.emulator_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune emulator period value"));
        goto error;
    }

    if (def->cputune.emulator_period > 0 &&
        (def->cputune.emulator_period < 1000 ||
         def->cputune.emulator_period > 1000000)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune emulator_period must be in range "
                         "[1000, 1000000]"));
        goto error;
    }

    if (virXPathLongLong("string(./cputune/emulator_quota[1])", ctxt,
                         &def->cputune.emulator_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune emulator quota value"));
        goto error;
    }

    if (def->cputune.emulator_quota > 0 &&
        (def->cputune.emulator_quota < 1000 ||
         def->cputune.emulator_quota > 18446744073709551LL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune emulator_quota must be in range "
                         "[1000, 18446744073709551]"));
        goto error;
    }

    if (virXPathULongLong("string(./cputune/iothread_period[1])", ctxt,
                          &def->cputune.iothread_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune iothread period value"));
        goto error;
    }

    if (def->cputune.iothread_period > 0 &&
        (def->cputune.iothread_period < 1000 ||
         def->cputune.iothread_period > 1000000)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune iothread_period must be in range "
                         "[1000, 1000000]"));
        goto error;
    }

    if (virXPathLongLong("string(./cputune/iothread_quota[1])", ctxt,
                         &def->cputune.iothread_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune iothread quota value"));
        goto error;
    }

    if (def->cputune.iothread_quota > 0 &&
        (def->cputune.iothread_quota < 1000 ||
         def->cputune.iothread_quota > 18446744073709551LL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Value of cputune iothread_quota must be in range "
                         "[1000, 18446744073709551]"));
        goto error;
    }

    if ((n = virXPathNodeSet("./cputune/vcpupin", ctxt, &nodes)) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        if (virDomainVcpuPinDefParseXML(def, nodes[i]))
            goto error;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/emulatorpin", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract emulatorpin nodes"));
        goto error;
    }

    if (n) {
        if (n > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("only one emulatorpin is supported"));
            VIR_FREE(nodes);
            goto error;
        }

        if (!(def->cputune.emulatorpin = virDomainEmulatorPinDefParseXML(nodes[0])))
            goto error;
    }
    VIR_FREE(nodes);


    if ((n = virXPathNodeSet("./cputune/iothreadpin", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract iothreadpin nodes"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        if (virDomainIOThreadPinDefParseXML(nodes[i], ctxt, def) < 0)
            goto error;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/vcpusched", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract vcpusched nodes"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        if (virDomainVcpuThreadSchedParse(nodes[i], def) < 0)
            goto error;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/iothreadsched", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract iothreadsched nodes"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        if (virDomainIOThreadSchedParse(nodes[i], def) < 0)
            goto error;
    }
    VIR_FREE(nodes);

    if (virCPUDefParseXML(ctxt, "./cpu[1]", VIR_CPU_TYPE_GUEST, &def->cpu) < 0)
        goto error;

    if (virDomainNumaDefCPUParseXML(def->numa, ctxt) < 0)
        goto error;

    if (virDomainNumaGetCPUCountTotal(def->numa) > virDomainDefGetVcpusMax(def)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Number of CPUs in <numa> exceeds the"
                         " <vcpu> count"));
        goto error;
    }

    if (virDomainNumaGetMaxCPUID(def->numa) >= virDomainDefGetVcpusMax(def)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("CPU IDs in <numa> exceed the <vcpu> count"));
        goto error;
    }

    if (virDomainNumatuneParseXML(def->numa,
                                  def->placement_mode ==
                                  VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                  ctxt) < 0)
        goto error;

    if (virDomainNumatuneHasPlacementAuto(def->numa) &&
        !def->cpumask && !virDomainDefHasVcpuPin(def) &&
        !def->cputune.emulatorpin &&
        !virDomainIOThreadIDArrayHasPin(def))
        def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO;

    if ((n = virXPathNodeSet("./resource", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract resource nodes"));
        goto error;
    }

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one resource element is supported"));
        goto error;
    }

    if (n &&
        !(def->resource = virDomainResourceDefParse(nodes[0], ctxt)))
        goto error;
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./features/*", ctxt, &nodes)) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        int val = virDomainFeatureTypeFromString((const char *)nodes[i]->name);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unexpected feature '%s'"), nodes[i]->name);
            goto error;
        }

        switch ((virDomainFeature) val) {
        case VIR_DOMAIN_FEATURE_APIC:
            if ((tmp = virXPathString("string(./features/apic/@eoi)", ctxt))) {
                int eoi;
                if ((eoi = virTristateSwitchTypeFromString(tmp)) <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown value for attribute eoi: '%s'"),
                                   tmp);
                    goto error;
                }
                def->apic_eoi = eoi;
                VIR_FREE(tmp);
            }
            /* fallthrough */
        case VIR_DOMAIN_FEATURE_ACPI:
        case VIR_DOMAIN_FEATURE_PAE:
        case VIR_DOMAIN_FEATURE_VIRIDIAN:
        case VIR_DOMAIN_FEATURE_PRIVNET:
        case VIR_DOMAIN_FEATURE_HYPERV:
        case VIR_DOMAIN_FEATURE_KVM:
            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            break;

        case VIR_DOMAIN_FEATURE_CAPABILITIES:
            node = ctxt->node;
            ctxt->node = nodes[i];
            if ((tmp = virXPathString("string(./@policy)", ctxt))) {
                if ((def->features[val] = virDomainCapabilitiesPolicyTypeFromString(tmp)) == -1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown state attribute '%s' of feature '%s'"),
                                   tmp, virDomainFeatureTypeToString(val));
                    goto error;
                }
                VIR_FREE(tmp);
            } else {
                def->features[val] = VIR_TRISTATE_SWITCH_ABSENT;
            }
            ctxt->node = node;
            break;

        case VIR_DOMAIN_FEATURE_HAP:
        case VIR_DOMAIN_FEATURE_PMU:
        case VIR_DOMAIN_FEATURE_PVSPINLOCK:
        case VIR_DOMAIN_FEATURE_VMPORT:
        case VIR_DOMAIN_FEATURE_SMM:
            node = ctxt->node;
            ctxt->node = nodes[i];
            if ((tmp = virXPathString("string(./@state)", ctxt))) {
                if ((def->features[val] = virTristateSwitchTypeFromString(tmp)) == -1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown state attribute '%s' of feature '%s'"),
                                   tmp, virDomainFeatureTypeToString(val));
                    goto error;
                }
                VIR_FREE(tmp);
            } else {
                def->features[val] = VIR_TRISTATE_SWITCH_ON;
            }
            ctxt->node = node;
            break;

        case VIR_DOMAIN_FEATURE_GIC:
            node = ctxt->node;
            ctxt->node = nodes[i];
            if ((tmp = virXPathString("string(./@version)", ctxt))) {
                gic_version = virGICVersionTypeFromString(tmp);
                if (gic_version < 0 || gic_version == VIR_GIC_VERSION_NONE) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("malformed gic version: %s"), tmp);
                    goto error;
                }
                def->gic_version = gic_version;
                VIR_FREE(tmp);
            }
            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            ctxt->node = node;
            break;

        case VIR_DOMAIN_FEATURE_IOAPIC:
            node = ctxt->node;
            ctxt->node = nodes[i];
            tmp = virXPathString("string(./@driver)", ctxt);
            if (tmp) {
                int value = virDomainIOAPICTypeFromString(tmp);
                if (value < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("Unknown driver mode: %s"),
                                   tmp);
                    goto error;
                }
                def->ioapic = value;
                def->features[val] = VIR_TRISTATE_SWITCH_ON;
            }
            ctxt->node = node;
            break;

        /* coverity[dead_error_begin] */
        case VIR_DOMAIN_FEATURE_LAST:
            break;
        }
    }
    VIR_FREE(nodes);

    if (def->features[VIR_DOMAIN_FEATURE_HYPERV] == VIR_TRISTATE_SWITCH_ON) {
        int feature;
        int value;
        node = ctxt->node;
        if ((n = virXPathNodeSet("./features/hyperv/*", ctxt, &nodes)) < 0)
            goto error;

        for (i = 0; i < n; i++) {
            feature = virDomainHypervTypeFromString((const char *)nodes[i]->name);
            if (feature < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported HyperV Enlightenment feature: %s"),
                               nodes[i]->name);
                goto error;
            }

            ctxt->node = nodes[i];

            if (!(tmp = virXPathString("string(./@state)", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("missing 'state' attribute for "
                                 "HyperV Enlightenment feature '%s'"),
                               nodes[i]->name);
                goto error;
            }

            if ((value = virTristateSwitchTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value of state argument "
                                 "for HyperV Enlightenment feature '%s'"),
                               nodes[i]->name);
                goto error;
            }

            VIR_FREE(tmp);
            def->hyperv_features[feature] = value;

            switch ((virDomainHyperv) feature) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
            case VIR_DOMAIN_HYPERV_VPINDEX:
            case VIR_DOMAIN_HYPERV_RUNTIME:
            case VIR_DOMAIN_HYPERV_SYNIC:
            case VIR_DOMAIN_HYPERV_STIMER:
            case VIR_DOMAIN_HYPERV_RESET:
                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                if (value != VIR_TRISTATE_SWITCH_ON)
                    break;

                if (virXPathUInt("string(./@retries)", ctxt,
                             &def->hyperv_spinlocks) < 0) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("invalid HyperV spinlock retry count"));
                    goto error;
                }

                if (def->hyperv_spinlocks < 0xFFF) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("HyperV spinlock retry count must be "
                                     "at least 4095"));
                    goto error;
                }
                break;

            case VIR_DOMAIN_HYPERV_VENDOR_ID:
                if (value != VIR_TRISTATE_SWITCH_ON)
                    break;

                if (!(def->hyperv_vendor_id = virXPathString("string(./@value)",
                                                             ctxt))) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("missing 'value' attribute for "
                                     "HyperV feature 'vendor_id'"));
                    goto error;
                }

                if (strlen(def->hyperv_vendor_id) > VIR_DOMAIN_HYPERV_VENDOR_ID_MAX) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("HyperV vendor_id value must not be more "
                                     "than %d characters."),
                                   VIR_DOMAIN_HYPERV_VENDOR_ID_MAX);
                    goto error;
                }

                /* ensure that the string can be passed to qemu */
                if (strchr(def->hyperv_vendor_id, ',')) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("HyperV vendor_id value is invalid"));
                    goto error;
                }

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
        VIR_FREE(nodes);
        ctxt->node = node;
    }

    if (def->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON) {
        int feature;
        int value;
        node = ctxt->node;
        if ((n = virXPathNodeSet("./features/kvm/*", ctxt, &nodes)) < 0)
            goto error;

        for (i = 0; i < n; i++) {
            feature = virDomainKVMTypeFromString((const char *)nodes[i]->name);
            if (feature < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported KVM feature: %s"),
                               nodes[i]->name);
                goto error;
            }

            ctxt->node = nodes[i];

            switch ((virDomainKVM) feature) {
                case VIR_DOMAIN_KVM_HIDDEN:
                    if (!(tmp = virXPathString("string(./@state)", ctxt))) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("missing 'state' attribute for "
                                         "KVM feature '%s'"),
                                       nodes[i]->name);
                        goto error;
                    }

                    if ((value = virTristateSwitchTypeFromString(tmp)) < 0) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       _("invalid value of state argument "
                                         "for KVM feature '%s'"),
                                       nodes[i]->name);
                        goto error;
                    }

                    VIR_FREE(tmp);
                    def->kvm_features[feature] = value;
                    break;

                /* coverity[dead_error_begin] */
                case VIR_DOMAIN_KVM_LAST:
                    break;
            }
        }
        VIR_FREE(nodes);
        ctxt->node = node;
    }

    if ((n = virXPathNodeSet("./features/capabilities/*", ctxt, &nodes)) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        int val = virDomainCapsFeatureTypeFromString((const char *)nodes[i]->name);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unexpected capability feature '%s'"), nodes[i]->name);
            goto error;
        }

        if (val >= 0 && val < VIR_DOMAIN_CAPS_FEATURE_LAST) {
            node = ctxt->node;
            ctxt->node = nodes[i];

            if ((tmp = virXPathString("string(./@state)", ctxt))) {
                if ((def->caps_features[val] = virTristateSwitchTypeFromString(tmp)) == -1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unknown state attribute '%s' of feature capability '%s'"),
                                   tmp, virDomainFeatureTypeToString(val));
                    goto error;
                }
                VIR_FREE(tmp);
            } else {
                def->caps_features[val] = VIR_TRISTATE_SWITCH_ON;
            }
            ctxt->node = node;
        }
    }
    VIR_FREE(nodes);

    if (virDomainEventActionParseXML(ctxt, "on_reboot",
                                     "string(./on_reboot[1])",
                                     &def->onReboot,
                                     VIR_DOMAIN_LIFECYCLE_RESTART,
                                     virDomainLifecycleTypeFromString) < 0)
        goto error;

    if (virDomainEventActionParseXML(ctxt, "on_poweroff",
                                     "string(./on_poweroff[1])",
                                     &def->onPoweroff,
                                     VIR_DOMAIN_LIFECYCLE_DESTROY,
                                     virDomainLifecycleTypeFromString) < 0)
        goto error;

    if (virDomainEventActionParseXML(ctxt, "on_crash",
                                     "string(./on_crash[1])",
                                     &def->onCrash,
                                     VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY,
                                     virDomainLifecycleCrashTypeFromString) < 0)
        goto error;

    if (virDomainEventActionParseXML(ctxt, "on_lockfailure",
                                     "string(./on_lockfailure[1])",
                                     &def->onLockFailure,
                                     VIR_DOMAIN_LOCK_FAILURE_DEFAULT,
                                     virDomainLockFailureTypeFromString) < 0)
        goto error;

    if (virDomainPMStateParseXML(ctxt,
                                 "string(./pm/suspend-to-mem/@enabled)",
                                 &def->pm.s3) < 0)
        goto error;

    if (virDomainPMStateParseXML(ctxt,
                                 "string(./pm/suspend-to-disk/@enabled)",
                                 &def->pm.s4) < 0)
        goto error;

    if (virDomainPerfDefParseXML(def, ctxt) < 0)
        goto error;

    if ((tmp = virXPathString("string(./clock/@offset)", ctxt)) &&
        (def->clock.offset = virDomainClockOffsetTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown clock offset '%s'"), tmp);
        goto error;
    }
    VIR_FREE(tmp);

    switch (def->clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        tmp = virXPathString("string(./clock/@adjustment)", ctxt);
        if (tmp) {
            if (STREQ(tmp, "reset")) {
                def->clock.data.utc_reset = true;
            } else {
                if (virStrToLong_ll(tmp, NULL, 10,
                                    &def->clock.data.variable.adjustment) < 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("unknown clock adjustment '%s'"),
                                   tmp);
                    goto error;
                }
                switch (def->clock.offset) {
                case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
                    def->clock.data.variable.basis = VIR_DOMAIN_CLOCK_BASIS_LOCALTIME;
                    break;
                case VIR_DOMAIN_CLOCK_OFFSET_UTC:
                    def->clock.data.variable.basis = VIR_DOMAIN_CLOCK_BASIS_UTC;
                    break;
                }
                def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_VARIABLE;
            }
            VIR_FREE(tmp);
        } else {
            def->clock.data.utc_reset = false;
        }
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
        if (virXPathLongLong("number(./clock/@adjustment)", ctxt,
                             &def->clock.data.variable.adjustment) < 0)
            def->clock.data.variable.adjustment = 0;
        if (virXPathLongLong("number(./clock/@adjustment0)", ctxt,
                             &def->clock.data.variable.adjustment0) < 0)
            def->clock.data.variable.adjustment0 = 0;
        tmp = virXPathString("string(./clock/@basis)", ctxt);
        if (tmp) {
            if ((def->clock.data.variable.basis = virDomainClockBasisTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown clock basis '%s'"), tmp);
                goto error;
            }
            VIR_FREE(tmp);
        } else {
            def->clock.data.variable.basis = VIR_DOMAIN_CLOCK_BASIS_UTC;
        }
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        def->clock.data.timezone = virXPathString("string(./clock/@timezone)", ctxt);
        if (!def->clock.data.timezone) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing 'timezone' attribute for clock with offset='timezone'"));
            goto error;
        }
        break;
    }

    if ((n = virXPathNodeSet("./clock/timer", ctxt, &nodes)) < 0)
        goto error;

    if (n && VIR_ALLOC_N(def->clock.timers, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainTimerDefPtr timer = virDomainTimerDefParseXML(nodes[i],
                                                               ctxt);
        if (!timer)
            goto error;

        def->clock.timers[def->clock.ntimers++] = timer;
    }
    VIR_FREE(nodes);

    if (virDomainDefParseBootOptions(def, ctxt, &bootHash) < 0)
        goto error;

    /* analysis of the disk devices */
    if ((n = virXPathNodeSet("./devices/disk", ctxt, &nodes)) < 0)
        goto error;

    if (n && VIR_ALLOC_N(def->disks, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainDiskDefPtr disk = virDomainDiskDefParseXML(xmlopt,
                                                            nodes[i],
                                                            ctxt,
                                                            bootHash,
                                                            def->seclabels,
                                                            def->nseclabels,
                                                            flags);
        if (!disk)
            goto error;

        virDomainDiskInsertPreAlloced(def, disk);
    }
    VIR_FREE(nodes);

    /* analysis of the controller devices */
    if ((n = virXPathNodeSet("./devices/controller", ctxt, &nodes)) < 0)
        goto error;

    if (n && VIR_ALLOC_N(def->controllers, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainControllerDefPtr controller = virDomainControllerDefParseXML(nodes[i],
                                                                              ctxt,
                                                                              flags);

        if (!controller)
            goto error;

        /* sanitize handling of "none" usb controller */
        if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
                if (usb_other || usb_none) {
                    virDomainControllerDefFree(controller);
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Can't add another USB controller: "
                                     "USB is disabled for this domain"));
                    goto error;
                }
                usb_none = true;
            } else {
                if (usb_none) {
                    virDomainControllerDefFree(controller);
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Can't add another USB controller: "
                                     "USB is disabled for this domain"));
                    goto error;
                }
                usb_other = true;
            }

            if (controller->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_NONE)
                usb_master = true;
        }

        virDomainControllerInsertPreAlloced(def, controller);
    }
    VIR_FREE(nodes);

    if (usb_other && !usb_master) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("No master USB controller specified"));
        goto error;
    }

    /* analysis of the resource leases */
    if ((n = virXPathNodeSet("./devices/lease", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract device leases"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->leases, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainLeaseDefPtr lease = virDomainLeaseDefParseXML(nodes[i]);
        if (!lease)
            goto error;

        def->leases[def->nleases++] = lease;
    }
    VIR_FREE(nodes);

    /* analysis of the filesystems */
    if ((n = virXPathNodeSet("./devices/filesystem", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->fss, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainFSDefPtr fs = virDomainFSDefParseXML(nodes[i], ctxt,
                                                      flags);
        if (!fs)
            goto error;

        def->fss[def->nfss++] = fs;
    }
    VIR_FREE(nodes);

    /* analysis of the network devices */
    if ((n = virXPathNodeSet("./devices/interface", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->nets, n) < 0)
        goto error;
    netprefix = caps->host.netprefix;
    for (i = 0; i < n; i++) {
        virDomainNetDefPtr net = virDomainNetDefParseXML(xmlopt,
                                                         nodes[i],
                                                         ctxt,
                                                         bootHash,
                                                         netprefix,
                                                         flags);
        if (!net)
            goto error;

        def->nets[def->nnets++] = net;

        /* <interface type='hostdev'> (and <interface type='net'>
         * where the actual network type is already known to be
         * hostdev) must also be in the hostdevs array.
         */
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            virDomainHostdevInsert(def, virDomainNetGetActualHostdev(net)) < 0) {
            goto error;
        }
    }
    VIR_FREE(nodes);


    /* analysis of the smartcard devices */
    if ((n = virXPathNodeSet("./devices/smartcard", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->smartcards, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainSmartcardDefPtr card = virDomainSmartcardDefParseXML(xmlopt,
                                                                      nodes[i],
                                                                      flags);
        if (!card)
            goto error;

        def->smartcards[def->nsmartcards++] = card;
    }
    VIR_FREE(nodes);


    /* analysis of the character devices */
    if ((n = virXPathNodeSet("./devices/parallel", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->parallels, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(xmlopt,
                                                         ctxt,
                                                         nodes[i],
                                                         def->seclabels,
                                                         def->nseclabels,
                                                         flags);
        if (!chr)
            goto error;

        if (chr->target.port == -1) {
            int maxport = -1;
            for (j = 0; j < i; j++) {
                if (def->parallels[j]->target.port > maxport)
                    maxport = def->parallels[j]->target.port;
            }
            chr->target.port = maxport + 1;
        }
        def->parallels[def->nparallels++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/serial", ctxt, &nodes)) < 0)
        goto error;

    if (n && VIR_ALLOC_N(def->serials, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(xmlopt,
                                                         ctxt,
                                                         nodes[i],
                                                         def->seclabels,
                                                         def->nseclabels,
                                                         flags);
        if (!chr)
            goto error;

        if (chr->target.port == -1) {
            int maxport = -1;
            for (j = 0; j < i; j++) {
                if (def->serials[j]->target.port > maxport)
                    maxport = def->serials[j]->target.port;
            }
            chr->target.port = maxport + 1;
        }
        def->serials[def->nserials++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/console", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract console devices"));
        goto error;
    }
    if (n && VIR_ALLOC_N(def->consoles, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(xmlopt,
                                                         ctxt,
                                                         nodes[i],
                                                         def->seclabels,
                                                         def->nseclabels,
                                                         flags);
        if (!chr)
            goto error;

        chr->target.port = i;
        def->consoles[def->nconsoles++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/channel", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->channels, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainChrDefPtr chr = virDomainChrDefParseXML(xmlopt,
                                                         ctxt,
                                                         nodes[i],
                                                         def->seclabels,
                                                         def->nseclabels,
                                                         flags);
        if (!chr)
            goto error;

        def->channels[def->nchannels++] = chr;
    }
    VIR_FREE(nodes);


    /* analysis of the input devices */
    if ((n = virXPathNodeSet("./devices/input", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->inputs, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainInputDefPtr input = virDomainInputDefParseXML(def,
                                                               nodes[i],
                                                               ctxt,
                                                               flags);
        if (!input)
            goto error;

        /* Check if USB bus is required */
        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB && usb_none) {
            virDomainInputDefFree(input);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add USB input device. "
                             "USB bus is disabled"));
            goto error;
        }

        def->inputs[def->ninputs++] = input;
    }
    VIR_FREE(nodes);

    /* analysis of the graphics devices */
    if ((n = virXPathNodeSet("./devices/graphics", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->graphics, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainGraphicsDefPtr graphics = virDomainGraphicsDefParseXML(nodes[i],
                                                                        ctxt,
                                                                        flags);
        if (!graphics)
            goto error;

        def->graphics[def->ngraphics++] = graphics;
    }
    VIR_FREE(nodes);

    /* analysis of the sound devices */
    if ((n = virXPathNodeSet("./devices/sound", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->sounds, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainSoundDefPtr sound = virDomainSoundDefParseXML(nodes[i],
                                                               ctxt,
                                                               flags);
        if (!sound)
            goto error;

        def->sounds[def->nsounds++] = sound;
    }
    VIR_FREE(nodes);

    /* analysis of the video devices */
    if ((n = virXPathNodeSet("./devices/video", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->videos, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainVideoDefPtr video;
        ssize_t insertAt = -1;

        if (!(video = virDomainVideoDefParseXML(nodes[i], ctxt, def, flags)))
            goto error;

        if (video->primary) {
            if (def->nvideos != 0 && def->videos[0]->primary) {
                virDomainVideoDefFree(video);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only one primary video device is supported"));
                goto error;
            }

            insertAt = 0;
        }
        if (VIR_INSERT_ELEMENT_INPLACE(def->videos,
                                       insertAt,
                                       def->nvideos,
                                       video) < 0) {
            virDomainVideoDefFree(video);
            goto error;
        }
    }

    VIR_FREE(nodes);

    /* analysis of the host devices */
    if ((n = virXPathNodeSet("./devices/hostdev", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_REALLOC_N(def->hostdevs, def->nhostdevs + n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainHostdevDefPtr hostdev;

        hostdev = virDomainHostdevDefParseXML(xmlopt, nodes[i], ctxt,
                                              bootHash, flags);
        if (!hostdev)
            goto error;

        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
            usb_none) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add host USB device: "
                             "USB is disabled in this host"));
            virDomainHostdevDefFree(hostdev);
            goto error;
        }

        def->hostdevs[def->nhostdevs++] = hostdev;

        /* For a domain definition, we need to check if the controller
         * for this hostdev exists yet and if not add it. This cannot be
         * done during virDomainHostdevAssignAddress (as part of device
         * post processing) because that will result in the failure to
         * load the controller during hostdev hotplug.
         */
        if (virDomainDefMaybeAddHostdevSCSIcontroller(def) < 0)
            goto error;
    }
    VIR_FREE(nodes);

    /* analysis of the watchdog devices */
    def->watchdog = NULL;
    if ((n = virXPathNodeSet("./devices/watchdog", ctxt, &nodes)) < 0)
        goto error;
    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only a single watchdog device is supported"));
        goto error;
    }
    if (n > 0) {
        virDomainWatchdogDefPtr watchdog =
            virDomainWatchdogDefParseXML(nodes[0], flags);
        if (!watchdog)
            goto error;

        def->watchdog = watchdog;
        VIR_FREE(nodes);
    }

    /* analysis of the memballoon devices */
    def->memballoon = NULL;
    if ((n = virXPathNodeSet("./devices/memballoon", ctxt, &nodes)) < 0)
        goto error;
    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only a single memory balloon device is supported"));
        goto error;
    }
    if (n > 0) {
        virDomainMemballoonDefPtr memballoon =
            virDomainMemballoonDefParseXML(nodes[0], ctxt, flags);
        if (!memballoon)
            goto error;

        def->memballoon = memballoon;
        VIR_FREE(nodes);
    }

    /* Parse the RNG devices */
    if ((n = virXPathNodeSet("./devices/rng", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->rngs, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainRNGDefPtr rng = virDomainRNGDefParseXML(xmlopt, nodes[i],
                                                         ctxt, flags);
        if (!rng)
            goto error;

        def->rngs[def->nrngs++] = rng;
    }
    VIR_FREE(nodes);

    /* Parse the TPM devices */
    if ((n = virXPathNodeSet("./devices/tpm", ctxt, &nodes)) < 0)
        goto error;

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only a single TPM device is supported"));
        goto error;
    }

    if (n > 0) {
        if (!(def->tpm = virDomainTPMDefParseXML(nodes[0], ctxt, flags)))
            goto error;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/nvram", ctxt, &nodes)) < 0)
        goto error;

    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only a single nvram device is supported"));
        goto error;
    } else if (n == 1) {
        virDomainNVRAMDefPtr nvram =
            virDomainNVRAMDefParseXML(nodes[0], flags);
        if (!nvram)
            goto error;
        def->nvram = nvram;
        VIR_FREE(nodes);
    }

    /* analysis of the hub devices */
    if ((n = virXPathNodeSet("./devices/hub", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->hubs, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainHubDefPtr hub = virDomainHubDefParseXML(nodes[i], flags);
        if (!hub)
            goto error;

        if (hub->type == VIR_DOMAIN_HUB_TYPE_USB && usb_none) {
            virDomainHubDefFree(hub);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add USB hub: "
                             "USB is disabled for this domain"));
            goto error;
        }

        def->hubs[def->nhubs++] = hub;
    }
    VIR_FREE(nodes);

    /* analysis of the redirected devices */
    if ((n = virXPathNodeSet("./devices/redirdev", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->redirdevs, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainRedirdevDefPtr redirdev =
            virDomainRedirdevDefParseXML(xmlopt, nodes[i], bootHash, flags);
        if (!redirdev)
            goto error;

        def->redirdevs[def->nredirdevs++] = redirdev;
    }
    VIR_FREE(nodes);

    /* analysis of the redirection filter rules */
    if ((n = virXPathNodeSet("./devices/redirfilter", ctxt, &nodes)) < 0)
        goto error;
    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only one set of redirection filter rule is supported"));
        goto error;
    }

    if (n) {
        virDomainRedirFilterDefPtr redirfilter =
            virDomainRedirFilterDefParseXML(nodes[0], ctxt);
        if (!redirfilter)
            goto error;

        def->redirfilter = redirfilter;
    }
    VIR_FREE(nodes);

    /* analysis of the panic devices */
    if ((n = virXPathNodeSet("./devices/panic", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->panics, n) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        virDomainPanicDefPtr panic = virDomainPanicDefParseXML(nodes[i], flags);
        if (!panic)
            goto error;

        def->panics[def->npanics++] = panic;
    }
    VIR_FREE(nodes);

    /* analysis of the shmem devices */
    if ((n = virXPathNodeSet("./devices/shmem", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->shmems, n) < 0)
        goto error;

    node = ctxt->node;
    for (i = 0; i < n; i++) {
        virDomainShmemDefPtr shmem;
        ctxt->node = nodes[i];
        shmem = virDomainShmemDefParseXML(nodes[i], ctxt, flags);
        if (!shmem)
            goto error;

        def->shmems[def->nshmems++] = shmem;
    }
    ctxt->node = node;
    VIR_FREE(nodes);

    /* analysis of memory devices */
    if ((n = virXPathNodeSet("./devices/memory", ctxt, &nodes)) < 0)
        goto error;
    if (n && VIR_ALLOC_N(def->mems, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virDomainMemoryDefPtr mem = virDomainMemoryDefParseXML(nodes[i],
                                                               ctxt,
                                                               flags);
        if (!mem)
            goto error;

        def->mems[def->nmems++] = mem;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/iommu", ctxt, &nodes)) < 0)
        goto error;

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only a single IOMMU device is supported"));
        goto error;
    }

    if (n > 0) {
        if (!(def->iommu = virDomainIOMMUDefParseXML(nodes[0], ctxt)))
            goto error;
    }
    VIR_FREE(nodes);

    /* analysis of the user namespace mapping */
    if ((n = virXPathNodeSet("./idmap/uid", ctxt, &nodes)) < 0)
        goto error;

    if (n) {
        def->idmap.uidmap = virDomainIdmapDefParseXML(ctxt, nodes, n);
        if (!def->idmap.uidmap)
            goto error;

        def->idmap.nuidmap = n;
    }
    VIR_FREE(nodes);

    if  ((n = virXPathNodeSet("./idmap/gid", ctxt, &nodes)) < 0)
        goto error;

    if (n) {
        def->idmap.gidmap =  virDomainIdmapDefParseXML(ctxt, nodes, n);
        if (!def->idmap.gidmap)
            goto error;

        def->idmap.ngidmap = n;
    }
    VIR_FREE(nodes);

    if ((def->idmap.uidmap && !def->idmap.gidmap) ||
        (!def->idmap.uidmap && def->idmap.gidmap)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("uid and gid should be mapped both"));
            goto error;
    }

    if ((node = virXPathNode("./sysinfo[1]", ctxt)) != NULL) {
        xmlNodePtr oldnode = ctxt->node;
        ctxt->node = node;
        def->sysinfo = virSysinfoParseXML(node, ctxt,
                                          def->uuid, uuid_generated);
        ctxt->node = oldnode;

        if (def->sysinfo == NULL)
            goto error;
    }

    if ((tmp = virXPathString("string(./os/smbios/@mode)", ctxt))) {
        int mode;

        if ((mode = virDomainSmbiosModeTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown smbios mode '%s'"), tmp);
            goto error;
        }
        def->os.smbios_mode = mode;
        VIR_FREE(tmp);
    }

    if (virDomainKeyWrapDefParseXML(def, ctxt) < 0)
        goto error;

    /* Extract custom metadata */
    if ((node = virXPathNode("./metadata[1]", ctxt)) != NULL)
        def->metadata = xmlCopyNode(node, 1);

    /* we have to make a copy of all of the callback pointers here since
     * we won't have the virCaps structure available during free
     */
    def->ns = xmlopt->ns;

    if (def->ns.parse &&
        (def->ns.parse)(xml, root, ctxt, &def->namespaceData) < 0)
        goto error;

    /* callback to fill driver specific domain aspects */
    if (virDomainDefPostParse(def, caps, flags, xmlopt, parseOpaque) < 0)
        goto error;

    /* valdiate configuration */
    if (virDomainDefValidate(def, caps, flags, xmlopt) < 0)
        goto error;

    virHashFree(bootHash);

    return def;

 error:
    VIR_FREE(tmp);
    VIR_FREE(nodes);
    virHashFree(bootHash);
    virDomainDefFree(def);
    return NULL;
}


static virDomainObjPtr
virDomainObjParseXML(xmlDocPtr xml,
                     xmlXPathContextPtr ctxt,
                     virCapsPtr caps,
                     virDomainXMLOptionPtr xmlopt,
                     unsigned int flags)
{
    char *tmp = NULL;
    long val;
    xmlNodePtr config;
    xmlNodePtr oldnode;
    virDomainObjPtr obj;
    xmlNodePtr *nodes = NULL;
    size_t i;
    int n;
    int state;
    int reason = 0;

    if (!(obj = virDomainObjNew(xmlopt)))
        return NULL;

    if (!(config = virXPathNode("./domain", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no domain config"));
        goto error;
    }

    oldnode = ctxt->node;
    ctxt->node = config;
    obj->def = virDomainDefParseXML(xml, config, ctxt, caps, xmlopt, NULL, flags);
    ctxt->node = oldnode;
    if (!obj->def)
        goto error;

    if (!(tmp = virXPathString("string(./@state)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing domain state"));
        goto error;
    }
    if ((state = virDomainStateTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid domain state '%s'"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    VIR_FREE(tmp);

    if ((tmp = virXPathString("string(./@reason)", ctxt))) {
        if ((reason = virDomainStateReasonFromString(state, tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid domain state reason '%s'"), tmp);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);
    }

    virDomainObjSetState(obj, state, reason);

    if (virXPathLong("string(./@pid)", ctxt, &val) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid pid"));
        goto error;
    }
    obj->pid = (pid_t)val;

    if ((n = virXPathNodeSet("./taint", ctxt, &nodes)) < 0)
        goto error;
    for (i = 0; i < n; i++) {
        char *str = virXMLPropString(nodes[i], "flag");
        if (str) {
            int flag = virDomainTaintTypeFromString(str);
            if (flag < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unknown taint flag %s"), str);
                VIR_FREE(str);
                goto error;
            }
            VIR_FREE(str);
            virDomainObjTaint(obj, flag);
        }
    }
    VIR_FREE(nodes);

    if (xmlopt->privateData.parse &&
        xmlopt->privateData.parse(ctxt, obj, &xmlopt->config) < 0)
        goto error;

    return obj;

 error:
    virObjectUnref(obj);
    VIR_FREE(nodes);
    return NULL;
}


static virDomainDefPtr
virDomainDefParse(const char *xmlStr,
                  const char *filename,
                  virCapsPtr caps,
                  virDomainXMLOptionPtr xmlopt,
                  void *parseOpaque,
                  unsigned int flags)
{
    xmlDocPtr xml;
    virDomainDefPtr def = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(filename, xmlStr, _("(domain_definition)")))) {
        def = virDomainDefParseNode(xml, xmlDocGetRootElement(xml), caps,
                                    xmlopt, parseOpaque, flags);
        xmlFreeDoc(xml);
    }

    xmlKeepBlanksDefault(keepBlanksDefault);
    return def;
}

virDomainDefPtr
virDomainDefParseString(const char *xmlStr,
                        virCapsPtr caps,
                        virDomainXMLOptionPtr xmlopt,
                        void *parseOpaque,
                        unsigned int flags)
{
    return virDomainDefParse(xmlStr, NULL, caps, xmlopt, parseOpaque, flags);
}

virDomainDefPtr
virDomainDefParseFile(const char *filename,
                      virCapsPtr caps,
                      virDomainXMLOptionPtr xmlopt,
                      void *parseOpaque,
                      unsigned int flags)
{
    return virDomainDefParse(NULL, filename, caps, xmlopt, parseOpaque, flags);
}


virDomainDefPtr
virDomainDefParseNode(xmlDocPtr xml,
                      xmlNodePtr root,
                      virCapsPtr caps,
                      virDomainXMLOptionPtr xmlopt,
                      void *parseOpaque,
                      unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virDomainDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "domain")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <domain>"),
                       root->name);
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virDomainDefParseXML(xml, root, ctxt, caps, xmlopt, parseOpaque, flags);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


virDomainObjPtr
virDomainObjParseNode(xmlDocPtr xml,
                      xmlNodePtr root,
                      virCapsPtr caps,
                      virDomainXMLOptionPtr xmlopt,
                      unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virDomainObjPtr obj = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "domstatus")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <domstatus>"),
                       root->name);
        goto cleanup;
    }

    if (!(ctxt = xmlXPathNewContext(xml))) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    obj = virDomainObjParseXML(xml, ctxt, caps, xmlopt, flags);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return obj;
}


virDomainObjPtr
virDomainObjParseFile(const char *filename,
                      virCapsPtr caps,
                      virDomainXMLOptionPtr xmlopt,
                      unsigned int flags)
{
    xmlDocPtr xml;
    virDomainObjPtr obj = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParseFile(filename))) {
        obj = virDomainObjParseNode(xml, xmlDocGetRootElement(xml),
                                    caps, xmlopt, flags);
        xmlFreeDoc(xml);
    }

    xmlKeepBlanksDefault(keepBlanksDefault);
    return obj;
}


static bool
virDomainTimerDefCheckABIStability(virDomainTimerDefPtr src,
                                   virDomainTimerDefPtr dst)
{
    if (src->name != dst->name) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target timer %s does not match source %s"),
                       virDomainTimerNameTypeToString(dst->name),
                       virDomainTimerNameTypeToString(src->name));
        return false;
    }

    if (src->present != dst->present) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target timer presence %d does not match source %d"),
                       dst->present, src->present);
        return false;
    }

    if (src->name == VIR_DOMAIN_TIMER_NAME_TSC) {
        if (src->frequency != dst->frequency) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target TSC frequency %lu does not match source %lu"),
                           dst->frequency, src->frequency);
            return false;
        }

        if (src->mode != dst->mode) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target TSC mode %s does not match source %s"),
                           virDomainTimerModeTypeToString(dst->mode),
                           virDomainTimerModeTypeToString(src->mode));
            return false;
        }
    }

    return true;
}


static bool
virDomainDeviceInfoCheckABIStability(virDomainDeviceInfoPtr src,
                                     virDomainDeviceInfoPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device address type %s does not match source %s"),
                       virDomainDeviceAddressTypeToString(dst->type),
                       virDomainDeviceAddressTypeToString(src->type));
        return false;
    }

    switch ((virDomainDeviceAddressType) src->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (src->addr.pci.domain != dst->addr.pci.domain ||
            src->addr.pci.bus != dst->addr.pci.bus ||
            src->addr.pci.slot != dst->addr.pci.slot ||
            src->addr.pci.function != dst->addr.pci.function) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device PCI address %04x:%02x:%02x.%02x "
                             "does not match source %04x:%02x:%02x.%02x"),
                           dst->addr.pci.domain, dst->addr.pci.bus,
                           dst->addr.pci.slot, dst->addr.pci.function,
                           src->addr.pci.domain, src->addr.pci.bus,
                           src->addr.pci.slot, src->addr.pci.function);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (src->addr.drive.controller != dst->addr.drive.controller ||
            src->addr.drive.bus != dst->addr.drive.bus ||
            src->addr.drive.unit != dst->addr.drive.unit) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device drive address %d:%d:%d "
                             "does not match source %d:%d:%d"),
                           dst->addr.drive.controller, dst->addr.drive.bus,
                           dst->addr.drive.unit,
                           src->addr.drive.controller, src->addr.drive.bus,
                           src->addr.drive.unit);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        if (src->addr.vioserial.controller != dst->addr.vioserial.controller ||
            src->addr.vioserial.bus != dst->addr.vioserial.bus ||
            src->addr.vioserial.port != dst->addr.vioserial.port) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device virtio serial address %d:%d:%d "
                             "does not match source %d:%d:%d"),
                           dst->addr.vioserial.controller, dst->addr.vioserial.bus,
                           dst->addr.vioserial.port,
                           src->addr.vioserial.controller, src->addr.vioserial.bus,
                           src->addr.vioserial.port);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        if (src->addr.ccid.controller != dst->addr.ccid.controller ||
            src->addr.ccid.slot != dst->addr.ccid.slot) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device ccid address %d:%d "
                             "does not match source %d:%d"),
                           dst->addr.ccid.controller,
                           dst->addr.ccid.slot,
                           src->addr.ccid.controller,
                           src->addr.ccid.slot);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (src->addr.isa.iobase != dst->addr.isa.iobase ||
            src->addr.isa.irq != dst->addr.isa.irq) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device isa address %d:%d "
                             "does not match source %d:%d"),
                           dst->addr.isa.iobase,
                           dst->addr.isa.irq,
                           src->addr.isa.iobase,
                           src->addr.isa.irq);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (src->addr.dimm.slot != dst->addr.dimm.slot) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device dimm slot %u does not match "
                             "source %u"),
                           dst->addr.dimm.slot,
                           src->addr.dimm.slot);
            return false;
        }

        if (src->addr.dimm.base != dst->addr.dimm.base) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device dimm base address '%llx' does "
                             "not match source '%llx'"),
                           dst->addr.dimm.base,
                           src->addr.dimm.base);
            return false;
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    return true;
}


static bool
virDomainVirtioOptionsCheckABIStability(virDomainVirtioOptionsPtr src,
                                        virDomainVirtioOptionsPtr dst)
{
    if (src->iommu != dst->iommu) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device iommu option '%s' does not "
                         "match source '%s'"),
                       virTristateSwitchTypeToString(dst->iommu),
                       virTristateSwitchTypeToString(src->iommu));
        return false;
    }
    if (src->ats != dst->ats) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device ats option '%s' does not "
                         "match source '%s'"),
                       virTristateSwitchTypeToString(dst->ats),
                       virTristateSwitchTypeToString(src->ats));
        return false;
    }
    return true;
}


static bool
virDomainDiskDefCheckABIStability(virDomainDiskDefPtr src,
                                  virDomainDiskDefPtr dst)
{
    if (src->device != dst->device) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk device %s does not match source %s"),
                       virDomainDiskDeviceTypeToString(dst->device),
                       virDomainDiskDeviceTypeToString(src->device));
        return false;
    }

    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk bus %s does not match source %s"),
                       virDomainDiskBusTypeToString(dst->bus),
                       virDomainDiskBusTypeToString(src->bus));
        return false;
    }

    if (STRNEQ(src->dst, dst->dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk %s does not match source %s"),
                       dst->dst, src->dst);
        return false;
    }

    if (STRNEQ_NULLABLE(src->serial, dst->serial)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk serial %s does not match source %s"),
                       NULLSTR(dst->serial), NULLSTR(src->serial));
        return false;
    }

    if (STRNEQ_NULLABLE(src->wwn, dst->wwn)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk wwn '%s' does not match source '%s'"),
                       NULLSTR(dst->wwn), NULLSTR(src->wwn));
        return false;

    }

    if (src->src->readonly != dst->src->readonly ||
        src->src->shared != dst->src->shared) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target disk access mode does not match source"));
        return false;
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainControllerDefCheckABIStability(virDomainControllerDefPtr src,
                                        virDomainControllerDefPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller type %s does not match source %s"),
                       virDomainControllerTypeToString(dst->type),
                       virDomainControllerTypeToString(src->type));
        return false;
    }

    if (src->idx != dst->idx) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller index %d does not match source %d"),
                       dst->idx, src->idx);
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller model %d does not match source %d"),
                       dst->model, src->model);
        return false;
    }

    if (src->type == VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL) {
        if (src->opts.vioserial.ports != dst->opts.vioserial.ports) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller ports %d does not match source %d"),
                           dst->opts.vioserial.ports, src->opts.vioserial.ports);
            return false;
        }

        if (src->opts.vioserial.vectors != dst->opts.vioserial.vectors) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller vectors %d does not match source %d"),
                           dst->opts.vioserial.vectors, src->opts.vioserial.vectors);
            return false;
        }
    } else if (src->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        if (src->opts.usbopts.ports != dst->opts.usbopts.ports) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller ports %d does not match source %d"),
                           dst->opts.usbopts.ports, src->opts.usbopts.ports);
            return false;
        }
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainFsDefCheckABIStability(virDomainFSDefPtr src,
                                virDomainFSDefPtr dst)
{
    if (STRNEQ(src->dst, dst->dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target filesystem guest target %s does not match source %s"),
                       dst->dst, src->dst);
        return false;
    }

    if (src->readonly != dst->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target filesystem access mode does not match source"));
        return false;
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainNetDefCheckABIStability(virDomainNetDefPtr src,
                                 virDomainNetDefPtr dst)
{
    char srcmac[VIR_MAC_STRING_BUFLEN];
    char dstmac[VIR_MAC_STRING_BUFLEN];

    if (virMacAddrCmp(&src->mac, &dst->mac) != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card mac %s"
                         " does not match source %s"),
                       virMacAddrFormat(&dst->mac, dstmac),
                       virMacAddrFormat(&src->mac, srcmac));
        return false;
    }

    if (STRNEQ_NULLABLE(src->model, dst->model)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card model %s does not match source %s"),
                       NULLSTR(dst->model), NULLSTR(src->model));
        return false;
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainInputDefCheckABIStability(virDomainInputDefPtr src,
                                   virDomainInputDefPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target input device type %s does not match source %s"),
                       virDomainInputTypeToString(dst->type),
                       virDomainInputTypeToString(src->type));
        return false;
    }

    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target input device bus %s does not match source %s"),
                       virDomainInputBusTypeToString(dst->bus),
                       virDomainInputBusTypeToString(src->bus));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainSoundDefCheckABIStability(virDomainSoundDefPtr src,
                                   virDomainSoundDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sound card model %s does not match source %s"),
                       virDomainSoundModelTypeToString(dst->model),
                       virDomainSoundModelTypeToString(src->model));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainVideoDefCheckABIStability(virDomainVideoDefPtr src,
                                   virDomainVideoDefPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card model %s does not match source %s"),
                       virDomainVideoTypeToString(dst->type),
                       virDomainVideoTypeToString(src->type));
        return false;
    }

    if (src->ram != dst->ram) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card ram %u does not match source %u"),
                       dst->ram, src->ram);
        return false;
    }

    if (src->vram != dst->vram) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vram %u does not match source %u"),
                       dst->vram, src->vram);
        return false;
    }

    if (src->vram64 != dst->vram64) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vram64 %u does not match source %u"),
                       dst->vram64, src->vram64);
        return false;
    }

    if (src->vgamem != dst->vgamem) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vgamem %u does not match source %u"),
                       dst->vgamem, src->vgamem);
        return false;
    }

    if (src->heads != dst->heads) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card heads %u does not match source %u"),
                       dst->heads, src->heads);
        return false;
    }

    if ((src->accel && !dst->accel) ||
        (!src->accel && dst->accel)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target video card acceleration does not match source"));
        return false;
    }

    if (src->accel) {
        if (src->accel->accel2d != dst->accel->accel2d) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target video card 2d accel %u does not match source %u"),
                           dst->accel->accel2d, src->accel->accel2d);
            return false;
        }

        if (src->accel->accel3d != dst->accel->accel3d) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target video card 3d accel %u does not match source %u"),
                           dst->accel->accel3d, src->accel->accel3d);
            return false;
        }
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainHostdevDefCheckABIStability(virDomainHostdevDefPtr src,
                                     virDomainHostdevDefPtr dst)
{
    if (src->mode != dst->mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target host device mode %s does not match source %s"),
                       virDomainHostdevModeTypeToString(dst->mode),
                       virDomainHostdevModeTypeToString(src->mode));
        return false;
    }

    if (src->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        src->source.subsys.type != dst->source.subsys.type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target host device subsystem %s does not match source %s"),
                       virDomainHostdevSubsysTypeToString(dst->source.subsys.type),
                       virDomainHostdevSubsysTypeToString(src->source.subsys.type));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(src->info, dst->info))
        return false;

    return true;
}


static bool
virDomainSmartcardDefCheckABIStability(virDomainSmartcardDefPtr src,
                                       virDomainSmartcardDefPtr dst)
{
    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainSerialDefCheckABIStability(virDomainChrDefPtr src,
                                    virDomainChrDefPtr dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target serial type %s does not match source %s"),
                       virDomainChrSerialTargetTypeToString(dst->targetType),
                       virDomainChrSerialTargetTypeToString(src->targetType));
        return false;
    }

    if (src->target.port != dst->target.port) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target serial port %d does not match source %d"),
                       dst->target.port, src->target.port);
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainParallelDefCheckABIStability(virDomainChrDefPtr src,
                                      virDomainChrDefPtr dst)
{
    if (src->target.port != dst->target.port) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target parallel port %d does not match source %d"),
                       dst->target.port, src->target.port);
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainChannelDefCheckABIStability(virDomainChrDefPtr src,
                                     virDomainChrDefPtr dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target channel type %s does not match source %s"),
                       virDomainChrChannelTargetTypeToString(dst->targetType),
                       virDomainChrChannelTargetTypeToString(src->targetType));
        return false;
    }

    switch (src->targetType) {

    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
        if (STRNEQ_NULLABLE(src->target.name, dst->target.name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target channel name %s does not match source %s"),
                           NULLSTR(dst->target.name), NULLSTR(src->target.name));
            return false;
        }
        if (src->source->type != dst->source->type &&
            (src->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC ||
             dst->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) &&
            !src->target.name) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Changing device type to/from spicevmc would"
                             " change default target channel name"));
            return false;
        }
        break;
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
        if (memcmp(src->target.addr, dst->target.addr,
                   sizeof(*src->target.addr)) != 0) {
            char *saddr = virSocketAddrFormatFull(src->target.addr, true, ":");
            char *daddr = virSocketAddrFormatFull(dst->target.addr, true, ":");
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target channel addr %s does not match source %s"),
                           NULLSTR(daddr), NULLSTR(saddr));
            VIR_FREE(saddr);
            VIR_FREE(daddr);
            return false;
        }
        break;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainConsoleDefCheckABIStability(virDomainChrDefPtr src,
                                     virDomainChrDefPtr dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target console type %s does not match source %s"),
                       virDomainChrConsoleTargetTypeToString(dst->targetType),
                       virDomainChrConsoleTargetTypeToString(src->targetType));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainWatchdogDefCheckABIStability(virDomainWatchdogDefPtr src,
                                      virDomainWatchdogDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target watchdog model %s does not match source %s"),
                       virDomainWatchdogModelTypeToString(dst->model),
                       virDomainWatchdogModelTypeToString(src->model));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainMemballoonDefCheckABIStability(virDomainMemballoonDefPtr src,
                                        virDomainMemballoonDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target balloon model %s does not match source %s"),
                       virDomainMemballoonModelTypeToString(dst->model),
                       virDomainMemballoonModelTypeToString(src->model));
        return false;
    }

    if (src->autodeflate != dst->autodeflate) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target balloon autodeflate attribute value "
                         "'%s' does not match source '%s'"),
                       virTristateSwitchTypeToString(dst->autodeflate),
                       virTristateSwitchTypeToString(src->autodeflate));
        return false;
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainRNGDefCheckABIStability(virDomainRNGDefPtr src,
                                 virDomainRNGDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target RNG model '%s' does not match source '%s'"),
                       virDomainRNGModelTypeToString(dst->model),
                       virDomainRNGModelTypeToString(src->model));
        return false;
    }

    if (src->virtio && dst->virtio &&
        !virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainHubDefCheckABIStability(virDomainHubDefPtr src,
                                 virDomainHubDefPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target hub device type %s does not match source %s"),
                       virDomainHubTypeToString(dst->type),
                       virDomainHubTypeToString(src->type));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainRedirdevDefCheckABIStability(virDomainRedirdevDefPtr src,
                                      virDomainRedirdevDefPtr dst)
{
    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target redirected device bus %s does not match "
                         "source %s"),
                       virDomainRedirdevBusTypeToString(dst->bus),
                       virDomainRedirdevBusTypeToString(src->bus));
        return false;
    }

    switch ((virDomainRedirdevBus) src->bus) {
    case VIR_DOMAIN_REDIRDEV_BUS_USB:
        if (src->source->type != dst->source->type) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target redirected device source type %s does "
                             "not match source device source type %s"),
                           virDomainChrTypeToString(dst->source->type),
                           virDomainChrTypeToString(src->source->type));
            return false;
        }
        break;
    case VIR_DOMAIN_REDIRDEV_BUS_LAST:
        break;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainRedirFilterDefCheckABIStability(virDomainRedirFilterDefPtr src,
                                         virDomainRedirFilterDefPtr dst)
{
    size_t i;

    if (src->nusbdevs != dst->nusbdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target USB redirection filter rule "
                         "count %zu does not match source %zu"),
                         dst->nusbdevs, src->nusbdevs);
        return false;
    }

    for (i = 0; i < src->nusbdevs; i++) {
        virDomainRedirFilterUSBDevDefPtr srcUSBDev = src->usbdevs[i];
        virDomainRedirFilterUSBDevDefPtr dstUSBDev = dst->usbdevs[i];
        if (srcUSBDev->usbClass != dstUSBDev->usbClass) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("Target USB Class code does not match source"));
            return false;
        }

        if (srcUSBDev->vendor != dstUSBDev->vendor) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("Target USB vendor ID does not match source"));
            return false;
        }

        if (srcUSBDev->product != dstUSBDev->product) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("Target USB product ID does not match source"));
            return false;
        }

        if (srcUSBDev->version != dstUSBDev->version) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("Target USB version does not match source"));
            return false;
        }

        if (srcUSBDev->allow != dstUSBDev->allow) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target USB allow '%s' does not match source '%s'"),
                             dstUSBDev->allow ? "yes" : "no",
                             srcUSBDev->allow ? "yes" : "no");
            return false;
        }
    }

    return true;
}


static bool
virDomainDefFeaturesCheckABIStability(virDomainDefPtr src,
                                      virDomainDefPtr dst)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        if (src->features[i] != dst->features[i]) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("State of feature '%s' differs: "
                             "source: '%s', destination: '%s'"),
                           virDomainFeatureTypeToString(i),
                           virTristateSwitchTypeToString(src->features[i]),
                           virTristateSwitchTypeToString(dst->features[i]));
            return false;
        }
    }

    /* APIC EOI */
    if (src->apic_eoi != dst->apic_eoi) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("State of APIC EOI differs: "
                         "source: '%s', destination: '%s'"),
                       virTristateSwitchTypeToString(src->apic_eoi),
                       virTristateSwitchTypeToString(dst->apic_eoi));
        return false;
    }

    /* GIC version */
    if (src->gic_version != dst->gic_version) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Source GIC version '%s' does not match destination '%s'"),
                       virGICVersionTypeToString(src->gic_version),
                       virGICVersionTypeToString(dst->gic_version));
        return false;
    }

    /* hyperv */
    if (src->features[VIR_DOMAIN_FEATURE_HYPERV] == VIR_TRISTATE_SWITCH_ON) {
        for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
            switch ((virDomainHyperv) i) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
            case VIR_DOMAIN_HYPERV_VPINDEX:
            case VIR_DOMAIN_HYPERV_RUNTIME:
            case VIR_DOMAIN_HYPERV_SYNIC:
            case VIR_DOMAIN_HYPERV_STIMER:
            case VIR_DOMAIN_HYPERV_RESET:
                if (src->hyperv_features[i] != dst->hyperv_features[i]) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("State of HyperV enlightenment "
                                     "feature '%s' differs: "
                                     "source: '%s', destination: '%s'"),
                                   virDomainHypervTypeToString(i),
                                   virTristateSwitchTypeToString(src->hyperv_features[i]),
                                   virTristateSwitchTypeToString(dst->hyperv_features[i]));
                    return false;
                }

                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                /* spinlock count matters! */
                if (src->hyperv_spinlocks != dst->hyperv_spinlocks) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("HyperV spinlock retry count differs: "
                                     "source: '%u', destination: '%u'"),
                                   src->hyperv_spinlocks,
                                   dst->hyperv_spinlocks);
                    return false;
                }
                break;

            case VIR_DOMAIN_HYPERV_VENDOR_ID:
                if (STRNEQ_NULLABLE(src->hyperv_vendor_id, dst->hyperv_vendor_id)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("HyperV vendor_id differs: "
                                     "source: '%s', destination: '%s'"),
                                   src->hyperv_vendor_id,
                                   dst->hyperv_vendor_id);
                    return false;
                }
                break;

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
    }

    /* kvm */
    if (src->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON) {
        for (i = 0; i < VIR_DOMAIN_KVM_LAST; i++) {
            switch ((virDomainKVM) i) {
            case VIR_DOMAIN_KVM_HIDDEN:
                if (src->kvm_features[i] != dst->kvm_features[i]) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("State of KVM feature '%s' differs: "
                                     "source: '%s', destination: '%s'"),
                                   virDomainKVMTypeToString(i),
                                   virTristateSwitchTypeToString(src->kvm_features[i]),
                                   virTristateSwitchTypeToString(dst->kvm_features[i]));
                    return false;
                }

                break;

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_KVM_LAST:
                break;
            }
        }
    }

    /* ioapic */
    if (src->ioapic != dst->ioapic) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("State of ioapic differs: "
                         "source: '%s', destination: '%s'"),
                       virDomainIOAPICTypeToString(src->ioapic),
                       virDomainIOAPICTypeToString(dst->ioapic));
        return false;
    }

    return true;
}

static bool
virDomainPanicDefCheckABIStability(virDomainPanicDefPtr src,
                                   virDomainPanicDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target panic model '%s' does not match source '%s'"),
                       virDomainPanicModelTypeToString(dst->model),
                       virDomainPanicModelTypeToString(src->model));
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainShmemDefCheckABIStability(virDomainShmemDefPtr src,
                                   virDomainShmemDefPtr dst)
{
    if (STRNEQ_NULLABLE(src->name, dst->name)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory name '%s' does not match source "
                         "'%s'"), dst->name, src->name);
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory model '%s' does not match "
                         "source model '%s'"),
                       virDomainShmemModelTypeToString(dst->model),
                       virDomainShmemModelTypeToString(src->model));
        return false;
    }

    if (src->size != dst->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory size '%llu' does not match "
                         "source size '%llu'"), dst->size, src->size);
        return false;
    }

    if (src->server.enabled != dst->server.enabled) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target shared memory server usage doesn't match "
                         "source"));
        return false;
    }

    if (src->msi.vectors != dst->msi.vectors ||
        src->msi.enabled != dst->msi.enabled ||
        src->msi.ioeventfd != dst->msi.ioeventfd) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target shared memory MSI configuration doesn't match "
                         "source"));
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainTPMDefCheckABIStability(virDomainTPMDefPtr src,
                                 virDomainTPMDefPtr dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target TPM device type doesn't match source"));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target TPM device model doesn't match source"));
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainMemtuneCheckABIStability(const virDomainDef *src,
                                  const virDomainDef *dst,
                                  unsigned int flags)
{
    if (virDomainDefGetMemoryInitial(src) != virDomainDefGetMemoryInitial(dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain max memory %lld "
                         "does not match source %lld"),
                       virDomainDefGetMemoryInitial(dst),
                       virDomainDefGetMemoryInitial(src));
        return false;
    }

    if (!(flags & VIR_DOMAIN_DEF_ABI_CHECK_SKIP_VOLATILE) &&
        src->mem.cur_balloon != dst->mem.cur_balloon) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain current memory %lld "
                         "does not match source %lld"),
                       dst->mem.cur_balloon,
                       src->mem.cur_balloon);
        return false;
    }

    if (src->mem.max_memory != dst->mem.max_memory) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target maximum memory size '%llu' "
                         "doesn't match source '%llu'"),
                       dst->mem.max_memory,
                       src->mem.max_memory);
        return false;
    }

    if (src->mem.memory_slots != dst->mem.memory_slots) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory slots "
                         "count '%u' doesn't match source '%u'"),
                       dst->mem.memory_slots,
                       src->mem.memory_slots);
        return false;
    }

    return true;
}


static bool
virDomainMemoryDefCheckABIStability(virDomainMemoryDefPtr src,
                                    virDomainMemoryDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device model '%s' "
                         "doesn't match source model '%s'"),
                       virDomainMemoryModelTypeToString(dst->model),
                       virDomainMemoryModelTypeToString(src->model));
        return false;
    }

    if (src->targetNode != dst->targetNode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device targetNode '%d' "
                         "doesn't match source targetNode '%d'"),
                       dst->targetNode, src->targetNode);
        return false;
    }

    if (src->size != dst->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device size '%llu' doesn't match "
                         "source memory device size '%llu'"),
                       dst->size, src->size);
        return false;
    }

    if (src->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        src->labelsize != dst->labelsize) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target NVDIMM label size '%llu' doesn't match "
                         "source NVDIMM label size '%llu'"),
                       src->labelsize, dst->labelsize);
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainIOMMUDefCheckABIStability(virDomainIOMMUDefPtr src,
                                   virDomainIOMMUDefPtr dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device model '%s' "
                         "does not match source '%s'"),
                       virDomainIOMMUModelTypeToString(dst->model),
                       virDomainIOMMUModelTypeToString(src->model));
        return false;
    }
    if (src->intremap != dst->intremap) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device intremap value '%s' "
                         "does not match source '%s'"),
                       virTristateSwitchTypeToString(dst->intremap),
                       virTristateSwitchTypeToString(src->intremap));
        return false;
    }
    if (src->caching_mode != dst->caching_mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device caching mode '%s' "
                         "does not match source '%s'"),
                       virTristateSwitchTypeToString(dst->caching_mode),
                       virTristateSwitchTypeToString(src->caching_mode));
        return false;
    }
    if (src->eim != dst->eim) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device eim value '%s' "
                         "does not match source '%s'"),
                       virTristateSwitchTypeToString(dst->eim),
                       virTristateSwitchTypeToString(src->eim));
        return false;
    }
    if (src->iotlb != dst->iotlb) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device iotlb value '%s' "
                         "does not match source '%s'"),
                       virTristateSwitchTypeToString(dst->iotlb),
                       virTristateSwitchTypeToString(src->iotlb));
        return false;
    }
    return true;
}


static bool
virDomainDefVcpuCheckAbiStability(virDomainDefPtr src,
                                  virDomainDefPtr dst)
{
    size_t i;

    if (src->maxvcpus != dst->maxvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain vCPU max %zu does not match source %zu"),
                       dst->maxvcpus, src->maxvcpus);
        return false;
    }

    for (i = 0; i < src->maxvcpus; i++) {
        virDomainVcpuDefPtr svcpu = src->vcpus[i];
        virDomainVcpuDefPtr dvcpu = dst->vcpus[i];

        if (svcpu->online != dvcpu->online) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("State of vCPU '%zu' differs between source and "
                             "destination definitions"), i);
            return false;
        }

        if (svcpu->order != dvcpu->order) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("vcpu enable order of vCPU '%zu' differs between "
                             "source and destination definitions"), i);
            return false;
        }
    }

    return true;
}


/* This compares two configurations and looks for any differences
 * which will affect the guest ABI. This is primarily to allow
 * validation of custom XML config passed in during migration
 */
bool
virDomainDefCheckABIStabilityFlags(virDomainDefPtr src,
                                   virDomainDefPtr dst,
                                   virDomainXMLOptionPtr xmlopt,
                                   unsigned int flags)
{
    size_t i;
    virErrorPtr err;
    char *strSrc;
    char *strDst;

    if (src->virtType != dst->virtType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain virt type %s does not match source %s"),
                       virDomainVirtTypeToString(dst->virtType),
                       virDomainVirtTypeToString(src->virtType));
        goto error;
    }

    if (memcmp(src->uuid, dst->uuid, VIR_UUID_BUFLEN) != 0) {
        char uuidsrc[VIR_UUID_STRING_BUFLEN];
        char uuiddst[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(src->uuid, uuidsrc);
        virUUIDFormat(dst->uuid, uuiddst);
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain uuid %s does not match source %s"),
                       uuiddst, uuidsrc);
        goto error;
    }

    /* Not strictly ABI related, but we want to make sure domains
     * don't get silently re-named through the backdoor when passing
     * custom XML into various APIs, since this would create havoc
     */
    if (STRNEQ_NULLABLE(src->name, dst->name)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain name '%s' does not match source '%s'"),
                       dst->name, src->name);
        goto error;
    }

    if (!virDomainMemtuneCheckABIStability(src, dst, flags))
        goto error;

    if (!virDomainNumaCheckABIStability(src->numa, dst->numa))
        goto error;

    if (!virDomainDefVcpuCheckAbiStability(src, dst))
        goto error;

    if (src->niothreadids != dst->niothreadids) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain iothreads count %zu does not "
                         "match source %zu"),
                       dst->niothreadids, src->niothreadids);
        goto error;
    }

    if (src->os.type != dst->os.type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain OS type %s does not match source %s"),
                       virDomainOSTypeToString(dst->os.type),
                       virDomainOSTypeToString(src->os.type));
        goto error;
    }
    if (src->os.arch != dst->os.arch) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain architecture %s does not match source %s"),
                       virArchToString(dst->os.arch),
                       virArchToString(src->os.arch));
        goto error;
    }
    if (STRNEQ_NULLABLE(src->os.machine, dst->os.machine)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("Target domain machine type %s does not match source %s"),
                    dst->os.machine, src->os.machine);
        goto error;
    }

    if (src->os.smbios_mode != dst->os.smbios_mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain SMBIOS mode %s does not match source %s"),
                       virDomainSmbiosModeTypeToString(dst->os.smbios_mode),
                       virDomainSmbiosModeTypeToString(src->os.smbios_mode));
        goto error;
    }

    if (!virDomainDefFeaturesCheckABIStability(src, dst))
        goto error;

    if (src->clock.ntimers != dst->clock.ntimers) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain timers do not match source"));
        goto error;
    }

    for (i = 0; i < src->clock.ntimers; i++) {
        if (!virDomainTimerDefCheckABIStability(src->clock.timers[i],
                                                dst->clock.timers[i]))
            goto error;
    }

    if (!virCPUDefIsEqual(src->cpu, dst->cpu, true))
        goto error;

    if (!virSysinfoIsEqual(src->sysinfo, dst->sysinfo))
        goto error;

    if (src->ndisks != dst->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain disk count %zu does not match source %zu"),
                       dst->ndisks, src->ndisks);
        goto error;
    }

    for (i = 0; i < src->ndisks; i++)
        if (!virDomainDiskDefCheckABIStability(src->disks[i], dst->disks[i]))
            goto error;

    if (src->ncontrollers != dst->ncontrollers) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain controller count %zu "
                         "does not match source %zu"),
                       dst->ncontrollers, src->ncontrollers);
        goto error;
    }

    for (i = 0; i < src->ncontrollers; i++)
        if (!virDomainControllerDefCheckABIStability(src->controllers[i],
                                                     dst->controllers[i]))
            goto error;

    if (src->nfss != dst->nfss) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain filesystem count %zu "
                         "does not match source %zu"),
                       dst->nfss, src->nfss);
        goto error;
    }

    for (i = 0; i < src->nfss; i++)
        if (!virDomainFsDefCheckABIStability(src->fss[i], dst->fss[i]))
            goto error;

    if (src->nnets != dst->nnets) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain net card count %zu "
                         "does not match source %zu"),
                       dst->nnets, src->nnets);
        goto error;
    }

    for (i = 0; i < src->nnets; i++)
        if (!virDomainNetDefCheckABIStability(src->nets[i], dst->nets[i]))
            goto error;

    if (src->ninputs != dst->ninputs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain input device count %zu "
                         "does not match source %zu"),
                       dst->ninputs, src->ninputs);
        goto error;
    }

    for (i = 0; i < src->ninputs; i++)
        if (!virDomainInputDefCheckABIStability(src->inputs[i], dst->inputs[i]))
            goto error;

    if (src->nsounds != dst->nsounds) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain sound card count %zu "
                         "does not match source %zu"),
                       dst->nsounds, src->nsounds);
        goto error;
    }

    for (i = 0; i < src->nsounds; i++)
        if (!virDomainSoundDefCheckABIStability(src->sounds[i], dst->sounds[i]))
            goto error;

    if (src->nvideos != dst->nvideos) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain video card count %zu "
                         "does not match source %zu"),
                       dst->nvideos, src->nvideos);
        goto error;
    }

    for (i = 0; i < src->nvideos; i++)
        if (!virDomainVideoDefCheckABIStability(src->videos[i], dst->videos[i]))
            goto error;

    if (src->nhostdevs != dst->nhostdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain host device count %zu "
                         "does not match source %zu"),
                       dst->nhostdevs, src->nhostdevs);
        goto error;
    }

    for (i = 0; i < src->nhostdevs; i++)
        if (!virDomainHostdevDefCheckABIStability(src->hostdevs[i],
                                                  dst->hostdevs[i]))
            goto error;

    if (src->nsmartcards != dst->nsmartcards) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain smartcard count %zu "
                         "does not match source %zu"),
                       dst->nsmartcards, src->nsmartcards);
        goto error;
    }

    for (i = 0; i < src->nsmartcards; i++)
        if (!virDomainSmartcardDefCheckABIStability(src->smartcards[i],
                                                    dst->smartcards[i]))
            goto error;

    if (src->nserials != dst->nserials) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain serial port count %zu "
                         "does not match source %zu"),
                       dst->nserials, src->nserials);
        goto error;
    }

    for (i = 0; i < src->nserials; i++)
        if (!virDomainSerialDefCheckABIStability(src->serials[i],
                                                 dst->serials[i]))
            goto error;

    if (src->nparallels != dst->nparallels) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain parallel port count %zu "
                         "does not match source %zu"),
                       dst->nparallels, src->nparallels);
        goto error;
    }

    for (i = 0; i < src->nparallels; i++)
        if (!virDomainParallelDefCheckABIStability(src->parallels[i],
                                                   dst->parallels[i]))
            goto error;

    if (src->nchannels != dst->nchannels) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain channel count %zu "
                         "does not match source %zu"),
                       dst->nchannels, src->nchannels);
        goto error;
    }

    for (i = 0; i < src->nchannels; i++)
        if (!virDomainChannelDefCheckABIStability(src->channels[i],
                                                  dst->channels[i]))
            goto error;

    if (src->nconsoles != dst->nconsoles) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain console count %zu "
                         "does not match source %zu"),
                       dst->nconsoles, src->nconsoles);
        goto error;
    }

    for (i = 0; i < src->nconsoles; i++)
        if (!virDomainConsoleDefCheckABIStability(src->consoles[i],
                                                  dst->consoles[i]))
            goto error;

    if (src->nhubs != dst->nhubs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain hub device count %zu "
                         "does not match source %zu"),
                       dst->nhubs, src->nhubs);
        goto error;
    }

    for (i = 0; i < src->nhubs; i++)
        if (!virDomainHubDefCheckABIStability(src->hubs[i], dst->hubs[i]))
            goto error;

    if (src->nredirdevs != dst->nredirdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain redirected devices count %zu "
                         "does not match source %zu"),
                       dst->nredirdevs, src->nredirdevs);
        goto error;
    }

    for (i = 0; i < src->nredirdevs; i++) {
        if (!virDomainRedirdevDefCheckABIStability(src->redirdevs[i],
                                                   dst->redirdevs[i]))
            goto error;
    }

    if ((!src->redirfilter && dst->redirfilter) ||
        (src->redirfilter && !dst->redirfilter)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain USB redirection filter count %d "
                         "does not match source %d"),
                       dst->redirfilter ? 1 : 0, src->redirfilter ? 1 : 0);
        goto error;
    }

    if (src->redirfilter &&
        !virDomainRedirFilterDefCheckABIStability(src->redirfilter,
                                                  dst->redirfilter))
        goto error;

    if ((!src->watchdog && dst->watchdog) ||
        (src->watchdog && !dst->watchdog)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain watchdog count %d "
                         "does not match source %d"),
                       dst->watchdog ? 1 : 0, src->watchdog ? 1 : 0);
        goto error;
    }

    if (src->watchdog &&
        !virDomainWatchdogDefCheckABIStability(src->watchdog, dst->watchdog))
        goto error;

    if ((!src->memballoon && dst->memballoon) ||
        (src->memballoon && !dst->memballoon)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory balloon count %d "
                         "does not match source %d"),
                       dst->memballoon ? 1 : 0, src->memballoon ? 1 : 0);
        goto error;
    }

    if (src->memballoon &&
        !virDomainMemballoonDefCheckABIStability(src->memballoon,
                                                 dst->memballoon))
        goto error;

    if (src->nrngs != dst->nrngs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain RNG device count %zu "
                         "does not match source %zu"), dst->nrngs, src->nrngs);
        goto error;
    }

    for (i = 0; i < src->nrngs; i++)
        if (!virDomainRNGDefCheckABIStability(src->rngs[i], dst->rngs[i]))
            goto error;

    if (src->npanics != dst->npanics) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain panic device count %zu "
                         "does not match source %zu"), dst->npanics, src->npanics);
        goto error;
    }

    for (i = 0; i < src->npanics; i++) {
        if (!virDomainPanicDefCheckABIStability(src->panics[i], dst->panics[i]))
            goto error;
    }

    if (src->nshmems != dst->nshmems) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain shared memory device count %zu "
                         "does not match source %zu"), dst->nshmems, src->nshmems);
        goto error;
    }

    for (i = 0; i < src->nshmems; i++) {
        if (!virDomainShmemDefCheckABIStability(src->shmems[i], dst->shmems[i]))
            goto error;
    }

    if (src->tpm && dst->tpm) {
        if (!virDomainTPMDefCheckABIStability(src->tpm, dst->tpm))
            goto error;
    } else if (src->tpm || dst->tpm) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Either both target and source domains or none of "
                         "them must have TPM device present"));
        goto error;
    }

    if (src->nmems != dst->nmems) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory device count %zu "
                         "does not match source %zu"), dst->nmems, src->nmems);
        goto error;
    }

    for (i = 0; i < src->nmems; i++) {
        if (!virDomainMemoryDefCheckABIStability(src->mems[i], dst->mems[i]))
            goto error;
    }

    if (!!src->iommu != !!dst->iommu) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain IOMMU device count "
                         "does not match source"));
        goto error;
    }

    if (src->iommu &&
        !virDomainIOMMUDefCheckABIStability(src->iommu, dst->iommu))
        goto error;

    if (xmlopt && xmlopt->abi.domain &&
        !xmlopt->abi.domain(src, dst))
        goto error;

    /* Coverity is not very happy with this - all dead_error_condition */
#if !STATIC_ANALYSIS
    /* This switch statement is here to trigger compiler warning when adding
     * a new device type. When you are adding a new field to the switch you
     * also have to add an check above. Otherwise the switch statement has no
     * real function here and should be optimized out by the compiler. */
    i = VIR_DOMAIN_DEVICE_LAST;
    switch ((virDomainDeviceType) i) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
        break;
    }
#endif

    return true;

 error:
    err = virSaveLastError();

    strSrc = virDomainDefFormat(src, NULL, 0);
    strDst = virDomainDefFormat(dst, NULL, 0);
    VIR_DEBUG("XMLs that failed stability check were: src=\"%s\", dst=\"%s\"",
              NULLSTR(strSrc), NULLSTR(strDst));
    VIR_FREE(strSrc);
    VIR_FREE(strDst);

    if (err) {
        virSetError(err);
        virFreeError(err);
    }
    return false;
}


bool
virDomainDefCheckABIStability(virDomainDefPtr src,
                              virDomainDefPtr dst,
                              virDomainXMLOptionPtr xmlopt)
{
    return virDomainDefCheckABIStabilityFlags(src, dst, xmlopt, 0);
}


static int
virDomainDefAddDiskControllersForType(virDomainDefPtr def,
                                      int controllerType,
                                      int diskBus)
{
    size_t i;
    int maxController = -1;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->bus != diskBus)
            continue;

        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        if ((int)def->disks[i]->info.addr.drive.controller > maxController)
            maxController = def->disks[i]->info.addr.drive.controller;
    }

    if (maxController == -1)
        return 0;

    for (i = 0; i <= maxController; i++) {
        if (virDomainDefMaybeAddController(def, controllerType, i, -1) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainDefMaybeAddVirtioSerialController(virDomainDefPtr def)
{
    /* Look for any virtio serial or virtio console devs */
    size_t i;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr channel = def->channels[i];

        if (channel->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {
            int idx = 0;
            if (channel->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL)
                idx = channel->info.addr.vioserial.controller;

            if (virDomainDefMaybeAddController(def,
                VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL, idx, -1) < 0)
                return -1;
        }
    }

    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDefPtr console = def->consoles[i];

        if (console->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO) {
            int idx = 0;
            if (console->info.type ==
                VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL)
                idx = console->info.addr.vioserial.controller;

            if (virDomainDefMaybeAddController(def,
                VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL, idx, -1) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virDomainDefMaybeAddSmartcardController(virDomainDefPtr def)
{
    /* Look for any smartcard devs */
    size_t i;

    for (i = 0; i < def->nsmartcards; i++) {
        virDomainSmartcardDefPtr smartcard = def->smartcards[i];
        int idx = 0;

        if (smartcard->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID) {
            idx = smartcard->info.addr.ccid.controller;
        } else if (smartcard->info.type
                   == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            size_t j;
            int max = -1;

            for (j = 0; j < def->nsmartcards; j++) {
                virDomainDeviceInfoPtr info = &def->smartcards[j]->info;
                if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID &&
                    info->addr.ccid.controller == 0 &&
                    (int) info->addr.ccid.slot > max)
                    max = info->addr.ccid.slot;
            }
            smartcard->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID;
            smartcard->info.addr.ccid.controller = 0;
            smartcard->info.addr.ccid.slot = max + 1;
        }

        if (virDomainDefMaybeAddController(def,
                                           VIR_DOMAIN_CONTROLLER_TYPE_CCID,
                                           idx, -1) < 0)
            return -1;
    }

    return 0;
}

/*
 * Based on the declared <address/> info for any devices,
 * add necessary drive controllers which are not already present
 * in the XML. This is for compat with existing apps which will
 * not know/care about <controller> info in the XML
 */
static int
virDomainDefAddImplicitControllers(virDomainDefPtr def)
{
    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                              VIR_DOMAIN_DISK_BUS_SCSI) < 0)
        return -1;

    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_FDC,
                                              VIR_DOMAIN_DISK_BUS_FDC) < 0)
        return -1;

    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                              VIR_DOMAIN_DISK_BUS_IDE) < 0)
        return -1;

    if (virDomainDefAddDiskControllersForType(def,
                                              VIR_DOMAIN_CONTROLLER_TYPE_SATA,
                                              VIR_DOMAIN_DISK_BUS_SATA) < 0)
        return -1;

    if (virDomainDefMaybeAddVirtioSerialController(def) < 0)
        return -1;

    if (virDomainDefMaybeAddSmartcardController(def) < 0)
        return -1;

    if (virDomainDefMaybeAddHostdevSCSIcontroller(def) < 0)
        return -1;

    return 0;
}

static int
virDomainDefAddImplicitVideo(virDomainDefPtr def)
{
    int ret = -1;
    virDomainVideoDefPtr video = NULL;

    /* For backwards compatibility, if no <video> tag is set but there
     * is a <graphics> tag, then we add a single video tag */
    if (def->ngraphics == 0 || def->nvideos > 0)
        return 0;

    if (VIR_ALLOC(video) < 0)
        goto cleanup;
    video->type = virDomainVideoDefaultType(def);
    if (video->type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot determine default video type"));
        goto cleanup;
    }
    video->heads = 1;
    if (VIR_APPEND_ELEMENT(def->videos, def->nvideos, video) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virDomainVideoDefFree(video);
    return ret;
}

int
virDomainDefAddImplicitDevices(virDomainDefPtr def)
{
    if (virDomainDefAddConsoleCompat(def) < 0)
        return -1;

    if (virDomainDefAddImplicitControllers(def) < 0)
        return -1;

    if (virDomainDefAddImplicitVideo(def) < 0)
        return -1;

    return 0;
}

virDomainIOThreadIDDefPtr
virDomainIOThreadIDFind(const virDomainDef *def,
                        unsigned int iothread_id)
{
    size_t i;

    if (!def->iothreadids || !def->niothreadids)
        return NULL;

    for (i = 0; i < def->niothreadids; i++) {
        if (iothread_id == def->iothreadids[i]->iothread_id)
            return def->iothreadids[i];
    }

    return NULL;
}

virDomainIOThreadIDDefPtr
virDomainIOThreadIDAdd(virDomainDefPtr def,
                       unsigned int iothread_id)
{
    virDomainIOThreadIDDefPtr iothrid = NULL;

    if (VIR_ALLOC(iothrid) < 0)
        goto error;

    iothrid->iothread_id = iothread_id;

    if (VIR_APPEND_ELEMENT_COPY(def->iothreadids, def->niothreadids,
                                iothrid) < 0)
        goto error;

    return iothrid;

 error:
    virDomainIOThreadIDDefFree(iothrid);
    return NULL;
}


void
virDomainIOThreadIDDel(virDomainDefPtr def,
                       unsigned int iothread_id)
{
    size_t i, j;

    for (i = 0; i < def->niothreadids; i++) {
        if (def->iothreadids[i]->iothread_id == iothread_id) {
            /* If we were sequential and removed a threadid in the
             * beginning or middle of the list, then unconditionally
             * clear the autofill flag so we don't lose these
             * definitions for XML formatting.
             */
            for (j = i + 1; j < def->niothreadids; j++)
                def->iothreadids[j]->autofill = false;

            virDomainIOThreadIDDefFree(def->iothreadids[i]);
            VIR_DELETE_ELEMENT(def->iothreadids, i, def->niothreadids);

            return;
        }
    }
}


static int
virDomainEventActionDefFormat(virBufferPtr buf,
                              int type,
                              const char *name,
                              virEventActionToStringFunc convFunc)
{
    const char *typeStr = convFunc(type);
    if (!typeStr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected %s action: %d"), name, type);
        return -1;
    }

    virBufferAsprintf(buf, "<%s>%s</%s>\n", name, typeStr, name);

    return 0;
}


static void
virSecurityLabelDefFormat(virBufferPtr buf,
                          virSecurityLabelDefPtr def,
                          unsigned int flags)
{
    const char *sectype = virDomainSeclabelTypeToString(def->type);

    if (!sectype)
        return;

    if (def->type == VIR_DOMAIN_SECLABEL_DEFAULT)
        return;

    /* libvirt versions prior to 0.10.0 support just a single seclabel element
     * in the XML, and that would typically be filled with type=selinux.
     * Don't format it in the MIGRATABLE case, for backwards compatibility
     */
    if ((STREQ_NULLABLE(def->model, "dac") ||
         STREQ_NULLABLE(def->model, "none")) && def->implicit &&
         (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))
        return;

    virBufferAsprintf(buf, "<seclabel type='%s'",
                      sectype);

    virBufferEscapeString(buf, " model='%s'", def->model);

    if (def->type == VIR_DOMAIN_SECLABEL_NONE) {
        virBufferAddLit(buf, "/>\n");
        return;
    }

    virBufferAsprintf(buf, " relabel='%s'",
                      def->relabel ? "yes" : "no");

    if (def->label || def->imagelabel || def->baselabel) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<label>%s</label>\n",
                              def->label);
        if (def->relabel)
            virBufferEscapeString(buf, "<imagelabel>%s</imagelabel>\n",
                                  def->imagelabel);
        if (def->type == VIR_DOMAIN_SECLABEL_DYNAMIC)
            virBufferEscapeString(buf, "<baselabel>%s</baselabel>\n",
                                  def->baselabel);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</seclabel>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


static void
virSecurityDeviceLabelDefFormat(virBufferPtr buf,
                                virSecurityDeviceLabelDefPtr def,
                                unsigned int flags)
{
    /* For offline output, skip elements that allow labels but have no
     * label specified (possible if labelskip was ignored on input).  */
    if ((flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE) && !def->label && def->relabel)
        return;

    virBufferAddLit(buf, "<seclabel");

    if (def->model)
        virBufferEscapeString(buf, " model='%s'", def->model);

    if (def->labelskip)
        virBufferAddLit(buf, " labelskip='yes'");
    else
        virBufferAsprintf(buf, " relabel='%s'", def->relabel ? "yes" : "no");

    if (def->label) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<label>%s</label>\n",
                              def->label);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</seclabel>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


static int
virDomainLeaseDefFormat(virBufferPtr buf,
                        virDomainLeaseDefPtr def)
{
    virBufferAddLit(buf, "<lease>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<lockspace>%s</lockspace>\n", def->lockspace);
    virBufferEscapeString(buf, "<key>%s</key>\n", def->key);
    virBufferEscapeString(buf, "<target path='%s'", def->path);
    if (def->offset)
        virBufferAsprintf(buf, " offset='%llu'", def->offset);
    virBufferAddLit(buf, "/>\n");
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</lease>\n");

    return 0;
}

static void
virDomainDiskGeometryDefFormat(virBufferPtr buf,
                               virDomainDiskDefPtr def)
{
    const char *trans =
        virDomainDiskGeometryTransTypeToString(def->geometry.trans);

    if (def->geometry.cylinders > 0 &&
        def->geometry.heads > 0 &&
        def->geometry.sectors > 0) {
        virBufferAsprintf(buf,
                          "<geometry cyls='%u' heads='%u' secs='%u'",
                          def->geometry.cylinders,
                          def->geometry.heads,
                          def->geometry.sectors);

        if (def->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT)
            virBufferEscapeString(buf, " trans='%s'", trans);

        virBufferAddLit(buf, "/>\n");
    }
}

static void
virDomainDiskBlockIoDefFormat(virBufferPtr buf,
                              virDomainDiskDefPtr def)
{
    if (def->blockio.logical_block_size > 0 ||
        def->blockio.physical_block_size > 0) {
        virBufferAddLit(buf, "<blockio");
        if (def->blockio.logical_block_size > 0) {
            virBufferAsprintf(buf,
                              " logical_block_size='%u'",
                              def->blockio.logical_block_size);
        }
        if (def->blockio.physical_block_size > 0) {
            virBufferAsprintf(buf,
                              " physical_block_size='%u'",
                              def->blockio.physical_block_size);
        }
        virBufferAddLit(buf, "/>\n");
    }
}


/* virDomainSourceDefFormatSeclabel:
 *
 * This function automatically closes the <source> element and formats any
 * possible seclabels.
 */
static void
virDomainDiskSourceDefFormatSeclabel(virBufferPtr buf,
                                     size_t nseclabels,
                                     virSecurityDeviceLabelDefPtr *seclabels,
                                     unsigned int flags,
                                     bool skipSeclables)
{
    size_t n;

    if (nseclabels && !skipSeclables) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        for (n = 0; n < nseclabels; n++)
            virSecurityDeviceLabelDefFormat(buf, seclabels[n], flags);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</source>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}

static void
virDomainSourceDefFormatSeclabel(virBufferPtr buf,
                                 size_t nseclabels,
                                 virSecurityDeviceLabelDefPtr *seclabels,
                                 unsigned int flags)
{
    virDomainDiskSourceDefFormatSeclabel(buf, nseclabels, seclabels, flags, false);
}


static int
virDomainDiskSourceFormatNetwork(virBufferPtr buf,
                                 virStorageSourcePtr src)
{
    size_t n;
    char *path = NULL;

    virBufferAsprintf(buf, "<source protocol='%s'",
                      virStorageNetProtocolTypeToString(src->protocol));

    if (src->volume) {
        if (virAsprintf(&path, "%s%s", src->volume, src->path) < 0)
            return -1;
    }

    virBufferEscapeString(buf, " name='%s'", path ? path : src->path);

    VIR_FREE(path);

    if (src->nhosts == 0 && !src->snapshot && !src->configFile) {
        virBufferAddLit(buf, "/>\n");
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);

        for (n = 0; n < src->nhosts; n++) {
            virBufferAddLit(buf, "<host");
            virBufferEscapeString(buf, " name='%s'", src->hosts[n].name);
            virBufferEscapeString(buf, " port='%s'", src->hosts[n].port);

            if (src->hosts[n].transport)
                virBufferAsprintf(buf, " transport='%s'",
                                  virStorageNetHostTransportTypeToString(src->hosts[n].transport));

            virBufferEscapeString(buf, " socket='%s'", src->hosts[n].socket);
            virBufferAddLit(buf, "/>\n");
        }

        virBufferEscapeString(buf, "<snapshot name='%s'/>\n", src->snapshot);
        virBufferEscapeString(buf, "<config file='%s'/>\n", src->configFile);

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</source>\n");
    }

    return 0;
}


static int
virDomainDiskSourceFormatInternal(virBufferPtr buf,
                                  virStorageSourcePtr src,
                                  int policy,
                                  unsigned int flags,
                                  bool skipSeclabels)
{
    const char *startupPolicy = NULL;

    if (policy)
        startupPolicy = virDomainStartupPolicyTypeToString(policy);

    if (src->path || src->nhosts > 0 || src->srcpool || startupPolicy) {
        switch ((virStorageType)src->type) {
        case VIR_STORAGE_TYPE_FILE:
            virBufferAddLit(buf, "<source");
            virBufferEscapeString(buf, " file='%s'", src->path);
            virBufferEscapeString(buf, " startupPolicy='%s'", startupPolicy);

            virDomainDiskSourceDefFormatSeclabel(buf, src->nseclabels,
                                                 src->seclabels, flags,
                                                 skipSeclabels);
            break;

        case VIR_STORAGE_TYPE_BLOCK:
            virBufferAddLit(buf, "<source");
            virBufferEscapeString(buf, " dev='%s'", src->path);
            virBufferEscapeString(buf, " startupPolicy='%s'", startupPolicy);

            virDomainDiskSourceDefFormatSeclabel(buf, src->nseclabels,
                                                 src->seclabels, flags,
                                                 skipSeclabels);
            break;

        case VIR_STORAGE_TYPE_DIR:
            virBufferAddLit(buf, "<source");
            virBufferEscapeString(buf, " dir='%s'", src->path);
            virBufferEscapeString(buf, " startupPolicy='%s'", startupPolicy);
            virBufferAddLit(buf, "/>\n");
            break;

        case VIR_STORAGE_TYPE_NETWORK:
            if (virDomainDiskSourceFormatNetwork(buf, src) < 0)
                return -1;
            break;

        case VIR_STORAGE_TYPE_VOLUME:
            virBufferAddLit(buf, "<source");

            if (src->srcpool) {
                virBufferEscapeString(buf, " pool='%s'", src->srcpool->pool);
                virBufferEscapeString(buf, " volume='%s'",
                                      src->srcpool->volume);
                if (src->srcpool->mode)
                    virBufferAsprintf(buf, " mode='%s'",
                                      virStorageSourcePoolModeTypeToString(src->srcpool->mode));
            }
            virBufferEscapeString(buf, " startupPolicy='%s'", startupPolicy);

            virDomainDiskSourceDefFormatSeclabel(buf, src->nseclabels,
                                                 src->seclabels, flags,
                                                 skipSeclabels);
            break;

        case VIR_STORAGE_TYPE_NONE:
        case VIR_STORAGE_TYPE_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected disk type %d"), src->type);
            return -1;
        }
    }

    return 0;
}


int
virDomainDiskSourceFormat(virBufferPtr buf,
                          virStorageSourcePtr src,
                          int policy,
                          unsigned int flags)
{
    return virDomainDiskSourceFormatInternal(buf, src, policy, flags, false);
}


static int
virDomainDiskBackingStoreFormat(virBufferPtr buf,
                                virStorageSourcePtr backingStore,
                                const char *backingStoreRaw,
                                unsigned int idx)
{
    const char *type;
    const char *format;

    if (!backingStore) {
        if (!backingStoreRaw)
            virBufferAddLit(buf, "<backingStore/>\n");
        return 0;
    }

    if (!backingStore->type ||
        !(type = virStorageTypeToString(backingStore->type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk backing store type %d"),
                       backingStore->type);
        return -1;
    }

    if (backingStore->format <= 0 ||
        !(format = virStorageFileFormatTypeToString(backingStore->format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk backing store format %d"),
                       backingStore->format);
        return -1;
    }

    virBufferAsprintf(buf, "<backingStore type='%s' index='%u'>\n",
                      type, idx);
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<format type='%s'/>\n", format);
    /* We currently don't output seclabels for backing chain element */
    if (virDomainDiskSourceFormatInternal(buf, backingStore, 0, 0, true) < 0 ||
        virDomainDiskBackingStoreFormat(buf,
                                        backingStore->backingStore,
                                        backingStore->backingStoreRaw,
                                        idx + 1) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</backingStore>\n");
    return 0;
}


#define FORMAT_IOTUNE(val)                                                     \
        if (def->blkdeviotune.val) {                                           \
            virBufferAsprintf(buf, "<" #val ">%llu</" #val ">\n",              \
                              def->blkdeviotune.val);                          \
        }

static int
virDomainDiskDefFormat(virBufferPtr buf,
                       virDomainDiskDefPtr def,
                       unsigned int flags)
{
    const char *type = virStorageTypeToString(def->src->type);
    const char *device = virDomainDiskDeviceTypeToString(def->device);
    const char *bus = virDomainDiskBusTypeToString(def->bus);
    const char *cachemode = virDomainDiskCacheTypeToString(def->cachemode);
    const char *error_policy = virDomainDiskErrorPolicyTypeToString(def->error_policy);
    const char *rerror_policy = virDomainDiskErrorPolicyTypeToString(def->rerror_policy);
    const char *iomode = virDomainDiskIoTypeToString(def->iomode);
    const char *ioeventfd = virTristateSwitchTypeToString(def->ioeventfd);
    const char *event_idx = virTristateSwitchTypeToString(def->event_idx);
    const char *copy_on_read = virTristateSwitchTypeToString(def->copy_on_read);
    const char *sgio = virDomainDeviceSGIOTypeToString(def->sgio);
    const char *discard = virDomainDiskDiscardTypeToString(def->discard);
    const char *detect_zeroes = virDomainDiskDetectZeroesTypeToString(def->detect_zeroes);
    virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

    if (!type || !def->src->type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk type %d"), def->src->type);
        return -1;
    }
    if (!device) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk device %d"), def->device);
        return -1;
    }
    if (!bus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk bus %d"), def->bus);
        return -1;
    }
    if (!cachemode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk cache mode %d"), def->cachemode);
        return -1;
    }
    if (!iomode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk io mode %d"), def->iomode);
        return -1;
    }
    if (!sgio) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected disk sgio mode '%d'"), def->sgio);
        return -1;
    }

    virBufferAsprintf(buf,
                      "<disk type='%s' device='%s'",
                      type, device);
    if (def->rawio) {
        virBufferAsprintf(buf, " rawio='%s'",
                          virTristateBoolTypeToString(def->rawio));
    }

    if (def->sgio)
        virBufferAsprintf(buf, " sgio='%s'", sgio);

    if (def->snapshot &&
        !(def->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE &&
          def->src->readonly))
        virBufferAsprintf(buf, " snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(def->snapshot));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(&driverBuf, " name='%s'", def->src->driverName);
    if (def->src->format > 0)
        virBufferAsprintf(&driverBuf, " type='%s'",
                          virStorageFileFormatTypeToString(def->src->format));
    if (def->cachemode)
        virBufferAsprintf(&driverBuf, " cache='%s'", cachemode);
    if (def->error_policy)
        virBufferAsprintf(&driverBuf, " error_policy='%s'", error_policy);
    if (def->rerror_policy)
        virBufferAsprintf(&driverBuf, " rerror_policy='%s'", rerror_policy);
    if (def->iomode)
        virBufferAsprintf(&driverBuf, " io='%s'", iomode);
    if (def->ioeventfd)
        virBufferAsprintf(&driverBuf, " ioeventfd='%s'", ioeventfd);
    if (def->event_idx)
        virBufferAsprintf(&driverBuf, " event_idx='%s'", event_idx);
    if (def->copy_on_read)
        virBufferAsprintf(&driverBuf, " copy_on_read='%s'", copy_on_read);
    if (def->discard)
        virBufferAsprintf(&driverBuf, " discard='%s'", discard);
    if (def->iothread)
        virBufferAsprintf(&driverBuf, " iothread='%u'", def->iothread);
    if (def->detect_zeroes)
        virBufferAsprintf(&driverBuf, " detect_zeroes='%s'", detect_zeroes);

    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);

    if (virBufferUse(&driverBuf)) {
        virBufferAddLit(buf, "<driver");
        virBufferAddBuffer(buf, &driverBuf);
        virBufferAddLit(buf, "/>\n");
    }

    if (def->src->auth) {
        if (virStorageAuthDefFormat(buf, def->src->auth) < 0)
            return -1;
    }

    if (virDomainDiskSourceFormat(buf, def->src, def->startupPolicy,
                                  flags) < 0)
        return -1;

    /* Don't format backingStore to inactive XMLs until the code for
     * persistent storage of backing chains is ready. */
    if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE) &&
        virDomainDiskBackingStoreFormat(buf, def->src->backingStore,
                                        def->src->backingStoreRaw, 1) < 0)
        return -1;

    virBufferEscapeString(buf, "<backenddomain name='%s'/>\n", def->domain_name);

    virDomainDiskGeometryDefFormat(buf, def);
    virDomainDiskBlockIoDefFormat(buf, def);

    /* For now, mirroring is currently output-only: we only output it
     * for live domains, therefore we ignore it on input except for
     * the internal parse on libvirtd restart.  We prefer to output
     * the new style similar to backingStore, but for back-compat on
     * blockcopy files we also have to output old style attributes.
     * The parser accepts either style across libvirtd upgrades. */
    if (def->mirror && !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)) {
        const char *formatStr = NULL;

        if (def->mirror->format)
            formatStr = virStorageFileFormatTypeToString(def->mirror->format);
        virBufferAsprintf(buf, "<mirror type='%s'",
                          virStorageTypeToString(def->mirror->type));
        if (def->mirror->type == VIR_STORAGE_TYPE_FILE &&
            def->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
            virBufferEscapeString(buf, " file='%s'", def->mirror->path);
            virBufferEscapeString(buf, " format='%s'", formatStr);
        }
        virBufferEscapeString(buf, " job='%s'",
                              virDomainBlockJobTypeToString(def->mirrorJob));
        if (def->mirrorState) {
            const char *mirror;

            mirror = virDomainDiskMirrorStateTypeToString(def->mirrorState);
            virBufferEscapeString(buf, " ready='%s'", mirror);
        }
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<format type='%s'/>\n", formatStr);
        if (virDomainDiskSourceFormat(buf, def->mirror, 0, 0) < 0)
            return -1;
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</mirror>\n");
    }

    virBufferAsprintf(buf, "<target dev='%s' bus='%s'",
                      def->dst, bus);
    if ((def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY ||
         def->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
        def->tray_status != VIR_DOMAIN_DISK_TRAY_CLOSED)
        virBufferAsprintf(buf, " tray='%s'",
                          virDomainDiskTrayTypeToString(def->tray_status));
    if (def->bus == VIR_DOMAIN_DISK_BUS_USB &&
        def->removable != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " removable='%s'",
                          virTristateSwitchTypeToString(def->removable));
    }
    virBufferAddLit(buf, "/>\n");

    /*disk I/O throttling*/
    if (def->blkdeviotune.total_bytes_sec ||
        def->blkdeviotune.read_bytes_sec ||
        def->blkdeviotune.write_bytes_sec ||
        def->blkdeviotune.total_iops_sec ||
        def->blkdeviotune.read_iops_sec ||
        def->blkdeviotune.write_iops_sec ||
        def->blkdeviotune.total_bytes_sec_max ||
        def->blkdeviotune.read_bytes_sec_max ||
        def->blkdeviotune.write_bytes_sec_max ||
        def->blkdeviotune.total_iops_sec_max ||
        def->blkdeviotune.read_iops_sec_max ||
        def->blkdeviotune.write_iops_sec_max ||
        def->blkdeviotune.size_iops_sec ||
        def->blkdeviotune.group_name ||
        def->blkdeviotune.total_bytes_sec_max_length ||
        def->blkdeviotune.read_bytes_sec_max_length ||
        def->blkdeviotune.write_bytes_sec_max_length ||
        def->blkdeviotune.total_iops_sec_max_length ||
        def->blkdeviotune.read_iops_sec_max_length ||
        def->blkdeviotune.write_iops_sec_max_length) {
        virBufferAddLit(buf, "<iotune>\n");
        virBufferAdjustIndent(buf, 2);

        FORMAT_IOTUNE(total_bytes_sec);
        FORMAT_IOTUNE(read_bytes_sec);
        FORMAT_IOTUNE(write_bytes_sec);
        FORMAT_IOTUNE(total_iops_sec);
        FORMAT_IOTUNE(read_iops_sec);
        FORMAT_IOTUNE(write_iops_sec);

        FORMAT_IOTUNE(total_bytes_sec_max);
        FORMAT_IOTUNE(read_bytes_sec_max);
        FORMAT_IOTUNE(write_bytes_sec_max);
        FORMAT_IOTUNE(total_iops_sec_max);
        FORMAT_IOTUNE(read_iops_sec_max);
        FORMAT_IOTUNE(write_iops_sec_max);

        if (def->blkdeviotune.size_iops_sec) {
            virBufferAsprintf(buf, "<size_iops_sec>%llu</size_iops_sec>\n",
                              def->blkdeviotune.size_iops_sec);
        }

        if (def->blkdeviotune.group_name) {
            virBufferEscapeString(buf, "<group_name>%s</group_name>\n",
                                  def->blkdeviotune.group_name);
        }

        FORMAT_IOTUNE(total_bytes_sec_max_length);
        FORMAT_IOTUNE(read_bytes_sec_max_length);
        FORMAT_IOTUNE(write_bytes_sec_max_length);
        FORMAT_IOTUNE(total_iops_sec_max_length);
        FORMAT_IOTUNE(read_iops_sec_max_length);
        FORMAT_IOTUNE(write_iops_sec_max_length);

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</iotune>\n");
    }

    if (def->src->readonly)
        virBufferAddLit(buf, "<readonly/>\n");
    if (def->src->shared)
        virBufferAddLit(buf, "<shareable/>\n");
    if (def->transient)
        virBufferAddLit(buf, "<transient/>\n");
    virBufferEscapeString(buf, "<serial>%s</serial>\n", def->serial);
    virBufferEscapeString(buf, "<wwn>%s</wwn>\n", def->wwn);
    virBufferEscapeString(buf, "<vendor>%s</vendor>\n", def->vendor);
    virBufferEscapeString(buf, "<product>%s</product>\n", def->product);
    if (def->src->encryption &&
        virStorageEncryptionFormat(buf, def->src->encryption) < 0)
        return -1;
    if (virDomainDeviceInfoFormat(buf, &def->info,
                                  flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</disk>\n");
    return 0;
}
#undef FORMAT_IOTUNE


static void
virDomainControllerDriverFormat(virBufferPtr buf,
                                virDomainControllerDefPtr def)
{
    virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

    if (def->queues)
        virBufferAsprintf(&driverBuf, " queues='%u'", def->queues);

    if (def->cmd_per_lun)
        virBufferAsprintf(&driverBuf, " cmd_per_lun='%u'", def->cmd_per_lun);

    if (def->max_sectors)
        virBufferAsprintf(&driverBuf, " max_sectors='%u'", def->max_sectors);

    if (def->ioeventfd) {
        virBufferAsprintf(&driverBuf, " ioeventfd='%s'",
                          virTristateSwitchTypeToString(def->ioeventfd));
    }

    if (def->iothread)
        virBufferAsprintf(&driverBuf, " iothread='%u'", def->iothread);

    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);

    if (virBufferUse(&driverBuf)) {
        virBufferAddLit(buf, "<driver");
        virBufferAddBuffer(buf, &driverBuf);
        virBufferAddLit(buf, "/>\n");
    }
}


static int
virDomainControllerDefFormat(virBufferPtr buf,
                             virDomainControllerDefPtr def,
                             unsigned int flags)
{
    const char *type = virDomainControllerTypeToString(def->type);
    const char *model = NULL;
    const char *modelName = NULL;
    virBuffer childBuf = VIR_BUFFER_INITIALIZER;

    virBufferAdjustIndent(&childBuf, virBufferGetIndent(buf, false) + 2);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected controller type %d"), def->type);
        return -1;
    }

    if (def->model != -1) {
        model = virDomainControllerModelTypeToString(def, def->model);

        if (!model) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected model type %d"), def->model);
            return -1;
        }
    }

    virBufferAsprintf(buf,
                      "<controller type='%s' index='%d'",
                      type, def->idx);

    if (model)
        virBufferEscapeString(buf, " model='%s'", model);

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (def->opts.vioserial.ports != -1) {
            virBufferAsprintf(buf, " ports='%d'",
                              def->opts.vioserial.ports);
        }
        if (def->opts.vioserial.vectors != -1) {
            virBufferAsprintf(buf, " vectors='%d'",
                              def->opts.vioserial.vectors);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (def->opts.usbopts.ports != -1) {
            virBufferAsprintf(buf, " ports='%d'",
                              def->opts.usbopts.ports);
        }
        break;

    default:
        break;
    }

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
        if (def->opts.pciopts.modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected model name value %d"),
                               def->opts.pciopts.modelName);
                return -1;
            }
            virBufferAsprintf(&childBuf, "<model name='%s'/>\n", modelName);
        }

        if (def->opts.pciopts.chassisNr != -1 ||
            def->opts.pciopts.chassis != -1 ||
            def->opts.pciopts.port != -1 ||
            def->opts.pciopts.busNr != -1 ||
            def->opts.pciopts.numaNode != -1) {
            virBufferAddLit(&childBuf, "<target");
            if (def->opts.pciopts.chassisNr != -1)
                virBufferAsprintf(&childBuf, " chassisNr='%d'",
                                  def->opts.pciopts.chassisNr);
            if (def->opts.pciopts.chassis != -1)
                virBufferAsprintf(&childBuf, " chassis='%d'",
                                  def->opts.pciopts.chassis);
            if (def->opts.pciopts.port != -1)
                virBufferAsprintf(&childBuf, " port='0x%x'",
                                  def->opts.pciopts.port);
            if (def->opts.pciopts.busNr != -1)
                virBufferAsprintf(&childBuf, " busNr='%d'",
                                  def->opts.pciopts.busNr);
            if (def->opts.pciopts.numaNode == -1) {
                virBufferAddLit(&childBuf, "/>\n");
            } else {
                virBufferAddLit(&childBuf, ">\n");
                virBufferAdjustIndent(&childBuf, 2);
                virBufferAsprintf(&childBuf, "<node>%d</node>\n",
                                  def->opts.pciopts.numaNode);
                virBufferAdjustIndent(&childBuf, -2);
                virBufferAddLit(&childBuf, "</target>\n");
            }
        }
    }

    virDomainControllerDriverFormat(&childBuf, def);

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags) &&
        virDomainDeviceInfoFormat(&childBuf, &def->info, flags) < 0)
        return -1;

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
        def->opts.pciopts.pcihole64) {
        virBufferAsprintf(&childBuf, "<pcihole64 unit='KiB'>%lu</"
                          "pcihole64>\n", def->opts.pciopts.pcihole64size);
    }

    if (virBufferUse(&childBuf)) {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childBuf);
        virBufferAddLit(buf, "</controller>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


int
virDomainFSIndexByName(virDomainDefPtr def, const char *name)
{
    virDomainFSDefPtr fs;
    size_t i;

    for (i = 0; i < def->nfss; i++) {
        fs = def->fss[i];
        if (STREQ(fs->dst, name))
            return i;
    }
    return -1;
}


static int
virDomainFSDefFormat(virBufferPtr buf,
                     virDomainFSDefPtr def,
                     unsigned int flags)
{
    const char *type = virDomainFSTypeToString(def->type);
    const char *accessmode = virDomainFSAccessModeTypeToString(def->accessmode);
    const char *fsdriver = virDomainFSDriverTypeToString(def->fsdriver);
    const char *wrpolicy = virDomainFSWrpolicyTypeToString(def->wrpolicy);
    const char *src = def->src->path;
    virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected filesystem type %d"), def->type);
        return -1;
    }

   if (!accessmode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected accessmode %d"), def->accessmode);
        return -1;
    }


    virBufferAsprintf(buf,
                      "<filesystem type='%s' accessmode='%s'>\n",
                      type, accessmode);
    virBufferAdjustIndent(buf, 2);
    if (def->fsdriver) {
        virBufferAsprintf(&driverBuf, " type='%s'", fsdriver);

        if (def->format)
            virBufferAsprintf(&driverBuf, " format='%s'",
                              virStorageFileFormatTypeToString(def->format));

        /* Don't generate anything if wrpolicy is set to default */
        if (def->wrpolicy)
            virBufferAsprintf(&driverBuf, " wrpolicy='%s'", wrpolicy);

    }

    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);

    if (virBufferUse(&driverBuf)) {
        virBufferAddLit(buf, "<driver");
        virBufferAddBuffer(buf, &driverBuf);
        virBufferAddLit(buf, "/>\n");
    }

    switch (def->type) {
    case VIR_DOMAIN_FS_TYPE_MOUNT:
    case VIR_DOMAIN_FS_TYPE_BIND:
        virBufferEscapeString(buf, "<source dir='%s'/>\n",
                              src);
        break;

    case VIR_DOMAIN_FS_TYPE_BLOCK:
        virBufferEscapeString(buf, "<source dev='%s'/>\n",
                              src);
        break;

    case VIR_DOMAIN_FS_TYPE_FILE:
        virBufferEscapeString(buf, "<source file='%s'/>\n",
                              src);
        break;

    case VIR_DOMAIN_FS_TYPE_TEMPLATE:
        virBufferEscapeString(buf, "<source name='%s'/>\n",
                              src);
        break;

    case VIR_DOMAIN_FS_TYPE_RAM:
        virBufferAsprintf(buf, "<source usage='%lld' units='KiB'/>\n",
                          def->usage / 1024);
        break;

    case VIR_DOMAIN_FS_TYPE_VOLUME:
        virBufferAddLit(buf, "<source");
        virBufferEscapeString(buf, " pool='%s'", def->src->srcpool->pool);
        virBufferEscapeString(buf, " volume='%s'", def->src->srcpool->volume);
        virBufferAddLit(buf, "/>\n");
        break;
    }

    virBufferEscapeString(buf, "<target dir='%s'/>\n",
                          def->dst);

    if (def->readonly)
        virBufferAddLit(buf, "<readonly/>\n");

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;


    if (def->space_hard_limit)
        virBufferAsprintf(buf, "<space_hard_limit unit='bytes'>"
                          "%llu</space_hard_limit>\n", def->space_hard_limit);
    if (def->space_soft_limit) {
        virBufferAsprintf(buf, "<space_soft_limit unit='bytes'>"
                          "%llu</space_soft_limit>\n", def->space_soft_limit);
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</filesystem>\n");
    return 0;
}


static int
virDomainNetIPInfoFormat(virBufferPtr buf,
                         virNetDevIPInfoPtr def)
{
    size_t i;

    /* Output IP addresses */
    for (i = 0; i < def->nips; i++) {
        virSocketAddrPtr address = &def->ips[i]->address;
        char *ipStr = virSocketAddrFormat(address);
        const char *familyStr = NULL;

        if (!ipStr)
            return -1;
        if (VIR_SOCKET_ADDR_IS_FAMILY(address, AF_INET6))
            familyStr = "ipv6";
        else if (VIR_SOCKET_ADDR_IS_FAMILY(address, AF_INET))
            familyStr = "ipv4";
        virBufferAsprintf(buf, "<ip address='%s'",
                          ipStr);
        VIR_FREE(ipStr);
        if (familyStr)
            virBufferAsprintf(buf, " family='%s'", familyStr);
        if (def->ips[i]->prefix)
            virBufferAsprintf(buf, " prefix='%u'", def->ips[i]->prefix);
        if (VIR_SOCKET_ADDR_VALID(&def->ips[i]->peer)) {
            if (!(ipStr = virSocketAddrFormat(&def->ips[i]->peer)))
                return -1;
            virBufferAsprintf(buf, " peer='%s'", ipStr);
            VIR_FREE(ipStr);
        }
        virBufferAddLit(buf, "/>\n");
    }

    for (i = 0; i < def->nroutes; i++)
        if (virNetDevIPRouteFormat(buf, def->routes[i]) < 0)
            return -1;
    return 0;
}


static int
virDomainHostdevDefFormatSubsys(virBufferPtr buf,
                                virDomainHostdevDefPtr def,
                                unsigned int flags,
                                bool includeTypeInAddr)
{
    bool closedSource = false;
    virDomainHostdevSubsysUSBPtr usbsrc = &def->source.subsys.u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &def->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHostPtr hostsrc = &def->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &def->source.subsys.u.mdev;
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &scsisrc->u.iscsi;

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
        pcisrc->backend != VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT) {
        const char *backend =
            virDomainHostdevSubsysPCIBackendTypeToString(pcisrc->backend);

        if (!backend) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected pci hostdev driver name type %d"),
                           pcisrc->backend);
            return -1;
        }
        virBufferAsprintf(buf, "<driver name='%s'/>\n", backend);
    }

    virBufferAddLit(buf, "<source");
    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
        if (def->startupPolicy) {
            const char *policy;
            policy = virDomainStartupPolicyTypeToString(def->startupPolicy);
            virBufferAsprintf(buf, " startupPolicy='%s'", policy);
        }
        if (usbsrc->autoAddress && (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))
            virBufferAddLit(buf, " autoAddress='yes'");

        if (def->missing && !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
            virBufferAddLit(buf, " missing='yes'");
    }

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
        const char *protocol =
            virDomainHostdevSubsysSCSIProtocolTypeToString(scsisrc->protocol);

        virBufferAsprintf(buf, " protocol='%s' name='%s'",
                          protocol, iscsisrc->path);
    }

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST) {
        const char *protocol =
            virDomainHostdevSubsysSCSIHostProtocolTypeToString(hostsrc->protocol);
        closedSource = true;

        virBufferAsprintf(buf, " protocol='%s' wwpn='%s'/",
                          protocol, hostsrc->wwpn);
    }

    virBufferAddLit(buf, ">\n");

    virBufferAdjustIndent(buf, 2);
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (usbsrc->vendor) {
            virBufferAsprintf(buf, "<vendor id='0x%.4x'/>\n", usbsrc->vendor);
            virBufferAsprintf(buf, "<product id='0x%.4x'/>\n", usbsrc->product);
        }
        if (usbsrc->bus || usbsrc->device) {
            virBufferAsprintf(buf, "<address %sbus='%d' device='%d'/>\n",
                              includeTypeInAddr ? "type='usb' " : "",
                              usbsrc->bus, usbsrc->device);
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (virPCIDeviceAddressFormat(buf, pcisrc->addr,
                                      includeTypeInAddr) != 0)
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("PCI address Formatting failed"));

        if ((flags & VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES) &&
            (def->origstates.states.pci.unbind_from_stub ||
             def->origstates.states.pci.remove_slot ||
             def->origstates.states.pci.reprobe)) {
            virBufferAddLit(buf, "<origstates>\n");
            virBufferAdjustIndent(buf, 2);
            if (def->origstates.states.pci.unbind_from_stub)
                virBufferAddLit(buf, "<unbind/>\n");
            if (def->origstates.states.pci.remove_slot)
                virBufferAddLit(buf, "<removeslot/>\n");
            if (def->origstates.states.pci.reprobe)
                virBufferAddLit(buf, "<reprobe/>\n");
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</origstates>\n");
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            virBufferAddLit(buf, "<host");
            virBufferEscapeString(buf, " name='%s'", iscsisrc->hosts[0].name);
            virBufferEscapeString(buf, " port='%s'", iscsisrc->hosts[0].port);
            virBufferAddLit(buf, "/>\n");
        } else {
            virBufferAsprintf(buf, "<adapter name='%s'/>\n",
                              scsihostsrc->adapter);
            virBufferAsprintf(buf,
                              "<address %sbus='%u' target='%u' unit='%llu'/>\n",
                              includeTypeInAddr ? "type='scsi' " : "",
                              scsihostsrc->bus, scsihostsrc->target,
                              scsihostsrc->unit);
        }
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        virBufferAsprintf(buf, "<address uuid='%s'/>\n",
                          mdevsrc->uuidstr);
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev type %d"),
                       def->source.subsys.type);
        return -1;
    }

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
        scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI &&
        iscsisrc->auth) {
        if (virStorageAuthDefFormat(buf, iscsisrc->auth) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    if (!closedSource)
        virBufferAddLit(buf, "</source>\n");

    return 0;
}

static int
virDomainHostdevDefFormatCaps(virBufferPtr buf,
                              virDomainHostdevDefPtr def)
{
    virBufferAddLit(buf, "<source>\n");

    virBufferAdjustIndent(buf, 2);
    switch (def->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        virBufferEscapeString(buf, "<block>%s</block>\n",
                              def->source.caps.u.storage.block);
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        virBufferEscapeString(buf, "<char>%s</char>\n",
                              def->source.caps.u.misc.chardev);
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        virBufferEscapeString(buf, "<interface>%s</interface>\n",
                              def->source.caps.u.net.ifname);
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev type %d"),
                       def->source.caps.type);
        return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</source>\n");

    if (def->source.caps.type == VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET &&
        virDomainNetIPInfoFormat(buf, &def->source.caps.u.net.ip) < 0)
        return -1;

    return 0;
}

/* virDomainActualNetDefContentsFormat() - format just the subelements
 * of <interface> that may be overridden by what is in the
 * virDomainActualNetDef, but inside the current element, rather
 * than enclosed in an <actual> subelement.
 */
static int
virDomainActualNetDefContentsFormat(virBufferPtr buf,
                                    virDomainNetDefPtr def,
                                    bool inSubelement,
                                    unsigned int flags)
{
    virDomainNetType actualType = virDomainNetGetActualType(def);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        if (virDomainHostdevDefFormatSubsys(buf, virDomainNetGetActualHostdev(def),
                                            flags, true) < 0) {
            return -1;
        }
    } else {
        virBufferAddLit(buf, "<source");
        if (def->type == VIR_DOMAIN_NET_TYPE_NETWORK && !inSubelement) {
            /* When we're putting our output into the <actual>
             * subelement rather than the main <interface>, the
             * network name and portgroup don't need to be included in
             * the <source> here because the main interface element's
             * <source> has the same info already. If we've been
             * called to output directly into the main element's
             * <source> though (the case here - "!inSubElement"), we
             * *do* need to output network/portgroup, because the
             * caller won't have done it).
             */
            virBufferEscapeString(buf, " network='%s'",
                                  def->data.network.name);
            virBufferEscapeString(buf, " portgroup='%s'",
                                  def->data.network.portgroup);
        }
        if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
            actualType == VIR_DOMAIN_NET_TYPE_NETWORK) {
            int macTableManager = virDomainNetGetActualBridgeMACTableManager(def);

            /* actualType == NETWORK includes the name of the bridge
             * that is used by the network, whether we are
             * "inSubElement" or not.
             */
            virBufferEscapeString(buf, " bridge='%s'",
                                  virDomainNetGetActualBridgeName(def));
            if (macTableManager) {
                virBufferAsprintf(buf, " macTableManager='%s'",
                                  virNetworkBridgeMACTableManagerTypeToString(macTableManager));
            }
        } else if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
            const char *mode;

            virBufferEscapeString(buf, " dev='%s'",
                                  virDomainNetGetActualDirectDev(def));
            mode = virNetDevMacVLanModeTypeToString(virDomainNetGetActualDirectMode(def));
            if (!mode) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected source mode %d"),
                               virDomainNetGetActualDirectMode(def));
                return -1;
            }
            virBufferAsprintf(buf, " mode='%s'", mode);
        }

        virBufferAddLit(buf, "/>\n");
    }
    if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS &&
        def->data.network.actual && def->data.network.actual->class_id) {
        virBufferAsprintf(buf, "<class id='%u'/>\n",
                          def->data.network.actual->class_id);
    }

    if (virNetDevVlanFormat(virDomainNetGetActualVlan(def), buf) < 0)
        return -1;
    if (virNetDevVPortProfileFormat(virDomainNetGetActualVirtPortProfile(def), buf) < 0)
        return -1;
    if (virNetDevBandwidthFormat(virDomainNetGetActualBandwidth(def), buf) < 0)
        return -1;
    return 0;
}

/* virDomainActualNetDefFormat() - format the ActualNetDef
 * info inside an <actual> element, as required for internal storage
 * of domain status
 */
static int
virDomainActualNetDefFormat(virBufferPtr buf,
                            virDomainNetDefPtr def,
                            unsigned int flags)
{
    virDomainNetType type;
    const char *typeStr;

    if (!def)
        return 0;
    type = virDomainNetGetActualType(def);
    typeStr = virDomainNetTypeToString(type);

    if (!typeStr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected net type %d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<actual type='%s'", typeStr);
    if (type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virDomainHostdevDefPtr hostdef = virDomainNetGetActualHostdev(def);
        if  (hostdef && hostdef->managed)
            virBufferAddLit(buf, " managed='yes'");
    }
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");

    virBufferAdjustIndent(buf, 2);
    if (virDomainActualNetDefContentsFormat(buf, def, true, flags) < 0)
       return -1;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</actual>\n");
    return 0;
}


static int
virDomainVirtioNetGuestOptsFormat(char **outstr,
                                  virDomainNetDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (def->driver.virtio.guest.csum) {
        virBufferAsprintf(&buf, "csum='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.csum));
    }
    if (def->driver.virtio.guest.tso4) {
        virBufferAsprintf(&buf, "tso4='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.tso4));
    }
    if (def->driver.virtio.guest.tso6) {
        virBufferAsprintf(&buf, "tso6='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.tso6));
    }
    if (def->driver.virtio.guest.ecn) {
        virBufferAsprintf(&buf, "ecn='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.ecn));
    }
    if (def->driver.virtio.guest.ufo) {
        virBufferAsprintf(&buf, "ufo='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.ufo));
    }
    virBufferTrim(&buf, " ", -1);

    if (virBufferCheckError(&buf) < 0)
        return -1;

    *outstr = virBufferContentAndReset(&buf);
    return 0;
}


static int
virDomainVirtioNetHostOptsFormat(char **outstr,
                                 virDomainNetDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (def->driver.virtio.host.csum) {
        virBufferAsprintf(&buf, "csum='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.csum));
    }
    if (def->driver.virtio.host.gso) {
        virBufferAsprintf(&buf, "gso='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.gso));
    }
    if (def->driver.virtio.host.tso4) {
        virBufferAsprintf(&buf, "tso4='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.tso4));
    }
    if (def->driver.virtio.host.tso6) {
        virBufferAsprintf(&buf, "tso6='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.tso6));
    }
    if (def->driver.virtio.host.ecn) {
        virBufferAsprintf(&buf, "ecn='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.ecn));
    }
    if (def->driver.virtio.host.ufo) {
        virBufferAsprintf(&buf, "ufo='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.ufo));
    }
    if (def->driver.virtio.host.mrg_rxbuf) {
        virBufferAsprintf(&buf, "mrg_rxbuf='%s' ",
                          virTristateSwitchTypeToString(def->driver.virtio.host.mrg_rxbuf));
    }
    virBufferTrim(&buf, " ", -1);

    if (virBufferCheckError(&buf) < 0)
        return -1;

    *outstr = virBufferContentAndReset(&buf);
    return 0;
}


static int
virDomainVirtioNetDriverFormat(char **outstr,
                               virDomainNetDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (def->driver.virtio.name) {
        virBufferAsprintf(&buf, " name='%s'",
                          virDomainNetBackendTypeToString(def->driver.virtio.name));
    }
    if (def->driver.virtio.txmode) {
        virBufferAsprintf(&buf, " txmode='%s'",
                          virDomainNetVirtioTxModeTypeToString(def->driver.virtio.txmode));
    }
    if (def->driver.virtio.ioeventfd) {
        virBufferAsprintf(&buf, " ioeventfd='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.ioeventfd));
    }
    if (def->driver.virtio.event_idx) {
        virBufferAsprintf(&buf, " event_idx='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.event_idx));
    }
    if (def->driver.virtio.queues)
        virBufferAsprintf(&buf, " queues='%u'", def->driver.virtio.queues);
    if (def->driver.virtio.rx_queue_size)
        virBufferAsprintf(&buf, " rx_queue_size='%u'",
                          def->driver.virtio.rx_queue_size);

    virDomainVirtioOptionsFormat(&buf, def->virtio);

    if (virBufferCheckError(&buf) < 0)
        return -1;

    *outstr = virBufferContentAndReset(&buf);
    return 0;
}


int
virDomainNetDefFormat(virBufferPtr buf,
                      virDomainNetDefPtr def,
                      char *prefix,
                      unsigned int flags)
{
    virDomainNetType actualType = virDomainNetGetActualType(def);
    bool publicActual = false;
    int sourceLines = 0;
    const char *typeStr;
    virDomainHostdevDefPtr hostdef = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];

    /* publicActual is true if we should report the current state in
     * def->data.network.actual *instead of* the config (*not* in
     * addition to)
     */
    if (def->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        def->data.network.actual &&
        !(flags & (VIR_DOMAIN_DEF_FORMAT_INACTIVE |
                   VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                   VIR_DOMAIN_DEF_FORMAT_MIGRATABLE)))
        publicActual = true;

    if (publicActual) {
        if (!(typeStr = virDomainNetTypeToString(actualType))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected actual net type %d"), actualType);
            return -1;
        }
        if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV)
            hostdef = virDomainNetGetActualHostdev(def);
    } else {
        if (!(typeStr = virDomainNetTypeToString(def->type))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected net type %d"), def->type);
            return -1;
        }
        if (def->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)
            hostdef = &def->data.hostdev.def;
    }

    virBufferAsprintf(buf, "<interface type='%s'", typeStr);
    if (hostdef && hostdef->managed)
        virBufferAddLit(buf, " managed='yes'");
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");

    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<mac address='%s'/>\n",
                      virMacAddrFormat(&def->mac, macstr));

    if (publicActual) {
        /* when there is a virDomainActualNetDef, and we haven't been
         * asked to 1) report the domain's inactive XML, or 2) give
         * the internal version of the ActualNetDef separately in an
         * <actual> subelement, we can just put the ActualDef data in
         * the standard place...  (this is for public reporting of
         * interface status)
         */
        if (virDomainActualNetDefContentsFormat(buf, def, false, flags) < 0)
            return -1;
    } else {
        /* ...but if we've asked for the inactive XML (rather than
         * status), or to report the ActualDef as a separate <actual>
         * subelement (this is how we privately store interface
         * status), or there simply *isn't* any ActualNetDef, then
         * format the NetDef's data here, and optionally format the
         * ActualNetDef as an <actual> subelement of this element.
         */
        switch (def->type) {
        case VIR_DOMAIN_NET_TYPE_NETWORK:
            virBufferEscapeString(buf, "<source network='%s'",
                                  def->data.network.name);
            virBufferEscapeString(buf, " portgroup='%s'",
                                  def->data.network.portgroup);
            sourceLines++;
            break;

        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            break;

        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
            if (def->data.vhostuser->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
                virBufferAddLit(buf, "<source type='unix'");
                virBufferEscapeString(buf, " path='%s'",
                                      def->data.vhostuser->data.nix.path);
                virBufferAsprintf(buf, " mode='%s'",
                                  def->data.vhostuser->data.nix.listen ?
                                  "server"  : "client");
                sourceLines++;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_BRIDGE:
           if (def->data.bridge.brname) {
               virBufferEscapeString(buf, "<source bridge='%s'",
                                     def->data.bridge.brname);
               sourceLines++;
           }
            break;

        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
            if (def->data.socket.address) {
                virBufferAsprintf(buf, "<source address='%s' port='%d'",
                                  def->data.socket.address,
                                  def->data.socket.port);
            } else {
                virBufferAsprintf(buf, "<source port='%d'",
                                  def->data.socket.port);
            }
            sourceLines++;

            if (def->type != VIR_DOMAIN_NET_TYPE_UDP)
                break;

            virBufferAddLit(buf, ">\n");
            sourceLines++;
            virBufferAdjustIndent(buf, 2);

            virBufferAsprintf(buf, "<local address='%s' port='%d'/>\n",
                              def->data.socket.localaddr,
                              def->data.socket.localport);
            virBufferAdjustIndent(buf, -2);
            break;

        case VIR_DOMAIN_NET_TYPE_INTERNAL:
            if (def->data.internal.name) {
                virBufferEscapeString(buf, "<source name='%s'",
                                      def->data.internal.name);
                sourceLines++;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            virBufferEscapeString(buf, "<source dev='%s'",
                                  def->data.direct.linkdev);
            virBufferAsprintf(buf, " mode='%s'",
                              virNetDevMacVLanModeTypeToString(def->data.direct.mode));
            sourceLines++;
            break;

        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
            if (virDomainHostdevDefFormatSubsys(buf, &def->data.hostdev.def,
                                                flags, true) < 0) {
                return -1;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }

        /* if sourceLines == 0 - no <source> info at all so far
         *    sourceLines == 1 - first line written, no terminating ">"
         *    sourceLines > 1 - multiple lines, including subelements
         */
        if (def->hostIP.nips || def->hostIP.nroutes) {
            if (sourceLines == 0) {
                virBufferAddLit(buf, "<source>\n");
                sourceLines += 2;
            } else if (sourceLines == 1) {
                virBufferAddLit(buf, ">\n");
                sourceLines++;
            }
            virBufferAdjustIndent(buf, 2);
            if (virDomainNetIPInfoFormat(buf, &def->hostIP) < 0)
                return -1;
            virBufferAdjustIndent(buf, -2);
        }
        if (sourceLines == 1)
            virBufferAddLit(buf, "/>\n");
        else if (sourceLines > 1)
            virBufferAddLit(buf, "</source>\n");

        if (virNetDevVlanFormat(&def->vlan, buf) < 0)
            return -1;
        if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
            return -1;
        if (virNetDevBandwidthFormat(def->bandwidth, buf) < 0)
            return -1;

        /* ONLY for internal status storage - format the ActualNetDef
         * as a subelement of <interface> so that no persistent config
         * data is overwritten.
         */
        if (def->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
            (flags & VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET) &&
            (virDomainActualNetDefFormat(buf, def, flags) < 0))
            return -1;

    }

    if (virDomainNetIPInfoFormat(buf, &def->guestIP) < 0)
        return -1;

    virBufferEscapeString(buf, "<script path='%s'/>\n",
                          def->script);
    virBufferEscapeString(buf, "<backenddomain name='%s'/>\n", def->domain_name);

    if (def->ifname &&
        !((flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE) &&
          (STRPREFIX(def->ifname, VIR_NET_GENERATED_TAP_PREFIX) ||
           (prefix && STRPREFIX(def->ifname, prefix))))) {
        /* Skip auto-generated target names for inactive config. */
        virBufferEscapeString(buf, "<target dev='%s'/>\n", def->ifname);
    }

    if (def->ifname_guest || def->ifname_guest_actual) {
        virBufferAddLit(buf, "<guest");
        /* Skip auto-generated target names for inactive config. */
        if (def->ifname_guest)
            virBufferEscapeString(buf, " dev='%s'", def->ifname_guest);

        /* Only set if the host is running, so shouldn't pollute output */
        if (def->ifname_guest_actual)
            virBufferEscapeString(buf, " actual='%s'", def->ifname_guest_actual);
        virBufferAddLit(buf, "/>\n");
    }
    if (def->model) {
        virBufferEscapeString(buf, "<model type='%s'/>\n",
                              def->model);
        if (STREQ(def->model, "virtio")) {
            char *str = NULL, *gueststr = NULL, *hoststr = NULL;
            int rc = 0;

            if (virDomainVirtioNetDriverFormat(&str, def) < 0 ||
                virDomainVirtioNetGuestOptsFormat(&gueststr, def) < 0 ||
                virDomainVirtioNetHostOptsFormat(&hoststr, def) < 0)
                rc = -1;

            if (!gueststr && !hoststr) {
                if (str)
                    virBufferAsprintf(buf, "<driver%s/>\n", str);
            } else {
                if (str)
                    virBufferAsprintf(buf, "<driver%s>\n", str);
                else
                    virBufferAddLit(buf, "<driver>\n");
                virBufferAdjustIndent(buf, 2);
                if (hoststr)
                    virBufferAsprintf(buf, "<host %s/>\n", hoststr);
                if (gueststr)
                    virBufferAsprintf(buf, "<guest %s/>\n", gueststr);
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</driver>\n");
            }
            VIR_FREE(str);
            VIR_FREE(hoststr);
            VIR_FREE(gueststr);

            if (rc < 0)
                return -1;
        }
    }
    if (def->backend.tap || def->backend.vhost) {
        virBufferAddLit(buf, "<backend");
        virBufferEscapeString(buf, " tap='%s'", def->backend.tap);
        virBufferEscapeString(buf, " vhost='%s'", def->backend.vhost);
        virBufferAddLit(buf, "/>\n");
    }
    if (def->filter) {
        if (virNWFilterFormatParamAttributes(buf, def->filterparams,
                                             def->filter) < 0)
            return -1;
    }

    if (def->tune.sndbuf_specified) {
        virBufferAddLit(buf,   "<tune>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<sndbuf>%lu</sndbuf>\n", def->tune.sndbuf);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf,   "</tune>\n");
    }

    if (def->linkstate) {
        virBufferAsprintf(buf, "<link state='%s'/>\n",
                          virDomainNetInterfaceLinkStateTypeToString(def->linkstate));
    }

    if (def->mtu)
        virBufferAsprintf(buf, "<mtu size='%u'/>\n", def->mtu);

    virDomainNetDefCoalesceFormatXML(buf, def->coalesce);

    if (virDomainDeviceInfoFormat(buf, &def->info,
                                  flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT
                                  | VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</interface>\n");
    return 0;
}


/* Assumes that "<device" has already been generated, and starts
 * output at " type='type'>". */
static int
virDomainChrSourceDefFormat(virBufferPtr buf,
                            virDomainChrDefPtr chr_def,
                            virDomainChrSourceDefPtr def,
                            bool tty_compat,
                            unsigned int flags)
{
    const char *type = virDomainChrTypeToString(def->type);
    size_t nseclabels = 0;
    virSecurityDeviceLabelDefPtr *seclabels = NULL;

    if (chr_def) {
        nseclabels = chr_def->nseclabels;
        seclabels = chr_def->seclabels;
    }

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected char type %d"), def->type);
        return -1;
    }

    /* Compat with legacy <console tty='/dev/pts/5'/> syntax */
    virBufferAsprintf(buf, " type='%s'", type);
    if (tty_compat) {
        virBufferEscapeString(buf, " tty='%s'",
                              def->data.file.path);
    }
    virBufferAddLit(buf, ">\n");

    switch ((virDomainChrType)def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        /* nada */
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (def->type != VIR_DOMAIN_CHR_TYPE_PTY ||
            (def->data.file.path &&
             !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))) {
            virBufferEscapeString(buf, "<source path='%s'",
                                  def->data.file.path);
            if (def->type == VIR_DOMAIN_CHR_TYPE_FILE &&
                def->data.file.append != VIR_TRISTATE_SWITCH_ABSENT)
                virBufferAsprintf(buf, " append='%s'",
                    virTristateSwitchTypeToString(def->data.file.append));
            virDomainSourceDefFormatSeclabel(buf, nseclabels, seclabels, flags);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        virBufferEscapeString(buf, "<source master='%s' ",
                              def->data.nmdm.master);
        virBufferEscapeString(buf, "slave='%s'/>\n", def->data.nmdm.slave);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (def->data.udp.bindService || def->data.udp.bindHost) {
            virBufferAddLit(buf, "<source mode='bind'");
            if (def->data.udp.bindService)
                virBufferEscapeString(buf, " host='%s'", def->data.udp.bindHost);
            if (def->data.udp.bindService)
                virBufferEscapeString(buf, " service='%s'", def->data.udp.bindService);
            virBufferAddLit(buf, "/>\n");
        }

        if (def->data.udp.connectService || def->data.udp.connectHost) {
            virBufferAddLit(buf, "<source mode='connect'");
            if (def->data.udp.connectService)
                virBufferEscapeString(buf, " host='%s'", def->data.udp.connectHost);
            if (def->data.udp.connectService)
                virBufferEscapeString(buf, " service='%s'", def->data.udp.connectService);
            virBufferAddLit(buf, "/>\n");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferAsprintf(buf, "<source mode='%s' ",
                          def->data.tcp.listen ? "bind" : "connect");
        virBufferEscapeString(buf, "host='%s' ", def->data.tcp.host);
        virBufferEscapeString(buf, "service='%s'", def->data.tcp.service);
        if (def->data.tcp.haveTLS != VIR_TRISTATE_BOOL_ABSENT &&
            !(flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE &&
              def->data.tcp.tlsFromConfig))
            virBufferAsprintf(buf, " tls='%s'",
                    virTristateBoolTypeToString(def->data.tcp.haveTLS));
        if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS)
            virBufferAsprintf(buf, " tlsFromConfig='%d'",
                              def->data.tcp.tlsFromConfig);
        virBufferAddLit(buf, "/>\n");

        virBufferAsprintf(buf, "<protocol type='%s'/>\n",
                          virDomainChrTcpProtocolTypeToString(
                              def->data.tcp.protocol));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (def->data.nix.path) {
            virBufferAsprintf(buf, "<source mode='%s'",
                              def->data.nix.listen ? "bind" : "connect");
            virBufferEscapeString(buf, " path='%s'", def->data.nix.path);
            virDomainSourceDefFormatSeclabel(buf, nseclabels, seclabels, flags);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        virBufferEscapeString(buf, "<source channel='%s'/>\n",
                              def->data.spiceport.channel);
        break;

    }

    if (def->logfile) {
        virBufferEscapeString(buf, "<log file='%s'", def->logfile);
        if (def->logappend != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(buf, " append='%s'",
                              virTristateSwitchTypeToString(def->logappend));
        }
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

static int
virDomainChrDefFormat(virBufferPtr buf,
                      virDomainChrDefPtr def,
                      unsigned int flags)
{
    const char *elementName = virDomainChrDeviceTypeToString(def->deviceType);
    const char *targetType = virDomainChrTargetTypeToString(def->deviceType,
                                                            def->targetType);
    bool tty_compat;

    int ret = 0;

    if (!elementName) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected char device type %d"),
                       def->deviceType);
        return -1;
    }

    virBufferAsprintf(buf, "<%s", elementName);
    virBufferAdjustIndent(buf, 2);
    tty_compat = (def->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
                  def->target.port == 0 &&
                  def->source->type == VIR_DOMAIN_CHR_TYPE_PTY &&
                  !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE) &&
                  def->source->data.file.path);
    if (virDomainChrSourceDefFormat(buf, def, def->source, tty_compat, flags) < 0)
        return -1;

    /* Format <target> block */
    switch (def->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL: {
        if (!targetType) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not format channel target type"));
            return -1;
        }
        virBufferAsprintf(buf, "<target type='%s'", targetType);

        switch (def->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD: {
            int port = virSocketAddrGetPort(def->target.addr);
            if (port < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to format guestfwd port"));
                return -1;
            }

            char *addr = virSocketAddrFormat(def->target.addr);
            if (addr == NULL)
                return -1;

            virBufferAsprintf(buf, " address='%s' port='%d'",
                              addr, port);
            VIR_FREE(addr);
            break;
        }

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            if (def->target.name)
                virBufferEscapeString(buf, " name='%s'", def->target.name);

            if (def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
                def->state != VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT &&
                !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
                virBufferAsprintf(buf, " state='%s'",
                                  virDomainChrDeviceStateTypeToString(def->state));
            }
            break;
        }

        virBufferAddLit(buf, "/>\n");
        break;
    }

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        virBufferAsprintf(buf,
                          "<target type='%s' port='%d'/>\n",
                          virDomainChrTargetTypeToString(def->deviceType,
                                                         def->targetType),
                          def->target.port);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        if (def->targetTypeAttr) {
            virBufferAsprintf(buf,
                              "<target type='%s' port='%d'/>\n",
                              virDomainChrTargetTypeToString(def->deviceType,
                                                             def->targetType),
                              def->target.port);
            break;
        }
        ATTRIBUTE_FALLTHROUGH;

    default:
        virBufferAsprintf(buf, "<target port='%d'/>\n",
                          def->target.port);
        break;
    }

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAsprintf(buf, "</%s>\n", elementName);

    return ret;
}

static int
virDomainSmartcardDefFormat(virBufferPtr buf,
                            virDomainSmartcardDefPtr def,
                            unsigned int flags)
{
    const char *mode = virDomainSmartcardTypeToString(def->type);
    size_t i;

    if (!mode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected smartcard type %d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<smartcard mode='%s'", mode);
    virBufferAdjustIndent(buf, 2);
    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        if (!virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "/>\n");
            return 0;
        }
        virBufferAddLit(buf, ">\n");
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        virBufferAddLit(buf, ">\n");
        for (i = 0; i < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; i++)
            virBufferEscapeString(buf, "<certificate>%s</certificate>\n",
                                  def->data.cert.file[i]);
        virBufferEscapeString(buf, "<database>%s</database>\n",
                              def->data.cert.database);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        if (virDomainChrSourceDefFormat(buf, NULL, def->data.passthru, false,
                                        flags) < 0)
            return -1;
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected smartcard type %d"), def->type);
        return -1;
    }
    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</smartcard>\n");
    return 0;
}

static int
virDomainSoundCodecDefFormat(virBufferPtr buf,
                             virDomainSoundCodecDefPtr def)
{
    const char *type = virDomainSoundCodecTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected codec type %d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<codec type='%s'/>\n",  type);

    return 0;
}

static int
virDomainTPMDefFormat(virBufferPtr buf,
                      virDomainTPMDefPtr def,
                      unsigned int flags)
{
    virBufferAsprintf(buf, "<tpm model='%s'>\n",
                      virDomainTPMModelTypeToString(def->model));
    virBufferAdjustIndent(buf, 2);
    virBufferAsprintf(buf, "<backend type='%s'>\n",
                      virDomainTPMBackendTypeToString(def->type));
    virBufferAdjustIndent(buf, 2);

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        virBufferEscapeString(buf, "<device path='%s'/>\n",
                              def->data.passthrough.source.data.file.path);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</backend>\n");

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</tpm>\n");

    return 0;
}


static int
virDomainSoundDefFormat(virBufferPtr buf,
                        virDomainSoundDefPtr def,
                        unsigned int flags)
{
    const char *model = virDomainSoundModelTypeToString(def->model);
    bool children = false;
    size_t i;

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected sound model %d"), def->model);
        return -1;
    }

    virBufferAsprintf(buf, "<sound model='%s'",  model);

    for (i = 0; i < def->ncodecs; i++) {
        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }
        virDomainSoundCodecDefFormat(buf, def->codecs[i]);
    }

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
    }

    if (children) {
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</sound>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static int
virDomainMemballoonDefFormat(virBufferPtr buf,
                             virDomainMemballoonDefPtr def,
                             unsigned int flags)
{
    const char *model = virDomainMemballoonModelTypeToString(def->model);
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    int indent = virBufferGetIndent(buf, false);

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected memballoon model %d"), def->model);
        return -1;
    }

    virBufferAsprintf(buf, "<memballoon model='%s'", model);

    if (def->autodeflate != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, " autodeflate='%s'",
                          virTristateSwitchTypeToString(def->autodeflate));

    virBufferAdjustIndent(&childrenBuf, indent + 2);

    if (def->period)
        virBufferAsprintf(&childrenBuf, "<stats period='%i'/>\n", def->period);

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags) &&
        virDomainDeviceInfoFormat(&childrenBuf, &def->info, flags) < 0) {
        virBufferFreeAndReset(&childrenBuf);
        return -1;
    }

    if (def->virtio) {
        virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

        virDomainVirtioOptionsFormat(&driverBuf, def->virtio);

        if (virBufferCheckError(&driverBuf) < 0) {
            virBufferFreeAndReset(&childrenBuf);
            return -1;
        }
        if (virBufferUse(&driverBuf)) {
            virBufferAddLit(&childrenBuf, "<driver");
            virBufferAddBuffer(&childrenBuf, &driverBuf);
            virBufferAddLit(&childrenBuf, "/>\n");
        }
    }

    if (!virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, "/>\n");
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childrenBuf);
        virBufferAddLit(buf, "</memballoon>\n");
    }

    return 0;
}

static int
virDomainNVRAMDefFormat(virBufferPtr buf,
                        virDomainNVRAMDefPtr def,
                        unsigned int flags)
{
    virBufferAddLit(buf, "<nvram>\n");
    virBufferAdjustIndent(buf, 2);
    if (virDomainDeviceInfoNeedsFormat(&def->info, flags) &&
        virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</nvram>\n");

    return 0;
}


static int
virDomainWatchdogDefFormat(virBufferPtr buf,
                           virDomainWatchdogDefPtr def,
                           unsigned int flags)
{
    const char *model = virDomainWatchdogModelTypeToString(def->model);
    const char *action = virDomainWatchdogActionTypeToString(def->action);

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected watchdog model %d"), def->model);
        return -1;
    }

    if (!action) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected watchdog action %d"), def->action);
        return -1;
    }

    virBufferAsprintf(buf, "<watchdog model='%s' action='%s'",
                      model, action);

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</watchdog>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

static int virDomainPanicDefFormat(virBufferPtr buf,
                                   virDomainPanicDefPtr def)
{
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    int indent = virBufferGetIndent(buf, false);

    virBufferAddLit(buf, "<panic");

    if (def->model)
        virBufferAsprintf(buf, " model='%s'",
                          virDomainPanicModelTypeToString(def->model));

    virBufferAdjustIndent(&childrenBuf, indent + 2);
    if (virDomainDeviceInfoFormat(&childrenBuf, &def->info, 0) < 0)
        return -1;
    if (virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childrenBuf);
        virBufferAddLit(buf, "</panic>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    virBufferFreeAndReset(&childrenBuf);
    return 0;
}

static int
virDomainShmemDefFormat(virBufferPtr buf,
                        virDomainShmemDefPtr def,
                        unsigned int flags)
{
    virBufferEscapeString(buf, "<shmem name='%s'>\n", def->name);

    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<model type='%s'/>\n",
                      virDomainShmemModelTypeToString(def->model));

    if (def->size)
        virBufferAsprintf(buf, "<size unit='M'>%llu</size>\n", def->size >> 20);

    if (def->server.enabled) {
        virBufferAddLit(buf, "<server");
        virBufferEscapeString(buf, " path='%s'", def->server.chr.data.nix.path);
        virBufferAddLit(buf, "/>\n");
    }

    if (def->msi.enabled) {
        virBufferAddLit(buf, "<msi");
        if (def->msi.vectors)
            virBufferAsprintf(buf, " vectors='%u'", def->msi.vectors);
        if (def->msi.ioeventfd)
            virBufferAsprintf(buf, " ioeventfd='%s'",
                              virTristateSwitchTypeToString(def->msi.ioeventfd));
        virBufferAddLit(buf, "/>\n");
    }

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</shmem>\n");

    return 0;
}

static int
virDomainRNGDefFormat(virBufferPtr buf,
                      virDomainRNGDefPtr def,
                      unsigned int flags)
{
    const char *model = virDomainRNGModelTypeToString(def->model);
    const char *backend = virDomainRNGBackendTypeToString(def->backend);
    virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(buf, "<rng model='%s'>\n", model);
    virBufferAdjustIndent(buf, 2);
    if (def->rate) {
        virBufferAsprintf(buf, "<rate bytes='%u'", def->rate);
        if (def->period)
            virBufferAsprintf(buf, " period='%u'", def->period);
        virBufferAddLit(buf, "/>\n");
    }
    virBufferAsprintf(buf, "<backend model='%s'", backend);

    switch ((virDomainRNGBackend) def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        virBufferEscapeString(buf, ">%s</backend>\n", def->source.file);
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        virBufferAdjustIndent(buf, 2);
        if (virDomainChrSourceDefFormat(buf, NULL, def->source.chardev,
                                        false, flags) < 0)
            return -1;
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</backend>\n");

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);
    if (virBufferCheckError(&driverBuf) < 0)
        return -1;

    if (virBufferUse(&driverBuf)) {
        virBufferAddLit(buf, "<driver");
        virBufferAddBuffer(buf, &driverBuf);
        virBufferAddLit(buf, "/>\n");
    }

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</rng>\n");
    return 0;
}

void
virDomainRNGDefFree(virDomainRNGDefPtr def)
{
    if (!def)
        return;

    switch ((virDomainRNGBackend) def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        VIR_FREE(def->source.file);
        break;
    case VIR_DOMAIN_RNG_BACKEND_EGD:
        virDomainChrSourceDefFree(def->source.chardev);
        break;
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    virDomainDeviceInfoClear(&def->info);
    VIR_FREE(def->virtio);
    VIR_FREE(def);
}


static int
virDomainMemorySourceDefFormat(virBufferPtr buf,
                               virDomainMemoryDefPtr def)
{
    char *bitmap = NULL;
    int ret = -1;

    if (!def->pagesize && !def->sourceNodes && !def->nvdimmPath)
        return 0;

    virBufferAddLit(buf, "<source>\n");
    virBufferAdjustIndent(buf, 2);

    switch ((virDomainMemoryModel) def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        if (def->sourceNodes) {
            if (!(bitmap = virBitmapFormat(def->sourceNodes)))
                goto cleanup;

            virBufferAsprintf(buf, "<nodemask>%s</nodemask>\n", bitmap);
        }

        if (def->pagesize)
            virBufferAsprintf(buf, "<pagesize unit='KiB'>%llu</pagesize>\n",
                              def->pagesize);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        virBufferEscapeString(buf, "<path>%s</path>\n", def->nvdimmPath);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</source>\n");

    ret = 0;

 cleanup:
    VIR_FREE(bitmap);
    return ret;
}


static void
virDomainMemoryTargetDefFormat(virBufferPtr buf,
                               virDomainMemoryDefPtr def)
{
    virBufferAddLit(buf, "<target>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<size unit='KiB'>%llu</size>\n", def->size);
    if (def->targetNode >= 0)
        virBufferAsprintf(buf, "<node>%d</node>\n", def->targetNode);
    if (def->labelsize) {
        virBufferAddLit(buf, "<label>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<size unit='KiB'>%llu</size>\n", def->labelsize);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</label>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</target>\n");
}

static int
virDomainMemoryDefFormat(virBufferPtr buf,
                         virDomainMemoryDefPtr def,
                         unsigned int flags)
{
    const char *model = virDomainMemoryModelTypeToString(def->model);

    virBufferAsprintf(buf, "<memory model='%s'", model);
    if (def->access)
        virBufferAsprintf(buf, " access='%s'",
                          virDomainMemoryAccessTypeToString(def->access));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (virDomainMemorySourceDefFormat(buf, def) < 0)
        return -1;

    virDomainMemoryTargetDefFormat(buf, def);

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</memory>\n");
    return 0;
}

static void
virDomainVideoAccelDefFormat(virBufferPtr buf,
                             virDomainVideoAccelDefPtr def)
{
    virBufferAddLit(buf, "<acceleration");
    if (def->accel3d) {
        virBufferAsprintf(buf, " accel3d='%s'",
                          virTristateBoolTypeToString(def->accel3d));
    }
    if (def->accel2d) {
        virBufferAsprintf(buf, " accel2d='%s'",
                          virTristateBoolTypeToString(def->accel2d));
    }
    virBufferAddLit(buf, "/>\n");
}


static int
virDomainVideoDefFormat(virBufferPtr buf,
                        virDomainVideoDefPtr def,
                        unsigned int flags)
{
    const char *model = virDomainVideoTypeToString(def->type);
    virBuffer driverBuf = VIR_BUFFER_INITIALIZER;

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected video model %d"), def->type);
        return -1;
    }

    virBufferAddLit(buf, "<video>\n");
    virBufferAdjustIndent(buf, 2);
    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);
    if (virBufferCheckError(&driverBuf) < 0)
        return -1;
    if (virBufferUse(&driverBuf)) {
        virBufferAddLit(buf, "<driver");
        virBufferAddBuffer(buf, &driverBuf);
        virBufferAddLit(buf, "/>\n");
    }
    virBufferAsprintf(buf, "<model type='%s'",
                      model);
    if (def->ram)
        virBufferAsprintf(buf, " ram='%u'", def->ram);
    if (def->vram)
        virBufferAsprintf(buf, " vram='%u'", def->vram);
    if (def->vram64)
        virBufferAsprintf(buf, " vram64='%u'", def->vram64);
    if (def->vgamem)
        virBufferAsprintf(buf, " vgamem='%u'", def->vgamem);
    if (def->heads)
        virBufferAsprintf(buf, " heads='%u'", def->heads);
    if (def->primary)
        virBufferAddLit(buf, " primary='yes'");
    if (def->accel) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virDomainVideoAccelDefFormat(buf, def->accel);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</model>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</video>\n");
    return 0;
}

static int
virDomainInputDefFormat(virBufferPtr buf,
                        virDomainInputDefPtr def,
                        unsigned int flags)
{
    const char *type = virDomainInputTypeToString(def->type);
    const char *bus = virDomainInputBusTypeToString(def->bus);
    virBuffer childbuf = VIR_BUFFER_INITIALIZER;

    /* don't format keyboard into migratable XML for backward compatibility */
    if (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE &&
        def->type == VIR_DOMAIN_INPUT_TYPE_KBD &&
        (def->bus == VIR_DOMAIN_INPUT_BUS_PS2 ||
         def->bus == VIR_DOMAIN_INPUT_BUS_XEN))
        return 0;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected input type %d"), def->type);
        return -1;
    }
    if (!bus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected input bus type %d"), def->bus);
        return -1;
    }

    virBufferAsprintf(buf, "<input type='%s' bus='%s'",
                      type, bus);

    virBufferAdjustIndent(&childbuf, virBufferGetIndent(buf, false) + 2);
    virBufferEscapeString(&childbuf, "<source evdev='%s'/>\n", def->source.evdev);
    if (virDomainDeviceInfoFormat(&childbuf, &def->info, flags) < 0)
        return -1;

    if (!virBufferUse(&childbuf)) {
        virBufferAddLit(buf, "/>\n");
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childbuf);
        virBufferAddLit(buf, "</input>\n");
    }

    return 0;
}


static int
virDomainTimerDefFormat(virBufferPtr buf,
                        virDomainTimerDefPtr def)
{
    const char *name = virDomainTimerNameTypeToString(def->name);

    if (!name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected timer name %d"), def->name);
        return -1;
    }
    virBufferAsprintf(buf, "<timer name='%s'", name);

    if (def->present == 0) {
        virBufferAddLit(buf, " present='no'");
    } else if (def->present == 1) {
        virBufferAddLit(buf, " present='yes'");
    }

    if (def->tickpolicy != -1) {
        const char *tickpolicy
            = virDomainTimerTickpolicyTypeToString(def->tickpolicy);
        if (!tickpolicy) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected timer tickpolicy %d"),
                           def->tickpolicy);
            return -1;
        }
        virBufferAsprintf(buf, " tickpolicy='%s'", tickpolicy);
    }

    if ((def->name == VIR_DOMAIN_TIMER_NAME_PLATFORM)
        || (def->name == VIR_DOMAIN_TIMER_NAME_RTC)) {
        if (def->track != -1) {
            const char *track
                = virDomainTimerTrackTypeToString(def->track);
            if (!track) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected timer track %d"),
                               def->track);
                return -1;
            }
            virBufferAsprintf(buf, " track='%s'", track);
        }
    }

    if (def->name == VIR_DOMAIN_TIMER_NAME_TSC) {
        if (def->frequency > 0)
            virBufferAsprintf(buf, " frequency='%lu'", def->frequency);

        if (def->mode != -1) {
            const char *mode
                = virDomainTimerModeTypeToString(def->mode);
            if (!mode) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected timer mode %d"),
                               def->mode);
                return -1;
            }
            virBufferAsprintf(buf, " mode='%s'", mode);
        }
    }

    if (def->catchup.threshold == 0 && def->catchup.slew == 0 &&
        def->catchup.limit == 0) {
        virBufferAddLit(buf, "/>\n");
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAddLit(buf, "<catchup");
        if (def->catchup.threshold > 0)
            virBufferAsprintf(buf, " threshold='%lu'", def->catchup.threshold);
        if (def->catchup.slew > 0)
            virBufferAsprintf(buf, " slew='%lu'", def->catchup.slew);
        if (def->catchup.limit > 0)
            virBufferAsprintf(buf, " limit='%lu'", def->catchup.limit);
        virBufferAddLit(buf, "/>\n");
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</timer>\n");
    }

    return 0;
}

static void
virDomainGraphicsAuthDefFormatAttr(virBufferPtr buf,
                                   virDomainGraphicsAuthDefPtr def,
                                   unsigned int flags)
{
    if (!def->passwd)
        return;

    if (flags & VIR_DOMAIN_DEF_FORMAT_SECURE)
        virBufferEscapeString(buf, " passwd='%s'",
                              def->passwd);

    if (def->expires) {
        char strbuf[100];
        struct tm tmbuf, *tm;
        tm = gmtime_r(&def->validTo, &tmbuf);
        strftime(strbuf, sizeof(strbuf), "%Y-%m-%dT%H:%M:%S", tm);
        virBufferAsprintf(buf, " passwdValidTo='%s'", strbuf);
    }

    if (def->connected)
        virBufferEscapeString(buf, " connected='%s'",
                              virDomainGraphicsAuthConnectedTypeToString(def->connected));
}


static void
virDomainGraphicsListenDefFormat(virBufferPtr buf,
                                 virDomainGraphicsListenDefPtr def,
                                 unsigned int flags)
{
    /* If generating migratable XML, skip listen address
     * dragged in from config file */
    if ((flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE) && def->fromConfig)
        return;

    virBufferAddLit(buf, "<listen");
    virBufferAsprintf(buf, " type='%s'",
                      virDomainGraphicsListenTypeToString(def->type));

    if (def->address &&
        (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS ||
         (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK &&
          !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)))) {
        /* address may also be set to show current status when type='network',
         * but we don't want to print that if INACTIVE data is requested. */
        virBufferAsprintf(buf, " address='%s'", def->address);
    }

    if (def->network &&
        (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK)) {
        virBufferEscapeString(buf, " network='%s'", def->network);
    }

    if (def->socket &&
        def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET &&
        !(def->autoGenerated &&
          (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))) {
        virBufferEscapeString(buf, " socket='%s'", def->socket);
    }

    if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS) {
        virBufferAsprintf(buf, " fromConfig='%d'", def->fromConfig);
        virBufferAsprintf(buf, " autoGenerated='%s'",
                          def->autoGenerated ? "yes" : "no");
    }

    virBufferAddLit(buf, "/>\n");
}


/**
 * virDomainGraphicsListenDefFormatAddr:
 * @buf: buffer where the output XML is written
 * @glisten: first listen element
 * @flags: bit-wise or of VIR_DOMAIN_DEF_FORMAT_*
 *
 * This is used to add a legacy 'listen' attribute into <graphics> element to
 * improve backward compatibility.
 */
static void
virDomainGraphicsListenDefFormatAddr(virBufferPtr buf,
                                     virDomainGraphicsListenDefPtr glisten,
                                     unsigned int flags)
{
    if (!glisten)
        return;

    if (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE && glisten->fromConfig)
        return;

    if (glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK &&
        flags & (VIR_DOMAIN_DEF_FORMAT_INACTIVE |
                 VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))
        return;

    if (glisten->address)
        virBufferAsprintf(buf, " listen='%s'", glisten->address);
}

static void
virDomainSpiceGLDefFormat(virBufferPtr buf, virDomainGraphicsDefPtr def)
{
    if (def->data.spice.gl == VIR_TRISTATE_BOOL_ABSENT)
        return;

    virBufferAsprintf(buf, "<gl enable='%s'",
                      virTristateBoolTypeToString(def->data.spice.gl));
    virBufferEscapeString(buf, " rendernode='%s'", def->data.spice.rendernode);
    virBufferAddLit(buf, "/>\n");
}

static int
virDomainGraphicsDefFormat(virBufferPtr buf,
                           virDomainGraphicsDefPtr def,
                           unsigned int flags)
{
    virDomainGraphicsListenDefPtr glisten = virDomainGraphicsGetListen(def, 0);
    const char *type = virDomainGraphicsTypeToString(def->type);
    bool children = false;
    size_t i;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected net type %d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<graphics type='%s'", type);

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (!glisten) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing listen element for graphics"));
            return -1;
        }

        switch (glisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            /* To not break migration we shouldn't print the 'socket' attribute
             * if it's auto-generated or if it's based on config option from
             * qemu.conf.  If the socket is provided by user we need to print it
             * into migratable XML. */
            if (glisten->socket &&
                !((glisten->autoGenerated || glisten->fromConfig) &&
                  (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))) {
                virBufferEscapeString(buf, " socket='%s'", glisten->socket);
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (def->data.vnc.port &&
                (!def->data.vnc.autoport || !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)))
                virBufferAsprintf(buf, " port='%d'",
                                  def->data.vnc.port);
            else if (def->data.vnc.autoport)
                virBufferAddLit(buf, " port='-1'");

            virBufferAsprintf(buf, " autoport='%s'",
                              def->data.vnc.autoport ? "yes" : "no");

            if (def->data.vnc.websocketGenerated &&
                (flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
                virBufferAddLit(buf, " websocket='-1'");
            else if (def->data.vnc.websocket)
                virBufferAsprintf(buf, " websocket='%d'", def->data.vnc.websocket);

            virDomainGraphicsListenDefFormatAddr(buf, glisten, flags);
            break;
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
            break;
        }

        if (def->data.vnc.keymap)
            virBufferEscapeString(buf, " keymap='%s'",
                                  def->data.vnc.keymap);

        if (def->data.vnc.sharePolicy)
            virBufferAsprintf(buf, " sharePolicy='%s'",
                              virDomainGraphicsVNCSharePolicyTypeToString(
                              def->data.vnc.sharePolicy));

        virDomainGraphicsAuthDefFormatAttr(buf, &def->data.vnc.auth, flags);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        if (def->data.sdl.display)
            virBufferEscapeString(buf, " display='%s'",
                                  def->data.sdl.display);

        if (def->data.sdl.xauth)
            virBufferEscapeString(buf, " xauth='%s'",
                                  def->data.sdl.xauth);
        if (def->data.sdl.fullscreen)
            virBufferAddLit(buf, " fullscreen='yes'");

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        if (def->data.rdp.port)
            virBufferAsprintf(buf, " port='%d'",
                              def->data.rdp.port);
        else if (def->data.rdp.autoport)
            virBufferAddLit(buf, " port='0'");

        if (def->data.rdp.autoport)
            virBufferAddLit(buf, " autoport='yes'");

        if (def->data.rdp.replaceUser)
            virBufferAddLit(buf, " replaceUser='yes'");

        if (def->data.rdp.multiUser)
            virBufferAddLit(buf, " multiUser='yes'");

        virDomainGraphicsListenDefFormatAddr(buf, glisten, flags);

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        if (def->data.desktop.display)
            virBufferEscapeString(buf, " display='%s'",
                                  def->data.desktop.display);

        if (def->data.desktop.fullscreen)
            virBufferAddLit(buf, " fullscreen='yes'");

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (!glisten) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing listen element for spice graphics"));
            return -1;
        }

        switch (glisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (def->data.spice.port)
                virBufferAsprintf(buf, " port='%d'",
                                  def->data.spice.port);

            if (def->data.spice.tlsPort)
                virBufferAsprintf(buf, " tlsPort='%d'",
                                  def->data.spice.tlsPort);

            virBufferAsprintf(buf, " autoport='%s'",
                              def->data.spice.autoport ? "yes" : "no");

            virDomainGraphicsListenDefFormatAddr(buf, glisten, flags);
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
            if (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE)
                virBufferAddStr(buf, " autoport='no'");
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
            break;
        }

        if (def->data.spice.keymap)
            virBufferEscapeString(buf, " keymap='%s'",
                                  def->data.spice.keymap);

        if (def->data.spice.defaultMode != VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY)
            virBufferAsprintf(buf, " defaultMode='%s'",
              virDomainGraphicsSpiceChannelModeTypeToString(def->data.spice.defaultMode));

        virDomainGraphicsAuthDefFormatAttr(buf, &def->data.spice.auth, flags);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    for (i = 0; i < def->nListens; i++) {
        if (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE) {
            /* If the listen is based on config options from qemu.conf we need
             * to skip it.  It's up to user to properly configure both hosts for
             * migration. */
            if (def->listens[i].fromConfig)
                continue;

            /* If the socket is provided by user in the XML we need to skip this
             * listen type to support migration back to old libvirt since old
             * libvirt supports specifying socket path inside graphics element
             * as 'socket' attribute.  Auto-generated socket is a new feature
             * thus we can generate it in the migrateble XML. */
            if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
                def->listens[i].type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET &&
                def->listens[i].socket &&
                !def->listens[i].autoGenerated)
                continue;

            /* The new listen type none is in the migratable XML represented as
             * port=0 and autoport=no because old libvirt support this
             * configuration for spice. */
            if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
                def->listens[i].type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE)
                continue;
        }
        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }
        virDomainGraphicsListenDefFormat(buf, &def->listens[i], flags);
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        for (i = 0; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST; i++) {
            int mode = def->data.spice.channels[i];
            if (mode == VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY)
                continue;

            if (!children) {
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                children = true;
            }

            virBufferAsprintf(buf, "<channel name='%s' mode='%s'/>\n",
                              virDomainGraphicsSpiceChannelNameTypeToString(i),
                              virDomainGraphicsSpiceChannelModeTypeToString(mode));
        }
        if (!children && (def->data.spice.image || def->data.spice.jpeg ||
                          def->data.spice.zlib || def->data.spice.playback ||
                          def->data.spice.streaming || def->data.spice.copypaste ||
                          def->data.spice.mousemode || def->data.spice.filetransfer ||
                          def->data.spice.gl)) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }
        if (def->data.spice.image)
            virBufferAsprintf(buf, "<image compression='%s'/>\n",
                              virDomainGraphicsSpiceImageCompressionTypeToString(def->data.spice.image));
        if (def->data.spice.jpeg)
            virBufferAsprintf(buf, "<jpeg compression='%s'/>\n",
                              virDomainGraphicsSpiceJpegCompressionTypeToString(def->data.spice.jpeg));
        if (def->data.spice.zlib)
            virBufferAsprintf(buf, "<zlib compression='%s'/>\n",
                              virDomainGraphicsSpiceZlibCompressionTypeToString(def->data.spice.zlib));
        if (def->data.spice.playback)
            virBufferAsprintf(buf, "<playback compression='%s'/>\n",
                              virTristateSwitchTypeToString(def->data.spice.playback));
        if (def->data.spice.streaming)
            virBufferAsprintf(buf, "<streaming mode='%s'/>\n",
                              virDomainGraphicsSpiceStreamingModeTypeToString(def->data.spice.streaming));
        if (def->data.spice.mousemode)
            virBufferAsprintf(buf, "<mouse mode='%s'/>\n",
                              virDomainGraphicsSpiceMouseModeTypeToString(def->data.spice.mousemode));
        if (def->data.spice.copypaste)
            virBufferAsprintf(buf, "<clipboard copypaste='%s'/>\n",
                              virTristateBoolTypeToString(def->data.spice.copypaste));
        if (def->data.spice.filetransfer)
            virBufferAsprintf(buf, "<filetransfer enable='%s'/>\n",
                              virTristateBoolTypeToString(def->data.spice.filetransfer));

        virDomainSpiceGLDefFormat(buf, def);
    }

    if (children) {
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</graphics>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static int
virDomainHostdevDefFormat(virBufferPtr buf,
                          virDomainHostdevDefPtr def,
                          unsigned int flags)
{
    const char *mode = virDomainHostdevModeTypeToString(def->mode);
    virDomainHostdevSubsysSCSIPtr scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysMediatedDevPtr mdevsrc = &def->source.subsys.u.mdev;
    const char *type;

    if (!mode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev mode %d"), def->mode);
        return -1;
    }

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        type = virDomainHostdevSubsysTypeToString(def->source.subsys.type);
        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %d"),
                           def->source.subsys.type);
            return -1;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        type = virDomainHostdevCapsTypeToString(def->source.caps.type);
        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %d"),
                           def->source.caps.type);
            return -1;
        }
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev mode %d"), def->mode);
        return -1;
    }

    virBufferAsprintf(buf, "<hostdev mode='%s' type='%s'",
                      mode, type);
    if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virBufferAsprintf(buf, " managed='%s'",
                          def->managed ? "yes" : "no");

        if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
            scsisrc->sgio)
            virBufferAsprintf(buf, " sgio='%s'",
                              virDomainDeviceSGIOTypeToString(scsisrc->sgio));

        if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
            scsisrc->rawio) {
            virBufferAsprintf(buf, " rawio='%s'",
                              virTristateBoolTypeToString(scsisrc->rawio));
        }

        if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV)
            virBufferAsprintf(buf, " model='%s'",
                              virMediatedDeviceModelTypeToString(mdevsrc->model));
    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        if (virDomainHostdevDefFormatSubsys(buf, def, flags, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        if (virDomainHostdevDefFormatCaps(buf, def) < 0)
            return -1;
        break;
    }

    if (def->readonly)
        virBufferAddLit(buf, "<readonly/>\n");
    if (def->shareable)
        virBufferAddLit(buf, "<shareable/>\n");

    if (virDomainDeviceInfoFormat(buf, def->info,
                                  flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT
                                  | VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</hostdev>\n");

    return 0;
}

static int
virDomainRedirdevDefFormat(virBufferPtr buf,
                           virDomainRedirdevDefPtr def,
                           unsigned int flags)
{
    const char *bus;

    bus = virDomainRedirdevBusTypeToString(def->bus);

    virBufferAsprintf(buf, "<redirdev bus='%s'", bus);
    virBufferAdjustIndent(buf, 2);
    if (virDomainChrSourceDefFormat(buf, NULL, def->source, false, flags) < 0)
        return -1;
    if (virDomainDeviceInfoFormat(buf, &def->info,
                                  flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT) < 0)
        return -1;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</redirdev>\n");
    return 0;
}

static int
virDomainRedirFilterDefFormat(virBufferPtr buf,
                              virDomainRedirFilterDefPtr filter)
{
    size_t i;

    /* no need format an empty redirfilter */
    if (filter->nusbdevs == 0)
        return 0;

    virBufferAddLit(buf, "<redirfilter>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < filter->nusbdevs; i++) {
        virDomainRedirFilterUSBDevDefPtr usbdev = filter->usbdevs[i];
        virBufferAddLit(buf, "<usbdev");
        if (usbdev->usbClass >= 0)
            virBufferAsprintf(buf, " class='0x%02X'", usbdev->usbClass);

        if (usbdev->vendor >= 0)
            virBufferAsprintf(buf, " vendor='0x%04X'", usbdev->vendor);

        if (usbdev->product >= 0)
            virBufferAsprintf(buf, " product='0x%04X'", usbdev->product);

        if (usbdev->version >= 0)
            virBufferAsprintf(buf, " version='%d.%02d'",
                                 ((usbdev->version & 0xf000) >> 12) * 10 +
                                 ((usbdev->version & 0x0f00) >>  8),
                                 ((usbdev->version & 0x00f0) >>  4) * 10 +
                                 ((usbdev->version & 0x000f) >>  0));

        virBufferAsprintf(buf, " allow='%s'/>\n", usbdev->allow ? "yes" : "no");

    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</redirfilter>\n");
    return 0;
}

static int
virDomainHubDefFormat(virBufferPtr buf,
                      virDomainHubDefPtr def,
                      unsigned int flags)
{
    const char *type = virDomainHubTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hub type %d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<hub type='%s'", type);

    if (virDomainDeviceInfoNeedsFormat(&def->info, flags)) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        if (virDomainDeviceInfoFormat(buf, &def->info, flags) < 0)
            return -1;
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</hub>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}


static void
virDomainResourceDefFormat(virBufferPtr buf,
                           virDomainResourceDefPtr def)
{
    virBufferAddLit(buf, "<resource>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<partition>%s</partition>\n", def->partition);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</resource>\n");
}


static int
virDomainHugepagesFormatBuf(virBufferPtr buf,
                            virDomainHugePagePtr hugepage)
{
    int ret = -1;

    virBufferAsprintf(buf, "<page size='%llu' unit='KiB'",
                      hugepage->size);

    if (hugepage->nodemask) {
        char *nodeset = NULL;
        if (!(nodeset = virBitmapFormat(hugepage->nodemask)))
            goto cleanup;
        virBufferAsprintf(buf, " nodeset='%s'", nodeset);
        VIR_FREE(nodeset);
    }

    virBufferAddLit(buf, "/>\n");

    ret = 0;
 cleanup:
    return ret;
}

static void
virDomainHugepagesFormat(virBufferPtr buf,
                         virDomainHugePagePtr hugepages,
                         size_t nhugepages)
{
    size_t i;

    if (nhugepages == 1 &&
        hugepages[0].size == 0) {
        virBufferAddLit(buf, "<hugepages/>\n");
        return;
    }

    virBufferAddLit(buf, "<hugepages>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < nhugepages; i++)
        virDomainHugepagesFormatBuf(buf, &hugepages[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</hugepages>\n");
}

static void
virDomainLoaderDefFormat(virBufferPtr buf,
                         virDomainLoaderDefPtr loader)
{
    const char *readonly = virTristateBoolTypeToString(loader->readonly);
    const char *secure = virTristateBoolTypeToString(loader->secure);
    const char *type = virDomainLoaderTypeToString(loader->type);

    virBufferAddLit(buf, "<loader");

    if (loader->readonly)
        virBufferAsprintf(buf, " readonly='%s'", readonly);

    if (loader->secure)
        virBufferAsprintf(buf, " secure='%s'", secure);

    virBufferAsprintf(buf, " type='%s'>", type);

    virBufferEscapeString(buf, "%s</loader>\n", loader->path);
    if (loader->nvram || loader->templt) {
        virBufferAddLit(buf, "<nvram");
        virBufferEscapeString(buf, " template='%s'", loader->templt);
        if (loader->nvram)
            virBufferEscapeString(buf, ">%s</nvram>\n", loader->nvram);
        else
            virBufferAddLit(buf, "/>\n");
    }
}

static void
virDomainKeyWrapDefFormat(virBufferPtr buf, virDomainKeyWrapDefPtr keywrap)
{
    virBufferAddLit(buf, "<keywrap>\n");
    virBufferAdjustIndent(buf, 2);

    if (keywrap->aes)
        virBufferAsprintf(buf, "<cipher name='aes' state='%s'/>\n",
                          virTristateSwitchTypeToString(keywrap->aes));

    if (keywrap->dea)
        virBufferAsprintf(buf, "<cipher name='dea' state='%s'/>\n",
                          virTristateSwitchTypeToString(keywrap->dea));

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</keywrap>\n");
}

static void
virDomainPerfDefFormat(virBufferPtr buf, virDomainPerfDefPtr perf)
{
    size_t i;
    bool wantPerf = false;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (perf->events[i])
            wantPerf = true;
    }
    if (!wantPerf)
        return;

    virBufferAddLit(buf, "<perf>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (perf->events[i])
            virBufferAsprintf(buf, "<event name='%s' enabled='%s'/>\n",
                              virPerfEventTypeToString(i),
                              virTristateBoolTypeToString(perf->events[i]));
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</perf>\n");
}

static bool
virDomainDefHasCapabilitiesFeatures(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_CAPS_FEATURE_LAST; i++) {
        if (def->caps_features[i] != VIR_TRISTATE_SWITCH_ABSENT)
            return true;
    }

    return false;
}


static void
virDomainSchedulerFormat(virBufferPtr buf,
                         const char *name,
                         virDomainThreadSchedParamPtr sched,
                         size_t id)
{
    switch (sched->policy) {
        case VIR_PROC_POLICY_BATCH:
        case VIR_PROC_POLICY_IDLE:
            virBufferAsprintf(buf, "<%ssched "
                              "%ss='%zu' scheduler='%s'/>\n",
                              name, name, id,
                              virProcessSchedPolicyTypeToString(sched->policy));
            break;

        case VIR_PROC_POLICY_RR:
        case VIR_PROC_POLICY_FIFO:
            virBufferAsprintf(buf, "<%ssched "
                              "%ss='%zu' scheduler='%s' priority='%d'/>\n",
                              name, name, id,
                              virProcessSchedPolicyTypeToString(sched->policy),
                              sched->priority);
            break;

        case VIR_PROC_POLICY_NONE:
        case VIR_PROC_POLICY_LAST:
            break;
        }

}


static int
virDomainCputuneDefFormat(virBufferPtr buf,
                          virDomainDefPtr def)
{
    size_t i;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    int ret = -1;

    virBufferAdjustIndent(&childrenBuf, virBufferGetIndent(buf, false) + 2);

    if (def->cputune.sharesSpecified)
        virBufferAsprintf(&childrenBuf, "<shares>%llu</shares>\n",
                          def->cputune.shares);
    if (def->cputune.period)
        virBufferAsprintf(&childrenBuf, "<period>%llu</period>\n",
                          def->cputune.period);
    if (def->cputune.quota)
        virBufferAsprintf(&childrenBuf, "<quota>%lld</quota>\n",
                          def->cputune.quota);
    if (def->cputune.global_period)
        virBufferAsprintf(&childrenBuf, "<global_period>%llu</global_period>\n",
                          def->cputune.global_period);
    if (def->cputune.global_quota)
        virBufferAsprintf(&childrenBuf, "<global_quota>%lld</global_quota>\n",
                          def->cputune.global_quota);

    if (def->cputune.emulator_period)
        virBufferAsprintf(&childrenBuf, "<emulator_period>%llu"
                          "</emulator_period>\n",
                          def->cputune.emulator_period);

    if (def->cputune.emulator_quota)
        virBufferAsprintf(&childrenBuf, "<emulator_quota>%lld"
                          "</emulator_quota>\n",
                          def->cputune.emulator_quota);

    if (def->cputune.iothread_period)
        virBufferAsprintf(&childrenBuf, "<iothread_period>%llu"
                          "</iothread_period>\n",
                          def->cputune.iothread_period);

    if (def->cputune.iothread_quota)
        virBufferAsprintf(&childrenBuf, "<iothread_quota>%lld"
                          "</iothread_quota>\n",
                          def->cputune.iothread_quota);

    for (i = 0; i < def->maxvcpus; i++) {
        char *cpumask;
        virDomainVcpuDefPtr vcpu = def->vcpus[i];

        if (!vcpu->cpumask)
            continue;

        if (!(cpumask = virBitmapFormat(vcpu->cpumask)))
            goto cleanup;

        virBufferAsprintf(&childrenBuf,
                          "<vcpupin vcpu='%zu' cpuset='%s'/>\n", i, cpumask);

        VIR_FREE(cpumask);
    }

    if (def->cputune.emulatorpin) {
        char *cpumask;
        virBufferAddLit(&childrenBuf, "<emulatorpin ");

        if (!(cpumask = virBitmapFormat(def->cputune.emulatorpin)))
            goto cleanup;

        virBufferAsprintf(&childrenBuf, "cpuset='%s'/>\n", cpumask);
        VIR_FREE(cpumask);
    }

    for (i = 0; i < def->niothreadids; i++) {
        char *cpumask;

        /* Ignore iothreadids with no cpumask */
        if (!def->iothreadids[i]->cpumask)
            continue;

        virBufferAsprintf(&childrenBuf, "<iothreadpin iothread='%u' ",
                          def->iothreadids[i]->iothread_id);

        if (!(cpumask = virBitmapFormat(def->iothreadids[i]->cpumask)))
            goto cleanup;

        virBufferAsprintf(&childrenBuf, "cpuset='%s'/>\n", cpumask);
        VIR_FREE(cpumask);
    }

    for (i = 0; i < def->maxvcpus; i++) {
        virDomainSchedulerFormat(&childrenBuf, "vcpu",
                                 &def->vcpus[i]->sched, i);
    }

    for (i = 0; i < def->niothreadids; i++) {
        virDomainSchedulerFormat(&childrenBuf, "iothread",
                                 &def->iothreadids[i]->sched,
                                 def->iothreadids[i]->iothread_id);
    }

    if (virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, "<cputune>\n");
        virBufferAddBuffer(buf, &childrenBuf);
        virBufferAddLit(buf, "</cputune>\n");
    }

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&childrenBuf);
    return ret;
}


static int
virDomainCpuDefFormat(virBufferPtr buf,
                      const virDomainDef *def)
{
    virDomainVcpuDefPtr vcpu;
    size_t i;
    char *cpumask = NULL;
    int ret = -1;

    virBufferAddLit(buf, "<vcpu");
    virBufferAsprintf(buf, " placement='%s'",
                      virDomainCpuPlacementModeTypeToString(def->placement_mode));

    if (def->cpumask && !virBitmapIsAllSet(def->cpumask)) {
        if ((cpumask = virBitmapFormat(def->cpumask)) == NULL)
            goto cleanup;
        virBufferAsprintf(buf, " cpuset='%s'", cpumask);
    }
    if (virDomainDefHasVcpusOffline(def))
        virBufferAsprintf(buf, " current='%u'", virDomainDefGetVcpus(def));
    virBufferAsprintf(buf, ">%u</vcpu>\n", virDomainDefGetVcpusMax(def));

    if (def->individualvcpus) {
        virBufferAddLit(buf, "<vcpus>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < def->maxvcpus; i++) {
            vcpu = def->vcpus[i];

            virBufferAsprintf(buf, "<vcpu id='%zu' enabled='%s'",
                              i, vcpu->online ? "yes" : "no");
            if (vcpu->hotpluggable)
                virBufferAsprintf(buf, " hotpluggable='%s'",
                                  virTristateBoolTypeToString(vcpu->hotpluggable));

            if (vcpu->order != 0)
                virBufferAsprintf(buf, " order='%d'", vcpu->order);

            virBufferAddLit(buf, "/>\n");
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</vcpus>\n");
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpumask);

    return ret;
}


static bool
virDomainDefIothreadShouldFormat(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->niothreadids; i++) {
        if (!def->iothreadids[i]->autofill)
            return true;
    }

    return false;
}


static void
virDomainIOMMUDefFormat(virBufferPtr buf,
                        const virDomainIOMMUDef *iommu)
{
    virBuffer childBuf = VIR_BUFFER_INITIALIZER;

    virBufferAdjustIndent(&childBuf, virBufferGetIndent(buf, false) + 2);

    if (iommu->intremap != VIR_TRISTATE_SWITCH_ABSENT ||
        iommu->caching_mode != VIR_TRISTATE_SWITCH_ABSENT ||
        iommu->iotlb != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAddLit(&childBuf, "<driver");
        if (iommu->intremap != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&childBuf, " intremap='%s'",
                              virTristateSwitchTypeToString(iommu->intremap));
        }
        if (iommu->caching_mode != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&childBuf, " caching_mode='%s'",
                              virTristateSwitchTypeToString(iommu->caching_mode));
        }
        if (iommu->eim != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&childBuf, " eim='%s'",
                              virTristateSwitchTypeToString(iommu->eim));
        }
        if (iommu->iotlb != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&childBuf, " iotlb='%s'",
                              virTristateSwitchTypeToString(iommu->iotlb));
        }
        virBufferAddLit(&childBuf, "/>\n");
    }

    virBufferAsprintf(buf, "<iommu model='%s'",
                      virDomainIOMMUModelTypeToString(iommu->model));
    if (virBufferUse(&childBuf)) {
        virBufferAddLit(buf, ">\n");
        virBufferAddBuffer(buf, &childBuf);
        virBufferAddLit(buf, "</iommu>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


/* This internal version appends to an existing buffer
 * (possibly with auto-indent), rather than flattening
 * to string.
 * Return -1 on failure.  */
int
virDomainDefFormatInternal(virDomainDefPtr def,
                           virCapsPtr caps,
                           unsigned int flags,
                           virBufferPtr buf)
{
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *type = NULL;
    int n;
    size_t i;
    virBuffer childrenBuf = VIR_BUFFER_INITIALIZER;
    int indent;
    char *netprefix = NULL;

    virCheckFlags(VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS |
                  VIR_DOMAIN_DEF_FORMAT_STATUS |
                  VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                  VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                  VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST,
                  -1);

    if (!(type = virDomainVirtTypeToString(def->virtType))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain type %d"), def->virtType);
        goto error;
    }

    if (def->id == -1)
        flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    virBufferAsprintf(buf, "<domain type='%s'", type);
    if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
        virBufferAsprintf(buf, " id='%d'", def->id);
    if (def->namespaceData && def->ns.href)
        virBufferAsprintf(buf, " %s", (def->ns.href)());
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);

    virBufferEscapeString(buf, "<title>%s</title>\n", def->title);

    virBufferEscapeString(buf, "<description>%s</description>\n",
                          def->description);

    if (def->metadata) {
        xmlBufferPtr xmlbuf;
        int oldIndentTreeOutput = xmlIndentTreeOutput;

        /* Indentation on output requires that we previously set
         * xmlKeepBlanksDefault to 0 when parsing; also, libxml does 2
         * spaces per level of indentation of intermediate elements,
         * but no leading indentation before the starting element.
         * Thankfully, libxml maps what looks like globals into
         * thread-local uses, so we are thread-safe.  */
        xmlIndentTreeOutput = 1;
        xmlbuf = xmlBufferCreate();
        if (xmlNodeDump(xmlbuf, def->metadata->doc, def->metadata,
                        virBufferGetIndent(buf, false) / 2, 1) < 0) {
            xmlBufferFree(xmlbuf);
            xmlIndentTreeOutput = oldIndentTreeOutput;
            goto error;
        }
        virBufferAsprintf(buf, "%s\n", (char *) xmlBufferContent(xmlbuf));
        xmlBufferFree(xmlbuf);
        xmlIndentTreeOutput = oldIndentTreeOutput;
    }

    if (virDomainDefHasMemoryHotplug(def)) {
        virBufferAsprintf(buf,
                          "<maxMemory slots='%u' unit='KiB'>%llu</maxMemory>\n",
                          def->mem.memory_slots, def->mem.max_memory);
    }

    virBufferAddLit(buf, "<memory");
    if (def->mem.dump_core)
        virBufferAsprintf(buf, " dumpCore='%s'",
                          virTristateSwitchTypeToString(def->mem.dump_core));
    virBufferAsprintf(buf, " unit='KiB'>%llu</memory>\n",
                      virDomainDefGetMemoryTotal(def));

    virBufferAsprintf(buf, "<currentMemory unit='KiB'>%llu</currentMemory>\n",
                      def->mem.cur_balloon);

    /* start format blkiotune */
    indent = virBufferGetIndent(buf, false);
    virBufferAdjustIndent(&childrenBuf, indent + 2);
    if (def->blkio.weight)
        virBufferAsprintf(&childrenBuf, "<weight>%u</weight>\n",
                          def->blkio.weight);

    for (n = 0; n < def->blkio.ndevices; n++) {
        virBlkioDevicePtr dev = &def->blkio.devices[n];

        if (!dev->weight && !dev->riops && !dev->wiops &&
            !dev->rbps && !dev->wbps)
            continue;
        virBufferAddLit(&childrenBuf, "<device>\n");
        virBufferAdjustIndent(&childrenBuf, 2);
        virBufferEscapeString(&childrenBuf, "<path>%s</path>\n",
                              dev->path);
        if (dev->weight)
            virBufferAsprintf(&childrenBuf, "<weight>%u</weight>\n",
                              dev->weight);
        if (dev->riops)
            virBufferAsprintf(&childrenBuf, "<read_iops_sec>%u</read_iops_sec>\n",
                              dev->riops);
        if (dev->wiops)
            virBufferAsprintf(&childrenBuf, "<write_iops_sec>%u</write_iops_sec>\n",
                              dev->wiops);
        if (dev->rbps)
            virBufferAsprintf(&childrenBuf, "<read_bytes_sec>%llu</read_bytes_sec>\n",
                              dev->rbps);
        if (dev->wbps)
            virBufferAsprintf(&childrenBuf, "<write_bytes_sec>%llu</write_bytes_sec>\n",
                              dev->wbps);
        virBufferAdjustIndent(&childrenBuf, -2);
        virBufferAddLit(&childrenBuf, "</device>\n");
    }
    if (virBufferUse(&childrenBuf)) {
        virBufferAddLit(buf, "<blkiotune>\n");
        virBufferAddBuffer(buf, &childrenBuf);
        virBufferAddLit(buf, "</blkiotune>\n");
    }
    virBufferFreeAndReset(&childrenBuf);

    /* add memtune only if there are any */
    if (virMemoryLimitIsSet(def->mem.hard_limit) ||
        virMemoryLimitIsSet(def->mem.soft_limit) ||
        virMemoryLimitIsSet(def->mem.swap_hard_limit) ||
        def->mem.min_guarantee) {
        virBufferAddLit(buf, "<memtune>\n");
        virBufferAdjustIndent(buf, 2);
        if (virMemoryLimitIsSet(def->mem.hard_limit)) {
            virBufferAsprintf(buf, "<hard_limit unit='KiB'>"
                              "%llu</hard_limit>\n", def->mem.hard_limit);
        }
        if (virMemoryLimitIsSet(def->mem.soft_limit)) {
            virBufferAsprintf(buf, "<soft_limit unit='KiB'>"
                              "%llu</soft_limit>\n", def->mem.soft_limit);
        }
        if (def->mem.min_guarantee) {
            virBufferAsprintf(buf, "<min_guarantee unit='KiB'>"
                              "%llu</min_guarantee>\n", def->mem.min_guarantee);
        }
        if (virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virBufferAsprintf(buf, "<swap_hard_limit unit='KiB'>"
                              "%llu</swap_hard_limit>\n", def->mem.swap_hard_limit);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</memtune>\n");
    }

    if (def->mem.nhugepages || def->mem.nosharepages || def->mem.locked
        || def->mem.source || def->mem.access || def->mem.allocation)
    {
        virBufferAddLit(buf, "<memoryBacking>\n");
        virBufferAdjustIndent(buf, 2);
        if (def->mem.nhugepages)
            virDomainHugepagesFormat(buf, def->mem.hugepages, def->mem.nhugepages);
        if (def->mem.nosharepages)
            virBufferAddLit(buf, "<nosharepages/>\n");
        if (def->mem.locked)
            virBufferAddLit(buf, "<locked/>\n");
        if (def->mem.source)
            virBufferAsprintf(buf, "<source type='%s'/>\n",
                virDomainMemorySourceTypeToString(def->mem.source));
        if (def->mem.access)
            virBufferAsprintf(buf, "<access mode='%s'/>\n",
                virDomainMemoryAccessTypeToString(def->mem.access));
        if (def->mem.allocation)
            virBufferAsprintf(buf, "<allocation mode='%s'/>\n",
                virDomainMemoryAllocationTypeToString(def->mem.allocation));

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</memoryBacking>\n");
    }

    if (virDomainCpuDefFormat(buf, def) < 0)
        goto error;

    if (def->niothreadids > 0) {
        virBufferAsprintf(buf, "<iothreads>%zu</iothreads>\n",
                          def->niothreadids);
        if (virDomainDefIothreadShouldFormat(def)) {
            virBufferAddLit(buf, "<iothreadids>\n");
            virBufferAdjustIndent(buf, 2);
            for (i = 0; i < def->niothreadids; i++) {
                virBufferAsprintf(buf, "<iothread id='%u'/>\n",
                                  def->iothreadids[i]->iothread_id);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</iothreadids>\n");
        }
    }

    if (virDomainCputuneDefFormat(buf, def) < 0)
        goto error;

    if (virDomainNumatuneFormatXML(buf, def->numa) < 0)
        goto error;

    if (def->resource)
        virDomainResourceDefFormat(buf, def->resource);

    if (def->sysinfo)
        ignore_value(virSysinfoFormat(buf, def->sysinfo));

    if (def->os.bootloader) {
        virBufferEscapeString(buf, "<bootloader>%s</bootloader>\n",
                              def->os.bootloader);
        virBufferEscapeString(buf,
                              "<bootloader_args>%s</bootloader_args>\n",
                              def->os.bootloaderArgs);
    }

    virBufferAddLit(buf, "<os>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferAddLit(buf, "<type");
    if (def->os.arch)
        virBufferAsprintf(buf, " arch='%s'", virArchToString(def->os.arch));
    if (def->os.machine)
        virBufferAsprintf(buf, " machine='%s'", def->os.machine);
    /*
     * HACK: For xen driver we previously used bogus 'linux' as the
     * os type for paravirt, whereas capabilities declare it to
     * be 'xen'. So we convert to the former for backcompat
     */
    if (def->virtType == VIR_DOMAIN_VIRT_XEN &&
        def->os.type == VIR_DOMAIN_OSTYPE_XEN)
        virBufferAsprintf(buf, ">%s</type>\n",
                          virDomainOSTypeToString(VIR_DOMAIN_OSTYPE_LINUX));
    else
        virBufferAsprintf(buf, ">%s</type>\n",
                          virDomainOSTypeToString(def->os.type));

    virBufferEscapeString(buf, "<init>%s</init>\n",
                          def->os.init);
    for (i = 0; def->os.initargv && def->os.initargv[i]; i++)
        virBufferEscapeString(buf, "<initarg>%s</initarg>\n",
                              def->os.initargv[i]);
    if (def->os.loader)
        virDomainLoaderDefFormat(buf, def->os.loader);
    virBufferEscapeString(buf, "<kernel>%s</kernel>\n",
                          def->os.kernel);
    virBufferEscapeString(buf, "<initrd>%s</initrd>\n",
                          def->os.initrd);
    virBufferEscapeString(buf, "<cmdline>%s</cmdline>\n",
                          def->os.cmdline);
    virBufferEscapeString(buf, "<dtb>%s</dtb>\n",
                          def->os.dtb);
    virBufferEscapeString(buf, "<root>%s</root>\n",
                          def->os.root);
    if (def->os.slic_table) {
        virBufferAddLit(buf, "<acpi>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<table type='slic'>%s</table>\n",
                              def->os.slic_table);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</acpi>\n");
    }

    if (!def->os.bootloader) {
        for (n = 0; n < def->os.nBootDevs; n++) {
            const char *boottype =
                virDomainBootTypeToString(def->os.bootDevs[n]);
            if (!boottype) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected boot device type %d"),
                               def->os.bootDevs[n]);
                goto error;
            }
            virBufferAsprintf(buf, "<boot dev='%s'/>\n", boottype);
        }

        if (def->os.bootmenu) {
            virBufferAsprintf(buf, "<bootmenu enable='%s'",
                              virTristateBoolTypeToString(def->os.bootmenu));
            if (def->os.bm_timeout_set)
                virBufferAsprintf(buf, " timeout='%u'", def->os.bm_timeout);
            virBufferAddLit(buf, "/>\n");
        }

        if (def->os.bios.useserial || def->os.bios.rt_set) {
            virBufferAddLit(buf, "<bios");
            if (def->os.bios.useserial)
                virBufferAsprintf(buf, " useserial='%s'",
                                  virTristateBoolTypeToString(def->os.bios.useserial));
            if (def->os.bios.rt_set)
                virBufferAsprintf(buf, " rebootTimeout='%d'", def->os.bios.rt_delay);

            virBufferAddLit(buf, "/>\n");
        }
    }

    if (def->os.smbios_mode) {
        const char *mode;

        mode = virDomainSmbiosModeTypeToString(def->os.smbios_mode);
        if (mode == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected smbios mode %d"), def->os.smbios_mode);
            goto error;
        }
        virBufferAsprintf(buf, "<smbios mode='%s'/>\n", mode);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</os>\n");


    if (def->idmap.uidmap) {
        virBufferAddLit(buf, "<idmap>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < def->idmap.nuidmap; i++) {
            virBufferAsprintf(buf,
                              "<uid start='%u' target='%u' count='%u'/>\n",
                              def->idmap.uidmap[i].start,
                              def->idmap.uidmap[i].target,
                              def->idmap.uidmap[i].count);
        }
        for (i = 0; i < def->idmap.ngidmap; i++) {
            virBufferAsprintf(buf,
                              "<gid start='%u' target='%u' count='%u'/>\n",
                              def->idmap.gidmap[i].start,
                              def->idmap.gidmap[i].target,
                              def->idmap.gidmap[i].count);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</idmap>\n");
    }

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT)
            break;
    }

    if (i != VIR_DOMAIN_FEATURE_LAST ||
        virDomainDefHasCapabilitiesFeatures(def)) {
        virBufferAddLit(buf, "<features>\n");
        virBufferAdjustIndent(buf, 2);

        for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
            const char *name = virDomainFeatureTypeToString(i);
            size_t j;

            if (!name) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected feature %zu"), i);
                goto error;
            }

            switch ((virDomainFeature) i) {
            case VIR_DOMAIN_FEATURE_ACPI:
            case VIR_DOMAIN_FEATURE_PAE:
            case VIR_DOMAIN_FEATURE_VIRIDIAN:
            case VIR_DOMAIN_FEATURE_PRIVNET:
                switch ((virTristateSwitch) def->features[i]) {
                case VIR_TRISTATE_SWITCH_ABSENT:
                    break;

                case VIR_TRISTATE_SWITCH_ON:
                   virBufferAsprintf(buf, "<%s/>\n", name);
                   break;

                case VIR_TRISTATE_SWITCH_LAST:
                case VIR_TRISTATE_SWITCH_OFF:
                   virReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("Unexpected state of feature '%s'"), name);

                   goto error;
                   break;
                }

                break;

            case VIR_DOMAIN_FEATURE_HAP:
            case VIR_DOMAIN_FEATURE_PMU:
            case VIR_DOMAIN_FEATURE_PVSPINLOCK:
            case VIR_DOMAIN_FEATURE_VMPORT:
            case VIR_DOMAIN_FEATURE_SMM:
                switch ((virTristateSwitch) def->features[i]) {
                case VIR_TRISTATE_SWITCH_LAST:
                case VIR_TRISTATE_SWITCH_ABSENT:
                    break;

                case VIR_TRISTATE_SWITCH_ON:
                   virBufferAsprintf(buf, "<%s state='on'/>\n", name);
                   break;

                case VIR_TRISTATE_SWITCH_OFF:
                   virBufferAsprintf(buf, "<%s state='off'/>\n", name);
                   break;
                }

                break;

            case VIR_DOMAIN_FEATURE_APIC:
                if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                    virBufferAddLit(buf, "<apic");
                    if (def->apic_eoi) {
                        virBufferAsprintf(buf, " eoi='%s'",
                                          virTristateSwitchTypeToString(def->apic_eoi));
                    }
                    virBufferAddLit(buf, "/>\n");
                }
                break;

            case VIR_DOMAIN_FEATURE_HYPERV:
                if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                    break;

                virBufferAddLit(buf, "<hyperv>\n");
                virBufferAdjustIndent(buf, 2);
                for (j = 0; j < VIR_DOMAIN_HYPERV_LAST; j++) {
                    if (def->hyperv_features[j] == VIR_TRISTATE_SWITCH_ABSENT)
                        continue;

                    virBufferAsprintf(buf, "<%s state='%s'",
                                      virDomainHypervTypeToString(j),
                                      virTristateSwitchTypeToString(
                                          def->hyperv_features[j]));

                    switch ((virDomainHyperv) j) {
                    case VIR_DOMAIN_HYPERV_RELAXED:
                    case VIR_DOMAIN_HYPERV_VAPIC:
                    case VIR_DOMAIN_HYPERV_VPINDEX:
                    case VIR_DOMAIN_HYPERV_RUNTIME:
                    case VIR_DOMAIN_HYPERV_SYNIC:
                    case VIR_DOMAIN_HYPERV_STIMER:
                    case VIR_DOMAIN_HYPERV_RESET:
                        break;

                    case VIR_DOMAIN_HYPERV_SPINLOCKS:
                        if (def->hyperv_features[j] != VIR_TRISTATE_SWITCH_ON)
                            break;
                        virBufferAsprintf(buf, " retries='%d'",
                                          def->hyperv_spinlocks);
                        break;

                    case VIR_DOMAIN_HYPERV_VENDOR_ID:
                        if (def->hyperv_features[j] != VIR_TRISTATE_SWITCH_ON)
                            break;
                        virBufferEscapeString(buf, " value='%s'",
                                              def->hyperv_vendor_id);
                        break;

                    /* coverity[dead_error_begin] */
                    case VIR_DOMAIN_HYPERV_LAST:
                        break;
                    }

                    virBufferAddLit(buf, "/>\n");
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</hyperv>\n");
                break;

            case VIR_DOMAIN_FEATURE_KVM:
                if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                    break;

                virBufferAddLit(buf, "<kvm>\n");
                virBufferAdjustIndent(buf, 2);
                for (j = 0; j < VIR_DOMAIN_KVM_LAST; j++) {
                    switch ((virDomainKVM) j) {
                    case VIR_DOMAIN_KVM_HIDDEN:
                        if (def->kvm_features[j])
                            virBufferAsprintf(buf, "<%s state='%s'/>\n",
                                              virDomainKVMTypeToString(j),
                                              virTristateSwitchTypeToString(
                                                  def->kvm_features[j]));
                        break;

                    /* coverity[dead_error_begin] */
                    case VIR_DOMAIN_KVM_LAST:
                        break;
                    }
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</kvm>\n");
                break;

            case VIR_DOMAIN_FEATURE_CAPABILITIES:
                if (def->features[i] == VIR_DOMAIN_CAPABILITIES_POLICY_DEFAULT &&
                        !virDomainDefHasCapabilitiesFeatures(def))
                    break;

                virBufferAsprintf(buf, "<capabilities policy='%s'>\n",
                                  virDomainCapabilitiesPolicyTypeToString(def->features[i]));
                virBufferAdjustIndent(buf, 2);
                for (j = 0; j < VIR_DOMAIN_CAPS_FEATURE_LAST; j++) {
                    if (def->caps_features[j] != VIR_TRISTATE_SWITCH_ABSENT)
                        virBufferAsprintf(buf, "<%s state='%s'/>\n",
                                          virDomainCapsFeatureTypeToString(j),
                                          virTristateSwitchTypeToString(
                                              def->caps_features[j]));
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</capabilities>\n");
                break;

            case VIR_DOMAIN_FEATURE_GIC:
                if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                    virBufferAddLit(buf, "<gic");
                    if (def->gic_version != VIR_GIC_VERSION_NONE)
                        virBufferAsprintf(buf, " version='%s'",
                                          virGICVersionTypeToString(def->gic_version));
                    virBufferAddLit(buf, "/>\n");
                }
                break;

            case VIR_DOMAIN_FEATURE_IOAPIC:
                if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                    virBufferAsprintf(buf, "<ioapic driver='%s'/>\n",
                                      virDomainIOAPICTypeToString(def->ioapic));
                }
                break;

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_FEATURE_LAST:
                break;
            }
        }

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</features>\n");
    }

    if (virCPUDefFormatBufFull(buf, def->cpu, def->numa,
                               !!(flags & VIR_DOMAIN_DEF_FORMAT_UPDATE_CPU)) < 0)
        goto error;

    virBufferAsprintf(buf, "<clock offset='%s'",
                      virDomainClockOffsetTypeToString(def->clock.offset));
    switch (def->clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        if (def->clock.data.utc_reset)
            virBufferAddLit(buf, " adjustment='reset'");
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
        virBufferAsprintf(buf, " adjustment='%lld' basis='%s'",
                          def->clock.data.variable.adjustment,
                          virDomainClockBasisTypeToString(def->clock.data.variable.basis));
        if (flags & VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST) {
            if (def->clock.data.variable.adjustment0)
                virBufferAsprintf(buf, " adjustment0='%lld'",
                                  def->clock.data.variable.adjustment0);
        }
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virBufferEscapeString(buf, " timezone='%s'", def->clock.data.timezone);
        break;
    }
    if (def->clock.ntimers == 0) {
        virBufferAddLit(buf, "/>\n");
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        for (n = 0; n < def->clock.ntimers; n++) {
            if (virDomainTimerDefFormat(buf, def->clock.timers[n]) < 0)
                goto error;
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</clock>\n");
    }

    if (virDomainEventActionDefFormat(buf, def->onPoweroff,
                                      "on_poweroff",
                                      virDomainLifecycleTypeToString) < 0)
        goto error;
    if (virDomainEventActionDefFormat(buf, def->onReboot,
                                      "on_reboot",
                                      virDomainLifecycleTypeToString) < 0)
        goto error;
    if (virDomainEventActionDefFormat(buf, def->onCrash,
                                      "on_crash",
                                      virDomainLifecycleCrashTypeToString) < 0)
        goto error;
    if (def->onLockFailure != VIR_DOMAIN_LOCK_FAILURE_DEFAULT &&
        virDomainEventActionDefFormat(buf, def->onLockFailure,
                                      "on_lockfailure",
                                      virDomainLockFailureTypeToString) < 0)
        goto error;

    if (def->pm.s3 || def->pm.s4) {
        virBufferAddLit(buf, "<pm>\n");
        virBufferAdjustIndent(buf, 2);
        if (def->pm.s3) {
            virBufferAsprintf(buf, "<suspend-to-mem enabled='%s'/>\n",
                              virTristateBoolTypeToString(def->pm.s3));
        }
        if (def->pm.s4) {
            virBufferAsprintf(buf, "<suspend-to-disk enabled='%s'/>\n",
                              virTristateBoolTypeToString(def->pm.s4));
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</pm>\n");
    }

    virDomainPerfDefFormat(buf, &def->perf);

    virBufferAddLit(buf, "<devices>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<emulator>%s</emulator>\n",
                          def->emulator);

    for (n = 0; n < def->ndisks; n++)
        if (virDomainDiskDefFormat(buf, def->disks[n], flags) < 0)
            goto error;

    for (n = 0; n < def->ncontrollers; n++)
        if (virDomainControllerDefFormat(buf, def->controllers[n], flags) < 0)
            goto error;

    for (n = 0; n < def->nleases; n++)
        if (virDomainLeaseDefFormat(buf, def->leases[n]) < 0)
            goto error;

    for (n = 0; n < def->nfss; n++)
        if (virDomainFSDefFormat(buf, def->fss[n], flags) < 0)
            goto error;

    if (caps)
        netprefix = caps->host.netprefix;
    for (n = 0; n < def->nnets; n++)
        if (virDomainNetDefFormat(buf, def->nets[n], netprefix, flags) < 0)
            goto error;

    for (n = 0; n < def->nsmartcards; n++)
        if (virDomainSmartcardDefFormat(buf, def->smartcards[n], flags) < 0)
            goto error;

    for (n = 0; n < def->nserials; n++)
        if (virDomainChrDefFormat(buf, def->serials[n], flags) < 0)
            goto error;

    for (n = 0; n < def->nparallels; n++)
        if (virDomainChrDefFormat(buf, def->parallels[n], flags) < 0)
            goto error;

    for (n = 0; n < def->nconsoles; n++) {
        virDomainChrDef console;
        /* Back compat, ignore the console element for hvm guests
         * if it is type == serial
         */
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM &&
            (def->consoles[n]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
             def->consoles[n]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE) &&
            (n < def->nserials)) {
            memcpy(&console, def->serials[n], sizeof(console));
            console.deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
            console.targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
        } else {
            memcpy(&console, def->consoles[n], sizeof(console));
        }
        if (virDomainChrDefFormat(buf, &console, flags) < 0)
            goto error;
    }

    for (n = 0; n < def->nchannels; n++)
        if (virDomainChrDefFormat(buf, def->channels[n], flags) < 0)
            goto error;

    for (n = 0; n < def->ninputs; n++) {
        if (virDomainInputDefFormat(buf, def->inputs[n], flags) < 0)
            goto error;
    }

    if (def->tpm) {
        if (virDomainTPMDefFormat(buf, def->tpm, flags) < 0)
            goto error;
    }

    for (n = 0; n < def->ngraphics; n++) {
        if (virDomainGraphicsDefFormat(buf, def->graphics[n], flags) < 0)
            goto error;
    }

    for (n = 0; n < def->nsounds; n++) {
        if (virDomainSoundDefFormat(buf, def->sounds[n], flags) < 0)
            goto error;
    }

    for (n = 0; n < def->nvideos; n++) {
        if (virDomainVideoDefFormat(buf, def->videos[n], flags) < 0)
            goto error;
    }

    for (n = 0; n < def->nhostdevs; n++) {
        /* If parent.type != NONE, this is just a pointer to the
         * hostdev in a higher-level device (e.g. virDomainNetDef),
         * and will have already been formatted there.
         */
        if (def->hostdevs[n]->parent.type == VIR_DOMAIN_DEVICE_NONE &&
            virDomainHostdevDefFormat(buf, def->hostdevs[n], flags) < 0) {
            goto error;
        }
    }

    for (n = 0; n < def->nredirdevs; n++) {
        if (virDomainRedirdevDefFormat(buf, def->redirdevs[n], flags) < 0)
            goto error;
    }

    if (def->redirfilter)
        virDomainRedirFilterDefFormat(buf, def->redirfilter);

    for (n = 0; n < def->nhubs; n++) {
        if (virDomainHubDefFormat(buf, def->hubs[n], flags) < 0)
            goto error;
    }

    if (def->watchdog)
        virDomainWatchdogDefFormat(buf, def->watchdog, flags);

    if (def->memballoon)
        virDomainMemballoonDefFormat(buf, def->memballoon, flags);

    for (n = 0; n < def->nrngs; n++) {
        if (virDomainRNGDefFormat(buf, def->rngs[n], flags))
            goto error;
    }

    if (def->nvram)
        virDomainNVRAMDefFormat(buf, def->nvram, flags);

    for (n = 0; n < def->npanics; n++) {
        if (virDomainPanicDefFormat(buf, def->panics[n]) < 0)
            goto error;
    }

    for (n = 0; n < def->nshmems; n++) {
        if (virDomainShmemDefFormat(buf, def->shmems[n], flags) < 0)
            goto error;
    }

    for (n = 0; n < def->nmems; n++) {
        if (virDomainMemoryDefFormat(buf, def->mems[n], flags) < 0)
            goto error;
    }

    if (def->iommu)
        virDomainIOMMUDefFormat(buf, def->iommu);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</devices>\n");

    for (n = 0; n < def->nseclabels; n++)
        virSecurityLabelDefFormat(buf, def->seclabels[n], flags);

    if (def->namespaceData && def->ns.format) {
        if ((def->ns.format)(buf, def->namespaceData) < 0)
            goto error;
    }

    if (def->keywrap)
        virDomainKeyWrapDefFormat(buf, def->keywrap);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</domain>\n");

    if (virBufferCheckError(buf) < 0)
        goto error;

    return 0;

 error:
    virBufferFreeAndReset(buf);
    virBufferFreeAndReset(&childrenBuf);
    return -1;
}

unsigned int virDomainDefFormatConvertXMLFlags(unsigned int flags)
{
    unsigned int formatFlags = 0;

    if (flags & VIR_DOMAIN_XML_SECURE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_SECURE;
    if (flags & VIR_DOMAIN_XML_INACTIVE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;
    if (flags & VIR_DOMAIN_XML_UPDATE_CPU)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_UPDATE_CPU;
    if (flags & VIR_DOMAIN_XML_MIGRATABLE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_MIGRATABLE;

    return formatFlags;
}


char *
virDomainDefFormat(virDomainDefPtr def, virCapsPtr caps, unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS, NULL);
    if (virDomainDefFormatInternal(def, caps, flags, &buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *
virDomainObjFormat(virDomainXMLOptionPtr xmlopt,
                   virDomainObjPtr obj,
                   virCapsPtr caps,
                   unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int state;
    int reason;
    size_t i;

    state = virDomainObjGetState(obj, &reason);
    virBufferAsprintf(&buf, "<domstatus state='%s' reason='%s' pid='%lld'>\n",
                      virDomainStateTypeToString(state),
                      virDomainStateReasonToString(state, reason),
                      (long long)obj->pid);
    virBufferAdjustIndent(&buf, 2);

    for (i = 0; i < VIR_DOMAIN_TAINT_LAST; i++) {
        if (obj->taint & (1 << i))
            virBufferAsprintf(&buf, "<taint flag='%s'/>\n",
                              virDomainTaintTypeToString(i));
    }

    if (xmlopt->privateData.format &&
        xmlopt->privateData.format(&buf, obj) < 0)
        goto error;

    if (virDomainDefFormatInternal(obj->def, caps, flags, &buf) < 0)
        goto error;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domstatus>\n");

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static bool
virDomainDeviceIsUSB(virDomainDeviceDefPtr dev)
{
    int t = dev->type;
    if ((t == VIR_DOMAIN_DEVICE_DISK &&
         dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) ||
        (t == VIR_DOMAIN_DEVICE_INPUT &&
         dev->data.input->type == VIR_DOMAIN_INPUT_BUS_USB) ||
        (t == VIR_DOMAIN_DEVICE_HOSTDEV &&
         dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
         dev->data.hostdev->source.subsys.type ==
         VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) ||
        (t == VIR_DOMAIN_DEVICE_HUB &&
         dev->data.hub->type == VIR_DOMAIN_HUB_TYPE_USB) ||
        (t == VIR_DOMAIN_DEVICE_REDIRDEV &&
         dev->data.redirdev->bus == VIR_DOMAIN_REDIRDEV_BUS_USB))
        return true;

    return false;
}

static int
virDomainDeviceInfoCheckBootIndex(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                  virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                                  virDomainDeviceInfoPtr info,
                                  void *opaque)
{
    virDomainDeviceInfoPtr newinfo = opaque;

    if (info->bootIndex == newinfo->bootIndex) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("boot order %u is already used by another device"),
                       newinfo->bootIndex);
        return -1;
    }
    return 0;
}


/**
 * virDomainDefGetDiskByWWN:
 * @def: domain definition
 * @wwn: wwn of a disk to find
 *
 * Returns a disk definition pointer corresponding to the given WWN identifier
 * or NULL either if @wwn was NULL or if disk with given WWN is not present in
 * the domain definition.
 */
static virDomainDiskDefPtr
virDomainDefGetDiskByWWN(virDomainDefPtr def,
                         const char *wwn)
{
    size_t i;

    if (!wwn)
        return NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ_NULLABLE(def->disks[i]->wwn, wwn))
            return def->disks[i];
    }

    return NULL;
}


int
virDomainDefCompatibleDevice(virDomainDefPtr def,
                             virDomainDeviceDefPtr dev,
                             virDomainDeviceAction action)
{
    virDomainDeviceInfoPtr info = virDomainDeviceGetInfo(dev);

    if (action != VIR_DOMAIN_DEVICE_ACTION_ATTACH)
        return 0;

    if (!virDomainDefHasUSB(def) &&
        def->os.type != VIR_DOMAIN_OSTYPE_EXE &&
        virDomainDeviceIsUSB(dev)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Device configuration is not compatible: "
                         "Domain has no USB bus support"));
        return -1;
    }

    if (info && info->bootIndex > 0) {
        if (def->os.nBootDevs > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("per-device boot elements cannot be used"
                             " together with os/boot elements"));
            return -1;
        }
        if (virDomainDeviceInfoIterate(def,
                                       virDomainDeviceInfoCheckBootIndex,
                                       info) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_MEMORY) {
        unsigned long long sz = dev->data.memory->size;

        if ((virDomainDefGetMemoryTotal(def) + sz) > def->mem.max_memory) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Attaching memory device with size '%llu' would "
                             "exceed domain's maxMemory config"), sz);
            return -1;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        if (!!virDomainDefGetDiskByWWN(def, dev->data.disk->wwn)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Domain already has a disk with wwn '%s'"),
                           dev->data.disk->wwn);
            return -1;
        }
    }

    return 0;
}

int
virDomainSaveXML(const char *configDir,
                 virDomainDefPtr def,
                 const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *configFile = NULL;
    int ret = -1;

    if (!configDir)
        return 0;

    if ((configFile = virDomainConfigFile(configDir, def->name)) == NULL)
        goto cleanup;

    if (virFileMakePath(configDir) < 0) {
        virReportSystemError(errno,
                             _("cannot create config directory '%s'"),
                             configDir);
        goto cleanup;
    }

    virUUIDFormat(def->uuid, uuidstr);
    ret = virXMLSaveFile(configFile,
                         virXMLPickShellSafeComment(def->name, uuidstr), "edit",
                         xml);

 cleanup:
    VIR_FREE(configFile);
    return ret;
}

int
virDomainSaveConfig(const char *configDir,
                    virCapsPtr caps,
                    virDomainDefPtr def)
{
    int ret = -1;
    char *xml;

    if (!(xml = virDomainDefFormat(def, caps, VIR_DOMAIN_DEF_FORMAT_SECURE)))
        goto cleanup;

    if (virDomainSaveXML(configDir, def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}

int
virDomainSaveStatus(virDomainXMLOptionPtr xmlopt,
                    const char *statusDir,
                    virDomainObjPtr obj,
                    virCapsPtr caps)
{
    unsigned int flags = (VIR_DOMAIN_DEF_FORMAT_SECURE |
                          VIR_DOMAIN_DEF_FORMAT_STATUS |
                          VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                          VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                          VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST);

    int ret = -1;
    char *xml;

    if (!(xml = virDomainObjFormat(xmlopt, obj, caps, flags)))
        goto cleanup;

    if (virDomainSaveXML(statusDir, obj->def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


int
virDomainDeleteConfig(const char *configDir,
                      const char *autostartDir,
                      virDomainObjPtr dom)
{
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if ((configFile = virDomainConfigFile(configDir, dom->def->name)) == NULL)
        goto cleanup;
    if ((autostartLink = virDomainConfigFile(autostartDir,
                                             dom->def->name)) == NULL)
        goto cleanup;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);
    dom->autostart = 0;

    if (unlink(configFile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("cannot remove config %s"),
                             configFile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    return ret;
}

char
*virDomainConfigFile(const char *dir,
                     const char *name)
{
    char *ret;

    ignore_value(virAsprintf(&ret, "%s/%s.xml", dir, name));
    return ret;
}

/* Translates a device name of the form (regex) "[fhv]d[a-z]+" into
 * the corresponding bus,index combination (e.g. sda => (0,0), sdi (1,1),
 *                                               hdd => (1,1), vdaa => (0,26))
 * @param disk The disk device
 * @param busIdx parsed bus number
 * @param devIdx parsed device number
 * @return 0 on success, -1 on failure
 */
int
virDiskNameToBusDeviceIndex(virDomainDiskDefPtr disk,
                            int *busIdx,
                            int *devIdx)
{

    int idx = virDiskNameToIndex(disk->dst);
    if (idx < 0)
        return -1;

    switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            *busIdx = idx / 2;
            *devIdx = idx % 2;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            *busIdx = idx / 7;
            *devIdx = idx % 7;
            break;
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_SD:
        default:
            *busIdx = 0;
            *devIdx = idx;
            break;
    }

    return 0;
}

int
virDomainFSInsert(virDomainDefPtr def, virDomainFSDefPtr fs)
{

    return VIR_APPEND_ELEMENT(def->fss, def->nfss, fs);
}

virDomainFSDefPtr
virDomainFSRemove(virDomainDefPtr def, size_t i)
{
    virDomainFSDefPtr fs = def->fss[i];

    VIR_DELETE_ELEMENT(def->fss, i, def->nfss);
    return fs;
}

virDomainFSDefPtr
virDomainGetFilesystemForTarget(virDomainDefPtr def,
                                const char *target)
{
    size_t i;

    for (i = 0; i < def->nfss; i++) {
        if (STREQ(def->fss[i]->dst, target))
            return def->fss[i];
    }

    return NULL;
}


int
virDomainChrDefForeach(virDomainDefPtr def,
                       bool abortOnError,
                       virDomainChrDefIterator iter,
                       void *opaque)
{
    size_t i;
    int rc = 0;

    for (i = 0; i < def->nserials; i++) {
        if ((iter)(def,
                   def->serials[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            goto done;
    }

    for (i = 0; i < def->nparallels; i++) {
        if ((iter)(def,
                   def->parallels[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            goto done;
    }

    for (i = 0; i < def->nchannels; i++) {
        if ((iter)(def,
                   def->channels[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            goto done;
    }
    for (i = 0; i < def->nconsoles; i++) {
        if (virDomainSkipBackcompatConsole(def, i, false))
            continue;
        if ((iter)(def,
                   def->consoles[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            goto done;
    }

 done:
    return rc;
}


int
virDomainSmartcardDefForeach(virDomainDefPtr def,
                             bool abortOnError,
                             virDomainSmartcardDefIterator iter,
                             void *opaque)
{
    size_t i;
    int rc = 0;

    for (i = 0; i < def->nsmartcards; i++) {
        if ((iter)(def,
                   def->smartcards[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            goto done;
    }

 done:
    return rc;
}


int
virDomainUSBDeviceDefForeach(virDomainDefPtr def,
                             virDomainUSBDeviceDefIterator iter,
                             void *opaque,
                             bool skipHubs)
{
    size_t i;

    /* usb-hub */
    if (!skipHubs) {
        for (i = 0; i < def->nhubs; i++) {
            virDomainHubDefPtr hub = def->hubs[i];
            if (hub->type == VIR_DOMAIN_HUB_TYPE_USB) {
                if (iter(&hub->info, opaque) < 0)
                    return -1;
            }
        }
    }

    /* usb-host */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            if (iter(hostdev->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-storage */
    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
            if (iter(&disk->info, opaque) < 0)
                return -1;
        }
    }

    /* TODO: add def->nets here when libvirt starts supporting usb-net */

    /* usb-ccid */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID) {
            if (iter(&cont->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-kbd, usb-mouse, usb-tablet */
    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDefPtr input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            if (iter(&input->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-serial */
    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr serial = def->serials[i];
        if (serial->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB) {
            if (iter(&serial->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-audio model=usb */
    for (i = 0; i < def->nsounds; i++) {
        virDomainSoundDefPtr sound = def->sounds[i];
        if (sound->model == VIR_DOMAIN_SOUND_MODEL_USB) {
            if (iter(&sound->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-redir */
    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDefPtr redirdev = def->redirdevs[i];
        if (redirdev->bus == VIR_DOMAIN_REDIRDEV_BUS_USB) {
            if (iter(&redirdev->info, opaque) < 0)
                return -1;
        }
    }

    return 0;
}


/* Call iter(disk, name, depth, opaque) for each element of disk and
 * its backing chain in the pre-populated disk->src.backingStore.
 * ignoreOpenFailure determines whether to warn about a chain that
 * mentions a backing file without also having metadata on that
 * file.  */
int
virDomainDiskDefForeachPath(virDomainDiskDefPtr disk,
                            bool ignoreOpenFailure,
                            virDomainDiskDefPathIterator iter,
                            void *opaque)
{
    int ret = -1;
    size_t depth = 0;
    virStorageSourcePtr tmp;
    char *brokenRaw = NULL;

    if (!ignoreOpenFailure) {
        if (virStorageFileChainGetBroken(disk->src, &brokenRaw) < 0)
            goto cleanup;

        if (brokenRaw) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to visit backing chain file %s"),
                           brokenRaw);
            goto cleanup;
        }
    }

    for (tmp = disk->src; tmp; tmp = tmp->backingStore) {
        /* execute the callback only for local storage */
        if (virStorageSourceIsLocalStorage(tmp) &&
            tmp->path) {
            if (iter(disk, tmp->path, depth, opaque) < 0)
                goto cleanup;
        }

        depth++;
    }

    ret = 0;

 cleanup:
    VIR_FREE(brokenRaw);
    return ret;
}


/* Copy src into a new definition; with the quality of the copy
 * depending on the migratable flag (false for transitions between
 * persistent and active, true for transitions across save files or
 * snapshots).  */
virDomainDefPtr
virDomainDefCopy(virDomainDefPtr src,
                 virCapsPtr caps,
                 virDomainXMLOptionPtr xmlopt,
                 void *parseOpaque,
                 bool migratable)
{
    char *xml;
    virDomainDefPtr ret;
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;

    if (migratable)
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE | VIR_DOMAIN_DEF_FORMAT_MIGRATABLE;

    /* Easiest to clone via a round-trip through XML.  */
    if (!(xml = virDomainDefFormat(src, caps, format_flags)))
        return NULL;

    ret = virDomainDefParseString(xml, caps, xmlopt, parseOpaque, parse_flags);

    VIR_FREE(xml);
    return ret;
}

virDomainDefPtr
virDomainObjCopyPersistentDef(virDomainObjPtr dom,
                              virCapsPtr caps,
                              virDomainXMLOptionPtr xmlopt)
{
    virDomainDefPtr cur;

    cur = virDomainObjGetPersistentDef(caps, xmlopt, dom);
    return virDomainDefCopy(cur, caps, xmlopt, NULL, false);
}


virDomainState
virDomainObjGetState(virDomainObjPtr dom, int *reason)
{
    if (reason)
        *reason = dom->state.reason;

    return dom->state.state;
}


void
virDomainObjSetState(virDomainObjPtr dom, virDomainState state, int reason)
{
    int last = -1;

    switch (state) {
    case VIR_DOMAIN_NOSTATE:
        last = VIR_DOMAIN_NOSTATE_LAST;
        break;
    case VIR_DOMAIN_RUNNING:
        last = VIR_DOMAIN_RUNNING_LAST;
        break;
    case VIR_DOMAIN_BLOCKED:
        last = VIR_DOMAIN_BLOCKED_LAST;
        break;
    case VIR_DOMAIN_PAUSED:
        last = VIR_DOMAIN_PAUSED_LAST;
        break;
    case VIR_DOMAIN_SHUTDOWN:
        last = VIR_DOMAIN_SHUTDOWN_LAST;
        break;
    case VIR_DOMAIN_SHUTOFF:
        last = VIR_DOMAIN_SHUTOFF_LAST;
        break;
    case VIR_DOMAIN_CRASHED:
        last = VIR_DOMAIN_CRASHED_LAST;
        break;
    case VIR_DOMAIN_PMSUSPENDED:
        last = VIR_DOMAIN_PMSUSPENDED_LAST;
        break;
    default:
        last = -1;
    }

    if (last < 0) {
        VIR_ERROR(_("invalid domain state: %d"), state);
        return;
    }

    dom->state.state = state;
    if (reason > 0 && reason < last)
        dom->state.reason = reason;
    else
        dom->state.reason = 0;
}


const char *
virDomainStateReasonToString(virDomainState state, int reason)
{
    switch (state) {
    case VIR_DOMAIN_NOSTATE:
        return virDomainNostateReasonTypeToString(reason);
    case VIR_DOMAIN_RUNNING:
        return virDomainRunningReasonTypeToString(reason);
    case VIR_DOMAIN_BLOCKED:
        return virDomainBlockedReasonTypeToString(reason);
    case VIR_DOMAIN_PAUSED:
        return virDomainPausedReasonTypeToString(reason);
    case VIR_DOMAIN_SHUTDOWN:
        return virDomainShutdownReasonTypeToString(reason);
    case VIR_DOMAIN_SHUTOFF:
        return virDomainShutoffReasonTypeToString(reason);
    case VIR_DOMAIN_CRASHED:
        return virDomainCrashedReasonTypeToString(reason);
    case VIR_DOMAIN_PMSUSPENDED:
        return virDomainPMSuspendedReasonTypeToString(reason);
    case VIR_DOMAIN_LAST:
        break;
    }
    VIR_WARN("Unexpected domain state: %d", state);
    return NULL;
}


int
virDomainStateReasonFromString(virDomainState state, const char *reason)
{
    switch (state) {
    case VIR_DOMAIN_NOSTATE:
        return virDomainNostateReasonTypeFromString(reason);
    case VIR_DOMAIN_RUNNING:
        return virDomainRunningReasonTypeFromString(reason);
    case VIR_DOMAIN_BLOCKED:
        return virDomainBlockedReasonTypeFromString(reason);
    case VIR_DOMAIN_PAUSED:
        return virDomainPausedReasonTypeFromString(reason);
    case VIR_DOMAIN_SHUTDOWN:
        return virDomainShutdownReasonTypeFromString(reason);
    case VIR_DOMAIN_SHUTOFF:
        return virDomainShutoffReasonTypeFromString(reason);
    case VIR_DOMAIN_CRASHED:
        return virDomainCrashedReasonTypeFromString(reason);
    case VIR_DOMAIN_PMSUSPENDED:
        return virDomainPMSuspendedReasonTypeFromString(reason);
    case VIR_DOMAIN_LAST:
        break;
    }
    VIR_WARN("Unexpected domain state: %d", state);
    return -1;
}


/* Some access functions to gloss over the difference between NetDef
 * (<interface>) and ActualNetDef (<actual>). If the NetDef has an
 * ActualNetDef, return the requested value from the ActualNetDef,
 * otherwise return the value from the NetDef.
 */

virDomainNetType
virDomainNetGetActualType(virDomainNetDefPtr iface)
{
    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
        return iface->type;
    if (!iface->data.network.actual)
        return iface->type;
    return iface->data.network.actual->type;
}

const char *
virDomainNetGetActualBridgeName(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_BRIDGE)
        return iface->data.bridge.brname;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        (iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
         iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_NETWORK))
        return iface->data.network.actual->data.bridge.brname;
    return NULL;
}

int
virDomainNetGetActualBridgeMACTableManager(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        (iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
         iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_NETWORK))
        return iface->data.network.actual->data.bridge.macTableManager;
    return 0;
}

const char *
virDomainNetGetActualDirectDev(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.direct.linkdev;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.network.actual->data.direct.linkdev;
    return NULL;
}

int
virDomainNetGetActualDirectMode(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.direct.mode;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.network.actual->data.direct.mode;
    return 0;
}

virDomainHostdevDefPtr
virDomainNetGetActualHostdev(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)
        return &iface->data.hostdev.def;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)
        return &iface->data.network.actual->data.hostdev.def;
    return NULL;
}

virNetDevVPortProfilePtr
virDomainNetGetActualVirtPortProfile(virDomainNetDefPtr iface)
{
    switch (iface->type) {
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        return iface->virtPortProfile;
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (!iface->data.network.actual)
            return NULL;
        switch (iface->data.network.actual->type) {
        case VIR_DOMAIN_NET_TYPE_DIRECT:
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
            return iface->data.network.actual->virtPortProfile;
        default:
            return NULL;
        }
    default:
        return NULL;
    }
}

virNetDevBandwidthPtr
virDomainNetGetActualBandwidth(virDomainNetDefPtr iface)
{
    /* if there is an ActualNetDef, *always* return
     * its bandwidth rather than the NetDef's bandwidth.
     */
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual)
        return iface->data.network.actual->bandwidth;
    return iface->bandwidth;
}

virNetDevVlanPtr
virDomainNetGetActualVlan(virDomainNetDefPtr iface)
{
    virNetDevVlanPtr vlan = &iface->vlan;

    /* if there is an ActualNetDef, *always* return
     * its vlan rather than the NetDef's vlan.
     */
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual)
        vlan = &iface->data.network.actual->vlan;

    if (vlan->nTags > 0)
        return vlan;
    return NULL;
}


bool
virDomainNetGetActualTrustGuestRxFilters(virDomainNetDefPtr iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual)
        return (iface->data.network.actual->trustGuestRxFilters
                == VIR_TRISTATE_BOOL_YES);
    return iface->trustGuestRxFilters == VIR_TRISTATE_BOOL_YES;
}


/* Return listens[i] from the appropriate union for the graphics
 * type, or NULL if this is an unsuitable type, or the index is out of
 * bounds. If force0 is TRUE, i == 0, and there is no listen array,
 * allocate one with a single item. */
virDomainGraphicsListenDefPtr
virDomainGraphicsGetListen(virDomainGraphicsDefPtr def, size_t i)
{
    if (!def->listens || (def->nListens <= i))
        return NULL;

    return &def->listens[i];
}


int
virDomainGraphicsListenAppendAddress(virDomainGraphicsDefPtr def,
                                     const char *address)
{
    virDomainGraphicsListenDef glisten;

    memset(&glisten, 0, sizeof(glisten));

    glisten.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;

    if (VIR_STRDUP(glisten.address, address) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(def->listens, def->nListens, glisten) < 0)
        goto error;

    return 0;
 error:
    VIR_FREE(glisten.address);
    return -1;
}


int
virDomainGraphicsListenAppendSocket(virDomainGraphicsDefPtr def,
                                    const char *socketPath)
{
    virDomainGraphicsListenDef glisten;

    memset(&glisten, 0, sizeof(glisten));

    glisten.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;

    if (VIR_STRDUP(glisten.socket, socketPath) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT_COPY(def->listens, def->nListens, glisten) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(glisten.socket);
    return -1;
}


/**
 * virDomainNetFind:
 * @def: domain's def
 * @device: could be the interface name or MAC address
 *
 * Finds a domain's net def, given the interface name or MAC address
 *
 * Returns a pointer to the net def or NULL if not found.
 */
virDomainNetDefPtr
virDomainNetFind(virDomainDefPtr def, const char *device)
{
    bool isMac = false;
    virDomainNetDefPtr net = NULL;
    virMacAddr mac;
    size_t i;

    if (virMacAddrParse(device, &mac) == 0)
        isMac = true;

    if (isMac) {
        for (i = 0; i < def->nnets; i++) {
            if (virMacAddrCmp(&mac, &def->nets[i]->mac) == 0) {
                net = def->nets[i];
                break;
            }
        }
    } else { /* ifname */
        for (i = 0; i < def->nnets; i++) {
            if (STREQ_NULLABLE(device, def->nets[i]->ifname)) {
                net = def->nets[i];
                break;
            }
        }
    }

    return net;
}

/**
 * virDomainDeviceDefCopy:
 * @caps: Capabilities
 * @def: Domain definition to which @src belongs
 * @src: source to be copied
 *
 * virDomainDeviceDefCopy does a deep copy of only the parts of a
 * DeviceDef that are valid when just the flag VIR_DOMAIN_DEF_PARSE_INACTIVE is
 * set. This means that any part of the device xml that is conditionally
 * parsed/formatted based on some other flag being set (or on the INACTIVE
 * flag being reset) *will not* be copied to the destination. Caveat emptor.
 *
 * Returns a pointer to copied @src or NULL in case of error.
 */
virDomainDeviceDefPtr
virDomainDeviceDefCopy(virDomainDeviceDefPtr src,
                       const virDomainDef *def,
                       virCapsPtr caps,
                       virDomainXMLOptionPtr xmlopt)
{
    virDomainDeviceDefPtr ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int flags = VIR_DOMAIN_DEF_FORMAT_INACTIVE | VIR_DOMAIN_DEF_FORMAT_SECURE;
    char *xmlStr = NULL;
    int rc = -1;
    char *netprefix;

    switch ((virDomainDeviceType) src->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        rc = virDomainDiskDefFormat(&buf, src->data.disk, flags);
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        rc = virDomainLeaseDefFormat(&buf, src->data.lease);
        break;
    case VIR_DOMAIN_DEVICE_FS:
        rc = virDomainFSDefFormat(&buf, src->data.fs, flags);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        netprefix = caps->host.netprefix;
        rc = virDomainNetDefFormat(&buf, src->data.net, netprefix, flags);
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        rc = virDomainInputDefFormat(&buf, src->data.input, flags);
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        rc = virDomainSoundDefFormat(&buf, src->data.sound, flags);
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        rc = virDomainVideoDefFormat(&buf, src->data.video, flags);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        rc = virDomainHostdevDefFormat(&buf, src->data.hostdev, flags);
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        rc = virDomainWatchdogDefFormat(&buf, src->data.watchdog, flags);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        rc = virDomainControllerDefFormat(&buf, src->data.controller, flags);
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        rc = virDomainGraphicsDefFormat(&buf, src->data.graphics, flags);
        break;
    case VIR_DOMAIN_DEVICE_HUB:
        rc = virDomainHubDefFormat(&buf, src->data.hub, flags);
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        rc = virDomainRedirdevDefFormat(&buf, src->data.redirdev, flags);
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        rc = virDomainRNGDefFormat(&buf, src->data.rng, flags);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        rc = virDomainChrDefFormat(&buf, src->data.chr, flags);
        break;
    case VIR_DOMAIN_DEVICE_TPM:
        rc = virDomainTPMDefFormat(&buf, src->data.tpm, flags);
        break;
    case VIR_DOMAIN_DEVICE_PANIC:
        rc = virDomainPanicDefFormat(&buf, src->data.panic);
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        rc = virDomainMemoryDefFormat(&buf, src->data.memory, flags);
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        rc = virDomainShmemDefFormat(&buf, src->data.shmem, flags);
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Copying definition of '%d' type "
                         "is not implemented yet."),
                       src->type);
        goto cleanup;
    }

    if (rc < 0)
        goto cleanup;

    xmlStr = virBufferContentAndReset(&buf);
    ret = virDomainDeviceDefParse(xmlStr, def, caps, xmlopt,
                                  VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                  VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);

 cleanup:
    VIR_FREE(xmlStr);
    return ret;
}


virSecurityLabelDefPtr
virDomainDefGetSecurityLabelDef(virDomainDefPtr def, const char *model)
{
    size_t i;
    virSecurityLabelDefPtr seclabel = NULL;

    if (def == NULL || model == NULL)
        return NULL;

    for (i = 0; i < def->nseclabels; i++) {
        if (def->seclabels[i]->model == NULL)
            continue;
        if (STREQ(def->seclabels[i]->model, model))
            return def->seclabels[i];
    }

    return seclabel;
}


virSecurityDeviceLabelDefPtr
virDomainChrDefGetSecurityLabelDef(virDomainChrDefPtr def, const char *model)
{
    size_t i;

    if (def == NULL)
        return NULL;

    for (i = 0; i < def->nseclabels; i++) {
        if (STREQ_NULLABLE(def->seclabels[i]->model, model))
            return def->seclabels[i];
    }
    return NULL;
}


typedef struct {
    const char *devAlias;
    virDomainDeviceDefPtr dev;
} virDomainDefFindDeviceCallbackData;

static int
virDomainDefFindDeviceCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                               virDomainDeviceDefPtr dev,
                               virDomainDeviceInfoPtr info,
                               void *opaque)
{
    virDomainDefFindDeviceCallbackData *data = opaque;

    if (STREQ_NULLABLE(info->alias, data->devAlias)) {
        *data->dev = *dev;
        return -1;
    }
    return 0;
}

int
virDomainDefFindDevice(virDomainDefPtr def,
                       const char *devAlias,
                       virDomainDeviceDefPtr dev,
                       bool reportError)
{
    virDomainDefFindDeviceCallbackData data = { devAlias, dev };

    dev->type = VIR_DOMAIN_DEVICE_NONE;
    virDomainDeviceInfoIterateInternal(def, virDomainDefFindDeviceCallback,
                                       true, &data);

    if (dev->type == VIR_DOMAIN_DEVICE_NONE) {
        if (reportError) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no device found with alias %s"), devAlias);
        } else {
            VIR_DEBUG("no device found with alias %s", devAlias);
        }
        return -1;
    }

    return 0;
}


char *
virDomainObjGetMetadata(virDomainObjPtr vm,
                        int type,
                        const char *uri,
                        unsigned int flags)
{
    virDomainDefPtr def;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, NULL);

    if (type >= VIR_DOMAIN_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%d'"), type);
        goto cleanup;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    switch ((virDomainMetadataType) type) {
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        if (VIR_STRDUP(ret, def->description) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_METADATA_TITLE:
        if (VIR_STRDUP(ret, def->title) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_METADATA_ELEMENT:
        if (!def->metadata)
            break;

        if (virXMLExtractNamespaceXML(def->metadata, uri, &ret) < 0)
            goto cleanup;
        break;

    /* coverity[dead_error_begin] */
    case VIR_DOMAIN_METADATA_LAST:
        break;
    }

    if (!ret)
        virReportError(VIR_ERR_NO_DOMAIN_METADATA, "%s",
                       _("Requested metadata element is not present"));

 cleanup:
    return ret;
}


static int
virDomainDefSetMetadata(virDomainDefPtr def,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri)
{
    xmlDocPtr doc = NULL;
    xmlNodePtr old;
    xmlNodePtr new = NULL;
    char *tmp;
    int ret = -1;

    if (type >= VIR_DOMAIN_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%d'"), type);
        goto cleanup;
    }

    switch ((virDomainMetadataType) type) {
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        if (VIR_STRDUP(tmp, metadata) < 0)
            goto cleanup;

        VIR_FREE(def->description);
        def->description = tmp;
        break;

    case VIR_DOMAIN_METADATA_TITLE:
        if (VIR_STRDUP(tmp, metadata) < 0)
            goto cleanup;

        VIR_FREE(def->title);
        def->title = tmp;
        break;

    case VIR_DOMAIN_METADATA_ELEMENT:
        if (metadata) {
            /* parse and modify the xml from the user */
            if (!(doc = virXMLParseString(metadata, _("(metadata_xml)"))))
                goto cleanup;

            if (virXMLInjectNamespace(doc->children, uri, key) < 0)
                goto cleanup;

            /* create the root node if needed */
            if (!def->metadata &&
                !(def->metadata = xmlNewNode(NULL, (unsigned char *)"metadata"))) {
                virReportOOMError();
                goto cleanup;
            }

            if (!(new = xmlCopyNode(doc->children, 1))) {
                virReportOOMError();
                goto cleanup;
            }
        }

        /* remove possible other nodes sharing the namespace */
        while ((old = virXMLFindChildNodeByNs(def->metadata, uri))) {
            xmlUnlinkNode(old);
            xmlFreeNode(old);
        }

        if (new &&
            !(xmlAddChild(def->metadata, new))) {
            xmlFreeNode(new);
            virReportOOMError();
            goto cleanup;
        }
        break;

    /* coverity[dead_error_begin] */
    case VIR_DOMAIN_METADATA_LAST:
        break;
    }

    ret = 0;

 cleanup:
    xmlFreeDoc(doc);
    return ret;
}


int
virDomainObjSetMetadata(virDomainObjPtr vm,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri,
                        virCapsPtr caps,
                        virDomainXMLOptionPtr xmlopt,
                        const char *stateDir,
                        const char *configDir,
                        unsigned int flags)
{
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        return -1;

    if (def) {
        if (virDomainDefSetMetadata(def, type, metadata, key, uri) < 0)
            return -1;

        if (virDomainSaveStatus(xmlopt, stateDir, vm, caps) < 0)
            return -1;
    }

    if (persistentDef) {
        if (virDomainDefSetMetadata(persistentDef, type, metadata, key,
                                    uri) < 0)
            return -1;

        if (virDomainSaveConfig(configDir, caps, persistentDef) < 0)
            return -1;
    }

    return 0;
}


bool
virDomainDefNeedsPlacementAdvice(virDomainDefPtr def)
{
    if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
        return true;

    if (virDomainNumatuneHasPlacementAuto(def->numa))
        return true;

    return false;
}


int
virDomainDiskDefCheckDuplicateInfo(const virDomainDiskDef *a,
                                   const virDomainDiskDef *b)
{
    if (STREQ(a->dst, b->dst)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("target '%s' duplicated for disk sources '%s' and '%s'"),
                       a->dst,
                       NULLSTR(virDomainDiskGetSource(a)),
                       NULLSTR(virDomainDiskGetSource(b)));
        return -1;
    }

    /* Duplicate WWN/serial isn't usually problematic for the OS and
     * forbidding it would possibly inhibit using multipath configurations */

    return 0;
}


/**
 * virDomainDefHasMemballoon:
 * @def: domain definition
 *
 * Returns true if domain has a memory ballooning device configured.
 */
bool
virDomainDefHasMemballoon(const virDomainDef *def)
{
    return def->memballoon &&
           def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE;
}


/**
 * virDomainObjGetShortName:
 * @vm: Machine for which to get a name
 * @unique: Make sure the name is unique (use id as well)
 *
 * Shorten domain name to avoid possible path length limitations.
 */
char *
virDomainObjGetShortName(const virDomainDef *def)
{
    const int dommaxlen = 20;
    char *ret = NULL;

    ignore_value(virAsprintf(&ret, "%d-%.*s",
                             def->id, dommaxlen, def->name));

    return ret;
}


int
virDomainGetBlkioParametersAssignFromDef(virDomainDefPtr def,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         int maxparams)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *data = NULL;
    size_t i;

#define VIR_BLKIO_ASSIGN(param, format, name)                                  \
    if (*nparams < maxparams) {                                                \
        for (i = 0; i < def->blkio.ndevices; i++) {                            \
            if (!def->blkio.devices[i].param)                                  \
                continue;                                                      \
            virBufferAsprintf(&buf, "%s," format ",",                          \
                              def->blkio.devices[i].path,                      \
                              def->blkio.devices[i].param);                    \
        }                                                                      \
        virBufferTrim(&buf, ",", -1);                                          \
        if (virBufferCheckError(&buf) < 0)                                     \
            goto error;                                                        \
        data = virBufferContentAndReset(&buf);                                 \
        if (virTypedParameterAssign(&(params[(*nparams)++]), name,             \
                                    VIR_TYPED_PARAM_STRING, data) < 0)         \
            goto error;                                                        \
        data = NULL;                                                           \
    }

    /* blkiotune.device_weight */
    VIR_BLKIO_ASSIGN(weight, "%u", VIR_DOMAIN_BLKIO_DEVICE_WEIGHT);
    /* blkiotune.device_read_iops */
    VIR_BLKIO_ASSIGN(riops, "%u", VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS);
    /* blkiotune.device_write_iops */
    VIR_BLKIO_ASSIGN(wiops, "%u", VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS);
    /* blkiotune.device_read_bps */
    VIR_BLKIO_ASSIGN(rbps, "%llu", VIR_DOMAIN_BLKIO_DEVICE_READ_BPS);
    /* blkiotune.device_write_bps */
    VIR_BLKIO_ASSIGN(wbps, "%llu", VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS);

#undef VIR_BLKIO_ASSIGN

    return 0;

 error:
    VIR_FREE(data);
    virBufferFreeAndReset(&buf);
    return -1;
}


void
virDomainDefVcpuOrderClear(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->maxvcpus; i++)
        def->vcpus[i]->order = 0;
}


/**
 * virDomainDiskSetBlockIOTune:
 * @disk: The disk to set block I/O tuning on
 * @info: The BlockIoTuneInfo to be set on the @disk
 *
 * Set the block I/O tune settings from @info on the @disk, but error out early
 * in case of any error.  That is to make sure nothing will fail half-way.
 *
 * Returns: 0 on success, -1 otherwise
 */
int
virDomainDiskSetBlockIOTune(virDomainDiskDefPtr disk,
                            virDomainBlockIoTuneInfo *info)
{
    char *tmp_group = NULL;

    if (VIR_STRDUP(tmp_group, info->group_name) < 0)
        return -1;

    VIR_FREE(disk->blkdeviotune.group_name);
    disk->blkdeviotune = *info;
    VIR_STEAL_PTR(disk->blkdeviotune.group_name, tmp_group);

    return 0;
}
