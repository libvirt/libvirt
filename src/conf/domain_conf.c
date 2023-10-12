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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "configmake.h"
#include "internal.h"
#include "virerror.h"
#include "checkpoint_conf.h"
#include "datatypes.h"
#include "domain_addr.h"
#include "domain_conf.h"
#include "domain_postparse.h"
#include "domain_validate.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virlog.h"
#include "virnetworkportdef.h"
#include "storage_conf.h"
#include "storage_source_conf.h"
#include "virfile.h"
#include "virbitmap.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "device_conf.h"
#include "network_conf.h"
#include "virsecret.h"
#include "virstring.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnetdevmacvlan.h"
#include "virarptable.h"
#include "virmdev.h"
#include "virdomainsnapshotobjlist.h"
#include "virdomaincheckpointobjlist.h"
#include "virutil.h"
#include "virdomainjob.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_conf");

#define VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS \
    (VIR_DOMAIN_DEF_FORMAT_SECURE | \
     VIR_DOMAIN_DEF_FORMAT_INACTIVE | \
     VIR_DOMAIN_DEF_FORMAT_MIGRATABLE)

VIR_ENUM_IMPL(virDomainTaint,
              VIR_DOMAIN_TAINT_LAST,
              "custom-argv",
              "custom-monitor",
              "high-privileges",
              "shell-scripts",
              "disk-probing",
              "external-launch",
              "host-cpu",
              "hook-script",
              "cdrom-passthrough",
              "custom-dtb",
              "custom-ga-command",
              "custom-hypervisor-feature",
              "deprecated-config",
              "custom-device",
              "nbdkit-restart",
);

VIR_ENUM_IMPL(virDomainTaintMessage,
              VIR_DOMAIN_TAINT_LAST,
              N_("custom configuration parameters specified"),
              N_("custom monitor control commands issued"),
              N_("running with undesirable elevated privileges"),
              N_("network configuration using opaque shell scripts"),
              N_("potentially unsafe disk format probing"),
              N_("managing externally launched configuration"),
              N_("potentially unsafe use of host CPU passthrough"),
              N_("configuration potentially modified by hook script"),
              N_("use of host cdrom passthrough"),
              N_("custom device tree blob used"),
              N_("custom guest agent control commands issued"),
              N_("hypervisor feature autodetection override"),
              N_("use of deprecated configuration settings"),
              N_("custom device configuration"),
              N_("nbdkit restart failed"),
);

VIR_ENUM_IMPL(virDomainVirt,
              VIR_DOMAIN_VIRT_LAST,
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
              "vz",
              "hvf",
);

VIR_ENUM_IMPL(virDomainOS,
              VIR_DOMAIN_OSTYPE_LAST,
              "hvm",
              "xen",
              "linux",
              "exe",
              "uml",
              "xenpvh",
);

VIR_ENUM_IMPL(virDomainHyperVMode,
              VIR_DOMAIN_HYPERV_MODE_LAST,
              "none",
              "custom",
              "passthrough",
);

VIR_ENUM_IMPL(virDomainBoot,
              VIR_DOMAIN_BOOT_LAST,
              "fd",
              "cdrom",
              "hd",
              "network",
);

VIR_ENUM_IMPL(virDomainFeature,
              VIR_DOMAIN_FEATURE_LAST,
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
              "ioapic",
              "hpt",
              "vmcoreinfo",
              "htm",
              "nested-hv",
              "msrs",
              "ccf-assist",
              "xen",
              "cfpc",
              "sbbc",
              "ibs",
              "tcg",
              "async-teardown",
);

VIR_ENUM_IMPL(virDomainCapabilitiesPolicy,
              VIR_DOMAIN_CAPABILITIES_POLICY_LAST,
              "default",
              "allow",
              "deny",
);

VIR_ENUM_IMPL(virDomainHyperv,
              VIR_DOMAIN_HYPERV_LAST,
              "relaxed",
              "vapic",
              "spinlocks",
              "vpindex",
              "runtime",
              "synic",
              "stimer",
              "reset",
              "vendor_id",
              "frequencies",
              "reenlightenment",
              "tlbflush",
              "ipi",
              "evmcs",
              "avic",
);

VIR_ENUM_IMPL(virDomainKVM,
              VIR_DOMAIN_KVM_LAST,
              "hidden",
              "hint-dedicated",
              "poll-control",
              "pv-ipi",
              "dirty-ring",
);

VIR_ENUM_IMPL(virDomainXen,
              VIR_DOMAIN_XEN_LAST,
              "e820_host",
              "passthrough",
);

VIR_ENUM_IMPL(virDomainXenPassthroughMode,
              VIR_DOMAIN_XEN_PASSTHROUGH_MODE_LAST,
              "default",
              "sync_pt",
              "share_pt",
);

VIR_ENUM_IMPL(virDomainMsrsUnknown,
              VIR_DOMAIN_MSRS_UNKNOWN_LAST,
              "ignore",
              "fault",
);

VIR_ENUM_IMPL(virDomainProcessCapsFeature,
              VIR_DOMAIN_PROCES_CAPS_FEATURE_LAST,
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
              "wake_alarm",
);

VIR_ENUM_IMPL(virDomainLifecycle,
              VIR_DOMAIN_LIFECYCLE_LAST,
              "poweroff",
              "reboot",
              "crash",
);

VIR_ENUM_IMPL(virDomainLifecycleAction,
              VIR_DOMAIN_LIFECYCLE_ACTION_LAST,
              "destroy",
              "restart",
              "rename-restart",
              "preserve",
              "coredump-destroy",
              "coredump-restart",
);

VIR_ENUM_IMPL(virDomainLockFailure,
              VIR_DOMAIN_LOCK_FAILURE_LAST,
              "default",
              "poweroff",
              "restart",
              "pause",
              "ignore",
);

VIR_ENUM_IMPL(virDomainDevice,
              VIR_DOMAIN_DEVICE_LAST,
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
              "iommu",
              "vsock",
              "audio",
              "crypto",
);

VIR_ENUM_IMPL(virDomainDiskDevice,
              VIR_DOMAIN_DISK_DEVICE_LAST,
              "disk",
              "cdrom",
              "floppy",
              "lun",
);

VIR_ENUM_IMPL(virDomainDiskGeometryTrans,
              VIR_DOMAIN_DISK_TRANS_LAST,
              "default",
              "none",
              "auto",
              "lba",
);

VIR_ENUM_IMPL(virDomainDiskBus,
              VIR_DOMAIN_DISK_BUS_LAST,
              "none",
              "ide",
              "fdc",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml",
              "sata",
              "sd",
);

VIR_ENUM_IMPL(virDomainDiskCache,
              VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback",
              "directsync",
              "unsafe",
);

VIR_ENUM_IMPL(virDomainDiskErrorPolicy,
              VIR_DOMAIN_DISK_ERROR_POLICY_LAST,
              "default",
              "stop",
              "report",
              "ignore",
              "enospace",
);

VIR_ENUM_IMPL(virDomainDiskIo,
              VIR_DOMAIN_DISK_IO_LAST,
              "default",
              "native",
              "threads",
              "io_uring",
);

VIR_ENUM_IMPL(virDomainDeviceSGIO,
              VIR_DOMAIN_DEVICE_SGIO_LAST,
              "default",
              "filtered",
              "unfiltered",
);

VIR_ENUM_IMPL(virDomainController,
              VIR_DOMAIN_CONTROLLER_TYPE_LAST,
              "ide",
              "fdc",
              "scsi",
              "sata",
              "virtio-serial",
              "ccid",
              "usb",
              "pci",
              "xenbus",
              "isa",
);

VIR_ENUM_IMPL(virDomainControllerModelPCI,
              VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST,
              "pci-root",
              "pcie-root",
              "pci-bridge",
              "dmi-to-pci-bridge",
              "pcie-to-pci-bridge",
              "pcie-root-port",
              "pcie-switch-upstream-port",
              "pcie-switch-downstream-port",
              "pci-expander-bus",
              "pcie-expander-bus",
);

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
              "spapr-pci-host-bridge",
              "pcie-pci-bridge",
);

VIR_ENUM_IMPL(virDomainControllerModelSCSI,
              VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST,
              "auto",
              "buslogic",
              "lsilogic",
              "lsisas1068",
              "vmpvscsi",
              "ibmvscsi",
              "virtio-scsi",
              "lsisas1078",
              "virtio-transitional",
              "virtio-non-transitional",
              "ncr53c90",
              "dc390",
              "am53c974",
);

VIR_ENUM_IMPL(virDomainControllerModelISA, VIR_DOMAIN_CONTROLLER_MODEL_ISA_LAST,
);

VIR_ENUM_IMPL(virDomainControllerModelUSB,
              VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST,
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
              "none",
);

VIR_ENUM_IMPL(virDomainControllerModelIDE,
              VIR_DOMAIN_CONTROLLER_MODEL_IDE_LAST,
              "piix3",
              "piix4",
              "ich6",
);

VIR_ENUM_IMPL(virDomainControllerModelVirtioSerial,
              VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_LAST,
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainFS,
              VIR_DOMAIN_FS_TYPE_LAST,
              "mount",
              "block",
              "file",
              "template",
              "ram",
              "bind",
              "volume",
);

VIR_ENUM_IMPL(virDomainFSDriver,
              VIR_DOMAIN_FS_DRIVER_TYPE_LAST,
              "default",
              "path",
              "handle",
              "loop",
              "nbd",
              "ploop",
              "virtiofs",
);

VIR_ENUM_IMPL(virDomainFSAccessMode,
              VIR_DOMAIN_FS_ACCESSMODE_LAST,
              "",
              "passthrough",
              "mapped",
              "squash",
);

VIR_ENUM_IMPL(virDomainFSWrpolicy,
              VIR_DOMAIN_FS_WRPOLICY_LAST,
              "default",
              "immediate",
);

VIR_ENUM_IMPL(virDomainFSModel,
              VIR_DOMAIN_FS_MODEL_LAST,
              "default",
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainFSMultidevs,
              VIR_DOMAIN_FS_MULTIDEVS_LAST,
              "default",
              "remap",
              "forbid",
              "warn",
);

VIR_ENUM_IMPL(virDomainFSCacheMode,
              VIR_DOMAIN_FS_CACHE_MODE_LAST,
              "default",
              "none",
              "always",
);

VIR_ENUM_IMPL(virDomainFSSandboxMode,
              VIR_DOMAIN_FS_SANDBOX_MODE_LAST,
              "default",
              "namespace",
              "chroot",
);


VIR_ENUM_IMPL(virDomainNet,
              VIR_DOMAIN_NET_TYPE_LAST,
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
              "udp",
              "vdpa",
              "null",
              "vds",
);

VIR_ENUM_IMPL(virDomainNetModel,
              VIR_DOMAIN_NET_MODEL_LAST,
              "unknown",
              "netfront",
              "rtl8139",
              "virtio",
              "e1000",
              "e1000e",
              "igb",
              "virtio-transitional",
              "virtio-non-transitional",
              "usb-net",
              "spapr-vlan",
              "lan9118",
              "scm91c111",
              "vlance",
              "vmxnet",
              "vmxnet2",
              "vmxnet3",
              "Am79C970A",
              "Am79C973",
              "82540EM",
              "82545EM",
              "82543GC",
);

VIR_ENUM_IMPL(virDomainNetDriver,
              VIR_DOMAIN_NET_DRIVER_TYPE_LAST,
              "default",
              "qemu",
              "vhost",
);

VIR_ENUM_IMPL(virDomainNetVirtioTxMode,
              VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST,
              "default",
              "iothread",
              "timer",
);

VIR_ENUM_IMPL(virDomainNetTeaming,
              VIR_DOMAIN_NET_TEAMING_TYPE_LAST,
              "none",
              "persistent",
              "transient",
);

VIR_ENUM_IMPL(virDomainNetInterfaceLinkState,
              VIR_DOMAIN_NET_INTERFACE_LINK_STATE_LAST,
              "default",
              "up",
              "down",
);

VIR_ENUM_IMPL(virDomainNetBackend,
              VIR_DOMAIN_NET_BACKEND_LAST,
              "default",
              "passt",
);

VIR_ENUM_IMPL(virDomainNetProto,
              VIR_DOMAIN_NET_PROTO_LAST,
              "none",
              "tcp",
              "udp",
);

VIR_ENUM_IMPL(virDomainChrDeviceState,
              VIR_DOMAIN_CHR_DEVICE_STATE_LAST,
              "default",
              "connected",
              "disconnected",
);

VIR_ENUM_IMPL(virDomainNetMacType,
              VIR_DOMAIN_NET_MAC_TYPE_LAST,
              "",
              "generated",
              "static",
);

VIR_ENUM_IMPL(virDomainChrSerialTarget,
              VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST,
              "none",
              "isa-serial",
              "usb-serial",
              "pci-serial",
              "spapr-vio-serial",
              "system-serial",
              "sclp-serial",
              "isa-debug",
);

VIR_ENUM_IMPL(virDomainChrChannelTarget,
              VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST,
              "none",
              "guestfwd",
              "virtio",
              "xen",
);

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
              "sclplm",
);

VIR_ENUM_IMPL(virDomainChrSerialTargetModel,
              VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_LAST,
              "none",
              "isa-serial",
              "usb-serial",
              "pci-serial",
              "spapr-vty",
              "pl011",
              "sclpconsole",
              "sclplmconsole",
              "16550a",
              "isa-debugcon",
);

VIR_ENUM_IMPL(virDomainChrDevice,
              VIR_DOMAIN_CHR_DEVICE_TYPE_LAST,
              "parallel",
              "serial",
              "console",
              "channel",
);

VIR_ENUM_IMPL(virDomainChr,
              VIR_DOMAIN_CHR_TYPE_LAST,
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
              "nmdm",
              "qemu-vdagent",
              "dbus",
);

VIR_ENUM_IMPL(virDomainChrTcpProtocol,
              VIR_DOMAIN_CHR_TCP_PROTOCOL_LAST,
              "raw",
              "telnet",
              "telnets",
              "tls",
);

VIR_ENUM_IMPL(virDomainChrSpicevmc,
              VIR_DOMAIN_CHR_SPICEVMC_LAST,
              "vdagent",
              "smartcard",
              "usbredir",
);

VIR_ENUM_IMPL(virDomainSmartcard,
              VIR_DOMAIN_SMARTCARD_TYPE_LAST,
              "host",
              "host-certificates",
              "passthrough",
);

VIR_ENUM_IMPL(virDomainSoundCodec,
              VIR_DOMAIN_SOUND_CODEC_TYPE_LAST,
              "duplex",
              "micro",
              "output",
);

VIR_ENUM_IMPL(virDomainSoundModel,
              VIR_DOMAIN_SOUND_MODEL_LAST,
              "sb16",
              "es1370",
              "pcspk",
              "ac97",
              "ich6",
              "ich9",
              "usb",
              "ich7",
);

VIR_ENUM_IMPL(virDomainAudioType,
              VIR_DOMAIN_AUDIO_TYPE_LAST,
              "none",
              "alsa",
              "coreaudio",
              "jack",
              "oss",
              "pulseaudio",
              "sdl",
              "spice",
              "file",
              "dbus",
);

VIR_ENUM_IMPL(virDomainAudioSDLDriver,
              VIR_DOMAIN_AUDIO_SDL_DRIVER_LAST,
              "",
              "esd",
              "alsa",
              "arts",
              "pulseaudio",
);

VIR_ENUM_IMPL(virDomainAudioFormat,
              VIR_DOMAIN_AUDIO_FORMAT_LAST,
              "",
              "u8",
              "s8",
              "u16",
              "s16",
              "u32",
              "s32",
              "f32",
);

VIR_ENUM_IMPL(virDomainKeyWrapCipherName,
              VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_LAST,
              "aes",
              "dea",
);

VIR_ENUM_IMPL(virDomainMemballoonModel,
              VIR_DOMAIN_MEMBALLOON_MODEL_LAST,
              "virtio",
              "xen",
              "none",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainSmbiosMode,
              VIR_DOMAIN_SMBIOS_LAST,
              "none",
              "emulate",
              "host",
              "sysinfo",
);

VIR_ENUM_IMPL(virDomainWatchdogModel,
              VIR_DOMAIN_WATCHDOG_MODEL_LAST,
              "i6300esb",
              "ib700",
              "diag288",
              "itco",
);

VIR_ENUM_IMPL(virDomainWatchdogAction,
              VIR_DOMAIN_WATCHDOG_ACTION_LAST,
              "reset",
              "shutdown",
              "poweroff",
              "pause",
              "dump",
              "none",
              "inject-nmi",
);

VIR_ENUM_IMPL(virDomainPanicModel,
              VIR_DOMAIN_PANIC_MODEL_LAST,
              "default",
              "isa",
              "pseries",
              "hyperv",
              "s390",
              "pvpanic",
);

VIR_ENUM_IMPL(virDomainVideoBackend,
              VIR_DOMAIN_VIDEO_BACKEND_TYPE_LAST,
              "default",
              "qemu",
              "vhostuser",
);

VIR_ENUM_IMPL(virDomainVideo,
              VIR_DOMAIN_VIDEO_TYPE_LAST,
              "default",
              "vga",
              "cirrus",
              "vmvga",
              "xen",
              "vbox",
              "qxl",
              "parallels",
              "virtio",
              "gop",
              "none",
              "bochs",
              "ramfb",
);

VIR_ENUM_IMPL(virDomainVideoVGAConf,
              VIR_DOMAIN_VIDEO_VGACONF_LAST,
              "io",
              "on",
              "off",
);

VIR_ENUM_IMPL(virDomainInput,
              VIR_DOMAIN_INPUT_TYPE_LAST,
              "mouse",
              "tablet",
              "keyboard",
              "passthrough",
              "evdev",
);

VIR_ENUM_IMPL(virDomainInputBus,
              VIR_DOMAIN_INPUT_BUS_LAST,
              "default",
              "ps2",
              "usb",
              "xen",
              "parallels",
              "virtio",
              "none",
);

VIR_ENUM_IMPL(virDomainInputModel,
              VIR_DOMAIN_INPUT_MODEL_LAST,
              "default",
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainInputSourceGrab,
              VIR_DOMAIN_INPUT_SOURCE_GRAB_LAST,
              "default",
              "all",
);

VIR_ENUM_IMPL(virDomainInputSourceGrabToggle,
              VIR_DOMAIN_INPUT_SOURCE_GRAB_TOGGLE_LAST,
              "default",
              "ctrl-ctrl",
              "alt-alt",
              "shift-shift",
              "meta-meta",
              "scrolllock",
              "ctrl-scrolllock",
);

VIR_ENUM_IMPL(virDomainGraphics,
              VIR_DOMAIN_GRAPHICS_TYPE_LAST,
              "sdl",
              "vnc",
              "rdp",
              "desktop",
              "spice",
              "egl-headless",
              "dbus",
);

VIR_ENUM_IMPL(virDomainGraphicsListen,
              VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST,
              "none",
              "address",
              "network",
              "socket",
);

VIR_ENUM_IMPL(virDomainGraphicsAuthConnected,
              VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_LAST,
              "default",
              "fail",
              "disconnect",
              "keep",
);

VIR_ENUM_IMPL(virDomainGraphicsVNCSharePolicy,
              VIR_DOMAIN_GRAPHICS_VNC_SHARE_LAST,
              "default",
              "allow-exclusive",
              "force-shared",
              "ignore",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceChannelName,
              VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST,
              "main",
              "display",
              "inputs",
              "cursor",
              "playback",
              "record",
              "smartcard",
              "usbredir",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceChannelMode,
              VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_LAST,
              "any",
              "secure",
              "insecure",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceImageCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LAST,
              "default",
              "auto_glz",
              "auto_lz",
              "quic",
              "glz",
              "lz",
              "off",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceJpegCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_LAST,
              "default",
              "auto",
              "never",
              "always",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceZlibCompression,
              VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_LAST,
              "default",
              "auto",
              "never",
              "always",
);

VIR_ENUM_IMPL(virDomainMouseMode,
              VIR_DOMAIN_MOUSE_MODE_LAST,
              "default",
              "server",
              "client",
);

VIR_ENUM_IMPL(virDomainGraphicsSpiceStreamingMode,
              VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_LAST,
              "default",
              "filter",
              "all",
              "off",
);

VIR_ENUM_IMPL(virDomainHostdevMode,
              VIR_DOMAIN_HOSTDEV_MODE_LAST,
              "subsystem",
              "capabilities",
);

VIR_ENUM_IMPL(virDomainHostdevSubsys,
              VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST,
              "usb",
              "pci",
              "scsi",
              "scsi_host",
              "mdev",
);

VIR_ENUM_IMPL(virDomainHostdevSubsysPCIBackend,
              VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST,
              "default",
              "kvm",
              "vfio",
              "xen",
);

VIR_ENUM_IMPL(virDomainHostdevSubsysSCSIProtocol,
              VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST,
              "adapter",
              "iscsi",
);


VIR_ENUM_IMPL(virDomainHostdevPCIOrigstate,
              VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_LAST,
              "unbind",
              "removeslot",
              "reprobe",
);

VIR_ENUM_IMPL(virDomainHostdevSubsysUSBGuestReset,
              VIR_DOMAIN_HOSTDEV_USB_GUEST_RESET_LAST,
              "default",
              "off",
              "uninitialized",
              "on",
);

VIR_ENUM_IMPL(virDomainHostdevSubsysSCSIHostProtocol,
              VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_LAST,
              "none",
              "vhost",
);

VIR_ENUM_IMPL(virDomainHostdevSubsysSCSIVHostModel,
              VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_LAST,
              "default",
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainHostdevCaps,
              VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST,
              "storage",
              "misc",
              "net",
);

VIR_ENUM_IMPL(virDomainHub,
              VIR_DOMAIN_HUB_TYPE_LAST,
              "usb",
);

VIR_ENUM_IMPL(virDomainRedirdevBus,
              VIR_DOMAIN_REDIRDEV_BUS_LAST,
              "usb",
);

VIR_ENUM_IMPL(virDomainState,
              VIR_DOMAIN_LAST,
              "nostate",
              "running",
              "blocked",
              "paused",
              "shutdown",
              "shutoff",
              "crashed",
              "pmsuspended",
);

VIR_ENUM_IMPL(virDomainNostateReason,
              VIR_DOMAIN_NOSTATE_LAST,
              "unknown",
);

VIR_ENUM_IMPL(virDomainRunningReason,
              VIR_DOMAIN_RUNNING_LAST,
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
              "post-copy",
              "post-copy failed",
);

VIR_ENUM_IMPL(virDomainBlockedReason,
              VIR_DOMAIN_BLOCKED_LAST,
              "unknown",
);

VIR_ENUM_IMPL(virDomainPausedReason,
              VIR_DOMAIN_PAUSED_LAST,
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
              "post-copy failed",
              "api error",
);

VIR_ENUM_IMPL(virDomainShutdownReason,
              VIR_DOMAIN_SHUTDOWN_LAST,
              "unknown",
              "user",
);

VIR_ENUM_IMPL(virDomainShutoffReason,
              VIR_DOMAIN_SHUTOFF_LAST,
              "unknown",
              "shutdown",
              "destroyed",
              "crashed",
              "migrated",
              "saved",
              "failed",
              "from snapshot",
              "daemon",
);

VIR_ENUM_IMPL(virDomainCrashedReason,
              VIR_DOMAIN_CRASHED_LAST,
              "unknown",
              "panicked",
);

VIR_ENUM_IMPL(virDomainPMSuspendedReason,
              VIR_DOMAIN_PMSUSPENDED_LAST,
              "unknown",
);

VIR_ENUM_IMPL(virDomainSeclabel,
              VIR_DOMAIN_SECLABEL_LAST,
              "default",
              "none",
              "dynamic",
              "static",
);

VIR_ENUM_IMPL(virDomainClockOffset,
              VIR_DOMAIN_CLOCK_OFFSET_LAST,
              "utc",
              "localtime",
              "variable",
              "timezone",
              "absolute",
);

VIR_ENUM_IMPL(virDomainClockBasis,
              VIR_DOMAIN_CLOCK_BASIS_LAST,
              "utc",
              "localtime",
);

VIR_ENUM_IMPL(virDomainTimerName,
              VIR_DOMAIN_TIMER_NAME_LAST,
              "platform",
              "pit",
              "rtc",
              "hpet",
              "tsc",
              "kvmclock",
              "hypervclock",
              "armvtimer",
);

VIR_ENUM_IMPL(virDomainTimerTrack,
              VIR_DOMAIN_TIMER_TRACK_LAST,
              "none",
              "boot",
              "guest",
              "wall",
              "realtime",
);

VIR_ENUM_IMPL(virDomainTimerTickpolicy,
              VIR_DOMAIN_TIMER_TICKPOLICY_LAST,
              "none",
              "delay",
              "catchup",
              "merge",
              "discard",
);

VIR_ENUM_IMPL(virDomainTimerMode,
              VIR_DOMAIN_TIMER_MODE_LAST,
              "none",
              "auto",
              "native",
              "emulate",
              "paravirt",
              "smpsafe",
);

VIR_ENUM_IMPL(virDomainStartupPolicy,
              VIR_DOMAIN_STARTUP_POLICY_LAST,
              "default",
              "mandatory",
              "requisite",
              "optional",
);

VIR_ENUM_IMPL(virDomainCpuPlacementMode,
              VIR_DOMAIN_CPU_PLACEMENT_MODE_LAST,
              "static",
              "auto",
);

VIR_ENUM_IMPL(virDomainDiskTray,
              VIR_DOMAIN_DISK_TRAY_LAST,
              "closed",
              "open",
);

VIR_ENUM_IMPL(virDomainRNGModel,
              VIR_DOMAIN_RNG_MODEL_LAST,
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainRNGBackend,
              VIR_DOMAIN_RNG_BACKEND_LAST,
              "random",
              "egd",
              "builtin",
);

VIR_ENUM_IMPL(virDomainTPMModel,
              VIR_DOMAIN_TPM_MODEL_LAST,
              "default",
              "tpm-tis",
              "tpm-crb",
              "tpm-spapr",
              "spapr-tpm-proxy",
);

VIR_ENUM_IMPL(virDomainTPMBackend,
              VIR_DOMAIN_TPM_TYPE_LAST,
              "passthrough",
              "emulator",
              "external",
);

VIR_ENUM_IMPL(virDomainTPMVersion,
              VIR_DOMAIN_TPM_VERSION_LAST,
              "default",
              "1.2",
              "2.0",
);

VIR_ENUM_IMPL(virDomainTPMPcrBank,
              VIR_DOMAIN_TPM_PCR_BANK_LAST,
              "sha1",
              "sha256",
              "sha384",
              "sha512",
);

VIR_ENUM_IMPL(virDomainIOMMUModel,
              VIR_DOMAIN_IOMMU_MODEL_LAST,
              "intel",
              "smmuv3",
              "virtio",
);

VIR_ENUM_IMPL(virDomainVsockModel,
              VIR_DOMAIN_VSOCK_MODEL_LAST,
              "default",
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainCryptoModel,
              VIR_DOMAIN_CRYPTO_MODEL_LAST,
              "virtio",
);

VIR_ENUM_IMPL(virDomainCryptoType,
              VIR_DOMAIN_CRYPTO_TYPE_LAST,
              "qemu",
);

VIR_ENUM_IMPL(virDomainCryptoBackend,
              VIR_DOMAIN_CRYPTO_BACKEND_LAST,
              "builtin",
              "lkcf",
);

VIR_ENUM_IMPL(virDomainDiskDiscard,
              VIR_DOMAIN_DISK_DISCARD_LAST,
              "default",
              "unmap",
              "ignore",
);

VIR_ENUM_IMPL(virDomainDiskDetectZeroes,
              VIR_DOMAIN_DISK_DETECT_ZEROES_LAST,
              "default",
              "off",
              "on",
              "unmap",
);

VIR_ENUM_IMPL(virDomainDiskModel,
              VIR_DOMAIN_DISK_MODEL_LAST,
              "default",
              "virtio",
              "virtio-transitional",
              "virtio-non-transitional",
);

VIR_ENUM_IMPL(virDomainDiskMirrorState,
              VIR_DOMAIN_DISK_MIRROR_STATE_LAST,
              "none",
              "yes",
              "abort",
              "pivot",
);

VIR_ENUM_IMPL(virDomainMemorySource,
              VIR_DOMAIN_MEMORY_SOURCE_LAST,
              "none",
              "file",
              "anonymous",
              "memfd",
);

VIR_ENUM_IMPL(virDomainMemoryAllocation,
              VIR_DOMAIN_MEMORY_ALLOCATION_LAST,
              "none",
              "immediate",
              "ondemand",
);

VIR_ENUM_IMPL(virDomainLoader,
              VIR_DOMAIN_LOADER_TYPE_LAST,
              "none",
              "rom",
              "pflash",
);

VIR_ENUM_IMPL(virDomainIOAPIC,
              VIR_DOMAIN_IOAPIC_LAST,
              "none",
              "qemu",
              "kvm",
);

VIR_ENUM_IMPL(virDomainHPTResizing,
              VIR_DOMAIN_HPT_RESIZING_LAST,
              "none",
              "enabled",
              "disabled",
              "required",
);

VIR_ENUM_IMPL(virDomainOsDefFirmware,
              VIR_DOMAIN_OS_DEF_FIRMWARE_LAST,
              "none",
              "bios",
              "efi",
);

VIR_ENUM_IMPL(virDomainOsDefFirmwareFeature,
              VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_LAST,
              "enrolled-keys",
              "secure-boot",
);

VIR_ENUM_IMPL(virDomainCFPC,
              VIR_DOMAIN_CFPC_LAST,
              "none",
              "broken",
              "workaround",
              "fixed",
);

VIR_ENUM_IMPL(virDomainSBBC,
              VIR_DOMAIN_SBBC_LAST,
              "none",
              "broken",
              "workaround",
              "fixed",
);

VIR_ENUM_IMPL(virDomainIBS,
              VIR_DOMAIN_IBS_LAST,
              "none",
              "broken",
              "workaround",
              "fixed-ibs",
              "fixed-ccd",
              "fixed-na",
);

VIR_ENUM_IMPL(virDomainSnapshotLocation,
              VIR_DOMAIN_SNAPSHOT_LOCATION_LAST,
              "default",
              "no",
              "internal",
              "external",
              "manual",
);

/* Internal mapping: subset of block job types that can be present in
 * <mirror> XML (remaining types are not two-phase). */
VIR_ENUM_DECL(virDomainBlockJob);
VIR_ENUM_IMPL(virDomainBlockJob,
              VIR_DOMAIN_BLOCK_JOB_TYPE_LAST,
              "", "", "copy", "", "active-commit", "",
);

VIR_ENUM_IMPL(virDomainMemoryModel,
              VIR_DOMAIN_MEMORY_MODEL_LAST,
              "",
              "dimm",
              "nvdimm",
              "virtio-pmem",
              "virtio-mem",
              "sgx-epc",
);

VIR_ENUM_IMPL(virDomainShmemModel,
              VIR_DOMAIN_SHMEM_MODEL_LAST,
              "ivshmem",
              "ivshmem-plain",
              "ivshmem-doorbell",
);

VIR_ENUM_IMPL(virDomainShmemRole,
              VIR_DOMAIN_SHMEM_ROLE_LAST,
              "default",
              "master",
              "peer",
);

VIR_ENUM_IMPL(virDomainLaunchSecurity,
              VIR_DOMAIN_LAUNCH_SECURITY_LAST,
              "",
              "sev",
              "s390-pv",
);

typedef enum {
    VIR_DOMAIN_NET_VHOSTUSER_MODE_NONE,
    VIR_DOMAIN_NET_VHOSTUSER_MODE_CLIENT,
    VIR_DOMAIN_NET_VHOSTUSER_MODE_SERVER,

    VIR_DOMAIN_NET_VHOSTUSER_MODE_LAST
} virDomainNetVhostuserMode;

VIR_ENUM_DECL(virDomainNetVhostuserMode);
VIR_ENUM_IMPL(virDomainNetVhostuserMode,
              VIR_DOMAIN_NET_VHOSTUSER_MODE_LAST,
              "",
              "client",
              "server",
);

typedef enum {
    VIR_DOMAIN_CHR_SOURCE_MODE_CONNECT,
    VIR_DOMAIN_CHR_SOURCE_MODE_BIND,

    VIR_DOMAIN_CHR_SOURCE_MODE_LAST
} virDomainChrSourceMode;


VIR_ENUM_DECL(virDomainChrSourceMode);
VIR_ENUM_IMPL(virDomainChrSourceMode,
              VIR_DOMAIN_CHR_SOURCE_MODE_LAST,
              "connect",
              "bind",
);


static virClass *virDomainObjClass;
static virClass *virDomainXMLOptionClass;
static void virDomainObjDispose(void *obj);
static void virDomainXMLOptionDispose(void *obj);


static void
virDomainChrSourceDefFormat(virBuffer *buf,
                            virDomainChrSourceDef *def,
                            unsigned int flags);


static int
virDomainChrSourceReconnectDefParseXML(virDomainChrSourceReconnectDef *def,
                                       xmlNodePtr node,
                                       xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr cur;

    ctxt->node = node;

    if ((cur = virXPathNode("./reconnect", ctxt))) {
        if (virXMLPropTristateBool(cur, "enabled", VIR_XML_PROP_NONE,
                                   &def->enabled) < 0)
            return -1;

        if (def->enabled == VIR_TRISTATE_BOOL_YES) {
            if (virXMLPropUInt(cur, "timeout", 10, VIR_XML_PROP_REQUIRED,
                               &def->timeout) < 0)
                return -1;
        }
    }

    return 0;
}


static int virDomainObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virDomainXMLOption, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainObj);


static void
virDomainXMLOptionDispose(void *obj)
{
    virDomainXMLOption *xmlopt = obj;

    if (xmlopt->config.privFree)
        (xmlopt->config.privFree)(xmlopt->config.priv);
}

/**
 * virDomainKeyWrapCipherDefParseXML:
 *
 * @def  Domain definition
 * @node An XML cipher node
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
virDomainKeyWrapCipherDefParseXML(virDomainKeyWrapDef *keywrap,
                                  xmlNodePtr node)
{
    virDomainKeyWrapCipherName name;
    virTristateSwitch state;

    if (virXMLPropEnum(node, "name", virDomainKeyWrapCipherNameTypeFromString,
                       VIR_XML_PROP_REQUIRED, &name) < 0)
        return -1;

    if (virXMLPropTristateSwitch(node, "state", VIR_XML_PROP_REQUIRED,
                                 &state) < 0)
        return -1;

    switch (name) {
    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_AES:
        if (keywrap->aes != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("A domain definition can have no more than one cipher node with name %1$s"),
                           virDomainKeyWrapCipherNameTypeToString(name));

            return -1;
        }
        keywrap->aes = state;
        break;

    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_DEA:
        if (keywrap->dea != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("A domain definition can have no more than one cipher node with name %1$s"),
                           virDomainKeyWrapCipherNameTypeToString(name));

            return -1;
        }
        keywrap->dea = state;
        break;

    case VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_LAST:
        break;
    }

    return 0;
}

static int
virDomainKeyWrapDefParseXML(virDomainDef *def, xmlXPathContextPtr ctxt)
{
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree virDomainKeyWrapDef *keywrap = NULL;

    if ((n = virXPathNodeSet("./keywrap/cipher", ctxt, &nodes)) < 0)
        return n;

    keywrap = g_new0(virDomainKeyWrapDef, 1);

    for (i = 0; i < n; i++) {
        if (virDomainKeyWrapCipherDefParseXML(keywrap, nodes[i]) < 0)
            return -1;
    }

    if (keywrap->aes || keywrap->dea)
        def->keywrap = g_steal_pointer(&keywrap);

    return 0;
}


/**
 * virDomainXMLOptionNew:
 *
 * Allocate a new domain XML configuration
 */
virDomainXMLOption *
virDomainXMLOptionNew(virDomainDefParserConfig *config,
                      virDomainXMLPrivateDataCallbacks *priv,
                      virXMLNamespace *xmlns,
                      virDomainABIStability *abi,
                      virSaveCookieCallbacks *saveCookie,
                      virDomainJobObjConfig *jobConfig)
{
    virDomainXMLOption *xmlopt;

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

    if (jobConfig)
        xmlopt->jobObjConfig = *jobConfig;

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
virXMLNamespace *
virDomainXMLOptionGetNamespace(virDomainXMLOption *xmlopt)
{
    return &xmlopt->ns;
}

static int
virDomainVirtioOptionsParseXML(xmlNodePtr driver,
                               virDomainVirtioOptions **virtio)
{
    if (*virtio || !driver)
        return 0;

    *virtio = g_new0(virDomainVirtioOptions, 1);

    if (virXMLPropTristateSwitch(driver, "iommu", VIR_XML_PROP_NONE,
                                 &(*virtio)->iommu) < 0)
        return -1;

    if (virXMLPropTristateSwitch(driver, "ats", VIR_XML_PROP_NONE,
                                 &(*virtio)->ats) < 0)
        return -1;

    if (virXMLPropTristateSwitch(driver, "packed", VIR_XML_PROP_NONE,
                                 &(*virtio)->packed) < 0)
        return -1;

    if (virXMLPropTristateSwitch(driver, "page_per_vq", VIR_XML_PROP_NONE,
                                 &(*virtio)->page_per_vq) < 0)
        return -1;

    return 0;
}


virSaveCookieCallbacks *
virDomainXMLOptionGetSaveCookie(virDomainXMLOption *xmlopt)
{
    return &xmlopt->saveCookie;
}


void
virDomainXMLOptionSetCloseCallbackAlloc(virDomainXMLOption *xmlopt,
                                        virDomainCloseCallbackDataAlloc cb)
{
    xmlopt->closecallbackAlloc = cb;
}


void
virDomainXMLOptionSetMomentPostParse(virDomainXMLOption *xmlopt,
                                     virDomainMomentPostParseCallback cb)
{
    xmlopt->momentPostParse = cb;
}


int
virDomainXMLOptionRunMomentPostParse(virDomainXMLOption *xmlopt,
                                     virDomainMomentDef *def)
{
    if (!xmlopt->momentPostParse)
        return virDomainMomentDefPostParse(def);
    return xmlopt->momentPostParse(def);
}


void
virBlkioDeviceArrayClear(virBlkioDevice *devices,
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
 * and fills a virBlkioDevice *struct.
 */
static int
virDomainBlkioDeviceParseXML(xmlNodePtr root,
                             xmlXPathContextPtr ctxt,
                             virBlkioDevice *dev)
{
    g_autofree char *path = NULL;
    g_autofree char *weight = NULL;
    g_autofree char *read_bytes_sec = NULL;
    g_autofree char *write_bytes_sec = NULL;
    g_autofree char *read_iops_sec = NULL;
    g_autofree char *write_iops_sec = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = root;

    /* To avoid the need for explicit cleanup on failure,
     * don't set dev->path until we're assured of
     * success. Until then, store it in an autofree pointer.
     */
    if (!(path = virXPathString("string(./path)", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing per-device path"));
        return -1;
    }

    if ((weight = virXPathString("string(./weight)", ctxt)) &&
        (virStrToLong_ui(weight, NULL, 10, &dev->weight) < 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not parse weight %1$s"), weight);
        return -1;
    }

    if ((read_bytes_sec = virXPathString("string(./read_bytes_sec)", ctxt)) &&
        (virStrToLong_ull(read_bytes_sec, NULL, 10, &dev->rbps) < 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not parse read bytes sec %1$s"),
                       read_bytes_sec);
        return -1;
    }

    if ((write_bytes_sec = virXPathString("string(./write_bytes_sec)", ctxt)) &&
        (virStrToLong_ull(write_bytes_sec, NULL, 10, &dev->wbps) < 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not parse write bytes sec %1$s"),
                       write_bytes_sec);
        return -1;
    }

    if ((read_iops_sec = virXPathString("string(./read_iops_sec)", ctxt)) &&
        (virStrToLong_ui(read_iops_sec, NULL, 10, &dev->riops) < 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not parse read iops sec %1$s"),
                       read_iops_sec);
        return -1;
    }

    if ((write_iops_sec = virXPathString("string(./write_iops_sec)", ctxt)) &&
        (virStrToLong_ui(write_iops_sec, NULL, 10, &dev->wiops) < 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not parse write iops sec %1$s"),
                       write_iops_sec);
        return -1;
    }

    dev->path = g_steal_pointer(&path);
    return 0;
}


/**
 * virDomainObjTaint:
 * @obj: domain object
 * @taint: domain taint flag
 *
 * Marks @obj as tainted by @taint. Returns 'false' if @obj already has
 * been tainted with @taint.
 */
bool
virDomainObjTaint(virDomainObj *obj,
                  virDomainTaintFlags taint)
{
    unsigned int flag = (1 << taint);

    if (obj->taint & flag)
        return false;

    obj->taint |= flag;
    return true;
}


void virDomainObjDeprecation(virDomainObj *obj,
                             const char *msg)
{
    obj->deprecations = g_renew(char *, obj->deprecations,
                                obj->ndeprecations + 1);
    obj->deprecations[obj->ndeprecations++] = g_strdup(msg);
}


static void
virDomainGraphicsAuthDefClear(virDomainGraphicsAuthDef *def)
{
    if (!def)
        return;

    VIR_FREE(def->passwd);

    /* Don't free def */
}

static void
virDomainGraphicsListenDefClear(virDomainGraphicsListenDef *def)
{
    if (!def)
        return;

    VIR_FREE(def->address);
    VIR_FREE(def->network);
    VIR_FREE(def->socket);
    return;
}


void virDomainGraphicsDefFree(virDomainGraphicsDef *def)
{
    size_t i;

    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        g_free(def->data.vnc.keymap);
        virDomainGraphicsAuthDefClear(&def->data.vnc.auth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        g_free(def->data.sdl.display);
        g_free(def->data.sdl.xauth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        g_free(def->data.desktop.display);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        g_free(def->data.spice.rendernode);
        g_free(def->data.spice.keymap);
        virDomainGraphicsAuthDefClear(&def->data.spice.auth);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        g_free(def->data.egl_headless.rendernode);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        g_free(def->data.dbus.address);
        g_free(def->data.dbus.rendernode);
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    for (i = 0; i < def->nListens; i++)
        virDomainGraphicsListenDefClear(&def->listens[i]);
    g_free(def->listens);

    virObjectUnref(def->privateData);
    g_free(def);
}

const char *virDomainInputDefGetPath(virDomainInputDef *input)
{
    switch ((virDomainInputType) input->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
    case VIR_DOMAIN_INPUT_TYPE_KBD:
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        return NULL;

    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        return input->source.evdev;
    }
    return NULL;
}

void virDomainInputDefFree(virDomainInputDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    g_free(def->source.evdev);
    g_free(def->virtio);
    g_free(def);
}

void virDomainLeaseDefFree(virDomainLeaseDef *def)
{
    if (!def)
        return;

    g_free(def->lockspace);
    g_free(def->key);
    g_free(def->path);

    g_free(def);
}


static virDomainVcpuDef *
virDomainVcpuDefNew(virDomainXMLOption *xmlopt)
{
    virDomainVcpuDef *ret = NULL;
    g_autoptr(virObject) priv = NULL;

    if (xmlopt && xmlopt->privateData.vcpuNew &&
        !(priv = xmlopt->privateData.vcpuNew()))
        return NULL;

    ret = g_new0(virDomainVcpuDef, 1);

    ret->privateData = g_steal_pointer(&priv);

    return ret;
}


static void
virDomainVcpuDefFree(virDomainVcpuDef *info)
{
    if (!info)
        return;

    virBitmapFree(info->cpumask);
    virObjectUnref(info->privateData);
    g_free(info);
}


int
virDomainDefSetVcpusMax(virDomainDef *def,
                        unsigned int maxvcpus,
                        virDomainXMLOption *xmlopt)
{
    size_t oldmax = def->maxvcpus;
    size_t i;

    if (def->maxvcpus == maxvcpus)
        return 0;

    if (def->maxvcpus < maxvcpus) {
        VIR_EXPAND_N(def->vcpus, def->maxvcpus, maxvcpus - def->maxvcpus);

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
virDomainDefSetVcpus(virDomainDef *def,
                     unsigned int vcpus)
{
    size_t i;

    if (vcpus > def->maxvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("maximum vCPU count must not be less than current vCPU count"));
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
virBitmap *
virDomainDefGetOnlineVcpumap(const virDomainDef *def)
{
    virBitmap *ret = virBitmapNew(def->maxvcpus);
    size_t i;

    for (i = 0; i < def->maxvcpus; i++) {
        if (def->vcpus[i]->online)
            ignore_value(virBitmapSetBit(ret, i));
    }

    return ret;
}


virDomainVcpuDef *
virDomainDefGetVcpu(virDomainDef *def,
                    unsigned int vcpu)
{
    if (vcpu >= def->maxvcpus)
        return NULL;

    return def->vcpus[vcpu];
}


static virDomainThreadSchedParam *
virDomainDefGetVcpuSched(virDomainDef *def,
                         unsigned int vcpu)
{
    virDomainVcpuDef *vcpuinfo;

    if (!(vcpuinfo = virDomainDefGetVcpu(def, vcpu))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vCPU '%1$u' is not present in domain definition"),
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
 * @hostcpus: default CPU pinning bitmap based on host CPUs
 * @autoCpuset: Cpu pinning bitmap used in case of automatic cpu pinning
 *
 * Fills the @cpumaps array as documented by the virDomainGetVcpuPinInfo API.
 * In case when automatic cpu pinning is supported, the bitmap should be passed
 * as @autoCpuset.
 *
 * Returns number of filled entries.
 */
int
virDomainDefGetVcpuPinInfoHelper(virDomainDef *def,
                                 int maplen,
                                 int ncpumaps,
                                 unsigned char *cpumaps,
                                 virBitmap *hostcpus,
                                 virBitmap *autoCpuset)
{
    int maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i;

    for (i = 0; i < maxvcpus && i < ncpumaps; i++) {
        virDomainVcpuDef *vcpu = virDomainDefGetVcpu(def, i);
        virBitmap *bitmap = NULL;

        if (vcpu && vcpu->cpumask)
            bitmap = vcpu->cpumask;
        else if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
                 autoCpuset)
            bitmap = autoCpuset;
        else if (def->cpumask)
            bitmap = def->cpumask;
        else
            bitmap = hostcpus;

        virBitmapToDataBuf(bitmap, VIR_GET_CPUMAP(cpumaps, maplen, i), maplen);
    }

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
    if ((tmp *= def->cpu->dies) > UINT_MAX ||
        (tmp *= def->cpu->cores) > UINT_MAX ||
        (tmp *= def->cpu->threads) > UINT_MAX) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cpu topology results in more than %1$u cpus"), UINT_MAX);
        return -1;
    }

    if (maxvcpus)
        *maxvcpus = tmp;

    return 0;
}


static virDomainDiskDef *
virDomainDiskDefNewSource(virDomainXMLOption *xmlopt,
                          virStorageSource **src)
{
    void *privateData = NULL;
    virDomainDiskDef *ret;

    if (xmlopt &&
        xmlopt->privateData.diskNew &&
        !(privateData = xmlopt->privateData.diskNew()))
        return NULL;

    ret = g_new0(virDomainDiskDef, 1);
    ret->src = g_steal_pointer(src);
    ret->privateData = privateData;

    return ret;
}


virDomainDiskDef *
virDomainDiskDefNew(virDomainXMLOption *xmlopt)
{
    g_autoptr(virStorageSource) src = virStorageSourceNew();

    return virDomainDiskDefNewSource(xmlopt, &src);
}


void
virDomainDiskDefFree(virDomainDiskDef *def)
{
    if (!def)
        return;

    virObjectUnref(def->src);
    g_free(def->serial);
    g_free(def->dst);
    virObjectUnref(def->mirror);
    g_free(def->wwn);
    g_free(def->driverName);
    g_free(def->vendor);
    g_free(def->product);
    g_free(def->domain_name);
    g_free(def->blkdeviotune.group_name);
    g_free(def->virtio);
    virDomainDeviceInfoClear(&def->info);
    virObjectUnref(def->privateData);

    g_free(def);
}


int
virDomainDiskGetType(virDomainDiskDef *def)
{
    return def->src->type;
}


void
virDomainDiskSetType(virDomainDiskDef *def, int type)
{
    def->src->type = type;
}


const char *
virDomainDiskGetSource(virDomainDiskDef const *def)
{
    return def->src->path;
}


void
virDomainDiskSetSource(virDomainDiskDef *def, const char *src)
{
    char *tmp = g_strdup(src);
    g_free(def->src->path);
    def->src->path = tmp;
}


void
virDomainDiskEmptySource(virDomainDiskDef *def)
{
    virStorageSource *src = def->src;
    bool readonly = src->readonly;

    virStorageSourceClear(src);
    src->type = VIR_STORAGE_TYPE_FILE;
    /* readonly property is necessary for CDROMs and thus can't be cleared */
    src->readonly = readonly;
}


const char *
virDomainDiskGetDriver(const virDomainDiskDef *def)
{
    return def->driverName;
}


void
virDomainDiskSetDriver(virDomainDiskDef *def, const char *name)
{
    char *tmp = g_strdup(name);
    g_free(def->driverName);
    def->driverName = tmp;
}


int
virDomainDiskGetFormat(virDomainDiskDef *def)
{
    return def->src->format;
}


void
virDomainDiskSetFormat(virDomainDiskDef *def, int format)
{
    def->src->format = format;
}


virDomainControllerDef *
virDomainControllerDefNew(virDomainControllerType type)
{
    virDomainControllerDef *def;

    def = g_new0(virDomainControllerDef, 1);

    def->type = type;

    /* initialize anything that has a non-0 default */
    def->model = -1;
    def->idx = -1;

    switch (def->type) {
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
        def->opts.pciopts.targetIndex = -1;
        def->opts.pciopts.numaNode = -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
        def->opts.xenbusopts.maxGrantFrames = -1;
        def->opts.xenbusopts.maxEventChannels = -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        break;
    }

    return def;
}


void virDomainControllerDefFree(virDomainControllerDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    g_free(def->virtio);

    g_free(def);
}


/**
 * virDomainControllerIsPSeriesPHB:
 * @cont: controller
 *
 * Checks whether @cont is a PCI Host Bridge (PHB), a specific type
 * of PCI controller used by pSeries guests.
 *
 * Returns: true if @cont is a PHB, false otherwise.
 */
bool
virDomainControllerIsPSeriesPHB(const virDomainControllerDef *cont)
{
    virDomainControllerPCIModelName name;

    /* PHBs are pci-root controllers */
    if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI ||
        cont->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
        return false;
    }

    name = cont->opts.pciopts.modelName;

    /* The actual device used for PHBs is spapr-pci-host-bridge */
    if (name != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE)
        return false;

    return true;
}


virDomainFSDef *
virDomainFSDefNew(virDomainXMLOption *xmlopt)
{
    virDomainFSDef *ret;

    ret = g_new0(virDomainFSDef, 1);

    ret->src = virStorageSourceNew();

    ret->thread_pool_size = -1;

    if (xmlopt &&
        xmlopt->privateData.fsNew &&
        !(ret->privateData = xmlopt->privateData.fsNew()))
        goto cleanup;

    return ret;

 cleanup:
    virDomainFSDefFree(ret);
    return NULL;

}

void virDomainFSDefFree(virDomainFSDef *def)
{
    if (!def)
        return;

    virObjectUnref(def->src);
    g_free(def->dst);
    virDomainDeviceInfoClear(&def->info);
    g_free(def->virtio);
    virObjectUnref(def->privateData);
    g_free(def->binary);
    g_free(def->sock);

    g_free(def);
}


static void
virDomainHostdevSubsysSCSIClear(virDomainHostdevSubsysSCSI *scsisrc)
{
    if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
        g_clear_pointer(&scsisrc->u.iscsi.src, virObjectUnref);
    } else {
        VIR_FREE(scsisrc->u.host.adapter);
        g_clear_pointer(&scsisrc->u.host.src, virObjectUnref);
    }
}


static void
virDomainHostdevDefClear(virDomainHostdevDef *def)
{
    if (!def)
        return;

    /* Device info is freed elsewhere with 'parentnet' if present. */
    if (!def->parentnet)
        virDomainDeviceInfoFree(def->info);

    virDomainNetTeamingInfoFree(def->teaming);

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        switch (def->source.caps.type) {
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
        switch (def->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            virDomainHostdevSubsysSCSIClear(&def->source.subsys.u.scsi);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            VIR_FREE(def->source.subsys.u.scsi_host.wwpn);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            g_clear_pointer(&def->source.subsys.u.pci.origstates, virBitmapFree);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        break;
    }
}


void
virDomainActualNetDefFree(virDomainActualNetDef *def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        g_free(def->data.bridge.brname);
        break;
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        g_free(def->data.direct.linkdev);
        break;
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        virDomainHostdevDefClear(&def->data.hostdev.def);
        break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    g_free(def->virtPortProfile);
    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    g_free(def);
}


virDomainVsockDef *
virDomainVsockDefNew(virDomainXMLOption *xmlopt)
{
    virDomainVsockDef *ret = NULL;
    virDomainVsockDef *vsock;

    vsock = g_new0(virDomainVsockDef, 1);

    if (xmlopt &&
        xmlopt->privateData.vsockNew &&
        !(vsock->privateData = xmlopt->privateData.vsockNew()))
        goto cleanup;

    ret = g_steal_pointer(&vsock);
 cleanup:
    virDomainVsockDefFree(vsock);
    return ret;
}


void
virDomainVsockDefFree(virDomainVsockDef *vsock)
{
    if (!vsock)
        return;

    virObjectUnref(vsock->privateData);
    virDomainDeviceInfoClear(&vsock->info);
    g_free(vsock->virtio);
    g_free(vsock);
}


virDomainIOMMUDef *
virDomainIOMMUDefNew(void)
{
    g_autoptr(virDomainIOMMUDef) iommu = NULL;

    iommu = g_new0(virDomainIOMMUDef, 1);

    return g_steal_pointer(&iommu);
}


void
virDomainIOMMUDefFree(virDomainIOMMUDef *iommu)
{
    if (!iommu)
        return;

    virDomainDeviceInfoClear(&iommu->info);
    g_free(iommu);
}


void
virDomainNetTeamingInfoFree(virDomainNetTeamingInfo *teaming)
{
    if (!teaming)
        return;

    g_free(teaming->persistent);
    g_free(teaming);
}

void
virDomainNetPortForwardFree(virDomainNetPortForward *pf)
{
    size_t i;

    if (!pf)
        return;

    g_free(pf->dev);

    for (i = 0; i < pf->nRanges; i++)
        g_free(pf->ranges[i]);

    g_free(pf->ranges);
    g_free(pf);
}

void
virDomainNetDefFree(virDomainNetDef *def)
{
    size_t i;

    if (!def)
        return;

    g_free(def->modelstr);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        virObjectUnref(def->data.vhostuser);
        break;

    case VIR_DOMAIN_NET_TYPE_VDPA:
        g_free(def->data.vdpa.devicepath);
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
        g_free(def->data.socket.address);
        g_free(def->data.socket.localaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
        g_free(def->data.network.name);
        g_free(def->data.network.portgroup);
        virDomainActualNetDefFree(def->data.network.actual);
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        g_free(def->data.bridge.brname);
        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        g_free(def->data.internal.name);
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        g_free(def->data.direct.linkdev);
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        virDomainHostdevDefClear(&def->data.hostdev.def);
        break;

    case VIR_DOMAIN_NET_TYPE_VDS:
        g_free(def->data.vds.portgroup_id);
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    g_free(def->backend.tap);
    g_free(def->backend.vhost);
    g_free(def->backend.logFile);
    virDomainNetTeamingInfoFree(def->teaming);
    g_free(def->virtPortProfile);
    g_free(def->script);
    g_free(def->downscript);
    g_free(def->domain_name);
    g_free(def->ifname);
    g_free(def->ifname_guest);
    g_free(def->ifname_guest_actual);
    g_free(def->virtio);
    g_free(def->coalesce);
    g_free(def->sourceDev);

    virNetDevIPInfoClear(&def->guestIP);
    virNetDevIPInfoClear(&def->hostIP);
    virDomainDeviceInfoClear(&def->info);

    g_free(def->filter);
    g_clear_pointer(&def->filterparams, g_hash_table_unref);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);

    for (i = 0; i < def->nPortForwards; i++)
        virDomainNetPortForwardFree(def->portForwards[i]);
    g_free(def->portForwards);

    virObjectUnref(def->privateData);
    g_free(def);
}


const char *
virDomainChrSourceDefGetPath(virDomainChrSourceDef *chr)
{
    if (!chr)
        return NULL;

    switch ((virDomainChrType) chr->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
        return chr->data.file.path;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        return chr->data.nix.path;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        return NULL;
    }

    return NULL;
}


void ATTRIBUTE_NONNULL(1)
virDomainChrSourceDefClear(virDomainChrSourceDef *def)
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

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        VIR_FREE(def->data.dbus.channel);
        break;
    }

    VIR_FREE(def->logfile);
}

/* Almost deep copies the contents of src into dest. Some parts are not copied
 * though. */
void
virDomainChrSourceDefCopy(virDomainChrSourceDef *dest,
                          const virDomainChrSourceDef *src)
{
    virDomainChrSourceDefClear(dest);

    dest->type = src->type;
    dest->logfile = g_strdup(src->logfile);
    dest->logappend = src->logappend;

    switch ((virDomainChrType)src->type) {
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (src->type == VIR_DOMAIN_CHR_TYPE_FILE)
            dest->data.file.append = src->data.file.append;
        dest->data.file.path = g_strdup(src->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        dest->data.udp.bindHost = g_strdup(src->data.udp.bindHost);
        dest->data.udp.bindService = g_strdup(src->data.udp.bindService);
        dest->data.udp.connectHost = g_strdup(src->data.udp.connectHost);
        dest->data.udp.connectService = g_strdup(src->data.udp.connectService);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        dest->data.tcp.host = g_strdup(src->data.tcp.host);
        dest->data.tcp.service = g_strdup(src->data.tcp.service);

        dest->data.tcp.haveTLS = src->data.tcp.haveTLS;
        dest->data.tcp.tlsFromConfig = src->data.tcp.tlsFromConfig;

        dest->data.tcp.reconnect.enabled = src->data.tcp.reconnect.enabled;
        dest->data.tcp.reconnect.timeout = src->data.tcp.reconnect.timeout;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        dest->data.nix.path = g_strdup(src->data.nix.path);

        dest->data.nix.reconnect.enabled = src->data.nix.reconnect.enabled;
        dest->data.nix.reconnect.timeout = src->data.nix.reconnect.timeout;
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        dest->data.nmdm.master = g_strdup(src->data.nmdm.master);
        dest->data.nmdm.slave = g_strdup(src->data.nmdm.slave);

        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        dest->data.spicevmc = src->data.spicevmc;
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        dest->data.spiceport.channel = g_strdup(src->data.spiceport.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
        dest->data.qemuVdagent.clipboard = src->data.qemuVdagent.clipboard;
        dest->data.qemuVdagent.mouse = src->data.qemuVdagent.mouse;
        break;

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        dest->data.dbus.channel = g_strdup(src->data.dbus.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }
}

static void
virDomainChrSourceDefDispose(void *obj)
{
    virDomainChrSourceDef *def = obj;
    size_t i;

    virDomainChrSourceDefClear(def);
    virObjectUnref(def->privateData);

    if (def->seclabels) {
        for (i = 0; i < def->nseclabels; i++)
            virSecurityDeviceLabelDefFree(def->seclabels[i]);
        g_free(def->seclabels);
    }
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

    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        return STREQ_NULLABLE(src->data.file.path, tgt->data.file.path);

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        return STREQ_NULLABLE(src->data.nmdm.master, tgt->data.nmdm.master) &&
            STREQ_NULLABLE(src->data.nmdm.slave, tgt->data.nmdm.slave);

    case VIR_DOMAIN_CHR_TYPE_UDP:
        return STREQ_NULLABLE(src->data.udp.bindHost, tgt->data.udp.bindHost) &&
            STREQ_NULLABLE(src->data.udp.bindService, tgt->data.udp.bindService) &&
            STREQ_NULLABLE(src->data.udp.connectHost, tgt->data.udp.connectHost) &&
            STREQ_NULLABLE(src->data.udp.connectService, tgt->data.udp.connectService);

    case VIR_DOMAIN_CHR_TYPE_TCP:
        return src->data.tcp.listen == tgt->data.tcp.listen &&
            src->data.tcp.protocol == tgt->data.tcp.protocol &&
            STREQ_NULLABLE(src->data.tcp.host, tgt->data.tcp.host) &&
            STREQ_NULLABLE(src->data.tcp.service, tgt->data.tcp.service) &&
            src->data.tcp.reconnect.enabled == tgt->data.tcp.reconnect.enabled &&
            src->data.tcp.reconnect.timeout == tgt->data.tcp.reconnect.timeout;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        return src->data.nix.listen == tgt->data.nix.listen &&
            STREQ_NULLABLE(src->data.nix.path, tgt->data.nix.path) &&
            src->data.nix.reconnect.enabled == tgt->data.nix.reconnect.enabled &&
            src->data.nix.reconnect.timeout == tgt->data.nix.reconnect.timeout;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        return STREQ_NULLABLE(src->data.spiceport.channel,
                              tgt->data.spiceport.channel);

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        return src->data.spicevmc == tgt->data.spicevmc;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
        return src->data.qemuVdagent.clipboard == tgt->data.qemuVdagent.clipboard &&
            src->data.qemuVdagent.mouse == tgt->data.qemuVdagent.mouse;

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        return STREQ_NULLABLE(src->data.dbus.channel,
                              tgt->data.dbus.channel);

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    return true;
}

void virDomainChrDefFree(virDomainChrDef *def)
{
    if (!def)
        return;

    switch ((virDomainChrDeviceType)def->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        switch (def->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            g_free(def->target.addr);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            g_free(def->target.name);
            break;
        }
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        break;
    }

    virObjectUnref(def->source);
    virDomainDeviceInfoClear(&def->info);

    g_free(def);
}

void virDomainSmartcardDefFree(virDomainSmartcardDef *def)
{
    size_t i;
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        for (i = 0; i < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; i++)
            g_free(def->data.cert.file[i]);
        g_free(def->data.cert.database);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        virObjectUnref(def->data.passthru);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
    default:
        break;
    }

    virDomainDeviceInfoClear(&def->info);

    g_free(def);
}

void virDomainSoundCodecDefFree(virDomainSoundCodecDef *def)
{
    if (!def)
        return;

    g_free(def);
}

void virDomainSoundDefFree(virDomainSoundDef *def)
{
    size_t i;

    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    for (i = 0; i < def->ncodecs; i++)
        virDomainSoundCodecDefFree(def->codecs[i]);
    g_free(def->codecs);

    g_free(def);
}

static void
virDomainAudioIOALSAFree(virDomainAudioIOALSA *def)
{
    g_free(def->dev);
}

static void
virDomainAudioIOJackFree(virDomainAudioIOJack *def)
{
    g_free(def->serverName);
    g_free(def->clientName);
    g_free(def->connectPorts);
}

static void
virDomainAudioIOOSSFree(virDomainAudioIOOSS *def)
{
    g_free(def->dev);
}

static void
virDomainAudioIOPulseAudioFree(virDomainAudioIOPulseAudio *def)
{
    g_free(def->name);
    g_free(def->streamName);
}

void
virDomainAudioDefFree(virDomainAudioDef *def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        virDomainAudioIOALSAFree(&def->backend.alsa.input);
        virDomainAudioIOALSAFree(&def->backend.alsa.output);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_JACK:
        virDomainAudioIOJackFree(&def->backend.jack.input);
        virDomainAudioIOJackFree(&def->backend.jack.output);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_OSS:
        virDomainAudioIOOSSFree(&def->backend.oss.input);
        virDomainAudioIOOSSFree(&def->backend.oss.output);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        virDomainAudioIOPulseAudioFree(&def->backend.pulseaudio.input);
        virDomainAudioIOPulseAudioFree(&def->backend.pulseaudio.output);
        g_free(def->backend.pulseaudio.serverName);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SDL:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        g_free(def->backend.file.path);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
    case VIR_DOMAIN_AUDIO_TYPE_LAST:
        break;
    }

    g_free(def);
}

virDomainSoundDef *
virDomainSoundDefRemove(virDomainDef *def, size_t idx)
{
    virDomainSoundDef *ret = def->sounds[idx];
    VIR_DELETE_ELEMENT(def->sounds, idx, def->nsounds);
    return ret;
}

void virDomainMemballoonDefFree(virDomainMemballoonDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    g_free(def->virtio);

    g_free(def);
}

void virDomainNVRAMDefFree(virDomainNVRAMDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    g_free(def);
}

void virDomainWatchdogDefFree(virDomainWatchdogDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    g_free(def);
}

void virDomainShmemDefFree(virDomainShmemDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    virObjectUnref(def->server.chr);
    g_free(def->name);
    g_free(def);
}


virDomainVideoDef *
virDomainVideoDefNew(virDomainXMLOption *xmlopt)
{
    virDomainVideoDef *def;

    def = g_new0(virDomainVideoDef, 1);

    if (xmlopt && xmlopt->privateData.videoNew &&
        !(def->privateData = xmlopt->privateData.videoNew())) {
        VIR_FREE(def);
        return NULL;
    }

    def->heads = 1;
    return def;
}


void
virDomainVideoDefClear(virDomainVideoDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);

    if (def->accel)
        VIR_FREE(def->accel->rendernode);
    VIR_FREE(def->accel);
    VIR_FREE(def->res);
    VIR_FREE(def->virtio);
    if (def->driver)
        VIR_FREE(def->driver->vhost_user_binary);
    VIR_FREE(def->driver);
    virObjectUnref(def->privateData);

    memset(def, 0, sizeof(*def));
}


void virDomainVideoDefFree(virDomainVideoDef *def)
{
    if (!def)
        return;

    virDomainVideoDefClear(def);
    g_free(def);
}


virDomainHostdevDef *
virDomainHostdevDefNew(void)
{
    virDomainHostdevDef *def;

    def = g_new0(virDomainHostdevDef, 1);

    def->info = g_new0(virDomainDeviceInfo, 1);

    return def;
}


static virDomainTPMDef *
virDomainTPMDefNew(virDomainXMLOption *xmlopt)
{
    virDomainTPMDef *def;

    def = g_new0(virDomainTPMDef, 1);

    if (xmlopt && xmlopt->privateData.tpmNew &&
        !(def->privateData = xmlopt->privateData.tpmNew())) {
        VIR_FREE(def);
        return NULL;
    }

    return def;
}

void virDomainTPMDefFree(virDomainTPMDef *def)
{
    if (!def)
        return;

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        virObjectUnref(def->data.passthrough.source);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        virObjectUnref(def->data.emulator.source);
        g_free(def->data.emulator.storagepath);
        g_free(def->data.emulator.logfile);
        virBitmapFree(def->data.emulator.activePcrBanks);
        break;
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        virObjectUnref(def->data.external.source);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    virDomainDeviceInfoClear(&def->info);
    virObjectUnref(def->privateData);
    g_free(def);
}

void virDomainHostdevDefFree(virDomainHostdevDef *def)
{
    if (!def)
        return;

    /* free all subordinate objects */
    virDomainHostdevDefClear(def);

    /* If there is a parentnet device object, it will handle freeing
     * the memory.
     */
    if (!def->parentnet)
        g_free(def);
}

void virDomainHubDefFree(virDomainHubDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    g_free(def);
}

void virDomainRedirdevDefFree(virDomainRedirdevDef *def)
{
    if (!def)
        return;

    virObjectUnref(def->source);
    virDomainDeviceInfoClear(&def->info);

    g_free(def);
}

void virDomainRedirFilterDefFree(virDomainRedirFilterDef *def)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < def->nusbdevs; i++)
        g_free(def->usbdevs[i]);

    g_free(def->usbdevs);
    g_free(def);
}

void virDomainMemoryDefFree(virDomainMemoryDef *def)
{
    if (!def)
        return;

    switch (def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        virBitmapFree(def->source.dimm.nodes);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        g_free(def->source.nvdimm.path);
        g_free(def->target.nvdimm.uuid);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        g_free(def->source.virtio_pmem.path);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        virBitmapFree(def->source.virtio_mem.nodes);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        virBitmapFree(def->source.sgx_epc.nodes);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    virDomainDeviceInfoClear(&def->info);
    g_free(def);
}

void virDomainDeviceDefFree(virDomainDeviceDef *def)
{
    if (!def)
        return;

    switch (def->type) {
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
        virDomainIOMMUDefFree(def->data.iommu);
        break;
    case VIR_DOMAIN_DEVICE_VSOCK:
        virDomainVsockDefFree(def->data.vsock);
        break;
    case VIR_DOMAIN_DEVICE_AUDIO:
        virDomainAudioDefFree(def->data.audio);
        break;
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virDomainCryptoDefFree(def->data.crypto);
        break;
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
        break;
    }

    g_free(def);
}

static void
virDomainClockDefClear(virDomainClockDef *def)
{
    size_t i;

    if (def->offset == VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE)
        VIR_FREE(def->data.timezone);

    for (i = 0; i < def->ntimers; i++)
        VIR_FREE(def->timers[i]);
    VIR_FREE(def->timers);
}


static bool
virDomainIOThreadIDArrayHasPin(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->niothreadids; i++) {
        if (def->iothreadids[i]->cpumask)
            return true;
    }
    return false;
}


static virDomainIOThreadIDDef *
virDomainIOThreadIDDefNew(void)
{
    virDomainIOThreadIDDef *def = g_new0(virDomainIOThreadIDDef, 1);

    def->thread_pool_min = -1;
    def->thread_pool_max = -1;

    return def;
}


void
virDomainIOThreadIDDefFree(virDomainIOThreadIDDef *def)
{
    if (!def)
        return;
    virBitmapFree(def->cpumask);
    g_free(def);
}


static void
virDomainIOThreadIDDefArrayFree(virDomainIOThreadIDDef **def,
                                int nids)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < nids; i++)
        virDomainIOThreadIDDefFree(def[i]);

    g_free(def);
}


static int
virDomainIOThreadIDDefArrayInit(virDomainDef *def,
                                unsigned int iothreads)
{
    size_t i;
    ssize_t nxt = -1;
    g_autoptr(virBitmap) thrmap = NULL;

    /* Same value (either 0 or some number), then we have none to fill in or
     * the iothreadid array was filled from the XML
     */
    if (iothreads == def->niothreadids)
        return 0;

    /* iothread's are numbered starting at 1, account for that */
    thrmap = virBitmapNew(iothreads + 1);
    virBitmapSetAll(thrmap);

    /* Clear 0 since we don't use it, then mark those which are
     * already provided by the user */
    ignore_value(virBitmapClearBit(thrmap, 0));
    for (i = 0; i < def->niothreadids; i++)
        ignore_value(virBitmapClearBit(thrmap,
                                       def->iothreadids[i]->iothread_id));

    /* resize array */
    VIR_REALLOC_N(def->iothreadids, iothreads);

    /* Populate iothreadids[] using the set bit number from thrmap */
    while (def->niothreadids < iothreads) {
        g_autoptr(virDomainIOThreadIDDef) iothrid = NULL;

        if ((nxt = virBitmapNextSetBit(thrmap, nxt)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to populate iothreadids"));
            return -1;
        }
        iothrid = virDomainIOThreadIDDefNew();
        iothrid->iothread_id = nxt;
        iothrid->autofill = true;
        def->iothreadids[def->niothreadids++] = g_steal_pointer(&iothrid);
    }

    return 0;
}


void
virDomainResourceDefFree(virDomainResourceDef *resource)
{
    if (!resource)
        return;

    g_free(resource->partition);
    g_free(resource->appid);
    g_free(resource);
}

void
virDomainPanicDefFree(virDomainPanicDef *panic)
{
    if (!panic)
        return;

    virDomainDeviceInfoClear(&panic->info);
    g_free(panic);
}

virDomainLoaderDef *
virDomainLoaderDefNew(void)
{
    virDomainLoaderDef *def = NULL;

    def = g_new0(virDomainLoaderDef, 1);

    return def;
}

void
virDomainLoaderDefFree(virDomainLoaderDef *loader)
{
    if (!loader)
        return;

    g_free(loader->path);
    virObjectUnref(loader->nvram);
    g_free(loader->nvramTemplate);
    g_free(loader);
}


static void
virDomainResctrlMonDefFree(virDomainResctrlMonDef *domresmon)
{
    if (!domresmon)
        return;

    virBitmapFree(domresmon->vcpus);
    virObjectUnref(domresmon->instance);
    g_free(domresmon);
}


static void
virDomainResctrlDefFree(virDomainResctrlDef *resctrl)
{
    size_t i = 0;

    if (!resctrl)
        return;

    for (i = 0; i < resctrl->nmonitors; i++)
        virDomainResctrlMonDefFree(resctrl->monitors[i]);

    virObjectUnref(resctrl->alloc);
    virBitmapFree(resctrl->vcpus);
    g_free(resctrl->monitors);
    g_free(resctrl);
}


void
virDomainSecDefFree(virDomainSecDef *def)
{
    if (!def)
        return;

    switch ((virDomainLaunchSecurity) def->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        g_free(def->data.sev.dh_cert);
        g_free(def->data.sev.session);
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
        break;
    }

    g_free(def);
}

static void
virDomainOSDefClear(virDomainOSDef *os)
{
    size_t i;

    g_free(os->firmwareFeatures);
    g_free(os->machine);
    g_free(os->init);
    for (i = 0; os->initargv && os->initargv[i]; i++)
        g_free(os->initargv[i]);
    g_free(os->initargv);
    for (i = 0; os->initenv && os->initenv[i]; i++) {
        g_free(os->initenv[i]->name);
        g_free(os->initenv[i]->value);
        g_free(os->initenv[i]);
    }
    g_free(os->initdir);
    g_free(os->inituser);
    g_free(os->initgroup);
    g_free(os->initenv);
    g_free(os->kernel);
    g_free(os->initrd);
    g_free(os->cmdline);
    g_free(os->dtb);
    g_free(os->root);
    g_free(os->slic_table);
    virDomainLoaderDefFree(os->loader);
    g_free(os->bootloader);
    g_free(os->bootloaderArgs);
}


void virDomainDefFree(virDomainDef *def)
{
    size_t i;

    if (!def)
        return;

    virDomainResourceDefFree(def->resource);

    for (i = 0; i < def->maxvcpus; i++)
        virDomainVcpuDefFree(def->vcpus[i]);
    g_free(def->vcpus);

    /* hostdevs must be freed before nets (or any future "intelligent
     * hostdevs") because the pointer to the hostdev is really
     * pointing into the middle of the higher level device's object,
     * so the original object must still be available during the call
     * to virDomainHostdevDefFree().
     */
    for (i = 0; i < def->nhostdevs; i++)
        virDomainHostdevDefFree(def->hostdevs[i]);
    g_free(def->hostdevs);

    for (i = 0; i < def->nleases; i++)
        virDomainLeaseDefFree(def->leases[i]);
    g_free(def->leases);

    for (i = 0; i < def->ngraphics; i++)
        virDomainGraphicsDefFree(def->graphics[i]);
    g_free(def->graphics);

    for (i = 0; i < def->ninputs; i++)
        virDomainInputDefFree(def->inputs[i]);
    g_free(def->inputs);

    for (i = 0; i < def->ndisks; i++)
        virDomainDiskDefFree(def->disks[i]);
    g_free(def->disks);

    for (i = 0; i < def->ncontrollers; i++)
        virDomainControllerDefFree(def->controllers[i]);
    g_free(def->controllers);

    for (i = 0; i < def->nfss; i++)
        virDomainFSDefFree(def->fss[i]);
    g_free(def->fss);

    for (i = 0; i < def->nnets; i++)
        virDomainNetDefFree(def->nets[i]);
    g_free(def->nets);

    for (i = 0; i < def->nsmartcards; i++)
        virDomainSmartcardDefFree(def->smartcards[i]);
    g_free(def->smartcards);

    for (i = 0; i < def->nserials; i++)
        virDomainChrDefFree(def->serials[i]);
    g_free(def->serials);

    for (i = 0; i < def->nparallels; i++)
        virDomainChrDefFree(def->parallels[i]);
    g_free(def->parallels);

    for (i = 0; i < def->nchannels; i++)
        virDomainChrDefFree(def->channels[i]);
    g_free(def->channels);

    for (i = 0; i < def->nconsoles; i++)
        virDomainChrDefFree(def->consoles[i]);
    g_free(def->consoles);

    for (i = 0; i < def->nsounds; i++)
        virDomainSoundDefFree(def->sounds[i]);
    g_free(def->sounds);

    for (i = 0; i < def->naudios; i++)
        virDomainAudioDefFree(def->audios[i]);
    g_free(def->audios);

    for (i = 0; i < def->nvideos; i++)
        virDomainVideoDefFree(def->videos[i]);
    g_free(def->videos);

    for (i = 0; i < def->nhubs; i++)
        virDomainHubDefFree(def->hubs[i]);
    g_free(def->hubs);

    for (i = 0; i < def->nredirdevs; i++)
        virDomainRedirdevDefFree(def->redirdevs[i]);
    g_free(def->redirdevs);

    for (i = 0; i < def->nrngs; i++)
        virDomainRNGDefFree(def->rngs[i]);
    g_free(def->rngs);

    for (i = 0; i < def->nmems; i++)
        virDomainMemoryDefFree(def->mems[i]);
    g_free(def->mems);

    for (i = 0; i < def->ntpms; i++)
        virDomainTPMDefFree(def->tpms[i]);
    g_free(def->tpms);

    for (i = 0; i < def->npanics; i++)
        virDomainPanicDefFree(def->panics[i]);
    g_free(def->panics);

    for (i = 0; i < def->ncryptos; i++)
        virDomainCryptoDefFree(def->cryptos[i]);
    g_free(def->cryptos);

    virDomainIOMMUDefFree(def->iommu);

    g_free(def->idmap.uidmap);
    g_free(def->idmap.gidmap);

    virDomainOSDefClear(&def->os);

    virDomainClockDefClear(&def->clock);

    g_free(def->name);
    virBitmapFree(def->cpumask);
    g_free(def->emulator);
    g_free(def->description);
    g_free(def->title);
    g_free(def->kvm_features);
    g_free(def->hyperv_vendor_id);
    g_free(def->tcg_features);

    virBlkioDeviceArrayClear(def->blkio.devices,
                             def->blkio.ndevices);
    g_free(def->blkio.devices);

    for (i = 0; i < def->nwatchdogs; i++)
        virDomainWatchdogDefFree(def->watchdogs[i]);
    g_free(def->watchdogs);

    virDomainMemballoonDefFree(def->memballoon);
    virDomainNVRAMDefFree(def->nvram);
    virDomainVsockDefFree(def->vsock);

    for (i = 0; i < def->mem.nhugepages; i++)
        virBitmapFree(def->mem.hugepages[i].nodemask);
    g_free(def->mem.hugepages);

    for (i = 0; i < def->nseclabels; i++)
        virSecurityLabelDefFree(def->seclabels[i]);
    g_free(def->seclabels);

    virCPUDefFree(def->cpu);

    virDomainIOThreadIDDefArrayFree(def->iothreadids, def->niothreadids);

    g_free(def->defaultIOThread);

    virBitmapFree(def->cputune.emulatorpin);
    g_free(def->cputune.emulatorsched);

    virDomainNumaFree(def->numa);

    for (i = 0; i < def->nsysinfo; i++)
        virSysinfoDefFree(def->sysinfo[i]);
    g_free(def->sysinfo);

    virDomainRedirFilterDefFree(def->redirfilter);

    for (i = 0; i < def->nshmems; i++)
        virDomainShmemDefFree(def->shmems[i]);
    g_free(def->shmems);

    for (i = 0; i < def->nresctrls; i++)
        virDomainResctrlDefFree(def->resctrls[i]);
    g_free(def->resctrls);

    g_free(def->keywrap);

    if (def->namespaceData && def->ns.free)
        (def->ns.free)(def->namespaceData);

    virDomainSecDefFree(def->sec);

    xmlFreeNode(def->metadata);

    g_free(def);
}

static void
virDomainObjDeprecationFree(virDomainObj *dom)
{
    size_t i = 0;
    for (i = 0; i < dom->ndeprecations; i++) {
        g_free(dom->deprecations[i]);
    }
    g_free(dom->deprecations);
}

static void virDomainObjDispose(void *obj)
{
    virDomainObj *dom = obj;

    VIR_DEBUG("obj=%p", dom);
    virCondDestroy(&dom->cond);
    virDomainDefFree(dom->def);
    virDomainDefFree(dom->newDef);

    if (dom->privateDataFreeFunc)
        (dom->privateDataFreeFunc)(dom->privateData);

    virDomainObjDeprecationFree(dom);
    virDomainSnapshotObjListFree(dom->snapshots);
    virDomainCheckpointObjListFree(dom->checkpoints);
    virDomainJobObjFree(dom->job);
    virObjectUnref(dom->closecallbacks);
}

virDomainObj *
virDomainObjNew(virDomainXMLOption *xmlopt)
{
    virDomainObj *domain;

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
        domain->privateData = (xmlopt->privateData.alloc)(xmlopt->config.priv);
        if (!domain->privateData)
            goto error;
        domain->privateDataFreeFunc = xmlopt->privateData.free;
    }

    if (xmlopt->closecallbackAlloc) {
        domain->closecallbacks = (xmlopt->closecallbackAlloc)();
    }

    if (!(domain->snapshots = virDomainSnapshotObjListNew()))
        goto error;

    if (!(domain->checkpoints = virDomainCheckpointObjListNew()))
        goto error;

    domain->job = g_new0(virDomainJobObj, 1);
    if (virDomainObjInitJob(domain->job,
                            &xmlopt->jobObjConfig.cb,
                            &xmlopt->jobObjConfig.jobDataPrivateCb) < 0)
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


virDomainDef *
virDomainDefNew(virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainDef) ret = NULL;

    ret = g_new0(virDomainDef, 1);

    if (!(ret->numa = virDomainNumaNew()))
        return NULL;

    ret->mem.hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    ret->mem.soft_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    ret->mem.swap_hard_limit = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (xmlopt && xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_WIDE_SCSI)
        ret->scsiBusMaxUnit = SCSI_WIDE_BUS_MAX_CONT_UNIT;
    else
        ret->scsiBusMaxUnit = SCSI_NARROW_BUS_MAX_CONT_UNIT;

    return g_steal_pointer(&ret);
}


void virDomainObjAssignDef(virDomainObj *domain,
                           virDomainDef **def,
                           bool live,
                           virDomainDef **oldDef)
{
    if (oldDef)
        *oldDef = NULL;
    if (virDomainObjIsActive(domain)) {
        if (oldDef)
            *oldDef = domain->newDef;
        else
            virDomainDefFree(domain->newDef);
        domain->newDef = g_steal_pointer(def);
        return;
    }

    if (live) {
        /* save current configuration to be restored on domain shutdown */
        if (!domain->newDef)
            domain->newDef = domain->def;
        else
            virDomainDefFree(domain->def);
        domain->def = g_steal_pointer(def);
        return;
    }

    if (oldDef)
        *oldDef = domain->def;
    else
        virDomainDefFree(domain->def);
    domain->def = g_steal_pointer(def);
}


/**
 * virDomainObjEndAPI:
 * @vm: domain object
 *
 * Finish working with a domain object in an API.  This function
 * clears whatever was left of a domain that was gathered using
 * virDomainObjListFindByUUID(). Currently that means only unlocking and
 * decrementing the reference counter of that domain.  And in order to
 * make sure the caller does not access the domain, the pointer is
 * cleared.
 */
void
virDomainObjEndAPI(virDomainObj **vm)
{
    if (!*vm)
        return;

    virObjectUnlock(*vm);
    g_clear_pointer(vm, virObjectUnref);
}


void
virDomainObjBroadcast(virDomainObj *vm)
{
    virCondBroadcast(&vm->cond);
}


int
virDomainObjWait(virDomainObj *vm)
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
virDomainObjWaitUntil(virDomainObj *vm,
                      unsigned long long whenms)
{
    if (virCondWaitUntil(&vm->cond, &vm->parent.lock, whenms) >= 0)
        return 0;

    if (errno == ETIMEDOUT)
        return 1;

    virReportSystemError(errno, "%s",
                         _("failed to wait for domain condition"));
    return -1;
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
virDomainObjSetDefTransient(virDomainXMLOption *xmlopt,
                            virDomainObj *domain,
                            void *parseOpaque)
{
    if (!domain->persistent)
        return 0;

    if (domain->newDef)
        return 0;

    if (!(domain->newDef = virDomainDefCopy(domain->def, xmlopt,
                                            parseOpaque, false)))
        return -1;

    return 0;
}


/*
 * Remove the running configuration and replace it with the persistent one.
 *
 * @param domain domain object pointer
 */
void
virDomainObjRemoveTransientDef(virDomainObj *domain)
{
    if (!domain->newDef)
        return;

    virDomainDefFree(domain->def);
    domain->def = g_steal_pointer(&domain->newDef);
    domain->def->id = -1;
}


/*
 * Return the persistent domain configuration. If domain is transient,
 * return the running config.
 *
 * @param caps pointer to capabilities info
 * @param xmlopt pointer to XML parser configuration object
 * @param domain domain object pointer
 * @return NULL on error, virDomainDef * on success
 */
virDomainDef *
virDomainObjGetPersistentDef(virDomainXMLOption *xmlopt,
                             virDomainObj *domain,
                             void *parseOpaque)
{
    if (virDomainObjIsActive(domain) &&
        virDomainObjSetDefTransient(xmlopt, domain, parseOpaque) < 0)
        return NULL;

    if (domain->newDef)
        return domain->newDef;

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
virDomainObjUpdateModificationImpact(virDomainObj *vm,
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
                       _("transient domains do not have any persistent config"));
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
virDomainObjGetDefs(virDomainObj *vm,
                    unsigned int flags,
                    virDomainDef **liveDef,
                    virDomainDef **persDef)
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
virDomainDef *
virDomainObjGetOneDefState(virDomainObj *vm,
                           unsigned int flags,
                           bool *live)
{
    if (flags & VIR_DOMAIN_AFFECT_LIVE &&
        flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virReportInvalidArg(flags, "%s",
                            _("Flags 'VIR_DOMAIN_AFFECT_LIVE' and 'VIR_DOMAIN_AFFECT_CONFIG' are mutually exclusive"));
        return NULL;
    }

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        return NULL;

    if (live)
        *live = flags & VIR_DOMAIN_AFFECT_LIVE;

    if (virDomainObjIsActive(vm) && flags & VIR_DOMAIN_AFFECT_CONFIG)
        return vm->newDef;

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
virDomainDef *
virDomainObjGetOneDef(virDomainObj *vm,
                      unsigned int flags)
{
    return virDomainObjGetOneDefState(vm, flags, NULL);
}

virDomainDeviceInfo *
virDomainDeviceGetInfo(const virDomainDeviceDef *device)
{
    switch (device->type) {
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
    case VIR_DOMAIN_DEVICE_IOMMU:
        return &device->data.iommu->info;
    case VIR_DOMAIN_DEVICE_VSOCK:
        return &device->data.vsock->info;
    case VIR_DOMAIN_DEVICE_CRYPTO:
        return &device->data.crypto->info;

    /* The following devices do not contain virDomainDeviceInfo */
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
        break;
    }
    return NULL;
}


/**
 * virDomainDeviceSetData
 * @device: virDomainDeviceDef * with ->type filled in
 * @devicedata: *Def * data for a device. Ex: virDomainDiskDef *
 *
 * Set the data.X variable for the device->type value. Basically
 * a mapping of virDomainDeviceType to the associated name in
 * the virDomainDeviceDef union
 */
void
virDomainDeviceSetData(virDomainDeviceDef *device,
                       void *devicedata)
{
    switch (device->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        device->data.disk = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_NET:
        device->data.net = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        device->data.sound = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        device->data.hostdev = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        device->data.video = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        device->data.controller = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        device->data.graphics = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        device->data.smartcard = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        device->data.chr = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        device->data.input = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_FS:
        device->data.fs = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        device->data.watchdog = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        device->data.memballoon = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        device->data.rng = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_NVRAM:
        device->data.nvram = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_HUB:
        device->data.hub = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        device->data.shmem = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_TPM:
        device->data.tpm = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_PANIC:
        device->data.panic = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        device->data.memory = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        device->data.redirdev = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_VSOCK:
        device->data.vsock = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_IOMMU:
        device->data.iommu = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        device->data.lease = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_AUDIO:
        device->data.audio = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_CRYPTO:
        device->data.crypto = devicedata;
        break;
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }
}


static int
virDomainDefHasDeviceAddressIterator(virDomainDef *def G_GNUC_UNUSED,
                                     virDomainDeviceDef *dev G_GNUC_UNUSED,
                                     virDomainDeviceInfo *info,
                                     void *opaque)
{
    virDomainDeviceInfo *needle = opaque;

    /* break iteration if the info was found */
    if (virDomainDeviceInfoAddressIsEqual(info, needle))
        return -1;

    return 0;
}


static bool
virDomainSkipBackcompatConsole(virDomainDef *def,
                               size_t idx,
                               bool all)
{
    virDomainChrDef *console = def->consoles[idx];

    if (!all && idx == 0 &&
        (console->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
         console->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE) &&
        def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        return true;
    }

    return false;
}


/*
 * Iterates over domain devices calling @cb on each device. The default
 * behaviour can be altered with virDomainDeviceIterateFlags.
 */
int
virDomainDeviceInfoIterateFlags(virDomainDef *def,
                                virDomainDeviceInfoCallback cb,
                                unsigned int iteratorFlags,
                                void *opaque)
{
    size_t i;
    int rc;
    virDomainDeviceDef device;

    device.type = VIR_DOMAIN_DEVICE_DISK;
    for (i = 0; i < def->ndisks; i++) {
        device.data.disk = def->disks[i];
        if ((rc = cb(def, &device, &def->disks[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_NET;
    for (i = 0; i < def->nnets; i++) {
        device.data.net = def->nets[i];
        if ((rc = cb(def, &device, &def->nets[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_SOUND;
    for (i = 0; i < def->nsounds; i++) {
        device.data.sound = def->sounds[i];
        if ((rc = cb(def, &device, &def->sounds[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_HOSTDEV;
    for (i = 0; i < def->nhostdevs; i++) {
        device.data.hostdev = def->hostdevs[i];
        if ((rc = cb(def, &device, def->hostdevs[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_VIDEO;
    for (i = 0; i < def->nvideos; i++) {
        device.data.video = def->videos[i];
        if ((rc = cb(def, &device, &def->videos[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_CONTROLLER;
    for (i = 0; i < def->ncontrollers; i++) {
        device.data.controller = def->controllers[i];
        if ((rc = cb(def, &device, &def->controllers[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_SMARTCARD;
    for (i = 0; i < def->nsmartcards; i++) {
        device.data.smartcard = def->smartcards[i];
        if ((rc = cb(def, &device, &def->smartcards[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_CHR;
    for (i = 0; i < def->nserials; i++) {
        device.data.chr = def->serials[i];
        if ((rc = cb(def, &device, &def->serials[i]->info, opaque)) != 0)
            return rc;
    }
    for (i = 0; i < def->nparallels; i++) {
        device.data.chr = def->parallels[i];
        if ((rc = cb(def, &device, &def->parallels[i]->info, opaque)) != 0)
            return rc;
    }
    for (i = 0; i < def->nchannels; i++) {
        device.data.chr = def->channels[i];
        if ((rc = cb(def, &device, &def->channels[i]->info, opaque)) != 0)
            return rc;
    }
    for (i = 0; i < def->nconsoles; i++) {
        bool all = iteratorFlags & DOMAIN_DEVICE_ITERATE_ALL_CONSOLES;

        if (virDomainSkipBackcompatConsole(def, i, all))
            continue;
        device.data.chr = def->consoles[i];
        if ((rc = cb(def, &device, &def->consoles[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_INPUT;
    for (i = 0; i < def->ninputs; i++) {
        device.data.input = def->inputs[i];
        if ((rc = cb(def, &device, &def->inputs[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_FS;
    for (i = 0; i < def->nfss; i++) {
        device.data.fs = def->fss[i];
        if ((rc = cb(def, &device, &def->fss[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_WATCHDOG;
    for (i = 0; i < def->nwatchdogs; i++) {
        device.data.watchdog = def->watchdogs[i];
        if ((rc = cb(def, &device, &def->watchdogs[i]->info, opaque)) != 0)
            return rc;
    }
    if (def->memballoon) {
        device.type = VIR_DOMAIN_DEVICE_MEMBALLOON;
        device.data.memballoon = def->memballoon;
        if ((rc = cb(def, &device, &def->memballoon->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_RNG;
    for (i = 0; i < def->nrngs; i++) {
        device.data.rng = def->rngs[i];
        if ((rc = cb(def, &device, &def->rngs[i]->info, opaque)) != 0)
            return rc;
    }
    if (def->nvram) {
        device.type = VIR_DOMAIN_DEVICE_NVRAM;
        device.data.nvram = def->nvram;
        if ((rc = cb(def, &device, &def->nvram->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_HUB;
    for (i = 0; i < def->nhubs; i++) {
        device.data.hub = def->hubs[i];
        if ((rc = cb(def, &device, &def->hubs[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_SHMEM;
    for (i = 0; i < def->nshmems; i++) {
        device.data.shmem = def->shmems[i];
        if ((rc = cb(def, &device, &def->shmems[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_TPM;
    for (i = 0; i < def->ntpms; i++) {
        device.data.tpm = def->tpms[i];
        if ((rc = cb(def, &device, &def->tpms[i]->info, opaque)) != 0)
            return rc;
    }
    device.type = VIR_DOMAIN_DEVICE_PANIC;
    for (i = 0; i < def->npanics; i++) {
        device.data.panic = def->panics[i];
        if ((rc = cb(def, &device, &def->panics[i]->info, opaque)) != 0)
            return rc;
    }

    device.type = VIR_DOMAIN_DEVICE_MEMORY;
    for (i = 0; i < def->nmems; i++) {
        device.data.memory = def->mems[i];
        if ((rc = cb(def, &device, &def->mems[i]->info, opaque)) != 0)
            return rc;
    }

    device.type = VIR_DOMAIN_DEVICE_REDIRDEV;
    for (i = 0; i < def->nredirdevs; i++) {
        device.data.redirdev = def->redirdevs[i];
        if ((rc = cb(def, &device, &def->redirdevs[i]->info, opaque)) != 0)
            return rc;
    }

    device.type = VIR_DOMAIN_DEVICE_IOMMU;
    if (def->iommu) {
        device.data.iommu = def->iommu;
        if ((rc = cb(def, &device, &def->iommu->info, opaque)) != 0)
            return rc;
    }

    device.type = VIR_DOMAIN_DEVICE_VSOCK;
    if (def->vsock) {
        device.data.vsock = def->vsock;
        if ((rc = cb(def, &device, &def->vsock->info, opaque)) != 0)
            return rc;
    }

    device.type = VIR_DOMAIN_DEVICE_CRYPTO;
    for (i = 0; i < def->ncryptos; i++) {
        device.data.crypto = def->cryptos[i];
        if ((rc = cb(def, &device, &def->cryptos[i]->info, opaque)) != 0)
            return rc;
    }

    /* If the flag below is set, make sure @cb can handle @info being NULL */
    if (iteratorFlags & DOMAIN_DEVICE_ITERATE_MISSING_INFO) {
        device.type = VIR_DOMAIN_DEVICE_GRAPHICS;
        for (i = 0; i < def->ngraphics; i++) {
            device.data.graphics = def->graphics[i];
            if ((rc = cb(def, &device, NULL, opaque)) != 0)
                return rc;
        }
        device.type = VIR_DOMAIN_DEVICE_AUDIO;
        for (i = 0; i < def->naudios; i++) {
            device.data.audio = def->audios[i];
            if ((rc = cb(def, &device, NULL, opaque)) != 0)
                return rc;
        }
        device.type = VIR_DOMAIN_DEVICE_LEASE;
        for (i = 0; i < def->nleases; i++) {
            device.data.lease = def->leases[i];
            if ((rc = cb(def, &device, NULL, opaque)) != 0)
                return rc;
        }
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
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        break;
    }
#endif

    return 0;
}


int
virDomainDeviceInfoIterate(virDomainDef *def,
                           virDomainDeviceInfoCallback cb,
                           void *opaque)
{
    return virDomainDeviceInfoIterateFlags(def, cb, 0, opaque);
}


bool
virDomainDefHasDeviceAddress(virDomainDef *def,
                             virDomainDeviceInfo *info)
{
    if (virDomainDeviceInfoIterateFlags(def,
                                        virDomainDefHasDeviceAddressIterator,
                                        DOMAIN_DEVICE_ITERATE_ALL_CONSOLES,
                                        info) < 0)
        return true;

    return false;
}


static int
virDomainDefAddConsoleCompat(virDomainDef *def)
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
        virDomainChrDef *cons = def->consoles[i];

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
            VIR_APPEND_ELEMENT(def->serials, def->nserials, def->consoles[0]);

            /* modify it to be a serial port */
            def->serials[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
            def->serials[0]->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE;
            def->serials[0]->target.port = 0;
        } else {
            /* if the console source doesn't match */
            if (!virDomainChrSourceDefIsEqual(def->serials[0]->source,
                                              def->consoles[0]->source)) {
                g_clear_pointer(&def->consoles[0], virDomainChrDefFree);
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
               def->serials[0]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {

        switch ((virDomainChrSerialTargetType) def->serials[0]->targetType) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE: {

            /* Create a stub console to match the serial port.
             * console[0] either does not exist
             *                or has a different type than SERIAL or NONE.
             */
            virDomainChrDef *chr;
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

            break;
        }

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST:
            /* Nothing to do */
            break;
        }
    }

    return 0;
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
bool
virDomainDriveAddressIsUsedByDisk(const virDomainDef *def,
                                  virDomainDiskBus bus_type,
                                  const virDomainDeviceDriveAddress *addr)
{
    virDomainDiskDef *disk;
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
    virDomainHostdevDef *hostdev;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != type ||
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
bool
virDomainSCSIDriveAddressIsUsed(const virDomainDef *def,
                                const virDomainDeviceDriveAddress *addr)
{
    const virDomainControllerDef *cont;

    cont = virDomainDeviceFindSCSIController(def, addr);
    if (cont) {
        int max = -1;
        int reserved = -1;

        /* Different controllers have different limits. These limits here are
         * taken from QEMU source code, but nevertheless they should apply to
         * other hypervisors too. */
        switch ((virDomainControllerModelSCSI) cont->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
            max = 16383;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            max = 31;
            reserved = 7;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
            max = 1;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
            max = 255;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            reserved = 7;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
            reserved = 7;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
            reserved = 7;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DC390:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AM53C974:
            max = 6;
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
            break;
        }

        if (max != -1 && addr->unit > max)
            return true;
        if (reserved != -1 && addr->unit == reserved)
            return true;
    }

    if (virDomainDriveAddressIsUsedByDisk(def, VIR_DOMAIN_DISK_BUS_SCSI,
                                          addr) ||
        virDomainDriveAddressIsUsedByHostdev(def,
                                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI,
                                             addr))
        return true;

    return false;
}


bool
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


bool
virDomainDefLifecycleActionAllowed(virDomainLifecycle type,
                                   virDomainLifecycleAction action)
{
    switch (type) {
    case VIR_DOMAIN_LIFECYCLE_POWEROFF:
    case VIR_DOMAIN_LIFECYCLE_REBOOT:
        switch (action) {
        case VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY:
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART:
        case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME:
        case VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE:
        case VIR_DOMAIN_LIFECYCLE_ACTION_LAST:
            return true;
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY:
        case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART:
            break;
        }
        break;
    case VIR_DOMAIN_LIFECYCLE_CRASH:
    case VIR_DOMAIN_LIFECYCLE_LAST:
        return true;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("Lifecycle event '%1$s' doesn't support '%2$s' action"),
                   virDomainLifecycleTypeToString(type),
                   virDomainLifecycleActionTypeToString(action));
    return false;
}


int
virDomainObjCheckActive(virDomainObj *dom)
{
    if (!virDomainObjIsActive(dom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        return -1;
    }
    return 0;
}


/**
 * virDomainDeviceLoadparmIsValid
 * @loadparm : The string to validate
 *
 * The valid set of values for loadparm are [a-zA-Z0-9.]
 * and blank spaces.
 * The maximum allowed length is 8 characters.
 * An empty string is considered invalid
 */
static bool
virDomainDeviceLoadparmIsValid(const char *loadparm)
{
    if (virStringIsEmpty(loadparm) || !STRLIM(loadparm, 8)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("loadparm value '%1$s' must be between 1 and 8 characters"),
                       loadparm);
        return false;
    }

    if (strspn(loadparm, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789. ") != strlen(loadparm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid loadparm value '%1$s', expecting chars in set of [a-zA-Z0-9.] and blank spaces"),
                       loadparm);
        return false;
    }

    return true;
}


static void
virDomainVirtioOptionsFormat(virBuffer *buf,
                             virDomainVirtioOptions *virtio)
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
    if (virtio->packed != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " packed='%s'",
                          virTristateSwitchTypeToString(virtio->packed));
    }
    if (virtio->page_per_vq != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " page_per_vq='%s'",
                          virTristateSwitchTypeToString(virtio->page_per_vq));
    }
}


static void ATTRIBUTE_NONNULL(2)
virDomainDeviceInfoFormat(virBuffer *buf,
                          const virDomainDeviceInfo *info,
                          unsigned int flags)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if ((flags & VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT) && info->bootIndex) {
        virBufferAsprintf(buf, "<boot order='%u'", info->bootIndex);

        if (info->loadparm)
            virBufferAsprintf(buf, " loadparm='%s'", info->loadparm);

        virBufferAddLit(buf, "/>\n");
    }

    if (info->alias)
        virBufferAsprintf(buf, "<alias name='%s'/>\n", info->alias);

    if (info->mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB) {
        virBufferAsprintf(buf, "<master startport='%d'/>\n",
                          info->master.usb.startport);
    }

    if ((flags & VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM) &&
        (info->romenabled != VIR_TRISTATE_BOOL_ABSENT ||
         info->rombar != VIR_TRISTATE_SWITCH_ABSENT ||
         info->romfile)) {

        virBufferAddLit(buf, "<rom");
        if (info->romenabled != VIR_TRISTATE_BOOL_ABSENT) {
            const char *romenabled = virTristateBoolTypeToString(info->romenabled);

            if (romenabled)
                virBufferAsprintf(buf, " enabled='%s'", romenabled);
        }
        if (info->rombar != VIR_TRISTATE_SWITCH_ABSENT) {
            const char *rombar = virTristateSwitchTypeToString(info->rombar);

            if (rombar)
                virBufferAsprintf(buf, " bar='%s'", rombar);
        }
        if (info->romfile)
            virBufferEscapeString(buf, " file='%s'", info->romfile);
        virBufferAddLit(buf, "/>\n");
    }

    if (info->acpiIndex != 0)
        virBufferAsprintf(buf, "<acpi index='%u'/>\n", info->acpiIndex);

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
        /* We're done here */
        return;

    virBufferAsprintf(&attrBuf, " type='%s'",
                      virDomainDeviceAddressTypeToString(info->type));

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (!virPCIDeviceAddressIsEmpty(&info->addr.pci)) {
            virBufferAsprintf(&attrBuf, " domain='0x%04x' bus='0x%02x' "
                              "slot='0x%02x' function='0x%d'",
                              info->addr.pci.domain,
                              info->addr.pci.bus,
                              info->addr.pci.slot,
                              info->addr.pci.function);
        }
        if (info->addr.pci.multi) {
            virBufferAsprintf(&attrBuf, " multifunction='%s'",
                              virTristateSwitchTypeToString(info->addr.pci.multi));
        }

        if (virZPCIDeviceAddressIsPresent(&info->addr.pci.zpci)) {
            virBufferAsprintf(&childBuf,
                              "<zpci uid='0x%.4x' fid='0x%.8x'/>\n",
                              info->addr.pci.zpci.uid.value,
                              info->addr.pci.zpci.fid.value);
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        virBufferAsprintf(&attrBuf, " controller='%d' bus='%d' target='%d' unit='%d'",
                          info->addr.drive.controller,
                          info->addr.drive.bus,
                          info->addr.drive.target,
                          info->addr.drive.unit);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        virBufferAsprintf(&attrBuf, " controller='%d' bus='%d' port='%d'",
                          info->addr.vioserial.controller,
                          info->addr.vioserial.bus,
                          info->addr.vioserial.port);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        virBufferAsprintf(&attrBuf, " controller='%d' slot='%d'",
                          info->addr.ccid.controller,
                          info->addr.ccid.slot);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        virBufferAsprintf(&attrBuf, " bus='%d'", info->addr.usb.bus);
        if (virDomainUSBAddressPortIsValid(info->addr.usb.port)) {
            virBufferAddLit(&attrBuf, " port='");
            virDomainUSBAddressPortFormatBuf(&attrBuf, info->addr.usb.port);
            virBufferAddLit(&attrBuf, "'");
        }
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (info->addr.spaprvio.has_reg)
            virBufferAsprintf(&attrBuf, " reg='0x%08llx'", info->addr.spaprvio.reg);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        virBufferAsprintf(&attrBuf, " cssid='0x%x' ssid='0x%x' devno='0x%04x'",
                          info->addr.ccw.cssid,
                          info->addr.ccw.ssid,
                          info->addr.ccw.devno);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (info->addr.isa.iobase > 0)
            virBufferAsprintf(&attrBuf, " iobase='0x%x'", info->addr.isa.iobase);
        if (info->addr.isa.irq > 0)
            virBufferAsprintf(&attrBuf, " irq='0x%x'", info->addr.isa.irq);
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        virBufferAsprintf(&attrBuf, " slot='%u'", info->addr.dimm.slot);
        if (info->addr.dimm.base)
            virBufferAsprintf(&attrBuf, " base='0x%llx'", info->addr.dimm.base);

        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    virXMLFormatElement(buf, "address", &attrBuf, &childBuf);
}

static int
virDomainDeviceUSBMasterParseXML(xmlNodePtr node,
                                 virDomainDeviceUSBMaster *master)
{
    memset(master, 0, sizeof(*master));

    if (virXMLPropUInt(node, "startport", 10, VIR_XML_PROP_NONE,
                       &master->startport) < 0)
        return -1;

    return 0;
}

static int
virDomainDeviceBootParseXML(xmlNodePtr node,
                            virDomainDeviceInfo *info)
{
    g_autofree char *loadparm = NULL;

    if (virXMLPropUInt(node, "order", 10,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &info->bootIndex) < 0)
        return -1;

    info->effectiveBootIndex = info->bootIndex;

    loadparm = virXMLPropString(node, "loadparm");
    if (loadparm) {
        if (virStringToUpper(&info->loadparm, loadparm) != 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to convert loadparm '%1$s' to upper case"),
                           loadparm);
            return -1;
        }

        if (!virDomainDeviceLoadparmIsValid(info->loadparm)) {
            VIR_FREE(info->loadparm);
            return -1;
        }
    }

    return 0;
}

static int
virDomainDeviceISAAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceISAAddress *addr)
{
    memset(addr, 0, sizeof(*addr));

    if (virXMLPropUInt(node, "iobase", 16, VIR_XML_PROP_NONE,
                       &addr->iobase) < 0)
        return -1;

    if (virXMLPropUInt(node, "irq", 16, VIR_XML_PROP_NONE, &addr->irq) < 0)
        return -1;

    return 0;
}


static int
virDomainDeviceDimmAddressParseXML(xmlNodePtr node,
                                   virDomainDeviceDimmAddress *addr)
{
    if (virXMLPropUInt(node, "slot", 10, VIR_XML_PROP_REQUIRED,
                       &addr->slot) < 0)
        return -1;

    if (virXMLPropULongLong(node, "base", 16, VIR_XML_PROP_NONE,
                            &addr->base) < 0)
        return -1;

    return 0;
}


static int
virDomainDeviceAddressParseXML(xmlNodePtr address,
                               virDomainDeviceInfo *info)
{
    if (virXMLPropEnum(address, "type",
                       virDomainDeviceAddressTypeFromString,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &info->type) < 0) {
        return -1;
    }

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (virPCIDeviceAddressParseXML(address, &info->addr.pci) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (virDomainDeviceDriveAddressParseXML(address, &info->addr.drive) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        if (virDomainDeviceVirtioSerialAddressParseXML
                (address, &info->addr.vioserial) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        if (virDomainDeviceCcidAddressParseXML(address, &info->addr.ccid) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        if (virDomainDeviceUSBAddressParseXML(address, &info->addr.usb) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (virDomainDeviceSpaprVioAddressParseXML(address, &info->addr.spaprvio) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        if (virCCWDeviceAddressParseXML(address, &info->addr.ccw) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (virDomainDeviceISAAddressParseXML(address, &info->addr.isa) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("virtio-s390 bus doesn't have an address"));
        return -1;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (virDomainDeviceDimmAddressParseXML(address, &info->addr.dimm) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    return 0;
}


#define USER_ALIAS_PREFIX "ua-"
#define USER_ALIAS_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"

bool
virDomainDeviceAliasIsUserAlias(const char *aliasStr)
{
    return aliasStr && STRPREFIX(aliasStr, USER_ALIAS_PREFIX);
}


static int
virDomainDeviceInfoParseXML(virDomainXMLOption *xmlopt,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            virDomainDeviceInfo *info,
                            unsigned int flags)
{
    xmlNodePtr acpi = NULL;
    xmlNodePtr address = NULL;
    xmlNodePtr master = NULL;
    xmlNodePtr boot = NULL;
    xmlNodePtr rom = NULL;
    int ret = -1;
    g_autofree char *aliasStr = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    virDomainDeviceInfoClear(info);
    ctxt->node = node;

    if ((aliasStr = virXPathString("string(./alias/@name)", ctxt)))
        if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) ||
            (xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_USER_ALIAS &&
             virDomainDeviceAliasIsUserAlias(aliasStr) &&
             strspn(aliasStr, USER_ALIAS_CHARS) == strlen(aliasStr)))
            info->alias = g_steal_pointer(&aliasStr);

    if ((master = virXPathNode("./master", ctxt))) {
        info->mastertype = VIR_DOMAIN_CONTROLLER_MASTER_USB;
        if (virDomainDeviceUSBMasterParseXML(master, &info->master.usb) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT &&
        (boot = virXPathNode("./boot", ctxt))) {
        if (virDomainDeviceBootParseXML(boot, info))
            goto cleanup;
    }

    if ((flags & VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) &&
        (rom = virXPathNode("./rom", ctxt))) {
        if (virXMLPropTristateBool(rom, "enabled", VIR_XML_PROP_NONE,
                                   &info->romenabled) < 0)
            goto cleanup;

        if (virXMLPropTristateSwitch(rom, "bar", VIR_XML_PROP_NONE,
                                     &info->rombar) < 0)
            goto cleanup;

        info->romfile = virXMLPropString(rom, "file");

        if (info->romenabled == VIR_TRISTATE_BOOL_NO &&
            (info->rombar != VIR_TRISTATE_SWITCH_ABSENT || info->romfile)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ROM tuning is not supported when ROM is disabled"));
            goto cleanup;
        }
    }

    if ((acpi = virXPathNode("./acpi", ctxt))) {
        if (virXMLPropUInt(acpi, "index", 10, VIR_XML_PROP_NONZERO,
                           &info->acpiIndex) < 0)
            goto cleanup;
    }

    if ((address = virXPathNode("./address", ctxt)) &&
        virDomainDeviceAddressParseXML(address, info) < 0)
        goto cleanup;


    ret = 0;
 cleanup:
    if (ret < 0)
        virDomainDeviceInfoClear(info);
    return ret;
}

static int
virDomainHostdevSubsysUSBDefParseXML(xmlNodePtr node,
                                     xmlXPathContextPtr ctxt,
                                     virDomainHostdevDef *def)
{
    virDomainHostdevSubsysUSB *usbsrc = &def->source.subsys.u.usb;
    xmlNodePtr vendorNode;
    xmlNodePtr productNode;
    xmlNodePtr addressNode;
    virTristateBool autoAddress;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virXMLPropEnum(node, "startupPolicy",
                       virDomainStartupPolicyTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->startupPolicy) < 0)
        return -1;

    if (virXMLPropTristateBool(node, "autoAddress", VIR_XML_PROP_NONE,
                               &autoAddress) < 0)
        return -1;
    virTristateBoolToBool(autoAddress, &usbsrc->autoAddress);

    if (virXMLPropEnum(node, "guestReset",
                       virDomainHostdevSubsysUSBGuestResetTypeFromString,
                       VIR_XML_PROP_NONZERO, &usbsrc->guestReset) < 0)
        return -1;

    /* Product can validly be 0, so we need some extra help to determine
     * if it is uninitialized */
    vendorNode = virXPathNode("./vendor", ctxt);
    productNode = virXPathNode("./product", ctxt);

    if (vendorNode) {
        if (virXMLPropUInt(vendorNode, "id", 0,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &usbsrc->vendor) < 0)
            return -1;

        if (!productNode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing product"));
            return -1;
        }
    }

    if (productNode) {
        if (virXMLPropUInt(productNode, "id", 0,
                           VIR_XML_PROP_REQUIRED, &usbsrc->product) < 0)
            return -1;

        if (!vendorNode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing vendor"));
            return -1;
        }
    }

    if ((addressNode = virXPathNode("./address", ctxt))) {
        if (virXMLPropUInt(addressNode, "bus", 0,
                           VIR_XML_PROP_REQUIRED, &usbsrc->bus) < 0)
            return -1;

        if (virXMLPropUInt(addressNode, "device", 0,
                           VIR_XML_PROP_REQUIRED, &usbsrc->device) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainHostdevSubsysPCIDefParseXML(xmlNodePtr node,
                                     xmlXPathContextPtr ctxt,
                                     virDomainHostdevDef *def,
                                     unsigned int flags)
{
    xmlNodePtr address = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virXMLPropTristateBool(node, "writeFiltering",
                               VIR_XML_PROP_NONE,
                               &def->writeFiltering) < 0)
        return -1;

    if ((address = virXPathNode("./address", ctxt)) &&
        virPCIDeviceAddressParseXML(address, &def->source.subsys.u.pci.addr) < 0)
        return -1;

    if ((flags & VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES)) {
        virDomainHostdevSubsysPCI *pcisrc = &def->source.subsys.u.pci;
        g_autofree xmlNodePtr *nodes = NULL;
        ssize_t nnodes;
        size_t i;

        if ((nnodes = virXPathNodeSet("./origstates/*", ctxt, &nodes)) < 0)
            return -1;

        if (nnodes > 0) {
            if (!pcisrc->origstates)
                pcisrc->origstates = virBitmapNew(VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_LAST);
            else
                virBitmapClearAll(pcisrc->origstates);

            for (i = 0; i < nnodes; i++) {
                int state;

                if ((state = virDomainHostdevPCIOrigstateTypeFromString((const char *) nodes[i]->name)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unsupported element '%1$s' of 'origstates'"),
                                   (const char *) nodes[i]->name);
                    return -1;
                }

                virBitmapSetBitExpand(pcisrc->origstates, state);
            }
        }
    }

    return 0;
}


int
virDomainStorageNetworkParseHost(xmlNodePtr hostnode,
                                 virStorageNetHostDef *host)
{
    int ret = -1;
    g_autofree char *transport = NULL;
    g_autofree char *port = NULL;

    memset(host, 0, sizeof(*host));

    if (virXMLPropEnumDefault(hostnode, "transport",
                              virStorageNetHostTransportTypeFromString,
                              VIR_XML_PROP_NONE,
                              &host->transport,
                              VIR_STORAGE_NET_HOST_TRANS_TCP) < 0) {
        goto cleanup;
    }

    host->socket = virXMLPropString(hostnode, "socket");

    if (host->transport == VIR_STORAGE_NET_HOST_TRANS_UNIX &&
        host->socket == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing socket for unix transport"));
        goto cleanup;
    }

    if (host->transport != VIR_STORAGE_NET_HOST_TRANS_UNIX &&
        host->socket != NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("transport '%1$s' does not support socket attribute"),
                       transport);
        goto cleanup;
    }

    if (host->transport != VIR_STORAGE_NET_HOST_TRANS_UNIX) {
        if (!(host->name = virXMLPropString(hostnode, "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing name for host"));
            goto cleanup;
        }

        if ((port = virXMLPropString(hostnode, "port"))) {
            if (virStringParsePort(port, &host->port) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (ret < 0)
        virStorageNetHostDefClear(host);
    return ret;
}


static int
virDomainStorageNetworkParseHosts(xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  virStorageNetHostDef **hosts,
                                  size_t *nhosts)
{
    g_autofree xmlNodePtr *hostnodes = NULL;
    ssize_t nhostnodes;
    size_t i;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if ((nhostnodes = virXPathNodeSet("./host", ctxt, &hostnodes)) <= 0)
        return nhostnodes;

    *hosts = g_new0(virStorageNetHostDef, nhostnodes);
    *nhosts = nhostnodes;

    for (i = 0; i < nhostnodes; i++) {
        if (virDomainStorageNetworkParseHost(hostnodes[i], *hosts + i) < 0)
            return -1;
    }

    return 0;
}


static void
virDomainStorageNetworkParseNFS(xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               virStorageSource *src)
{
    xmlNodePtr nfsIdentityNode = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);

    ctxt->node = node;

    if ((nfsIdentityNode = virXPathNode("./identity", ctxt))) {
        src->nfs_user = virXMLPropString(nfsIdentityNode, "user");
        src->nfs_group = virXMLPropString(nfsIdentityNode, "group");
    }
}


static int
virDomainHostdevSubsysSCSIHostDefParseXML(xmlNodePtr sourcenode,
                                          xmlXPathContextPtr ctxt,
                                          virDomainHostdevSubsysSCSI *scsisrc,
                                          unsigned int flags,
                                          virDomainXMLOption *xmlopt)
{
    virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
    xmlNodePtr addressnode = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = sourcenode;

    if (!(addressnode = virXPathNode("./address", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'address' must be specified for scsi hostdev source"));
        return -1;
    }

    if (virXMLPropUInt(addressnode, "bus", 0, VIR_XML_PROP_REQUIRED,
                       &scsihostsrc->bus) < 0)
        return -1;

    if (virXMLPropUInt(addressnode, "target", 0, VIR_XML_PROP_REQUIRED,
                       &scsihostsrc->target) < 0)
        return -1;

    if (virXMLPropULongLong(addressnode, "unit", 0, VIR_XML_PROP_REQUIRED,
                            &scsihostsrc->unit) < 0)
        return -1;

    if (!(scsihostsrc->adapter = virXPathString("string(./adapter/@name)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'adapter' name must be specified for scsi hostdev source"));
        return -1;
    }

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        xmlopt && xmlopt->privateData.storageParse) {
        if ((ctxt->node = virXPathNode("./privateData", ctxt))) {
            if (!scsihostsrc->src)
                scsihostsrc->src = virStorageSourceNew();
            if (xmlopt->privateData.storageParse(ctxt, scsihostsrc->src) < 0)
                return -1;
        }
    }
    return 0;
}


static int
virDomainHostdevSubsysSCSIiSCSIDefParseXML(xmlNodePtr sourcenode,
                                           virDomainHostdevSubsysSCSI *def,
                                           xmlXPathContextPtr ctxt,
                                           unsigned int flags,
                                           virDomainXMLOption *xmlopt)
{
    int auth_secret_usage = -1;
    virDomainHostdevSubsysSCSIiSCSI *iscsisrc = &def->u.iscsi;
    g_autoptr(virStorageAuthDef) authdef = NULL;
    xmlNodePtr node;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = sourcenode;

    /* For the purposes of command line creation, this needs to look
     * like a disk storage source */
    iscsisrc->src = virStorageSourceNew();
    iscsisrc->src->type = VIR_STORAGE_TYPE_NETWORK;
    iscsisrc->src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    if (!(iscsisrc->src->path = virXMLPropString(sourcenode, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing iSCSI hostdev source path name"));
        return -1;
    }

    if (virDomainStorageNetworkParseHosts(sourcenode, ctxt, &iscsisrc->src->hosts,
                                          &iscsisrc->src->nhosts) < 0)
        return -1;

    if (iscsisrc->src->nhosts < 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing the host address for the iSCSI hostdev"));
        return -1;
    }
    if (iscsisrc->src->nhosts > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one source host address may be specified for the iSCSI hostdev"));
        return -1;
    }

    if ((node = virXPathNode("./auth", ctxt))) {
        if (!(authdef = virStorageAuthDefParse(node, ctxt)))
            return -1;
        if ((auth_secret_usage = virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid secret type %1$s"),
                           authdef->secrettype);
            return -1;
        }
        if (auth_secret_usage != VIR_SECRET_USAGE_TYPE_ISCSI) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("hostdev invalid secret type '%1$s'"),
                           authdef->secrettype);
            return -1;
        }
        iscsisrc->src->auth = g_steal_pointer(&authdef);
    }

    virStorageSourceInitiatorParseXML(ctxt, &iscsisrc->src->initiator);

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        xmlopt && xmlopt->privateData.storageParse) {
        if ((ctxt->node = virXPathNode("./privateData", ctxt)) &&
            xmlopt->privateData.storageParse(ctxt, iscsisrc->src) < 0)
            return -1;
    }

    return 0;
}

static int
virDomainHostdevSubsysSCSIDefParseXML(xmlNodePtr sourcenode,
                                      virDomainHostdevSubsysSCSI *scsisrc,
                                      xmlXPathContextPtr ctxt,
                                      unsigned int flags,
                                      virDomainXMLOption *xmlopt)
{
    if (virXMLPropEnum(sourcenode, "protocol",
                       virDomainHostdevSubsysSCSIProtocolTypeFromString,
                       VIR_XML_PROP_NONE,
                       &scsisrc->protocol) < 0) {
        return -1;
    }

    switch (scsisrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE:
        return virDomainHostdevSubsysSCSIHostDefParseXML(sourcenode, ctxt, scsisrc,
                                                         flags, xmlopt);

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI:
        return virDomainHostdevSubsysSCSIiSCSIDefParseXML(sourcenode, scsisrc, ctxt,
                                                          flags, xmlopt);

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainHostdevSCSIProtocolType, scsisrc->protocol);
        return -1;
    }

    return 0;
}

static int
virDomainHostdevSubsysSCSIVHostDefParseXML(xmlNodePtr sourcenode,
                                           virDomainHostdevDef *def)
{
    virDomainHostdevSubsysSCSIVHost *hostsrc = &def->source.subsys.u.scsi_host;
    g_autofree char *wwpn = NULL;


    if (virXMLPropEnum(sourcenode, "protocol",
                       virDomainHostdevSubsysSCSIHostProtocolTypeFromString,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &hostsrc->protocol) < 0) {
        return -1;
    }

    switch (hostsrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST:
        if (!(wwpn = virXMLPropString(sourcenode, "wwpn"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing vhost-scsi hostdev source wwpn"));
            return -1;
        }

        if (!STRPREFIX(wwpn, "naa.") ||
            !virValidateWWN(wwpn + 4)) {
            virReportError(VIR_ERR_XML_ERROR, "%s", _("malformed 'wwpn' value"));
            return -1;
        }
        hostsrc->wwpn = g_steal_pointer(&wwpn);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_NONE:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_LAST:
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid hostdev protocol '%1$s'"),
                       virDomainHostdevSubsysSCSIHostProtocolTypeToString(hostsrc->protocol));
        return -1;
    }

    return 0;
}

static int
virDomainHostdevSubsysMediatedDevDefParseXML(virDomainHostdevDef *def,
                                             xmlXPathContextPtr ctxt)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {0};
    xmlNodePtr node = NULL;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &def->source.subsys.u.mdev;
    g_autofree char *uuidxml = NULL;

    if (!(node = virXPathNode("./source/address", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing <address> element"));
        return -1;
    }

    if (!(uuidxml = virXMLPropString(node, "uuid"))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing 'uuid' attribute for element <address>"));
        return -1;
    }

    if (virUUIDParse(uuidxml, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Cannot parse uuid attribute of element <address>"));
        return -1;
    }

    virUUIDFormat(uuid, mdevsrc->uuidstr);
    return 0;
}

static int
virDomainHostdevDefParseXMLSubsys(xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  virDomainHostdevSubsysType type,
                                  virDomainHostdevDef *def,
                                  unsigned int flags,
                                  virDomainXMLOption *xmlopt)
{
    xmlNodePtr sourcenode;
    xmlNodePtr driver_node = NULL;
    virDomainHostdevSubsysPCI *pcisrc = &def->source.subsys.u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIVHost *scsihostsrc = &def->source.subsys.u.scsi_host;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &def->source.subsys.u.mdev;
    virTristateBool managed;
    g_autofree char *model = NULL;
    int rv;

    /* @managed can be read from the xml document - it is always an
     * attribute of the toplevel element, no matter what type of
     * element that might be (pure hostdev, or higher level device
     * (e.g. <interface>) with type='hostdev')
     */
    ignore_value(virXMLPropTristateBool(node, "managed",
                                        VIR_XML_PROP_NONE, &managed));
    virTristateBoolToBool(managed, &def->managed);

    model = virXMLPropString(node, "model");

    /* @type is passed in from the caller rather than read from the
     * xml document, because it is specified in different places for
     * different kinds of defs - it is an attribute of
     * <source>/<address> for an intelligent hostdev (<interface>),
     * but an attribute of the toplevel element for a standard
     * <hostdev>.  (the functions we're going to call expect address
     * type to already be known).
     */
    def->source.subsys.type = type;

    if (!(sourcenode = virXPathNode("./source", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <source> element in hostdev device"));
        return -1;
    }

    if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
        virXPathBoolean("boolean(./source/@startupPolicy)", ctxt)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting startupPolicy is only allowed for USB devices"));
        return -1;
    }

    if ((rv = virXMLPropEnum(node, "sgio",
                             virDomainDeviceSGIOTypeFromString,
                             VIR_XML_PROP_NONZERO,
                             &scsisrc->sgio)) < 0) {
        return -1;
    }

    if (rv > 0) {
        if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("sgio is only supported for scsi host device"));
            return -1;
        }
    }

    if ((rv = virXMLPropTristateBool(node, "rawio",
                                     VIR_XML_PROP_NONE,
                                     &scsisrc->rawio)) < 0) {
        return -1;
    }

    if (rv > 0 && def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("rawio is only supported for scsi host device"));
        return -1;
    }

    if (def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV &&
        def->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST) {
        if (model) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("'model' attribute in <hostdev> is only supported when type='%1$s'"),
                           virDomainHostdevSubsysTypeToString(def->source.subsys.type));
            return -1;
        }
    }

    if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST) {
        if (virXMLPropEnum(node, "model",
                           virDomainHostdevSubsysSCSIVHostModelTypeFromString,
                           VIR_XML_PROP_NONE,
                           &scsihostsrc->model) < 0)
            return -1;
    } else if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV) {
        if (virXMLPropEnum(node, "model",
                           virMediatedDeviceModelTypeFromString,
                           VIR_XML_PROP_REQUIRED,
                           &mdevsrc->model) < 0)
            return -1;

        if (virXMLPropTristateSwitch(node, "display",
                                     VIR_XML_PROP_NONE,
                                     &mdevsrc->display) < 0)
            return -1;

        if (virXMLPropTristateSwitch(node, "ramfb",
                                     VIR_XML_PROP_NONE,
                                     &mdevsrc->ramfb) < 0)
            return -1;
    }

    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (virDomainHostdevSubsysPCIDefParseXML(sourcenode, ctxt, def, flags) < 0)
            return -1;

        driver_node = virXPathNode("./driver", ctxt);
        if (virXMLPropEnum(driver_node, "name",
                           virDomainHostdevSubsysPCIBackendTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &pcisrc->backend) < 0)
            return -1;

        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (virDomainHostdevSubsysUSBDefParseXML(sourcenode, ctxt, def) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (virDomainHostdevSubsysSCSIDefParseXML(sourcenode, scsisrc, ctxt, flags, xmlopt) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        if (virDomainHostdevSubsysSCSIVHostDefParseXML(sourcenode, def) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        if (virDomainHostdevSubsysMediatedDevDefParseXML(def, ctxt) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("address type='%1$s' not supported in hostdev interfaces"),
                       virDomainHostdevSubsysTypeToString(def->source.subsys.type));
        return -1;
    }

    return 0;
}

static virNetDevIPAddr *
virDomainNetIPParseXML(xmlNodePtr node)
{
    /* Parse the prefix in every case */
    unsigned int prefixValue = 0;
    int family = AF_UNSPEC;
    g_autofree virNetDevIPAddr *ip = NULL;
    g_autofree char *prefixStr = NULL;
    g_autofree char *familyStr = NULL;
    g_autofree char *address = NULL;
    g_autofree char *peer = NULL;

    if (!(address = virXMLPropString(node, "address"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing required address in <ip>"));
        return NULL;
    }

    familyStr = virXMLPropString(node, "family");
    if (familyStr && STREQ(familyStr, "ipv4"))
        family = AF_INET;
    else if (familyStr && STREQ(familyStr, "ipv6"))
        family = AF_INET6;
    else
        family = virSocketAddrNumericFamily(address);

    ip = g_new0(virNetDevIPAddr, 1);

    if (virSocketAddrParse(&ip->address, address, family) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid address '%1$s' in <ip>"),
                       address);
        return NULL;
    }

    prefixStr = virXMLPropString(node, "prefix");
    if (prefixStr &&
        ((virStrToLong_ui(prefixStr, NULL, 10, &prefixValue) < 0) ||
         (family == AF_INET6 && prefixValue > 128) ||
         (family == AF_INET && prefixValue > 32))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid prefix value '%1$s' in <ip>"),
                       prefixStr);
        return NULL;
    }
    ip->prefix = prefixValue;

    if ((peer = virXMLPropString(node, "peer")) != NULL &&
        virSocketAddrParse(&ip->peer, peer, family) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid peer '%1$s' in <ip>"), peer);
        return NULL;
    }

    return g_steal_pointer(&ip);
}


/* fill in a virNetDevIPInfo *from the <route> and <ip>
 * elements found in the given XML context.
 *
 * return 0 on success (including none found) and -1 on failure.
 */
static int
virDomainNetIPInfoParseXML(const char *source,
                           xmlNodePtr node,
                           xmlXPathContextPtr ctxt,
                           virNetDevIPInfo *def)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    size_t i;
    g_autofree xmlNodePtr *ipNodes = NULL;
    int nipNodes;
    g_autofree xmlNodePtr *routeNodes = NULL;
    int nrouteNodes;

    if (node)
        ctxt->node = node;

    if ((nipNodes = virXPathNodeSet("./ip", ctxt, &ipNodes)) < 0 ||
        (nrouteNodes = virXPathNodeSet("./route", ctxt, &routeNodes)) < 0)
        return -1;

    for (i = 0; i < nipNodes; i++) {
        virNetDevIPAddr *ip = NULL;

        if (!(ip = virDomainNetIPParseXML(ipNodes[i])))
            goto error;

        VIR_APPEND_ELEMENT(def->ips, def->nips, ip);
    }

    for (i = 0; i < nrouteNodes; i++) {
        virNetDevIPRoute *route = NULL;

        if (!(route = virNetDevIPRouteParseXML(source, routeNodes[i])))
            goto error;

        VIR_APPEND_ELEMENT(def->routes, def->nroutes, route);
    }

    return 0;
 error:
    virNetDevIPInfoClear(def);
    return -1;
}


static int
virDomainNetDefCoalesceParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virNetDevCoalesce **coalesce)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    unsigned long long tmp = 0;
    g_autofree char *str = NULL;

    ctxt->node = node;

    str = virXPathString("string(./rx/frames/@max)", ctxt);
    if (!str)
        return 0;

    if (virStrToLong_ullp(str, NULL, 10, &tmp) < 0) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("cannot parse value '%1$s' for coalesce parameter"),
                       str);
        return -1;
    }

    if (tmp > UINT32_MAX) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("value '%1$llu' is too big for coalesce parameter, maximum is '%2$lu'"),
                       tmp, (unsigned long) UINT32_MAX);
        return -1;
    }

    *coalesce = g_new0(virNetDevCoalesce, 1);
    (*coalesce)->rx_max_coalesced_frames = tmp;

    return 0;
}

static void
virDomainNetDefCoalesceFormatXML(virBuffer *buf,
                                 virNetDevCoalesce *coalesce)
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
virDomainHostdevDefParseXMLCaps(xmlNodePtr node G_GNUC_UNUSED,
                                xmlXPathContextPtr ctxt,
                                virDomainHostdevCapsType type,
                                virDomainHostdevDef *def)
{
    /* @type is passed in from the caller rather than read from the
     * xml document, because it is specified in different places for
     * different kinds of defs - it is an attribute of
     * <source>/<address> for an intelligent hostdev (<interface>),
     * but an attribute of the toplevel element for a standard
     * <hostdev>.  (the functions we're going to call expect address
     * type to already be known).
     */
    def->source.caps.type = type;

    if (!virXPathNode("./source", ctxt)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing <source> element in hostdev device"));
        return -1;
    }

    switch (def->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        if (!(def->source.caps.u.storage.block =
              virXPathString("string(./source/block[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <block> element in hostdev storage device"));
            return -1;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        if (!(def->source.caps.u.misc.chardev =
              virXPathString("string(./source/char[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <char> element in hostdev character device"));
            return -1;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        if (!(def->source.caps.u.net.ifname =
              virXPathString("string(./source/interface[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing <interface> element in hostdev net device"));
            return -1;
        }
        if (virDomainNetIPInfoParseXML(_("Domain hostdev device"), NULL,
                                       ctxt, &def->source.caps.u.net.ip) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("address type='%1$s' not supported in hostdev interfaces"),
                       virDomainHostdevCapsTypeToString(def->source.caps.type));
        return -1;
    }

    return 0;
}


virDomainControllerDef *
virDomainDeviceFindSCSIController(const virDomainDef *def,
                                  const virDomainDeviceDriveAddress *addr)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
            def->controllers[i]->idx == addr->controller)
            return def->controllers[i];
    }

    return NULL;
}

int
virDomainDiskDefAssignAddress(virDomainXMLOption *xmlopt G_GNUC_UNUSED,
                              virDomainDiskDef *def,
                              const virDomainDef *vmdef)
{
    int idx = virDiskNameToIndex(def->dst);
    if (idx < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unknown disk name '%1$s' and no address specified"),
                       def->dst);
        return -1;
    }

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI: {
        virDomainDeviceDriveAddress addr = {0, 0, 0, 0, 0};
        unsigned int controller;
        unsigned int unit;

        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        if (vmdef->scsiBusMaxUnit > SCSI_NARROW_BUS_MAX_CONT_UNIT) {
            /* For a wide SCSI bus we define the default mapping to be
             * 16 units per bus, 1 bus per controller, many controllers.
             * Unit 7 is the SCSI controller itself. Therefore unit 7
             * cannot be assigned to disks and is skipped.
             */
            controller = idx / (vmdef->scsiBusMaxUnit - 1);
            unit = idx % (vmdef->scsiBusMaxUnit - 1);

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
                           _("using disk target name '%1$s' conflicts with SCSI host device address controller='%2$u' bus='%3$u' target='%4$u' unit='%5$u"),
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

    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        /* Other disk bus's aren't controller based */
        break;
    }

    return 0;
}

static virSecurityLabelDef *
virSecurityLabelDefParseXML(xmlXPathContextPtr ctxt,
                            unsigned int flags)
{
    g_autofree char *model = NULL;
    virTristateBool relabel = VIR_TRISTATE_BOOL_ABSENT;
    g_autoptr(virSecurityLabelDef) seclabel = NULL;

    if ((model = virXMLPropString(ctxt->node, "model")) &&
        !STRLIM(model, VIR_SECURITY_MODEL_BUFLEN - 1))
        g_clear_pointer(&model, g_free);

    if (!(seclabel = virSecurityLabelDefNew(model)))
        return NULL;

    /* set default value */
    seclabel->type = VIR_DOMAIN_SECLABEL_DYNAMIC;

    if (virXMLPropEnum(ctxt->node, "type",
                       virDomainSeclabelTypeFromString,
                       VIR_XML_PROP_NONZERO,
                       &seclabel->type) < 0)
        return NULL;

    if (seclabel->type == VIR_DOMAIN_SECLABEL_STATIC ||
        seclabel->type == VIR_DOMAIN_SECLABEL_NONE)
        seclabel->relabel = false;

    if (virXMLPropTristateBool(ctxt->node, "relabel", VIR_XML_PROP_NONE, &relabel) < 0)
        return NULL;

    virTristateBoolToBool(relabel, &seclabel->relabel);

    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
        !seclabel->relabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("dynamic label type must use resource relabeling"));
        return NULL;
    }
    if (seclabel->type == VIR_DOMAIN_SECLABEL_NONE &&
        seclabel->relabel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("resource relabeling is not compatible with 'none' label type"));
        return NULL;
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
                               _("unsupported type='%1$s' to model 'none'"),
                               virDomainSeclabelTypeToString(seclabel->type));
                return NULL;
            }
            /* combination of relabel='yes' and type='static'
             * is checked a few lines above. */
        }
        return g_steal_pointer(&seclabel);
    }

    /* Only parse label, if using static labels, or
     * if the 'live' VM XML is requested
     */
    if (seclabel->type == VIR_DOMAIN_SECLABEL_STATIC ||
        (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
         seclabel->type != VIR_DOMAIN_SECLABEL_NONE)) {
        seclabel->label = virXPathString("string(./label[1])", ctxt);
        if (!seclabel->label || !STRLIM(seclabel->label, VIR_SECURITY_LABEL_BUFLEN - 1)) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("security label is missing"));
            return NULL;
        }
    }

    /* Only parse imagelabel, if requested live XML with relabeling */
    if (seclabel->relabel &&
        (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
         seclabel->type != VIR_DOMAIN_SECLABEL_NONE)) {
        seclabel->imagelabel = virXPathString("string(./imagelabel[1])", ctxt);

        if (!seclabel->imagelabel || !STRLIM(seclabel->imagelabel, VIR_SECURITY_LABEL_BUFLEN - 1)) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("security imagelabel is missing"));
            return NULL;
        }
    }

    /* Only parse baselabel for dynamic label type */
    if (seclabel->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        seclabel->baselabel = virXPathString("string(./baselabel[1])", ctxt);

        if (seclabel->baselabel &&
            !STRLIM(seclabel->baselabel, VIR_SECURITY_LABEL_BUFLEN - 1))
            g_clear_pointer(&seclabel->baselabel, g_free);
    }

    return g_steal_pointer(&seclabel);
}

static int
virSecurityLabelDefsParseXML(virDomainDef *def,
                             xmlXPathContextPtr ctxt,
                             virDomainXMLOption *xmlopt,
                             unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    size_t i = 0, j;
    int n;
    g_autofree xmlNodePtr *list = NULL;

    /* Allocate a security labels based on XML */
    if ((n = virXPathNodeSet("./seclabel", ctxt, &list)) < 0)
        goto error;
    if (n == 0)
        return 0;

    def->seclabels = g_new0(virSecurityLabelDef *, n);

    /* Parse each "seclabel" tag */
    for (i = 0; i < n; i++) {
        virSecurityLabelDef *seclabel;

        ctxt->node = list[i];
        if (!(seclabel = virSecurityLabelDefParseXML(ctxt, flags)))
            goto error;

        for (j = 0; j < i; j++) {
            if (STREQ_NULLABLE(seclabel->model, def->seclabels[j]->model)) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("seclabel for model %1$s is already provided"),
                               seclabel->model);
                virSecurityLabelDefFree(seclabel);
                goto error;
            }
        }

        def->seclabels[i] = seclabel;
    }
    def->nseclabels = n;

    /* libvirt versions prior to 0.10.0 support just a single seclabel element
     * in guest's XML and model attribute can be suppressed if type is none or
     * type is dynamic, baselabel is not defined and INACTIVE flag is set.
     *
     * To avoid compatibility issues, for this specific case the first model
     * defined in host's capabilities is used as model for the seclabel.
     */
    if (def->nseclabels == 1 &&
        !def->seclabels[0]->model &&
        xmlopt != NULL &&
        xmlopt->config.defSecModel != NULL) {
        if (def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_NONE ||
            (def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DYNAMIC &&
             !def->seclabels[0]->baselabel &&
             (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
            /* Copy model from host. */
            VIR_DEBUG("Found seclabel without a model, using '%s'",
                      xmlopt->config.defSecModel);
            def->seclabels[0]->model = g_strdup(xmlopt->config.defSecModel);

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
                               _("missing security model when using multiple labels"));
                goto error;
            }
        }
    }

    return 0;

 error:
    for (; i > 0; i--)
        virSecurityLabelDefFree(def->seclabels[i - 1]);
    VIR_FREE(def->seclabels);
    def->nseclabels = 0;
    return -1;
}

/* Parse the <seclabel> from a disk or character device. */
static int
virSecurityDeviceLabelDefParseXML(virSecurityDeviceLabelDef ***seclabels_rtn,
                                  size_t *nseclabels_rtn,
                                  xmlXPathContextPtr ctxt,
                                  unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virSecurityDeviceLabelDef **seclabels = NULL;
    size_t nseclabels = 0;
    int n;
    size_t i, j;
    g_autofree xmlNodePtr *list = NULL;

    if ((n = virXPathNodeSet("./seclabel", ctxt, &list)) < 0)
        goto error;
    if (n == 0)
        return 0;

    seclabels = g_new0(virSecurityDeviceLabelDef *, n);
    nseclabels = n;
    for (i = 0; i < n; i++)
        seclabels[i] = g_new0(virSecurityDeviceLabelDef, 1);

    for (i = 0; i < n; i++) {
        g_autofree char *model = NULL;
        g_autofree char *label = NULL;
        int relabelSpecified;
        virTristateBool t;

        /* get model associated to this override */
        model = virXMLPropString(list[i], "model");
        if (model) {
            /* check for duplicate seclabels */
            for (j = 0; j < i; j++) {
                if (STREQ_NULLABLE(model, seclabels[j]->model)) {
                    virReportError(VIR_ERR_XML_DETAIL,
                                   _("seclabel for model %1$s is already provided"), model);
                    goto error;
                }
            }
            seclabels[i]->model = g_steal_pointer(&model);
        }

        relabelSpecified = virXMLPropTristateBool(list[i], "relabel",
                                                  VIR_XML_PROP_NONE, &t);
        if (relabelSpecified < 0)
            goto error;

        seclabels[i]->relabel = true;
        virTristateBoolToBool(t, &seclabels[i]->relabel);

        /* labelskip is only parsed on live images */
        seclabels[i]->labelskip = false;
        if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
            if (virXMLPropTristateBool(list[i], "labelskip", VIR_XML_PROP_NONE, &t) < 0)
                goto error;

            virTristateBoolToBool(t, &seclabels[i]->labelskip);
        }

        ctxt->node = list[i];
        label = virXPathString("string(./label)", ctxt);

        if (label && STRLIM(label, VIR_SECURITY_LABEL_BUFLEN - 1))
            seclabels[i]->label = g_steal_pointer(&label);

        if (seclabels[i]->label && !seclabels[i]->relabel) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot specify a label if relabelling is turned off. model=%1$s"),
                           NULLSTR(seclabels[i]->model));
            goto error;
        }

        if (relabelSpecified > 0 &&
            flags & VIR_DOMAIN_DEF_PARSE_INACTIVE &&
            seclabels[i]->relabel && !seclabels[i]->label) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot specify relabel if label is missing. model=%1$s"),
                           NULLSTR(seclabels[i]->model));
            goto error;
        }
    }

    *nseclabels_rtn = nseclabels;
    *seclabels_rtn = seclabels;

    return 0;

 error:
    for (i = 0; i < nseclabels; i++)
        virSecurityDeviceLabelDefFree(seclabels[i]);
    VIR_FREE(seclabels);
    return -1;
}


/* Parse the XML definition for a lease
 */
static virDomainLeaseDef *
virDomainLeaseDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    virDomainLeaseDef *def;
    g_autofree char *lockspace = NULL;
    g_autofree char *key = NULL;
    g_autofree char *path = NULL;
    xmlNodePtr targetNode = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;
    def = g_new0(virDomainLeaseDef, 1);

    if (!(key = virXPathString("string(./key)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'key' element for lease"));
        goto error;
    }

    if (!(lockspace = virXPathString("string(./lockspace)", ctxt)))
        goto error;

    if (!(targetNode = virXPathNode("./target", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'target' element for lease"));
        goto error;
    }

    if (!(path = virXMLPropString(targetNode, "path"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing 'path' attribute to 'target' element for lease"));
        goto error;
    }

    if (virXMLPropULongLong(targetNode, "offset", 10,
                            VIR_XML_PROP_NONE, &def->offset) < 0)
        goto error;

    def->key = g_steal_pointer(&key);
    def->lockspace = g_steal_pointer(&lockspace);
    def->path = g_steal_pointer(&path);

    return def;

 error:
    virDomainLeaseDefFree(def);
    return NULL;
}

static virStorageSourcePoolDef *
virDomainDiskSourcePoolDefParse(xmlNodePtr node,
                                virDomainDefParseFlags flags)
{
    g_autoptr(virStorageSourcePoolDef) source = g_new0(virStorageSourcePoolDef, 1);

    source->pool = virXMLPropString(node, "pool");
    source->volume = virXMLPropString(node, "volume");

    /* CD-ROM and Floppy allows no source -> empty pool */
    if (!source->pool && !source->volume)
        return g_steal_pointer(&source);

    if (!source->pool || !source->volume) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'pool' and 'volume' must be specified together for 'pool' type source"));
        return NULL;
    }

    if (virXMLPropEnum(node, "mode",
                       virStorageSourcePoolModeTypeFromString,
                       VIR_XML_PROP_NONZERO,
                       &source->mode) < 0)
        return NULL;

    if (flags & VIR_DOMAIN_DEF_PARSE_VOLUME_TRANSLATED) {
        if (virXMLPropEnum(node, "actualType",
                           virStorageTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &source->actualtype) < 0)
            return NULL;
    }

    return g_steal_pointer(&source);
}


static virStorageNetCookieDef *
virDomainStorageNetCookieParse(xmlNodePtr node,
                               xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virStorageNetCookieDef) cookie = NULL;

    ctxt->node = node;

    cookie = g_new0(virStorageNetCookieDef, 1);

    if (!(cookie->name = virXPathString("string(./@name)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("missing cookie name"));
        return NULL;
    }

    if (!(cookie->value = virXPathString("string(.)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, _("missing value for cookie '%1$s'"),
                       cookie->name);
        return NULL;
    }

    return g_steal_pointer(&cookie);
}


static int
virDomainStorageNetCookiesParse(xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virStorageSource *src)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    ssize_t nnodes;
    size_t i;

    ctxt->node = node;

    if ((nnodes = virXPathNodeSet("./cookie", ctxt, &nodes)) < 0)
        return -1;

    src->cookies = g_new0(virStorageNetCookieDef *, nnodes);
    src->ncookies = nnodes;

    for (i = 0; i < nnodes; i++) {
        if (!(src->cookies[i] = virDomainStorageNetCookieParse(nodes[i], ctxt)))
            return -1;
    }

    if (virStorageSourceNetCookiesValidate(src) < 0)
        return -1;

    return 0;
}


static int
virDomainDiskSourceNetworkParse(xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virStorageSource *src,
                                unsigned int flags)
{
    virStorageNetProtocol protocol;
    xmlNodePtr tmpnode;

    if (virXMLPropEnum(node, "protocol", virStorageNetProtocolTypeFromString,
                       VIR_XML_PROP_REQUIRED, &protocol) < 0)
        return -1;

    src->protocol = protocol;

    if (!(src->path = virXMLPropString(node, "name")) &&
        src->protocol != VIR_STORAGE_NET_PROTOCOL_NBD) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing name for disk source"));
        return -1;
    }

    if (virXMLPropTristateBool(node, "tls", VIR_XML_PROP_NONE,
                               &src->haveTLS) < 0)
        return -1;

    src->tlsHostname = virXMLPropString(node, "tlsHostname");

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        int value;
        if (virXMLPropInt(node, "tlsFromConfig", 10, VIR_XML_PROP_NONE,
                          &value, 0) < 0)
            return -1;
        src->tlsFromConfig = !!value;
    }

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_NBD) {
        xmlNodePtr cur;
        if ((cur = virXPathNode("./reconnect", ctxt))) {
            if (virXMLPropUInt(cur, "delay", 10, VIR_XML_PROP_NONE,
                               &src->reconnectDelay) < 0)
                return -1;
        }
    }

    /* for historical reasons we store the volume and image name in one XML
     * element although it complicates thing when attempting to access them. */
    if (src->path &&
        (src->protocol == VIR_STORAGE_NET_PROTOCOL_GLUSTER ||
         src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD)) {
        char *tmp;
        if (!(tmp = strchr(src->path, '/')) ||
            tmp == src->path) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("can't split path '%1$s' into pool name and image name"),
                           src->path);
            return -1;
        }

        src->volume = src->path;

        src->path = g_strdup(tmp + 1);

        tmp[0] = '\0';
    }

    /* snapshot currently works only for remote disks */
    src->snapshot = virXPathString("string(./snapshot/@name)", ctxt);

    /* config file currently only works with remote disks */
    src->configFile = virXPathString("string(./config/@file)", ctxt);

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTP ||
        src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS)
        src->query = virXMLPropString(node, "query");

    if (virDomainStorageNetworkParseHosts(node, ctxt, &src->hosts, &src->nhosts) < 0)
        return -1;

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_NFS)
        virDomainStorageNetworkParseNFS(node, ctxt, src);

    virStorageSourceNetworkAssignDefaultPorts(src);

    virStorageSourceInitiatorParseXML(ctxt, &src->initiator);

    if ((src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS ||
         src->protocol == VIR_STORAGE_NET_PROTOCOL_FTPS) &&
        (tmpnode = virXPathNode("./ssl", ctxt))) {
        if (virXMLPropTristateBool(tmpnode, "verify", VIR_XML_PROP_NONE,
                                   &src->sslverify) < 0)
            return -1;
    }

    if ((src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTP ||
         src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS) &&
        (tmpnode = virXPathNode("./cookies", ctxt))) {
        if (virDomainStorageNetCookiesParse(tmpnode, ctxt, src) < 0)
            return -1;
    }

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTP ||
        src->protocol == VIR_STORAGE_NET_PROTOCOL_HTTPS ||
        src->protocol == VIR_STORAGE_NET_PROTOCOL_FTP ||
        src->protocol == VIR_STORAGE_NET_PROTOCOL_FTPS) {

        if (virXPathULongLong("string(./readahead/@size)", ctxt, &src->readahead) == -2 ||
            virXPathULongLong("string(./timeout/@seconds)", ctxt, &src->timeout) == -2) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                          _("invalid readahead size or timeout"));
            return -1;
        }
    }
    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_SSH) {
        if ((tmpnode = virXPathNode("./knownHosts", ctxt))) {
            if (!(src->ssh_known_hosts_file = virXMLPropStringRequired(tmpnode, "path")))
                return -1;
        }
        if ((tmpnode = virXPathNode("./identity", ctxt))) {
            if (!(src->ssh_user = virXMLPropStringRequired(tmpnode, "username")))
                return -1;

            /* optional path to an ssh key file */
            src->ssh_keyfile = virXMLPropString(tmpnode, "keyfile");

            /* optional ssh-agent socket location */
            src->ssh_agent = virXMLPropString(tmpnode, "agentsock");
            if (!src->ssh_keyfile && !src->ssh_agent) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("element '%1$s' requires either 'keyfile' or 'agentsock' attribute"),
                               tmpnode->name);
                return -1;
            }
        }
    }

    return 0;
}


static int
virDomainDiskSourceNVMeParse(xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             virStorageSource *src)
{
    g_autoptr(virStorageSourceNVMeDef) nvme = NULL;
    g_autofree char *type = NULL;
    xmlNodePtr address;

    nvme = g_new0(virStorageSourceNVMeDef, 1);

    if (!(type = virXMLPropString(node, "type"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing 'type' attribute to disk source"));
        return -1;
    }

    if (STRNEQ(type, "pci")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported source type '%1$s'"),
                       type);
        return -1;
    }

    if (virXMLPropULongLong(node, "namespace", 10,
                            VIR_XML_PROP_REQUIRED,
                            &nvme->namespc) < 0) {
        return -1;
    }

    if (virXMLPropTristateBool(node, "managed", VIR_XML_PROP_NONE,
                               &nvme->managed) < 0)
        return -1;

    if (!(address = virXPathNode("./address", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("NVMe disk source is missing address"));
        return -1;
    }

    if (virPCIDeviceAddressParseXML(address, &nvme->pciAddr) < 0)
        return -1;

    src->nvme = g_steal_pointer(&nvme);
    return 0;
}


static int
virDomainDiskSourceVHostUserParse(xmlNodePtr node,
                                  virStorageSource *src,
                                  virDomainXMLOption *xmlopt,
                                  xmlXPathContextPtr ctxt)
{
    g_autofree char *type = virXMLPropString(node, "type");
    g_autofree char *path = virXMLPropString(node, "path");

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing 'type' attribute for vhostuser disk source"));
        return -1;
    }

    if (STRNEQ(type, "unix")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid 'type' attribute for vhostuser disk source"));
        return -1;
    }

    if (!path) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing 'path' attribute for vhostuser disk source"));
        return -1;
    }

    if (!(src->vhostuser = virDomainChrSourceDefNew(xmlopt)))
        return -1;

    src->vhostuser->type = virDomainChrTypeFromString(type);
    src->vhostuser->data.nix.path = g_steal_pointer(&path);

    if (virDomainChrSourceReconnectDefParseXML(&src->vhostuser->data.nix.reconnect,
                                               node,
                                               ctxt) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainDiskSourcePRParse(xmlNodePtr node,
                           xmlXPathContextPtr ctxt,
                           virStoragePRDef **pr)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(ctxt->node = virXPathNode("./reservations", ctxt)))
        return 0;

    if (!(*pr = virStoragePRDefParseXML(ctxt)))
        return -1;

    return 0;
}


virStorageSource *
virDomainStorageSourceParseBase(const char *type,
                                const char *format,
                                const char *index)
{
    g_autoptr(virStorageSource) src = NULL;

    src = virStorageSourceNew();
    src->type = VIR_STORAGE_TYPE_FILE;

    if (type) {
        int tmp;
        if ((tmp = virStorageTypeFromString(type)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown storage source type '%1$s'"), type);
            return NULL;
        }

        src->type = tmp;
    }

    if (format &&
        (src->format = virStorageFileFormatTypeFromString(format)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown storage source format '%1$s'"), format);
        return NULL;
    }

    if (index &&
        virStrToLong_uip(index, NULL, 10, &src->id) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid storage source index '%1$s'"), index);
        return NULL;
    }

    return g_steal_pointer(&src);
}


static virStorageSourceSlice *
virDomainStorageSourceParseSlice(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *offset = NULL;
    g_autofree char *size = NULL;
    g_autofree virStorageSourceSlice *ret = g_new0(virStorageSourceSlice, 1);

    ctxt->node = node;

    if (!(offset = virXPathString("string(./@offset)", ctxt)) ||
        !(size = virXPathString("string(./@size)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing offset or size attribute of slice"));
        return NULL;
    }

    if (virStrToLong_ullp(offset, NULL, 10, &ret->offset) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("malformed value '%1$s' of 'offset' attribute of slice"),
                       offset);
        return NULL;
    }

    if (virStrToLong_ullp(size, NULL, 10, &ret->size) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("malformed value '%1$s' of 'size' attribute of slice"),
                       size);
        return NULL;
    }

    return g_steal_pointer(&ret);
}


static int
virDomainStorageSourceParseSlices(virStorageSource *src,
                                  xmlXPathContextPtr ctxt)
{
    xmlNodePtr node;

    if ((node = virXPathNode("./slices/slice[@type='storage']", ctxt))) {
        if (!(src->sliceStorage = virDomainStorageSourceParseSlice(node, ctxt)))
            return -1;
    }

    return 0;
}


/**
 * virDomainStorageSourceParse:
 * @node: XML node pointing to the source element to parse
 * @ctxt: XPath context
 * @src: filled with parsed data
 * @flags: XML parser flags
 * @xmlopt: XML parser callbacks
 *
 * Parses @src definition from element pointed to by @node. Note that this
 * does not parse the 'type' and 'format' attributes of @src and 'type' needs
 * to be set correctly prior to calling this function.
 */
int
virDomainStorageSourceParse(xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            virStorageSource *src,
                            unsigned int flags,
                            virDomainXMLOption *xmlopt)
{
    virStorageType actualType = src->type;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr tmp;

    ctxt->node = node;

    if (src->type == VIR_STORAGE_TYPE_VOLUME) {
        if (!(src->srcpool = virDomainDiskSourcePoolDefParse(node, flags)))
            return -1;

        /* If requested we need to also parse the translated volume runtime data */
        if (flags & VIR_DOMAIN_DEF_PARSE_VOLUME_TRANSLATED)
            actualType = virStorageSourceGetActualType(src);
    }

    switch (actualType) {
    case VIR_STORAGE_TYPE_FILE:
        src->path = virXMLPropString(node, "file");
        src->fdgroup = virXMLPropString(node, "fdgroup");
        break;
    case VIR_STORAGE_TYPE_BLOCK:
        src->path = virXMLPropString(node, "dev");
        break;
    case VIR_STORAGE_TYPE_DIR:
        src->path = virXMLPropString(node, "dir");
        break;
    case VIR_STORAGE_TYPE_NETWORK:
        if (virDomainDiskSourceNetworkParse(node, ctxt, src, flags) < 0)
            return -1;
        break;
    case VIR_STORAGE_TYPE_VOLUME:
        /* parsed above */
        break;
    case VIR_STORAGE_TYPE_NVME:
        if (virDomainDiskSourceNVMeParse(node, ctxt, src) < 0)
            return -1;
        break;
    case VIR_STORAGE_TYPE_VHOST_USER:
        if (virDomainDiskSourceVHostUserParse(node, src, xmlopt, ctxt) < 0)
            return -1;
        break;
    case VIR_STORAGE_TYPE_VHOST_VDPA:
        if (!(src->vdpadev = virXMLPropStringRequired(node, "dev")))
            return -1;
        break;
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk type %1$s"),
                       virStorageTypeToString(actualType));
        return -1;
    }

    if ((tmp = virXPathNode("./auth", ctxt)) &&
        !(src->auth = virStorageAuthDefParse(tmp, ctxt)))
        return -1;

    if ((tmp = virXPathNode("./encryption", ctxt)) &&
        !(src->encryption = virStorageEncryptionParseNode(tmp, ctxt)))
        return -1;

    if (virDomainDiskSourcePRParse(node, ctxt, &src->pr) < 0)
        return -1;

    if (virDomainStorageSourceParseSlices(src, ctxt) < 0)
        return -1;

    if (virSecurityDeviceLabelDefParseXML(&src->seclabels, &src->nseclabels,
                                          ctxt, flags) < 0)
        return -1;

    /* People sometimes pass a bogus '' source path when they mean to omit the
     * source element completely (e.g. CDROM without media). This is just a
     * little compatibility check to help those broken apps */
    if (src->path && !*src->path)
        VIR_FREE(src->path);

    if ((flags & VIR_DOMAIN_DEF_PARSE_STATUS) &&
        xmlopt && xmlopt->privateData.storageParse &&
        (tmp = virXPathNode("./privateData", ctxt))) {
        ctxt->node = tmp;

        if (xmlopt->privateData.storageParse(ctxt, src) < 0)
            return -1;
    }

    return 0;
}


int
virDomainDiskBackingStoreParse(xmlXPathContextPtr ctxt,
                               virStorageSource *src,
                               unsigned int flags,
                               virDomainXMLOption *xmlopt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr source;
    g_autoptr(virStorageSource) backingStore = NULL;
    g_autofree char *type = NULL;
    g_autofree char *format = NULL;
    g_autofree char *idx = NULL;

    if (!(ctxt->node = virXPathNode("./backingStore", ctxt)))
        return 0;

    /* terminator does not have a type */
    if (!(type = virXMLPropString(ctxt->node, "type"))) {
        src->backingStore = virStorageSourceNew();
        return 0;
    }

    if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
        idx = virXMLPropString(ctxt->node, "index");

    if (!(format = virXPathString("string(./format/@type)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing disk backing store format"));
        return -1;
    }

    if (!(source = virXPathNode("./source", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing disk backing store source"));
        return -1;
    }

    if (!(backingStore = virDomainStorageSourceParseBase(type, format, idx)))
        return -1;

    if (virParseScaledValue("./format/metadata_cache/max_size", NULL,
                            ctxt,
                            &backingStore->metadataCacheMaxSize,
                            1, ULLONG_MAX, false) < 0)
        return -1;

    /* backing store is always read-only */
    backingStore->readonly = true;

    if (virDomainStorageSourceParse(source, ctxt, backingStore, flags, xmlopt) < 0 ||
        virDomainDiskBackingStoreParse(ctxt, backingStore, flags, xmlopt) < 0)
        return -1;

    src->backingStore = g_steal_pointer(&backingStore);

    return 0;
}

#define PARSE_IOTUNE(val) \
    if (virXPathULongLong("string(./iotune/" #val ")", \
                          ctxt, &def->blkdeviotune.val) == -2) { \
        virReportError(VIR_ERR_XML_ERROR, \
                       _("disk iotune field '%1$s' must be an integer"), #val); \
        return -1; \
    }

static int
virDomainDiskDefIotuneParse(virDomainDiskDef *def,
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

    return 0;
}
#undef PARSE_IOTUNE


static int
virDomainDiskDefMirrorParse(virDomainDiskDef *def,
                            xmlNodePtr cur,
                            xmlXPathContextPtr ctxt,
                            unsigned int flags,
                            virDomainXMLOption *xmlopt)
{
    xmlNodePtr mirrorNode;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *mirrorFormat = NULL;
    g_autofree char *mirrorType = NULL;
    g_autofree char *ready = NULL;
    g_autofree char *blockJob = NULL;
    g_autofree char *index = NULL;

    ctxt->node = cur;

    if ((blockJob = virXMLPropString(cur, "job"))) {
        if ((def->mirrorJob = virDomainBlockJobTypeFromString(blockJob)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown mirror job type '%1$s'"), blockJob);
            return -1;
        }
    } else {
        def->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    }

    if ((mirrorType = virXMLPropString(cur, "type"))) {
        mirrorFormat = virXPathString("string(./format/@type)", ctxt);
        index = virXPathString("string(./source/@index)", ctxt);
    } else {
        if (def->mirrorJob != VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror without type only supported by copy job"));
            return -1;
        }
        mirrorFormat = virXMLPropString(cur, "format");
    }

    if (!(def->mirror = virDomainStorageSourceParseBase(mirrorType, mirrorFormat,
                                                        index)))
        return -1;

    if (mirrorType) {
        if (!(mirrorNode = virXPathNode("./source", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror requires source element"));
            return -1;
        }

        if (virDomainStorageSourceParse(mirrorNode, ctxt, def->mirror, flags,
                                        xmlopt) < 0)
            return -1;
        if (virDomainDiskBackingStoreParse(ctxt, def->mirror, flags, xmlopt) < 0)
            return -1;
    } else {
        /* For back-compat reasons, we handle a file name encoded as
         * attributes, even though we prefer modern output in the style of
         * backingStore */
        if (!(def->mirror->path = virXMLPropString(cur, "file"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("mirror requires file name"));
            return -1;
        }
    }

    if ((ready = virXMLPropString(cur, "ready")) &&
        (def->mirrorState = virDomainDiskMirrorStateTypeFromString(ready)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown mirror ready state %1$s"), ready);
        return -1;
    }

    if (virParseScaledValue("./format/metadata_cache/max_size", NULL,
                            ctxt,
                            &def->mirror->metadataCacheMaxSize,
                            1, ULLONG_MAX, false) < 0)
        return -1;

    return 0;
}


static int
virDomainDiskDefGeometryParse(virDomainDiskDef *def,
                              xmlNodePtr cur)
{
    if (virXMLPropUInt(cur, "cyls", 10, VIR_XML_PROP_NONE,
                       &def->geometry.cylinders) < 0)
        return -1;

    if (virXMLPropUInt(cur, "heads", 10, VIR_XML_PROP_NONE,
                       &def->geometry.heads) < 0)
        return -1;

    if (virXMLPropUInt(cur, "secs", 10, VIR_XML_PROP_NONE,
                       &def->geometry.sectors) < 0)
        return -1;

    if (virXMLPropEnum(cur, "trans", virDomainDiskGeometryTransTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->geometry.trans) < 0)
        return -1;

    return 0;
}


static int
virDomainDiskDefDriverParseXML(virDomainDiskDef *def,
                               xmlNodePtr cur)
{
    def->driverName = virXMLPropString(cur, "name");

    if (virXMLPropEnum(cur, "cache", virDomainDiskCacheTypeFromString,
                       VIR_XML_PROP_NONE, &def->cachemode) < 0)
        return -1;

    if (virXMLPropEnum(cur, "error_policy",
                       virDomainDiskErrorPolicyTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->error_policy) < 0)
        return -1;

    if (virXMLPropEnum(cur, "rerror_policy",
                       virDomainDiskErrorPolicyTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->rerror_policy) < 0)
        return -1;

    if (def->rerror_policy == VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid disk read error policy: '%1$s'"),
                       virDomainDiskErrorPolicyTypeToString(def->rerror_policy));
        return -1;
    }

    if (virXMLPropEnum(cur, "io", virDomainDiskIoTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->iomode) < 0)
        return -1;

    if (virXMLPropTristateSwitch(cur, "ioeventfd", VIR_XML_PROP_NONE,
                                 &def->ioeventfd) < 0)
        return -1;

    if (virXMLPropTristateSwitch(cur, "event_idx", VIR_XML_PROP_NONE,
                                 &def->event_idx) < 0)
        return -1;

    if (virXMLPropTristateSwitch(cur, "copy_on_read", VIR_XML_PROP_NONE,
                                 &def->copy_on_read) < 0)
        return -1;

    if (virXMLPropEnum(cur, "discard", virDomainDiskDiscardTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->discard) < 0)
        return -1;

    if (virXMLPropUInt(cur, "iothread", 10, VIR_XML_PROP_NONZERO, &def->iothread) < 0)
        return -1;

    if (virXMLPropEnum(cur, "detect_zeroes",
                       virDomainDiskDetectZeroesTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->detect_zeroes) < 0)
        return -1;

    if (virXMLPropUInt(cur, "queues", 10, VIR_XML_PROP_NONE, &def->queues) < 0)
        return -1;

    if (virXMLPropUInt(cur, "queue_size", 10, VIR_XML_PROP_NONE, &def->queue_size) < 0)
        return -1;

    if (virXMLPropTristateSwitch(cur, "discard_no_unref", VIR_XML_PROP_NONE,
                                 &def->discard_no_unref) < 0)
        return -1;

    return 0;
}


static int
virDomainDiskDefDriverSourceParseXML(virStorageSource *src,
                                     xmlNodePtr cur,
                                     xmlXPathContextPtr ctxt)
{
    g_autofree char *tmp = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = cur;

    if ((tmp = virXMLPropString(cur, "type"))) {
        if (STREQ(tmp, "aio")) {
            /* Xen back-compat */
            src->format = VIR_STORAGE_FILE_RAW;
        } else {
            if ((src->format = virStorageFileFormatTypeFromString(tmp)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown driver format value '%1$s'"), tmp);
                return -1;
            }
        }
    }

    if (virParseScaledValue("./metadata_cache/max_size", NULL,
                            ctxt,
                            &src->metadataCacheMaxSize,
                            1, ULLONG_MAX, false) < 0)
        return -1;

    return 0;
}


static int
virDomainDiskDefParsePrivateData(xmlXPathContextPtr ctxt,
                                 virDomainDiskDef *disk,
                                 virDomainXMLOption *xmlopt)
{
    xmlNodePtr private_node = virXPathNode("./privateData", ctxt);
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    if (!xmlopt ||
        !xmlopt->privateData.diskParse ||
        !private_node)
        return 0;

    ctxt->node = private_node;

    if (xmlopt->privateData.diskParse(ctxt, disk) < 0)
        return -1;

    return 0;
}


static virStorageSource *
virDomainDiskDefParseSourceXML(virDomainXMLOption *xmlopt,
                               xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    g_autoptr(virStorageSource) src = virStorageSourceNew();
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr tmp;

    ctxt->node = node;

    if (virXMLPropEnumDefault(node, "type",
                              virStorageTypeFromString,
                              VIR_XML_PROP_NONZERO,
                              &src->type,
                              VIR_STORAGE_TYPE_FILE) < 0)
        return NULL;

    if ((tmp = virXPathNode("./source[1]", ctxt))) {
        if (virDomainStorageSourceParse(tmp, ctxt, src, flags, xmlopt) < 0)
            return NULL;

        if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
            g_autofree char *sourceindex = NULL;

            if ((sourceindex = virXMLPropString(tmp, "index")) &&
                virStrToLong_uip(sourceindex, NULL, 10, &src->id) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid disk index '%1$s'"), sourceindex);
                return NULL;
            }
        }
    } else {
        /* Reset src->type in case when 'source' was not present */
        src->type = VIR_STORAGE_TYPE_FILE;
    }

    if (virXPathNode("./readonly[1]", ctxt))
        src->readonly = true;

    if (virXPathNode("./shareable[1]", ctxt))
        src->shared = true;

    if ((tmp = virXPathNode("./auth", ctxt))) {
        /* If we've already parsed <source> and found an <auth> child,
         * then generate an error to avoid ambiguity */
        if (src->auth) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("an <auth> definition already found for disk source"));
            return NULL;
        }

        if (!(src->auth = virStorageAuthDefParse(tmp, ctxt)))
            return NULL;
    }

    if ((tmp = virXPathNode("./encryption", ctxt))) {
        /* If we've already parsed <source> and found an <encryption> child,
         * then generate an error to avoid ambiguity */
        if (src->encryption) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("an <encryption> definition already found for disk source"));
            return NULL;
        }

        if (!(src->encryption = virStorageEncryptionParseNode(tmp, ctxt)))
            return NULL;
    }

    if (virDomainDiskBackingStoreParse(ctxt, src, flags, xmlopt) < 0)
        return NULL;

    return g_steal_pointer(&src);
}


static virDomainDiskDef *
virDomainDiskDefParseXML(virDomainXMLOption *xmlopt,
                         xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         unsigned int flags)
{
    g_autoptr(virDomainDiskDef) def = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr sourceNode;
    xmlNodePtr targetNode;
    xmlNodePtr geometryNode;
    xmlNodePtr blockioNode;
    xmlNodePtr driverNode;
    xmlNodePtr mirrorNode;
    xmlNodePtr transientNode;
    g_autoptr(virStorageSource) src = NULL;

    if (!(src = virDomainDiskDefParseSourceXML(xmlopt, node, ctxt, flags)))
        return NULL;

    if (!(def = virDomainDiskDefNewSource(xmlopt, &src)))
        return NULL;

    ctxt->node = node;

    if (virXMLPropEnumDefault(node, "device", virDomainDiskDeviceTypeFromString,
                              VIR_XML_PROP_NONE, &def->device,
                              VIR_DOMAIN_DISK_DEVICE_DISK) < 0)
        return NULL;

    if (virXMLPropEnum(node, "model", virDomainDiskModelTypeFromString,
                       VIR_XML_PROP_NONE, &def->model) < 0)
        return NULL;

    if (virXMLPropEnum(node, "snapshot", virDomainSnapshotLocationTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->snapshot) < 0)
        return NULL;

    if (virXMLPropTristateBool(node, "rawio", VIR_XML_PROP_NONE, &def->rawio) < 0)
        return NULL;

    if (virXMLPropEnum(node, "sgio", virDomainDeviceSGIOTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->sgio) < 0)
        return NULL;

    if ((sourceNode = virXPathNode("./source", ctxt))) {
        if (virXMLPropEnum(sourceNode, "startupPolicy",
                           virDomainStartupPolicyTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->startupPolicy) < 0)
            return NULL;
    }

    if ((targetNode = virXPathNode("./target", ctxt))) {
        def->dst = virXMLPropString(targetNode, "dev");

        if (virXMLPropEnum(targetNode, "bus",
                           virDomainDiskBusTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->bus) < 0)
            return NULL;

        if (virXMLPropEnum(targetNode, "tray", virDomainDiskTrayTypeFromString,
                           VIR_XML_PROP_NONE, &def->tray_status) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(targetNode, "removable", VIR_XML_PROP_NONE,
                                     &def->removable) < 0)
            return NULL;

        if (virXMLPropUInt(targetNode, "rotation_rate", 10, VIR_XML_PROP_NONE,
                           &def->rotation_rate) < 0)
            return NULL;
    }

    if ((geometryNode = virXPathNode("./geometry", ctxt))) {
        if (virDomainDiskDefGeometryParse(def, geometryNode) < 0)
            return NULL;
    }

    if ((blockioNode = virXPathNode("./blockio", ctxt))) {
        if (virXMLPropUInt(blockioNode, "logical_block_size", 10, VIR_XML_PROP_NONE,
                           &def->blockio.logical_block_size) < 0)
            return NULL;

        if (virXMLPropUInt(blockioNode, "physical_block_size", 10, VIR_XML_PROP_NONE,
                           &def->blockio.physical_block_size) < 0)
            return NULL;

        if (virXMLPropUInt(blockioNode, "discard_granularity", 10, VIR_XML_PROP_NONE,
                           &def->blockio.discard_granularity) < 0)
            return NULL;
    }

    if ((driverNode = virXPathNode("./driver", ctxt))) {
        if (virDomainVirtioOptionsParseXML(driverNode, &def->virtio) < 0)
            return NULL;

        if (virDomainDiskDefDriverParseXML(def, driverNode) < 0)
            return NULL;

        if (virDomainDiskDefDriverSourceParseXML(def->src, driverNode, ctxt) < 0)
            return NULL;
    }

    if ((mirrorNode = virXPathNode("./mirror", ctxt))) {
        if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
            if (virDomainDiskDefMirrorParse(def, mirrorNode, ctxt, flags, xmlopt) < 0)
                return NULL;
        }
    }

    if (virXPathNode("./auth", ctxt))
        def->diskElementAuth = true;

    if (virXPathNode("./encryption", ctxt))
        def->diskElementEnc = true;

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        xmlNodePtr diskSecretsPlacementNode;

        if ((diskSecretsPlacementNode = virXPathNode("./diskSecretsPlacement", ctxt))) {
            g_autofree char *secretAuth = virXMLPropString(diskSecretsPlacementNode, "auth");
            g_autofree char *secretEnc = virXMLPropString(diskSecretsPlacementNode, "enc");

            def->diskElementAuth = !!secretAuth;
            def->diskElementEnc = !!secretEnc;
        }
    }

    if ((transientNode = virXPathNode("./transient", ctxt))) {
        def->transient = true;

        if (virXMLPropTristateBool(transientNode, "shareBacking",
                                   VIR_XML_PROP_NONE,
                                   &def->transientShareBacking) < 0)
            return NULL;
    }

    if (virDomainDiskDefIotuneParse(def, ctxt) < 0)
        return NULL;

    def->domain_name = virXPathString("string(./backenddomain/@name)", ctxt);
    def->serial = virXPathString("string(./serial)", ctxt);
    def->wwn = virXPathString("string(./wwn)", ctxt);
    def->vendor = virXPathString("string(./vendor)", ctxt);
    def->product = virXPathString("string(./product)", ctxt);

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info,
                                    flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) < 0) {
        return NULL;
    }

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        virDomainDiskDefParsePrivateData(ctxt, def, xmlopt) < 0)
        return NULL;

    return g_steal_pointer(&def);
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

    if (virParseScaledValue(xpath, units_xpath, ctxt,
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

    ret = virParseScaledValue(xpath, units_xpath, ctxt, &bytes, 1024,
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
virDomainDefSetMemoryTotal(virDomainDef *def,
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
    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        return virDomainControllerModelSCSITypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        return virDomainControllerModelUSBTypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        return virDomainControllerModelPCITypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
        return virDomainControllerModelIDETypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        return virDomainControllerModelVirtioSerialTypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
        return virDomainControllerModelISATypeFromString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        return -1;
    }
    return -1;
}


static const char *
virDomainControllerModelTypeToString(virDomainControllerDef *def,
                                     int model)
{
    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        return virDomainControllerModelSCSITypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        return virDomainControllerModelUSBTypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        return virDomainControllerModelPCITypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
        return virDomainControllerModelIDETypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        return virDomainControllerModelVirtioSerialTypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
        return virDomainControllerModelISATypeToString(model);
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        return NULL;
    }
    return NULL;
}


static virDomainControllerDef *
virDomainControllerDefParseXML(virDomainXMLOption *xmlopt,
                               xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    g_autoptr(virDomainControllerDef) def = NULL;
    virDomainControllerType type = VIR_DOMAIN_CONTROLLER_TYPE_IDE;
    xmlNodePtr driver = NULL;
    g_autofree xmlNodePtr *targetNodes = NULL;
    int ntargetNodes = 0;
    g_autofree xmlNodePtr *modelNodes = NULL;
    int nmodelNodes = 0;
    int numaNode = -1;
    int ports;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int rc;
    g_autofree char *model = NULL;

    ctxt->node = node;

    if (virXMLPropEnum(node, "type", virDomainControllerTypeFromString,
                       VIR_XML_PROP_NONE, &type) < 0)
        return NULL;

    if (!(def = virDomainControllerDefNew(type)))
        return NULL;

    if ((model = virXMLPropString(node, "model"))) {
        if ((def->model = virDomainControllerModelTypeFromString(def, model)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown model type '%1$s'"), model);
            return NULL;
        }
    }

    if (virXMLPropInt(node, "index", 10, VIR_XML_PROP_NONNEGATIVE,
                      &def->idx, def->idx) < 0)
        return NULL;

    if ((driver = virXPathNode("./driver", ctxt))) {
        if (virXMLPropUInt(driver, "queues", 10, VIR_XML_PROP_NONE,
                           &def->queues) < 0)
            return NULL;

        if (virXMLPropUInt(driver, "cmd_per_lun", 10, VIR_XML_PROP_NONE,
                           &def->cmd_per_lun) < 0)
            return NULL;

        if (virXMLPropUInt(driver, "max_sectors", 10, VIR_XML_PROP_NONE,
                           &def->max_sectors) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(driver, "ioeventfd",
                                     VIR_XML_PROP_NONE,
                                     &def->ioeventfd) < 0)
            return NULL;

        if (virXMLPropUInt(driver, "iothread", 10, VIR_XML_PROP_NONE,
                           &def->iothread) < 0)
            return NULL;

        if (virDomainVirtioOptionsParseXML(driver, &def->virtio) < 0)
            return NULL;
    }

    if ((nmodelNodes = virXPathNodeSet("./model", ctxt, &modelNodes)) > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Multiple <model> elements in controller definition not allowed"));
        return NULL;
    }

    if (nmodelNodes == 1) {
        if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if (virXMLPropEnum(modelNodes[0], "name",
                               virDomainControllerPCIModelNameTypeFromString,
                               VIR_XML_PROP_NONE,
                               &def->opts.pciopts.modelName) < 0)
                return NULL;
        }
    }

    if ((ntargetNodes = virXPathNodeSet("./target", ctxt, &targetNodes)) > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Multiple <target> elements in controller definition not allowed"));
        return NULL;
    }

    if (ntargetNodes == 1) {
        if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if (virXMLPropInt(targetNodes[0], "chassisNr", 0, VIR_XML_PROP_NONNEGATIVE,
                              &def->opts.pciopts.chassisNr,
                              def->opts.pciopts.chassisNr) < 0)
                return NULL;

            if (virXMLPropInt(targetNodes[0], "chassis", 0, VIR_XML_PROP_NONNEGATIVE,
                              &def->opts.pciopts.chassis,
                              def->opts.pciopts.chassis) < 0)
                return NULL;

            if (virXMLPropInt(targetNodes[0], "port", 0, VIR_XML_PROP_NONNEGATIVE,
                              &def->opts.pciopts.port,
                              def->opts.pciopts.port) < 0)
                return NULL;

            if (virXMLPropInt(targetNodes[0], "busNr", 0, VIR_XML_PROP_NONNEGATIVE,
                              &def->opts.pciopts.busNr,
                              def->opts.pciopts.busNr) < 0)
                return NULL;

            if (virXMLPropTristateSwitch(targetNodes[0], "hotplug",
                                         VIR_XML_PROP_NONE,
                                         &def->opts.pciopts.hotplug) < 0)
                return NULL;

            if (virXMLPropInt(targetNodes[0], "index", 0, VIR_XML_PROP_NONNEGATIVE,
                              &def->opts.pciopts.targetIndex,
                              def->opts.pciopts.targetIndex) < 0)
                return NULL;
        }
    }

    /* node is parsed differently from target attributes because
     * someone thought it should be a subelement instead...
     */
    rc = virXPathInt("string(./target/node)", ctxt, &numaNode);
    if (rc == -2 || (rc == 0 && numaNode < 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid NUMA node in target"));
        return NULL;
    }

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
        def->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
        VIR_DEBUG("Ignoring device address for none model usb controller");
    } else if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt,
                                           &def->info, flags) < 0) {
        return NULL;
    }

    if (virXMLPropInt(node, "ports", 10, VIR_XML_PROP_NONNEGATIVE, &ports, -1) < 0)
        return NULL;

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL: {
        if (virXMLPropInt(node, "vectors", 10, VIR_XML_PROP_NONNEGATIVE,
                          &def->opts.vioserial.vectors,
                          def->opts.vioserial.vectors) < 0)
            return NULL;

        def->opts.vioserial.ports = ports;
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
            if ((rc = virParseScaledValue("./pcihole64", NULL,
                                          ctxt, &bytes, 1024,
                                          1024ULL * ULONG_MAX, false)) < 0)
                return NULL;

            if (rc == 1)
                def->opts.pciopts.pcihole64 = true;
            def->opts.pciopts.pcihole64size = VIR_DIV_UP(bytes, 1024);
        }
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
            /* Other controller models don't require extra checks */
            break;
        }

        if (numaNode >= 0)
            def->opts.pciopts.numaNode = numaNode;

        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS: {
        if (virXMLPropInt(node, "maxGrantFrames", 10, VIR_XML_PROP_NONNEGATIVE,
                          &def->opts.xenbusopts.maxGrantFrames,
                          def->opts.xenbusopts.maxGrantFrames) < 0)
            return NULL;

        if (virXMLPropInt(node, "maxEventChannels", 10, VIR_XML_PROP_NONNEGATIVE,
                          &def->opts.xenbusopts.maxEventChannels,
                          def->opts.xenbusopts.maxEventChannels) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
    default:
        break;
    }

    return g_steal_pointer(&def);
}


void
virDomainNetGenerateMAC(virDomainXMLOption *xmlopt,
                        virMacAddr *mac)
{
    virMacAddrGenerate(xmlopt->config.macPrefix, mac);
}


static virDomainFSDef *
virDomainFSDefParseXML(virDomainXMLOption *xmlopt,
                       xmlNodePtr node,
                       xmlXPathContextPtr ctxt,
                       unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainFSDef *def;
    xmlNodePtr driver_node = NULL;
    xmlNodePtr source_node = NULL;
    g_autofree char *source = NULL;
    g_autofree char *target = NULL;
    g_autofree char *format = NULL;
    g_autofree char *usage = NULL;
    g_autofree char *units = NULL;
    g_autofree char *sock = NULL;
    int rv;

    ctxt->node = node;

    if (!(def = virDomainFSDefNew(xmlopt)))
        return NULL;

    if (virXMLPropEnum(node, "type",
                       virDomainFSTypeFromString,
                       VIR_XML_PROP_NONE,
                       &def->type) < 0)
        goto error;

    if (virXMLPropEnum(node, "accessmode",
                             virDomainFSAccessModeTypeFromString,
                             VIR_XML_PROP_NONE,
                             &def->accessmode) < 0)
        goto error;

    if ((rv = virXMLPropUInt(node, "fmode", 8,
                             VIR_XML_PROP_NONE,
                             &def->fmode)) < 0) {
        goto error;
    } else if (rv > 0) {
        if (def->fmode > 0777) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid fmode: '0%1$o'"), def->fmode);
            goto error;
        }
    }

    if ((rv = virXMLPropUInt(node, "dmode", 8,
                             VIR_XML_PROP_NONE,
                             &def->dmode)) < 0) {
        goto error;
    } else if (rv > 0) {
        if (def->dmode > 0777) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid dmode: '0%1$o'"), def->dmode);
            goto error;
        }
    }

    if (virXMLPropEnum(node, "model",
                       virDomainFSModelTypeFromString,
                       VIR_XML_PROP_NONZERO,
                       &def->model) < 0)
        goto error;

    if (virXMLPropEnum(node, "multidevs",
                       virDomainFSMultidevsTypeFromString,
                       VIR_XML_PROP_NONE,
                       &def->multidevs) < 0)
        goto error;

    if (virParseScaledValue("./space_hard_limit[1]",
                            NULL, ctxt, &def->space_hard_limit,
                            1, ULLONG_MAX, false) < 0)
        goto error;

    if (virParseScaledValue("./space_soft_limit[1]",
                            NULL, ctxt, &def->space_soft_limit,
                            1, ULLONG_MAX, false) < 0)
        goto error;

    if ((source_node = virXPathNode("./source", ctxt))) {
        sock = virXMLPropString(source_node, "socket");
        if (def->type == VIR_DOMAIN_FS_TYPE_MOUNT ||
            def->type == VIR_DOMAIN_FS_TYPE_BIND) {
            source = virXMLPropString(source_node, "dir");
        } else if (def->type == VIR_DOMAIN_FS_TYPE_FILE) {
            source = virXMLPropString(source_node, "file");
        } else if (def->type == VIR_DOMAIN_FS_TYPE_BLOCK) {
            source = virXMLPropString(source_node, "dev");
        } else if (def->type == VIR_DOMAIN_FS_TYPE_TEMPLATE) {
            source = virXMLPropString(source_node, "name");
        } else if (def->type == VIR_DOMAIN_FS_TYPE_RAM) {
            usage = virXMLPropString(source_node, "usage");
            units = virXMLPropString(source_node, "units");
        } else if (def->type == VIR_DOMAIN_FS_TYPE_VOLUME) {
            def->src->type = VIR_STORAGE_TYPE_VOLUME;
            if (!(def->src->srcpool = virDomainDiskSourcePoolDefParse(source_node, flags)))
                goto error;
        }
    }

    target = virXPathString("string(./target/@dir)", ctxt);

    if (virXPathNode("./readonly", ctxt))
        def->readonly = true;

    if ((driver_node = virXPathNode("./driver", ctxt))) {
        if (virXMLPropEnum(driver_node, "type",
                           virDomainFSDriverTypeFromString,
                           VIR_XML_PROP_NONE, &def->fsdriver) < 0)
            goto error;

        if (virXMLPropEnum(driver_node, "wrpolicy",
                           virDomainFSWrpolicyTypeFromString,
                           VIR_XML_PROP_NONE, &def->wrpolicy) < 0)
            goto error;

        if ((format = virXMLPropString(driver_node, "format")) &&
            ((def->format = virStorageFileFormatTypeFromString(format)) <= 0)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown driver format value '%1$s'"), format);
            goto error;
        }

        if (virDomainVirtioOptionsParseXML(driver_node, &def->virtio) < 0)
            goto error;
    }

    if (def->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        g_autofree char *queue_size = virXPathString("string(./driver/@queue)", ctxt);
        g_autofree char *binary = virXPathString("string(./binary/@path)", ctxt);
        g_autofree char *thread_pool_size = virXPathString("string(./binary/thread_pool/@size)", ctxt);
        xmlNodePtr binary_node = virXPathNode("./binary", ctxt);
        xmlNodePtr binary_lock_node = virXPathNode("./binary/lock", ctxt);
        xmlNodePtr binary_cache_node = virXPathNode("./binary/cache", ctxt);
        xmlNodePtr binary_sandbox_node = virXPathNode("./binary/sandbox", ctxt);

        if (queue_size && virStrToLong_ull(queue_size, NULL, 10, &def->queue_size) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse queue size '%1$s' for virtiofs"),
                           queue_size);
            goto error;
        }

        if (thread_pool_size &&
            virStrToLong_i(thread_pool_size, NULL, 10, &def->thread_pool_size) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("cannot parse thread pool size '%1$s' for virtiofs"),
                           thread_pool_size);
            goto error;
        }

        if (binary)
            def->binary = virFileSanitizePath(binary);

        if (virXMLPropTristateSwitch(binary_node, "xattr",
                                     VIR_XML_PROP_NONE,
                                     &def->xattr) < 0)
            goto error;

        if (virXMLPropTristateSwitch(binary_lock_node, "posix",
                                     VIR_XML_PROP_NONE,
                                     &def->posix_lock) < 0)
            goto error;

        if (virXMLPropTristateSwitch(binary_lock_node, "flock",
                                     VIR_XML_PROP_NONE,
                                     &def->flock) < 0)
            goto error;

        if (virXMLPropEnum(binary_cache_node, "mode",
                           virDomainFSCacheModeTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->cache) < 0)
            goto error;

        if (virXMLPropEnum(binary_sandbox_node, "mode",
                           virDomainFSSandboxModeTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->sandbox) < 0)
            goto error;
    }

    if (source == NULL && def->type != VIR_DOMAIN_FS_TYPE_RAM
        && def->type != VIR_DOMAIN_FS_TYPE_VOLUME && !sock) {
        virReportError(VIR_ERR_NO_SOURCE,
                       target ? "%s" : NULL, target);
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
                           _("cannot parse usage '%1$s' for RAM filesystem"),
                           usage);
            goto error;
        }
        if (virScaleInteger(&def->usage, units,
                            1024, ULLONG_MAX) < 0)
            goto error;
    }

    def->src->path = g_steal_pointer(&source);
    def->sock = g_steal_pointer(&sock);
    def->dst = g_steal_pointer(&target);

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info,
                                    flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) < 0)
        goto error;

    return def;

 error:
    virDomainFSDefFree(def);
    return NULL;
}

static int
virDomainActualNetDefParseXML(xmlNodePtr node,
                              xmlXPathContextPtr ctxt,
                              virDomainNetDef *parent,
                              virDomainActualNetDef **def,
                              unsigned int flags,
                              virDomainXMLOption *xmlopt)
{
    virDomainActualNetDef *actual = NULL;
    int ret = -1;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr bandwidth_node = NULL;
    xmlNodePtr vlanNode;
    xmlNodePtr virtPortNode;
    g_autofree char *addrtype = NULL;
    g_autofree char *macTableManager = NULL;

    actual = g_new0(virDomainActualNetDef, 1);

    ctxt->node = node;

    if (virXMLPropEnum(node, "type", virDomainNetTypeFromString,
                       VIR_XML_PROP_REQUIRED, &actual->type) < 0)
        goto error;

    if (actual->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        actual->type != VIR_DOMAIN_NET_TYPE_DIRECT &&
        actual->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        actual->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported type '%1$s' in interface's <actual> element"),
                       virDomainNetTypeToString(actual->type));
        goto error;
    }

    if (virXMLPropTristateBool(node, "trustGuestRxFilters", VIR_XML_PROP_NONE,
                               &actual->trustGuestRxFilters) < 0)
        goto error;

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
                           _("<virtualport> element unsupported for type='%1$s' in interface's <actual> element"),
                             virDomainNetTypeToString(actual->type));
            goto error;
        }
    }

    if (actual->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        xmlNodePtr sourceNode = virXPathNode("./source[1]", ctxt);

        if (sourceNode) {
            int rc;
            virNetDevMacVLanMode mode;

            actual->data.direct.linkdev = virXMLPropString(sourceNode, "dev");

            if ((rc = virXMLPropEnum(sourceNode, "mode",
                                     virNetDevMacVLanModeTypeFromString,
                                     VIR_XML_PROP_NONE, &mode)) < 0)
                goto error;

            if (rc == 1)
                actual->data.direct.mode = mode;
        }
    } else if (actual->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virDomainHostdevDef *hostdev = &actual->data.hostdev.def;
        int type;

        hostdev->parentnet = parent;
        hostdev->info = &parent->info;
        /* The helper function expects type to already be found and
         * passed in as a string, since it is in a different place in
         * NetDef vs HostdevDef.
         */
        addrtype = virXPathString("string(./source/address/@type)", ctxt);
        /* if not explicitly stated, source/vendor implies usb device */
        if (!addrtype && virXPathNode("./source/vendor", ctxt))
            addrtype = g_strdup("usb");

        if ((type = virDomainHostdevSubsysTypeFromString(addrtype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown host device source address type '%1$s'"),
                           addrtype);
            goto error;
        }

        hostdev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, type,
                                              hostdev, flags, xmlopt) < 0) {
            goto error;
        }
    } else if (actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
               actual->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        g_autofree char *class_id = NULL;
        xmlNodePtr sourceNode;

        class_id = virXPathString("string(./class/@id)", ctxt);
        if (class_id &&
            virStrToLong_ui(class_id, NULL, 10, &actual->class_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse class id '%1$s'"),
                           class_id);
            goto error;
        }

        sourceNode = virXPathNode("./source", ctxt);
        if (sourceNode) {
            char *brname = virXMLPropString(sourceNode, "bridge");

            if (!brname && actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Missing <source> element with bridge name in interface's <actual> element"));
                goto error;
            }
            actual->data.bridge.brname = brname;
            macTableManager = virXMLPropString(sourceNode, "macTableManager");
            if (macTableManager &&
                (actual->data.bridge.macTableManager
                 = virNetworkBridgeMACTableManagerTypeFromString(macTableManager)) <= 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid macTableManager setting '%1$s' in domain interface's <actual> element"),
                               macTableManager);
                goto error;
            }
        }
    }

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        virNetDevBandwidthParse(&actual->bandwidth,
                                NULL,
                                bandwidth_node,
                                actual->type == VIR_DOMAIN_NET_TYPE_NETWORK) < 0)
        goto error;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &actual->vlan) < 0)
        goto error;

    if (virNetworkPortOptionsParseXML(ctxt, &actual->isolatedPort) < 0)
        goto error;

    *def = g_steal_pointer(&actual);
    ret = 0;
 error:
    virDomainActualNetDefFree(actual);

    return ret;
}

#define NET_MODEL_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"


int
virDomainNetAppendIPAddress(virDomainNetDef *def,
                            const char *address,
                            int family,
                            unsigned int prefix)
{
    virNetDevIPAddr *ipDef = NULL;
    ipDef = g_new0(virNetDevIPAddr, 1);

    if (virSocketAddrParse(&ipDef->address, address, family) < 0)
        goto error;
    ipDef->prefix = prefix;

    VIR_APPEND_ELEMENT(def->guestIP.ips, def->guestIP.nips, ipDef);

    return 0;

 error:
    VIR_FREE(ipDef);
    return -1;
}


static int
virDomainNetTeamingInfoParseXML(xmlXPathContextPtr ctxt,
                                virDomainNetTeamingInfo **teaming)
{
    g_autofree char *typeStr = virXPathString("string(./teaming/@type)", ctxt);
    g_autofree char *persistentStr = virXPathString("string(./teaming/@persistent)", ctxt);
    g_autoptr(virDomainNetTeamingInfo) tmpTeaming = NULL;
    int tmpType;

    if (!typeStr && !persistentStr)
        return 0;

    tmpTeaming = g_new0(virDomainNetTeamingInfo, 1);

    if ((tmpType = virDomainNetTeamingTypeFromString(typeStr)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown teaming type '%1$s'"),
                           typeStr);
            return -1;
    }

    tmpTeaming->type = tmpType;
    tmpTeaming->persistent = g_steal_pointer(&persistentStr);
    *teaming = g_steal_pointer(&tmpTeaming);
    return 0;
}


static int
virDomainNetDefParseXMLDriver(virDomainNetDef *def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr driver_node;

    if (!(driver_node = virXPathNode("./driver", ctxt)))
        return 0;

    if (virDomainVirtioOptionsParseXML(driver_node, &def->virtio) < 0)
        return -1;

    if (def->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        virDomainNetIsVirtioModel(def)) {
        xmlNodePtr hostNode;
        xmlNodePtr guestNode;

        if (virXMLPropEnum(driver_node, "name",
                           virDomainNetDriverTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->driver.virtio.name) < 0)
            return -1;

        if (virXMLPropEnum(driver_node, "txmode",
                           virDomainNetVirtioTxModeTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->driver.virtio.txmode) < 0)
            return -1;

        if (virXMLPropTristateSwitch(driver_node, "ioeventfd",
                                     VIR_XML_PROP_NONE,
                                     &def->driver.virtio.ioeventfd) < 0)
            return -1;

        if (virXMLPropTristateSwitch(driver_node, "event_idx",
                                     VIR_XML_PROP_NONE,
                                     &def->driver.virtio.event_idx) < 0)
            return -1;

        if (virXMLPropUInt(driver_node, "queues", 10,
                           VIR_XML_PROP_NONE,
                           &def->driver.virtio.queues) < 0)
            return -1;

        /* There's always at least one TX/RX queue. */
        if (def->driver.virtio.queues == 1)
            def->driver.virtio.queues = 0;

        if (virXMLPropUInt(driver_node, "rx_queue_size", 10,
                           VIR_XML_PROP_NONE,
                           &def->driver.virtio.rx_queue_size) < 0)
            return -1;

        if (virXMLPropUInt(driver_node, "tx_queue_size", 10,
                           VIR_XML_PROP_NONE,
                           &def->driver.virtio.tx_queue_size) < 0)
            return -1;

        if (virXMLPropTristateSwitch(driver_node, "rss",
                                     VIR_XML_PROP_NONE,
                                     &def->driver.virtio.rss) < 0)
            return -1;

        if (virXMLPropTristateSwitch(driver_node, "rss_hash_report",
                                     VIR_XML_PROP_NONE,
                                     &def->driver.virtio.rss_hash_report) < 0)
            return -1;

        if ((hostNode = virXPathNode("./driver/host", ctxt))) {
            if (virXMLPropTristateSwitch(hostNode, "csum", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.csum) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "gso", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.gso) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "tso4", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.tso4) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "tso6", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.tso6) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "ecn", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.ecn) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "ufo", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.ufo) < 0)
                return -1;

            if (virXMLPropTristateSwitch(hostNode, "mrg_rxbuf",
                                         VIR_XML_PROP_NONE,
                                         &def->driver.virtio.host.mrg_rxbuf) < 0)
                return -1;
        }

        if ((guestNode = virXPathNode("./driver/guest", ctxt))) {
            if (virXMLPropTristateSwitch(guestNode, "csum", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.guest.csum) < 0)
                return -1;

            if (virXMLPropTristateSwitch(guestNode, "tso4", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.guest.tso4) < 0)
                return -1;

            if (virXMLPropTristateSwitch(guestNode, "tso6", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.guest.tso6) < 0)
                return -1;

            if (virXMLPropTristateSwitch(guestNode, "ecn", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.guest.ecn) < 0)
                return -1;

            if (virXMLPropTristateSwitch(guestNode, "ufo", VIR_XML_PROP_NONE,
                                         &def->driver.virtio.guest.ufo) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virDomainNetBackendParseXML(xmlNodePtr node,
                            virDomainNetDef *def)
{
    g_autofree char *tap = virXMLPropString(node, "tap");
    g_autofree char *vhost = virXMLPropString(node, "vhost");

    if (virXMLPropEnum(node, "type", virDomainNetBackendTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->backend.type) < 0) {
        return -1;
    }

    def->backend.logFile = virXMLPropString(node, "logFile");

    if (tap)
        def->backend.tap = virFileSanitizePath(tap);

    if (vhost &&
        def->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        virDomainNetIsVirtioModel(def)) {
        def->backend.vhost = virFileSanitizePath(vhost);
    }

    return 0;
}


static virDomainNetPortForwardRange *
virDomainNetPortForwardRangeParseXML(xmlNodePtr node,
                                     xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree virDomainNetPortForwardRange *def = g_new0(virDomainNetPortForwardRange, 1);

    ctxt->node = node;

    if (virXMLPropUInt(node, "start", 10,
                       VIR_XML_PROP_NONZERO, &def->start) < 0) {
        return NULL;
    }
    if (virXMLPropUInt(node, "end", 10,
                       VIR_XML_PROP_NONZERO, &def->end) < 0) {
        return NULL;
    }
    if (virXMLPropUInt(node, "to", 10,
                       VIR_XML_PROP_NONZERO, &def->to) < 0) {
        return NULL;
    }
    if (virXMLPropTristateBool(node, "exclude", VIR_XML_PROP_NONE,
                               &def->exclude) < 0) {
        return NULL;
    }

    return g_steal_pointer(&def);
}


static int
virDomainNetPortForwardRangesParseXML(virDomainNetPortForward *def,
                                      xmlXPathContextPtr ctxt)
{
    int nRanges;
    g_autofree xmlNodePtr *ranges = NULL;
    size_t i;

    if ((nRanges = virXPathNodeSet("./range", ctxt, &ranges)) <= 0)
        return nRanges;

    def->ranges = g_new0(virDomainNetPortForwardRange *, nRanges);

    for (i = 0; i < nRanges; i++) {
        g_autofree virDomainNetPortForwardRange *range = NULL;

        if (!(range = virDomainNetPortForwardRangeParseXML(ranges[i], ctxt)))
            return -1;

        def->ranges[def->nRanges++] = g_steal_pointer(&range);
    }
    return 0;
}


static virDomainNetPortForward *
virDomainNetPortForwardDefParseXML(xmlNodePtr node,
                                   xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *address = NULL;
    g_autoptr(virDomainNetPortForward) def = g_new0(virDomainNetPortForward, 1);

    ctxt->node = node;

    if (virXMLPropEnum(node, "proto", virDomainNetProtoTypeFromString,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &def->proto) < 0) {
        return NULL;
    }

    address = virXMLPropString(node, "address");
    if (address && virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid address '%1$s' in <portForward>"), address);
        return NULL;
    }

    def->dev = virXMLPropString(node, "dev");

    if (virDomainNetPortForwardRangesParseXML(def, ctxt) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static int
virDomainNetPortForwardsParseXML(virDomainNetDef *def,
                                 xmlXPathContextPtr ctxt)
{
    int nPortForwards;
    g_autofree xmlNodePtr *portForwards = NULL;
    size_t i;

    if ((nPortForwards = virXPathNodeSet("./portForward",
                                         ctxt, &portForwards)) <= 0) {
        return nPortForwards;
    }

    def->portForwards = g_new0(virDomainNetPortForward *, nPortForwards);

    for (i = 0; i < nPortForwards; i++) {
        g_autoptr(virDomainNetPortForward) pf = NULL;

        if (!(pf = virDomainNetPortForwardDefParseXML(portForwards[i], ctxt)))
            return -1;

        def->portForwards[def->nPortForwards++] = g_steal_pointer(&pf);
    }
    return 0;
}


static int
virDomainNetDefParseXMLRequireSource(virDomainNetDef *def,
                                     xmlNodePtr source_node)
{
    if (!source_node) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("interface type='%1$s' requires a 'source' element"),
                       virDomainNetTypeToString(def->type));
        return -1;
    }

    return 0;
}


static int
virDomainNetDefParsePrivateData(xmlXPathContextPtr ctxt,
                                virDomainNetDef *net,
                                virDomainXMLOption *xmlopt)
{
    xmlNodePtr private_node = virXPathNode("./privateData", ctxt);
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    if (!xmlopt ||
        !xmlopt->privateData.networkParse ||
        !private_node)
        return 0;

    ctxt->node = private_node;

    if (xmlopt->privateData.networkParse(ctxt, net) < 0)
        return -1;

    return 0;
}



static virDomainNetDef *
virDomainNetDefParseXML(virDomainXMLOption *xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    g_autoptr(virDomainNetDef) def = NULL;
    xmlNodePtr source_node = NULL;
    xmlNodePtr virtualport_node = NULL;
    xmlNodePtr vlan_node = NULL;
    xmlNodePtr bandwidth_node = NULL;
    xmlNodePtr mac_node = NULL;
    xmlNodePtr target_node = NULL;
    xmlNodePtr coalesce_node = NULL;
    xmlNodePtr backend_node = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int rv;
    g_autofree char *macaddr = NULL;
    g_autofree char *model = NULL;
    g_autofree char *linkstate = NULL;
    unsigned int virtualport_flags = 0;
    bool parse_filterref = false;
    const char *prefix = xmlopt ? xmlopt->config.netPrefix : NULL;

    if (!(def = virDomainNetDefNew(xmlopt)))
        return NULL;

    ctxt->node = node;

    if (virXMLPropEnumDefault(node, "type", virDomainNetTypeFromString,
                              VIR_XML_PROP_NONE, &def->type, VIR_DOMAIN_NET_TYPE_USER) < 0)
        return NULL;

    if (virXMLPropTristateBool(node, "trustGuestRxFilters", VIR_XML_PROP_NONE,
                               &def->trustGuestRxFilters) < 0)
        return NULL;

    if ((model = virXPathString("string(./model/@type)", ctxt)) &&
        virDomainNetSetModelString(def, model) < 0)
        return NULL;

    if ((source_node = virXPathNode("./source", ctxt))) {
        if (virDomainNetIPInfoParseXML(_("interface host IP"), source_node, ctxt, &def->hostIP) < 0)
            return NULL;
    }

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(def->data.network.name = virXMLPropStringRequired(source_node, "network")))
            return NULL;

        def->data.network.portgroup = virXMLPropString(source_node, "portgroup");

        if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
            if (virXMLPropUUID(source_node, "portid", VIR_XML_PROP_NONE,
                               def->data.network.portid) < 0)
                return NULL;
        }

        if ((flags & VIR_DOMAIN_DEF_PARSE_ACTUAL_NET)) {
            xmlNodePtr actual_node = NULL;

            if ((actual_node = virXPathNode("./actual", ctxt)) &&
                (virDomainActualNetDefParseXML(actual_node, ctxt, def,
                                               &def->data.network.actual,
                                               flags, xmlopt) < 0))
                return NULL;
        }

        virtualport_flags = VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS;
        parse_filterref = true;
        break;

    case VIR_DOMAIN_NET_TYPE_VDS:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (virXMLPropUUID(source_node, "switchid", VIR_XML_PROP_REQUIRED,
                           def->data.vds.switch_id) < 0)
            return NULL;

        if (virXMLPropLongLong(source_node, "portid", 0, VIR_XML_PROP_REQUIRED,
                               &def->data.vds.port_id, def->data.vds.port_id) < 0)
            return NULL;

        if (!(def->data.vds.portgroup_id = virXMLPropStringRequired(source_node, "portgroupid")))
            return NULL;

        if (virXMLPropLongLong(source_node, "connectionid", 0, VIR_XML_PROP_REQUIRED,
                               &def->data.vds.connection_id, def->data.vds.connection_id) < 0)
            return NULL;

        break;

    case VIR_DOMAIN_NET_TYPE_INTERNAL:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(def->data.internal.name = virXMLPropStringRequired(source_node, "name")))
            return NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(def->data.bridge.brname = virXMLPropStringRequired(source_node, "bridge")))
            return NULL;

        virtualport_flags = VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS |
                            VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES |
                            VIR_VPORT_XML_REQUIRE_TYPE;
        parse_filterref = true;
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(def->data.direct.linkdev = virXMLPropStringRequired(source_node, "dev")))
            return NULL;

        if (virXMLPropEnumDefault(source_node, "mode",
                                  virNetDevMacVLanModeTypeFromString,
                                  VIR_XML_PROP_NONE,
                                  &def->data.direct.mode,
                                  VIR_NETDEV_MACVLAN_MODE_VEPA) < 0)
            return NULL;

        virtualport_flags = VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS |
                            VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES |
                            VIR_VPORT_XML_REQUIRE_TYPE;
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        parse_filterref = true;
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER: {
        g_autofree char *vhostuser_type = NULL;
        virDomainNetVhostuserMode vhostuser_mode;

        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(vhostuser_type = virXMLPropStringRequired(source_node, "type")))
            return NULL;

        if (STRNEQ_NULLABLE(vhostuser_type, "unix")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Type='%1$s' unsupported for <interface type='vhostuser'>"),
                           vhostuser_type);
            return NULL;
        }

        if (!(def->data.vhostuser = virDomainChrSourceDefNew(xmlopt)))
            return NULL;

        def->data.vhostuser->type = VIR_DOMAIN_CHR_TYPE_UNIX;

        if (!(def->data.vhostuser->data.nix.path = virXMLPropStringRequired(source_node, "path")))
            return NULL;

        if (virXMLPropEnum(source_node, "mode",
                           virDomainNetVhostuserModeTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &vhostuser_mode) < 0)
            return NULL;

        switch (vhostuser_mode) {
        case VIR_DOMAIN_NET_VHOSTUSER_MODE_CLIENT:
            def->data.vhostuser->data.nix.listen = false;
            break;

        case VIR_DOMAIN_NET_VHOSTUSER_MODE_SERVER:
            def->data.vhostuser->data.nix.listen = true;
            break;

        case VIR_DOMAIN_NET_VHOSTUSER_MODE_NONE:
        case VIR_DOMAIN_NET_VHOSTUSER_MODE_LAST:
            break;
        }

        if (virDomainChrSourceReconnectDefParseXML(&def->data.vhostuser->data.nix.reconnect,
                                                   source_node, ctxt) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_NET_TYPE_VDPA:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (!(def->data.vdpa.devicepath = virXMLPropStringRequired(source_node, "dev")))
            return NULL;
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
        if (virDomainNetDefParseXMLRequireSource(def, source_node) < 0)
            return NULL;

        if (def->type != VIR_DOMAIN_NET_TYPE_SERVER) {
            if (!(def->data.socket.address = virXMLPropStringRequired(source_node, "address")))
                return NULL;
        } else {
            def->data.socket.address = virXMLPropString(source_node, "address");
        }

        if (virXMLPropInt(source_node, "port", 10, VIR_XML_PROP_REQUIRED,
                          &def->data.socket.port, def->data.socket.port) < 0)
            return NULL;

        if (def->type == VIR_DOMAIN_NET_TYPE_UDP) {
            VIR_XPATH_NODE_AUTORESTORE_NAME(localCtxt, ctxt)
            xmlNodePtr local_node;

            ctxt->node = source_node;

            if (!(local_node = virXPathNode("./local", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'<local>' element missing for 'udp' socket interface"));
                return NULL;
            }

            if (!(def->data.socket.localaddr = virXMLPropStringRequired(local_node, "address")))
                return NULL;

            if (virXMLPropInt(local_node, "port", 10, VIR_XML_PROP_REQUIRED,
                              &def->data.socket.localport, def->data.socket.localport) < 0)
                return NULL;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV: {
        g_autofree char *addrtype = virXPathString("string(./source/address/@type)", ctxt);
        int type;

        def->data.hostdev.def.parentnet = def;
        def->data.hostdev.def.info = &def->info;
        def->data.hostdev.def.mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;

        /* if not explicitly stated, source/vendor implies usb device */
        if (!addrtype && virXPathNode("./source/vendor", ctxt))
            addrtype = g_strdup("usb");

        /* The helper function expects type to already be found and
         * passed in as a string, since it is in a different place in
         * NetDef vs HostdevDef. */

        if ((type = virDomainHostdevSubsysTypeFromString(addrtype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown host device source address type '%1$s'"),
                           addrtype);
            return NULL;
        }

        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, type,
                                              &def->data.hostdev.def,
                                              flags, xmlopt) < 0)
            return NULL;

        virtualport_flags = VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS |
                            VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES |
                            VIR_VPORT_XML_REQUIRE_TYPE;
    }
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
        def->sourceDev = virXMLPropString(source_node, "dev");
        break;

    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    if ((virtualport_node = virXPathNode("./virtualport", ctxt))) {
        if (virtualport_flags == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("<virtualport> element unsupported for <interface type='%1$s'>"),
                           virDomainNetTypeToString(def->type));
            return NULL;
        }

        if (!(def->virtPortProfile = virNetDevVPortProfileParse(virtualport_node,
                                                                virtualport_flags)))
            return NULL;
    }

    if ((target_node = virXPathNode("./target", ctxt))) {
        def->ifname = virXMLPropString(target_node, "dev");

        if (virXMLPropTristateBool(target_node, "managed", VIR_XML_PROP_NONE,
                                   &def->managed_tap) < 0)
            return NULL;
    }

    def->ifname_guest = virXPathString("string(./guest/@dev)", ctxt);
    def->ifname_guest_actual = virXPathString("string(./guest/@actual)", ctxt);

    linkstate = virXPathString("string(./link/@state)", ctxt);
    def->script = virXPathString("string(./script/@path)", ctxt);
    def->downscript = virXPathString("string(./downscript/@path)", ctxt);
    def->domain_name = virXPathString("string(./backenddomain/@name)", ctxt);

    if (parse_filterref) {
        xmlNodePtr filterref_node = virXPathNode("./filterref", ctxt);

        if (filterref_node) {
            def->filter = virXMLPropString(filterref_node, "filter");
            def->filterparams = virNWFilterParseParamAttributes(filterref_node);
        }
    }

    if ((bandwidth_node = virXPathNode("./bandwidth", ctxt)) &&
        (virNetDevBandwidthParse(&def->bandwidth, NULL, bandwidth_node,
                                 def->type == VIR_DOMAIN_NET_TYPE_NETWORK) < 0))
        return NULL;

    if ((vlan_node = virXPathNode("./vlan", ctxt)) &&
        (virNetDevVlanParse(vlan_node, ctxt, &def->vlan) < 0))
        return NULL;

    if ((mac_node = virXPathNode("./mac", ctxt))) {
        if ((macaddr = virXMLPropString(mac_node, "address"))) {
            if (virMacAddrParse((const char *)macaddr, &def->mac) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("unable to parse mac address '%1$s'"),
                               (const char *)macaddr);
                return NULL;
            }
            if (virMacAddrIsMulticast(&def->mac)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("expected unicast mac address, found multicast '%1$s'"),
                               (const char *)macaddr);
                return NULL;
            }
        }

        if (virXMLPropEnum(mac_node, "type",
                           virDomainNetMacTypeTypeFromString,
                           VIR_XML_PROP_NONZERO, &def->mac_type) < 0)
            return NULL;

        if (virXMLPropTristateBool(mac_node, "check", VIR_XML_PROP_NONE,
                                   &def->mac_check) < 0)
            return NULL;
    }

    if (!macaddr || virMacAddrIsAllClear(&def->mac)) {
        virDomainNetGenerateMAC(xmlopt, &def->mac);
        def->mac_generated = true;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info,
                                    flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT
                                    | VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) < 0) {
        return NULL;
    }

    if (virDomainNetIPInfoParseXML(_("guest interface"), node,
                                   ctxt, &def->guestIP) < 0)
        return NULL;

    if (virDomainNetPortForwardsParseXML(def, ctxt) < 0)
        return NULL;

    if (def->managed_tap != VIR_TRISTATE_BOOL_NO && def->ifname &&
        (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) &&
        (STRPREFIX(def->ifname, VIR_NET_GENERATED_VNET_PREFIX) ||
         STRPREFIX(def->ifname, VIR_NET_GENERATED_MACVTAP_PREFIX) ||
         STRPREFIX(def->ifname, VIR_NET_GENERATED_MACVLAN_PREFIX) ||
         (prefix && STRPREFIX(def->ifname, prefix)))) {
        /* An auto-generated target name, blank it out */
        g_clear_pointer(&def->ifname, g_free);
    }

    if (virDomainNetDefParseXMLDriver(def, ctxt) < 0)
        return NULL;

    if ((backend_node = virXPathNode("./backend", ctxt)) &&
        virDomainNetBackendParseXML(backend_node, def) < 0) {
        return NULL;
    }

    def->linkstate = VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DEFAULT;
    if (linkstate != NULL) {
        if ((def->linkstate = virDomainNetInterfaceLinkStateTypeFromString(linkstate)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown interface link state '%1$s'"),
                           linkstate);
            return NULL;
        }
    }

    if (virDomainNetTeamingInfoParseXML(ctxt, &def->teaming) < 0)
        return NULL;

    rv = virXPathULongLong("string(./tune/sndbuf)", ctxt, &def->tune.sndbuf);
    if (rv >= 0) {
        def->tune.sndbuf_specified = true;
    } else if (rv == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("sndbuf must be a positive integer"));
        return NULL;
    }

    if (virXPathUInt("string(./mtu/@size)", ctxt, &def->mtu) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("malformed mtu size"));
        return NULL;
    }

    if ((coalesce_node = virXPathNode("./coalesce", ctxt))) {
        if (virDomainNetDefCoalesceParseXML(coalesce_node, ctxt, &def->coalesce) < 0)
            return NULL;
    }

    if (virNetworkPortOptionsParseXML(ctxt, &def->isolatedPort) < 0)
        return NULL;

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        virDomainNetDefParsePrivateData(ctxt, def, xmlopt) < 0)
        return NULL;

    return g_steal_pointer(&def);
}

static int
virDomainChrDefaultTargetType(int devtype)
{
    switch ((virDomainChrDeviceType) devtype) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        virReportError(VIR_ERR_XML_ERROR,
                       _("target type must be specified for %1$s device"),
                       virDomainChrDeviceTypeToString(devtype));
        return -1;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        return VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* No target type yet */
        break;
    }

    return 0;
}

static int
virDomainChrTargetTypeFromString(int devtype,
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
        /* No target type yet */
        ret = 0;
        break;
    }

    return ret;
}

static int
virDomainChrTargetModelFromString(int devtype,
                                  const char *targetModel)
{
    int ret = -1;

    if (!targetModel)
        return 0;

    switch ((virDomainChrDeviceType) devtype) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        ret = virDomainChrSerialTargetModelTypeFromString(targetModel);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* Target model not supported yet */
        ret = 0;
        break;
    }

    return ret;
}

static int
virDomainChrDefParseTargetXML(virDomainChrDef *def,
                              xmlNodePtr cur,
                              xmlXPathContextPtr ctxt,
                              unsigned int flags)
{
    unsigned int port;
    g_autofree char *targetType = virXMLPropString(cur, "type");
    g_autofree char *targetModel = NULL;
    g_autofree char *addrStr = NULL;
    g_autofree char *portStr = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = cur;

    if ((def->targetType =
         virDomainChrTargetTypeFromString(def->deviceType,
                                          targetType)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown target type '%1$s' specified for character device"),
                       targetType);
        return -1;
    }

    targetModel = virXPathString("string(./model/@name)", ctxt);

    if ((def->targetModel =
         virDomainChrTargetModelFromString(def->deviceType,
                                           targetModel)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown target model '%1$s' specified for character device"),
                       targetModel);
        return -1;
    }

    switch (def->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        switch (def->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            addrStr = virXMLPropString(cur, "address");

            def->target.addr = g_new0(virSocketAddr, 1);

            if (addrStr == NULL) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("guestfwd channel does not define a target address"));
                return -1;
            }

            if (virSocketAddrParse(def->target.addr, addrStr, AF_UNSPEC) < 0)
                return -1;

            if (def->target.addr->data.stor.ss_family != AF_INET) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("guestfwd channel only supports IPv4 addresses"));
                return -1;
            }

            if (virXMLPropUInt(cur, "port", 10, VIR_XML_PROP_REQUIRED, &port) < 0)
                return -1;

            virSocketAddrSetPort(def->target.addr, port);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            def->target.name = virXMLPropString(cur, "name");

            if (def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
                !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {

                if (virXMLPropEnum(cur, "state",
                                   virDomainChrDeviceStateTypeFromString,
                                   VIR_XML_PROP_NONZERO, &def->state) < 0)
                    return -1;
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
                           _("Invalid port number: %1$s"),
                           portStr);
            return -1;
        }
        def->target.port = port;
        break;
    }

    return 0;
}


static int
virDomainChrSourceDefParseTCP(virDomainChrSourceDef *def,
                              xmlNodePtr source,
                              xmlXPathContextPtr ctxt,
                              unsigned int flags)
{
    virDomainChrSourceMode mode;

    if (virXMLPropEnumDefault(source, "mode", virDomainChrSourceModeTypeFromString,
                              VIR_XML_PROP_NONE, &mode,
                              VIR_DOMAIN_CHR_SOURCE_MODE_CONNECT) < 0)
        return -1;

    def->data.tcp.listen = mode == VIR_DOMAIN_CHR_SOURCE_MODE_BIND;
    def->data.tcp.host = virXMLPropString(source, "host");
    def->data.tcp.service = virXMLPropString(source, "service");

    if (virXMLPropTristateBool(source, "tls", VIR_XML_PROP_NONE,
                               &def->data.tcp.haveTLS) < 0)
        return -1;

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        int tmpVal;

        if (virXMLPropInt(source, "tlsFromConfig", 10, VIR_XML_PROP_NONE,
                          &tmpVal, 0) < 0)
            return -1;
        def->data.tcp.tlsFromConfig = !!tmpVal;
    }

    if (virDomainChrSourceReconnectDefParseXML(&def->data.tcp.reconnect,
                                               source,
                                               ctxt) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainChrSourceDefParseUDP(virDomainChrSourceDef *def,
                              xmlNodePtr source)
{
    virDomainChrSourceMode mode;

    if (virXMLPropEnumDefault(source, "mode", virDomainChrSourceModeTypeFromString,
                              VIR_XML_PROP_NONE, &mode,
                              VIR_DOMAIN_CHR_SOURCE_MODE_CONNECT) < 0)
        return -1;

    if (mode == VIR_DOMAIN_CHR_SOURCE_MODE_CONNECT &&
        !def->data.udp.connectHost && !def->data.udp.connectService) {
        def->data.udp.connectHost = virXMLPropString(source, "host");
        def->data.udp.connectService = virXMLPropString(source, "service");
    } else if (mode == VIR_DOMAIN_CHR_SOURCE_MODE_BIND &&
               !def->data.udp.bindHost && !def->data.udp.bindService) {
        def->data.udp.bindHost = virXMLPropString(source, "host");
        def->data.udp.bindService = virXMLPropString(source, "service");
    }

    return 0;
}


static int
virDomainChrSourceDefParseUnix(virDomainChrSourceDef *def,
                               xmlNodePtr source,
                               xmlXPathContextPtr ctxt)
{
    virDomainChrSourceMode mode;

    if (virXMLPropEnumDefault(source, "mode", virDomainChrSourceModeTypeFromString,
                              VIR_XML_PROP_NONE, &mode,
                              VIR_DOMAIN_CHR_SOURCE_MODE_CONNECT) < 0)
        return -1;

    def->data.nix.listen = mode == VIR_DOMAIN_CHR_SOURCE_MODE_BIND;
    def->data.nix.path = virXMLPropString(source, "path");

    if (virDomainChrSourceReconnectDefParseXML(&def->data.nix.reconnect,
                                               source,
                                               ctxt) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainChrSourceDefParseFile(virDomainChrSourceDef *def,
                               xmlNodePtr source)
{
    def->data.file.path = virXMLPropString(source, "path");

    if (virXMLPropTristateSwitch(source, "append", VIR_XML_PROP_NONE,
                                 &def->data.file.append) < 0)
        return -1;

    return 0;
}


static int
virDomainChrSourceDefParseProtocol(virDomainChrSourceDef *def,
                                   xmlNodePtr protocol)
{
    g_autofree char *prot = NULL;

    if (def->type != VIR_DOMAIN_CHR_TYPE_TCP)
        return 0;

    if ((prot = virXMLPropString(protocol, "type")) &&
        (def->data.tcp.protocol =
         virDomainChrTcpProtocolTypeFromString(prot)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown protocol '%1$s'"), prot);
        return -1;
    }

    return 0;
}


static int
virDomainChrSourceDefParseLog(virDomainChrSourceDef *def,
                              xmlNodePtr log)
{
    def->logfile = virXMLPropString(log, "file");

    if (virXMLPropTristateSwitch(log, "append", VIR_XML_PROP_NONE,
                                 &def->logappend) < 0)
        return -1;

    return 0;
}


static int
virDomainChrSourceDefParseQemuVdagent(virDomainChrSourceDef *def,
                                      xmlNodePtr source,
                                      xmlXPathContextPtr ctxt)
{
    xmlNodePtr cur;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = source;
    if ((cur = virXPathNode("./clipboard", ctxt))) {
        if (virXMLPropTristateBool(cur, "copypaste",
                                   VIR_XML_PROP_REQUIRED,
                                   &def->data.qemuVdagent.clipboard) < 0)
            return -1;
    }
    if ((cur = virXPathNode("./mouse", ctxt))) {
        if (virXMLPropEnum(cur, "mode",
                           virDomainMouseModeTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &def->data.qemuVdagent.mouse) < 0)
            return -1;
    }

    return 0;
}


/* Parse the source half of the XML definition for a character device,
 * where node is the first element of node->children of the parent
 * element.  def->type must already be valid.
 *
 * Return -1 on failure, 0 on success. */
static int
virDomainChrSourceDefParseXML(virDomainChrSourceDef *def,
                              xmlNodePtr cur, unsigned int flags,
                              virDomainChrDef *chr_def,
                              xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *logs = NULL;
    int nlogs = 0;
    g_autofree xmlNodePtr *protocols = NULL;
    int nprotocols = 0;
    g_autofree xmlNodePtr *sources = NULL;
    int nsources = 0;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = cur;

    if ((nsources = virXPathNodeSet("./source", ctxt, &sources)) < 0)
        goto error;

    if (nsources > 0) {
        /* Parse only the first source element since only one is used
         * for chardev devices, the only exception is UDP type, where
         * user can specify two source elements. */
        if (nsources > 1 && def->type != VIR_DOMAIN_CHR_TYPE_UDP) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("only one source element is allowed for character device"));
            goto error;
        }
        if (nsources > 2) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("only two source elements are allowed for character device"));
            goto error;
        }

        switch ((virDomainChrType) def->type) {
        case VIR_DOMAIN_CHR_TYPE_FILE:
            if (virDomainChrSourceDefParseFile(def, sources[0]) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_TYPE_PTY:
            /* PTY path is only parsed from live xml.  */
            if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
                def->data.file.path = virXMLPropString(sources[0], "path");
            break;

        case VIR_DOMAIN_CHR_TYPE_DEV:
        case VIR_DOMAIN_CHR_TYPE_PIPE:
            def->data.file.path = virXMLPropString(sources[0], "path");
            break;

        case VIR_DOMAIN_CHR_TYPE_UNIX:
            if (virDomainChrSourceDefParseUnix(def, sources[0], ctxt) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_TYPE_UDP:
            if ((virDomainChrSourceDefParseUDP(def, sources[0]) < 0) ||
                (nsources == 2 && virDomainChrSourceDefParseUDP(def, sources[1]) < 0))
                goto error;
            break;

        case VIR_DOMAIN_CHR_TYPE_TCP:
            if (virDomainChrSourceDefParseTCP(def, sources[0], ctxt, flags) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
            def->data.spiceport.channel = virXMLPropString(sources[0], "channel");
            break;

        case VIR_DOMAIN_CHR_TYPE_DBUS:
            def->data.dbus.channel = virXMLPropString(sources[0], "channel");
            break;

        case VIR_DOMAIN_CHR_TYPE_NMDM:
            def->data.nmdm.master = virXMLPropString(sources[0], "master");
            def->data.nmdm.slave = virXMLPropString(sources[0], "slave");
            break;

        case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
            if (virDomainChrSourceDefParseQemuVdagent(def, sources[0], ctxt) < 0)
                goto error;

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
            xmlNodePtr tmp = ctxt->node;

            ctxt->node = sources[0];
            if (virSecurityDeviceLabelDefParseXML(&def->seclabels, &def->nseclabels,
                                                  ctxt, flags) < 0) {
                goto error;
            }
            ctxt->node = tmp;
        }
    }

    if ((nlogs = virXPathNodeSet("./log", ctxt, &logs)) < 0)
        goto error;

    if (nlogs == 1) {
        if (virDomainChrSourceDefParseLog(def, logs[0]) < 0)
            goto error;
    } else if (nlogs > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one log element is allowed for character device"));
        goto error;
    }

    if ((nprotocols = virXPathNodeSet("./protocol", ctxt, &protocols)) < 0)
        goto error;

    if (nprotocols == 1) {
        if (virDomainChrSourceDefParseProtocol(def, protocols[0]) < 0)
            goto error;
    } else if (nprotocols > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one protocol element is allowed for character device"));
        goto error;
    }

    return 0;

 error:
    virDomainChrSourceDefClear(def);
    return -1;
}


static virClass *virDomainChrSourceDefClass;

static int
virDomainChrSourceDefOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainChrSourceDef, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainChrSourceDef);

virDomainChrSourceDef *
virDomainChrSourceDefNew(virDomainXMLOption *xmlopt)
{
    virDomainChrSourceDef *def = NULL;

    if (virDomainChrSourceDefInitialize() < 0)
        return NULL;

    if (!(def = virObjectNew(virDomainChrSourceDefClass)))
        return NULL;

    if (xmlopt && xmlopt->privateData.chrSourceNew &&
        !(def->privateData = xmlopt->privateData.chrSourceNew())) {
        g_clear_pointer(&def, virObjectUnref);
    }

    return def;
}


/* Create a new character device definition and set
 * default port.
 */
virDomainChrDef *
virDomainChrDefNew(virDomainXMLOption *xmlopt)
{
    virDomainChrDef *def = NULL;

    def = g_new0(virDomainChrDef, 1);

    def->target.port = -1;

    if (!(def->source = virDomainChrSourceDefNew(xmlopt)))
        VIR_FREE(def);

    return def;
}

/* Parse the XML definition for a character device
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
static virDomainChrDef *
virDomainChrDefParseXML(virDomainXMLOption *xmlopt,
                        xmlXPathContextPtr ctxt,
                        xmlNodePtr node,
                        unsigned int flags)
{
    xmlNodePtr target;
    const char *nodeName;
    virDomainChrDef *def;
    g_autofree char *type = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(def = virDomainChrDefNew(xmlopt)))
        return NULL;

    type = virXMLPropString(node, "type");
    if (type == NULL) {
        def->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if ((def->source->type = virDomainChrTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown type presented to host for character device: %1$s"),
                       type);
        goto error;
    }

    nodeName = (const char *) node->name;
    if ((def->deviceType = virDomainChrDeviceTypeFromString(nodeName)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown character device type: %1$s"),
                       nodeName);
        goto error;
    }

    if ((target = virXPathNode("./target", ctxt))) {
        if (virDomainChrDefParseTargetXML(def, target, ctxt, flags) < 0)
            goto error;
    } else if ((def->targetType = virDomainChrDefaultTargetType(def->deviceType)) < 0) {
        goto error;
    }

    if (virDomainChrSourceDefParseXML(def->source, node, flags, def,
                                      ctxt) < 0)
        goto error;

    if (def->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
        if (def->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spicevmc device type only supports virtio"));
            goto error;
        } else {
            def->source->data.spicevmc = VIR_DOMAIN_CHR_SPICEVMC_VDAGENT;
        }
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    if (def->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        def->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb-serial requires address of usb type"));
        goto error;
    }

    return def;

 error:
    virDomainChrDefFree(def);
    return NULL;
}

static virDomainSmartcardDef *
virDomainSmartcardDefParseXML(virDomainXMLOption *xmlopt,
                              xmlNodePtr node,
                              xmlXPathContextPtr ctxt,
                              unsigned int flags)
{
    g_autoptr(virDomainSmartcardDef) def = NULL;
    g_autofree char *type = NULL;
    g_autofree xmlNodePtr *certificates = NULL;
    int n = 0;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;
    def = g_new0(virDomainSmartcardDef, 1);

    if (virXMLPropEnum(node, "mode", virDomainSmartcardTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0)
        return NULL;

    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        n = virXPathNodeSet("./certificate", ctxt, &certificates);
        if (n != VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("host-certificates mode needs exactly three certificates"));
            return NULL;
        }

        if (!(def->data.cert.file[0] = virXMLNodeContentString(certificates[0])) ||
            !(def->data.cert.file[1] = virXMLNodeContentString(certificates[1])) ||
            !(def->data.cert.file[2] = virXMLNodeContentString(certificates[2])))
            return NULL;

        if (virXPathNode("./database", ctxt) &&
            !def->data.cert.database) {
            if (!(def->data.cert.database =
                  virXPathString("string(./database/text())", ctxt)))
                return NULL;

            if (*def->data.cert.database != '/') {
                virReportError(VIR_ERR_XML_ERROR,
                               _("expecting absolute path: %1$s"),
                               def->data.cert.database);
                return NULL;
            }
        }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        type = virXMLPropString(node, "type");
        if (type == NULL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("passthrough mode requires a character device type attribute"));
            return NULL;
        }

        if (!(def->data.passthru = virDomainChrSourceDefNew(xmlopt)))
            return NULL;

        if ((def->data.passthru->type = virDomainChrTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown type presented to host for character device: %1$s"),
                           type);
            return NULL;
        }

        if (virDomainChrSourceDefParseXML(def->data.passthru, node, flags,
                                          NULL, ctxt) < 0)
            return NULL;

        if (def->data.passthru->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
            def->data.passthru->data.spicevmc
                = VIR_DOMAIN_CHR_SPICEVMC_SMARTCARD;
        }

        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainSmartcardType, def->type);
        return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        return NULL;

    return g_steal_pointer(&def);
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
 * or like this:
 *
 * <tpm model='tpm-tis'>
 *   <backend type='emulator' version='2.0'/>
 * </tpm>
 *
 * Emulator state encryption is supported with the following:
 *
 * <tpm model='tpm-tis'>
 *   <backend type='emulator' version='2.0'>
 *     <encryption secret='32ee7e76-2178-47a1-ab7b-269e6e348015'/>
 *     <active_pcr_banks>
 *       <sha256/>
 *       <sha384/>
 *     </active_pcr_banks>
 *   </backend>
 * </tpm>
 *
 * Emulator persistent_state is supported with the following:
 *
 * <tpm model='tpm-tis'>
 *   <backend type='emulator' version='2.0' persistent_state='yes'>
 * </tpm>
 */
static virDomainTPMDef *
virDomainTPMDefParseXML(virDomainXMLOption *xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    virDomainTPMDef *def;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int nbackends;
    int nnodes;
    size_t i;
    g_autofree char *path = NULL;
    g_autofree char *secretuuid = NULL;
    g_autofree char *persistent_state = NULL;
    g_autofree xmlNodePtr *backends = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *type = NULL;
    int bank;

    if (!(def = virDomainTPMDefNew(xmlopt)))
        return NULL;

    if (virXMLPropEnum(node, "model",
                       virDomainTPMModelTypeFromString,
                       VIR_XML_PROP_NONZERO,
                       &def->model) < 0)
        goto error;

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

    if (virXMLPropEnum(backends[0], "type",
                       virDomainTPMBackendTypeFromString,
                       VIR_XML_PROP_REQUIRED,
                       &def->type) < 0)
        goto error;

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        if (!(def->data.passthrough.source = virDomainChrSourceDefNew(xmlopt)))
            goto error;
        path = virXPathString("string(./backend/device/@path)", ctxt);
        if (!path)
            path = g_strdup(VIR_DOMAIN_TPM_DEFAULT_DEVICE);
        def->data.passthrough.source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        def->data.passthrough.source->data.file.path = g_steal_pointer(&path);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        if (virXMLPropEnum(backends[0], "version",
                           virDomainTPMVersionTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->data.emulator.version) < 0)
            goto error;

        if (!(def->data.emulator.source = virDomainChrSourceDefNew(xmlopt)))
            goto error;
        secretuuid = virXPathString("string(./backend/encryption/@secret)", ctxt);
        if (secretuuid) {
            if (virUUIDParse(secretuuid, def->data.emulator.secretuuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to parse secret uuid '%1$s'"), secretuuid);
                goto error;
            }
            def->data.emulator.hassecretuuid = true;
        }

        persistent_state = virXMLPropString(backends[0], "persistent_state");
        if (persistent_state) {
            if (virStringParseYesNo(persistent_state,
                                    &def->data.emulator.persistent_state) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Invalid persistent_state value, either 'yes' or 'no'"));
                goto error;
            }
        }

        if ((nnodes = virXPathNodeSet("./backend/active_pcr_banks/*", ctxt, &nodes)) < 0)
            break;
        if (nnodes > 0)
            def->data.emulator.activePcrBanks = virBitmapNew(0);
        for (i = 0; i < nnodes; i++) {
            if ((bank = virDomainTPMPcrBankTypeFromString((const char *)nodes[i]->name)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported PCR banks '%1$s'"),
                               nodes[i]->name);
                goto error;
            }
            virBitmapSetBitExpand(def->data.emulator.activePcrBanks, bank);
        }
        break;
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        if (!(type = virXPathString("string(./backend/source/@type)", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing external TPM backend source type"));
            goto error;
        }

        if (!(def->data.external.source = virDomainChrSourceDefNew(xmlopt)))
            goto error;

        def->data.external.source->type = virDomainChrTypeFromString(type);
        if (def->data.external.source->type < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown backend source type '%1$s' for external TPM"),
                           type);
            goto error;
        }

        if (virDomainChrSourceDefParseXML(def->data.external.source,
                                          backends[0], flags, NULL, ctxt) < 0)
            goto error;
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        goto error;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        xmlopt && xmlopt->privateData.tpmParse) {
        if ((ctxt->node = virXPathNode("./privateData", ctxt))) {
            if (xmlopt->privateData.tpmParse(ctxt, def) < 0)
                goto error;
        }
    }

    return def;

 error:
    virDomainTPMDefFree(def);
    return NULL;
}

static virDomainPanicDef *
virDomainPanicDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    virDomainPanicDef *panic;
    g_autofree char *model = NULL;

    panic = g_new0(virDomainPanicDef, 1);

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt,
                                    &panic->info, flags) < 0)
        goto error;

    model = virXMLPropString(node, "model");
    if (model != NULL &&
        (panic->model = virDomainPanicModelTypeFromString(model)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown panic model '%1$s'"), model);
        goto error;
    }

    return panic;

 error:
    virDomainPanicDefFree(panic);
    return NULL;
}

/* Parse the XML definition for an input device */
static virDomainInputDef *
virDomainInputDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainInputDef *def;
    g_autofree char *type = NULL;
    g_autofree char *bus = NULL;
    g_autofree char *model = NULL;
    xmlNodePtr source = NULL;

    def = g_new0(virDomainInputDef, 1);

    ctxt->node = node;

    type = virXMLPropString(node, "type");
    bus = virXMLPropString(node, "bus");
    model = virXMLPropString(node, "model");

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing input device type"));
        goto error;
    }

    if ((def->type = virDomainInputTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown input device type '%1$s'"), type);
        goto error;
    }

    if (model &&
        ((def->model = virDomainInputModelTypeFromString(model)) < 0 ||
         def->model == VIR_DOMAIN_INPUT_MODEL_DEFAULT)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown input model '%1$s'"), model);
        goto error;
    }

    if (bus &&
        ((def->bus = virDomainInputBusTypeFromString(bus)) < 0 ||
         def->bus == VIR_DOMAIN_INPUT_BUS_DEFAULT)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown input bus type '%1$s'"), bus);
        goto error;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    if (def->bus == VIR_DOMAIN_INPUT_BUS_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid address for a USB device"));
        goto error;
    }

    if ((source = virXPathNode("./source", ctxt))) {
        g_autofree char *evdev = NULL;

        if (def->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH)
            evdev = virXMLPropString(source, "evdev");
        else if (def->type == VIR_DOMAIN_INPUT_TYPE_EVDEV)
            evdev = virXMLPropString(source, "dev");

        if (evdev)
            def->source.evdev = virFileSanitizePath(evdev);

        if (def->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH ||
            def->type == VIR_DOMAIN_INPUT_TYPE_EVDEV) {
            if (!def->source.evdev) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Missing evdev path for input device"));
                goto error;
            }
        }

        if (def->type == VIR_DOMAIN_INPUT_TYPE_EVDEV) {
            if (virXMLPropEnum(source, "grab",
                               virDomainInputSourceGrabTypeFromString,
                               VIR_XML_PROP_NONZERO, &def->source.grab) < 0)
                goto error;

            if (virXMLPropEnum(source, "grabToggle",
                               virDomainInputSourceGrabToggleTypeFromString,
                               VIR_XML_PROP_NONZERO, &def->source.grabToggle) < 0)
                goto error;

            if (virXMLPropTristateSwitch(source, "repeat",
                                         VIR_XML_PROP_NONE, &def->source.repeat) < 0)
                goto error;
        }
    }

    if (virDomainVirtioOptionsParseXML(virXPathNode("./driver", ctxt),
                                       &def->virtio) < 0)
        goto error;

    return def;

 error:
    virDomainInputDefFree(def);
    return NULL;
}


/* Parse the XML definition for a hub device */
static virDomainHubDef *
virDomainHubDefParseXML(virDomainXMLOption *xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    virDomainHubDef *def;
    g_autofree char *type = NULL;

    def = g_new0(virDomainHubDef, 1);

    type = virXMLPropString(node, "type");

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing hub device type"));
        goto error;
    }

    if ((def->type = virDomainHubTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown hub device type '%1$s'"), type);
        goto error;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    return def;

 error:
    virDomainHubDefFree(def);
    return NULL;
}


/* Parse the XML definition for a clock timer */
static virDomainTimerDef *
virDomainTimerDefParseXML(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    g_autofree virDomainTimerDef *def = g_new0(virDomainTimerDef, 1);
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr catchup;

    ctxt->node = node;

    if (virXMLPropEnum(node, "name", virDomainTimerNameTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->name) < 0)
        return NULL;

    if (virXMLPropTristateBool(node, "present",
                               VIR_XML_PROP_NONE,
                               &def->present) < 0)
        return NULL;

    if (virXMLPropEnum(node, "tickpolicy", virDomainTimerTickpolicyTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->tickpolicy) < 0)
        return NULL;

    if (virXMLPropEnum(node, "track", virDomainTimerTrackTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->track) < 0)
        return NULL;

    if (virXMLPropULongLong(node, "frequency", 10, VIR_XML_PROP_NONE, &def->frequency) < 0)
        return NULL;

    if (virXMLPropEnum(node, "mode", virDomainTimerModeTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->mode) < 0)
        return NULL;

    catchup = virXPathNode("./catchup", ctxt);
    if (catchup != NULL) {
        if (virXMLPropULongLong(catchup, "threshold", 10, VIR_XML_PROP_NONE,
                                &def->catchup.threshold) < 0)
            return NULL;

        if (virXMLPropULongLong(catchup, "slew", 10, VIR_XML_PROP_NONE,
                                &def->catchup.slew) < 0)
            return NULL;

        if (virXMLPropULongLong(catchup, "limit", 10, VIR_XML_PROP_NONE,
                                &def->catchup.limit) < 0)
            return NULL;
    }

    return g_steal_pointer(&def);
}


static int
virDomainGraphicsAuthDefParseXML(xmlNodePtr node,
                                 virDomainGraphicsAuthDef *def,
                                 int type)
{
    g_autofree char *validTo = NULL;
    g_autofree char *connected = virXMLPropString(node, "connected");

    def->passwd = virXMLPropString(node, "passwd");

    if (!def->passwd)
        return 0;

    validTo = virXMLPropString(node, "passwdValidTo");
    if (validTo) {
        g_autoptr(GDateTime) then = NULL;
        g_autoptr(GTimeZone) tz = g_time_zone_new_utc();
        char *tmp;
        int year, mon, mday, hour, min, sec;

        /* Expect: YYYY-MM-DDTHH:MM:SS (%d-%d-%dT%d:%d:%d)  eg 2010-11-28T14:29:01 */
        if (/* year */
            virStrToLong_i(validTo, &tmp, 10, &year) < 0 || *tmp != '-' ||
            /* month */
            virStrToLong_i(tmp+1, &tmp, 10, &mon) < 0 || *tmp != '-' ||
            /* day */
            virStrToLong_i(tmp+1, &tmp, 10, &mday) < 0 || *tmp != 'T' ||
            /* hour */
            virStrToLong_i(tmp+1, &tmp, 10, &hour) < 0 || *tmp != ':' ||
            /* minute */
            virStrToLong_i(tmp+1, &tmp, 10, &min) < 0 || *tmp != ':' ||
            /* second */
            virStrToLong_i(tmp+1, &tmp, 10, &sec) < 0 || *tmp != '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse password validity time '%1$s', expect YYYY-MM-DDTHH:MM:SS"),
                           validTo);
            VIR_FREE(def->passwd);
            return -1;
        }

        then = g_date_time_new(tz, year, mon, mday, hour, min, sec);
        def->validTo = (time_t)g_date_time_to_unix(then);
        def->expires = true;
    }

    if (connected) {
        int action = virDomainGraphicsAuthConnectedTypeFromString(connected);
        if (action <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown connected value %1$s"),
                           connected);
            return -1;
        }

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
virDomainGraphicsListenDefParseXML(virDomainGraphicsListenDef *def,
                                   xmlNodePtr node,
                                   xmlNodePtr parent,
                                   unsigned int flags)
{
    int ret = -1;
    g_autofree char *address = virXMLPropString(node, "address");
    g_autofree char *network = virXMLPropString(node, "network");
    g_autofree char *socketPath = virXMLPropString(node, "socket");
    g_autofree char *autoGenerated = virXMLPropString(node, "autoGenerated");
    g_autofree char *addressCompat = NULL;
    g_autofree char *socketCompat = NULL;

    if (parent) {
        addressCompat = virXMLPropString(parent, "listen");
        socketCompat = virXMLPropString(parent, "socket");
    }

    if (virXMLPropEnum(node, "type", virDomainGraphicsListenTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0)
        goto error;

    if (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS) {
        if (address && addressCompat && STRNEQ(address, addressCompat)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("graphics 'listen' attribute '%1$s' must match 'address' attribute of first listen element (found '%2$s')"),
                           addressCompat, address);
            goto error;
        }

        if (!address)
            address = g_steal_pointer(&addressCompat);
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET) {
        if (socketPath && socketCompat && STRNEQ(socketPath, socketCompat)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("graphics 'socket' attribute '%1$s' must match 'socket' attribute of first listen element (found '%2$s')"),
                           socketCompat, socketPath);
            goto error;
        }

        if (!socketPath)
            socketPath = g_steal_pointer(&socketCompat);
    }

    if (address && address[0] &&
        (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS ||
         (def->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK &&
          !(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)))) {
        def->address = g_steal_pointer(&address);
    }

    if (network && network[0]) {
        if (def->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'network' attribute is valid only for listen type 'network'"));
            goto error;
        }
        def->network = g_steal_pointer(&network);
    }

    if (socketPath && socketPath[0]) {
        if (def->type != VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'socket' attribute is valid only for listen type 'socket'"));
            goto error;
        }
        def->socket = g_steal_pointer(&socketPath);
    }

    if (flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        int tmp;
        if (virXMLPropInt(node, "fromConfig", 10, VIR_XML_PROP_NONE, &tmp, 0) < 0)
            return -1;
        def->fromConfig = tmp != 0;
    }

    if (autoGenerated &&
        flags & VIR_DOMAIN_DEF_PARSE_STATUS) {
        if (virStringParseYesNo(autoGenerated, &def->autoGenerated) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid autoGenerated value: %1$s"),
                           autoGenerated);
            goto error;
        }
    }

    ret = 0;
 error:
    if (ret < 0)
        virDomainGraphicsListenDefClear(def);
    return ret;
}


static int
virDomainGraphicsListensParseXML(virDomainGraphicsDef *def,
                                 xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainGraphicsListenDef newListen = {0};
    int nListens;
    int ret = -1;
    g_autofree xmlNodePtr *listenNodes = NULL;
    g_autofree char *socketPath = NULL;

    ctxt->node = node;

    /* parse the <listen> subelements for graphics types that support it */
    nListens = virXPathNodeSet("./listen", ctxt, &listenNodes);
    if (nListens < 0)
        goto cleanup;

    if (nListens > 0) {
        size_t i;

        def->listens = g_new0(virDomainGraphicsListenDef, nListens);

        for (i = 0; i < nListens; i++) {
            if (virDomainGraphicsListenDefParseXML(&def->listens[i],
                                                   listenNodes[i],
                                                   i == 0 ? node : NULL,
                                                   flags) < 0)
                goto cleanup;

            def->nListens++;
        }
    }

    /* If no <listen/> element was found in XML for backward compatibility
     * we should try to parse 'listen' or 'socket' attribute from <graphics/>
     * element. */
    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        socketPath = virXMLPropString(node, "socket");

    if (socketPath) {
        newListen.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;
        newListen.socket = g_steal_pointer(&socketPath);
    } else {
        newListen.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;
        newListen.address = virXMLPropString(node, "listen");
        if (STREQ_NULLABLE(newListen.address, ""))
            VIR_FREE(newListen.address);
    }

    /* If no <listen/> element was found add a new one created by parsing
     * <graphics/> element. */
    if (def->nListens == 0) {
        VIR_APPEND_ELEMENT(def->listens, def->nListens, newListen);
    } else {
        virDomainGraphicsListenDef *glisten = &def->listens[0];

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
    return ret;
}


static int
virDomainGraphicsDefParseXMLVNC(virDomainGraphicsDef *def,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                unsigned int flags)
{
    g_autofree char *port = virXMLPropString(node, "port");
    g_autofree char *websocketGenerated = virXMLPropString(node, "websocketGenerated");
    g_autofree char *autoport = virXMLPropString(node, "autoport");
    xmlNodePtr audioNode;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        return -1;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &def->data.vnc.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse vnc port %1$s"), port);
            return -1;
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
        ignore_value(virStringParseYesNo(autoport, &def->data.vnc.autoport));

        if (def->data.vnc.autoport && flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)
            def->data.vnc.port = 0;
    }

    if (virXMLPropInt(node, "websocket", 10, VIR_XML_PROP_NONE,
                      &def->data.vnc.websocket, 0) < 0)
        return -1;

    if (websocketGenerated)
        ignore_value(virStringParseYesNo(websocketGenerated,
                     &def->data.vnc.websocketGenerated));

    if (virXMLPropEnum(node, "sharePolicy",
                       virDomainGraphicsVNCSharePolicyTypeFromString,
                       VIR_XML_PROP_NONE, &def->data.vnc.sharePolicy) < 0)
        return -1;

    if ((virXMLPropTristateBool(node, "powerControl", VIR_XML_PROP_NONE,
                                &def->data.vnc.powerControl)) < 0)
        return -1;

    def->data.vnc.keymap = virXMLPropString(node, "keymap");

    ctxt->node = node;
    audioNode = virXPathNode("./audio", ctxt);
    if (audioNode) {
        if (virXMLPropUInt(audioNode, "id", 10,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &def->data.vnc.audioId) < 0)
            return -1;
    }

    if (virDomainGraphicsAuthDefParseXML(node, &def->data.vnc.auth,
                                         def->type) < 0)
        return -1;

    return 0;
}


static int
virDomainGraphicsDefParseXMLSDL(virDomainGraphicsDef *def,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr glNode;
    virTristateBool fullscreen;

    ctxt->node = node;

    if (virXMLPropTristateBool(node, "fullscreen", VIR_XML_PROP_NONE,
                               &fullscreen) < 0)
        return -1;

    virTristateBoolToBool(fullscreen, &def->data.sdl.fullscreen);
    def->data.sdl.xauth = virXMLPropString(node, "xauth");
    def->data.sdl.display = virXMLPropString(node, "display");

    if ((glNode = virXPathNode("./gl", ctxt))) {
        if (virXMLPropTristateBool(glNode, "enable", VIR_XML_PROP_REQUIRED,
                                   &def->data.sdl.gl) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainGraphicsDefParseXMLRDP(virDomainGraphicsDef *def,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                unsigned int flags)
{
    g_autofree char *port = virXMLPropString(node, "port");
    g_autofree char *autoport = virXMLPropString(node, "autoport");
    g_autofree char *replaceUser = virXMLPropString(node, "replaceUser");
    g_autofree char *multiUser = virXMLPropString(node, "multiUser");

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        return -1;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &def->data.rdp.port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse rdp port %1$s"), port);
            return -1;
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

    return 0;
}


static int
virDomainGraphicsDefParseXMLDesktop(virDomainGraphicsDef *def,
                                    xmlNodePtr node)
{
    virTristateBool fullscreen;

    if (virXMLPropTristateBool(node, "fullscreen", VIR_XML_PROP_NONE,
                               &fullscreen) < 0)
        return -1;

    virTristateBoolToBool(fullscreen, &def->data.desktop.fullscreen);
    def->data.desktop.display = virXMLPropString(node, "display");

    return 0;
}


static int
virDomainGraphicsDefParseXMLSpice(virDomainGraphicsDef *def,
                                  xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  unsigned int flags)
{
    g_autofree xmlNodePtr *node_list = NULL;
    int n = 0;
    size_t i = 0;
    virTristateBool autoport;
    xmlNodePtr cur;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virDomainGraphicsListensParseXML(def, node, ctxt, flags) < 0)
        return -1;

    if (virXMLPropInt(node, "port", 10, VIR_XML_PROP_NONE,
                      &def->data.spice.port, 0) < 0)
        return -1;

    if (virXMLPropInt(node, "tlsPort", 10, VIR_XML_PROP_NONE,
                      &def->data.spice.tlsPort, 0) < 0)
        return -1;

    if (virXMLPropTristateBool(node, "autoport", VIR_XML_PROP_NONE,
                               &autoport) < 0)
        return -1;
    virTristateBoolToBool(autoport, &def->data.spice.autoport);

    def->data.spice.defaultMode = VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY;
    if (virXMLPropEnum(node, "defaultMode",
                       virDomainGraphicsSpiceChannelModeTypeFromString,
                       VIR_XML_PROP_NONE, &def->data.spice.defaultMode) < 0)
        return -1;

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
        return -1;

    if ((n = virXPathNodeSet("./channel", ctxt, &node_list)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        virDomainGraphicsSpiceChannelName name;
        virDomainGraphicsSpiceChannelMode mode;

        if (virXMLPropEnum(node_list[i], "name",
                           virDomainGraphicsSpiceChannelNameTypeFromString,
                           VIR_XML_PROP_REQUIRED, &name) < 0)
            return -1;

        if (virXMLPropEnum(node_list[i], "mode",
                           virDomainGraphicsSpiceChannelModeTypeFromString,
                           VIR_XML_PROP_REQUIRED, &mode) < 0)
            return -1;

        def->data.spice.channels[name] = mode;
    }

    if ((cur = virXPathNode("./image", ctxt))) {
        virDomainGraphicsSpiceImageCompression compression;

        if (virXMLPropEnum(cur, "compression",
                           virDomainGraphicsSpiceImageCompressionTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &compression) < 0)
            return -1;

        def->data.spice.image = compression;
    }

    if ((cur = virXPathNode("./jpeg", ctxt))) {
        virDomainGraphicsSpiceJpegCompression compression;

        if (virXMLPropEnum(cur, "compression",
                           virDomainGraphicsSpiceJpegCompressionTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &compression) < 0)
            return -1;

        def->data.spice.jpeg = compression;
    }

    if ((cur = virXPathNode("./zlib", ctxt))) {
        virDomainGraphicsSpiceZlibCompression compression;

        if (virXMLPropEnum(cur, "compression",
                           virDomainGraphicsSpiceZlibCompressionTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &compression) < 0)
            return -1;

        def->data.spice.zlib = compression;
    }

    if ((cur = virXPathNode("./playback", ctxt))) {
        if (virXMLPropTristateSwitch(cur, "compression",
                                     VIR_XML_PROP_REQUIRED,
                                     &def->data.spice.playback) < 0)
            return -1;
    }

    if ((cur = virXPathNode("./streaming", ctxt))) {
        virDomainGraphicsSpiceStreamingMode mode;

        if (virXMLPropEnum(cur, "mode",
                           virDomainGraphicsSpiceStreamingModeTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &mode) < 0)
            return -1;

        def->data.spice.streaming = mode;
    }

    if ((cur = virXPathNode("./clipboard", ctxt))) {
        if (virXMLPropTristateBool(cur, "copypaste",
                                   VIR_XML_PROP_REQUIRED,
                                   &def->data.spice.copypaste) < 0)
            return -1;
    }

    if ((cur = virXPathNode("./filetransfer", ctxt))) {
        if (virXMLPropTristateBool(cur, "enable",
                                   VIR_XML_PROP_REQUIRED,
                                   &def->data.spice.filetransfer) < 0)
            return -1;
    }

    if ((cur = virXPathNode("./gl", ctxt))) {
        def->data.spice.rendernode = virXMLPropString(cur, "rendernode");

        if (virXMLPropTristateBool(cur, "enable",
                                   VIR_XML_PROP_REQUIRED,
                                   &def->data.spice.gl) < 0)
            return -1;
    }

    if ((cur = virXPathNode("./mouse", ctxt))) {
        if (virXMLPropEnum(cur, "mode",
                           virDomainMouseModeTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &def->data.spice.mousemode) < 0)
            return -1;
    }

    return 0;
}


static void
virDomainGraphicsDefParseXMLEGLHeadless(virDomainGraphicsDef *def,
                                        xmlNodePtr node,
                                        xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr glNode;

    ctxt->node = node;

    if ((glNode = virXPathNode("./gl", ctxt)))
        def->data.egl_headless.rendernode = virXMLPropString(glNode,
                                                             "rendernode");
}


static int
virDomainGraphicsDefParseXMLDBus(virDomainGraphicsDef *def,
                                 xmlNodePtr node,
                                 xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr cur;
    virTristateBool p2p;

    if (virXMLPropTristateBool(node, "p2p", VIR_XML_PROP_NONE,
                               &p2p) < 0)
        return -1;
    def->data.dbus.p2p = p2p == VIR_TRISTATE_BOOL_YES;

    def->data.dbus.address = virXMLPropString(node, "address");
    def->data.dbus.fromConfig = def->data.dbus.address != NULL;

    ctxt->node = node;

    if ((cur = virXPathNode("./gl", ctxt))) {
        def->data.dbus.rendernode = virXMLPropString(cur,
                                                     "rendernode");

        if (virXMLPropTristateBool(cur, "enable",
                                   VIR_XML_PROP_REQUIRED,
                                   &def->data.dbus.gl) < 0)
            return -1;
    }

    cur = virXPathNode("./audio", ctxt);
    if (cur) {
        if (virXMLPropUInt(cur, "id", 10,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &def->data.dbus.audioId) < 0)
            return -1;
    }

    return 0;
}


virDomainGraphicsDef *
virDomainGraphicsDefNew(virDomainXMLOption *xmlopt)
{
    virDomainGraphicsDef *def = NULL;

    def = g_new0(virDomainGraphicsDef, 1);

    if (xmlopt && xmlopt->privateData.graphicsNew &&
        !(def->privateData = xmlopt->privateData.graphicsNew())) {
        VIR_FREE(def);
    }

    return def;
}


virDomainNetDef *
virDomainNetDefNew(virDomainXMLOption *xmlopt)
{
    virDomainNetDef *def = NULL;

    def = g_new0(virDomainNetDef, 1);

    if (xmlopt && xmlopt->privateData.networkNew &&
        !(def->privateData = xmlopt->privateData.networkNew())) {
        g_clear_pointer(&def, virDomainNetDefFree);
    }

    return def;
}


/* Parse the XML definition for a graphics device */
static virDomainGraphicsDef *
virDomainGraphicsDefParseXML(virDomainXMLOption *xmlopt,
                             xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             unsigned int flags)
{
    virDomainGraphicsDef *def;

    if (!(def = virDomainGraphicsDefNew(xmlopt)))
        return NULL;

    if (virXMLPropEnum(node, "type", virDomainGraphicsTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0)
        goto error;

    switch (def->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (virDomainGraphicsDefParseXMLVNC(def, node, ctxt, flags) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        if (virDomainGraphicsDefParseXMLSDL(def, node, ctxt) < 0)
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
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        virDomainGraphicsDefParseXMLEGLHeadless(def, node, ctxt);
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        if (virDomainGraphicsDefParseXMLDBus(def, node, ctxt) < 0)
            goto error;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return def;

 error:
    g_clear_pointer(&def, virDomainGraphicsDefFree);
    return NULL;
}


static virDomainSoundCodecDef *
virDomainSoundCodecDefParseXML(xmlNodePtr node)
{
    virDomainSoundCodecDef *def;
    g_autofree char *type = NULL;

    def = g_new0(virDomainSoundCodecDef, 1);

    type = virXMLPropString(node, "type");
    if ((def->type = virDomainSoundCodecTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown codec type '%1$s'"), type);
        goto error;
    }

    return def;

 error:
    virDomainSoundCodecDefFree(def);
    return NULL;
}


static virDomainSoundDef *
virDomainSoundDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    g_autoptr(virDomainSoundDef) def = g_new0(virDomainSoundDef, 1);
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr audioNode;

    ctxt->node = node;

    if (virXMLPropEnum(node, "model", virDomainSoundModelTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->model) < 0)
        return NULL;

    if (virDomainSoundModelSupportsCodecs(def)) {
        int ncodecs;
        g_autofree xmlNodePtr *codecNodes = NULL;

        /* parse the <codec> subelements for sound models that support it */
        ncodecs = virXPathNodeSet("./codec", ctxt, &codecNodes);
        if (ncodecs < 0)
            return NULL;

        if (ncodecs > 0) {
            size_t i;

            def->codecs = g_new0(virDomainSoundCodecDef *, ncodecs);

            for (i = 0; i < ncodecs; i++) {
                virDomainSoundCodecDef *codec = virDomainSoundCodecDefParseXML(codecNodes[i]);
                if (codec == NULL)
                    return NULL;

                codec->cad = def->ncodecs; /* that will do for now */
                def->codecs[def->ncodecs++] = codec;
            }
        }
    }

    if (def->model == VIR_DOMAIN_SOUND_MODEL_USB) {
        if (virXMLPropTristateBool(node, "multichannel", VIR_XML_PROP_NONE,
                                   &def->multichannel) < 0)
            return NULL;
    }

    audioNode = virXPathNode("./audio", ctxt);
    if (audioNode) {
        if (virXMLPropUInt(audioNode, "id", 10,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &def->audioId) < 0)
            return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static bool
virDomainSoundDefEquals(const virDomainSoundDef *a,
                        const virDomainSoundDef *b)
{
    size_t i;

    if (a->model != b->model)
        return false;

    if (a->ncodecs != b->ncodecs)
        return false;

    for (i = 0; i < a->ncodecs; i++) {
        if (a->codecs[i]->type != b->codecs[i]->type)
            return false;
    }

    if (a->multichannel != b->multichannel)
        return false;

    if (a->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        !virDomainDeviceInfoAddressIsEqual(&a->info, &b->info))
        return false;

    return true;
}


ssize_t
virDomainSoundDefFind(const virDomainDef *def,
                      const virDomainSoundDef *sound)
{
    size_t i;

    for (i = 0; i < def->nsounds; i++) {
        if (virDomainSoundDefEquals(sound, def->sounds[i]))
            return i;
    }

    return -1;
}


static int
virDomainAudioCommonParse(virDomainAudioIOCommon *def,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    xmlNodePtr settings;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);

    ctxt->node = node;
    settings = virXPathNode("./settings", ctxt);

    if (virXMLPropTristateBool(node, "mixingEngine", VIR_XML_PROP_NONE,
                               &def->mixingEngine) < 0)
        return -1;

    if (virXMLPropTristateBool(node, "fixedSettings", VIR_XML_PROP_NONE,
                               &def->fixedSettings) < 0)
        return -1;

    if (def->fixedSettings == VIR_TRISTATE_BOOL_YES &&
        def->mixingEngine != VIR_TRISTATE_BOOL_YES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("fixed audio settings requires mixing engine"));
        return -1;
    }

    if (virXMLPropUInt(node, "voices", 10,
                       VIR_XML_PROP_NONZERO,
                       &def->voices) < 0)
        return -1;

    if (virXMLPropUInt(node, "bufferLength", 10,
                       VIR_XML_PROP_NONZERO,
                       &def->bufferLength) < 0)
        return -1;

    if (settings) {
        if (def->fixedSettings != VIR_TRISTATE_BOOL_YES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("audio settings specified without fixed settings flag"));
            return -1;
        }

        if (virXMLPropUInt(settings, "frequency", 10,
                           VIR_XML_PROP_NONZERO,
                           &def->frequency) < 0)
            return -1;

        if (virXMLPropUInt(settings, "channels", 10,
                           VIR_XML_PROP_NONZERO,
                           &def->channels) < 0)
            return -1;

        if (virXMLPropEnum(settings, "format",
                           virDomainAudioFormatTypeFromString,
                           VIR_XML_PROP_NONZERO, &def->format) < 0)
            return -1;
    }

    return 0;
}


static void
virDomainAudioALSAParse(virDomainAudioIOALSA *def,
                        xmlNodePtr node)
{
    def->dev = virXMLPropString(node, "dev");
}


static int
virDomainAudioCoreAudioParse(virDomainAudioIOCoreAudio *def,
                             xmlNodePtr node)
{
    if (virXMLPropUInt(node, "bufferCount", 10, VIR_XML_PROP_NONE,
                       &def->bufferCount) < 0)
        return -1;

    return 0;
}


static int
virDomainAudioJackParse(virDomainAudioIOJack *def,
                        xmlNodePtr node)
{
    def->serverName = virXMLPropString(node, "serverName");
    def->clientName = virXMLPropString(node, "clientName");
    def->connectPorts = virXMLPropString(node, "connectPorts");

    if (virXMLPropTristateBool(node, "exactName", VIR_XML_PROP_NONE,
                               &def->exactName) < 0)
        return -1;

    return 0;
}


static int
virDomainAudioOSSParse(virDomainAudioIOOSS *def,
                       xmlNodePtr node)
{
    def->dev = virXMLPropString(node, "dev");

    if (virXMLPropTristateBool(node, "tryPoll", VIR_XML_PROP_NONE,
                               &def->tryPoll) < 0)
        return -1;

    if (virXMLPropUInt(node, "bufferCount", 10, VIR_XML_PROP_NONE,
                       &def->bufferCount) < 0)
        return -1;

    return 0;
}


static int
virDomainAudioPulseAudioParse(virDomainAudioIOPulseAudio *def,
                              xmlNodePtr node)
{
    def->name = virXMLPropString(node, "name");
    def->streamName = virXMLPropString(node, "streamName");

    if (virXMLPropUInt(node, "latency", 10, VIR_XML_PROP_NONE,
                       &def->latency) < 0)
        return -1;

    return 0;
}


static int
virDomainAudioSDLParse(virDomainAudioIOSDL *def,
                       xmlNodePtr node)
{
    if (virXMLPropUInt(node, "bufferCount", 10, VIR_XML_PROP_NONE,
                       &def->bufferCount) < 0)
        return -1;

    return 0;
}


static virDomainAudioDef *
virDomainAudioDefParseXML(virDomainXMLOption *xmlopt G_GNUC_UNUSED,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    virDomainAudioDef *def;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr inputNode, outputNode;

    def = g_new0(virDomainAudioDef, 1);
    ctxt->node = node;

    if (virXMLPropEnum(node, "type", virDomainAudioTypeTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0)
        goto error;

    if (virXMLPropUInt(node, "id", 10, VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &def->id) < 0)
        goto error;

    if (virXMLPropUInt(node, "timerPeriod", 10, VIR_XML_PROP_NONZERO,
                       &def->timerPeriod) < 0)
        goto error;

    inputNode = virXPathNode("./input", ctxt);
    outputNode = virXPathNode("./output", ctxt);

    if (inputNode && virDomainAudioCommonParse(&def->input, inputNode, ctxt) < 0)
        goto error;
    if (outputNode && virDomainAudioCommonParse(&def->output, outputNode, ctxt) < 0)
        goto error;

    switch (def->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        if (inputNode)
            virDomainAudioALSAParse(&def->backend.alsa.input, inputNode);
        if (outputNode)
            virDomainAudioALSAParse(&def->backend.alsa.output, outputNode);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        if (inputNode &&
            virDomainAudioCoreAudioParse(&def->backend.coreaudio.input, inputNode) < 0)
            goto error;
        if (outputNode &&
            virDomainAudioCoreAudioParse(&def->backend.coreaudio.output, outputNode) < 0)
            goto error;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_JACK:
        if (inputNode &&
            virDomainAudioJackParse(&def->backend.jack.input, inputNode) < 0)
            goto error;
        if (outputNode &&
            virDomainAudioJackParse(&def->backend.jack.output, outputNode) < 0)
            goto error;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_OSS: {
        int dspPolicySet;

        if (virXMLPropTristateBool(node, "tryMMap", VIR_XML_PROP_NONE,
                                   &def->backend.oss.tryMMap) < 0)
            goto error;

        if (virXMLPropTristateBool(node, "exclusive", VIR_XML_PROP_NONE,
                                   &def->backend.oss.exclusive) < 0)
            goto error;

        if ((dspPolicySet = virXMLPropInt(node, "dspPolicy", 10, VIR_XML_PROP_NONE,
                                     &def->backend.oss.dspPolicy, 0)) < 0)
            goto error;

        if (dspPolicySet != 0) {
            if (def->backend.oss.dspPolicy < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("cannot parse 'dspPolicy' value '%1$i'"),
                               def->backend.oss.dspPolicy);
                goto error;
            }
            def->backend.oss.dspPolicySet = true;
        }

        if (inputNode &&
            virDomainAudioOSSParse(&def->backend.oss.input, inputNode) < 0)
            goto error;
        if (outputNode &&
            virDomainAudioOSSParse(&def->backend.oss.output, outputNode) < 0)
            goto error;
        break;
    }

    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        def->backend.pulseaudio.serverName = virXMLPropString(node, "serverName");

        if (inputNode &&
            virDomainAudioPulseAudioParse(&def->backend.pulseaudio.input, inputNode) < 0)
            goto error;
        if (outputNode &&
            virDomainAudioPulseAudioParse(&def->backend.pulseaudio.output, outputNode) < 0)
            goto error;
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SDL: {
        if (virXMLPropEnum(node, "driver", virDomainAudioSDLDriverTypeFromString,
                           VIR_XML_PROP_NONZERO, &def->backend.sdl.driver) < 0)
            goto error;

        if (inputNode &&
            virDomainAudioSDLParse(&def->backend.sdl.input, inputNode) < 0)
            goto error;
        if (outputNode &&
            virDomainAudioSDLParse(&def->backend.sdl.output, outputNode) < 0)
            goto error;
        break;
    }

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        def->backend.file.path = virXMLPropString(node, "path");
        break;

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainAudioType, def->type);
        break;
    }

    return def;

 error:
    virDomainAudioDefFree(def);
    return NULL;
}


static virDomainWatchdogDef *
virDomainWatchdogDefParseXML(virDomainXMLOption *xmlopt,
                             xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             unsigned int flags)
{
    virDomainWatchdogDef *def;

    def = g_new0(virDomainWatchdogDef, 1);

    if (virXMLPropEnum(node, "model",
                       virDomainWatchdogModelTypeFromString,
                       VIR_XML_PROP_REQUIRED,
                       &def->model) < 0) {
        goto error;
    }

    if (virXMLPropEnumDefault(node, "action",
                              virDomainWatchdogActionTypeFromString,
                              VIR_XML_PROP_NONE,
                              &def->action,
                              VIR_DOMAIN_WATCHDOG_ACTION_RESET) < 0) {
        goto error;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    return def;

 error:
    virDomainWatchdogDefFree(def);
    return NULL;
}


static virDomainRNGDef *
virDomainRNGDefParseXML(virDomainXMLOption *xmlopt,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        unsigned int flags)
{
    virDomainRNGDef *def;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int nbackends;
    g_autofree xmlNodePtr *backends = NULL;
    g_autofree char *type = NULL;

    def = g_new0(virDomainRNGDef, 1);

    if (virXMLPropEnum(node, "model",
                       virDomainRNGModelTypeFromString,
                       VIR_XML_PROP_REQUIRED,
                       &def->model) < 0)
        goto error;

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

    if (virXMLPropEnum(backends[0], "model",
                       virDomainRNGBackendTypeFromString,
                       VIR_XML_PROP_REQUIRED,
                       &def->backend) < 0) {
        goto error;
    }

    switch (def->backend) {
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
                           _("unknown backend type '%1$s' for egd"),
                           type);
            goto error;
        }

        if (virDomainChrSourceDefParseXML(def->source.chardev,
                                          backends[0], flags,
                                          NULL, ctxt) < 0)
            goto error;
        break;

    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    if (virDomainVirtioOptionsParseXML(virXPathNode("./driver", ctxt),
                                       &def->virtio) < 0)
        goto error;

    return def;

 error:
    g_clear_pointer(&def, virDomainRNGDefFree);
    return NULL;
}


static virDomainMemballoonDef *
virDomainMemballoonDefParseXML(virDomainXMLOption *xmlopt,
                               xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    virDomainMemballoonDef *def;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr stats;

    ctxt->node = node;

    def = g_new0(virDomainMemballoonDef, 1);

    if (virXMLPropEnum(node, "model", virDomainMemballoonModelTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->model) < 0)
        goto error;

    if (virXMLPropTristateSwitch(node, "autodeflate", VIR_XML_PROP_NONE,
                                 &def->autodeflate) < 0)
        goto error;

    if (virXMLPropTristateSwitch(node, "freePageReporting",
                                 VIR_XML_PROP_NONE,
                                 &def->free_page_reporting) < 0)
        goto error;

    if ((stats = virXPathNode("./stats", ctxt))) {
        if (virXMLPropInt(stats, "period", 0, VIR_XML_PROP_NONE,
                          &def->period, 0) < 0)
            goto error;

        if (def->period < 0)
            def->period = 0;
    }

    if (def->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE)
        VIR_DEBUG("Ignoring device address for none model Memballoon");
    else if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt,
                                         &def->info, flags) < 0)
        goto error;

    if (virDomainVirtioOptionsParseXML(virXPathNode("./driver", ctxt),
                                       &def->virtio) < 0)
        goto error;

    return def;

 error:
    virDomainMemballoonDefFree(def);
    return NULL;
}

static virDomainNVRAMDef *
virDomainNVRAMDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    virDomainNVRAMDef *def;

    def = g_new0(virDomainNVRAMDef, 1);

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        goto error;

    return def;

 error:
    virDomainNVRAMDefFree(def);
    return NULL;
}

static virDomainShmemDef *
virDomainShmemDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    g_autoptr(virDomainShmemDef) def = g_new0(virDomainShmemDef, 1);
    xmlNodePtr model;
    xmlNodePtr msi;
    xmlNodePtr server;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if ((model = virXPathNode("./model", ctxt))) {
        /* If there's none, we will automatically have the first one
         * (as default).  Unfortunately this has to be done for
         * compatibility reasons. */
        if (virXMLPropEnum(model, "type", virDomainShmemModelTypeFromString,
                           VIR_XML_PROP_NONE, &def->model) < 0)
            return NULL;
    }

    if (!(def->name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("shmem element must contain 'name' attribute"));
        return NULL;
    }

    if (def->model != VIR_DOMAIN_SHMEM_MODEL_IVSHMEM) {
        if (virXMLPropEnum(node, "role", virDomainShmemRoleTypeFromString,
                           VIR_XML_PROP_NONZERO, &def->role) < 0)
            return NULL;
    }

    if (virParseScaledValue("./size[1]", NULL, ctxt,
                            &def->size, 1, ULLONG_MAX, false) < 0)
        return NULL;

    if ((server = virXPathNode("./server[1]", ctxt))) {
        g_autofree char *tmp = NULL;

        if (!(def->server.chr = virDomainChrSourceDefNew(xmlopt)))
            return NULL;

        def->server.enabled = true;
        def->server.chr->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        def->server.chr->data.nix.listen = false;
        if ((tmp = virXMLPropString(server, "path")))
            def->server.chr->data.nix.path = virFileSanitizePath(tmp);
    }

    if ((msi = virXPathNode("./msi[1]", ctxt))) {
        def->msi.enabled = true;

        if (virXMLPropUInt(msi, "vectors", 0, VIR_XML_PROP_NONE,
                           &def->msi.vectors) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(msi, "ioeventfd", VIR_XML_PROP_NONE,
                                     &def->msi.ioeventfd) < 0)
            return NULL;
    }

    /* msi option is only relevant with a server */
    if (def->msi.enabled && !def->server.enabled) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("msi option is only supported with a server"));
        return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        return NULL;


    return g_steal_pointer(&def);
}

static int
virSysinfoBIOSParseXML(xmlNodePtr node,
                       xmlXPathContextPtr ctxt,
                       virSysinfoBIOSDef **bios)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virSysinfoBIOSDef) def = g_new0(virSysinfoBIOSDef, 1);

    ctxt->node = node;

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
            return -1;
        }
    }

    if (!def->vendor && !def->version &&
        !def->date && !def->release)
        return 0;

    *bios = g_steal_pointer(&def);
    return 0;
}

static int
virSysinfoSystemParseXML(xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virSysinfoSystemDef **sysdef,
                         unsigned char *domUUID,
                         bool uuid_generated)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virSysinfoSystemDef) def = g_new0(virSysinfoSystemDef, 1);
    g_autofree char *tmpUUID = NULL;

    ctxt->node = node;

    def->manufacturer = virXPathString("string(entry[@name='manufacturer'])", ctxt);
    def->product = virXPathString("string(entry[@name='product'])", ctxt);
    def->version = virXPathString("string(entry[@name='version'])", ctxt);
    def->serial = virXPathString("string(entry[@name='serial'])", ctxt);
    tmpUUID = virXPathString("string(entry[@name='uuid'])", ctxt);
    if (tmpUUID) {
        unsigned char uuidbuf[VIR_UUID_BUFLEN];
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        if (virUUIDParse(tmpUUID, uuidbuf) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           "%s", _("malformed <sysinfo> uuid element"));
            return -1;
        }
        if (uuid_generated) {
            memcpy(domUUID, uuidbuf, VIR_UUID_BUFLEN);
        } else if (memcmp(domUUID, uuidbuf, VIR_UUID_BUFLEN) != 0) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("UUID mismatch between <uuid> and <sysinfo>"));
            return -1;
        }
        /* Although we've validated the UUID as good, virUUIDParse() is
         * lax with respect to allowing extraneous "-" and " ", but the
         * underlying hypervisor may be less forgiving. Use virUUIDFormat()
         * to validate format in xml is right. If not, then format it
         * properly so that it's used correctly later.
         */
        virUUIDFormat(uuidbuf, uuidstr);
        def->uuid = g_strdup(uuidstr);
    }
    def->sku = virXPathString("string(entry[@name='sku'])", ctxt);
    def->family = virXPathString("string(entry[@name='family'])", ctxt);

    if (!def->manufacturer && !def->product && !def->version &&
        !def->serial && !def->uuid && !def->sku && !def->family)
        return 0;

    *sysdef = g_steal_pointer(&def);
    return 0;
}

static int
virSysinfoBaseBoardParseXML(xmlXPathContextPtr ctxt,
                            virSysinfoBaseBoardDef **baseBoard,
                            size_t *nbaseBoard)
{
    size_t i, nboards = 0;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int n;
    g_autofree virSysinfoBaseBoardDef *boards = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    if ((n = virXPathNodeSet("./baseBoard", ctxt, &nodes)) < 0)
        return -1;

    if (n)
        boards = g_new0(virSysinfoBaseBoardDef, n);

    for (i = 0; i < n; i++) {
        virSysinfoBaseBoardDef *def = boards + nboards;

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

    *baseBoard = g_steal_pointer(&boards);
    *nbaseBoard = nboards;

    return 0;
}


static int
virSysinfoOEMStringsParseXML(xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             virSysinfoOEMStringsDef **oem)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int ret = -1;
    virSysinfoOEMStringsDef *def;
    int nstrings;
    size_t i;
    g_autofree xmlNodePtr *strings = NULL;

    ctxt->node = node;

    nstrings = virXPathNodeSet("./entry", ctxt, &strings);
    if (nstrings < 0)
        return -1;
    if (nstrings == 0)
        return 0;

    def = g_new0(virSysinfoOEMStringsDef, 1);

    def->values = g_new0(char *, nstrings);

    def->nvalues = nstrings;
    for (i = 0; i < nstrings; i++) {
        if (!(def->values[i] = virXMLNodeContentString(strings[i])))
            goto cleanup;
    }

    *oem = g_steal_pointer(&def);
    ret = 0;
 cleanup:
    virSysinfoOEMStringsDefFree(def);
    return ret;
}


static int
virSysinfoChassisParseXML(xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virSysinfoChassisDef **chassisdef)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virSysinfoChassisDef) def = g_new0(virSysinfoChassisDef, 1);

    ctxt->node = node;

    def->manufacturer = virXPathString("string(entry[@name='manufacturer'])", ctxt);
    def->version = virXPathString("string(entry[@name='version'])", ctxt);
    def->serial = virXPathString("string(entry[@name='serial'])", ctxt);
    def->asset = virXPathString("string(entry[@name='asset'])", ctxt);
    def->sku = virXPathString("string(entry[@name='sku'])", ctxt);

    if (!def->manufacturer && !def->version &&
        !def->serial && !def->asset && !def->sku)
        return 0;

    *chassisdef = g_steal_pointer(&def);
    return 0;
}


static int
virSysinfoParseSMBIOSDef(virSysinfoDef *def,
                         xmlXPathContextPtr ctxt,
                         unsigned char *domUUID,
                         bool uuid_generated)
{
    xmlNodePtr tmpnode;

    /* Extract BIOS related metadata */
    if ((tmpnode = virXPathNode("./bios[1]", ctxt)) != NULL) {
        if (virSysinfoBIOSParseXML(tmpnode, ctxt, &def->bios) < 0)
            return -1;
    }

    /* Extract system related metadata */
    if ((tmpnode = virXPathNode("./system[1]", ctxt)) != NULL) {
        if (virSysinfoSystemParseXML(tmpnode, ctxt, &def->system,
                                     domUUID, uuid_generated) < 0)
            return -1;
    }

    /* Extract system base board metadata */
    if (virSysinfoBaseBoardParseXML(ctxt, &def->baseBoard, &def->nbaseBoard) < 0)
        return -1;

    /* Extract chassis related metadata */
    if ((tmpnode = virXPathNode("./chassis[1]", ctxt)) != NULL) {
        if (virSysinfoChassisParseXML(tmpnode, ctxt, &def->chassis) < 0)
            return -1;
    }

    /* Extract system related metadata */
    if ((tmpnode = virXPathNode("./oemStrings[1]", ctxt)) != NULL) {
        if (virSysinfoOEMStringsParseXML(tmpnode, ctxt, &def->oemStrings) < 0)
            return -1;
    }

    return 0;
}


static int
virSysinfoParseFWCfgDef(virSysinfoDef *def,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    int n;
    size_t i;

    ctxt->node = node;

    if ((n = virXPathNodeSet("./entry", ctxt, &nodes)) < 0)
        return -1;

    if (n == 0)
        return 0;

    def->fw_cfgs = g_new0(virSysinfoFWCfgDef, n);

    for (i = 0; i < n; i++) {
        g_autofree char *name = NULL;
        g_autofree char *value = NULL;
        g_autofree char *file = NULL;
        g_autofree char *sanitizedFile = NULL;

        if (!(name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Firmware entry is missing 'name' attribute"));
            return -1;
        }

        if (!(value = virXMLNodeContentString(nodes[i])))
            return -1;

        file = virXMLPropString(nodes[i], "file");

        if (virStringIsEmpty(value))
            VIR_FREE(value);

        if (!value && !file) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Firmware entry must have either value or 'file' attribute"));
            return -1;
        }

        if (file)
            sanitizedFile = virFileSanitizePath(file);

        def->fw_cfgs[i].name = g_steal_pointer(&name);
        def->fw_cfgs[i].value = g_steal_pointer(&value);
        def->fw_cfgs[i].file = g_steal_pointer(&sanitizedFile);
        def->nfw_cfgs++;
    }

    return 0;
}


static virSysinfoDef *
virSysinfoParseXML(xmlNodePtr node,
                   xmlXPathContextPtr ctxt,
                   unsigned char *domUUID,
                   bool uuid_generated)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virSysinfoDef) def = g_new0(virSysinfoDef, 1);

    ctxt->node = node;

    if (virXMLPropEnum(node, "type", virSysinfoTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0)
        return NULL;

    switch (def->type) {
    case VIR_SYSINFO_SMBIOS:
        if (virSysinfoParseSMBIOSDef(def, ctxt, domUUID, uuid_generated) < 0)
            return NULL;
        break;

    case VIR_SYSINFO_FWCFG:
        if (virSysinfoParseFWCfgDef(def, node, ctxt) < 0)
            return NULL;
        break;

    case VIR_SYSINFO_LAST:
        break;
    }

    return g_steal_pointer(&def);
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

    case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
        return 16 * 1024;

    case VIR_DOMAIN_VIDEO_TYPE_XEN:
        /* Original Xen PVFB hardcoded to 4 MB */
        return 4 * 1024;

    case VIR_DOMAIN_VIDEO_TYPE_QXL:
        /* QEMU use 64M as the minimal video memory for qxl device */
        return 64 * 1024;

    case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
    case VIR_DOMAIN_VIDEO_TYPE_VBOX:
    case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
    case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
    case VIR_DOMAIN_VIDEO_TYPE_GOP:
    case VIR_DOMAIN_VIDEO_TYPE_NONE:
    case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
    case VIR_DOMAIN_VIDEO_TYPE_LAST:
    default:
        return 0;
    }
}


static virDomainVideoAccelDef *
virDomainVideoAccelDefParseXML(xmlNodePtr node)
{
    g_autofree virDomainVideoAccelDef *def = NULL;
    g_autofree char *rendernode = NULL;
    virTristateBool accel3d;
    virTristateBool accel2d;

    rendernode = virXMLPropString(node, "rendernode");
    if (virXMLPropTristateBool(node, "accel3d",
                               VIR_XML_PROP_NONE, &accel3d) < 0)
        return NULL;
    if (virXMLPropTristateBool(node, "accel2d",
                               VIR_XML_PROP_NONE, &accel2d) < 0)
        return NULL;

    if (!rendernode &&
        accel3d == VIR_TRISTATE_BOOL_ABSENT &&
        accel2d == VIR_TRISTATE_BOOL_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                _("missing values for acceleration"));
        return NULL;
    }

    def = g_new0(virDomainVideoAccelDef, 1);

    if (rendernode)
        def->rendernode = virFileSanitizePath(rendernode);
    def->accel3d = accel3d;
    def->accel2d = accel2d;

    return g_steal_pointer(&def);
}

static virDomainVideoResolutionDef *
virDomainVideoResolutionDefParseXML(xmlNodePtr node)
{
    g_autofree virDomainVideoResolutionDef *def = NULL;

    def = g_new0(virDomainVideoResolutionDef, 1);

    if (virXMLPropUInt(node, "x", 10, VIR_XML_PROP_REQUIRED, &def->x) < 0)
        return NULL;

    if (virXMLPropUInt(node, "y", 10, VIR_XML_PROP_REQUIRED, &def->y) < 0)
        return NULL;

    return g_steal_pointer(&def);
}

static virDomainVideoDriverDef *
virDomainVideoDriverDefParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt)
{
    g_autofree virDomainVideoDriverDef *def = NULL;
    xmlNodePtr driver = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(driver = virXPathNode("./driver", ctxt)))
        return NULL;

    def = g_new0(virDomainVideoDriverDef, 1);

    if (virXMLPropEnum(driver, "vgaconf",
                       virDomainVideoVGAConfTypeFromString,
                       VIR_XML_PROP_NONE, &def->vgaconf) < 0)
        return NULL;

    return g_steal_pointer(&def);
}

static int
virDomainVideoModelDefParseXML(virDomainVideoDef *def,
                               xmlNodePtr node,
                               xmlXPathContextPtr ctxt)
{
    xmlNodePtr accel_node;
    xmlNodePtr res_node;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virTristateBool primary;

    ctxt->node = node;

    if (virXMLPropTristateBool(node, "primary", VIR_XML_PROP_NONE, &primary) >= 0)
        def->primary = (primary == VIR_TRISTATE_BOOL_YES);

    if ((accel_node = virXPathNode("./acceleration", ctxt)) &&
        (def->accel = virDomainVideoAccelDefParseXML(accel_node)) == NULL)
        return -1;

    if ((res_node = virXPathNode("./resolution", ctxt)) &&
        (def->res = virDomainVideoResolutionDefParseXML(res_node)) == NULL)
        return -1;

    if (virXMLPropEnumDefault(node, "type",
                              virDomainVideoTypeFromString,
                              VIR_XML_PROP_NONE, &def->type,
                              VIR_DOMAIN_VIDEO_TYPE_DEFAULT) < 0)
        return -1;

    if (virXMLPropUInt(node, "ram", 10, VIR_XML_PROP_NONE, &def->ram) < 0)
        return -1;

    if (virXMLPropUInt(node, "vram", 10, VIR_XML_PROP_NONE, &def->vram) < 0)
        return -1;

    if (virXMLPropUInt(node, "vram64", 10, VIR_XML_PROP_NONE, &def->vram64) < 0)
        return -1;

    if (virXMLPropUInt(node, "vgamem", 10, VIR_XML_PROP_NONE, &def->vgamem) < 0)
        return -1;

    if (virXMLPropUIntDefault(node, "heads", 10, VIR_XML_PROP_NONE, &def->heads, 1) < 0)
        return -1;

    if (virXMLPropTristateSwitch(node, "blob", VIR_XML_PROP_NONE, &def->blob) < 0)
        return -1;

    return 0;
}

static virDomainVideoDef *
virDomainVideoDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    g_autoptr(virDomainVideoDef) def = NULL;
    xmlNodePtr driver;
    xmlNodePtr model;

    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    if (!(def = virDomainVideoDefNew(xmlopt)))
        return NULL;

    ctxt->node = node;

    if ((model = virXPathNode("./model", ctxt))) {
        if (virDomainVideoModelDefParseXML(def, model, ctxt) < 0)
            return NULL;
    }

    if ((driver = virXPathNode("./driver", ctxt))) {
        if (virXMLPropEnum(driver, "name",
                           virDomainVideoBackendTypeFromString,
                           VIR_XML_PROP_NONZERO, &def->backend) < 0)
            return NULL;
        if (virDomainVirtioOptionsParseXML(driver, &def->virtio) < 0)
            return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        return NULL;

    def->driver = virDomainVideoDriverDefParseXML(node, ctxt);

    return g_steal_pointer(&def);
}

static virDomainHostdevDef *
virDomainHostdevDefParseXML(virDomainXMLOption *xmlopt,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            unsigned int flags)
{
    virDomainHostdevDef *def;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    unsigned int type;

    ctxt->node = node;

    if (!(def = virDomainHostdevDefNew()))
        goto error;

    if (virXMLPropEnumDefault(node, "mode", virDomainHostdevModeTypeFromString,
                              VIR_XML_PROP_NONE,
                              &def->mode,
                              VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) < 0)
        goto error;

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        /* parse managed/mode/type, and the <source> element */
        if (virXMLPropEnum(node, "type",
                           virDomainHostdevSubsysTypeFromString,
                           VIR_XML_PROP_REQUIRED, &type) < 0)
            goto error;
        if (virDomainHostdevDefParseXMLSubsys(node, ctxt, type, def, flags, xmlopt) < 0)
            goto error;
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        /* parse managed/mode/type, and the <source> element */
        if (virXMLPropEnum(node, "type",
                           virDomainHostdevCapsTypeFromString,
                           VIR_XML_PROP_REQUIRED, &type) < 0)
            goto error;

        if (virDomainHostdevDefParseXMLCaps(node, ctxt, type, def) < 0)
            goto error;
        break;
    default:
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected hostdev mode %1$d"), def->mode);
        goto error;
    }

    if (def->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, def->info,
                                        flags  | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT
                                        | VIR_DOMAIN_DEF_PARSE_ALLOW_ROM) < 0)
            goto error;
    }
    if (def->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        switch (def->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            if (virXPathBoolean("boolean(./readonly)", ctxt))
                def->readonly = true;
            if (virXPathBoolean("boolean(./shareable)", ctxt))
                def->shareable = true;
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
    }

    if (virDomainNetTeamingInfoParseXML(ctxt, &def->teaming) < 0)
        goto error;

    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


static virDomainRedirdevDef *
virDomainRedirdevDefParseXML(virDomainXMLOption *xmlopt,
                             xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             unsigned int flags)
{
    virDomainRedirdevDef *def;
    g_autofree char *bus = NULL;
    g_autofree char *type = NULL;

    def = g_new0(virDomainRedirdevDef, 1);

    if (!(def->source = virDomainChrSourceDefNew(xmlopt)))
        goto error;

    bus = virXMLPropString(node, "bus");
    if (bus) {
        if ((def->bus = virDomainRedirdevBusTypeFromString(bus)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown redirdev bus '%1$s'"), bus);
            goto error;
        }
    } else {
        def->bus = VIR_DOMAIN_REDIRDEV_BUS_USB;
    }

    type = virXMLPropString(node, "type");
    if (type) {
        if ((def->source->type = virDomainChrTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown redirdev character device type '%1$s'"), type);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing type in redirdev"));
        goto error;
    }

    /* boot gets parsed in virDomainDeviceInfoParseXML
     * source gets parsed in virDomainChrSourceDefParseXML */
    if (virDomainChrSourceDefParseXML(def->source, node, flags,
                                      NULL, ctxt) < 0)
        goto error;

    if (def->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC)
        def->source->data.spicevmc = VIR_DOMAIN_CHR_SPICEVMC_USBREDIR;
    if (def->source->type == VIR_DOMAIN_CHR_TYPE_DBUS && !def->source->data.dbus.channel)
        def->source->data.dbus.channel = g_strdup("org.qemu.usbredir");

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info,
                                    flags | VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT) < 0)
        goto error;

    if (def->bus == VIR_DOMAIN_REDIRDEV_BUS_USB &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        def->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid address for a USB device"));
        goto error;
    }

    return def;

 error:
    virDomainRedirdevDefFree(def);
    return NULL;
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
                                     virDomainRedirFilterUSBDevDef *def)
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
                   _("Cannot parse USB device version %1$s"), version);
    return -1;
}

static virDomainRedirFilterUSBDevDef *
virDomainRedirFilterUSBDevDefParseXML(xmlNodePtr node)
{
    g_autofree virDomainRedirFilterUSBDevDef *def = NULL;
    g_autofree char *version = NULL;
    virTristateBool allow;

    def = g_new0(virDomainRedirFilterUSBDevDef, 1);

    if (virXMLPropInt(node, "class", 0, VIR_XML_PROP_NONE, &def->usbClass, -1) < 0)
        return NULL;

    if (def->usbClass != -1 && def->usbClass &~ 0xFF) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid USB Class code 0x%1$x"), def->usbClass);
        return NULL;
    }

    if (virXMLPropInt(node, "vendor", 0, VIR_XML_PROP_NONE, &def->vendor, -1) < 0)
        return NULL;

    if (virXMLPropInt(node, "product", 0, VIR_XML_PROP_NONE, &def->product, -1) < 0)
        return NULL;

    version = virXMLPropString(node, "version");
    if (version) {
        if (STREQ(version, "-1"))
            def->version = -1;
        else if ((virDomainRedirFilterUSBVersionHelper(version, def)) < 0)
            return NULL;
    } else {
        def->version = -1;
    }

    if (virXMLPropTristateBool(node, "allow", VIR_XML_PROP_REQUIRED, &allow) < 0)
        return NULL;

    virTristateBoolToBool(allow, &def->allow);

    return g_steal_pointer(&def);
}

static virDomainRedirFilterDef *
virDomainRedirFilterDefParseXML(xmlNodePtr node,
                                xmlXPathContextPtr ctxt)
{
    int n;
    size_t i;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainRedirFilterDef *def = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    def = g_new0(virDomainRedirFilterDef, 1);

    ctxt->node = node;
    if ((n = virXPathNodeSet("./usbdev", ctxt, &nodes)) < 0)
        goto error;

    if (n)
        def->usbdevs = g_new0(virDomainRedirFilterUSBDevDef *, n);

    for (i = 0; i < n; i++) {
        virDomainRedirFilterUSBDevDef *usbdev =
            virDomainRedirFilterUSBDevDefParseXML(nodes[i]);

        if (!usbdev)
            goto error;
        def->usbdevs[def->nusbdevs++] = usbdev;
    }

    return def;

 error:
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
    g_autofree char *tmp = virXPathString(xpath, ctxt);

    if (tmp == NULL) {
        *val = defaultVal;
    } else {
        *val = convFunc(tmp);
        if (*val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown %1$s action: %2$s"), name, tmp);
            return -1;
        }
    }
    return 0;
}

static int
virDomainPMStateParseXML(xmlXPathContextPtr ctxt,
                         const char *xpath,
                         virTristateBool *val)
{
    xmlNodePtr node = virXPathNode(xpath, ctxt);

    return virXMLPropTristateBool(node, "enabled",
                                  VIR_XML_PROP_NONE,
                                  val);
}


static int
virDomainPerfEventDefParseXML(virDomainPerfDef *perf,
                              xmlNodePtr node)
{
    virPerfEventType name;
    virTristateBool enabled;

    if (virXMLPropEnum(node, "name", virPerfEventTypeFromString,
                       VIR_XML_PROP_REQUIRED, &name) < 0)
        return -1;

    if (virXMLPropTristateBool(node, "enabled", VIR_XML_PROP_REQUIRED, &enabled) < 0)
        return -1;

    if (perf->events[name] != VIR_TRISTATE_BOOL_ABSENT) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("perf event '%1$s' was already specified"),
                       virPerfEventTypeToString(name));
        return -1;
    }

    perf->events[name] = enabled;

    return 0;
}

static int
virDomainPerfDefParseXML(virDomainDef *def,
                         xmlXPathContextPtr ctxt)
{
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;

    if ((n = virXPathNodeSet("./perf/event", ctxt, &nodes)) < 0)
        return n;

    for (i = 0; i < n; i++) {
        if (virDomainPerfEventDefParseXML(&def->perf, nodes[i]) < 0)
            return -1;
    }

    return 0;
}

static int
virDomainMemorySourceDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainMemoryDef *def)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *nodemask = NULL;
    unsigned long long *pagesize;
    virBitmap **sourceNodes = NULL;

    ctxt->node = node;

    switch (def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:

        if (def->model == VIR_DOMAIN_MEMORY_MODEL_DIMM) {
            pagesize = &def->source.dimm.pagesize;
            sourceNodes = &def->source.dimm.nodes;
        } else {
            pagesize = &def->source.virtio_mem.pagesize;
            sourceNodes = &def->source.virtio_mem.nodes;
        }

        if (virDomainParseMemory("./pagesize", "./pagesize/@unit", ctxt,
                                 pagesize, false, false) < 0)
            return -1;

        if ((nodemask = virXPathString("string(./nodemask)", ctxt))) {
            if (virBitmapParse(nodemask, sourceNodes,
                               VIR_DOMAIN_CPUMASK_LEN) < 0)
                return -1;

            if (virBitmapIsAllClear(*sourceNodes)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'nodemask': %1$s"), nodemask);
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        def->source.nvdimm.path = virXPathString("string(./path)", ctxt);

        if (virDomainParseMemory("./alignsize", "./alignsize/@unit", ctxt,
                                 &def->source.nvdimm.alignsize, false, false) < 0)
            return -1;

        if (virXPathBoolean("boolean(./pmem)", ctxt))
            def->source.nvdimm.pmem = true;

        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        def->source.virtio_pmem.path = virXPathString("string(./path)", ctxt);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        if ((nodemask = virXPathString("string(./nodemask)", ctxt))) {
            if (virBitmapParse(nodemask, &def->source.sgx_epc.nodes,
                               VIR_DOMAIN_CPUMASK_LEN) < 0)
                return -1;

            if (virBitmapIsAllClear(def->source.sgx_epc.nodes)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'nodemask': %1$s"), nodemask);
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


static int
virDomainMemoryTargetDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainMemoryDef *def)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr addrNode = NULL;
    unsigned long long *addr;
    int rv;

    ctxt->node = node;

    if ((rv = virXPathInt("string(./node)", ctxt, &def->targetNode)) == -2 ||
        (rv == 0 && def->targetNode < 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid value of memory device node"));
        return -1;
    }

    if (virDomainParseMemory("./size", "./size/@unit", ctxt,
                             &def->size, true, false) < 0)
        return -1;

    switch (def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (virDomainParseMemory("./label/size", "./label/size/@unit", ctxt,
                                 &def->target.nvdimm.labelsize, false, false) < 0)
            return -1;

        if (def->target.nvdimm.labelsize && def->target.nvdimm.labelsize < 128) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("nvdimm label must be at least 128KiB"));
            return -1;
        }

        if (def->target.nvdimm.labelsize >= def->size) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("label size must be smaller than NVDIMM size"));
            return -1;
        }

        if (virXPathBoolean("boolean(./readonly)", ctxt))
            def->target.nvdimm.readonly = true;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        if (virDomainParseMemory("./block", "./block/@unit", ctxt,
                                 &def->target.virtio_mem.blocksize, false, false) < 0)
            return -1;

        if (virDomainParseMemory("./requested", "./requested/@unit", ctxt,
                                 &def->target.virtio_mem.requestedsize, false, false) < 0)
            return -1;

        addrNode = virXPathNode("./address", ctxt);
        addr = &def->target.virtio_mem.address;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        addrNode = virXPathNode("./address", ctxt);
        addr = &def->target.virtio_pmem.address;
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    if (addrNode &&
        virXMLPropULongLong(addrNode, "base", 16,
                            VIR_XML_PROP_NONE, addr) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainSEVDefParseXML(virDomainSEVDef *def,
                        xmlXPathContextPtr ctxt)
{
    int rc;

    if (virXMLPropTristateBool(ctxt->node, "kernelHashes", VIR_XML_PROP_NONE,
                               &def->kernel_hashes) < 0)
        return -1;

    if (virXPathUIntBase("string(./policy)", ctxt, 16, &def->policy) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("failed to get launch security policy"));
        return -1;
    }

    /* the following attributes are platform dependent and if missing, we can
     * autofill them from domain capabilities later
     */
    rc = virXPathUInt("string(./cbitpos)", ctxt, &def->cbitpos);
    if (rc == 0) {
        def->haveCbitpos = true;
    } else if (rc == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid format for launch security cbitpos"));
        return -1;
    }

    rc = virXPathUInt("string(./reducedPhysBits)", ctxt,
                      &def->reduced_phys_bits);
    if (rc == 0) {
        def->haveReducedPhysBits = true;
    } else if (rc == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Invalid format for launch security reduced-phys-bits"));
        return -1;
    }

    def->dh_cert = virXPathString("string(./dhCert)", ctxt);
    def->session = virXPathString("string(./session)", ctxt);

    return 0;
}


static virDomainSecDef *
virDomainSecDefParseXML(xmlNodePtr lsecNode,
                        xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virDomainSecDef) sec = g_new0(virDomainSecDef, 1);

    ctxt->node = lsecNode;

    if (virXMLPropEnum(lsecNode, "type", virDomainLaunchSecurityTypeFromString,
                       VIR_XML_PROP_NONZERO | VIR_XML_PROP_REQUIRED,
                       &sec->sectype) < 0)
        return NULL;

    switch ((virDomainLaunchSecurity) sec->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        if (virDomainSEVDefParseXML(&sec->data.sev, ctxt) < 0)
            return NULL;
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
    default:
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported launch security type '%1$s'"),
                       virDomainLaunchSecurityTypeToString(sec->sectype));
        return NULL;
    }

    return g_steal_pointer(&sec);
}


virDomainMemoryDef *
virDomainMemoryDefNew(virDomainMemoryModel model)
{
    virDomainMemoryDef *def = NULL;

    def = g_new0(virDomainMemoryDef, 1);
    def->model = model;
    /* initialize to value which marks that the user didn't specify it */
    def->targetNode = -1;

    return def;
}


static virDomainMemoryDef *
virDomainMemoryDefParseXML(virDomainXMLOption *xmlopt,
                           xmlNodePtr memdevNode,
                           xmlXPathContextPtr ctxt,
                           unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr node;
    g_autoptr(virDomainMemoryDef) def = NULL;
    virDomainMemoryModel model;
    g_autofree char *tmp = NULL;

    ctxt->node = memdevNode;

    if (virXMLPropEnum(memdevNode, "model", virDomainMemoryModelTypeFromString,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &model) < 0)
        return NULL;

    def = virDomainMemoryDefNew(model);

    if (virXMLPropEnum(memdevNode, "access", virDomainMemoryAccessTypeFromString,
                       VIR_XML_PROP_NONZERO, &def->access) < 0)
        return NULL;

    if (virXMLPropTristateBool(memdevNode, "discard", VIR_XML_PROP_NONE,
                               &def->discard) < 0)
        return NULL;

    /* Extract NVDIMM UUID. */
    if (def->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        (tmp = virXPathString("string(./uuid[1])", ctxt))) {
        def->target.nvdimm.uuid = g_new0(unsigned char, VIR_UUID_BUFLEN);

        if (virUUIDParse(tmp, def->target.nvdimm.uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            return NULL;
        }
    }

    /* source */
    if ((node = virXPathNode("./source", ctxt)) &&
        virDomainMemorySourceDefParseXML(node, ctxt, def) < 0)
        return NULL;

    /* target */
    if (!(node = virXPathNode("./target", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing <target> element for <memory> device"));
        return NULL;
    }

    if (virDomainMemoryTargetDefParseXML(node, ctxt, def) < 0)
        return NULL;

    if (virDomainDeviceInfoParseXML(xmlopt, memdevNode, ctxt,
                                    &def->info, flags) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static virDomainIOMMUDef *
virDomainIOMMUDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr driver;
    g_autoptr(virDomainIOMMUDef) iommu = NULL;

    ctxt->node = node;

    iommu = virDomainIOMMUDefNew();

    if (virXMLPropEnum(node, "model", virDomainIOMMUModelTypeFromString,
                       VIR_XML_PROP_REQUIRED, &iommu->model) < 0)
        return NULL;

    if ((driver = virXPathNode("./driver", ctxt))) {
        if (virXMLPropTristateSwitch(driver, "intremap", VIR_XML_PROP_NONE,
                                     &iommu->intremap) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(driver, "caching_mode", VIR_XML_PROP_NONE,
                                     &iommu->caching_mode) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(driver, "iotlb", VIR_XML_PROP_NONE,
                                     &iommu->iotlb) < 0)
            return NULL;

        if (virXMLPropTristateSwitch(driver, "eim", VIR_XML_PROP_NONE,
                                     &iommu->eim) < 0)
            return NULL;

        if (virXMLPropUInt(driver, "aw_bits", 10, VIR_XML_PROP_NONE,
                           &iommu->aw_bits) < 0)
            return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt,
                                    &iommu->info, flags) < 0)
        return NULL;

    return g_steal_pointer(&iommu);
}


static virDomainVsockDef *
virDomainVsockDefParseXML(virDomainXMLOption *xmlopt,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt,
                          unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr cid;
    g_autoptr(virDomainVsockDef) vsock = NULL;

    ctxt->node = node;

    if (!(vsock = virDomainVsockDefNew(xmlopt)))
        return NULL;

    if (virXMLPropEnum(node, "model", virDomainVsockModelTypeFromString,
                       VIR_XML_PROP_NONE, &vsock->model) < 0)
        return NULL;

    if ((cid = virXPathNode("./cid", ctxt))) {
        if (virXMLPropUInt(cid, "address", 10,
                           VIR_XML_PROP_NONZERO,
                           &vsock->guest_cid) < 0)
            return NULL;

        if (virXMLPropTristateBool(cid, "auto", VIR_XML_PROP_NONE,
                                   &vsock->auto_cid) < 0)
            return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &vsock->info, flags) < 0)
        return NULL;

    if (virDomainVirtioOptionsParseXML(virXPathNode("./driver", ctxt),
                                       &vsock->virtio) < 0)
        return NULL;


    return g_steal_pointer(&vsock);
}


static virDomainCryptoDef *
virDomainCryptoDefParseXML(virDomainXMLOption *xmlopt,
                           xmlNodePtr node,
                           xmlXPathContextPtr ctxt,
                           unsigned int flags)
{
    g_autoptr(virDomainCryptoDef) def = NULL;
    int nbackends;
    g_autofree xmlNodePtr *backends = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    def = g_new0(virDomainCryptoDef, 1);

    if (virXMLPropEnum(node, "model", virDomainCryptoModelTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->model) < 0) {
        return NULL;
    }


    if (virXMLPropEnum(node, "type", virDomainCryptoTypeTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->type) < 0) {
        return NULL;
    }

    ctxt->node = node;

    if ((nbackends = virXPathNodeSet("./backend", ctxt, &backends)) < 0)
        return NULL;

    if (nbackends != 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one crypto backend is supported"));
        return NULL;
    }

    if (virXMLPropEnum(backends[0], "model",
                       virDomainCryptoBackendTypeFromString,
                       VIR_XML_PROP_REQUIRED, &def->backend) < 0) {
        return NULL;
    }

    if (virXMLPropUInt(backends[0], "queues", 10,
                       VIR_XML_PROP_NONE, &def->queues) < 0) {
        return NULL;
    }

    if (virDomainDeviceInfoParseXML(xmlopt, node, ctxt, &def->info, flags) < 0)
        return NULL;

    if (virDomainVirtioOptionsParseXML(virXPathNode("./driver", ctxt),
                                       &def->virtio) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static int
virDomainDeviceDefParseType(const char *typestr,
                            virDomainDeviceType *type)
{
    int tmp;

    /* Mapping of serial, parallel, console and channel to VIR_DOMAIN_DEVICE_CHR. */
    if (STREQ(typestr, "channel") ||
        STREQ(typestr, "console") ||
        STREQ(typestr, "parallel") ||
        STREQ(typestr, "serial")) {
        *type = VIR_DOMAIN_DEVICE_CHR;
        return 0;
    }

    if ((tmp = virDomainDeviceTypeFromString(typestr)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown device type '%1$s'"), typestr);
        return -1;
    }

    *type = tmp;
    return 0;
}


virDomainDeviceDef *
virDomainDeviceDefParse(const char *xmlStr,
                        const virDomainDef *def,
                        virDomainXMLOption *xmlopt,
                        void *parseOpaque,
                        unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    xmlNodePtr node;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virDomainDeviceDef) dev = NULL;

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("(device_definition)"), &ctxt)))
        return NULL;

    node = ctxt->node;

    dev = g_new0(virDomainDeviceDef, 1);

    if (virDomainDeviceDefParseType((const char *)node->name, &dev->type) < 0)
        return NULL;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (!(dev->data.disk = virDomainDiskDefParseXML(xmlopt, node, ctxt,
                                                        flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
        if (!(dev->data.lease = virDomainLeaseDefParseXML(node, ctxt)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_FS:
        if (!(dev->data.fs = virDomainFSDefParseXML(xmlopt, node, ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (!(dev->data.net = virDomainNetDefParseXML(xmlopt, node, ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        if (!(dev->data.input = virDomainInputDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_SOUND:
        if (!(dev->data.sound = virDomainSoundDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_AUDIO:
        if (!(dev->data.audio = virDomainAudioDefParseXML(xmlopt, node, ctxt)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        if (!(dev->data.watchdog = virDomainWatchdogDefParseXML(xmlopt, node,
                                                                ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_VIDEO:
        if (!(dev->data.video = virDomainVideoDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (!(dev->data.hostdev = virDomainHostdevDefParseXML(xmlopt, node,
                                                              ctxt,
                                                              flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        if (!(dev->data.controller = virDomainControllerDefParseXML(xmlopt, node,
                                                                    ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if (!(dev->data.graphics = virDomainGraphicsDefParseXML(xmlopt, node,
                                                                ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_HUB:
        if (!(dev->data.hub = virDomainHubDefParseXML(xmlopt, node,
                                                      ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        if (!(dev->data.redirdev = virDomainRedirdevDefParseXML(xmlopt, node,
                                                                ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        if (!(dev->data.rng = virDomainRNGDefParseXML(xmlopt, node,
                                                      ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        if (!(dev->data.chr = virDomainChrDefParseXML(xmlopt,
                                                      ctxt,
                                                      node,
                                                      flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        if (!(dev->data.smartcard = virDomainSmartcardDefParseXML(xmlopt, node,
                                                                  ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        if (!(dev->data.memballoon = virDomainMemballoonDefParseXML(xmlopt,
                                                                    node,
                                                                    ctxt,
                                                                    flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_NVRAM:
        if (!(dev->data.nvram = virDomainNVRAMDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        if (!(dev->data.shmem = virDomainShmemDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_TPM:
        if (!(dev->data.tpm = virDomainTPMDefParseXML(xmlopt, node, ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_PANIC:
        if (!(dev->data.panic = virDomainPanicDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        if (!(dev->data.memory = virDomainMemoryDefParseXML(xmlopt, node,
                                                            ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_IOMMU:
        if (!(dev->data.iommu = virDomainIOMMUDefParseXML(xmlopt, node,
                                                          ctxt, flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_VSOCK:
        if (!(dev->data.vsock = virDomainVsockDefParseXML(xmlopt, node, ctxt,
                                                          flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_CRYPTO:
        if (!(dev->data.crypto = virDomainCryptoDefParseXML(xmlopt, node, ctxt,
                                                            flags)))
            return NULL;
        break;
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    /* callback to fill driver specific device aspects */
    if (virDomainDeviceDefPostParseOne(dev, def, flags,
                                       xmlopt, parseOpaque) < 0)
        return NULL;

    /* validate the configuration */
    if (virDomainDeviceDefValidate(dev, def, flags, xmlopt, parseOpaque) < 0)
        return NULL;

    return g_steal_pointer(&dev);
}


virDomainDiskDef *
virDomainDiskDefParse(const char *xmlStr,
                      virDomainXMLOption *xmlopt,
                      unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (!(xml = virXMLParse(NULL, xmlStr, _("(disk_definition)"),
                            "disk", &ctxt, NULL, false)))
        return NULL;

    return virDomainDiskDefParseXML(xmlopt, ctxt->node, ctxt, flags);
}


virStorageSource *
virDomainDiskDefParseSource(const char *xmlStr,
                            virDomainXMLOption *xmlopt,
                            unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virStorageSource) src = NULL;
    xmlNodePtr driverNode;

    if (!(xml = virXMLParse(NULL, xmlStr, _("(disk_definition)"),
                            "disk", &ctxt, NULL, false)))
        return NULL;

    if (!(src = virDomainDiskDefParseSourceXML(xmlopt, ctxt->node, ctxt, flags)))
        return NULL;

    if ((driverNode = virXPathNode("./driver", ctxt))) {
        if (virDomainDiskDefDriverSourceParseXML(src, driverNode, ctxt) < 0)
            return NULL;
    }

    if (virStorageSourceIsEmpty(src)) {
        virReportError(VIR_ERR_NO_SOURCE, NULL);
        return NULL;
    }

    if (virDomainDiskDefValidateSource(src) < 0)
        return NULL;

    return g_steal_pointer(&src);
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
virDomainHostdevInsert(virDomainDef *def, virDomainHostdevDef *hostdev)
{
    VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev);

    return 0;
}

virDomainHostdevDef *
virDomainHostdevRemove(virDomainDef *def, size_t i)
{
    virDomainHostdevDef *hostdev = def->hostdevs[i];

    VIR_DELETE_ELEMENT(def->hostdevs, i, def->nhostdevs);
    return hostdev;
}


static int
virDomainHostdevMatchSubsysUSB(virDomainHostdevDef *first,
                               virDomainHostdevDef *second)
{
    virDomainHostdevSubsysUSB *first_usbsrc = &first->source.subsys.u.usb;
    virDomainHostdevSubsysUSB *second_usbsrc = &second->source.subsys.u.usb;

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
virDomainHostdevMatchSubsysPCI(virDomainHostdevDef *first,
                               virDomainHostdevDef *second)
{
    virDomainHostdevSubsysPCI *first_pcisrc = &first->source.subsys.u.pci;
    virDomainHostdevSubsysPCI *second_pcisrc = &second->source.subsys.u.pci;

    if (first_pcisrc->addr.domain == second_pcisrc->addr.domain &&
        first_pcisrc->addr.bus == second_pcisrc->addr.bus &&
        first_pcisrc->addr.slot == second_pcisrc->addr.slot &&
        first_pcisrc->addr.function == second_pcisrc->addr.function)
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysSCSIHost(virDomainHostdevDef *first,
                                    virDomainHostdevDef *second)
{
    virDomainHostdevSubsysSCSIHost *first_scsihostsrc =
        &first->source.subsys.u.scsi.u.host;
    virDomainHostdevSubsysSCSIHost *second_scsihostsrc =
        &second->source.subsys.u.scsi.u.host;

    if (STREQ(first_scsihostsrc->adapter, second_scsihostsrc->adapter) &&
        first_scsihostsrc->bus == second_scsihostsrc->bus &&
        first_scsihostsrc->target == second_scsihostsrc->target &&
        first_scsihostsrc->unit == second_scsihostsrc->unit)
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysSCSIiSCSI(virDomainHostdevDef *first,
                                     virDomainHostdevDef *second)
{
    virDomainHostdevSubsysSCSIiSCSI *first_iscsisrc =
        &first->source.subsys.u.scsi.u.iscsi;
    virDomainHostdevSubsysSCSIiSCSI *second_iscsisrc =
        &second->source.subsys.u.scsi.u.iscsi;

    if (STREQ(first_iscsisrc->src->hosts[0].name, second_iscsisrc->src->hosts[0].name) &&
        first_iscsisrc->src->hosts[0].port == second_iscsisrc->src->hosts[0].port &&
        STREQ(first_iscsisrc->src->path, second_iscsisrc->src->path))
        return 1;
    return 0;
}

static int
virDomainHostdevMatchSubsysMediatedDev(virDomainHostdevDef *a,
                                       virDomainHostdevDef *b)
{
    virDomainHostdevSubsysMediatedDev *src_a = &a->source.subsys.u.mdev;
    virDomainHostdevSubsysMediatedDev *src_b = &b->source.subsys.u.mdev;

    if (STREQ(src_a->uuidstr, src_b->uuidstr))
        return 1;

    return 0;
}

static int
virDomainHostdevMatchSubsys(virDomainHostdevDef *a,
                            virDomainHostdevDef *b)
{
    if (a->source.subsys.type != b->source.subsys.type)
        return 0;

    switch (a->source.subsys.type) {
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
virDomainHostdevMatchCapsStorage(virDomainHostdevDef *a,
                                 virDomainHostdevDef *b)
{
    return STREQ_NULLABLE(a->source.caps.u.storage.block,
                          b->source.caps.u.storage.block);
}


static int
virDomainHostdevMatchCapsMisc(virDomainHostdevDef *a,
                              virDomainHostdevDef *b)
{
    return STREQ_NULLABLE(a->source.caps.u.misc.chardev,
                          b->source.caps.u.misc.chardev);
}

static int
virDomainHostdevMatchCapsNet(virDomainHostdevDef *a,
                              virDomainHostdevDef *b)
{
    return STREQ_NULLABLE(a->source.caps.u.net.ifname,
                          b->source.caps.u.net.ifname);
}


static int
virDomainHostdevMatchCaps(virDomainHostdevDef *a,
                          virDomainHostdevDef *b)
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
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
        break;
    }
    return 0;
}


int
virDomainHostdevMatch(virDomainHostdevDef *a,
                      virDomainHostdevDef *b)
{
    if (a->mode != b->mode)
        return 0;

    switch (a->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return virDomainHostdevMatchSubsys(a, b);
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return virDomainHostdevMatchCaps(a, b);
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        break;
    }
    return 0;
}

/* Find an entry in hostdevs that matches the source spec in
 * @match. return pointer to the entry in @found (if found is
 * non-NULL). Returns index (within hostdevs) of matched entry, or -1
 * if no match was found.
 */
int
virDomainHostdevFind(virDomainDef *def,
                     virDomainHostdevDef *match,
                     virDomainHostdevDef **found)
{
    virDomainHostdevDef *local_found;
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
virDomainDiskIndexByAddress(virDomainDef *def,
                            virPCIDeviceAddress *pci_address,
                            virCCWDeviceAddress *ccw_addr,
                            unsigned int bus, unsigned int target,
                            unsigned int unit)
{
    virDomainDiskDef *vdisk;
    virDomainControllerDef *controller = NULL;
    size_t i;
    int cidx;

    if ((cidx = virDomainControllerFindByPCIAddress(def, pci_address)) >= 0)
        controller = def->controllers[cidx];

    if (!controller && ccw_addr) {
        cidx = virDomainControllerFindByCCWAddress(def, ccw_addr);
        if (cidx >= 0)
            controller = def->controllers[cidx];
    }

    for (i = 0; i < def->ndisks; i++) {
        vdisk = def->disks[i];
        if (vdisk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            virPCIDeviceAddressEqual(&vdisk->info.addr.pci, pci_address))
            return i;
        if (vdisk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
            ccw_addr &&
            virCCWDeviceAddressEqual(&vdisk->info.addr.ccw, ccw_addr)) {
            return i;
        }
        if (vdisk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virDomainDeviceDriveAddress *drive = &vdisk->info.addr.drive;
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

virDomainDiskDef *
virDomainDiskByAddress(virDomainDef *def,
                       virPCIDeviceAddress *pci_address,
                       virCCWDeviceAddress *ccw_addr,
                       unsigned int bus,
                       unsigned int target,
                       unsigned int unit)
{
    int idx = virDomainDiskIndexByAddress(def, pci_address, ccw_addr,
                                          bus, target, unit);
    return idx < 0 ? NULL : def->disks[idx];
}

int
virDomainDiskIndexByName(virDomainDef *def, const char *name,
                         bool allow_ambiguous)
{
    virDomainDiskDef *vdisk;
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

virDomainDiskDef *
virDomainDiskByName(virDomainDef *def,
                    const char *name,
                    bool allow_ambiguous)
{
    int idx = virDomainDiskIndexByName(def, name, allow_ambiguous);

    if (idx < 0)
        return NULL;

    return def->disks[idx];
}


virDomainDiskDef *
virDomainDiskByTarget(virDomainDef *def,
                      const char *dst)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ(def->disks[i]->dst, dst))
            return def->disks[i];
    }

    return NULL;
}


void virDomainDiskInsert(virDomainDef *def,
                         virDomainDiskDef *disk)
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
            def->disks[idx]->dst && disk->dst &&
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

    ignore_value(VIR_INSERT_ELEMENT(def->disks, insertAt, def->ndisks, disk));
}


virDomainDiskDef *
virDomainDiskRemove(virDomainDef *def, size_t i)
{
    virDomainDiskDef *disk = def->disks[i];

    VIR_DELETE_ELEMENT(def->disks, i, def->ndisks);
    return disk;
}

virDomainDiskDef *
virDomainDiskRemoveByName(virDomainDef *def, const char *name)
{
    int idx = virDomainDiskIndexByName(def, name, false);
    if (idx < 0)
        return NULL;
    return virDomainDiskRemove(def, idx);
}

int virDomainNetInsert(virDomainDef *def, virDomainNetDef *net)
{
    /* hostdev net devices must also exist in the hostdevs array */
    if (net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        virDomainHostdevInsert(def, &net->data.hostdev.def) < 0)
        return -1;

    VIR_APPEND_ELEMENT(def->nets, def->nnets, net);
    return 0;
}

/**
 * virDomainNetFindIdx:
 * @def: domain definition
 * @net: interface definition
 *
 * Lookup domain's network interface based on passed @net
 * definition. If @net's MAC address was auto generated,
 * the MAC comparison is ignored.
 *
 * Return: index of match if unique match found,
 *         -1 otherwise and an error is logged.
 */
int
virDomainNetFindIdx(virDomainDef *def, virDomainNetDef *net)
{
    size_t i;
    int matchidx = -1;
    char mac[VIR_MAC_STRING_BUFLEN];
    bool MACAddrSpecified = !net->mac_generated;
    bool PCIAddrSpecified = virDomainDeviceAddressIsValid(&net->info,
                                                          VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI);
    bool CCWAddrSpecified = virDomainDeviceAddressIsValid(&net->info,
                                                          VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW);
    g_autofree char *addr = NULL;
    const char *macAddr = _("(<null>)");
    const char *alias = _("(<null>)");

    if (MACAddrSpecified)
        macAddr = virMacAddrFormat(&net->mac, mac);

    for (i = 0; i < def->nnets; i++) {
        if (MACAddrSpecified &&
            virMacAddrCmp(&def->nets[i]->mac, &net->mac) != 0)
            continue;

        if (PCIAddrSpecified &&
            !virPCIDeviceAddressEqual(&def->nets[i]->info.addr.pci,
                                      &net->info.addr.pci))
            continue;

        if (CCWAddrSpecified &&
            !virCCWDeviceAddressEqual(&def->nets[i]->info.addr.ccw,
                                      &net->info.addr.ccw))
            continue;

        if (net->info.alias && def->nets[i]->info.alias &&
            STRNEQ(def->nets[i]->info.alias, net->info.alias)) {
            continue;
        }

        if (matchidx >= 0) {
            /* there were multiple matches on mac address, and no
             * qualifying guest-side PCI/CCW address was given, so we must
             * fail (NB: a USB address isn't adequate, since it may
             * specify only vendor and product ID, and there may be
             * multiples of those.
             */
            if (MACAddrSpecified) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("multiple devices matching MAC address %1$s found"),
                               macAddr);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("multiple matching devices found"));
            }

            return -1;
        }

        matchidx = i;
    }

    if (matchidx >= 0)
        return matchidx;

    if (net->info.alias)
        alias = net->info.alias;

    if (CCWAddrSpecified)
        addr = virCCWDeviceAddressAsString(&net->info.addr.ccw);
    else if (PCIAddrSpecified)
        addr = virPCIDeviceAddressAsString(&net->info.addr.pci);
    else
        addr = g_strdup(_("(<null>)"));

    virReportError(VIR_ERR_DEVICE_MISSING,
                   _("no device found at address '%1$s' matching MAC address '%2$s' and alias '%3$s'"),
                   addr, macAddr, alias);
    return -1;
}

bool
virDomainHasNet(virDomainDef *def, virDomainNetDef *net)
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
virDomainNetRemoveHostdev(virDomainDef *def,
                          virDomainNetDef *net)
{
    /* hostdev net devices are normally in the hostdevs array, but
     * might have already been removed by the time we get here */
    virDomainHostdevDef *hostdev = virDomainNetGetActualHostdev(net);
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


virDomainNetDef *
virDomainNetRemove(virDomainDef *def, size_t i)
{
    virDomainNetDef *net = def->nets[i];

    virDomainNetRemoveHostdev(def, net);
    VIR_DELETE_ELEMENT(def->nets, i, def->nnets);
    return net;
}


virDomainNetDef *
virDomainNetRemoveByObj(virDomainDef *def, virDomainNetDef *net)
{
    size_t i;

    /* the device might have been added to hostdevs but not nets */
    virDomainNetRemoveHostdev(def, net);

    for (i = 0; i < def->nnets; i++) {
        if (def->nets[i] == net) {
            VIR_DELETE_ELEMENT(def->nets, i, def->nnets);
            break;
        }
    }
    return net;
}


int
virDomainNetUpdate(virDomainDef *def,
                   size_t netidx,
                   virDomainNetDef *newnet)
{
    size_t hostdevidx;
    virDomainNetDef *oldnet = def->nets[netidx];
    virDomainHostdevDef *oldhostdev = virDomainNetGetActualHostdev(oldnet);
    virDomainHostdevDef *newhostdev = virDomainNetGetActualHostdev(newnet);

    /*
     * if newnet or oldnet has a valid hostdev*, we need to update the
     * hostdevs list
     */
    if (oldhostdev) {
        for (hostdevidx = 0; hostdevidx < def->nhostdevs; hostdevidx++) {
            if (def->hostdevs[hostdevidx] == oldhostdev)
                break;
        }
    }

    if (oldhostdev && hostdevidx < def->nhostdevs) {
        if (newhostdev) {
            /* update existing entry in def->hostdevs */
            def->hostdevs[hostdevidx] = newhostdev;
        } else {
            /* delete oldhostdev from def->hostdevs */
            virDomainHostdevRemove(def, hostdevidx);
        }
    } else if (newhostdev) {
        /* add newhostdev to end of def->hostdevs */
        VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, newhostdev);
    }

    def->nets[netidx] = newnet;
    return 0;
}


int
virDomainNetDHCPInterfaces(virDomainDef *def,
                           virDomainInterfacePtr **ifaces)
{
    g_autoptr(virConnect) conn = NULL;
    virDomainInterfacePtr *ifaces_ret = NULL;
    size_t ifaces_count = 0;
    size_t i;

    if (!(conn = virGetConnectNetwork()))
        return -1;

    for (i = 0; i < def->nnets; i++) {
        g_autoptr(virNetwork) network = NULL;
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virNetworkDHCPLeasePtr *leases = NULL;
        int n_leases = 0;
        virDomainInterfacePtr iface = NULL;
        size_t j;

        if (def->nets[i]->type != VIR_DOMAIN_NET_TYPE_NETWORK)
            continue;

        virMacAddrFormat(&(def->nets[i]->mac), macaddr);

        network = virNetworkLookupByName(conn,
                                         def->nets[i]->data.network.name);
        if (!network)
            goto error;

        if ((n_leases = virNetworkGetDHCPLeases(network, macaddr,
                                                &leases, 0)) < 0)
            goto error;

        if (n_leases) {
            ifaces_ret = g_renew(virDomainInterfacePtr, ifaces_ret, ifaces_count + 1);
            ifaces_ret[ifaces_count] = g_new0(virDomainInterface, 1);
            iface = ifaces_ret[ifaces_count];
            ifaces_count++;

            /* Assuming each lease corresponds to a separate IP */
            iface->naddrs = n_leases;
            iface->addrs = g_new0(virDomainIPAddress, iface->naddrs);
            iface->name = g_strdup(def->nets[i]->ifname);
            iface->hwaddr = g_strdup(macaddr);
        }

        for (j = 0; j < n_leases; j++) {
            virNetworkDHCPLeasePtr lease = leases[j];
            virDomainIPAddressPtr ip_addr = &iface->addrs[j];

            ip_addr->addr = g_strdup(lease->ipaddr);
            ip_addr->type = lease->type;
            ip_addr->prefix = lease->prefix;

            virNetworkDHCPLeaseFree(lease);
        }

        VIR_FREE(leases);
    }

    *ifaces = g_steal_pointer(&ifaces_ret);
    return ifaces_count;

 error:
    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);

    return -1;
}


int
virDomainNetARPInterfaces(virDomainDef *def,
                          virDomainInterfacePtr **ifaces)
{
    size_t i, j;
    size_t ifaces_count = 0;
    int ret = -1;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    virDomainInterfacePtr *ifaces_ret = NULL;
    virDomainInterfacePtr iface = NULL;
    virArpTable *table;

    table = virArpTableGet();
    if (!table)
        goto cleanup;

    for (i = 0; i < def->nnets; i++) {
        virMacAddrFormat(&(def->nets[i]->mac), macaddr);
        for (j = 0; j < table->n; j++) {
            virArpTableEntry entry = table->t[j];

            if (STREQ(entry.mac, macaddr)) {
                iface = g_new0(virDomainInterface, 1);

                iface->name = g_strdup(def->nets[i]->ifname);

                iface->hwaddr = g_strdup(macaddr);

                iface->addrs = g_new0(virDomainIPAddress, 1);
                iface->naddrs = 1;

                iface->addrs->addr = g_strdup(entry.ipaddr);

                VIR_APPEND_ELEMENT(ifaces_ret, ifaces_count, iface);
            }
        }
    }

    *ifaces = g_steal_pointer(&ifaces_ret);
    ret = ifaces_count;

 cleanup:
    virArpTableFree(table);
    virDomainInterfaceFree(iface);

    if (ifaces_ret) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces_ret[i]);
    }
    VIR_FREE(ifaces_ret);

    return ret;
}


void virDomainControllerInsert(virDomainDef *def,
                              virDomainControllerDef *controller)
{
    def->controllers = g_renew(virDomainControllerDef *, def->controllers, def->ncontrollers + 1);
    virDomainControllerInsertPreAlloced(def, controller);
}

void virDomainControllerInsertPreAlloced(virDomainDef *def,
                                         virDomainControllerDef *controller)
{
    int idx;
    /* Tentatively plan to insert controller at the end. */
    int insertAt = -1;
    virDomainControllerDef *current = NULL;

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
                       _("Unknown controller type %1$d"),
                       type);
        return NULL;
    }

    contIndex = virDomainControllerFind(def, type, idx);
    if (contIndex < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find %1$s controller with index %2$d required for device"),
                       contTypeStr, idx);
        return NULL;
    }
    if (!def->controllers[contIndex]->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device alias was not set for %1$s controller with index %2$d"),
                       contTypeStr, idx);
        return NULL;
    }
    return def->controllers[contIndex]->info.alias;
}


int
virDomainControllerFindByType(virDomainDef *def,
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
virDomainControllerFindByCCWAddress(virDomainDef *def,
                                    virCCWDeviceAddress *addr)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainDeviceInfo *info = &def->controllers[i]->info;

        if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
            virCCWDeviceAddressEqual(&info->addr.ccw, addr))
            return i;
    }

    return -1;
}

int
virDomainControllerFindByPCIAddress(virDomainDef *def,
                                    virPCIDeviceAddress *addr)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainDeviceInfo *info = &def->controllers[i]->info;

        if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            virPCIDeviceAddressEqual(&info->addr.pci, addr))
            return i;
    }

    return -1;
}

virDomainControllerDef *
virDomainControllerRemove(virDomainDef *def, size_t i)
{
    virDomainControllerDef *controller = def->controllers[i];

    VIR_DELETE_ELEMENT(def->controllers, i, def->ncontrollers);
    return controller;
}

int virDomainLeaseIndex(virDomainDef *def,
                        virDomainLeaseDef *lease)
{
    virDomainLeaseDef *vlease;
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


void virDomainLeaseInsertPreAlloc(virDomainDef *def)
{
    VIR_EXPAND_N(def->leases, def->nleases, 1);
}

void virDomainLeaseInsert(virDomainDef *def, virDomainLeaseDef *lease)
{
    virDomainLeaseInsertPreAlloc(def);
    virDomainLeaseInsertPreAlloced(def, lease);
}


void virDomainLeaseInsertPreAlloced(virDomainDef *def,
                                    virDomainLeaseDef *lease)
{
    if (lease == NULL)
        VIR_SHRINK_N(def->leases, def->nleases, 1);
    else
        def->leases[def->nleases-1] = lease;
}


virDomainLeaseDef *
virDomainLeaseRemoveAt(virDomainDef *def, size_t i)
{
    virDomainLeaseDef *lease = def->leases[i];

    VIR_DELETE_ELEMENT(def->leases, i, def->nleases);
    return lease;
}


virDomainLeaseDef *
virDomainLeaseRemove(virDomainDef *def,
                     virDomainLeaseDef *lease)
{
    int idx = virDomainLeaseIndex(def, lease);
    if (idx < 0)
        return NULL;
    return virDomainLeaseRemoveAt(def, idx);
}

bool
virDomainChrEquals(virDomainChrDef *src,
                   virDomainChrDef *tgt)
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
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!src->target.addr || !tgt->target.addr)
                return src->target.addr == tgt->target.addr;
            return memcmp(src->target.addr, tgt->target.addr,
                          sizeof(*src->target.addr)) == 0;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST:
            /* shouldn't happen */
            break;
        }
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        if (src->targetType != tgt->targetType)
            return false;

        G_GNUC_FALLTHROUGH;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        return src->target.port == tgt->target.port;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* shouldn't happen */
        break;
    }
    return false;
}

virDomainChrDef *
virDomainChrFind(virDomainDef *def,
                 virDomainChrDef *target)
{
    virDomainChrDef *chr;
    const virDomainChrDef **arrPtr;
    size_t i, cnt;

    virDomainChrGetDomainPtrs(def, target->deviceType, &arrPtr, &cnt);

    for (i = 0; i < cnt; i++) {
        /* Cast away const */
        chr = (virDomainChrDef *) arrPtr[i];
        if (virDomainChrEquals(chr, target))
            return chr;
    }
    return NULL;
}


/* Return the address within vmdef to be modified when working with a
 * chrdefptr of the given type.  */
static int G_GNUC_WARN_UNUSED_RESULT
virDomainChrGetDomainPtrsInternal(virDomainDef *vmdef,
                                  virDomainChrDeviceType type,
                                  virDomainChrDef ****arrPtr,
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
                   _("Unknown char device type: %1$d"), type);
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
    if (virDomainChrGetDomainPtrsInternal((virDomainDef *) vmdef, type,
                                          &arrVar, &cntVar) < 0) {
        *arrPtr = NULL;
        *cntPtr = 0;
    } else {
        *arrPtr = (const virDomainChrDef **) *arrVar;
        *cntPtr = *cntVar;
    }
}


int
virDomainChrPreAlloc(virDomainDef *vmdef,
                     virDomainChrDef *chr)
{
    virDomainChrDef ***arrPtr = NULL;
    size_t *cntPtr = NULL;

    if (virDomainChrGetDomainPtrsInternal(vmdef, chr->deviceType,
                                          &arrPtr, &cntPtr) < 0)
        return -1;

    VIR_REALLOC_N(*arrPtr, *cntPtr + 1);
    return 0;
}

void
virDomainChrInsertPreAlloced(virDomainDef *vmdef,
                             virDomainChrDef *chr)
{
    virDomainChrDef ***arrPtr = NULL;
    size_t *cntPtr = NULL;

    if (virDomainChrGetDomainPtrsInternal(vmdef, chr->deviceType,
                                          &arrPtr, &cntPtr) < 0)
        return;

    VIR_APPEND_ELEMENT_INPLACE(*arrPtr, *cntPtr, chr);
}

virDomainChrDef *
virDomainChrRemove(virDomainDef *vmdef,
                   virDomainChrDef *chr)
{
    virDomainChrDef *ret = NULL;
    virDomainChrDef ***arrPtr = NULL;
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
virDomainRNGFind(virDomainDef *def,
                 virDomainRNGDef *rng)
{
    size_t i;

    for (i = 0; i < def->nrngs; i++) {
        virDomainRNGDef *tmp = def->rngs[i];

        if (rng->model != tmp->model || rng->backend != tmp->backend)
            continue;

        if (rng->rate != tmp->rate || rng->period != tmp->period)
            continue;

        switch (rng->backend) {
        case VIR_DOMAIN_RNG_BACKEND_RANDOM:
            if (STRNEQ_NULLABLE(rng->source.file, tmp->source.file))
                continue;
            break;

        case VIR_DOMAIN_RNG_BACKEND_EGD:
            if (!virDomainChrSourceDefIsEqual(rng->source.chardev,
                                              tmp->source.chardev))
                continue;
            break;

        case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
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


virDomainRNGDef *
virDomainRNGRemove(virDomainDef *def,
                   size_t idx)
{
    virDomainRNGDef *ret = def->rngs[idx];

    VIR_DELETE_ELEMENT(def->rngs, idx, def->nrngs);

    return ret;
}


static int
virDomainMemoryFindByDefInternal(virDomainDef *def,
                                 virDomainMemoryDef *mem,
                                 bool allowAddressFallback)
{
    size_t i;

    for (i = 0; i < def->nmems; i++) {
        virDomainMemoryDef *tmp = def->mems[i];

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

        switch (mem->model) {
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
            if (tmp->source.dimm.pagesize != mem->source.dimm.pagesize)
                continue;

            if (!virBitmapEqual(tmp->source.dimm.nodes,
                                mem->source.dimm.nodes))
                continue;
            break;
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
            if (tmp->source.virtio_mem.pagesize != mem->source.virtio_mem.pagesize ||
                tmp->target.virtio_mem.blocksize != mem->target.virtio_mem.blocksize ||
                tmp->target.virtio_mem.requestedsize != mem->target.virtio_mem.requestedsize ||
                tmp->target.virtio_mem.address != mem->target.virtio_mem.address)
                continue;

            if (!virBitmapEqual(tmp->source.virtio_mem.nodes,
                                mem->source.virtio_mem.nodes))
                continue;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
            if (STRNEQ(tmp->source.nvdimm.path, mem->source.nvdimm.path))
                continue;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
            if (STRNEQ(tmp->source.virtio_pmem.path,
                       mem->source.virtio_pmem.path) ||
                tmp->target.virtio_pmem.address != mem->target.virtio_pmem.address)
                continue;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
            if (!virBitmapEqual(tmp->source.sgx_epc.nodes,
                                mem->source.sgx_epc.nodes))
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
virDomainMemoryFindByDef(virDomainDef *def,
                         virDomainMemoryDef *mem)
{
    return virDomainMemoryFindByDefInternal(def, mem, false);
}


int
virDomainMemoryFindInactiveByDef(virDomainDef *def,
                                 virDomainMemoryDef *mem)
{
    int ret;

    if ((ret = virDomainMemoryFindByDefInternal(def, mem, false)) < 0)
        ret = virDomainMemoryFindByDefInternal(def, mem, true);

    return ret;
}


/**
 * virDomainMemoryFindByDeviceInfo:
 * @def: domain definition
 * @info: device info to match
 * @pos: store position within array
 *
 * For given domain definition @def find <memory/> device with
 * matching address and matching device alias (if set in @info,
 * otherwise ignored).
 *
 * If @pos is not NULL then the position of the matched device
 * within the array is stored there.
 *
 * Returns: device if found,
 *          NULL otherwise.
 */
virDomainMemoryDef *
virDomainMemoryFindByDeviceInfo(virDomainDef *def,
                                virDomainDeviceInfo *info,
                                int *pos)
{
    size_t i;

    for (i = 0; i < def->nmems; i++) {
        virDomainMemoryDef *tmp = def->mems[i];

        if (!virDomainDeviceInfoAddressIsEqual(&tmp->info, info))
            continue;

        /* alias, if present */
        if (info->alias &&
            STRNEQ_NULLABLE(tmp->info.alias, info->alias))
            continue;

        if (pos)
            *pos = i;

        return tmp;
    }

    return NULL;
}


virDomainMemoryDef *
virDomainMemoryFindByDeviceAlias(virDomainDef *def,
                                 const char *alias)
{
    size_t i;

    for (i = 0; i < def->nmems; i++) {
        virDomainMemoryDef *tmp = def->mems[i];

        if (STREQ_NULLABLE(tmp->info.alias, alias))
            return tmp;
    }

    return NULL;
}


/**
 * virDomainMemoryInsert:
 *
 * Inserts a memory device definition into the domain definition. This helper
 * should be used only in hot/cold-plug cases as it's blindly modifying the
 * total memory size.
 */
int
virDomainMemoryInsert(virDomainDef *def,
                      virDomainMemoryDef *mem)
{
    unsigned long long memory = virDomainDefGetMemoryTotal(def);
    int id = def->nmems;

    if (mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        virDomainDefHasDeviceAddress(def, &mem->info)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain already contains a device with the same address"));
        return -1;
    }

    VIR_APPEND_ELEMENT_COPY(def->mems, def->nmems, mem);

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
virDomainMemoryDef *
virDomainMemoryRemove(virDomainDef *def,
                      int idx)
{
    unsigned long long memory = virDomainDefGetMemoryTotal(def);
    virDomainMemoryDef *ret = def->mems[idx];

    VIR_DELETE_ELEMENT(def->mems, idx, def->nmems);

    /* fix total memory size of the domain */
    virDomainDefSetMemoryTotal(def, memory - ret->size);

    return ret;
}


ssize_t
virDomainRedirdevDefFind(virDomainDef *def,
                         virDomainRedirdevDef *redirdev)
{
    size_t i;

    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDef *tmp = def->redirdevs[i];

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


virDomainRedirdevDef *
virDomainRedirdevDefRemove(virDomainDef *def, size_t idx)
{
    virDomainRedirdevDef *ret = def->redirdevs[idx];

    VIR_DELETE_ELEMENT(def->redirdevs, idx, def->nredirdevs);

    return ret;
}


int
virDomainShmemDefInsert(virDomainDef *def,
                        virDomainShmemDef *shmem)
{
    VIR_APPEND_ELEMENT(def->shmems, def->nshmems, shmem);

    return 0;
}


bool
virDomainShmemDefEquals(virDomainShmemDef *src,
                        virDomainShmemDef *dst)
{
    if (STRNEQ_NULLABLE(src->name, dst->name))
        return false;

    if (src->size != dst->size)
        return false;

    if (src->model != dst->model)
        return false;

    if (src->role != dst->role)
        return false;

    if (src->server.enabled != dst->server.enabled)
        return false;

    if (src->server.enabled) {
        if (STRNEQ_NULLABLE(src->server.chr->data.nix.path,
                            dst->server.chr->data.nix.path))
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
virDomainShmemDefFind(virDomainDef *def,
                      virDomainShmemDef *shmem)
{
    size_t i;

    for (i = 0; i < def->nshmems; i++) {
        if (virDomainShmemDefEquals(shmem, def->shmems[i]))
            return i;
    }

    return -1;
}


virDomainShmemDef *
virDomainShmemDefRemove(virDomainDef *def,
                        size_t idx)
{
    virDomainShmemDef *ret = def->shmems[idx];

    VIR_DELETE_ELEMENT(def->shmems, idx, def->nshmems);

    return ret;
}


static bool
virDomainInputDefEquals(const virDomainInputDef *a,
                        const virDomainInputDef *b)
{
    if (a->type != b->type)
        return false;

    if (a->bus != b->bus)
        return false;

    if (a->type == VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH &&
        STRNEQ_NULLABLE(a->source.evdev, b->source.evdev))
        return false;

    if (a->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        !virDomainDeviceInfoAddressIsEqual(&a->info, &b->info))
        return false;

    return true;
}


ssize_t
virDomainInputDefFind(const virDomainDef *def,
                      const virDomainInputDef *input)
{
    size_t i;

    for (i = 0; i < def->ninputs; i++) {
        if (virDomainInputDefEquals(input, def->inputs[i]))
            return i;
    }

    return -1;
}


bool
virDomainVsockDefEquals(const virDomainVsockDef *a,
                        const virDomainVsockDef *b)
{
    if (a->model != b->model)
        return false;

    if (a->auto_cid != b->auto_cid)
        return false;

    if (a->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        !virDomainDeviceInfoAddressIsEqual(&a->info, &b->info))
        return false;

    return true;
}


char *
virDomainDefGetDefaultEmulator(virDomainDef *def,
                               virCaps *caps)
{
    char *retemu;
    g_autofree virCapsDomainData *capsdata = NULL;

    if (!(capsdata = virCapabilitiesDomainDataLookup(caps, def->os.type,
            def->os.arch, def->virtType, NULL, NULL)))
        return NULL;

    retemu = g_strdup(capsdata->emulator);

    return retemu;
}

static int
virDomainDefParseBootXML(xmlXPathContextPtr ctxt,
                         virDomainDef *def)
{
    xmlNodePtr node;
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;

    /* analysis of the boot devices */
    if ((n = virXPathNodeSet("./os/boot", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n && i < VIR_DOMAIN_BOOT_LAST; i++) {
        if (virXMLPropEnum(nodes[i], "dev",
                           virDomainBootTypeFromString,
                           VIR_XML_PROP_REQUIRED,
                           &def->os.bootDevs[def->os.nBootDevs]) < 0)
            return -1;

        def->os.nBootDevs++;
    }

    if ((node = virXPathNode("./os/bootmenu[1]", ctxt))) {
        if (virXMLPropTristateBool(node, "enable",
                                   VIR_XML_PROP_NONE,
                                   &def->os.bootmenu) < 0)
            return -1;

        if (def->os.bootmenu == VIR_TRISTATE_BOOL_YES) {
            int rv;

            if ((rv = virXMLPropUInt(node, "timeout", 10,
                                     VIR_XML_PROP_NONE,
                                     &def->os.bm_timeout)) < 0) {
                return -1;
            } else if (rv > 0) {
                def->os.bm_timeout_set = true;
            }
        }
    }

    if ((node = virXPathNode("./os/bios[1]", ctxt))) {
        int rv;

        if (virXMLPropTristateBool(node, "useserial",
                                   VIR_XML_PROP_NONE,
                                   &def->os.bios.useserial) < 0) {
            def->os.bios.useserial = VIR_TRISTATE_BOOL_NO;
        }

        if ((rv = virXMLPropInt(node, "rebootTimeout", 10,
                                VIR_XML_PROP_NONE,
                                &def->os.bios.rt_delay, 0)) < 0) {
            return -1;
        } else if (rv > 0) {
            def->os.bios.rt_set = true;
        }
    }

    return 0;
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
static virDomainIdMapEntry *
virDomainIdmapDefParseXML(xmlXPathContextPtr ctxt,
                          xmlNodePtr *node,
                          size_t num)
{
    size_t i;
    virDomainIdMapEntry *idmap = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    idmap = g_new0(virDomainIdMapEntry, num);

    for (i = 0; i < num; i++) {
        ctxt->node = node[i];
        if (virXPathUInt("string(./@start)", ctxt, &idmap[i].start) < 0 ||
            virXPathUInt("string(./@target)", ctxt, &idmap[i].target) < 0 ||
            virXPathUInt("string(./@count)", ctxt, &idmap[i].count) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid idmap start/target/count settings"));
            VIR_FREE(idmap);
            return NULL;
        }
    }

    qsort(idmap, num, sizeof(idmap[0]), virDomainIdMapEntrySort);

    return idmap;
}

/* Parse the XML definition for an IOThread ID
 *
 * Format is :
 *
 *     <iothreads>4</iothreads>
 *     <iothreadids>
 *       <iothread id='1' thread_pool_min="0" thread_pool_max="60"/>
 *       <iothread id='3'/>
 *       <iothread id='5'/>
 *       <iothread id='7'/>
 *     </iothreadids>
 *     <defaultiothread thread_pool_min="8" thread_pool_max="8"/>
 */
static virDomainIOThreadIDDef *
virDomainIOThreadIDDefParseXML(xmlNodePtr node)
{
    g_autoptr(virDomainIOThreadIDDef) iothrid = virDomainIOThreadIDDefNew();
    xmlNodePtr pollNode;

    if (virXMLPropUInt(node, "id", 10,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &iothrid->iothread_id) < 0)
        return NULL;

    if (virXMLPropInt(node, "thread_pool_min", 10,
                      VIR_XML_PROP_NONNEGATIVE,
                      &iothrid->thread_pool_min, -1) < 0)
        return NULL;

    if (virXMLPropInt(node, "thread_pool_max", 10,
                      VIR_XML_PROP_NONNEGATIVE,
                      &iothrid->thread_pool_max, -1) < 0)
        return NULL;

    if ((pollNode = virXMLNodeGetSubelement(node, "poll"))) {
        int rc;

        if ((rc = virXMLPropULongLong(pollNode, "max", 10, VIR_XML_PROP_NONE,
                                      &iothrid->poll_max_ns)) < 0)
            return NULL;

        iothrid->set_poll_max_ns = rc == 1;

        if ((rc = virXMLPropULongLong(pollNode, "grow", 10, VIR_XML_PROP_NONE,
                                      &iothrid->poll_grow)) < 0)
            return NULL;

        iothrid->set_poll_grow = rc == 1;

        if ((rc = virXMLPropULongLong(pollNode, "shrink", 10, VIR_XML_PROP_NONE,
                                      &iothrid->poll_shrink)) < 0)
            return NULL;

        iothrid->set_poll_shrink = rc == 1;
    }

    return g_steal_pointer(&iothrid);
}


static int
virDomainDefaultIOThreadDefParse(virDomainDef *def,
                                 xmlXPathContextPtr ctxt)
{
    xmlNodePtr node = NULL;
    g_autofree virDomainDefaultIOThreadDef *thrd = NULL;

    node = virXPathNode("./defaultiothread", ctxt);
    if (!node)
        return 0;

    thrd = g_new0(virDomainDefaultIOThreadDef, 1);

    if (virXMLPropInt(node, "thread_pool_min", 10,
                      VIR_XML_PROP_NONNEGATIVE,
                      &thrd->thread_pool_min, -1) < 0)
        return -1;

    if (virXMLPropInt(node, "thread_pool_max", 10,
                      VIR_XML_PROP_NONNEGATIVE,
                      &thrd->thread_pool_max, -1) < 0)
        return -1;

    if (thrd->thread_pool_min == -1 &&
        thrd->thread_pool_max == -1)
        return 0;

    def->defaultIOThread = g_steal_pointer(&thrd);
    return 0;
}


static int
virDomainDefParseIOThreads(virDomainDef *def,
                           xmlXPathContextPtr ctxt)
{
    size_t i;
    int n = 0;
    unsigned int iothreads = 0;
    g_autofree char *tmp = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    tmp = virXPathString("string(./iothreads[1])", ctxt);
    if (tmp && virStrToLong_uip(tmp, NULL, 10, &iothreads) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid iothreads count '%1$s'"), tmp);
        return -1;
    }

    if (virDomainDefaultIOThreadDefParse(def, ctxt) < 0)
        return -1;

    /* Extract any iothread id's defined */
    if ((n = virXPathNodeSet("./iothreadids/iothread", ctxt, &nodes)) < 0)
        return -1;

    if (n > iothreads)
        iothreads = n;

    if (n)
        def->iothreadids = g_new0(virDomainIOThreadIDDef *, n);

    for (i = 0; i < n; i++) {
        g_autoptr(virDomainIOThreadIDDef) iothrid = NULL;

        if (!(iothrid = virDomainIOThreadIDDefParseXML(nodes[i])))
            return -1;

        if (virDomainIOThreadIDFind(def, iothrid->iothread_id)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("duplicate iothread id '%1$u' found"),
                           iothrid->iothread_id);
            return -1;
        }
        def->iothreadids[def->niothreadids++] = g_steal_pointer(&iothrid);
    }

    return virDomainIOThreadIDDefArrayInit(def, iothreads);
}


/* Parse the XML definition for a vcpupin
 *
 * vcpupin has the form of
 *   <vcpupin vcpu='0' cpuset='0'/>
 */
static int
virDomainVcpuPinDefParseXML(virDomainDef *def,
                            xmlNodePtr node)
{
    virDomainVcpuDef *vcpu;
    unsigned int vcpuid;
    g_autofree char *tmp = NULL;

    if (virXMLPropUInt(node, "vcpu", 10, VIR_XML_PROP_REQUIRED, &vcpuid) < 0)
        return -1;

    if (!(vcpu = virDomainDefGetVcpu(def, vcpuid))) {
        VIR_WARN("Ignoring vcpupin for missing vcpus");
        return 0;
    }

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for vcpupin"));
        return -1;
    }

    if (vcpu->cpumask) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("duplicate vcpupin for vcpu '%1$d'"), vcpuid);
        return -1;
    }

    if (virBitmapParse(tmp, &vcpu->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
        return -1;

    if (virBitmapIsAllClear(vcpu->cpumask)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %1$s"), tmp);
        return -1;
    }

    return 0;
}


/* Parse the XML definition for a iothreadpin
 * and an iothreadspin has the form
 *   <iothreadpin iothread='1' cpuset='2'/>
 */
static int
virDomainIOThreadPinDefParseXML(xmlNodePtr node,
                                virDomainDef *def)
{
    virDomainIOThreadIDDef *iothrid;
    unsigned int iothreadid;
    g_autofree char *tmp = NULL;
    g_autoptr(virBitmap) cpumask = NULL;

    if (virXMLPropUInt(node, "iothread", 10,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       &iothreadid) < 0)
        return -1;

    if (!(iothrid = virDomainIOThreadIDFind(def, iothreadid))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot find 'iothread' : %1$u"),
                       iothreadid);
        return -1;
    }

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for iothreadpin"));
        return -1;
    }

    if (virBitmapParse(tmp, &cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
        return -1;

    if (virBitmapIsAllClear(cpumask)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %1$s"),
                       tmp);
        return -1;
    }

    if (iothrid->cpumask) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("duplicate iothreadpin for same iothread '%1$u'"),
                       iothreadid);
        return -1;
    }

    iothrid->cpumask = g_steal_pointer(&cpumask);
    return 0;
}


/* Parse the XML definition for emulatorpin.
 * emulatorpin has the form of
 *   <emulatorpin cpuset='0'/>
 */
static virBitmap *
virDomainEmulatorPinDefParseXML(xmlNodePtr node)
{
    g_autofree char *tmp = NULL;
    g_autoptr(virBitmap) def = NULL;

    if (!(tmp = virXMLPropString(node, "cpuset"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuset for emulatorpin"));
        return NULL;
    }

    if (virBitmapParse(tmp, &def, VIR_DOMAIN_CPUMASK_LEN) < 0)
        return NULL;

    if (virBitmapIsAllClear(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid value of 'cpuset': %1$s"), tmp);
        return NULL;
    }

    return g_steal_pointer(&def);
}


virDomainControllerDef *
virDomainDefAddController(virDomainDef *def,
                          virDomainControllerType type,
                          int idx,
                          int model)
{
    virDomainControllerDef *cont;

    if (!(cont = virDomainControllerDefNew(type)))
        return NULL;

    if (idx < 0)
        idx = virDomainControllerFindUnusedIndex(def, type);

    cont->idx = idx;
    cont->model = model;

    VIR_APPEND_ELEMENT_COPY(def->controllers, def->ncontrollers, cont);

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
virDomainDefAddUSBController(virDomainDef *def, int idx, int model)
{
    virDomainControllerDef *cont; /* this is a *copy* of the virDomainControllerDef */

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
virDomainDefMaybeAddController(virDomainDef *def,
                               virDomainControllerType type,
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
virDomainDefMaybeAddInput(virDomainDef *def,
                          int type,
                          int bus)
{
    size_t i;
    virDomainInputDef *input;

    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->type == type &&
            def->inputs[i]->bus == bus)
            return 0;
    }

    input = g_new0(virDomainInputDef, 1);

    input->type = type;
    input->bus = bus;

    VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input);

    return 0;
}


static int
virDomainHugepagesParseXML(xmlNodePtr node,
                           xmlXPathContextPtr ctxt,
                           virDomainHugePage *hugepage)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *nodeset = NULL;

    ctxt->node = node;

    if (virDomainParseMemory("./@size", "./@unit", ctxt,
                             &hugepage->size, true, false) < 0)
        return -1;

    if (!hugepage->size) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("hugepage size can't be zero"));
        return -1;
    }

    if ((nodeset = virXMLPropString(node, "nodeset"))) {
        if (virBitmapParse(nodeset, &hugepage->nodemask,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;

        if (virBitmapIsAllClear(hugepage->nodemask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value of 'nodeset': %1$s"), nodeset);
            return -1;
        }
    }

    return 0;
}


static virDomainResourceDef *
virDomainResourceDefParse(xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainResourceDef *def = NULL;
    char *partition = NULL;
    char *appid = NULL;

    ctxt->node = node;

    partition = virXPathString("string(./partition)", ctxt);
    appid = virXPathString("string(./fibrechannel/@appid)", ctxt);

    if (!partition && !appid)
        return NULL;

    def = g_new0(virDomainResourceDef, 1);
    def->partition = partition;
    def->appid = appid;

    return def;
}


static int
virDomainFeaturesHyperVDefParse(virDomainDef *def,
                                xmlNodePtr node)
{
    virDomainHyperVMode mode;

    if (virXMLPropEnumDefault(node, "mode", virDomainHyperVModeTypeFromString,
                              VIR_XML_PROP_NONZERO, &mode,
                              VIR_DOMAIN_HYPERV_MODE_CUSTOM) < 0)
        return -1;

    def->features[VIR_DOMAIN_FEATURE_HYPERV] = mode;

    node = xmlFirstElementChild(node);
    while (node != NULL) {
        int feature;
        virTristateSwitch value;
        xmlNodePtr child;

        feature = virDomainHypervTypeFromString((const char *)node->name);
        if (feature < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported HyperV Enlightenment feature: %1$s"),
                           node->name);
            return -1;
        }

        if (virXMLPropTristateSwitch(node, "state", VIR_XML_PROP_REQUIRED,
                                     &value) < 0)
            return -1;

        def->hyperv_features[feature] = value;

        switch ((virDomainHyperv) feature) {
        case VIR_DOMAIN_HYPERV_RELAXED:
        case VIR_DOMAIN_HYPERV_VAPIC:
        case VIR_DOMAIN_HYPERV_VPINDEX:
        case VIR_DOMAIN_HYPERV_RUNTIME:
        case VIR_DOMAIN_HYPERV_SYNIC:
        case VIR_DOMAIN_HYPERV_RESET:
        case VIR_DOMAIN_HYPERV_FREQUENCIES:
        case VIR_DOMAIN_HYPERV_REENLIGHTENMENT:
        case VIR_DOMAIN_HYPERV_TLBFLUSH:
        case VIR_DOMAIN_HYPERV_IPI:
        case VIR_DOMAIN_HYPERV_EVMCS:
        case VIR_DOMAIN_HYPERV_AVIC:
            break;

        case VIR_DOMAIN_HYPERV_STIMER:
            if (value != VIR_TRISTATE_SWITCH_ON)
                break;

            child = xmlFirstElementChild(node);
            while (child) {
                if (STRNEQ((const char *)child->name, "direct")) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported Hyper-V stimer feature: %1$s"),
                                   child->name);
                    return -1;
                }

                if (virXMLPropTristateSwitch(child, "state", VIR_XML_PROP_REQUIRED,
                                             &def->hyperv_stimer_direct) < 0)
                    return -1;

                child = xmlNextElementSibling(child);
            }
            break;

        case VIR_DOMAIN_HYPERV_SPINLOCKS:
            if (value != VIR_TRISTATE_SWITCH_ON)
                break;

            if (virXMLPropUInt(node, "retries", 0, VIR_XML_PROP_REQUIRED,
                               &def->hyperv_spinlocks) < 0)
                return -1;

            if (def->hyperv_spinlocks < 0xFFF) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("HyperV spinlock retry count must be at least 4095"));
                return -1;
            }
            break;

        case VIR_DOMAIN_HYPERV_VENDOR_ID:
            if (value != VIR_TRISTATE_SWITCH_ON)
                break;

            if (!(def->hyperv_vendor_id = virXMLPropString(node, "value"))) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("missing 'value' attribute for HyperV feature 'vendor_id'"));
                return -1;
            }

            if (!STRLIM(def->hyperv_vendor_id, VIR_DOMAIN_HYPERV_VENDOR_ID_MAX)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("HyperV vendor_id value must not be more than %1$d characters."),
                               VIR_DOMAIN_HYPERV_VENDOR_ID_MAX);
                return -1;
            }

            /* ensure that the string can be passed to qemu */
            if (strchr(def->hyperv_vendor_id, ',')) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("HyperV vendor_id value is invalid"));
                return -1;
            }
            break;

        case VIR_DOMAIN_HYPERV_LAST:
            break;
        }

        node = xmlNextElementSibling(node);
    }

    return 0;
}


static int
virDomainFeaturesKVMDefParse(virDomainDef *def,
                             xmlNodePtr node)
{
    g_autofree virDomainFeatureKVM *kvm = g_new0(virDomainFeatureKVM, 1);
    g_autofree xmlNodePtr *feats = NULL;
    size_t nfeats = virXMLNodeGetSubelementList(node, NULL, &feats);
    size_t i;

    for (i = 0; i < nfeats; i++) {
        int feature;
        virTristateSwitch value;

        feature = virDomainKVMTypeFromString((const char *)feats[i]->name);
        if (feature < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported KVM feature: %1$s"),
                           feats[i]->name);
            return -1;
        }

        if (virXMLPropTristateSwitch(feats[i], "state", VIR_XML_PROP_REQUIRED,
                                     &value) < 0)
            return -1;

        kvm->features[feature] = value;

        /* dirty ring feature should parse size property */
        if (feature == VIR_DOMAIN_KVM_DIRTY_RING &&
            value == VIR_TRISTATE_SWITCH_ON) {

            if (virXMLPropUInt(feats[i], "size", 0, VIR_XML_PROP_REQUIRED,
                               &kvm->dirty_ring_size) < 0) {
                return -1;
            }

            if (!VIR_IS_POW2(kvm->dirty_ring_size) ||
                kvm->dirty_ring_size < 1024 ||
                kvm->dirty_ring_size > 65536) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("dirty ring must be power of 2 and ranges [1024, 65536]"));

                return -1;
            }
        }
    }

    def->features[VIR_DOMAIN_FEATURE_KVM] = VIR_TRISTATE_SWITCH_ON;
    def->kvm_features = g_steal_pointer(&kvm);

    return 0;
}


static int
virDomainFeaturesXENDefParse(virDomainDef *def,
                             xmlNodePtr node)
{
    g_autofree xmlNodePtr *feats = NULL;
    size_t nfeats = virXMLNodeGetSubelementList(node, NULL, &feats);
    size_t i;

    def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_ON;

    for (i = 0; i < nfeats; i++) {
        int feature;
        virTristateSwitch value;

        feature = virDomainXenTypeFromString((const char *)feats[i]->name);
        if (feature < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported Xen feature: %1$s"),
                           feats[i]->name);
            return -1;
        }

        if (virXMLPropTristateSwitch(feats[i], "state",
                                     VIR_XML_PROP_REQUIRED, &value) < 0)
            return -1;

        def->xen_features[feature] = value;

        switch ((virDomainXen) feature) {
        case VIR_DOMAIN_XEN_E820_HOST:
            break;

        case VIR_DOMAIN_XEN_PASSTHROUGH:
            if (value != VIR_TRISTATE_SWITCH_ON)
                break;

            if (virXMLPropEnum(feats[i], "mode",
                               virDomainXenPassthroughModeTypeFromString,
                               VIR_XML_PROP_NONZERO,
                               &def->xen_passthrough_mode) < 0)
                return -1;
            break;

            case VIR_DOMAIN_XEN_LAST:
                break;
        }
    }

    return 0;
}


static int
virDomainFeaturesCapabilitiesDefParse(virDomainDef *def,
                                      xmlNodePtr node)
{
    g_autofree xmlNodePtr *caps = NULL;
    size_t ncaps = virXMLNodeGetSubelementList(node, NULL, &caps);
    virDomainCapabilitiesPolicy policy;
    size_t i;

    if (virXMLPropEnumDefault(node, "policy",
                              virDomainCapabilitiesPolicyTypeFromString,
                              VIR_XML_PROP_NONE, &policy,
                              VIR_DOMAIN_CAPABILITIES_POLICY_DEFAULT) < 0)
        return -1;

    def->features[VIR_DOMAIN_FEATURE_CAPABILITIES] = policy;

    for (i = 0; i < ncaps; i++) {
        virTristateSwitch state;
        int val = virDomainProcessCapsFeatureTypeFromString((const char *)caps[i]->name);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unexpected capability feature '%1$s'"), caps[i]->name);
            return -1;
        }


        if (virXMLPropTristateSwitch(caps[i], "state", VIR_XML_PROP_NONE, &state) < 0)
            return -1;

        if (state == VIR_TRISTATE_SWITCH_ABSENT)
            state = VIR_TRISTATE_SWITCH_ON;

        def->caps_features[val] = state;
    }

    return 0;
}


static int
virDomainFeaturesTCGDefParse(virDomainDef *def,
                             xmlXPathContextPtr ctxt,
                             xmlNodePtr node)
{
    g_autofree virDomainFeatureTCG *tcg = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);

    tcg = g_new0(virDomainFeatureTCG, 1);
    ctxt->node = node;

    if (virDomainParseMemory("./tb-cache", "./tb-cache/@unit",
                             ctxt, &tcg->tb_cache, false, false) < 0)
        return -1;

    if (tcg->tb_cache == 0)
        return 0;

    def->features[VIR_DOMAIN_FEATURE_TCG] = VIR_TRISTATE_SWITCH_ON;
    def->tcg_features = g_steal_pointer(&tcg);
    return 0;
}


static int
virDomainFeaturesDefParse(virDomainDef *def,
                          xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    if ((n = virXPathNodeSet("./features/*", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        int val = virDomainFeatureTypeFromString((const char *)nodes[i]->name);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unexpected feature '%1$s'"), nodes[i]->name);
            return -1;
        }

        switch ((virDomainFeature) val) {
        case VIR_DOMAIN_FEATURE_ACPI:
        case VIR_DOMAIN_FEATURE_PAE:
        case VIR_DOMAIN_FEATURE_VIRIDIAN:
        case VIR_DOMAIN_FEATURE_PRIVNET:
            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            break;

        case VIR_DOMAIN_FEATURE_APIC: {
            virTristateSwitch eoi;
            if (virXMLPropTristateSwitch(nodes[i], "eoi", VIR_XML_PROP_NONE, &eoi) < 0)
                return -1;

            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            def->apic_eoi = eoi;
            break;
        }

        case VIR_DOMAIN_FEATURE_MSRS: {
            virDomainMsrsUnknown unknown;
            if (virXMLPropEnum(nodes[i], "unknown",
                               virDomainMsrsUnknownTypeFromString,
                               VIR_XML_PROP_REQUIRED, &unknown) < 0)
                return -1;

            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            def->msrs_features[VIR_DOMAIN_MSRS_UNKNOWN] = unknown;
            break;
        }

        case VIR_DOMAIN_FEATURE_HYPERV:
            if (virDomainFeaturesHyperVDefParse(def, nodes[i]) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_KVM:
            if (virDomainFeaturesKVMDefParse(def, nodes[i]) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_XEN:
            if (virDomainFeaturesXENDefParse(def, nodes[i]) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_CAPABILITIES: {
            if (virDomainFeaturesCapabilitiesDefParse(def, nodes[i]) < 0)
                return -1;
            break;
        }

        case VIR_DOMAIN_FEATURE_VMCOREINFO:
        case VIR_DOMAIN_FEATURE_HAP:
        case VIR_DOMAIN_FEATURE_PMU:
        case VIR_DOMAIN_FEATURE_PVSPINLOCK:
        case VIR_DOMAIN_FEATURE_VMPORT: {
            virTristateSwitch state;

            if (virXMLPropTristateSwitch(nodes[i], "state",
                                         VIR_XML_PROP_NONE, &state) < 0)
                return -1;

            if (state == VIR_TRISTATE_SWITCH_ABSENT)
                state = VIR_TRISTATE_SWITCH_ON;

            def->features[val] = state;
            break;
        }

        case VIR_DOMAIN_FEATURE_SMM: {
            virTristateSwitch state;

            if (virXMLPropTristateSwitch(nodes[i], "state",
                                         VIR_XML_PROP_NONE, &state) < 0)
                return -1;

            if (state == VIR_TRISTATE_SWITCH_ABSENT)
                state = VIR_TRISTATE_SWITCH_ON;

            def->features[val] = state;

            if (state == VIR_TRISTATE_SWITCH_ON) {
                int rv = virParseScaledValue("string(./features/smm/tseg)",
                                             "string(./features/smm/tseg/@unit)",
                                             ctxt,
                                             &def->tseg_size,
                                             1024 * 1024, /* Defaults to mebibytes */
                                             ULLONG_MAX,
                                             false);
                if (rv < 0)
                    return -1;

                def->tseg_specified = rv != 0;
            }
            break;
        }

        case VIR_DOMAIN_FEATURE_GIC:
            if (virXMLPropEnum(nodes[i], "version", virGICVersionTypeFromString,
                               VIR_XML_PROP_NONZERO, &def->gic_version) < 0)
                return -1;

            def->features[val] = VIR_TRISTATE_SWITCH_ON;
            break;

        case VIR_DOMAIN_FEATURE_IOAPIC: {
            virDomainIOAPIC driver;

            if (virXMLPropEnumDefault(nodes[i], "driver", virDomainIOAPICTypeFromString,
                                      VIR_XML_PROP_NONZERO, &driver,
                                      VIR_DOMAIN_IOAPIC_NONE) < 0)
                return -1;

            def->features[val] = driver;
            break;
        }

        case VIR_DOMAIN_FEATURE_HPT:
            if (virXMLPropEnum(nodes[i], "resizing",
                               virDomainHPTResizingTypeFromString,
                               VIR_XML_PROP_NONZERO, &def->hpt_resizing) < 0)
                return -1;

            if (virParseScaledValue("./features/hpt/maxpagesize",
                                    NULL,
                                    ctxt,
                                    &def->hpt_maxpagesize,
                                    1024,
                                    ULLONG_MAX,
                                    false) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s",
                               _("Unable to parse HPT maxpagesize setting"));
                return -1;
            }
            def->hpt_maxpagesize = VIR_DIV_UP(def->hpt_maxpagesize, 1024);

            if (def->hpt_resizing != VIR_DOMAIN_HPT_RESIZING_NONE ||
                def->hpt_maxpagesize > 0) {
                def->features[val] = VIR_TRISTATE_SWITCH_ON;
            }
            break;

        case VIR_DOMAIN_FEATURE_CFPC: {
            virDomainCFPC value;

            if (virXMLPropEnumDefault(nodes[i], "value", virDomainCFPCTypeFromString,
                                      VIR_XML_PROP_NONZERO, &value,
                                      VIR_DOMAIN_CFPC_NONE) < 0)
                return -1;

            def->features[val] = value;
            break;
        }

        case VIR_DOMAIN_FEATURE_SBBC: {
            virDomainSBBC value;

            if (virXMLPropEnumDefault(nodes[i], "value", virDomainSBBCTypeFromString,
                                      VIR_XML_PROP_NONZERO, &value,
                                      VIR_DOMAIN_SBBC_NONE) < 0)
                return -1;

            def->features[val] = value;
            break;
        }

        case VIR_DOMAIN_FEATURE_IBS: {
            virDomainIBS value;

            if (virXMLPropEnumDefault(nodes[i], "value", virDomainIBSTypeFromString,
                                      VIR_XML_PROP_NONZERO, &value,
                                      VIR_DOMAIN_IBS_NONE) < 0)
                return -1;

            def->features[val] = value;
            break;
        }

        case VIR_DOMAIN_FEATURE_HTM:
        case VIR_DOMAIN_FEATURE_NESTED_HV:
        case VIR_DOMAIN_FEATURE_CCF_ASSIST: {
            virTristateSwitch state;

            if (virXMLPropTristateSwitch(nodes[i], "state",
                                         VIR_XML_PROP_REQUIRED, &state) < 0)
                return -1;

            def->features[val] = state;
            break;
        }

        case VIR_DOMAIN_FEATURE_TCG:
            if (virDomainFeaturesTCGDefParse(def, ctxt, nodes[i]) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_ASYNC_TEARDOWN: {
            virTristateBool enabled;

            if (virXMLPropTristateBool(nodes[i], "enabled",
                                       VIR_XML_PROP_NONE, &enabled) < 0)
                return -1;

            if (enabled == VIR_TRISTATE_BOOL_ABSENT)
                enabled = VIR_TRISTATE_BOOL_YES;

            def->features[val] = enabled;
            break;
        }

        case VIR_DOMAIN_FEATURE_LAST:
            break;
        }
    }

    return 0;
}


static int
virDomainDefMaybeAddHostdevSCSIcontroller(virDomainDef *def)
{
    /* Look for any hostdev scsi dev */
    size_t i;
    int maxController = -1;
    virDomainHostdevDef *hostdev;
    int newModel = -1;

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];
        if (virHostdevIsSCSIDevice(hostdev) &&
            (int)hostdev->info->addr.drive.controller > maxController) {
            virDomainControllerDef *cont;

            maxController = hostdev->info->addr.drive.controller;
            /* We may be creating a new controller because this one is full.
             * So let's grab the model from it and update the model we're
             * going to add as long as this one isn't undefined. The premise
             * being keeping the same controller model for all SCSI hostdevs. */
            cont = virDomainDeviceFindSCSIController(def, &hostdev->info->addr.drive);
            if (cont && cont->model != -1)
                newModel = cont->model;
        }
    }

    if (maxController == -1)
        return 0;

    for (i = 0; i <= maxController; i++) {
        if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                           i, newModel) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainLoaderDefParseXMLNvram(virDomainLoaderDef *loader,
                                xmlNodePtr nvramNode,
                                xmlNodePtr nvramSourceNode,
                                xmlXPathContextPtr ctxt,
                                virDomainXMLOption *xmlopt,
                                unsigned int flags)
{
    g_autoptr(virStorageSource) src = virStorageSourceNew();
    unsigned int format = 0;
    int typePresent;

    if (!nvramNode)
        return 0;

    loader->nvramTemplate = virXMLPropString(nvramNode, "template");

    if (virXMLPropEnumDefault(nvramNode, "format",
                              virStorageFileFormatTypeFromString, VIR_XML_PROP_NONE,
                              &format, VIR_STORAGE_FILE_NONE) < 0) {
        return -1;
    }
    if (format &&
        format != VIR_STORAGE_FILE_RAW &&
        format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unsupported nvram format '%1$s'"),
                       virStorageFileFormatTypeToString(format));
        return -1;
    }
    src->format = format;

    if ((typePresent = virXMLPropEnum(nvramNode, "type",
                                      virStorageTypeFromString, VIR_XML_PROP_NONE,
                                      &src->type)) < 0)
        return -1;

    if (!typePresent) {
        if (!(src->path = virXMLNodeContentString(nvramNode)))
            return -1;

        if (STREQ(src->path, ""))
            VIR_FREE(src->path);

        src->type = VIR_STORAGE_TYPE_FILE;
    } else {
        if (!nvramSourceNode)
            return -1;

        if (virDomainStorageSourceParse(nvramSourceNode, ctxt, src, flags, xmlopt) < 0)
            return -1;

        loader->newStyleNVRAM = true;
    }

    loader->nvram = g_steal_pointer(&src);
    return 0;
}


static int
virDomainLoaderDefParseXMLLoader(virDomainLoaderDef *loader,
                                 xmlNodePtr loaderNode)
{
    unsigned int format = 0;

    if (!loaderNode) {
        /* If there is no <loader> element but the <nvram> element
         * was present, copy the format from the latter to the
         * former.
         *
         * This ensures that a configuration such as
         *
         *   <os>
         *     <nvram format='foo'/>
         *   </os>
         *
         * behaves as expected, that is, results in a firmware build
         * with format 'foo' being selected */
        if (loader->nvram)
            loader->format = loader->nvram->format;

        return 0;
    }

    if (virXMLPropTristateBool(loaderNode, "readonly", VIR_XML_PROP_NONE,
                               &loader->readonly) < 0)
        return -1;

    if (virXMLPropEnum(loaderNode, "type", virDomainLoaderTypeFromString,
                       VIR_XML_PROP_NONZERO, &loader->type) < 0)
        return -1;

    if (!(loader->path = virXMLNodeContentString(loaderNode)))
        return -1;

    if (STREQ(loader->path, ""))
        VIR_FREE(loader->path);

    if (virXMLPropTristateBool(loaderNode, "secure", VIR_XML_PROP_NONE,
                               &loader->secure) < 0)
        return -1;

    if (virXMLPropTristateBool(loaderNode, "stateless", VIR_XML_PROP_NONE,
                               &loader->stateless) < 0)
        return -1;

    if (virXMLPropEnumDefault(loaderNode, "format",
                              virStorageFileFormatTypeFromString, VIR_XML_PROP_NONE,
                              &format, VIR_STORAGE_FILE_NONE) < 0) {
        return -1;
    }
    if (format &&
        format != VIR_STORAGE_FILE_RAW &&
        format != VIR_STORAGE_FILE_QCOW2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unsupported loader format '%1$s'"),
                       virStorageFileFormatTypeToString(format));
        return -1;
    }
    loader->format = format;

    return 0;
}


static int
virDomainLoaderDefParseXML(virDomainLoaderDef *loader,
                           xmlNodePtr loaderNode,
                           xmlNodePtr nvramNode,
                           xmlNodePtr nvramSourceNode,
                           xmlXPathContextPtr ctxt,
                           virDomainXMLOption *xmlopt,
                           unsigned int flags)
{
    if (virDomainLoaderDefParseXMLNvram(loader,
                                        nvramNode, nvramSourceNode,
                                        ctxt, xmlopt, flags) < 0)
        return -1;

    if (virDomainLoaderDefParseXMLLoader(loader,
                                         loaderNode) < 0)
        return -1;

    if (loader->nvram &&
        loader->format && loader->nvram->format &&
        loader->format != loader->nvram->format) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Format mismatch: loader.format='%1$s' nvram.format='%2$s'"),
                       virStorageFileFormatTypeToString(loader->format),
                       virStorageFileFormatTypeToString(loader->nvram->format));
        return -1;
    }

    return 0;
}


static int
virDomainSchedulerParseCommonAttrs(xmlNodePtr node,
                                   virProcessSchedPolicy *policy,
                                   int *priority)
{
    if (virXMLPropEnum(node, "scheduler", virProcessSchedPolicyTypeFromString,
                       VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                       policy) < 0)
        return -1;

    if (*policy == VIR_PROC_POLICY_FIFO || *policy == VIR_PROC_POLICY_RR) {
        if (virXMLPropInt(node, "priority", 10, VIR_XML_PROP_REQUIRED,
                          priority, 0) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainEmulatorSchedParse(xmlNodePtr node,
                            virDomainDef *def)
{
    g_autofree virDomainThreadSchedParam *sched = NULL;

    sched = g_new0(virDomainThreadSchedParam, 1);

    if (virDomainSchedulerParseCommonAttrs(node,
                                           &sched->policy,
                                           &sched->priority) < 0)
        return -1;

    def->cputune.emulatorsched = g_steal_pointer(&sched);
    return 0;
}


static virBitmap *
virDomainSchedulerParse(xmlNodePtr node,
                        const char *elementName,
                        const char *attributeName,
                        virProcessSchedPolicy *policy,
                        int *priority)
{
    g_autoptr(virBitmap) ret = NULL;
    g_autofree char *tmp = NULL;

    if (!(tmp = virXMLPropString(node, attributeName))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing attribute '%1$s' in element '%2$s'"),
                       attributeName, elementName);
        return NULL;
    }

    if (virBitmapParse(tmp, &ret, VIR_DOMAIN_CPUMASK_LEN) < 0)
        return NULL;

    if (virBitmapIsAllClear(ret)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("'%1$s' scheduler bitmap '%2$s' is empty"),
                       attributeName, tmp);
        return NULL;
    }

    if (virDomainSchedulerParseCommonAttrs(node, policy, priority) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


static int
virDomainThreadSchedParseHelper(xmlNodePtr node,
                                const char *elementName,
                                const char *attributeName,
                                virDomainThreadSchedParam *(*func)(virDomainDef *, unsigned int),
                                virDomainDef *def)
{
    ssize_t next = -1;
    virDomainThreadSchedParam *sched = NULL;
    virProcessSchedPolicy policy = 0;
    int priority = 0;
    g_autoptr(virBitmap) map = NULL;

    if (!(map = virDomainSchedulerParse(node, elementName, attributeName,
                                        &policy, &priority)))
        return -1;

    while ((next = virBitmapNextSetBit(map, next)) > -1) {
        if (!(sched = func(def, next)))
            return -1;

        if (sched->policy != VIR_PROC_POLICY_NONE) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("'%1$s' attributes '%2$s' must not overlap"),
                           elementName, attributeName);
            return -1;
        }

        sched->policy = policy;
        sched->priority = priority;
    }

    return 0;
}


static int
virDomainVcpuThreadSchedParse(xmlNodePtr node,
                              virDomainDef *def)
{
    return virDomainThreadSchedParseHelper(node,
                                           "vcpusched",
                                           "vcpus",
                                           virDomainDefGetVcpuSched,
                                           def);
}


static virDomainThreadSchedParam *
virDomainDefGetIOThreadSched(virDomainDef *def,
                             unsigned int iothread)
{
    virDomainIOThreadIDDef *iothrinfo;

    if (!(iothrinfo = virDomainIOThreadIDFind(def, iothread))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot find 'iothread' : %1$u"),
                       iothread);
        return NULL;
    }

    return &iothrinfo->sched;
}


static int
virDomainIOThreadSchedParse(xmlNodePtr node,
                            virDomainDef *def)
{
    return virDomainThreadSchedParseHelper(node,
                                           "iothreadsched",
                                           "iothreads",
                                           virDomainDefGetIOThreadSched,
                                           def);
}


static int
virDomainVcpuParse(virDomainDef *def,
                   xmlXPathContextPtr ctxt,
                   virDomainXMLOption *xmlopt)
{
    int n;
    xmlNodePtr vcpuNode;
    size_t i;
    unsigned int maxvcpus;
    unsigned int vcpus;
    g_autofree char *tmp = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    vcpus = maxvcpus = 1;

    if ((vcpuNode = virXPathNode("./vcpu[1]", ctxt))) {
        if (!(tmp = virXMLNodeContentString(vcpuNode)))
            return -1;

        if (virStrToLong_ui(tmp, NULL, 10, &maxvcpus) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("maximum vcpus count must be an integer"));
            return -1;
        }
        VIR_FREE(tmp);

        if (virXMLPropUIntDefault(vcpuNode, "current", 10, VIR_XML_PROP_NONE, &vcpus, maxvcpus) < 0)
            return -1;

        if (virXMLPropEnumDefault(vcpuNode, "placement",
                                  virDomainCpuPlacementModeTypeFromString,
                                  VIR_XML_PROP_NONE, &def->placement_mode,
                                  VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC) < 0)
            return -1;

        if (def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
            tmp = virXMLPropString(vcpuNode, "cpuset");
            if (tmp) {
                if (virBitmapParse(tmp, &def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
                    return -1;

                if (virBitmapIsAllClear(def->cpumask)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("Invalid value of 'cpuset': %1$s"), tmp);
                    return -1;
                }

                VIR_FREE(tmp);
            }
        }
    }

    if (virDomainDefSetVcpusMax(def, maxvcpus, xmlopt) < 0)
        return -1;

    if ((n = virXPathNodeSet("./vcpus/vcpu", ctxt, &nodes)) < 0)
        return -1;

    if (n) {
        /* if individual vcpu states are provided take them as master */
        def->individualvcpus = true;

        for (i = 0; i < n; i++) {
            virDomainVcpuDef *vcpu;
            virTristateBool state;
            unsigned int id;

            if (virXMLPropUInt(nodes[i], "id", 10, VIR_XML_PROP_REQUIRED, &id) < 0)
                return -1;

            if (id >= def->maxvcpus) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("vcpu id '%1$u' is out of range of maximum vcpu count"),
                               id);
                return -1;
            }

            vcpu = virDomainDefGetVcpu(def, id);

            if (virXMLPropTristateBool(nodes[i], "enabled",
                                       VIR_XML_PROP_REQUIRED, &state) < 0)
                return -1;

            virTristateBoolToBool(state, &vcpu->online);

            if (virXMLPropTristateBool(nodes[i], "hotpluggable",
                                       VIR_XML_PROP_NONE,
                                       &vcpu->hotpluggable) < 0)
                return -1;

            if (virXMLPropUInt(nodes[i], "order", 10, VIR_XML_PROP_NONE,
                               &vcpu->order) < 0)
                return -1;
        }
    } else {
        if (virDomainDefSetVcpus(def, vcpus) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainDefParseBootInitOptions(virDomainDef *def,
                                 xmlXPathContextPtr ctxt)
{
    char *name = NULL;
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;

    def->os.init = virXPathString("string(./os/init[1])", ctxt);
    def->os.cmdline = virXPathString("string(./os/cmdline[1])", ctxt);
    def->os.initdir = virXPathString("string(./os/initdir[1])", ctxt);
    def->os.inituser = virXPathString("string(./os/inituser[1])", ctxt);
    def->os.initgroup = virXPathString("string(./os/initgroup[1])", ctxt);

    if ((n = virXPathNodeSet("./os/initarg", ctxt, &nodes)) < 0)
        return -1;

    def->os.initargv = g_new0(char *, n+1);
    for (i = 0; i < n; i++) {
        if (!nodes[i]->children ||
            !nodes[i]->children->content) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("No data supplied for <initarg> element"));
            return -1;
        }
        def->os.initargv[i] = g_strdup((const char *)nodes[i]->children->content);
    }
    def->os.initargv[n] = NULL;
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./os/initenv", ctxt, &nodes)) < 0)
        return -1;

    def->os.initenv = g_new0(virDomainOSEnv *, n + 1);
    for (i = 0; i < n; i++) {
        if (!(name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("No name supplied for <initenv> element"));
            return -1;
        }

        if (!nodes[i]->children ||
            !nodes[i]->children->content) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("No value supplied for <initenv name='%1$s'> element"),
                           name);
            return -1;
        }

        def->os.initenv[i] = g_new0(virDomainOSEnv, 1);
        def->os.initenv[i]->name = name;
        def->os.initenv[i]->value = g_strdup((const char *)nodes[i]->children->content);
    }
    def->os.initenv[n] = NULL;

    return 0;
}


static void
virDomainDefParseBootKernelOptions(virDomainDef *def,
                                   xmlXPathContextPtr ctxt)
{
    def->os.kernel = virXPathString("string(./os/kernel[1])", ctxt);
    def->os.initrd = virXPathString("string(./os/initrd[1])", ctxt);
    def->os.cmdline = virXPathString("string(./os/cmdline[1])", ctxt);
    def->os.dtb = virXPathString("string(./os/dtb[1])", ctxt);
    def->os.root = virXPathString("string(./os/root[1])", ctxt);
}


static int
virDomainDefParseBootFirmwareOptions(virDomainDef *def,
                                     xmlXPathContextPtr ctxt,
                                     unsigned int flags)
{
    g_autofree char *firmware = virXPathString("string(./os/@firmware)", ctxt);
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree int *features = NULL;
    bool abiUpdate = !!(flags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE);
    int fw = 0;
    int n = 0;
    size_t i;

    if ((n = virXPathNodeSet("./os/firmware/feature", ctxt, &nodes)) < 0)
        return -1;

    /* Migration compatibility kludge.
     *
     * Between 8.6.0 and 9.1.0 (extremes included), the migratable
     * XML produced when feature-based firmware autoselection was
     * enabled looked like
     *
     *   <os>
     *     <firmware>
     *       <feature name='foo' enabled='yes'/>
     *
     * Notice how there's no firmware='foo' attribute for the <os>
     * element, meaning that firmware autoselection is disabled, and
     * yet some <feature> elements, which are used to control the
     * firmware autoselection process, are present. We don't consider
     * this to be a valid combination, and want such a configuration
     * to get rejected when submitted by users.
     *
     * In order to achieve that, while at the same time keeping
     * migration coming from the libvirt versions listed above
     * working, we can simply stop parsing early and ignore the
     * <feature> tags when firmware autoselection is not enabled,
     * *except* if we're defining a new domain.
     *
     * This is safe to do because the configuration will either come
     * from another libvirt instance, in which case it will have a
     * properly filled in <loader> element that contains enough
     * information to successfully define and start the domain, or it
     * will be a random configuration that lacks such information, in
     * which case a different failure will be reported anyway.
     */
    if (n > 0 && !firmware && !abiUpdate)
        return 0;

    if (n > 0)
        features = g_new0(int, VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_LAST);

    for (i = 0; i < n; i++) {
        unsigned int feature;
        virTristateBool enabled;

        if (virXMLPropEnum(nodes[i], "name",
                           virDomainOsDefFirmwareFeatureTypeFromString,
                           VIR_XML_PROP_REQUIRED,
                           &feature) < 0)
            return -1;

        if (virXMLPropTristateBool(nodes[i], "enabled",
                                   VIR_XML_PROP_REQUIRED,
                                   &enabled) < 0)
            return -1;

        features[feature] = enabled;
    }

    def->os.firmwareFeatures = g_steal_pointer(&features);

    if (!firmware)
        return 0;

    fw = virDomainOsDefFirmwareTypeFromString(firmware);

    if (fw <= 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown firmware value %1$s"),
                       firmware);
        return -1;
    }

    def->os.firmware = fw;

    return 0;
}


static int
virDomainDefParseBootLoaderOptions(virDomainDef *def,
                                   xmlXPathContextPtr ctxt,
                                   virDomainXMLOption *xmlopt,
                                   unsigned int flags)
{
    xmlNodePtr loaderNode = virXPathNode("./os/loader[1]", ctxt);
    xmlNodePtr nvramNode = virXPathNode("./os/nvram[1]", ctxt);
    xmlNodePtr nvramSourceNode = virXPathNode("./os/nvram/source[1]", ctxt);

    if (!loaderNode && !nvramNode)
        return 0;

    def->os.loader = virDomainLoaderDefNew();

    if (virDomainLoaderDefParseXML(def->os.loader,
                                   loaderNode, nvramNode, nvramSourceNode,
                                   ctxt, xmlopt, flags) < 0)
        return -1;

    return 0;
}


static int
virDomainDefParseBootAcpiOptions(virDomainDef *def,
                                 xmlXPathContextPtr ctxt)
{
    int n;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;

    if ((n = virXPathNodeSet("./os/acpi/table", ctxt, &nodes)) < 0)
        return -1;

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Only one acpi table is supported"));
        return -1;
    }

    if (n == 1) {
        tmp = virXMLPropString(nodes[0], "type");

        if (!tmp) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing acpi table type"));
            return -1;
        }

        if (STREQ_NULLABLE(tmp, "slic")) {
            VIR_FREE(tmp);
            if (!(tmp = virXMLNodeContentString(nodes[0])))
                return -1;

            def->os.slic_table = virFileSanitizePath(tmp);
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Unknown acpi table type: %1$s"),
                           tmp);
            return -1;
        }
    }

    return 0;
}


static int
virDomainDefParseBootOptions(virDomainDef *def,
                             xmlXPathContextPtr ctxt,
                             virDomainXMLOption *xmlopt,
                             unsigned int flags)
{
    /*
     * Booting options for different OS types....
     *
     *   - A bootloader (and optional kernel+initrd)  (xen)
     *   - A kernel + initrd                          (xen)
     *   - A boot device (and optional kernel+initrd) (hvm)
     *   - An init script                             (exe)
     */

    switch ((virDomainOSType) def->os.type) {
    case VIR_DOMAIN_OSTYPE_HVM:
        virDomainDefParseBootKernelOptions(def, ctxt);

        if (virDomainDefParseBootFirmwareOptions(def, ctxt, flags) < 0)
            return -1;

        if (virDomainDefParseBootLoaderOptions(def, ctxt, xmlopt, flags) < 0)
            return -1;

        if (virDomainDefParseBootAcpiOptions(def, ctxt) < 0)
            return -1;

        if (virDomainDefParseBootXML(ctxt, def) < 0)
            return -1;

        break;

    case VIR_DOMAIN_OSTYPE_XEN:
    case VIR_DOMAIN_OSTYPE_XENPVH:
    case VIR_DOMAIN_OSTYPE_UML:
        virDomainDefParseBootKernelOptions(def, ctxt);

        if (virDomainDefParseBootLoaderOptions(def, ctxt, xmlopt, flags) < 0)
            return -1;

        break;

    case VIR_DOMAIN_OSTYPE_EXE:
        if (virDomainDefParseBootInitOptions(def, ctxt) < 0)
            return -1;

        break;

    case VIR_DOMAIN_OSTYPE_LINUX:
    case VIR_DOMAIN_OSTYPE_LAST:
        break;
    }

    return 0;
}


static int
virDomainResctrlParseVcpus(virDomainDef *def,
                           xmlNodePtr node,
                           virBitmap **vcpus)
{
    g_autofree char *vcpus_str = NULL;

    vcpus_str = virXMLPropString(node, "vcpus");
    if (!vcpus_str) {
        virReportError(VIR_ERR_XML_ERROR, _("Missing %1$s attribute 'vcpus'"),
                       node->name);
        return -1;
    }
    if (virBitmapParse(vcpus_str, vcpus, VIR_DOMAIN_CPUMASK_LEN) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid %1$s attribute 'vcpus' value '%2$s'"),
                       node->name, vcpus_str);
        return -1;
    }

    /* We need to limit the bitmap to number of vCPUs.  If there's nothing left,
     * then we can just clean up and return 0 immediately */
    virBitmapShrink(*vcpus, def->maxvcpus);

    return 0;
}


static int
virDomainResctrlVcpuMatch(virDomainDef *def,
                          virBitmap *vcpus,
                          virDomainResctrlDef **resctrl)
{
    ssize_t i = 0;

    for (i = 0; i < def->nresctrls; i++) {
        /* vcpus group has been created, directly use the existing one.
         * Just updating memory allocation information of that group
         */
        if (virBitmapEqual(def->resctrls[i]->vcpus, vcpus)) {
            *resctrl = def->resctrls[i];
            break;
        }
        if (virBitmapOverlaps(def->resctrls[i]->vcpus, vcpus)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Overlapping vcpus in resctrls"));
            return -1;
        }
    }
    return 0;
}


static int
virDomainCachetuneDefParseCache(xmlXPathContextPtr ctxt,
                                xmlNodePtr node,
                                virResctrlAlloc *alloc)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    unsigned int level;
    unsigned int cache;
    virCacheType type;
    unsigned long long size;

    ctxt->node = node;

    if (virXMLPropUInt(node, "id", 10, VIR_XML_PROP_REQUIRED, &cache) < 0)
        return -1;

    if (virXMLPropUInt(node, "level", 10, VIR_XML_PROP_REQUIRED, &level) < 0)
        return -1;

    if (virXMLPropEnum(node, "type", virCacheTypeFromString,
                       VIR_XML_PROP_REQUIRED, &type) < 0)
        return -1;

    if (virParseScaledValue("./@size", "./@unit",
                            ctxt, &size, 1024,
                            ULLONG_MAX, true) < 0)
        return -1;

    if (virResctrlAllocSetCacheSize(alloc, level, type, cache, size) < 0)
        return -1;

    return 0;
}


/* Checking if the monitor's vcpus and tag is conflicted with existing
 * allocation and monitors.
 *
 * Returns 1 if @monitor->vcpus equals to @resctrl->vcpus, then the monitor
 * will share the underlying resctrl group with @resctrl->alloc. Returns -1
 * if any conflict found. Returns 0 if no conflict and @monitor->vcpus is
 * not equal  to @resctrl->vcpus.
 */
static int
virDomainResctrlValidateMonitor(virDomainResctrlDef *resctrl,
                                virDomainResctrlMonDef *monitor)
{
    size_t i = 0;
    int vcpu = -1;
    bool vcpus_overlap_any = false;
    bool vcpus_equal_to_resctrl = false;
    bool vcpus_overlap_no_resctrl = false;
    bool default_alloc_monitor = virResctrlAllocIsEmpty(resctrl->alloc);

    if (virBitmapIsAllClear(monitor->vcpus)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("vcpus is empty"));
        return -1;
    }

    while ((vcpu = virBitmapNextSetBit(monitor->vcpus, vcpu)) >= 0) {
        if (!virBitmapIsBitSet(resctrl->vcpus, vcpu)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Monitor vcpus conflicts with allocation"));
            return -1;
        }
    }

    vcpus_equal_to_resctrl = virBitmapEqual(monitor->vcpus, resctrl->vcpus);

    for (i = 0; i < resctrl->nmonitors; i++) {
        if (virBitmapEqual(monitor->vcpus, resctrl->monitors[i]->vcpus)) {
            if (monitor->tag != resctrl->monitors[i]->tag) {
                continue;
            } else {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("Identical vcpus found in same type monitors"));
                return -1;
            }
        }

        if (virBitmapOverlaps(monitor->vcpus, resctrl->monitors[i]->vcpus))
            vcpus_overlap_any = true;

        if (vcpus_equal_to_resctrl ||
            virBitmapEqual(resctrl->monitors[i]->vcpus, resctrl->vcpus))
            continue;

        if (virBitmapOverlaps(monitor->vcpus, resctrl->monitors[i]->vcpus))
            vcpus_overlap_no_resctrl = true;
    }

    if (vcpus_overlap_no_resctrl ||
        (default_alloc_monitor && vcpus_overlap_any)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("vcpus overlaps in resctrl groups"));
        return -1;
    }

    if (vcpus_equal_to_resctrl && !default_alloc_monitor)
        return 1;

    return 0;
}


#define VIR_DOMAIN_RESCTRL_MONITOR_CACHELEVEL 3

static int
virDomainResctrlMonDefParse(virDomainDef *def,
                            xmlXPathContextPtr ctxt,
                            xmlNodePtr node,
                            virResctrlMonitorType tag,
                            virDomainResctrlDef *resctrl)
{
    virDomainResctrlMonDef *domresmon = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    unsigned int level = 0;
    size_t i = 0;
    int n = 0;
    int rv = -1;
    int ret = -1;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;
    g_autofree char *id = NULL;

    ctxt->node = node;

    if ((n = virXPathNodeSet("./monitor", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract monitor nodes"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        domresmon = g_new0(virDomainResctrlMonDef, 1);

        domresmon->tag = tag;

        domresmon->instance = virResctrlMonitorNew();
        if (!domresmon->instance) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not create monitor"));
            goto cleanup;
        }

        if (tag == VIR_RESCTRL_MONITOR_TYPE_CACHE) {
            if (virXMLPropUInt(nodes[i], "level", 10, VIR_XML_PROP_REQUIRED,
                               &level) < 0)
                goto cleanup;

            if (level != VIR_DOMAIN_RESCTRL_MONITOR_CACHELEVEL) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid monitor cache level '%1$d'"),
                               level);
                goto cleanup;
            }
        }

        if (virDomainResctrlParseVcpus(def, nodes[i], &domresmon->vcpus) < 0)
            goto cleanup;

        rv = virDomainResctrlValidateMonitor(resctrl, domresmon);
        if (rv < 0)
            goto cleanup;

        /* If monitor's vcpu list is identical to the vcpu list of the
         * associated allocation, set monitor's id to the same value
         * as the allocation. */
        if (rv == 1) {
            const char *alloc_id = virResctrlAllocGetID(resctrl->alloc);

            id = g_strdup(alloc_id);
        } else {
            if (!(tmp = virBitmapFormat(domresmon->vcpus)))
                goto cleanup;

            id = g_strdup_printf("vcpus_%s", tmp);
        }

        virResctrlMonitorSetAlloc(domresmon->instance, resctrl->alloc);

        if (virResctrlMonitorSetID(domresmon->instance, id) < 0)
            goto cleanup;

        VIR_APPEND_ELEMENT(resctrl->monitors, resctrl->nmonitors, domresmon);

        VIR_FREE(id);
        VIR_FREE(tmp);
    }

    ret = 0;
 cleanup:
    virDomainResctrlMonDefFree(domresmon);
    return ret;
}


static virDomainResctrlDef *
virDomainResctrlNew(xmlNodePtr node,
                    virResctrlAlloc *alloc,
                    virBitmap *vcpus,
                    unsigned int flags)
{
    virDomainResctrlDef *resctrl = NULL;
    g_autofree char *vcpus_str = NULL;
    g_autofree char *alloc_id = NULL;

    /* We need to format it back because we need to be consistent in the naming
     * even when users specify some "sub-optimal" string there. */
    vcpus_str = virBitmapFormat(vcpus);
    if (!vcpus_str)
        return NULL;

    if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE))
        alloc_id = virXMLPropString(node, "id");

    if (!alloc_id) {
        /* The number of allocations is limited and the directory structure is flat,
         * not hierarchical, so we need to have all same allocations in one
         * directory, so it's nice to have it named appropriately.  For now it's
         * 'vcpus_...' but it's designed in order for it to be changeable in the
         * future (it's part of the status XML). */
        alloc_id = g_strdup_printf("vcpus_%s", vcpus_str);
    }

    if (virResctrlAllocSetID(alloc, alloc_id) < 0)
        return NULL;

    resctrl = g_new0(virDomainResctrlDef, 1);
    resctrl->vcpus = virBitmapNewCopy(vcpus);
    resctrl->alloc = virObjectRef(alloc);

    return resctrl;
}


static int
virDomainCachetuneDefParse(virDomainDef *def,
                           xmlXPathContextPtr ctxt,
                           xmlNodePtr node,
                           unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainResctrlDef *resctrl = NULL;
    ssize_t i = 0;
    int n;
    int ret = -1;
    g_autoptr(virBitmap) vcpus = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autoptr(virResctrlAlloc) alloc = NULL;

    ctxt->node = node;

    if (virDomainResctrlParseVcpus(def, node, &vcpus) < 0)
        return -1;

    if (virBitmapIsAllClear(vcpus))
        return 0;

    if ((n = virXPathNodeSet("./cache", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract cache nodes under cachetune"));
        return -1;
    }

    if (virDomainResctrlVcpuMatch(def, vcpus, &resctrl) < 0)
        return -1;

    if (resctrl) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Identical vcpus in cachetunes found"));
        return -1;
    }

    if (!(alloc = virResctrlAllocNew()))
        return -1;

    for (i = 0; i < n; i++) {
        if (virDomainCachetuneDefParseCache(ctxt, nodes[i], alloc) < 0)
            return -1;
    }

    if (!(resctrl = virDomainResctrlNew(node, alloc, vcpus, flags)))
        return -1;

    if (virDomainResctrlMonDefParse(def, ctxt, node,
                                    VIR_RESCTRL_MONITOR_TYPE_CACHE,
                                    resctrl) < 0)
        goto cleanup;

    /* If no <cache> element or <monitor> element in <cachetune>, do not
     * append any resctrl element */
    if (!resctrl->nmonitors && n == 0) {
        ret = 0;
        goto cleanup;
    }

    VIR_APPEND_ELEMENT(def->resctrls, def->nresctrls, resctrl);

    ret = 0;
 cleanup:
    virDomainResctrlDefFree(resctrl);
    return ret;
}


static int
virDomainDefParseIDs(virDomainDef *def,
                     xmlXPathContextPtr ctxt,
                     unsigned int flags,
                     bool *uuid_generated)
{
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;
    int n;

    def->id = -1;

    if (!(flags & VIR_DOMAIN_DEF_PARSE_INACTIVE)) {
        if (virXMLPropInt(ctxt->node, "id", 10, VIR_XML_PROP_NONNEGATIVE,
                          &def->id, -1) < 0)
            return -1;
    }

    /* Extract domain name */
    if (!(def->name = virXPathString("string(./name[1])", ctxt))) {
        virReportError(VIR_ERR_NO_NAME, NULL);
        return -1;
    }

    /* Extract domain uuid. If both uuid and sysinfo/system/entry/uuid
     * exist, they must match; and if only the latter exists, it can
     * also serve as the uuid. */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        if (virUUIDGenerate(def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            return -1;
        }
        *uuid_generated = true;
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            return -1;
        }
        VIR_FREE(tmp);
    }

    /* Extract domain genid - a genid can either be provided or generated */
    if ((n = virXPathNodeSet("./genid", ctxt, &nodes)) < 0)
        return -1;

    if (n > 0) {
        if (n != 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("element 'genid' can only appear once"));
            return -1;
        }
        def->genidRequested = true;
        if (!(tmp = virXPathString("string(./genid)", ctxt))) {
            if (virUUIDGenerate(def->genid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Failed to generate genid"));
                return -1;
            }
            def->genidGenerated = true;
        } else {
            if (virUUIDParse(tmp, def->genid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("malformed genid element"));
                return -1;
            }
            VIR_FREE(tmp);
        }
    }
    VIR_FREE(nodes);
    return 0;
}


static int
virDomainDefParseCaps(virDomainDef *def,
                      xmlXPathContextPtr ctxt,
                      virDomainXMLOption *xmlopt)
{
    g_autofree char *virttype = NULL;
    g_autofree char *arch = NULL;
    g_autofree char *ostype = NULL;

    virttype = virXPathString("string(./@type)", ctxt);
    ostype = virXPathString("string(./os/type[1])", ctxt);
    arch = virXPathString("string(./os/type[1]/@arch)", ctxt);

    def->os.bootloader = virXPathString("string(./bootloader)", ctxt);
    def->os.bootloaderArgs = virXPathString("string(./bootloader_args)", ctxt);
    def->os.machine = virXPathString("string(./os/type[1]/@machine)", ctxt);
    def->emulator = virXPathString("string(./devices/emulator[1])", ctxt);

    if (!virttype) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing domain type attribute"));
        return -1;
    }
    if ((def->virtType = virDomainVirtTypeFromString(virttype)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid domain type %1$s"), virttype);
        return -1;
    }

    if (!ostype) {
        if (def->os.bootloader) {
            def->os.type = VIR_DOMAIN_OSTYPE_XEN;
        } else {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("an os <type> must be specified"));
            return -1;
        }
    } else {
        if ((def->os.type = virDomainOSTypeFromString(ostype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown OS type '%1$s'"), ostype);
            return -1;
        }
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

    if (arch && !(def->os.arch = virArchFromString(arch))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown architecture %1$s"), arch);
        return -1;
    }

    if (def->os.arch == VIR_ARCH_NONE) {
        if (xmlopt && xmlopt->config.defArch != VIR_ARCH_NONE)
            def->os.arch = xmlopt->config.defArch;
        else
            def->os.arch = virArchFromHost();
    }

    return 0;
}


static int
virDomainDefParseMemory(virDomainDef *def,
                        xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;
    xmlNodePtr node = NULL;
    size_t i;
    int n;

    /* Extract domain memory */
    if (virDomainParseMemory("./memory[1]", NULL, ctxt,
                             &def->mem.total_memory, false, true) < 0)
        return -1;

    if (virDomainParseMemory("./currentMemory[1]", NULL, ctxt,
                             &def->mem.cur_balloon, false, true) < 0)
        return -1;

    if (virDomainParseMemory("./maxMemory[1]", NULL, ctxt,
                             &def->mem.max_memory, false, false) < 0)
        return -1;

    if (virXPathUInt("string(./maxMemory[1]/@slots)", ctxt, &def->mem.memory_slots) == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Failed to parse memory slot count"));
        return -1;
    }

    /* and info about it */
    if ((node = virXPathNode("./memory[1]", ctxt)) &&
        virXMLPropTristateSwitch(node, "dumpCore",
                                 VIR_XML_PROP_NONE,
                                 &def->mem.dump_core) < 0)
        return -1;

    tmp = virXPathString("string(./memoryBacking/source/@type)", ctxt);
    if (tmp) {
        if ((def->mem.source = virDomainMemorySourceTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/source/type '%1$s'"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./memoryBacking/access/@mode)", ctxt);
    if (tmp) {
        if ((def->mem.access = virDomainMemoryAccessTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/access/mode '%1$s'"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./memoryBacking/allocation/@mode)", ctxt);
    if (tmp) {
        if ((def->mem.allocation = virDomainMemoryAllocationTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memoryBacking/allocation/mode '%1$s'"), tmp);
            return -1;
        }
        VIR_FREE(tmp);
    }

    if (virXPathUInt("string(./memoryBacking/allocation/@threads)",
                     ctxt, &def->mem.allocation_threads) == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Failed to parse memory allocation threads"));
        return -1;
    }

    if (virXPathNode("./memoryBacking/hugepages", ctxt)) {
        /* hugepages will be used */
        if ((n = virXPathNodeSet("./memoryBacking/hugepages/page", ctxt, &nodes)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot extract hugepages nodes"));
            return -1;
        }

        if (n) {
            def->mem.hugepages = g_new0(virDomainHugePage, n);

            for (i = 0; i < n; i++) {
                if (virDomainHugepagesParseXML(nodes[i], ctxt,
                                               &def->mem.hugepages[i]) < 0)
                    return -1;
                def->mem.nhugepages++;
            }

            VIR_FREE(nodes);
        } else {
            /* no hugepage pages */
            def->mem.hugepages = g_new0(virDomainHugePage, 1);
            def->mem.nhugepages = 1;
        }
    }

    if (virXPathBoolean("boolean(./memoryBacking/nosharepages)", ctxt))
        def->mem.nosharepages = true;

    if (virXPathBoolean("boolean(./memoryBacking/locked)", ctxt))
        def->mem.locked = true;

    if (virXPathBoolean("boolean(./memoryBacking/discard)", ctxt))
        def->mem.discard = VIR_TRISTATE_BOOL_YES;

    return 0;
}


static int
virDomainMemorytuneDefParseMemory(xmlXPathContextPtr ctxt,
                                  xmlNodePtr node,
                                  virResctrlAlloc *alloc)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    unsigned int id;
    unsigned int bandwidth;

    ctxt->node = node;

    if (virXMLPropUInt(node, "id", 10, VIR_XML_PROP_REQUIRED, &id) < 0)
        return -1;

    if (virXMLPropUInt(node, "bandwidth", 10, VIR_XML_PROP_REQUIRED,
                       &bandwidth) < 0)
        return -1;

    if (virResctrlAllocSetMemoryBandwidth(alloc, id, bandwidth) < 0)
        return -1;

    return 0;
}


static int
virDomainMemorytuneDefParse(virDomainDef *def,
                            xmlXPathContextPtr ctxt,
                            xmlNodePtr node,
                            unsigned int flags)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virDomainResctrlDef *resctrl = NULL;
    virDomainResctrlDef *newresctrl = NULL;
    g_autoptr(virBitmap) vcpus = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autoptr(virResctrlAlloc) alloc = NULL;
    ssize_t i = 0;
    size_t nmons = 0;
    size_t ret = -1;

    int n;

    ctxt->node = node;

    if (virDomainResctrlParseVcpus(def, node, &vcpus) < 0)
        return -1;

    if (virBitmapIsAllClear(vcpus))
        return 0;

    if ((n = virXPathNodeSet("./node", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract memory nodes under memorytune"));
        return -1;
    }

    if (virDomainResctrlVcpuMatch(def, vcpus, &resctrl) < 0)
        return -1;

    if (resctrl) {
        alloc = virObjectRef(resctrl->alloc);
    } else {
        if (!(alloc = virResctrlAllocNew()))
            return -1;
    }

    /* First, parse <memorytune/node> element if any <node> element exists */
    for (i = 0; i < n; i++) {
        if (virDomainMemorytuneDefParseMemory(ctxt, nodes[i], alloc) < 0)
            return -1;
    }

    /*
     * If this is a new allocation, format ID and append to resctrl, otherwise
     * just update the existing alloc information, which is done in above
     * virDomainMemorytuneDefParseMemory */
    if (!resctrl) {
        if (!(newresctrl = virDomainResctrlNew(node, alloc, vcpus, flags)))
            return -1;

        resctrl = newresctrl;
    }

    /* Next, parse <memorytune/monitor> element */
    nmons = resctrl->nmonitors;
    if (virDomainResctrlMonDefParse(def, ctxt, node,
                                    VIR_RESCTRL_MONITOR_TYPE_MEMBW,
                                    resctrl) < 0)
        goto cleanup;

    nmons = resctrl->nmonitors - nmons;
    /* Now @nmons contains the new <monitor> element number found in current
     * <memorytune> element, and @n holds the number of new <node> element,
     * only append the new @newresctrl object to domain if any of them is
     * not zero. */
    if (newresctrl && (nmons || n)) {
        VIR_APPEND_ELEMENT(def->resctrls, def->nresctrls, newresctrl);
    }

    ret = 0;
 cleanup:
    virDomainResctrlDefFree(newresctrl);
    return ret;
}


static int
virDomainDefTunablesParse(virDomainDef *def,
                          xmlXPathContextPtr ctxt,
                          virDomainXMLOption *xmlopt,
                          unsigned int flags)
{
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;

    /* Extract blkio cgroup tunables */
    if (virXPathUInt("string(./blkiotune/weight)", ctxt,
                     &def->blkio.weight) < 0)
        def->blkio.weight = 0;

    if ((n = virXPathNodeSet("./blkiotune/device", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract blkiotune nodes"));
        return -1;
    }
    if (n)
        def->blkio.devices = g_new0(virBlkioDevice, n);

    for (i = 0; i < n; i++) {
        if (virDomainBlkioDeviceParseXML(nodes[i], ctxt,
                                         &def->blkio.devices[i]) < 0)
            return -1;
        def->blkio.ndevices++;
    }
    VIR_FREE(nodes);

    /* Extract other memory tunables */
    if (virDomainParseMemoryLimit("./memtune/hard_limit[1]", NULL, ctxt,
                                  &def->mem.hard_limit) < 0)
        return -1;

    if (virDomainParseMemoryLimit("./memtune/soft_limit[1]", NULL, ctxt,
                                  &def->mem.soft_limit) < 0)
        return -1;

    if (virDomainParseMemory("./memtune/min_guarantee[1]", NULL, ctxt,
                             &def->mem.min_guarantee, false, false) < 0)
        return -1;

    if (virDomainParseMemoryLimit("./memtune/swap_hard_limit[1]", NULL, ctxt,
                                  &def->mem.swap_hard_limit) < 0)
        return -1;

    if (virDomainVcpuParse(def, ctxt, xmlopt) < 0)
        return -1;

    if (virDomainDefParseIOThreads(def, ctxt) < 0)
        return -1;

    /* Extract cpu tunables. */
    if ((n = virXPathULongLong("string(./cputune/shares[1])", ctxt,
                               &def->cputune.shares)) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune shares value"));
        return -1;
    } else if (n == 0) {
        def->cputune.sharesSpecified = true;
    }

    if (virXPathULongLong("string(./cputune/period[1])", ctxt,
                          &def->cputune.period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune period value"));
        return -1;
    }

    if (virXPathLongLong("string(./cputune/quota[1])", ctxt,
                         &def->cputune.quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune quota value"));
        return -1;
    }

    if (virXPathULongLong("string(./cputune/global_period[1])", ctxt,
                          &def->cputune.global_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune global period value"));
        return -1;
    }

    if (virXPathLongLong("string(./cputune/global_quota[1])", ctxt,
                         &def->cputune.global_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune global quota value"));
        return -1;
    }

    if (virXPathULongLong("string(./cputune/emulator_period[1])", ctxt,
                          &def->cputune.emulator_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune emulator period value"));
        return -1;
    }

    if (virXPathLongLong("string(./cputune/emulator_quota[1])", ctxt,
                         &def->cputune.emulator_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune emulator quota value"));
        return -1;
    }


    if (virXPathULongLong("string(./cputune/iothread_period[1])", ctxt,
                          &def->cputune.iothread_period) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune iothread period value"));
        return -1;
    }

    if (virXPathLongLong("string(./cputune/iothread_quota[1])", ctxt,
                         &def->cputune.iothread_quota) < -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("can't parse cputune iothread quota value"));
        return -1;
    }

    if ((n = virXPathNodeSet("./cputune/vcpupin", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        if (virDomainVcpuPinDefParseXML(def, nodes[i]))
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/emulatorpin", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract emulatorpin nodes"));
        return -1;
    }

    if (n) {
        if (n > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("only one emulatorpin is supported"));
            return -1;
        }

        if (!(def->cputune.emulatorpin = virDomainEmulatorPinDefParseXML(nodes[0])))
            return -1;
    }
    VIR_FREE(nodes);


    if ((n = virXPathNodeSet("./cputune/iothreadpin", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract iothreadpin nodes"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (virDomainIOThreadPinDefParseXML(nodes[i], def) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/vcpusched", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract vcpusched nodes"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (virDomainVcpuThreadSchedParse(nodes[i], def) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/iothreadsched", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract iothreadsched nodes"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (virDomainIOThreadSchedParse(nodes[i], def) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/emulatorsched", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract emulatorsched nodes"));
        return -1;
    }

    if (n) {
        if (n > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("only one emulatorsched is supported"));
            return -1;
        }

        if (virDomainEmulatorSchedParse(nodes[0], def) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/cachetune", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract cachetune nodes"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (virDomainCachetuneDefParse(def, ctxt, nodes[i], flags) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./cputune/memorytune", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract memorytune nodes"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        if (virDomainMemorytuneDefParse(def, ctxt, nodes[i], flags) < 0)
            return -1;
    }
    VIR_FREE(nodes);

    return 0;
}


static int
virDomainDefLifecycleParse(virDomainDef *def,
                           xmlXPathContextPtr ctxt)
{
    if (virDomainEventActionParseXML(ctxt, "on_reboot",
                                     "string(./on_reboot[1])",
                                     &def->onReboot,
                                     VIR_DOMAIN_LIFECYCLE_ACTION_RESTART,
                                     virDomainLifecycleActionTypeFromString) < 0)
        return -1;

    if (virDomainEventActionParseXML(ctxt, "on_poweroff",
                                     "string(./on_poweroff[1])",
                                     &def->onPoweroff,
                                     VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY,
                                     virDomainLifecycleActionTypeFromString) < 0)
        return -1;

    if (virDomainEventActionParseXML(ctxt, "on_crash",
                                     "string(./on_crash[1])",
                                     &def->onCrash,
                                     VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY,
                                     virDomainLifecycleActionTypeFromString) < 0)
        return -1;

    if (virDomainEventActionParseXML(ctxt, "on_lockfailure",
                                     "string(./on_lockfailure[1])",
                                     &def->onLockFailure,
                                     VIR_DOMAIN_LOCK_FAILURE_DEFAULT,
                                     virDomainLockFailureTypeFromString) < 0)
        return -1;

    if (virDomainPMStateParseXML(ctxt,
                                 "./pm/suspend-to-mem",
                                 &def->pm.s3) < 0)
        return -1;

    if (virDomainPMStateParseXML(ctxt,
                                 "./pm/suspend-to-disk",
                                 &def->pm.s4) < 0)
        return -1;

    return 0;
}


static int
virDomainDefClockParse(virDomainDef *def,
                       xmlXPathContextPtr ctxt)
{
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;

    if ((tmp = virXPathString("string(./clock/@offset)", ctxt)) &&
        (def->clock.offset = virDomainClockOffsetTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown clock offset '%1$s'"), tmp);
        return -1;
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
                                   _("unknown clock adjustment '%1$s'"),
                                   tmp);
                    return -1;
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
        if (virXPathLongLong("string(./clock/@adjustment)", ctxt,
                             &def->clock.data.variable.adjustment) < 0)
            def->clock.data.variable.adjustment = 0;
        if (virXPathLongLong("string(./clock/@adjustment0)", ctxt,
                             &def->clock.data.variable.adjustment0) < 0)
            def->clock.data.variable.adjustment0 = 0;
        tmp = virXPathString("string(./clock/@basis)", ctxt);
        if (tmp) {
            if ((def->clock.data.variable.basis = virDomainClockBasisTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown clock basis '%1$s'"), tmp);
                return -1;
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
            return -1;
        }
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_ABSOLUTE:
        if (virXPathULongLong("string(./clock/@start)", ctxt,
                              &def->clock.data.starttime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing 'start' attribute for clock with offset='absolute'"));
            return -1;
        }
        break;
    }

    if ((n = virXPathNodeSet("./clock/timer", ctxt, &nodes)) < 0)
        return -1;

    if (n)
        def->clock.timers = g_new0(virDomainTimerDef *, n);

    for (i = 0; i < n; i++) {
        virDomainTimerDef *timer = virDomainTimerDefParseXML(nodes[i], ctxt);

        if (!timer)
            return -1;

        def->clock.timers[def->clock.ntimers++] = timer;
    }
    VIR_FREE(nodes);

    return 0;
}

static int
virDomainDefControllersParse(virDomainDef *def,
                             xmlXPathContextPtr ctxt,
                             virDomainXMLOption *xmlopt,
                             unsigned int flags,
                             bool *usb_none)
{
    g_autofree xmlNodePtr *nodes = NULL;
    bool usb_other = false;
    bool usb_master = false;
    size_t i;
    int n;

    if ((n = virXPathNodeSet("./devices/controller", ctxt, &nodes)) < 0)
        return -1;

    if (n)
        def->controllers = g_new0(virDomainControllerDef *, n);

    for (i = 0; i < n; i++) {
        g_autoptr(virDomainControllerDef) controller = NULL;

        controller = virDomainControllerDefParseXML(xmlopt, nodes[i],
                                                    ctxt, flags);

        if (!controller)
            return -1;

        /* sanitize handling of "none" usb controller */
        if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
                if (usb_other || *usb_none) {
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Can't add another USB controller: USB is disabled for this domain"));
                    return -1;
                }
                *usb_none = true;
            } else {
                if (*usb_none) {
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Can't add another USB controller: USB is disabled for this domain"));
                    return -1;
                }
                usb_other = true;
            }

            if (controller->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_NONE)
                usb_master = true;
        }

        virDomainControllerInsertPreAlloced(def, g_steal_pointer(&controller));
    }

    if (usb_other && !usb_master) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("No master USB controller specified"));
        return -1;
    }

    return 0;
}

static virDomainDef *
virDomainDefParseXML(xmlXPathContextPtr ctxt,
                     virDomainXMLOption *xmlopt,
                     unsigned int flags)
{
    xmlNodePtr node = NULL;
    size_t i, j;
    int n;
    bool uuid_generated = false;
    bool usb_none = false;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *tmp = NULL;
    g_autoptr(virDomainDef) def = NULL;

    if (!(def = virDomainDefNew(xmlopt)))
        return NULL;

    if (virDomainDefParseIDs(def, ctxt, flags, &uuid_generated) < 0)
        return NULL;

    if (virDomainDefParseCaps(def, ctxt, xmlopt) < 0)
        return NULL;

    /* Extract short description of domain (title) */
    def->title = virXPathString("string(./title[1])", ctxt);
    if (def->title && strchr(def->title, '\n')) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Domain title can't contain newlines"));
        return NULL;
    }

    /* Extract documentation if present */
    def->description = virXPathString("string(./description[1])", ctxt);

    /* analysis of security label, done early even though we format it
     * late, so devices can refer to this for defaults */
    if (!(flags & VIR_DOMAIN_DEF_PARSE_SKIP_SECLABEL)) {
        if (virSecurityLabelDefsParseXML(def, ctxt, xmlopt, flags) == -1)
            return NULL;
    }

    if (virDomainDefParseMemory(def, ctxt) < 0)
        return NULL;

    if (virDomainDefTunablesParse(def, ctxt, xmlopt, flags) < 0)
        return NULL;

    if (virCPUDefParseXML(ctxt, "./cpu[1]", VIR_CPU_TYPE_GUEST, &def->cpu,
                          false) < 0)
        return NULL;

    if (virDomainNumaDefParseXML(def->numa, ctxt) < 0)
        return NULL;

    if (virDomainNumaGetCPUCountTotal(def->numa) > virDomainDefGetVcpusMax(def)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Number of CPUs in <numa> exceeds the <vcpu> count"));
        return NULL;
    }

    if (virDomainNumaGetMaxCPUID(def->numa) >= virDomainDefGetVcpusMax(def)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("CPU IDs in <numa> exceed the <vcpu> count"));
        return NULL;
    }

    if (virDomainNumatuneParseXML(def->numa,
                                  def->placement_mode ==
                                  VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
                                  ctxt) < 0)
        return NULL;

    if (virDomainNumatuneHasPlacementAuto(def->numa) &&
        !def->cpumask && !virDomainDefHasVcpuPin(def) &&
        !def->cputune.emulatorpin &&
        !virDomainIOThreadIDArrayHasPin(def))
        def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO;

    if ((n = virXPathNodeSet("./resource", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract resource nodes"));
        return NULL;
    }

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one resource element is supported"));
        return NULL;
    }

    if (n &&
        !(def->resource = virDomainResourceDefParse(nodes[0], ctxt)))
        return NULL;
    VIR_FREE(nodes);

    if (virDomainFeaturesDefParse(def, ctxt) < 0)
        return NULL;

    if (virDomainDefLifecycleParse(def, ctxt) < 0)
        return NULL;

    if (virDomainPerfDefParseXML(def, ctxt) < 0)
        return NULL;

    if (virDomainDefClockParse(def, ctxt) < 0)
        return NULL;

    if (virDomainDefParseBootOptions(def, ctxt, xmlopt, flags) < 0)
        return NULL;

    /* analysis of the disk devices */
    if ((n = virXPathNodeSet("./devices/disk", ctxt, &nodes)) < 0)
        return NULL;

    for (i = 0; i < n; i++) {
        virDomainDiskDef *disk = virDomainDiskDefParseXML(xmlopt,
                                                          nodes[i],
                                                          ctxt,
                                                          flags);
        if (!disk)
            return NULL;

        virDomainDiskInsert(def, disk);
    }
    VIR_FREE(nodes);

    if (virDomainDefControllersParse(def, ctxt, xmlopt, flags, &usb_none) < 0)
        return NULL;

    /* analysis of the resource leases */
    if ((n = virXPathNodeSet("./devices/lease", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract device leases"));
        return NULL;
    }
    if (n)
        def->leases = g_new0(virDomainLeaseDef *, n);
    for (i = 0; i < n; i++) {
        virDomainLeaseDef *lease = virDomainLeaseDefParseXML(nodes[i], ctxt);
        if (!lease)
            return NULL;

        def->leases[def->nleases++] = lease;
    }
    VIR_FREE(nodes);

    /* analysis of the filesystems */
    if ((n = virXPathNodeSet("./devices/filesystem", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->fss = g_new0(virDomainFSDef *, n);
    for (i = 0; i < n; i++) {
        virDomainFSDef *fs = virDomainFSDefParseXML(xmlopt,
                                                    nodes[i],
                                                    ctxt,
                                                    flags);
        if (!fs)
            return NULL;

        def->fss[def->nfss++] = fs;
    }
    VIR_FREE(nodes);

    /* analysis of the network devices */
    if ((n = virXPathNodeSet("./devices/interface", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->nets = g_new0(virDomainNetDef *, n);
    for (i = 0; i < n; i++) {
        virDomainNetDef *net = virDomainNetDefParseXML(xmlopt,
                                                       nodes[i],
                                                       ctxt,
                                                       flags);
        if (!net)
            return NULL;

        def->nets[def->nnets++] = net;

        /* <interface type='hostdev'> (and <interface type='net'>
         * where the actual network type is already known to be
         * hostdev) must also be in the hostdevs array.
         */
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            virDomainHostdevInsert(def, virDomainNetGetActualHostdev(net)) < 0) {
            return NULL;
        }
    }
    VIR_FREE(nodes);


    /* analysis of the smartcard devices */
    if ((n = virXPathNodeSet("./devices/smartcard", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->smartcards = g_new0(virDomainSmartcardDef *, n);

    for (i = 0; i < n; i++) {
        virDomainSmartcardDef *card = virDomainSmartcardDefParseXML(xmlopt,
                                                                    nodes[i],
                                                                    ctxt,
                                                                    flags);
        if (!card)
            return NULL;

        def->smartcards[def->nsmartcards++] = card;
    }
    VIR_FREE(nodes);


    /* analysis of the character devices */
    if ((n = virXPathNodeSet("./devices/parallel", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->parallels = g_new0(virDomainChrDef *, n);

    for (i = 0; i < n; i++) {
        virDomainChrDef *chr = virDomainChrDefParseXML(xmlopt,
                                                       ctxt,
                                                       nodes[i],
                                                       flags);
        if (!chr)
            return NULL;

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
        return NULL;

    if (n)
        def->serials = g_new0(virDomainChrDef *, n);

    for (i = 0; i < n; i++) {
        virDomainChrDef *chr = virDomainChrDefParseXML(xmlopt,
                                                       ctxt,
                                                       nodes[i],
                                                       flags);
        if (!chr)
            return NULL;

        def->serials[def->nserials++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/console", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot extract console devices"));
        return NULL;
    }
    if (n)
        def->consoles = g_new0(virDomainChrDef *, n);

    for (i = 0; i < n; i++) {
        virDomainChrDef *chr = virDomainChrDefParseXML(xmlopt,
                                                       ctxt,
                                                       nodes[i],
                                                       flags);
        if (!chr)
            return NULL;

        chr->target.port = i;
        def->consoles[def->nconsoles++] = chr;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/channel", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->channels = g_new0(virDomainChrDef *, n);

    for (i = 0; i < n; i++) {
        virDomainChrDef *chr = virDomainChrDefParseXML(xmlopt,
                                                       ctxt,
                                                       nodes[i],
                                                       flags);
        if (!chr)
            return NULL;

        def->channels[def->nchannels++] = chr;
    }
    VIR_FREE(nodes);


    /* analysis of the input devices */
    if ((n = virXPathNodeSet("./devices/input", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->inputs = g_new0(virDomainInputDef *, n);

    for (i = 0; i < n; i++) {
        virDomainInputDef *input = virDomainInputDefParseXML(xmlopt,
                                                             nodes[i],
                                                             ctxt,
                                                             flags);
        if (!input)
            return NULL;

        /* Check if USB bus is required */
        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB && usb_none) {
            virDomainInputDefFree(input);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add USB input device. USB bus is disabled"));
            return NULL;
        }

        def->inputs[def->ninputs++] = input;
    }
    VIR_FREE(nodes);

    /* analysis of the graphics devices */
    if ((n = virXPathNodeSet("./devices/graphics", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->graphics = g_new0(virDomainGraphicsDef *, n);
    for (i = 0; i < n; i++) {
        virDomainGraphicsDef *graphics = virDomainGraphicsDefParseXML(xmlopt,
                                                                      nodes[i],
                                                                      ctxt,
                                                                      flags);
        if (!graphics)
            return NULL;

        def->graphics[def->ngraphics++] = graphics;
    }
    VIR_FREE(nodes);

    /* analysis of the sound devices */
    if ((n = virXPathNodeSet("./devices/sound", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->sounds = g_new0(virDomainSoundDef *, n);
    for (i = 0; i < n; i++) {
        virDomainSoundDef *sound = virDomainSoundDefParseXML(xmlopt,
                                                             nodes[i],
                                                             ctxt,
                                                             flags);
        if (!sound)
            return NULL;

        def->sounds[def->nsounds++] = sound;
    }
    VIR_FREE(nodes);

    /* analysis of the audio devices */
    if ((n = virXPathNodeSet("./devices/audio", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->audios = g_new0(virDomainAudioDef *, n);
    for (i = 0; i < n; i++) {
        virDomainAudioDef *audio = virDomainAudioDefParseXML(xmlopt,
                                                             nodes[i],
                                                             ctxt);
        if (!audio)
            return NULL;

        def->audios[def->naudios++] = audio;
    }
    VIR_FREE(nodes);

    /* analysis of the video devices */
    if ((n = virXPathNodeSet("./devices/video", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->videos = g_new0(virDomainVideoDef *, n);
    for (i = 0; i < n; i++) {
        g_autoptr(virDomainVideoDef) video = NULL;
        ssize_t insertAt = -1;

        if (!(video = virDomainVideoDefParseXML(xmlopt, nodes[i],
                                                ctxt, flags)))
            return NULL;

        if (video->primary) {
            insertAt = 0;
        }

        if (VIR_INSERT_ELEMENT_INPLACE(def->videos,
                                       insertAt,
                                       def->nvideos,
                                       video) < 0) {
            return NULL;
        }
    }

    VIR_FREE(nodes);

    /* analysis of the host devices */
    if ((n = virXPathNodeSet("./devices/hostdev", ctxt, &nodes)) < 0)
        return NULL;
    if (n > 0)
        VIR_REALLOC_N(def->hostdevs, def->nhostdevs + n);

    for (i = 0; i < n; i++) {
        virDomainHostdevDef *hostdev;

        hostdev = virDomainHostdevDefParseXML(xmlopt, nodes[i], ctxt,
                                              flags);
        if (!hostdev)
            return NULL;

        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
            usb_none) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add host USB device: USB is disabled in this host"));
            virDomainHostdevDefFree(hostdev);
            return NULL;
        }

        def->hostdevs[def->nhostdevs++] = hostdev;

        /* For a domain definition, we need to check if the controller
         * for this hostdev exists yet and if not add it. This cannot be
         * done during virDomainHostdevAssignAddress (as part of device
         * post processing) because that will result in the failure to
         * load the controller during hostdev hotplug.
         */
        if (virDomainDefMaybeAddHostdevSCSIcontroller(def) < 0)
            return NULL;
    }
    VIR_FREE(nodes);

    /* analysis of the watchdog devices */
    n = virXPathNodeSet("./devices/watchdog", ctxt, &nodes);
    if (n < 0)
        return NULL;
    if (n)
        def->watchdogs = g_new0(virDomainWatchdogDef *, n);
    for (i = 0; i < n; i++) {
        virDomainWatchdogDef *watchdog;

        watchdog = virDomainWatchdogDefParseXML(xmlopt, nodes[i], ctxt, flags);
        if (!watchdog)
            return NULL;

        def->watchdogs[def->nwatchdogs++] = watchdog;
    }
    VIR_FREE(nodes);

    /* analysis of the memballoon devices */
    def->memballoon = NULL;
    if ((n = virXPathNodeSet("./devices/memballoon", ctxt, &nodes)) < 0)
        return NULL;
    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only a single memory balloon device is supported"));
        return NULL;
    }
    if (n > 0) {
        virDomainMemballoonDef *memballoon;

        memballoon = virDomainMemballoonDefParseXML(xmlopt, nodes[0], ctxt, flags);
        if (!memballoon)
            return NULL;

        def->memballoon = memballoon;
        VIR_FREE(nodes);
    }

    /* Parse the RNG devices */
    if ((n = virXPathNodeSet("./devices/rng", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->rngs = g_new0(virDomainRNGDef *, n);
    for (i = 0; i < n; i++) {
        virDomainRNGDef *rng = virDomainRNGDefParseXML(xmlopt, nodes[i],
                                                       ctxt, flags);
        if (!rng)
            return NULL;

        def->rngs[def->nrngs++] = rng;
    }
    VIR_FREE(nodes);

    /* Parse the crypto devices */
    if ((n = virXPathNodeSet("./devices/crypto", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->cryptos = g_new0(virDomainCryptoDef *, n);
    for (i = 0; i < n; i++) {
        virDomainCryptoDef *crypto = virDomainCryptoDefParseXML(xmlopt, nodes[i],
                                                                ctxt, flags);
        if (!crypto)
            return NULL;

        def->cryptos[def->ncryptos++] = crypto;
    }
    VIR_FREE(nodes);

    /* Parse the TPM devices */
    if ((n = virXPathNodeSet("./devices/tpm", ctxt, &nodes)) < 0)
        return NULL;

    if (n > 2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("a maximum of two TPM devices is supported, one of them being a TPM Proxy device"));
        return NULL;
    }

    if (n)
        def->tpms = g_new0(virDomainTPMDef *, n);

    for (i = 0; i < n; i++) {
        virDomainTPMDef *tpm = virDomainTPMDefParseXML(xmlopt, nodes[i],
                                                       ctxt, flags);
        if (!tpm)
            return NULL;

        def->tpms[def->ntpms++] = tpm;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/nvram", ctxt, &nodes)) < 0)
        return NULL;

    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only a single nvram device is supported"));
        return NULL;
    } else if (n == 1) {
        virDomainNVRAMDef *nvram =
            virDomainNVRAMDefParseXML(xmlopt, nodes[0], ctxt, flags);
        if (!nvram)
            return NULL;
        def->nvram = nvram;
        VIR_FREE(nodes);
    }

    /* analysis of the hub devices */
    if ((n = virXPathNodeSet("./devices/hub", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->hubs = g_new0(virDomainHubDef *, n);
    for (i = 0; i < n; i++) {
        virDomainHubDef *hub;

        hub = virDomainHubDefParseXML(xmlopt, nodes[i], ctxt, flags);
        if (!hub)
            return NULL;

        if (hub->type == VIR_DOMAIN_HUB_TYPE_USB && usb_none) {
            virDomainHubDefFree(hub);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Can't add USB hub: USB is disabled for this domain"));
            return NULL;
        }

        def->hubs[def->nhubs++] = hub;
    }
    VIR_FREE(nodes);

    /* analysis of the redirected devices */
    if ((n = virXPathNodeSet("./devices/redirdev", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->redirdevs = g_new0(virDomainRedirdevDef *, n);
    for (i = 0; i < n; i++) {
        virDomainRedirdevDef *redirdev =
            virDomainRedirdevDefParseXML(xmlopt, nodes[i], ctxt, flags);
        if (!redirdev)
            return NULL;

        def->redirdevs[def->nredirdevs++] = redirdev;
    }
    VIR_FREE(nodes);

    /* analysis of the redirection filter rules */
    if ((n = virXPathNodeSet("./devices/redirfilter", ctxt, &nodes)) < 0)
        return NULL;
    if (n > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only one set of redirection filter rule is supported"));
        return NULL;
    }

    if (n) {
        virDomainRedirFilterDef *redirfilter =
            virDomainRedirFilterDefParseXML(nodes[0], ctxt);
        if (!redirfilter)
            return NULL;

        def->redirfilter = redirfilter;
    }
    VIR_FREE(nodes);

    /* analysis of the panic devices */
    if ((n = virXPathNodeSet("./devices/panic", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->panics = g_new0(virDomainPanicDef *, n);
    for (i = 0; i < n; i++) {
        virDomainPanicDef *panic;

        panic = virDomainPanicDefParseXML(xmlopt, nodes[i], ctxt, flags);
        if (!panic)
            return NULL;

        def->panics[def->npanics++] = panic;
    }
    VIR_FREE(nodes);

    /* analysis of the shmem devices */
    if ((n = virXPathNodeSet("./devices/shmem", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->shmems = g_new0(virDomainShmemDef *, n);

    node = ctxt->node;
    for (i = 0; i < n; i++) {
        virDomainShmemDef *shmem;
        ctxt->node = nodes[i];
        shmem = virDomainShmemDefParseXML(xmlopt, nodes[i], ctxt, flags);
        if (!shmem)
            return NULL;

        def->shmems[def->nshmems++] = shmem;
    }
    ctxt->node = node;
    VIR_FREE(nodes);

    /* Check for launch security e.g. SEV feature */
    if ((node = virXPathNode("./launchSecurity", ctxt)) != NULL) {
        def->sec = virDomainSecDefParseXML(node, ctxt);
        if (!def->sec)
            return NULL;
    }

    /* analysis of memory devices */
    if ((n = virXPathNodeSet("./devices/memory", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->mems = g_new0(virDomainMemoryDef *, n);

    for (i = 0; i < n; i++) {
        virDomainMemoryDef *mem = virDomainMemoryDefParseXML(xmlopt,
                                                             nodes[i],
                                                             ctxt,
                                                             flags);
        if (!mem)
            return NULL;

        def->mems[def->nmems++] = mem;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/iommu", ctxt, &nodes)) < 0)
        return NULL;

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only a single IOMMU device is supported"));
        return NULL;
    }

    if (n > 0) {
        if (!(def->iommu = virDomainIOMMUDefParseXML(xmlopt, nodes[0],
                                                     ctxt, flags)))
            return NULL;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./devices/vsock", ctxt, &nodes)) < 0)
        return NULL;

    if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only a single vsock device is supported"));
        return NULL;
    }

    if (n > 0) {
        if (!(def->vsock = virDomainVsockDefParseXML(xmlopt, nodes[0],
                                                     ctxt, flags)))
            return NULL;
    }
    VIR_FREE(nodes);

    /* analysis of the user namespace mapping */
    if ((n = virXPathNodeSet("./idmap/uid", ctxt, &nodes)) < 0)
        return NULL;

    if (n) {
        def->idmap.uidmap = virDomainIdmapDefParseXML(ctxt, nodes, n);
        if (!def->idmap.uidmap)
            return NULL;

        def->idmap.nuidmap = n;
    }
    VIR_FREE(nodes);

    if  ((n = virXPathNodeSet("./idmap/gid", ctxt, &nodes)) < 0)
        return NULL;

    if (n) {
        def->idmap.gidmap =  virDomainIdmapDefParseXML(ctxt, nodes, n);
        if (!def->idmap.gidmap)
            return NULL;

        def->idmap.ngidmap = n;
    }
    VIR_FREE(nodes);

    if ((n = virXPathNodeSet("./sysinfo", ctxt, &nodes)) < 0)
        return NULL;

    def->sysinfo = g_new0(virSysinfoDef *, n);

    for (i = 0; i < n; i++) {
        virSysinfoDef *sysinfo = virSysinfoParseXML(nodes[i], ctxt,
                                                    def->uuid, uuid_generated);

        if (!sysinfo)
            return NULL;

        def->sysinfo[def->nsysinfo++] = sysinfo;
    }
    VIR_FREE(nodes);

    if ((tmp = virXPathString("string(./os/smbios/@mode)", ctxt))) {
        int mode;

        if ((mode = virDomainSmbiosModeTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown smbios mode '%1$s'"), tmp);
            return NULL;
        }
        def->os.smbios_mode = mode;
    }

    if (virDomainKeyWrapDefParseXML(def, ctxt) < 0)
        return NULL;

    /* Extract custom metadata */
    if ((node = virXPathNode("./metadata[1]", ctxt)) != NULL)
        def->metadata = xmlCopyNode(node, 1);

    /* we have to make a copy of all of the callback pointers here since
     * we won't have the virCaps structure available during free
     */
    def->ns = xmlopt->ns;

    if (def->ns.parse) {
        if (virXMLNamespaceRegister(ctxt, &def->ns) < 0)
            return NULL;
        if ((def->ns.parse)(ctxt, &def->namespaceData) < 0)
            return NULL;
    }

    return g_steal_pointer(&def);
}


static virDomainObj *
virDomainObjParseXML(xmlXPathContextPtr ctxt,
                     virDomainXMLOption *xmlopt,
                     unsigned int flags)
{
    long long vmpid;
    xmlNodePtr config;
    xmlNodePtr oldnode;
    g_autoptr(virDomainObj) obj = NULL;
    size_t i;
    int n;
    virDomainState state;
    int reason = 0;
    void *parseOpaque = NULL;
    g_autofree char *tmp = NULL;
    g_autofree xmlNodePtr *taintNodes = NULL;
    g_autofree xmlNodePtr *depNodes = NULL;

    if (!(obj = virDomainObjNew(xmlopt)))
        return NULL;

    if (!(config = virXPathNode("./domain", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no domain config"));
        return NULL;
    }

    oldnode = ctxt->node;
    ctxt->node = config;
    obj->def = virDomainDefParseXML(ctxt, xmlopt, flags);
    ctxt->node = oldnode;
    if (!obj->def)
        return NULL;

    if (virXMLPropEnum(ctxt->node, "state", virDomainStateTypeFromString,
                       VIR_XML_PROP_REQUIRED, &state) < 0)
        return NULL;

    if ((tmp = virXMLPropString(ctxt->node, "reason"))) {
        if ((reason = virDomainStateReasonFromString(state, tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid domain state reason '%1$s'"), tmp);
            return NULL;
        }
    }

    virDomainObjSetState(obj, state, reason);

    if (virXMLPropLongLong(ctxt->node, "pid", 10, VIR_XML_PROP_REQUIRED,
                           &vmpid, 0) < 0)
        return NULL;

    obj->pid = (pid_t) vmpid;

    if ((n = virXPathNodeSet("./taint", ctxt, &taintNodes)) < 0)
        return NULL;
    for (i = 0; i < n; i++) {
        int rc;
        virDomainTaintFlags taint;

        if ((rc = virXMLPropEnum(taintNodes[i], "flag",
                                 virDomainTaintTypeFromString,
                                 VIR_XML_PROP_NONE, &taint)) < 0)
            return NULL;

        if (rc == 1)
            virDomainObjTaint(obj, taint);
    }

    if ((n = virXPathNodeSet("./deprecation", ctxt, &depNodes)) < 0)
        return NULL;
    for (i = 0; i < n; i++) {
        g_autofree char *str = virXMLNodeContentString(depNodes[i]);
        virDomainObjDeprecation(obj, str);
    }

    if (xmlopt->privateData.parse &&
        xmlopt->privateData.parse(ctxt, obj, &xmlopt->config) < 0)
        return NULL;

    if (xmlopt->privateData.getParseOpaque)
        parseOpaque = xmlopt->privateData.getParseOpaque(obj);

    /* callback to fill driver specific domain aspects */
    if (virDomainDefPostParse(obj->def, flags, xmlopt, parseOpaque) < 0)
        return NULL;

    /* validate configuration */
    if (virDomainDefValidate(obj->def, flags, xmlopt, parseOpaque) < 0)
        return NULL;

    return g_steal_pointer(&obj);
}


static virDomainDef *
virDomainDefParse(const char *xmlStr,
                  const char *filename,
                  virDomainXMLOption *xmlopt,
                  void *parseOpaque,
                  unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);
    bool validate = flags & VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    xml = virXMLParse(filename, xmlStr, _("(domain_definition)"),
                      "domain", &ctxt, "domain.rng", validate);

    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virDomainDefParseNode(ctxt, xmlopt, parseOpaque, flags);
}

virDomainDef *
virDomainDefParseString(const char *xmlStr,
                        virDomainXMLOption *xmlopt,
                        void *parseOpaque,
                        unsigned int flags)
{
    return virDomainDefParse(xmlStr, NULL, xmlopt, parseOpaque, flags);
}

virDomainDef *
virDomainDefParseFile(const char *filename,
                      virDomainXMLOption *xmlopt,
                      void *parseOpaque,
                      unsigned int flags)
{
    return virDomainDefParse(NULL, filename, xmlopt, parseOpaque, flags);
}


virDomainDef *
virDomainDefParseNode(xmlXPathContext *ctxt,
                      virDomainXMLOption *xmlopt,
                      void *parseOpaque,
                      unsigned int flags)
{
    g_autoptr(virDomainDef) def = NULL;

    if (!(def = virDomainDefParseXML(ctxt, xmlopt, flags)))
        return NULL;

    /* callback to fill driver specific domain aspects */
    if (virDomainDefPostParse(def, flags, xmlopt, parseOpaque) < 0)
        return NULL;

    /* validate configuration */
    if (virDomainDefValidate(def, flags, xmlopt, parseOpaque) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


virDomainObj *
virDomainObjParseFile(const char *filename,
                      virDomainXMLOption *xmlopt,
                      unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    xml = virXMLParse(filename, NULL, NULL, "domstatus", &ctxt, NULL, false);
    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virDomainObjParseXML(ctxt, xmlopt, flags);
}


static bool
virDomainTimerDefCheckABIStability(virDomainTimerDef *src,
                                   virDomainTimerDef *dst)
{
    if (src->name != dst->name) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target timer %1$s does not match source %2$s"),
                       virDomainTimerNameTypeToString(dst->name),
                       virDomainTimerNameTypeToString(src->name));
        return false;
    }

    if (src->present != dst->present) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target timer presence '%1$s' does not match source '%2$s'"),
                       virTristateBoolTypeToString(dst->present),
                       virTristateBoolTypeToString(src->present));
        return false;
    }

    if (src->name == VIR_DOMAIN_TIMER_NAME_TSC) {
        if (src->frequency != dst->frequency) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target TSC frequency %1$llu does not match source %2$llu"),
                           dst->frequency, src->frequency);
            return false;
        }

        if (src->mode != dst->mode) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target TSC mode %1$s does not match source %2$s"),
                           virDomainTimerModeTypeToString(dst->mode),
                           virDomainTimerModeTypeToString(src->mode));
            return false;
        }
    }

    return true;
}


static bool
virDomainDeviceInfoCheckABIStability(virDomainDeviceInfo *src,
                                     virDomainDeviceInfo *dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device address type %1$s does not match source %2$s"),
                       virDomainDeviceAddressTypeToString(dst->type),
                       virDomainDeviceAddressTypeToString(src->type));
        return false;
    }

    switch (src->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (src->addr.pci.domain != dst->addr.pci.domain ||
            src->addr.pci.bus != dst->addr.pci.bus ||
            src->addr.pci.slot != dst->addr.pci.slot ||
            src->addr.pci.function != dst->addr.pci.function) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device PCI address %1$04x:%2$02x:%3$02x.%4$d does not match source %5$04x:%6$02x:%7$02x.%8$d"),
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
                           _("Target device drive address %1$d:%2$d:%3$d does not match source %4$d:%5$d:%6$d"),
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
                           _("Target device virtio serial address %1$d:%2$d:%3$d does not match source %4$d:%5$d:%6$d"),
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
                           _("Target device ccid address %1$d:%2$d does not match source %3$d:%4$d"),
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
                           _("Target device isa address %1$d:%2$d does not match source %3$d:%4$d"),
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
                           _("Target device dimm slot %1$u does not match source %2$u"),
                           dst->addr.dimm.slot,
                           src->addr.dimm.slot);
            return false;
        }

        if (src->addr.dimm.base != dst->addr.dimm.base) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target device dimm base address '%1$llx' does not match source '%2$llx'"),
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
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    if (src->acpiIndex != dst->acpiIndex) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target ACPI index '%1$u' does not match source '%2$u'"),
                       dst->acpiIndex, src->acpiIndex);
        return false;
    }

    return true;
}


static bool
virDomainVirtioOptionsCheckABIStability(virDomainVirtioOptions *src,
                                        virDomainVirtioOptions *dst)
{
    if (!src && !dst)
        return true;

    if (!src || !dst) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target device virtio options don't match the source"));
        return false;
    }

    if (src->iommu != dst->iommu) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device iommu option '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->iommu),
                       virTristateSwitchTypeToString(src->iommu));
        return false;
    }
    if (src->ats != dst->ats) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device ats option '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->ats),
                       virTristateSwitchTypeToString(src->ats));
        return false;
    }
    if (src->packed != dst->packed) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device packed option '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->packed),
                       virTristateSwitchTypeToString(src->packed));
        return false;
    }
    if (src->page_per_vq != dst->page_per_vq) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target device page_per_vq option '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->page_per_vq),
                       virTristateSwitchTypeToString(src->page_per_vq));
        return false;
    }
    return true;
}


static bool
virDomainDiskBlockIoCheckABIStability(virDomainDiskDef *src,
                                      virDomainDiskDef *dst)
{
    if (src->blockio.logical_block_size != dst->blockio.logical_block_size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk logical_block_size %1$u does not match source %2$u"),
                       dst->blockio.logical_block_size, src->blockio.logical_block_size);
        return false;
    }

    if (src->blockio.physical_block_size != dst->blockio.physical_block_size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk physical_block_size %1$u does not match source %2$u"),
                       dst->blockio.physical_block_size, src->blockio.physical_block_size);
        return false;
    }

    if (src->blockio.discard_granularity != dst->blockio.discard_granularity) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk discard_granularity %1$u does not match source %2$u"),
                       dst->blockio.discard_granularity, src->blockio.discard_granularity);
        return false;
    }
    return true;
}



static bool
virDomainDiskDefCheckABIStability(virDomainDiskDef *src,
                                  virDomainDiskDef *dst)
{
    if (src->device != dst->device) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk device %1$s does not match source %2$s"),
                       virDomainDiskDeviceTypeToString(dst->device),
                       virDomainDiskDeviceTypeToString(src->device));
        return false;
    }

    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk bus %1$s does not match source %2$s"),
                       virDomainDiskBusTypeToString(dst->bus),
                       virDomainDiskBusTypeToString(src->bus));
        return false;
    }

    if (STRNEQ(src->dst, dst->dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk %1$s does not match source %2$s"),
                       dst->dst, src->dst);
        return false;
    }

    if (STRNEQ_NULLABLE(src->serial, dst->serial)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk serial %1$s does not match source %2$s"),
                       NULLSTR(dst->serial), NULLSTR(src->serial));
        return false;
    }

    if (STRNEQ_NULLABLE(src->wwn, dst->wwn)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk wwn '%1$s' does not match source '%2$s'"),
                       NULLSTR(dst->wwn), NULLSTR(src->wwn));
        return false;

    }

    if (src->src->readonly != dst->src->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target disk access mode does not match source"));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk model %1$s does not match source %2$s"),
                       virDomainDiskModelTypeToString(dst->model),
                       virDomainDiskModelTypeToString(src->model));
        return false;
    }

    if (src->rotation_rate != dst->rotation_rate) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk rotation rate %1$u RPM does not match source %2$u RPM"),
                       dst->rotation_rate, src->rotation_rate);
        return false;
    }

    if (src->queues != dst->queues) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk queue count %1$u does not match source %2$u"),
                       dst->queues, src->queues);
        return false;
    }

    if (src->queue_size != dst->queue_size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target disk queue size %1$u does not match source %2$u"),
                       dst->queues, src->queues);
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    if (!virDomainDiskBlockIoCheckABIStability(src, dst))
        return false;

    return true;
}


static bool
virDomainControllerDefCheckABIStability(virDomainControllerDef *src,
                                        virDomainControllerDef *dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller type %1$s does not match source %2$s"),
                       virDomainControllerTypeToString(dst->type),
                       virDomainControllerTypeToString(src->type));
        return false;
    }

    if (src->idx != dst->idx) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller index %1$d does not match source %2$d"),
                       dst->idx, src->idx);
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target controller model %1$d does not match source %2$d"),
                       dst->model, src->model);
        return false;
    }

    if (src->type == VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL) {
        if (src->opts.vioserial.ports != dst->opts.vioserial.ports) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller ports %1$d does not match source %2$d"),
                           dst->opts.vioserial.ports, src->opts.vioserial.ports);
            return false;
        }

        if (src->opts.vioserial.vectors != dst->opts.vioserial.vectors) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller vectors %1$d does not match source %2$d"),
                           dst->opts.vioserial.vectors, src->opts.vioserial.vectors);
            return false;
        }
    } else if (src->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        if (src->opts.usbopts.ports != dst->opts.usbopts.ports) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target controller ports %1$d does not match source %2$d"),
                           dst->opts.usbopts.ports, src->opts.usbopts.ports);
            return false;
        }
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainFsDefCheckABIStability(virDomainFSDef *src,
                                virDomainFSDef *dst)
{
    if (STRNEQ_NULLABLE(src->dst, dst->dst)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target filesystem guest target %1$s does not match source %2$s"),
                       dst->dst, src->dst);
        return false;
    }

    if (src->readonly != dst->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target filesystem access mode does not match source"));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target filesystem model does not match source"));
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


bool
virDomainNetBackendIsEqual(virDomainNetBackend *src,
                           virDomainNetBackend *dst)
{
    if (src->type != dst->type ||
        STRNEQ_NULLABLE(src->tap, dst->tap) ||
        STRNEQ_NULLABLE(src->vhost, dst->vhost) ||
        STRNEQ_NULLABLE(src->logFile, dst->logFile)) {
        return false;
    }
    return true;
}


static bool
virDomainNetDefCheckABIStability(virDomainNetDef *src,
                                 virDomainNetDef *dst)
{
    char srcmac[VIR_MAC_STRING_BUFLEN];
    char dstmac[VIR_MAC_STRING_BUFLEN];

    if (virMacAddrCmp(&src->mac, &dst->mac) != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card mac %1$s does not match source %2$s"),
                       virMacAddrFormat(&dst->mac, dstmac),
                       virMacAddrFormat(&src->mac, srcmac));
        return false;
    }

    if (STRNEQ_NULLABLE(src->modelstr, dst->modelstr)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card model %1$s does not match source %2$s"),
                       NULLSTR(dst->modelstr), NULLSTR(src->modelstr));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card model %1$s does not match source %2$s"),
                       virDomainNetModelTypeToString(dst->model),
                       virDomainNetModelTypeToString(src->model));
        return false;
    }

    if (src->mtu != dst->mtu) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target network card MTU %1$d does not match source %2$d"),
                       dst->mtu, src->mtu);
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainInputDefCheckABIStability(virDomainInputDef *src,
                                   virDomainInputDef *dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target input device type %1$s does not match source %2$s"),
                       virDomainInputTypeToString(dst->type),
                       virDomainInputTypeToString(src->type));
        return false;
    }

    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target input device bus %1$s does not match source %2$s"),
                       virDomainInputBusTypeToString(dst->bus),
                       virDomainInputBusTypeToString(src->bus));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target input model %1$s does not match source %2$s"),
                       virDomainInputBusTypeToString(dst->model),
                       virDomainInputBusTypeToString(src->model));
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainSoundDefCheckABIStability(virDomainSoundDef *src,
                                   virDomainSoundDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sound card model %1$s does not match source %2$s"),
                       virDomainSoundModelTypeToString(dst->model),
                       virDomainSoundModelTypeToString(src->model));
        return false;
    }

    if (src->multichannel != dst->multichannel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target sound card multichannel setting '%1$s' does not match source '%2$s'"),
                       virTristateBoolTypeToString(dst->multichannel),
                       virTristateBoolTypeToString(src->multichannel));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainVideoDefCheckABIStability(virDomainVideoDef *src,
                                   virDomainVideoDef *dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card model %1$s does not match source %2$s"),
                       virDomainVideoTypeToString(dst->type),
                       virDomainVideoTypeToString(src->type));
        return false;
    }

    if (src->ram != dst->ram) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card ram %1$u does not match source %2$u"),
                       dst->ram, src->ram);
        return false;
    }

    if (src->vram != dst->vram) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vram %1$u does not match source %2$u"),
                       dst->vram, src->vram);
        return false;
    }

    if (src->vram64 != dst->vram64) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vram64 %1$u does not match source %2$u"),
                       dst->vram64, src->vram64);
        return false;
    }

    if (src->vgamem != dst->vgamem) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card vgamem %1$u does not match source %2$u"),
                       dst->vgamem, src->vgamem);
        return false;
    }

    if (src->heads != dst->heads) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target video card heads %1$u does not match source %2$u"),
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
                           _("Target video card 2d accel %1$u does not match source %2$u"),
                           dst->accel->accel2d, src->accel->accel2d);
            return false;
        }

        if (src->accel->accel3d != dst->accel->accel3d) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target video card 3d accel %1$u does not match source %2$u"),
                           dst->accel->accel3d, src->accel->accel3d);
            return false;
        }
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainHostdevDefCheckABIStability(virDomainHostdevDef *src,
                                     virDomainHostdevDef *dst)
{
    if (src->mode != dst->mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target host device mode %1$s does not match source %2$s"),
                       virDomainHostdevModeTypeToString(dst->mode),
                       virDomainHostdevModeTypeToString(src->mode));
        return false;
    }

    if (src->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        src->source.subsys.type != dst->source.subsys.type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target host device subsystem %1$s does not match source %2$s"),
                       virDomainHostdevSubsysTypeToString(dst->source.subsys.type),
                       virDomainHostdevSubsysTypeToString(src->source.subsys.type));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(src->info, dst->info))
        return false;

    return true;
}


static bool
virDomainSmartcardDefCheckABIStability(virDomainSmartcardDef *src,
                                       virDomainSmartcardDef *dst)
{
    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainSerialDefCheckABIStability(virDomainChrDef *src,
                                    virDomainChrDef *dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target serial type %1$s does not match source %2$s"),
                       virDomainChrSerialTargetTypeToString(dst->targetType),
                       virDomainChrSerialTargetTypeToString(src->targetType));
        return false;
    }

    if (src->targetModel != dst->targetModel) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target serial model %1$s does not match source %2$s"),
                       virDomainChrSerialTargetModelTypeToString(dst->targetModel),
                       virDomainChrSerialTargetModelTypeToString(src->targetModel));
        return false;
    }

    if (src->target.port != dst->target.port) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target serial port %1$d does not match source %2$d"),
                       dst->target.port, src->target.port);
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainParallelDefCheckABIStability(virDomainChrDef *src,
                                      virDomainChrDef *dst)
{
    if (src->target.port != dst->target.port) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target parallel port %1$d does not match source %2$d"),
                       dst->target.port, src->target.port);
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainChannelDefCheckABIStability(virDomainChrDef *src,
                                     virDomainChrDef *dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target channel type %1$s does not match source %2$s"),
                       virDomainChrChannelTargetTypeToString(dst->targetType),
                       virDomainChrChannelTargetTypeToString(src->targetType));
        return false;
    }

    switch (src->targetType) {

    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN:
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
        if (STRNEQ_NULLABLE(src->target.name, dst->target.name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target channel name %1$s does not match source %2$s"),
                           NULLSTR(dst->target.name), NULLSTR(src->target.name));
            return false;
        }
        if (src->source->type != dst->source->type &&
            (src->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC ||
             dst->source->type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) &&
            !src->target.name) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Changing device type to/from spicevmc would change default target channel name"));
            return false;
        }
        break;
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
        if (memcmp(src->target.addr, dst->target.addr,
                   sizeof(*src->target.addr)) != 0) {
            g_autofree char *saddr = virSocketAddrFormatFull(src->target.addr, true, ":");
            g_autofree char *daddr = virSocketAddrFormatFull(dst->target.addr, true, ":");
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target channel addr %1$s does not match source %2$s"),
                           NULLSTR(daddr), NULLSTR(saddr));
            return false;
        }
        break;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainConsoleDefCheckABIStability(virDomainChrDef *src,
                                     virDomainChrDef *dst)
{
    if (src->targetType != dst->targetType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target console type %1$s does not match source %2$s"),
                       virDomainChrConsoleTargetTypeToString(dst->targetType),
                       virDomainChrConsoleTargetTypeToString(src->targetType));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainWatchdogDefCheckABIStability(virDomainWatchdogDef *src,
                                      virDomainWatchdogDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target watchdog model %1$s does not match source %2$s"),
                       virDomainWatchdogModelTypeToString(dst->model),
                       virDomainWatchdogModelTypeToString(src->model));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainMemballoonDefCheckABIStability(virDomainMemballoonDef *src,
                                        virDomainMemballoonDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target balloon model %1$s does not match source %2$s"),
                       virDomainMemballoonModelTypeToString(dst->model),
                       virDomainMemballoonModelTypeToString(src->model));
        return false;
    }

    if (src->autodeflate != dst->autodeflate) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target balloon autodeflate attribute value '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->autodeflate),
                       virTristateSwitchTypeToString(src->autodeflate));
        return false;
    }

    if (src->free_page_reporting != dst->free_page_reporting) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target balloon freePageReporting attribute value '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->free_page_reporting),
                       virTristateSwitchTypeToString(src->free_page_reporting));
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainRNGDefCheckABIStability(virDomainRNGDef *src,
                                 virDomainRNGDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target RNG model '%1$s' does not match source '%2$s'"),
                       virDomainRNGModelTypeToString(dst->model),
                       virDomainRNGModelTypeToString(src->model));
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainHubDefCheckABIStability(virDomainHubDef *src,
                                 virDomainHubDef *dst)
{
    if (src->type != dst->type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target hub device type %1$s does not match source %2$s"),
                       virDomainHubTypeToString(dst->type),
                       virDomainHubTypeToString(src->type));
        return false;
    }

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainRedirdevDefCheckABIStability(virDomainRedirdevDef *src,
                                      virDomainRedirdevDef *dst)
{
    if (src->bus != dst->bus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target redirected device bus %1$s does not match source %2$s"),
                       virDomainRedirdevBusTypeToString(dst->bus),
                       virDomainRedirdevBusTypeToString(src->bus));
        return false;
    }

    switch ((virDomainRedirdevBus) src->bus) {
    case VIR_DOMAIN_REDIRDEV_BUS_USB:
        if (src->source->type != dst->source->type) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target redirected device source type %1$s does not match source device source type %2$s"),
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
virDomainRedirFilterDefCheckABIStability(virDomainRedirFilterDef *src,
                                         virDomainRedirFilterDef *dst)
{
    size_t i;

    if (src->nusbdevs != dst->nusbdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target USB redirection filter rule count %1$zu does not match source %2$zu"),
                         dst->nusbdevs, src->nusbdevs);
        return false;
    }

    for (i = 0; i < src->nusbdevs; i++) {
        virDomainRedirFilterUSBDevDef *srcUSBDev = src->usbdevs[i];
        virDomainRedirFilterUSBDevDef *dstUSBDev = dst->usbdevs[i];
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
                           _("Target USB allow '%1$s' does not match source '%2$s'"),
                             dstUSBDev->allow ? "yes" : "no",
                             srcUSBDev->allow ? "yes" : "no");
            return false;
        }
    }

    return true;
}


static bool
virDomainDefFeaturesCheckABIStability(virDomainDef *src,
                                      virDomainDef *dst)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        const char *featureName = virDomainFeatureTypeToString(i);

        switch ((virDomainFeature) i) {
        case VIR_DOMAIN_FEATURE_ACPI:
        case VIR_DOMAIN_FEATURE_PAE:
        case VIR_DOMAIN_FEATURE_HAP:
        case VIR_DOMAIN_FEATURE_VIRIDIAN:
        case VIR_DOMAIN_FEATURE_PRIVNET:
        case VIR_DOMAIN_FEATURE_HYPERV:
        case VIR_DOMAIN_FEATURE_KVM:
        case VIR_DOMAIN_FEATURE_XEN:
        case VIR_DOMAIN_FEATURE_PVSPINLOCK:
        case VIR_DOMAIN_FEATURE_PMU:
        case VIR_DOMAIN_FEATURE_VMPORT:
        case VIR_DOMAIN_FEATURE_SMM:
        case VIR_DOMAIN_FEATURE_VMCOREINFO:
        case VIR_DOMAIN_FEATURE_HTM:
        case VIR_DOMAIN_FEATURE_NESTED_HV:
        case VIR_DOMAIN_FEATURE_CCF_ASSIST:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s', destination: '%3$s'"),
                               featureName,
                               virTristateSwitchTypeToString(src->features[i]),
                               virTristateSwitchTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_CAPABILITIES:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s=%3$s', destination: '%4$s=%5$s'"),
                               featureName,
                               "policy",
                               virDomainCapabilitiesPolicyTypeToString(src->features[i]),
                               "policy",
                               virDomainCapabilitiesPolicyTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_GIC:
            if (src->features[i] != dst->features[i] ||
                src->gic_version != dst->gic_version) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s,%3$s=%4$s', destination: '%5$s,%6$s=%7$s'"),
                               featureName,
                               virTristateSwitchTypeToString(src->features[i]),
                               "version", virGICVersionTypeToString(src->gic_version),
                               virTristateSwitchTypeToString(dst->features[i]),
                               "version", virGICVersionTypeToString(dst->gic_version));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_HPT:
            if (src->features[i] != dst->features[i] ||
                src->hpt_resizing != dst->hpt_resizing ||
                src->hpt_maxpagesize != dst->hpt_maxpagesize) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s,%3$s=%4$s,%5$s=%6$llu', destination: '%7$s,%8$s=%9$s,%10$s=%11$llu'"),
                               featureName,
                               virTristateSwitchTypeToString(src->features[i]),
                               "resizing", virDomainHPTResizingTypeToString(src->hpt_resizing),
                               "maxpagesize", src->hpt_maxpagesize,
                               virTristateSwitchTypeToString(dst->features[i]),
                               "resizing", virDomainHPTResizingTypeToString(dst->hpt_resizing),
                               "maxpagesize", dst->hpt_maxpagesize);
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_APIC:
            if (src->features[i] != dst->features[i] ||
                src->apic_eoi != dst->apic_eoi) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s,%3$s=%4$s', destination: '%5$s,%6$s=%7$s'"),
                               featureName,
                               virTristateSwitchTypeToString(src->features[i]),
                               "eoi", virTristateSwitchTypeToString(src->apic_eoi),
                               virTristateSwitchTypeToString(dst->features[i]),
                               "eoi", virTristateSwitchTypeToString(dst->apic_eoi));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_IOAPIC:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s=%3$s', destination: '%4$s=%5$s'"),
                               featureName,
                               "driver", virDomainIOAPICTypeToString(src->features[i]),
                               "driver", virDomainIOAPICTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_CFPC:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s=%3$s', destination: '%4$s=%5$s'"),
                               featureName,
                               "value", virDomainCFPCTypeToString(src->features[i]),
                               "value", virDomainCFPCTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_SBBC:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s=%3$s', destination: '%4$s=%5$s'"),
                               featureName,
                               "value", virDomainSBBCTypeToString(src->features[i]),
                               "value", virDomainSBBCTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_IBS:
            if (src->features[i] != dst->features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of feature '%1$s' differs: source: '%2$s=%3$s', destination: '%4$s=%5$s'"),
                               featureName,
                               "value", virDomainIBSTypeToString(src->features[i]),
                               "value", virDomainIBSTypeToString(dst->features[i]));
                return false;
            }
            break;

        case VIR_DOMAIN_FEATURE_MSRS:
        case VIR_DOMAIN_FEATURE_TCG:
        case VIR_DOMAIN_FEATURE_ASYNC_TEARDOWN:
        case VIR_DOMAIN_FEATURE_LAST:
            break;
        }
    }

    /* hyperv */
    if (src->features[VIR_DOMAIN_FEATURE_HYPERV] != VIR_DOMAIN_HYPERV_MODE_NONE) {
        for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
            switch ((virDomainHyperv) i) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
            case VIR_DOMAIN_HYPERV_VPINDEX:
            case VIR_DOMAIN_HYPERV_RUNTIME:
            case VIR_DOMAIN_HYPERV_SYNIC:
            case VIR_DOMAIN_HYPERV_STIMER:
            case VIR_DOMAIN_HYPERV_RESET:
            case VIR_DOMAIN_HYPERV_FREQUENCIES:
            case VIR_DOMAIN_HYPERV_REENLIGHTENMENT:
            case VIR_DOMAIN_HYPERV_TLBFLUSH:
            case VIR_DOMAIN_HYPERV_IPI:
            case VIR_DOMAIN_HYPERV_EVMCS:
            case VIR_DOMAIN_HYPERV_AVIC:
                if (src->hyperv_features[i] != dst->hyperv_features[i]) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("State of HyperV enlightenment feature '%1$s' differs: source: '%2$s', destination: '%3$s'"),
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
                                   _("HyperV spinlock retry count differs: source: '%1$u', destination: '%2$u'"),
                                   src->hyperv_spinlocks,
                                   dst->hyperv_spinlocks);
                    return false;
                }
                break;

            case VIR_DOMAIN_HYPERV_VENDOR_ID:
                if (STRNEQ_NULLABLE(src->hyperv_vendor_id, dst->hyperv_vendor_id)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("HyperV vendor_id differs: source: '%1$s', destination: '%2$s'"),
                                   src->hyperv_vendor_id,
                                   dst->hyperv_vendor_id);
                    return false;
                }
                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
    }

    if (src->hyperv_features[VIR_DOMAIN_HYPERV_STIMER] == VIR_TRISTATE_SWITCH_ON) {
        if (src->hyperv_stimer_direct != dst->hyperv_stimer_direct) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("State of HyperV stimer direct feature differs: source: '%1$s', destination: '%2$s'"),
                           virTristateSwitchTypeToString(src->hyperv_stimer_direct),
                           virTristateSwitchTypeToString(dst->hyperv_stimer_direct));
            return false;
        }
    }

    /* xen */
    if (src->features[VIR_DOMAIN_FEATURE_XEN] == VIR_TRISTATE_SWITCH_ON) {
        for (i = 0; i < VIR_DOMAIN_XEN_LAST; i++) {
            if (src->xen_features[i] != dst->xen_features[i]) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("State of Xen feature '%1$s' differs: source: '%2$s', destination: '%3$s'"),
                               virDomainXenTypeToString(i),
                               virTristateSwitchTypeToString(src->xen_features[i]),
                               virTristateSwitchTypeToString(dst->xen_features[i]));
                return false;
            }
            switch ((virDomainXen) i) {
            case VIR_DOMAIN_XEN_E820_HOST:
                break;

            case VIR_DOMAIN_XEN_PASSTHROUGH:
                if (src->xen_passthrough_mode != dst->xen_passthrough_mode) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("'mode' of Xen passthrough feature differs: source: '%1$s', destination: '%2$s'"),
                                   virDomainXenPassthroughModeTypeToString(src->xen_passthrough_mode),
                                   virDomainXenPassthroughModeTypeToString(dst->xen_passthrough_mode));
                    return false;
                }
                break;

            case VIR_DOMAIN_XEN_LAST:
                break;
            }
        }
    }

    /* kvm */
    if (src->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON) {
        for (i = 0; i < VIR_DOMAIN_KVM_LAST; i++) {
            switch ((virDomainKVM) i) {
            case VIR_DOMAIN_KVM_HIDDEN:
            case VIR_DOMAIN_KVM_DEDICATED:
            case VIR_DOMAIN_KVM_POLLCONTROL:
            case VIR_DOMAIN_KVM_PVIPI:
            case VIR_DOMAIN_KVM_DIRTY_RING:
                if (src->kvm_features->features[i] != dst->kvm_features->features[i]) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("State of KVM feature '%1$s' differs: source: '%2$s', destination: '%3$s'"),
                                   virDomainKVMTypeToString(i),
                                   virTristateSwitchTypeToString(src->kvm_features->features[i]),
                                   virTristateSwitchTypeToString(dst->kvm_features->features[i]));
                    return false;
                }

                break;

            case VIR_DOMAIN_KVM_LAST:
                break;
            }
        }

        if (src->kvm_features->dirty_ring_size != dst->kvm_features->dirty_ring_size) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("dirty ring size of KVM feature '%1$s' differs: source: '%2$d', destination: '%3$d'"),
                           virDomainKVMTypeToString(i),
                           src->kvm_features->dirty_ring_size,
                           dst->kvm_features->dirty_ring_size);
            return false;
        }
    }

    /* smm */
    if (src->features[VIR_DOMAIN_FEATURE_SMM] == VIR_TRISTATE_SWITCH_ON) {
        if (src->tseg_specified != dst->tseg_specified) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("SMM TSEG differs: source: %1$s, destination: '%2$s'"),
                           src->tseg_specified ? _("specified") : _("not specified"),
                           dst->tseg_specified ? _("specified") : _("not specified"));
            return false;
        }

        if (src->tseg_specified &&
            src->tseg_size != dst->tseg_size) {
            const char *unit_src, *unit_dst;
            unsigned long long short_size_src = virFormatIntPretty(src->tseg_size,
                                                                   &unit_src);
            unsigned long long short_size_dst = virFormatIntPretty(dst->tseg_size,
                                                                   &unit_dst);

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Size of SMM TSEG size differs: source: '%1$llu %2$s', destination: '%3$llu %4$s'"),
                           short_size_src, unit_src,
                           short_size_dst, unit_dst);
            return false;
        }
    }

    return true;
}

static bool
virDomainPanicDefCheckABIStability(virDomainPanicDef *src,
                                   virDomainPanicDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target panic model '%1$s' does not match source '%2$s'"),
                       virDomainPanicModelTypeToString(dst->model),
                       virDomainPanicModelTypeToString(src->model));
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainShmemDefCheckABIStability(virDomainShmemDef *src,
                                   virDomainShmemDef *dst)
{
    if (src->role != dst->role) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory role '%1$s' does not match source role '%2$s'"),
                       virDomainShmemRoleTypeToString(dst->role),
                       virDomainShmemRoleTypeToString(src->role));
        return false;
    }

    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory model '%1$s' does not match source model '%2$s'"),
                       virDomainShmemModelTypeToString(dst->model),
                       virDomainShmemModelTypeToString(src->model));
        return false;
    }

    if (src->size != dst->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target shared memory size '%1$llu' does not match source size '%2$llu'"),
                       dst->size, src->size);
        return false;
    }

    if (src->server.enabled != dst->server.enabled) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target shared memory server usage doesn't match source"));
        return false;
    }

    if (src->msi.vectors != dst->msi.vectors ||
        src->msi.enabled != dst->msi.enabled ||
        src->msi.ioeventfd != dst->msi.ioeventfd) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target shared memory MSI configuration doesn't match source"));
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainTPMDefCheckABIStability(virDomainTPMDef *src,
                                 virDomainTPMDef *dst)
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

    switch (src->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        if (src->data.emulator.version != dst->data.emulator.version) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Target TPM version doesn't match source"));
            return false;
        }

        if (!virBitmapEqual(src->data.emulator.activePcrBanks,
                            dst->data.emulator.activePcrBanks)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Target active PCR banks doesn't match source"));
            return false;
        }
        break;

    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
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
                       _("Target domain max memory %1$lld does not match source %2$lld"),
                       virDomainDefGetMemoryInitial(dst),
                       virDomainDefGetMemoryInitial(src));
        return false;
    }

    if (!(flags & VIR_DOMAIN_DEF_ABI_CHECK_SKIP_VOLATILE) &&
        src->mem.cur_balloon != dst->mem.cur_balloon) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain current memory %1$lld does not match source %2$lld"),
                       dst->mem.cur_balloon,
                       src->mem.cur_balloon);
        return false;
    }

    if (src->mem.max_memory != dst->mem.max_memory) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target maximum memory size '%1$llu' doesn't match source '%2$llu'"),
                       dst->mem.max_memory,
                       src->mem.max_memory);
        return false;
    }

    if (src->mem.memory_slots != dst->mem.memory_slots) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory slots count '%1$u' doesn't match source '%2$u'"),
                       dst->mem.memory_slots,
                       src->mem.memory_slots);
        return false;
    }

    return true;
}


static bool
virDomainMemoryDefCheckABIStability(virDomainMemoryDef *src,
                                    virDomainMemoryDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device model '%1$s' doesn't match source model '%2$s'"),
                       virDomainMemoryModelTypeToString(dst->model),
                       virDomainMemoryModelTypeToString(src->model));
        return false;
    }

    if (src->targetNode != dst->targetNode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device targetNode '%1$d' doesn't match source targetNode '%2$d'"),
                       dst->targetNode, src->targetNode);
        return false;
    }

    if (src->size != dst->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target memory device size '%1$llu' doesn't match source memory device size '%2$llu'"),
                       dst->size, src->size);
        return false;
    }

    switch (src->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (src->target.nvdimm.labelsize != dst->target.nvdimm.labelsize) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target NVDIMM label size '%1$llu' doesn't match source NVDIMM label size '%2$llu'"),
                           src->target.nvdimm.labelsize,
                           dst->target.nvdimm.labelsize);
            return false;
        }

        if (src->source.nvdimm.alignsize != dst->source.nvdimm.alignsize) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target NVDIMM alignment '%1$llu' doesn't match source NVDIMM alignment '%2$llu'"),
                           src->source.nvdimm.alignsize,
                           dst->source.nvdimm.alignsize);
            return false;
        }

        if (src->source.nvdimm.pmem != dst->source.nvdimm.pmem) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Target NVDIMM pmem flag doesn't match source NVDIMM pmem flag"));
            return false;
        }

        if (src->target.nvdimm.readonly != dst->target.nvdimm.readonly) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Target NVDIMM readonly flag doesn't match source NVDIMM readonly flag"));
            return false;
        }

        if ((src->target.nvdimm.uuid || dst->target.nvdimm.uuid) &&
            !(src->target.nvdimm.uuid && dst->target.nvdimm.uuid &&
              memcmp(src->target.nvdimm.uuid, dst->target.nvdimm.uuid, VIR_UUID_BUFLEN) == 0)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Target NVDIMM UUID doesn't match source NVDIMM"));
            return false;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (src->target.virtio_pmem.address != dst->target.virtio_pmem.address) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target memory device address '0x%1$llx' doesn't match source memory device address '0x%2$llx'"),
                           dst->target.virtio_pmem.address,
                           src->target.virtio_pmem.address);
            return false;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        if (src->target.virtio_mem.blocksize != dst->target.virtio_mem.blocksize) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target memory device block size '%1$llu' doesn't match source memory device block size '%2$llu'"),
                           dst->target.virtio_mem.blocksize,
                           src->target.virtio_mem.blocksize);
            return false;
        }

        if (src->target.virtio_mem.requestedsize != dst->target.virtio_mem.requestedsize) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target memory device requested size '%1$llu' doesn't match source memory device requested size '%2$llu'"),
                           dst->target.virtio_mem.requestedsize,
                           src->target.virtio_mem.requestedsize);
            return false;
        }

        if (src->target.virtio_mem.address != dst->target.virtio_mem.address) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Target memory device address '0x%1$llx' doesn't match source memory device address '0x%2$llx'"),
                           dst->target.virtio_mem.address,
                           src->target.virtio_mem.address);
            return false;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainIOMMUDefCheckABIStability(virDomainIOMMUDef *src,
                                   virDomainIOMMUDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device model '%1$s' does not match source '%2$s'"),
                       virDomainIOMMUModelTypeToString(dst->model),
                       virDomainIOMMUModelTypeToString(src->model));
        return false;
    }
    if (src->intremap != dst->intremap) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device intremap value '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->intremap),
                       virTristateSwitchTypeToString(src->intremap));
        return false;
    }
    if (src->caching_mode != dst->caching_mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device caching mode '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->caching_mode),
                       virTristateSwitchTypeToString(src->caching_mode));
        return false;
    }
    if (src->eim != dst->eim) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device eim value '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->eim),
                       virTristateSwitchTypeToString(src->eim));
        return false;
    }
    if (src->iotlb != dst->iotlb) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device iotlb value '%1$s' does not match source '%2$s'"),
                       virTristateSwitchTypeToString(dst->iotlb),
                       virTristateSwitchTypeToString(src->iotlb));
        return false;
    }
    if (src->aw_bits != dst->aw_bits) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain IOMMU device aw_bits value '%1$d' does not match source '%2$d'"),
                       dst->aw_bits, src->aw_bits);
        return false;
    }

    return virDomainDeviceInfoCheckABIStability(&src->info, &dst->info);
}


static bool
virDomainVsockDefCheckABIStability(virDomainVsockDef *src,
                                   virDomainVsockDef *dst)
{
    if (src->model != dst->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain vsock device model '%1$s' does not match source '%2$s'"),
                       virDomainVsockModelTypeToString(dst->model),
                       virDomainVsockModelTypeToString(src->model));
        return false;
    }

    if (!virDomainVirtioOptionsCheckABIStability(src->virtio, dst->virtio))
        return false;

    if (!virDomainDeviceInfoCheckABIStability(&src->info, &dst->info))
        return false;

    return true;
}


static bool
virDomainDefVcpuCheckAbiStability(virDomainDef *src,
                                  virDomainDef *dst)
{
    size_t i;

    if (src->maxvcpus != dst->maxvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain vCPU max %1$zu does not match source %2$zu"),
                       dst->maxvcpus, src->maxvcpus);
        return false;
    }

    for (i = 0; i < src->maxvcpus; i++) {
        virDomainVcpuDef *svcpu = src->vcpus[i];
        virDomainVcpuDef *dvcpu = dst->vcpus[i];

        if (svcpu->online != dvcpu->online) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("State of vCPU '%1$zu' differs between source and destination definitions"),
                           i);
            return false;
        }

        if (svcpu->order != dvcpu->order) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("vcpu enable order of vCPU '%1$zu' differs between source and destination definitions"),
                           i);
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
virDomainDefCheckABIStabilityFlags(virDomainDef *src,
                                   virDomainDef *dst,
                                   virDomainXMLOption *xmlopt,
                                   unsigned int flags)
{
    size_t i;
    virErrorPtr err;
    g_autofree char *strSrc = NULL;
    g_autofree char *strDst = NULL;

    if (src->virtType != dst->virtType) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain virt type %1$s does not match source %2$s"),
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
                       _("Target domain uuid %1$s does not match source %2$s"),
                       uuiddst, uuidsrc);
        goto error;
    }

    if (src->genidRequested != dst->genidRequested) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain requested genid does not match source"));
        goto error;
    }

    if (src->genidRequested &&
        memcmp(src->genid, dst->genid, VIR_UUID_BUFLEN) != 0) {
        char guidsrc[VIR_UUID_STRING_BUFLEN];
        char guiddst[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(src->genid, guidsrc);
        virUUIDFormat(dst->genid, guiddst);
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain genid %1$s does not match source %2$s"),
                       guiddst, guidsrc);
        goto error;
    }

    /* Not strictly ABI related, but we want to make sure domains
     * don't get silently re-named through the backdoor when passing
     * custom XML into various APIs, since this would create havoc
     */
    if (STRNEQ_NULLABLE(src->name, dst->name)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain name '%1$s' does not match source '%2$s'"),
                       dst->name, src->name);
        goto error;
    }

    if (!virDomainMemtuneCheckABIStability(src, dst, flags))
        goto error;

    if (!virDomainNumaCheckABIStability(src->numa, dst->numa))
        goto error;

    if (!virDomainDefVcpuCheckAbiStability(src, dst))
        goto error;

    if (src->os.type != dst->os.type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain OS type %1$s does not match source %2$s"),
                       virDomainOSTypeToString(dst->os.type),
                       virDomainOSTypeToString(src->os.type));
        goto error;
    }
    if (src->os.arch != dst->os.arch) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain architecture %1$s does not match source %2$s"),
                       virArchToString(dst->os.arch),
                       virArchToString(src->os.arch));
        goto error;
    }
    if (STRNEQ_NULLABLE(src->os.machine, dst->os.machine)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("Target domain machine type %1$s does not match source %2$s"),
                    dst->os.machine, src->os.machine);
        goto error;
    }

    if (src->os.smbios_mode != dst->os.smbios_mode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain SMBIOS mode %1$s does not match source %2$s"),
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

    if (src->nsysinfo != dst->nsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain count of sysinfo does not match source"));
            goto error;
    }

    for (i = 0; i < src->nsysinfo; i++) {
        if (!virSysinfoIsEqual(src->sysinfo[i], dst->sysinfo[i]))
            goto error;
    }

    if (src->ndisks != dst->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain disk count %1$zu does not match source %2$zu"),
                       dst->ndisks, src->ndisks);
        goto error;
    }

    for (i = 0; i < src->ndisks; i++)
        if (!virDomainDiskDefCheckABIStability(src->disks[i], dst->disks[i]))
            goto error;

    if (src->ncontrollers != dst->ncontrollers) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain controller count %1$zu does not match source %2$zu"),
                       dst->ncontrollers, src->ncontrollers);
        goto error;
    }

    for (i = 0; i < src->ncontrollers; i++)
        if (!virDomainControllerDefCheckABIStability(src->controllers[i],
                                                     dst->controllers[i]))
            goto error;

    if (src->nfss != dst->nfss) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain filesystem count %1$zu does not match source %2$zu"),
                       dst->nfss, src->nfss);
        goto error;
    }

    for (i = 0; i < src->nfss; i++)
        if (!virDomainFsDefCheckABIStability(src->fss[i], dst->fss[i]))
            goto error;

    if (src->nnets != dst->nnets) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain net card count %1$zu does not match source %2$zu"),
                       dst->nnets, src->nnets);
        goto error;
    }

    for (i = 0; i < src->nnets; i++)
        if (!virDomainNetDefCheckABIStability(src->nets[i], dst->nets[i]))
            goto error;

    if (src->ninputs != dst->ninputs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain input device count %1$zu does not match source %2$zu"),
                       dst->ninputs, src->ninputs);
        goto error;
    }

    for (i = 0; i < src->ninputs; i++)
        if (!virDomainInputDefCheckABIStability(src->inputs[i], dst->inputs[i]))
            goto error;

    if (src->nsounds != dst->nsounds) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain sound card count %1$zu does not match source %2$zu"),
                       dst->nsounds, src->nsounds);
        goto error;
    }

    for (i = 0; i < src->nsounds; i++)
        if (!virDomainSoundDefCheckABIStability(src->sounds[i], dst->sounds[i]))
            goto error;

    if (src->nvideos != dst->nvideos) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain video card count %1$zu does not match source %2$zu"),
                       dst->nvideos, src->nvideos);
        goto error;
    }

    for (i = 0; i < src->nvideos; i++)
        if (!virDomainVideoDefCheckABIStability(src->videos[i], dst->videos[i]))
            goto error;

    if (src->nhostdevs != dst->nhostdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain host device count %1$zu does not match source %2$zu"),
                       dst->nhostdevs, src->nhostdevs);
        goto error;
    }

    for (i = 0; i < src->nhostdevs; i++)
        if (!virDomainHostdevDefCheckABIStability(src->hostdevs[i],
                                                  dst->hostdevs[i]))
            goto error;

    if (src->nsmartcards != dst->nsmartcards) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain smartcard count %1$zu does not match source %2$zu"),
                       dst->nsmartcards, src->nsmartcards);
        goto error;
    }

    for (i = 0; i < src->nsmartcards; i++)
        if (!virDomainSmartcardDefCheckABIStability(src->smartcards[i],
                                                    dst->smartcards[i]))
            goto error;

    if (src->nserials != dst->nserials) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain serial port count %1$zu does not match source %2$zu"),
                       dst->nserials, src->nserials);
        goto error;
    }

    for (i = 0; i < src->nserials; i++)
        if (!virDomainSerialDefCheckABIStability(src->serials[i],
                                                 dst->serials[i]))
            goto error;

    if (src->nparallels != dst->nparallels) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain parallel port count %1$zu does not match source %2$zu"),
                       dst->nparallels, src->nparallels);
        goto error;
    }

    for (i = 0; i < src->nparallels; i++)
        if (!virDomainParallelDefCheckABIStability(src->parallels[i],
                                                   dst->parallels[i]))
            goto error;

    if (src->nchannels != dst->nchannels) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain channel count %1$zu does not match source %2$zu"),
                       dst->nchannels, src->nchannels);
        goto error;
    }

    for (i = 0; i < src->nchannels; i++)
        if (!virDomainChannelDefCheckABIStability(src->channels[i],
                                                  dst->channels[i]))
            goto error;

    if (src->nconsoles != dst->nconsoles) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain console count %1$zu does not match source %2$zu"),
                       dst->nconsoles, src->nconsoles);
        goto error;
    }

    for (i = 0; i < src->nconsoles; i++)
        if (!virDomainConsoleDefCheckABIStability(src->consoles[i],
                                                  dst->consoles[i]))
            goto error;

    if (src->nhubs != dst->nhubs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain hub device count %1$zu does not match source %2$zu"),
                       dst->nhubs, src->nhubs);
        goto error;
    }

    for (i = 0; i < src->nhubs; i++)
        if (!virDomainHubDefCheckABIStability(src->hubs[i], dst->hubs[i]))
            goto error;

    if (src->nredirdevs != dst->nredirdevs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain redirected devices count %1$zu does not match source %2$zu"),
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
                       _("Target domain USB redirection filter count %1$d does not match source %2$d"),
                       dst->redirfilter ? 1 : 0, src->redirfilter ? 1 : 0);
        goto error;
    }

    if (src->redirfilter &&
        !virDomainRedirFilterDefCheckABIStability(src->redirfilter,
                                                  dst->redirfilter))
        goto error;


    if (src->nwatchdogs != dst->nwatchdogs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain watchdog device count %1$zu does not match source %2$zu"),
                       dst->nwatchdogs, src->nwatchdogs);
        goto error;
    }

    for (i = 0; i < src->nwatchdogs; i++) {
        if (!virDomainWatchdogDefCheckABIStability(src->watchdogs[i], dst->watchdogs[i]))
            goto error;
    }

    if ((!src->memballoon && dst->memballoon) ||
        (src->memballoon && !dst->memballoon)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory balloon count %1$d does not match source %2$d"),
                       dst->memballoon ? 1 : 0, src->memballoon ? 1 : 0);
        goto error;
    }

    if (src->memballoon &&
        !virDomainMemballoonDefCheckABIStability(src->memballoon,
                                                 dst->memballoon))
        goto error;

    if (src->nrngs != dst->nrngs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain RNG device count %1$zu does not match source %2$zu"),
                       dst->nrngs, src->nrngs);
        goto error;
    }

    for (i = 0; i < src->nrngs; i++)
        if (!virDomainRNGDefCheckABIStability(src->rngs[i], dst->rngs[i]))
            goto error;

    if (src->npanics != dst->npanics) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain panic device count %1$zu does not match source %2$zu"),
                       dst->npanics, src->npanics);
        goto error;
    }

    for (i = 0; i < src->npanics; i++) {
        if (!virDomainPanicDefCheckABIStability(src->panics[i], dst->panics[i]))
            goto error;
    }

    if (src->nshmems != dst->nshmems) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain shared memory device count %1$zu does not match source %2$zu"),
                       dst->nshmems, src->nshmems);
        goto error;
    }

    for (i = 0; i < src->nshmems; i++) {
        if (!virDomainShmemDefCheckABIStability(src->shmems[i], dst->shmems[i]))
            goto error;
    }

    if (src->ntpms != dst->ntpms) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain TPM device count %1$zu does not match source %2$zu"),
                       dst->ntpms, src->ntpms);
        goto error;
    }

    for (i = 0; i < src->ntpms; i++) {
        if (!virDomainTPMDefCheckABIStability(src->tpms[i], dst->tpms[i]))
            goto error;
    }

    if (src->nmems != dst->nmems) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target domain memory device count %1$zu does not match source %2$zu"),
                       dst->nmems, src->nmems);
        goto error;
    }

    for (i = 0; i < src->nmems; i++) {
        if (!virDomainMemoryDefCheckABIStability(src->mems[i], dst->mems[i]))
            goto error;
    }

    if (!!src->iommu != !!dst->iommu) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain IOMMU device count does not match source"));
        goto error;
    }

    if (src->iommu &&
        !virDomainIOMMUDefCheckABIStability(src->iommu, dst->iommu))
        goto error;

    if (!!src->vsock != !!dst->vsock) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Target domain vsock device count does not match source"));
        goto error;
    }

    if (src->vsock &&
        !virDomainVsockDefCheckABIStability(src->vsock, dst->vsock))
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
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        break;
    }
#endif

    return true;

 error:
    virErrorPreserveLast(&err);

    strSrc = virDomainDefFormat(src, xmlopt, 0);
    strDst = virDomainDefFormat(dst, xmlopt, 0);
    VIR_DEBUG("XMLs that failed stability check were: src=\"%s\", dst=\"%s\"",
              NULLSTR(strSrc), NULLSTR(strDst));

    virErrorRestore(&err);
    return false;
}


bool
virDomainDefCheckABIStability(virDomainDef *src,
                              virDomainDef *dst,
                              virDomainXMLOption *xmlopt)
{
    return virDomainDefCheckABIStabilityFlags(src, dst, xmlopt, 0);
}


static int
virDomainDefAddDiskControllersForType(virDomainDef *def,
                                      virDomainControllerType controllerType,
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
virDomainDefMaybeAddVirtioSerialController(virDomainDef *def)
{
    /* Look for any virtio serial or virtio console devs */
    size_t i;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDef *channel = def->channels[i];

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
        virDomainChrDef *console = def->consoles[i];

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
virDomainDefMaybeAddSmartcardController(virDomainDef *def)
{
    /* Look for any smartcard devs */
    size_t i;

    for (i = 0; i < def->nsmartcards; i++) {
        virDomainSmartcardDef *smartcard = def->smartcards[i];
        int idx = 0;

        if (smartcard->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID) {
            idx = smartcard->info.addr.ccid.controller;
        } else if (smartcard->info.type
                   == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            size_t j;
            int max = -1;

            for (j = 0; j < def->nsmartcards; j++) {
                virDomainDeviceInfo *info = &def->smartcards[j]->info;
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
virDomainDefAddImplicitControllers(virDomainDef *def)
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
virDomainDefAddImplicitVideo(virDomainDef *def, virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainVideoDef) video = NULL;

    /* For backwards compatibility, if no <video> tag is set but there
     * is a <graphics> tag, then we add a single video tag */
    if (def->ngraphics == 0 || def->nvideos > 0)
        return 0;

    if (!(video = virDomainVideoDefNew(xmlopt)))
        return -1;
    VIR_APPEND_ELEMENT(def->videos, def->nvideos, video);

    return 0;
}

int
virDomainDefAddImplicitDevices(virDomainDef *def, virDomainXMLOption *xmlopt)
{
    if ((xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_NO_STUB_CONSOLE) == 0) {
        if (virDomainDefAddConsoleCompat(def) < 0)
            return -1;
    }
    if (virDomainDefAddImplicitControllers(def) < 0)
        return -1;

    if (virDomainDefAddImplicitVideo(def, xmlopt) < 0)
        return -1;

    return 0;
}

virDomainIOThreadIDDef *
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

virDomainIOThreadIDDef *
virDomainIOThreadIDAdd(virDomainDef *def,
                       unsigned int iothread_id)
{
    virDomainIOThreadIDDef *iothrid = NULL;

    iothrid = virDomainIOThreadIDDefNew();
    iothrid->iothread_id = iothread_id;

    VIR_APPEND_ELEMENT_COPY(def->iothreadids, def->niothreadids, iothrid);

    return iothrid;
}


void
virDomainIOThreadIDDel(virDomainDef *def,
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
virDomainEventActionDefFormat(virBuffer *buf,
                              int type,
                              const char *name,
                              virEventActionToStringFunc convFunc)
{
    const char *typeStr = convFunc(type);
    if (!typeStr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected %1$s action: %2$d"), name, type);
        return -1;
    }

    virBufferAsprintf(buf, "<%s>%s</%s>\n", name, typeStr, name);

    return 0;
}


static void
virSecurityLabelDefFormat(virBuffer *buf,
                          virSecurityLabelDef *def,
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
virSecurityDeviceLabelDefFormat(virBuffer *buf,
                                virSecurityDeviceLabelDef *def,
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


static void
virDomainLeaseDefFormat(virBuffer *buf,
                        virDomainLeaseDef *def)
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
}

static void
virDomainDiskGeometryDefFormat(virBuffer *buf,
                               virDomainDiskDef *def)
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
virDomainDiskBlockIoDefFormat(virBuffer *buf,
                              virDomainDiskDef *def)
{
    if (def->blockio.logical_block_size > 0 ||
        def->blockio.physical_block_size > 0 ||
        def->blockio.discard_granularity > 0) {
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
        if (def->blockio.discard_granularity > 0) {
            virBufferAsprintf(buf,
                              " discard_granularity='%u'",
                              def->blockio.discard_granularity);
        }
        virBufferAddLit(buf, "/>\n");
    }
}


static void
virDomainSourceDefFormatSeclabel(virBuffer *buf,
                                 size_t nseclabels,
                                 virSecurityDeviceLabelDef **seclabels,
                                 unsigned int flags)
{
    size_t n;

    for (n = 0; n < nseclabels; n++)
        virSecurityDeviceLabelDefFormat(buf, seclabels[n], flags);
}


static void
virDomainDiskSourceFormatNetworkCookies(virBuffer *buf,
                                        virStorageSource *src,
                                        unsigned int flags)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_SECURE))
        return;

    for (i = 0; i < src->ncookies; i++) {
        virBufferEscapeString(&childBuf, "<cookie name='%s'>", src->cookies[i]->name);
        virBufferEscapeString(&childBuf, "%s</cookie>\n", src->cookies[i]->value);
    }

    virXMLFormatElement(buf, "cookies", NULL, &childBuf);
}


static void
virDomainDiskSourceFormatNetwork(virBuffer *attrBuf,
                                 virBuffer *childBuf,
                                 virStorageSource *src,
                                 unsigned int flags)
{
    size_t n;
    g_autofree char *path = NULL;

    virBufferAsprintf(attrBuf, " protocol='%s'",
                      virStorageNetProtocolTypeToString(src->protocol));

    if (src->volume)
        path = g_strdup_printf("%s/%s", src->volume, src->path);

    virBufferEscapeString(attrBuf, " name='%s'", path ? path : src->path);
    virBufferEscapeString(attrBuf, " query='%s'", src->query);

    if (src->haveTLS != VIR_TRISTATE_BOOL_ABSENT &&
        !(flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE &&
          src->tlsFromConfig))
        virBufferAsprintf(attrBuf, " tls='%s'",
                          virTristateBoolTypeToString(src->haveTLS));
    virBufferEscapeString(attrBuf, " tlsHostname='%s'", src->tlsHostname);
    if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS)
        virBufferAsprintf(attrBuf, " tlsFromConfig='%d'", src->tlsFromConfig);

    for (n = 0; n < src->nhosts; n++) {
        virBufferAddLit(childBuf, "<host");
        virBufferEscapeString(childBuf, " name='%s'", src->hosts[n].name);

        if (src->hosts[n].port)
            virBufferAsprintf(childBuf, " port='%u'", src->hosts[n].port);

        if (src->hosts[n].transport)
            virBufferAsprintf(childBuf, " transport='%s'",
                              virStorageNetHostTransportTypeToString(src->hosts[n].transport));

        virBufferEscapeString(childBuf, " socket='%s'", src->hosts[n].socket);
        virBufferAddLit(childBuf, "/>\n");
    }

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_NFS &&
        (src->nfs_user || src->nfs_group)) {
        virBufferAddLit(childBuf, "<identity");

        virBufferEscapeString(childBuf, " user='%s'", src->nfs_user);
        virBufferEscapeString(childBuf, " group='%s'", src->nfs_group);

        virBufferAddLit(childBuf, "/>\n");
    }

    if (src->reconnectDelay) {
        virBufferAsprintf(childBuf, "<reconnect delay='%u'/>\n", src->reconnectDelay);
    }

    virBufferEscapeString(childBuf, "<snapshot name='%s'/>\n", src->snapshot);
    virBufferEscapeString(childBuf, "<config file='%s'/>\n", src->configFile);

    virStorageSourceInitiatorFormatXML(&src->initiator, childBuf);

    if (src->sslverify != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(childBuf, "<ssl verify='%s'/>\n",
                          virTristateBoolTypeToString(src->sslverify));
    }

    virDomainDiskSourceFormatNetworkCookies(childBuf, src, flags);

    if (src->readahead)
        virBufferAsprintf(childBuf, "<readahead size='%llu'/>\n", src->readahead);

    if (src->timeout)
        virBufferAsprintf(childBuf, "<timeout seconds='%llu'/>\n", src->timeout);

    if (src->protocol == VIR_STORAGE_NET_PROTOCOL_SSH) {
        if (src->ssh_known_hosts_file)
            virBufferEscapeString(childBuf, "<knownHosts path='%s'/>\n", src->ssh_known_hosts_file);
        if (src->ssh_keyfile || src->ssh_agent) {
            virBufferAddLit(childBuf, "<identity");

            virBufferEscapeString(childBuf, " username='%s'", src->ssh_user);
            virBufferEscapeString(childBuf, " keyfile='%s'", src->ssh_keyfile);
            virBufferEscapeString(childBuf, " agentsock='%s'", src->ssh_agent);

            virBufferAddLit(childBuf, "/>\n");
        }
    }
}


static void
virDomainDiskSourceNVMeFormat(virBuffer *attrBuf,
                              virBuffer *childBuf,
                              const virStorageSourceNVMeDef *nvme)
{
    virBufferAddLit(attrBuf, " type='pci'");
    if (nvme->managed != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(attrBuf, " managed='%s'",
                          virTristateBoolTypeToString(nvme->managed));
    virBufferAsprintf(attrBuf, " namespace='%llu'", nvme->namespc);
    virPCIDeviceAddressFormat(childBuf, nvme->pciAddr, false);
}


static void
virDomainChrSourceReconnectDefFormat(virBuffer *buf,
                                     virDomainChrSourceReconnectDef *def);


static void
virDomainDiskSourceVhostuserFormat(virBuffer *attrBuf,
                                   virBuffer *childBuf,
                                   virDomainChrSourceDef *vhostuser)
{
    virBufferAddLit(attrBuf, " type='unix'");
    virBufferAsprintf(attrBuf, " path='%s'", vhostuser->data.nix.path);

    virDomainChrSourceReconnectDefFormat(childBuf, &vhostuser->data.nix.reconnect);
}


static int
virDomainDiskSourceFormatPrivateData(virBuffer *buf,
                                     virStorageSource *src,
                                     unsigned int flags,
                                     virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_STATUS) ||
        !xmlopt || !xmlopt->privateData.storageFormat)
        return 0;

    if (xmlopt->privateData.storageFormat(src, &childBuf) < 0)
        return -1;

    virXMLFormatElement(buf, "privateData", NULL, &childBuf);
    return 0;
}


static void
virDomainDiskSourceFormatSlice(virBuffer *buf,
                               const char *slicetype,
                               virStorageSourceSlice *slice)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;

    if (!slice)
        return;

    virBufferAsprintf(&attrBuf, " type='%s'", slicetype);
    virBufferAsprintf(&attrBuf, " offset='%llu'", slice->offset);
    virBufferAsprintf(&attrBuf, " size='%llu'", slice->size);

    virXMLFormatElement(buf, "slice", &attrBuf, NULL);
}


static void
virDomainDiskSourceFormatSlices(virBuffer *buf,
                                virStorageSource *src)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virDomainDiskSourceFormatSlice(&childBuf, "storage", src->sliceStorage);

    virXMLFormatElement(buf, "slices", NULL, &childBuf);
}


/**
 * virDomainDiskSourceFormat:
 * @buf: output buffer
 * @src: storage source definition to format
 * @element: name to use for the top-level element (often "source")
 * @policy: startup policy attribute value, if necessary
 * @attrIndex: the 'index' attribute of <source> is formatted if true
 * @flags: XML formatter flags
 * @skipAuth: Skip formatting of <auth>
 * @skipEnc: Skip formatting of <encryption>
 *                 regardless of the original definition state
 * @xmlopt: XML formatter callbacks
 *
 * Formats @src into a <source> element. Note that this doesn't format the
 * 'type' and 'format' properties of @src.
 */
int
virDomainDiskSourceFormat(virBuffer *buf,
                          virStorageSource *src,
                          const char *element,
                          int policy,
                          bool attrIndex,
                          unsigned int flags,
                          bool skipAuth,
                          bool skipEnc,
                          virDomainXMLOption *xmlopt)
{
    virStorageType actualType = src->type;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (src->type == VIR_STORAGE_TYPE_VOLUME) {
        if (src->srcpool) {
            virBufferEscapeString(&attrBuf, " pool='%s'", src->srcpool->pool);
            virBufferEscapeString(&attrBuf, " volume='%s'", src->srcpool->volume);
            if (src->srcpool->mode)
                virBufferAsprintf(&attrBuf, " mode='%s'",
                                  virStorageSourcePoolModeTypeToString(src->srcpool->mode));
        }

        if (flags & VIR_DOMAIN_DEF_FORMAT_VOLUME_TRANSLATED &&
            src->srcpool->actualtype != VIR_STORAGE_TYPE_NONE) {
            virBufferAsprintf(&attrBuf, " actualType='%s'",
                              virStorageTypeToString(src->srcpool->actualtype));
            actualType = virStorageSourceGetActualType(src);
        }
    }

    switch (actualType) {
    case VIR_STORAGE_TYPE_FILE:
        virBufferEscapeString(&attrBuf, " file='%s'", src->path);
        virBufferEscapeString(&attrBuf, " fdgroup='%s'", src->fdgroup);
        break;

    case VIR_STORAGE_TYPE_BLOCK:
        virBufferEscapeString(&attrBuf, " dev='%s'", src->path);
        break;

    case VIR_STORAGE_TYPE_DIR:
        virBufferEscapeString(&attrBuf, " dir='%s'", src->path);
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        virDomainDiskSourceFormatNetwork(&attrBuf, &childBuf, src, flags);
        break;

    case VIR_STORAGE_TYPE_VOLUME:
        /* formatted above */
        break;

    case VIR_STORAGE_TYPE_NVME:
        virDomainDiskSourceNVMeFormat(&attrBuf, &childBuf, src->nvme);
        break;

    case VIR_STORAGE_TYPE_VHOST_USER:
        virDomainDiskSourceVhostuserFormat(&attrBuf, &childBuf, src->vhostuser);
        break;

    case VIR_STORAGE_TYPE_VHOST_VDPA:
        virBufferEscapeString(&attrBuf, " dev='%s'", src->vdpadev);
        break;

    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk type %1$d"), actualType);
        return -1;
    }

    virDomainDiskSourceFormatSlices(&childBuf, src);

    if (actualType != VIR_STORAGE_TYPE_NETWORK)
        virDomainSourceDefFormatSeclabel(&childBuf, src->nseclabels,
                                         src->seclabels, flags);

    /* Storage Source formatting will not carry through the blunder
     * that disk source formatting had at one time to format the
     * <auth> for a volume source type. The <auth> information is
     * kept in the storage pool and would be overwritten anyway.
     * So avoid formatting it for volumes. */
    if (src->auth && !skipAuth && src->type != VIR_STORAGE_TYPE_VOLUME)
        virStorageAuthDefFormat(&childBuf, src->auth);

    if (src->encryption && !skipEnc &&
        virStorageEncryptionFormat(&childBuf, src->encryption) < 0)
        return -1;

    if (src->pr)
        virStoragePRDefFormat(&childBuf, src->pr,
                              flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE);
    if (policy && actualType != VIR_STORAGE_TYPE_NETWORK)
        virBufferEscapeString(&attrBuf, " startupPolicy='%s'",
                              virDomainStartupPolicyTypeToString(policy));

    if (attrIndex && src->id != 0)
        virBufferAsprintf(&attrBuf, " index='%u'", src->id);

    if (virDomainDiskSourceFormatPrivateData(&childBuf, src, flags, xmlopt) < 0)
        return -1;

    virXMLFormatElement(buf, element, &attrBuf, &childBuf);

    return 0;
}


int
virDomainDiskBackingStoreFormat(virBuffer *buf,
                                virStorageSource *src,
                                virDomainXMLOption *xmlopt,
                                unsigned int flags)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) formatAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) formatChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);
    bool inactive = flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE;
    virStorageSource *backingStore = src->backingStore;

    if (!backingStore)
        return 0;

    /* don't write detected backing chain members to inactive xml */
    if (inactive && backingStore->detected)
        return 0;

    if (backingStore->type == VIR_STORAGE_TYPE_NONE) {
        virBufferAddLit(buf, "<backingStore/>\n");
        return 0;
    }

    if (backingStore->format <= 0 || backingStore->format >= VIR_STORAGE_FILE_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk backing store format %1$d"),
                       backingStore->format);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " type='%s'",
                      virStorageTypeToString(backingStore->type));
    if (backingStore->id != 0)
        virBufferAsprintf(&attrBuf, " index='%u'", backingStore->id);

    virBufferAsprintf(&formatAttrBuf, " type='%s'",
                      virStorageFileFormatTypeToString(backingStore->format));

    if (backingStore->metadataCacheMaxSize > 0) {
        g_auto(virBuffer) metadataCacheChildBuf = VIR_BUFFER_INIT_CHILD(&formatChildBuf);

        virBufferAsprintf(&metadataCacheChildBuf,
                          "<max_size unit='bytes'>%llu</max_size>\n",
                          backingStore->metadataCacheMaxSize);

        virXMLFormatElement(&formatChildBuf, "metadata_cache", NULL, &metadataCacheChildBuf);
    }

    virXMLFormatElement(&childBuf, "format", &formatAttrBuf, &formatChildBuf);


    if (virDomainDiskSourceFormat(&childBuf, backingStore, "source", 0, false,
                                  flags, false, false, xmlopt) < 0)
        return -1;

    if (virDomainDiskBackingStoreFormat(&childBuf, backingStore, xmlopt, flags) < 0)
        return -1;

    virXMLFormatElement(buf, "backingStore", &attrBuf, &childBuf);

    return 0;
}


#define FORMAT_IOTUNE(val) \
        if (disk->blkdeviotune.val) { \
            virBufferAsprintf(&childBuf, "<" #val ">%llu</" #val ">\n", \
                              disk->blkdeviotune.val); \
        }

static void
virDomainDiskDefFormatIotune(virBuffer *buf,
                             virDomainDiskDef *disk)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

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

    if (disk->blkdeviotune.size_iops_sec) {
        virBufferAsprintf(&childBuf, "<size_iops_sec>%llu</size_iops_sec>\n",
                          disk->blkdeviotune.size_iops_sec);
    }

    if (disk->blkdeviotune.group_name) {
        virBufferEscapeString(&childBuf, "<group_name>%s</group_name>\n",
                              disk->blkdeviotune.group_name);
    }

    FORMAT_IOTUNE(total_bytes_sec_max_length);
    FORMAT_IOTUNE(read_bytes_sec_max_length);
    FORMAT_IOTUNE(write_bytes_sec_max_length);
    FORMAT_IOTUNE(total_iops_sec_max_length);
    FORMAT_IOTUNE(read_iops_sec_max_length);
    FORMAT_IOTUNE(write_iops_sec_max_length);

    virXMLFormatElement(buf, "iotune", NULL, &childBuf);
}

#undef FORMAT_IOTUNE


static void
virDomainDiskDefFormatDriver(virBuffer *buf,
                             virDomainDiskDef *disk)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virBufferEscapeString(&attrBuf, " name='%s'", virDomainDiskGetDriver(disk));

    if (disk->src->format > 0)
        virBufferAsprintf(&attrBuf, " type='%s'",
                          virStorageFileFormatTypeToString(disk->src->format));

    if (disk->cachemode)
        virBufferAsprintf(&attrBuf, " cache='%s'",
                          virDomainDiskCacheTypeToString(disk->cachemode));

    if (disk->error_policy)
        virBufferAsprintf(&attrBuf, " error_policy='%s'",
                          virDomainDiskErrorPolicyTypeToString(disk->error_policy));

    if (disk->rerror_policy)
        virBufferAsprintf(&attrBuf, " rerror_policy='%s'",
                          virDomainDiskErrorPolicyTypeToString(disk->rerror_policy));

    if (disk->iomode)
        virBufferAsprintf(&attrBuf, " io='%s'",
                          virDomainDiskIoTypeToString(disk->iomode));

    if (disk->ioeventfd)
        virBufferAsprintf(&attrBuf, " ioeventfd='%s'",
                          virTristateSwitchTypeToString(disk->ioeventfd));

    if (disk->event_idx)
        virBufferAsprintf(&attrBuf, " event_idx='%s'",
                          virTristateSwitchTypeToString(disk->event_idx));

    if (disk->copy_on_read)
        virBufferAsprintf(&attrBuf, " copy_on_read='%s'",
                          virTristateSwitchTypeToString(disk->copy_on_read));

    if (disk->discard)
        virBufferAsprintf(&attrBuf, " discard='%s'",
                          virDomainDiskDiscardTypeToString(disk->discard));

    if (disk->iothread)
        virBufferAsprintf(&attrBuf, " iothread='%u'", disk->iothread);

    if (disk->detect_zeroes)
        virBufferAsprintf(&attrBuf, " detect_zeroes='%s'",
                          virDomainDiskDetectZeroesTypeToString(disk->detect_zeroes));

    if (disk->discard_no_unref)
        virBufferAsprintf(&attrBuf, " discard_no_unref='%s'",
                          virTristateSwitchTypeToString(disk->discard_no_unref));

    if (disk->queues)
        virBufferAsprintf(&attrBuf, " queues='%u'", disk->queues);

    if (disk->queue_size)
        virBufferAsprintf(&attrBuf, " queue_size='%u'", disk->queue_size);

    virDomainVirtioOptionsFormat(&attrBuf, disk->virtio);

    if (disk->src->metadataCacheMaxSize > 0) {
        g_auto(virBuffer) metadataCacheChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);

        virBufferAsprintf(&metadataCacheChildBuf,
                          "<max_size unit='bytes'>%llu</max_size>\n",
                          disk->src->metadataCacheMaxSize);

        virXMLFormatElement(&childBuf, "metadata_cache", NULL, &metadataCacheChildBuf);
    }

    virXMLFormatElement(buf, "driver", &attrBuf, &childBuf);
}


static int
virDomainDiskDefFormatMirror(virBuffer *buf,
                             virDomainDiskDef *disk,
                             unsigned int flags,
                             virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) formatAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) formatChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);
    const char *formatStr = NULL;

    /* For now, mirroring is currently output-only: we only output it
     * for live domains, therefore we ignore it on input except for
     * the internal parse on libvirtd restart.  We prefer to output
     * the new style similar to backingStore, but for back-compat on
     * blockcopy files we also have to output old style attributes.
     * The parser accepts either style across libvirtd upgrades. */

    if (!disk->mirror ||
        (flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
        return 0;

    if (disk->mirror->format)
        formatStr = virStorageFileFormatTypeToString(disk->mirror->format);
    virBufferAsprintf(&attrBuf, " type='%s'",
                      virStorageTypeToString(disk->mirror->type));
    if (disk->mirror->type == VIR_STORAGE_TYPE_FILE &&
        disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_COPY) {
        virBufferEscapeString(&attrBuf, " file='%s'", disk->mirror->path);
        virBufferEscapeString(&attrBuf, " format='%s'", formatStr);
    }
    virBufferEscapeString(&attrBuf, " job='%s'",
                          virDomainBlockJobTypeToString(disk->mirrorJob));
    if (disk->mirrorState)
        virBufferEscapeString(&attrBuf, " ready='%s'",
                              virDomainDiskMirrorStateTypeToString(disk->mirrorState));

    virBufferEscapeString(&formatAttrBuf, " type='%s'", formatStr);
    if (disk->mirror->metadataCacheMaxSize > 0) {
        g_auto(virBuffer) metadataCacheChildBuf = VIR_BUFFER_INIT_CHILD(&formatChildBuf);

        virBufferAsprintf(&metadataCacheChildBuf,
                          "<max_size unit='bytes'>%llu</max_size>\n",
                          disk->mirror->metadataCacheMaxSize);

        virXMLFormatElement(&formatChildBuf, "metadata_cache", NULL, &metadataCacheChildBuf);
    }

    virXMLFormatElement(&childBuf, "format", &formatAttrBuf, &formatChildBuf);

    if (virDomainDiskSourceFormat(&childBuf, disk->mirror, "source", 0, true,
                                  flags, false, false, xmlopt) < 0)
        return -1;

    if (virDomainDiskBackingStoreFormat(&childBuf, disk->mirror, xmlopt, flags) < 0)
        return -1;

    virXMLFormatElement(buf, "mirror", &attrBuf, &childBuf);

    return 0;
}


static int
virDomainDiskDefFormatPrivateData(virBuffer *buf,
                                  virDomainDiskDef *disk,
                                  unsigned int flags,
                                  virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_STATUS) ||
        !xmlopt ||
        !xmlopt->privateData.diskFormat)
        return 0;

    if (xmlopt->privateData.diskFormat(disk, &childBuf) < 0)
        return -1;

    virXMLFormatElement(buf, "privateData", NULL, &childBuf);
    return 0;
}


static int
virDomainDiskDefFormat(virBuffer *buf,
                       virDomainDiskDef *def,
                       unsigned int flags,
                       virDomainXMLOption *xmlopt)
{
    const char *type = virStorageTypeToString(def->src->type);
    const char *device = virDomainDiskDeviceTypeToString(def->device);
    const char *bus = virDomainDiskBusTypeToString(def->bus);
    const char *sgio = virDomainDeviceSGIOTypeToString(def->sgio);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!type || !def->src->type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk type %1$d"), def->src->type);
        return -1;
    }
    if (!device) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk device %1$d"), def->device);
        return -1;
    }
    if (!bus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk bus %1$d"), def->bus);
        return -1;
    }
    if (!sgio) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected disk sgio mode '%1$d'"), def->sgio);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " type='%s' device='%s'", type, device);

    if (def->model) {
        virBufferAsprintf(&attrBuf, " model='%s'",
                          virDomainDiskModelTypeToString(def->model));
    }

    if (def->rawio) {
        virBufferAsprintf(&attrBuf, " rawio='%s'",
                          virTristateBoolTypeToString(def->rawio));
    }

    if (def->sgio)
        virBufferAsprintf(&attrBuf, " sgio='%s'", sgio);

    if (def->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
        !(def->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NO &&
          def->src->readonly))
        virBufferAsprintf(&attrBuf, " snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(def->snapshot));

    virDomainDiskDefFormatDriver(&childBuf, def);

    /* Format as child of <disk> if defined there; otherwise,
     * if defined as child of <source>, then format later */
    if (def->src->auth && def->diskElementAuth)
        virStorageAuthDefFormat(&childBuf, def->src->auth);

    if (virDomainDiskSourceFormat(&childBuf, def->src, "source", def->startupPolicy,
                                  true, flags,
                                  def->diskElementAuth, def->diskElementEnc,
                                  xmlopt) < 0)
        return -1;

    /* Don't format backingStore to inactive XMLs until the code for
     * persistent storage of backing chains is ready. */
    if (virDomainDiskBackingStoreFormat(&childBuf, def->src, xmlopt, flags) < 0)
        return -1;

    virBufferEscapeString(&childBuf, "<backenddomain name='%s'/>\n", def->domain_name);

    virDomainDiskGeometryDefFormat(&childBuf, def);
    virDomainDiskBlockIoDefFormat(&childBuf, def);

    if (virDomainDiskDefFormatMirror(&childBuf, def, flags, xmlopt) < 0)
        return -1;

    virBufferAsprintf(&childBuf, "<target dev='%s' bus='%s'",
                      def->dst, bus);
    if ((def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY ||
         def->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
        def->tray_status != VIR_DOMAIN_DISK_TRAY_CLOSED)
        virBufferAsprintf(&childBuf, " tray='%s'",
                          virDomainDiskTrayTypeToString(def->tray_status));
    if (def->bus == VIR_DOMAIN_DISK_BUS_USB &&
        def->removable != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&childBuf, " removable='%s'",
                          virTristateSwitchTypeToString(def->removable));
    }
    if (def->rotation_rate)
        virBufferAsprintf(&childBuf, " rotation_rate='%u'", def->rotation_rate);
    virBufferAddLit(&childBuf, "/>\n");

    virDomainDiskDefFormatIotune(&childBuf, def);

    if (def->src->readonly)
        virBufferAddLit(&childBuf, "<readonly/>\n");
    if (def->src->shared)
        virBufferAddLit(&childBuf, "<shareable/>\n");
    if (def->transient) {
        virBufferAddLit(&childBuf, "<transient");
        if (def->transientShareBacking == VIR_TRISTATE_BOOL_YES)
            virBufferAddLit(&childBuf, " shareBacking='yes'");
        virBufferAddLit(&childBuf, "/>\n");
    }
    virBufferEscapeString(&childBuf, "<serial>%s</serial>\n", def->serial);
    virBufferEscapeString(&childBuf, "<wwn>%s</wwn>\n", def->wwn);
    virBufferEscapeString(&childBuf, "<vendor>%s</vendor>\n", def->vendor);
    virBufferEscapeString(&childBuf, "<product>%s</product>\n", def->product);

    /* If originally found as a child of <disk>, then format thusly;
     * otherwise, will be formatted as child of <source> */
    if (def->src->encryption && def->diskElementEnc &&
        virStorageEncryptionFormat(&childBuf, def->src->encryption) < 0)
        return -1;
    virDomainDeviceInfoFormat(&childBuf, &def->info, flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT);

    if (virDomainDiskDefFormatPrivateData(&childBuf, def, flags, xmlopt) < 0)
        return -1;

    /* format diskElementAuth and diskElementEnc into status XML to preserve
     * formatting */
    if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS) {
        g_auto(virBuffer) secretPlacementAttrBuf = VIR_BUFFER_INITIALIZER;

        if (def->diskElementAuth)
            virBufferAddLit(&secretPlacementAttrBuf, " auth='true'");
        if (def->diskElementEnc)
            virBufferAddLit(&secretPlacementAttrBuf, " enc='true'");

        virXMLFormatElement(&childBuf, "diskSecretsPlacement", &secretPlacementAttrBuf, NULL);
    }

    virXMLFormatElement(buf, "disk", &attrBuf, &childBuf);
    return 0;
}


static void
virDomainControllerDriverFormat(virBuffer *buf,
                                virDomainControllerDef *def)
{
    g_auto(virBuffer) driverBuf = VIR_BUFFER_INITIALIZER;

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

    virXMLFormatElement(buf, "driver", &driverBuf, NULL);
}


static int
virDomainControllerDefFormatPCI(virBuffer *buf,
                                virDomainControllerDef *def,
                                unsigned int flags)
{
    g_auto(virBuffer) targetAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) targetChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    bool formatModelName = true;

    if (def->opts.pciopts.modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
        formatModelName = false;

    /* Historically, libvirt didn't support specifying a model name for
     * pci-root controllers; starting from 3.6.0, however, pSeries guests
     * use pci-root controllers with model name spapr-pci-host-bridge to
     * represent all PHBs, including the default one.
     *
     * In order to allow migration of pSeries guests from older libvirt
     * versions and back, we don't format the model name in the migratable
     * XML if it's spapr-pci-host-bridge, thus making "no model name" and
     * "spapr-pci-host-bridge model name" basically equivalent.
     *
     * The spapr-pci-host-bridge device is specific to pSeries.
     */
    if (def->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
        def->opts.pciopts.modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE &&
        flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE) {
        formatModelName = false;
    }

    if (formatModelName) {
        const char *modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
        if (!modelName) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected model name value %1$d"),
                           def->opts.pciopts.modelName);
            return -1;
        }
        virBufferAsprintf(buf, "<model name='%s'/>\n", modelName);
    }

    if (def->opts.pciopts.chassisNr != -1)
        virBufferAsprintf(&targetAttrBuf, " chassisNr='%d'", def->opts.pciopts.chassisNr);
    if (def->opts.pciopts.chassis != -1)
        virBufferAsprintf(&targetAttrBuf, " chassis='%d'", def->opts.pciopts.chassis);
    if (def->opts.pciopts.port != -1)
        virBufferAsprintf(&targetAttrBuf, " port='0x%x'", def->opts.pciopts.port);
    if (def->opts.pciopts.busNr != -1)
        virBufferAsprintf(&targetAttrBuf, " busNr='%d'", def->opts.pciopts.busNr);
    if (def->opts.pciopts.targetIndex != -1)
        virBufferAsprintf(&targetAttrBuf, " index='%d'", def->opts.pciopts.targetIndex);
    if (def->opts.pciopts.hotplug != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&targetAttrBuf, " hotplug='%s'",
                          virTristateSwitchTypeToString(def->opts.pciopts.hotplug));
    }

    if (def->opts.pciopts.numaNode != -1)
        virBufferAsprintf(&targetChildBuf, "<node>%d</node>\n", def->opts.pciopts.numaNode);

    virXMLFormatElement(buf, "target", &targetAttrBuf, &targetChildBuf);
    return 0;
}


static int
virDomainControllerDefFormat(virBuffer *buf,
                             virDomainControllerDef *def,
                             unsigned int flags)
{
    const char *type = virDomainControllerTypeToString(def->type);
    const char *model = NULL;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected controller type %1$d"), def->type);
        return -1;
    }

    if (def->model != -1) {
        model = virDomainControllerModelTypeToString(def, def->model);

        if (!model) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected model type %1$d"), def->model);
            return -1;
        }
    }

    virBufferAsprintf(&attrBuf,
                      " type='%s' index='%d'",
                      type, def->idx);

    if (model)
        virBufferEscapeString(&attrBuf, " model='%s'", model);

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (def->opts.vioserial.ports != -1) {
            virBufferAsprintf(&attrBuf, " ports='%d'",
                              def->opts.vioserial.ports);
        }
        if (def->opts.vioserial.vectors != -1) {
            virBufferAsprintf(&attrBuf, " vectors='%d'",
                              def->opts.vioserial.vectors);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (def->opts.usbopts.ports != -1) {
            virBufferAsprintf(&attrBuf, " ports='%d'",
                              def->opts.usbopts.ports);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
        if (def->opts.xenbusopts.maxGrantFrames != -1) {
            virBufferAsprintf(&attrBuf, " maxGrantFrames='%d'",
                              def->opts.xenbusopts.maxGrantFrames);
        }
        if (def->opts.xenbusopts.maxEventChannels != -1) {
            virBufferAsprintf(&attrBuf, " maxEventChannels='%d'",
                              def->opts.xenbusopts.maxEventChannels);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        if (virDomainControllerDefFormatPCI(&childBuf, def, flags) < 0)
            return -1;

    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        break;
    }


    virDomainControllerDriverFormat(&childBuf, def);

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
        def->opts.pciopts.pcihole64) {
        virBufferAsprintf(&childBuf, "<pcihole64 unit='KiB'>%lu</"
                          "pcihole64>\n", def->opts.pciopts.pcihole64size);
    }

    virXMLFormatElement(buf, "controller", &attrBuf, &childBuf);

    return 0;
}


int
virDomainFSIndexByName(virDomainDef *def, const char *name)
{
    virDomainFSDef *fs;
    size_t i;

    for (i = 0; i < def->nfss; i++) {
        fs = def->fss[i];
        if (STREQ(fs->dst, name))
            return i;
    }
    return -1;
}


static int
virDomainFSDefFormat(virBuffer *buf,
                     virDomainFSDef *def,
                     unsigned int flags)
{
    const char *type = virDomainFSTypeToString(def->type);
    const char *accessmode = virDomainFSAccessModeTypeToString(def->accessmode);
    const char *fsdriver = virDomainFSDriverTypeToString(def->fsdriver);
    const char *wrpolicy = virDomainFSWrpolicyTypeToString(def->wrpolicy);
    const char *multidevs = virDomainFSMultidevsTypeToString(def->multidevs);
    const char *src = def->src->path;
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) driverBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) binaryAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) binaryBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected filesystem type %1$d"), def->type);
        return -1;
    }

   if (!accessmode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected accessmode %1$d"), def->accessmode);
        return -1;
    }

    if (!multidevs) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected multidevs %1$d"), def->multidevs);
        return -1;
    }

    virBufferAsprintf(buf, "<filesystem type='%s'", type);
    if (def->accessmode != VIR_DOMAIN_FS_ACCESSMODE_DEFAULT)
        virBufferAsprintf(buf, " accessmode='%s'", accessmode);
    if (def->model) {
        virBufferAsprintf(buf, " model='%s'",
                          virDomainFSModelTypeToString(def->model));
    }
    if (def->multidevs)
        virBufferAsprintf(buf, " multidevs='%s'", multidevs);

    if (def->fmode)
        virBufferAsprintf(buf, " fmode='%04o'", def->fmode);

    if (def->dmode)
        virBufferAsprintf(buf, " dmode='%04o'", def->dmode);

    virBufferAddLit(buf, ">\n");

    virBufferAdjustIndent(buf, 2);
    virBufferAdjustIndent(&driverBuf, 2);
    virBufferAdjustIndent(&binaryBuf, 2);
    if (def->fsdriver) {
        virBufferAsprintf(&driverAttrBuf, " type='%s'", fsdriver);

        if (def->format)
            virBufferAsprintf(&driverAttrBuf, " format='%s'",
                              virStorageFileFormatTypeToString(def->format));

        /* Don't generate anything if wrpolicy is set to default */
        if (def->wrpolicy)
            virBufferAsprintf(&driverAttrBuf, " wrpolicy='%s'", wrpolicy);

        if (def->queue_size)
            virBufferAsprintf(&driverAttrBuf, " queue='%llu'", def->queue_size);

    }

    if (def->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        g_auto(virBuffer) lockAttrBuf = VIR_BUFFER_INITIALIZER;
        virBufferEscapeString(&binaryAttrBuf, " path='%s'", def->binary);

        if (def->xattr != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&binaryAttrBuf, " xattr='%s'",
                              virTristateSwitchTypeToString(def->xattr));
        }

        if (def->cache != VIR_DOMAIN_FS_CACHE_MODE_DEFAULT) {
            virBufferAsprintf(&binaryBuf, "<cache mode='%s'/>\n",
                              virDomainFSCacheModeTypeToString(def->cache));
        }

        if (def->sandbox != VIR_DOMAIN_FS_SANDBOX_MODE_DEFAULT) {
            virBufferAsprintf(&binaryBuf, "<sandbox mode='%s'/>\n",
                              virDomainFSSandboxModeTypeToString(def->sandbox));
        }

        if (def->posix_lock != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&lockAttrBuf, " posix='%s'",
                              virTristateSwitchTypeToString(def->posix_lock));
        }

        if (def->flock != VIR_TRISTATE_SWITCH_ABSENT) {
            virBufferAsprintf(&lockAttrBuf, " flock='%s'",
                              virTristateSwitchTypeToString(def->flock));
        }

        virXMLFormatElement(&binaryBuf, "lock", &lockAttrBuf, NULL);

        if (def->thread_pool_size >= 0)
            virBufferAsprintf(&binaryBuf, "<thread_pool size='%d'/>\n", def->thread_pool_size);

    }

    virDomainVirtioOptionsFormat(&driverAttrBuf, def->virtio);

    virXMLFormatElement(buf, "driver", &driverAttrBuf, &driverBuf);
    virXMLFormatElement(buf, "binary", &binaryAttrBuf, &binaryBuf);

    switch (def->type) {
    case VIR_DOMAIN_FS_TYPE_MOUNT:
    case VIR_DOMAIN_FS_TYPE_BIND:
        if (!def->sock)
            virBufferEscapeString(buf, "<source dir='%s'/>\n", src);
        else
            virBufferEscapeString(buf, "<source socket='%s'/>\n", def->sock);
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

    case VIR_DOMAIN_FS_TYPE_LAST:
        break;
    }

    virBufferEscapeString(buf, "<target dir='%s'/>\n",
                          def->dst);

    if (def->readonly)
        virBufferAddLit(buf, "<readonly/>\n");

    virDomainDeviceInfoFormat(buf, &def->info, flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT);

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
virDomainNetIPInfoFormat(virBuffer *buf,
                         virNetDevIPInfo *def)
{
    size_t i;

    /* Output IP addresses */
    for (i = 0; i < def->nips; i++) {
        virSocketAddr *address = &def->ips[i]->address;
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


static void
virDomainHostdevDefFormatSubsysUSB(virBuffer *buf,
                                   virDomainHostdevDef *def,
                                   unsigned int flags,
                                   bool includeTypeInAddr)
{
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainHostdevSubsysUSB *usbsrc = &def->source.subsys.u.usb;

    if (def->startupPolicy)
        virBufferAsprintf(&sourceAttrBuf, " startupPolicy='%s'",
                          virDomainStartupPolicyTypeToString(def->startupPolicy));

    if (usbsrc->autoAddress && (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE))
        virBufferAddLit(&sourceAttrBuf, " autoAddress='yes'");

    if (def->missing && !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
        virBufferAddLit(&sourceAttrBuf, " missing='yes'");

    if (usbsrc->guestReset) {
        virBufferAsprintf(&sourceAttrBuf, " guestReset='%s'",
                          virDomainHostdevSubsysUSBGuestResetTypeToString(usbsrc->guestReset));
    }

    if (usbsrc->vendor) {
        virBufferAsprintf(&sourceChildBuf, "<vendor id='0x%.4x'/>\n", usbsrc->vendor);
        virBufferAsprintf(&sourceChildBuf, "<product id='0x%.4x'/>\n", usbsrc->product);
    }

    if (usbsrc->bus || usbsrc->device)
        virBufferAsprintf(&sourceChildBuf, "<address %sbus='%d' device='%d'/>\n",
                          includeTypeInAddr ? "type='usb' " : "",
                          usbsrc->bus, usbsrc->device);

    virXMLFormatElement(buf, "source", &sourceAttrBuf, &sourceChildBuf);
}


static int
virDomainHostdevDefFormatSubsysPCI(virBuffer *buf,
                                   virDomainHostdevDef *def,
                                   unsigned int flags,
                                   bool includeTypeInAddr)
{
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainHostdevSubsysPCI *pcisrc = &def->source.subsys.u.pci;

    if (def->writeFiltering != VIR_TRISTATE_BOOL_ABSENT)
            virBufferAsprintf(&sourceAttrBuf, " writeFiltering='%s'",
                              virTristateBoolTypeToString(def->writeFiltering));

    if (pcisrc->backend != VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT) {
        const char *backend = virDomainHostdevSubsysPCIBackendTypeToString(pcisrc->backend);

        if (!backend) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected pci hostdev driver name type %1$d"),
                           pcisrc->backend);
            return -1;
        }

        virBufferAsprintf(buf, "<driver name='%s'/>\n", backend);
    }

    virPCIDeviceAddressFormat(&sourceChildBuf, pcisrc->addr, includeTypeInAddr);

    if (pcisrc->origstates &&
        (flags & VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES)) {
        g_auto(virBuffer) origstatesChildBuf = VIR_BUFFER_INIT_CHILD(&sourceChildBuf);
        ssize_t n = -1;

        while ((n = virBitmapNextSetBit(pcisrc->origstates, n)) >= 0)
            virBufferAsprintf(&origstatesChildBuf, "<%s/>\n",
                              virDomainHostdevPCIOrigstateTypeToString(n));

        virXMLFormatElement(&sourceChildBuf, "origstates", NULL, &origstatesChildBuf);
    }

    virXMLFormatElement(buf, "source", &sourceAttrBuf, &sourceChildBuf);
    return 0;
}


static int
virDomainHostdevDefFormatSubsysSCSI(virBuffer *buf,
                                    virDomainHostdevDef *def,
                                    unsigned int flags,
                                    bool includeTypeInAddr,
                                    virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainHostdevSubsysSCSI *scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
    virDomainHostdevSubsysSCSIiSCSI *iscsisrc = &scsisrc->u.iscsi;

    if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
        virBufferAsprintf(&sourceAttrBuf, " protocol='%s' name='%s'",
                          virDomainHostdevSubsysSCSIProtocolTypeToString(scsisrc->protocol),
                          iscsisrc->src->path);

        virBufferAddLit(&sourceChildBuf, "<host");
        virBufferEscapeString(&sourceChildBuf, " name='%s'", iscsisrc->src->hosts[0].name);
        if (iscsisrc->src->hosts[0].port)
            virBufferAsprintf(&sourceChildBuf, " port='%u'", iscsisrc->src->hosts[0].port);
        virBufferAddLit(&sourceChildBuf, "/>\n");

        if (virDomainDiskSourceFormatPrivateData(&sourceChildBuf, iscsisrc->src,
                                                 flags, xmlopt) < 0)
            return -1;

        if (iscsisrc->src->auth)
            virStorageAuthDefFormat(&sourceChildBuf, iscsisrc->src->auth);

        virStorageSourceInitiatorFormatXML(&iscsisrc->src->initiator,
                                           &sourceChildBuf);
    } else {
        virBufferAsprintf(&sourceChildBuf, "<adapter name='%s'/>\n",
                          scsihostsrc->adapter);

        virBufferAddLit(&sourceChildBuf, "<address");
        if (includeTypeInAddr)
            virBufferAddLit(&sourceChildBuf, " type='scsi'");
        virBufferAsprintf(&sourceChildBuf, " bus='%u' target='%u' unit='%llu'",
                          scsihostsrc->bus, scsihostsrc->target, scsihostsrc->unit);
        virBufferAddLit(&sourceChildBuf, "/>\n");

        if (scsihostsrc->src &&
            virDomainDiskSourceFormatPrivateData(&sourceChildBuf, scsihostsrc->src,
                                                 flags, xmlopt) < 0)
            return -1;
    }

    virXMLFormatElement(buf, "source", &sourceAttrBuf, &sourceChildBuf);
    return 0;
}


static void
virDomainHostdevDefFormatSubsysSCSIHost(virBuffer *buf,
                                        virDomainHostdevDef *def)
{
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
    virDomainHostdevSubsysSCSIVHost *hostsrc = &def->source.subsys.u.scsi_host;

    virBufferAsprintf(&sourceAttrBuf, " protocol='%s' wwpn='%s'",
                      virDomainHostdevSubsysSCSIHostProtocolTypeToString(hostsrc->protocol),
                      hostsrc->wwpn);

    virXMLFormatElement(buf, "source", &sourceAttrBuf, NULL);
}


static void
virDomainHostdevDefFormatSubsysMdev(virBuffer *buf,
                                    virDomainHostdevDef *def)
{
    g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    virDomainHostdevSubsysMediatedDev *mdevsrc = &def->source.subsys.u.mdev;

    virBufferAsprintf(&sourceChildBuf, "<address uuid='%s'/>\n", mdevsrc->uuidstr);

    virXMLFormatElement(buf, "source", NULL, &sourceChildBuf);
}


static int
virDomainHostdevDefFormatSubsys(virBuffer *buf,
                                virDomainHostdevDef *def,
                                unsigned int flags,
                                bool includeTypeInAddr,
                                virDomainXMLOption *xmlopt)
{
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        virDomainHostdevDefFormatSubsysUSB(buf, def, flags, includeTypeInAddr);
        return 0;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        return virDomainHostdevDefFormatSubsysPCI(buf, def, flags, includeTypeInAddr);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        return virDomainHostdevDefFormatSubsysSCSI(buf, def, flags, includeTypeInAddr, xmlopt);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        virDomainHostdevDefFormatSubsysSCSIHost(buf, def);
        return 0;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        virDomainHostdevDefFormatSubsysMdev(buf, def);
        return 0;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainHostdevSubsysType, def->source.subsys.type);
        return -1;
    }

    return 0;
}

static int
virDomainHostdevDefFormatCaps(virBuffer *buf,
                              virDomainHostdevDef *def)
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
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev type %1$d"),
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
virDomainActualNetDefContentsFormat(virBuffer *buf,
                                    virDomainNetDef *def,
                                    bool inSubelement,
                                    unsigned int flags,
                                    virDomainXMLOption *xmlopt)
{
    virDomainNetType actualType = virDomainNetGetActualType(def);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        if (virDomainHostdevDefFormatSubsys(buf, virDomainNetGetActualHostdev(def),
                                            flags, true, xmlopt) < 0) {
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
            if (virUUIDIsValid(def->data.network.portid)) {
                char uuidstr[VIR_UUID_STRING_BUFLEN];
                virUUIDFormat(def->data.network.portid, uuidstr);
                virBufferAsprintf(buf, " portid='%s'", uuidstr);
            }
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
                               _("unexpected source mode %1$d"),
                               virDomainNetGetActualDirectMode(def));
                return -1;
            }
            virBufferAsprintf(buf, " mode='%s'", mode);
        } else if (actualType == VIR_DOMAIN_NET_TYPE_USER) {
            virBufferEscapeString(buf, " dev='%s'", def->sourceDev);
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
    if (virNetDevBandwidthFormat(virDomainNetGetActualBandwidth(def), 0, buf) < 0)
        return -1;
    virNetworkPortOptionsFormat(virDomainNetGetActualPortOptionsIsolated(def), buf);
    return 0;
}

/* virDomainActualNetDefFormat() - format the ActualNetDef
 * info inside an <actual> element, as required for internal storage
 * of domain status
 */
static int
virDomainActualNetDefFormat(virBuffer *buf,
                            virDomainNetDef *def,
                            unsigned int flags,
                            virDomainXMLOption *xmlopt)
{
    virDomainNetType type;
    const char *typeStr;

    if (!def)
        return 0;
    type = virDomainNetGetActualType(def);
    typeStr = virDomainNetTypeToString(type);

    if (!typeStr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected net type %1$d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<actual type='%s'", typeStr);
    if (type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virDomainHostdevDef *hostdef = virDomainNetGetActualHostdev(def);
        if  (hostdef && hostdef->managed)
            virBufferAddLit(buf, " managed='yes'");
    }
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");

    virBufferAdjustIndent(buf, 2);
    if (virDomainActualNetDefContentsFormat(buf, def, true, flags, xmlopt) < 0)
       return -1;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</actual>\n");
    return 0;
}


static void
virDomainVirtioNetGuestOptsFormat(virBuffer *buf,
                                  virDomainNetDef *def)
{
    if (def->driver.virtio.guest.csum) {
        virBufferAsprintf(buf, " csum='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.csum));
    }
    if (def->driver.virtio.guest.tso4) {
        virBufferAsprintf(buf, " tso4='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.tso4));
    }
    if (def->driver.virtio.guest.tso6) {
        virBufferAsprintf(buf, " tso6='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.tso6));
    }
    if (def->driver.virtio.guest.ecn) {
        virBufferAsprintf(buf, " ecn='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.ecn));
    }
    if (def->driver.virtio.guest.ufo) {
        virBufferAsprintf(buf, " ufo='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.guest.ufo));
    }
}


static void
virDomainVirtioNetHostOptsFormat(virBuffer *buf,
                                 virDomainNetDef *def)
{
    if (def->driver.virtio.host.csum) {
        virBufferAsprintf(buf, " csum='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.csum));
    }
    if (def->driver.virtio.host.gso) {
        virBufferAsprintf(buf, " gso='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.gso));
    }
    if (def->driver.virtio.host.tso4) {
        virBufferAsprintf(buf, " tso4='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.tso4));
    }
    if (def->driver.virtio.host.tso6) {
        virBufferAsprintf(buf, " tso6='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.tso6));
    }
    if (def->driver.virtio.host.ecn) {
        virBufferAsprintf(buf, " ecn='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.ecn));
    }
    if (def->driver.virtio.host.ufo) {
        virBufferAsprintf(buf, " ufo='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.ufo));
    }
    if (def->driver.virtio.host.mrg_rxbuf) {
        virBufferAsprintf(buf, " mrg_rxbuf='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.host.mrg_rxbuf));
    }
}


static void
virDomainVirtioNetDriverFormat(virBuffer *buf,
                               virDomainNetDef *def)
{
    if (def->driver.virtio.name) {
        virBufferAsprintf(buf, " name='%s'",
                          virDomainNetDriverTypeToString(def->driver.virtio.name));
    }
    if (def->driver.virtio.txmode) {
        virBufferAsprintf(buf, " txmode='%s'",
                          virDomainNetVirtioTxModeTypeToString(def->driver.virtio.txmode));
    }
    if (def->driver.virtio.ioeventfd) {
        virBufferAsprintf(buf, " ioeventfd='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.ioeventfd));
    }
    if (def->driver.virtio.event_idx) {
        virBufferAsprintf(buf, " event_idx='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.event_idx));
    }
    if (def->driver.virtio.queues)
        virBufferAsprintf(buf, " queues='%u'", def->driver.virtio.queues);
    if (def->driver.virtio.rx_queue_size)
        virBufferAsprintf(buf, " rx_queue_size='%u'",
                          def->driver.virtio.rx_queue_size);
    if (def->driver.virtio.tx_queue_size)
        virBufferAsprintf(buf, " tx_queue_size='%u'",
                          def->driver.virtio.tx_queue_size);
    if (def->driver.virtio.rss != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " rss='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.rss));
    }
    if (def->driver.virtio.rss_hash_report != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(buf, " rss_hash_report='%s'",
                          virTristateSwitchTypeToString(def->driver.virtio.rss_hash_report));
    }

    virDomainVirtioOptionsFormat(buf, def->virtio);
}


static void
virDomainChrSourceReconnectDefFormat(virBuffer *buf,
                                     virDomainChrSourceReconnectDef *def)
{
    if (def->enabled == VIR_TRISTATE_BOOL_ABSENT)
        return;

    virBufferAsprintf(buf, "<reconnect enabled='%s'",
                      virTristateBoolTypeToString(def->enabled));

    if (def->enabled == VIR_TRISTATE_BOOL_YES)
        virBufferAsprintf(buf, " timeout='%u'", def->timeout);

    virBufferAddLit(buf, "/>\n");
}


static void
virDomainNetTeamingInfoFormat(virDomainNetTeamingInfo *teaming,
                              virBuffer *buf)
{
    if (teaming && teaming->type != VIR_DOMAIN_NET_TEAMING_TYPE_NONE) {
        virBufferAsprintf(buf, "<teaming type='%s'",
                          virDomainNetTeamingTypeToString(teaming->type));
        virBufferEscapeString(buf, " persistent='%s'", teaming->persistent);
        virBufferAddLit(buf, "/>\n");
    }
}


static void
virDomainNetBackendFormat(virBuffer *buf,
                          virDomainNetBackend *backend)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;

    if (backend->type) {
        virBufferAsprintf(&attrBuf, " type='%s'",
                          virDomainNetBackendTypeToString(backend->type));
    }
    virBufferEscapeString(&attrBuf, " tap='%s'", backend->tap);
    virBufferEscapeString(&attrBuf, " vhost='%s'", backend->vhost);
    virBufferEscapeString(&attrBuf, " logFile='%s'", backend->logFile);
    virXMLFormatElement(buf, "backend", &attrBuf, NULL);
}


static void
virDomainNetPortForwardRangesFormat(virBuffer *buf,
                                    virDomainNetPortForward *def)
{
    size_t i;

    for (i = 0; i < def->nRanges; i++) {
        virDomainNetPortForwardRange *range = def->ranges[i];
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;

        if (range->start) {
            virBufferAsprintf(&attrBuf, " start='%u'", range->start);
            if (range->end)
                virBufferAsprintf(&attrBuf, " end='%u'", range->end);
            if (range->to)
                virBufferAsprintf(&attrBuf, " to='%u'", range->to);
        }

        if (range->exclude) {
            virBufferAsprintf(&attrBuf, " exclude='%s'",
                              virTristateBoolTypeToString(range->exclude));
        }
        virXMLFormatElement(buf, "range", &attrBuf, NULL);
    }
}


static int
virDomainNetPortForwardsFormat(virBuffer *buf,
                               virDomainNetDef *def)
{
    size_t i;

    if (!def->nPortForwards)
        return 0;

    for (i = 0; i < def->nPortForwards; i++) {
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
        virDomainNetPortForward *pf = def->portForwards[i];

        virBufferAsprintf(&attrBuf, " proto='%s'",
                          virDomainNetProtoTypeToString(pf->proto));
        if (VIR_SOCKET_ADDR_VALID(&pf->address)) {
            g_autofree char *ipStr = virSocketAddrFormat(&pf->address);

            if (!ipStr)
                return -1;

            virBufferAsprintf(&attrBuf, " address='%s'", ipStr);
        }
        virBufferEscapeString(&attrBuf, " dev='%s'", pf->dev);

        virDomainNetPortForwardRangesFormat(&childBuf, pf);
        virXMLFormatElementEmpty(buf, "portForward", &attrBuf, &childBuf);
    }

    return 0;
}


static int
virDomainNetDefFormatPrivateData(virBuffer *buf,
                                 virDomainNetDef *net,
                                 unsigned int flags,
                                 virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_STATUS) ||
        !xmlopt ||
        !xmlopt->privateData.networkFormat)
        return 0;

    if (xmlopt->privateData.networkFormat(net, &childBuf) < 0)
        return -1;

    virXMLFormatElement(buf, "privateData", NULL, &childBuf);
    return 0;
}


int
virDomainNetDefFormat(virBuffer *buf,
                      virDomainNetDef *def,
                      virDomainXMLOption *xmlopt,
                      unsigned int flags)
{
    virDomainNetType actualType = virDomainNetGetActualType(def);
    bool publicActual = false;
    const char *typeStr;
    virDomainHostdevDef *hostdef = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];
    g_auto(virBuffer) targetAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) macAttrBuf = VIR_BUFFER_INITIALIZER;
    const char *prefix = xmlopt ? xmlopt->config.netPrefix : NULL;

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
                           _("unexpected actual net type %1$d"), actualType);
            return -1;
        }
        if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV)
            hostdef = virDomainNetGetActualHostdev(def);
    } else {
        if (!(typeStr = virDomainNetTypeToString(def->type))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected net type %1$d"), def->type);
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
    virBufferAsprintf(&macAttrBuf, " address='%s'",
                      virMacAddrFormat(&def->mac, macstr));
    if (def->mac_type)
        virBufferAsprintf(&macAttrBuf, " type='%s'", virDomainNetMacTypeTypeToString(def->mac_type));
    if (def->mac_check != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(&macAttrBuf, " check='%s'", virTristateBoolTypeToString(def->mac_check));
    virXMLFormatElement(buf, "mac", &macAttrBuf, NULL);

    if (publicActual) {
        /* when there is a virDomainActualNetDef, and we haven't been
         * asked to 1) report the domain's inactive XML, or 2) give
         * the internal version of the ActualNetDef separately in an
         * <actual> subelement, we can just put the ActualDef data in
         * the standard place...  (this is for public reporting of
         * interface status)
         */
        if (virDomainActualNetDefContentsFormat(buf, def, false, flags, xmlopt) < 0)
            return -1;
    } else {
        g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) sourceChildBuf = VIR_BUFFER_INIT_CHILD(buf);
        /* ...but if we've asked for the inactive XML (rather than
         * status), or to report the ActualDef as a separate <actual>
         * subelement (this is how we privately store interface
         * status), or there simply *isn't* any ActualNetDef, then
         * format the NetDef's data here, and optionally format the
         * ActualNetDef as an <actual> subelement of this element.
         */
        switch (def->type) {
        case VIR_DOMAIN_NET_TYPE_NETWORK:
            virBufferEscapeString(&sourceAttrBuf, " network='%s'",
                                  def->data.network.name);
            virBufferEscapeString(&sourceAttrBuf, " portgroup='%s'",
                                  def->data.network.portgroup);
            if (virUUIDIsValid(def->data.network.portid) &&
                !(flags & (VIR_DOMAIN_DEF_FORMAT_INACTIVE))) {
                char portidstr[VIR_UUID_STRING_BUFLEN];
                virUUIDFormat(def->data.network.portid, portidstr);
                virBufferEscapeString(&sourceAttrBuf, " portid='%s'", portidstr);
            }
            break;

        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            break;

        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
            if (def->data.vhostuser->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
                virBufferAddLit(&sourceAttrBuf, " type='unix'");
                virBufferEscapeString(&sourceAttrBuf, " path='%s'",
                                      def->data.vhostuser->data.nix.path);
                virBufferAsprintf(&sourceAttrBuf, " mode='%s'",
                                  def->data.vhostuser->data.nix.listen ?
                                  "server"  : "client");
                if (def->data.vhostuser->data.nix.reconnect.enabled) {
                    virDomainChrSourceReconnectDefFormat(&sourceChildBuf,
                                                         &def->data.vhostuser->data.nix.reconnect);
                }

            }
            break;

        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            virBufferEscapeString(&sourceAttrBuf, " bridge='%s'",
                                  def->data.bridge.brname);
            break;

        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
            virBufferEscapeString(&sourceAttrBuf, " address='%s'",
                                  def->data.socket.address);
            virBufferAsprintf(&sourceAttrBuf, " port='%d'",
                              def->data.socket.port);

            if (def->type != VIR_DOMAIN_NET_TYPE_UDP)
                break;

            virBufferAsprintf(&sourceChildBuf, "<local address='%s' port='%d'/>\n",
                              def->data.socket.localaddr,
                              def->data.socket.localport);
            break;

        case VIR_DOMAIN_NET_TYPE_INTERNAL:
            virBufferEscapeString(&sourceAttrBuf, " name='%s'",
                                  def->data.internal.name);
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            virBufferEscapeString(&sourceAttrBuf, " dev='%s'",
                                  def->data.direct.linkdev);
            virBufferAsprintf(&sourceAttrBuf, " mode='%s'",
                              virNetDevMacVLanModeTypeToString(def->data.direct.mode));
            break;

        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
            if (virDomainHostdevDefFormatSubsys(buf, &def->data.hostdev.def,
                                                flags, true, xmlopt) < 0) {
                return -1;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_VDPA:
            virBufferEscapeString(&sourceAttrBuf, " dev='%s'",
                                  def->data.vdpa.devicepath);
            break;

        case VIR_DOMAIN_NET_TYPE_VDS: {
            char switchidstr[VIR_UUID_STRING_BUFLEN];

            virUUIDFormat(def->data.vds.switch_id, switchidstr);
            virBufferEscapeString(&sourceAttrBuf, " switchid='%s'", switchidstr);
            virBufferAsprintf(&sourceAttrBuf, " portid='%lld'", def->data.vds.port_id);
            virBufferEscapeString(&sourceAttrBuf, " portgroupid='%s'", def->data.vds.portgroup_id);
            virBufferAsprintf(&sourceAttrBuf, " connectionid='%lld'", def->data.vds.connection_id);
            break;
        }

        case VIR_DOMAIN_NET_TYPE_USER:
            if (def->backend.type == VIR_DOMAIN_NET_BACKEND_PASST)
                virBufferEscapeString(&sourceAttrBuf, " dev='%s'", def->sourceDev);
            break;

        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }

        if (def->hostIP.nips || def->hostIP.nroutes) {
            if (virDomainNetIPInfoFormat(&sourceChildBuf, &def->hostIP) < 0)
                return -1;
        }

        virXMLFormatElement(buf, "source", &sourceAttrBuf, &sourceChildBuf);

        if (virNetDevVlanFormat(&def->vlan, buf) < 0)
            return -1;
        if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
            return -1;
        if (virNetDevBandwidthFormat(def->bandwidth, 0, buf) < 0)
            return -1;
        virNetworkPortOptionsFormat(def->isolatedPort, buf);

        /* ONLY for internal status storage - format the ActualNetDef
         * as a subelement of <interface> so that no persistent config
         * data is overwritten.
         */
        if (def->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
            (flags & VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET) &&
            (virDomainActualNetDefFormat(buf, def, flags, xmlopt) < 0))
            return -1;
    }

    if (virDomainNetIPInfoFormat(buf, &def->guestIP) < 0)
        return -1;

    if (virDomainNetPortForwardsFormat(buf, def) < 0)
        return -1;

    virBufferEscapeString(buf, "<script path='%s'/>\n",
                          def->script);
    virBufferEscapeString(buf, "<downscript path='%s'/>\n",
                          def->downscript);
    virBufferEscapeString(buf, "<backenddomain name='%s'/>\n", def->domain_name);

    if (def->ifname &&
        (def->managed_tap == VIR_TRISTATE_BOOL_NO ||
         !((flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE) &&
           (STRPREFIX(def->ifname, VIR_NET_GENERATED_VNET_PREFIX) ||
            STRPREFIX(def->ifname, VIR_NET_GENERATED_MACVTAP_PREFIX) ||
            STRPREFIX(def->ifname, VIR_NET_GENERATED_MACVLAN_PREFIX) ||
            (prefix && STRPREFIX(def->ifname, prefix)))))) {
        /* Skip auto-generated target names for inactive config. */
        virBufferEscapeString(&targetAttrBuf, " dev='%s'", def->ifname);
    }
    if (def->managed_tap != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&targetAttrBuf, " managed='%s'",
                          virTristateBoolTypeToString(def->managed_tap));
    }

    virXMLFormatElement(buf, "target", &targetAttrBuf, NULL);

    if (def->ifname_guest || def->ifname_guest_actual) {
        g_auto(virBuffer) guestAttrBuf = VIR_BUFFER_INITIALIZER;

        /* Skip auto-generated target names for inactive config. */
        virBufferEscapeString(&guestAttrBuf, " dev='%s'", def->ifname_guest);

        /* Only set if the host is running, so shouldn't pollute output */
        virBufferEscapeString(&guestAttrBuf, " actual='%s'", def->ifname_guest_actual);

        virXMLFormatElement(buf, "guest", &guestAttrBuf, NULL);
    }

    if (virDomainNetGetModelString(def)) {
        virBufferEscapeString(buf, "<model type='%s'/>\n",
                              virDomainNetGetModelString(def));
        if (virDomainNetIsVirtioModel(def)) {
            g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
            g_auto(virBuffer) driverChildBuf = VIR_BUFFER_INIT_CHILD(buf);
            g_auto(virBuffer) hostAttrBuf = VIR_BUFFER_INITIALIZER;
            g_auto(virBuffer) guestAttrBuf = VIR_BUFFER_INITIALIZER;

            virDomainVirtioNetDriverFormat(&driverAttrBuf, def);
            virDomainVirtioNetGuestOptsFormat(&guestAttrBuf, def);
            virDomainVirtioNetHostOptsFormat(&hostAttrBuf, def);

            virXMLFormatElement(&driverChildBuf, "host", &hostAttrBuf, NULL);
            virXMLFormatElement(&driverChildBuf, "guest", &guestAttrBuf, NULL);
            virXMLFormatElement(buf, "driver", &driverAttrBuf, &driverChildBuf);
        }
    }

    virDomainNetBackendFormat(buf, &def->backend);

    if (def->filter) {
        if (virNWFilterFormatParamAttributes(buf, def->filterparams,
                                             def->filter) < 0)
            return -1;
    }

    if (def->tune.sndbuf_specified) {
        g_auto(virBuffer) sndChildBuf = VIR_BUFFER_INIT_CHILD(buf);

        virBufferAsprintf(&sndChildBuf, "<sndbuf>%llu</sndbuf>\n", def->tune.sndbuf);

        virXMLFormatElement(buf, "tune", NULL, &sndChildBuf);
    }

    virDomainNetTeamingInfoFormat(def->teaming, buf);

    if (def->linkstate) {
        virBufferAsprintf(buf, "<link state='%s'/>\n",
                          virDomainNetInterfaceLinkStateTypeToString(def->linkstate));
    }

    if (def->mtu)
        virBufferAsprintf(buf, "<mtu size='%u'/>\n", def->mtu);

    virDomainNetDefCoalesceFormatXML(buf, def->coalesce);

    virDomainDeviceInfoFormat(buf, &def->info, flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT
                                                     | VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM);

    if (virDomainNetDefFormatPrivateData(buf, def, flags, xmlopt) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</interface>\n");
    return 0;
}


/* Assumes that "<device" has already been generated, and starts
 * output at " type='type'>". */
static int
virDomainChrAttrsDefFormat(virBuffer *buf,
                           virDomainChrSourceDef *def,
                           bool tty_compat)
{
    const char *type = virDomainChrTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected char type %1$d"), def->type);
        return -1;
    }

    /* Compat with legacy <console tty='/dev/pts/5'/> syntax */
    virBufferAsprintf(buf, " type='%s'", type);
    if (tty_compat) {
        virBufferEscapeString(buf, " tty='%s'",
                              def->data.file.path);
    }
    return 0;
}

static void
virDomainChrSourceDefFormat(virBuffer *buf,
                            virDomainChrSourceDef *def,
                            unsigned int flags)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    switch ((virDomainChrType)def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        /* nada */
        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
        if (def->data.qemuVdagent.mouse != VIR_DOMAIN_MOUSE_MODE_DEFAULT ||
            def->data.qemuVdagent.clipboard != VIR_TRISTATE_BOOL_ABSENT) {
            virBufferAddLit(buf, "<source>\n");
            virBufferAdjustIndent(buf, 2);
            if (def->data.qemuVdagent.clipboard != VIR_TRISTATE_BOOL_ABSENT)
                virBufferEscapeString(buf, "<clipboard copypaste='%s'/>\n",
                                      virTristateBoolTypeToString(def->data.qemuVdagent.clipboard));
            if (def->data.qemuVdagent.mouse != VIR_DOMAIN_MOUSE_MODE_DEFAULT)
                virBufferEscapeString(buf, "<mouse mode='%s'/>\n",
                                      virDomainMouseModeTypeToString(def->data.qemuVdagent.mouse));
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</source>\n");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (def->type != VIR_DOMAIN_CHR_TYPE_PTY ||
            (def->data.file.path &&
             !(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))) {
            virBufferEscapeString(&attrBuf, " path='%s'",
                                  def->data.file.path);
            if (def->type == VIR_DOMAIN_CHR_TYPE_FILE &&
                def->data.file.append != VIR_TRISTATE_SWITCH_ABSENT)
                virBufferAsprintf(&attrBuf, " append='%s'",
                    virTristateSwitchTypeToString(def->data.file.append));
            virDomainSourceDefFormatSeclabel(&childBuf, def->nseclabels,
                                             def->seclabels, flags);

            virXMLFormatElement(buf, "source", &attrBuf, &childBuf);
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
            virBufferEscapeString(buf, " host='%s'", def->data.udp.bindHost);
            virBufferEscapeString(buf, " service='%s'", def->data.udp.bindService);
            virBufferAddLit(buf, "/>\n");
        }

        if (def->data.udp.connectService || def->data.udp.connectHost) {
            virBufferAddLit(buf, "<source mode='connect'");
            virBufferEscapeString(buf, " host='%s'", def->data.udp.connectHost);
            virBufferEscapeString(buf, " service='%s'", def->data.udp.connectService);
            virBufferAddLit(buf, "/>\n");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferAsprintf(&attrBuf, " mode='%s' ",
                          def->data.tcp.listen ? "bind" : "connect");
        virBufferEscapeString(&attrBuf, "host='%s' ", def->data.tcp.host);
        virBufferEscapeString(&attrBuf, "service='%s'", def->data.tcp.service);
        if (def->data.tcp.haveTLS != VIR_TRISTATE_BOOL_ABSENT &&
            !(flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE &&
              def->data.tcp.tlsFromConfig))
            virBufferAsprintf(&attrBuf, " tls='%s'",
                    virTristateBoolTypeToString(def->data.tcp.haveTLS));
        if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS)
            virBufferAsprintf(&attrBuf, " tlsFromConfig='%d'",
                              def->data.tcp.tlsFromConfig);

        virDomainChrSourceReconnectDefFormat(&childBuf,
                                             &def->data.tcp.reconnect);

        virXMLFormatElement(buf, "source", &attrBuf, &childBuf);

        virBufferAsprintf(buf, "<protocol type='%s'/>\n",
                          virDomainChrTcpProtocolTypeToString(
                              def->data.tcp.protocol));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (def->data.nix.path) {
            virBufferAsprintf(&attrBuf, " mode='%s'",
                              def->data.nix.listen ? "bind" : "connect");
            virBufferEscapeString(&attrBuf, " path='%s'", def->data.nix.path);
            virDomainSourceDefFormatSeclabel(&childBuf, def->nseclabels,
                                             def->seclabels, flags);

            virDomainChrSourceReconnectDefFormat(&childBuf,
                                                 &def->data.nix.reconnect);

            virXMLFormatElement(buf, "source", &attrBuf, &childBuf);
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        virBufferEscapeString(buf, "<source channel='%s'/>\n",
                              def->data.spiceport.channel);
        break;

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        virBufferEscapeString(buf, "<source channel='%s'/>\n",
                              def->data.dbus.channel);
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
}


static int
virDomainChrTargetDefFormat(virBuffer *buf,
                            const virDomainChrDef *def,
                            unsigned int flags)
{
    const char *targetType = virDomainChrTargetTypeToString(def->deviceType,
                                                            def->targetType);

    switch ((virDomainChrDeviceType) def->deviceType) {
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
            g_autofree char *addr = NULL;
            if (port < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to format guestfwd port"));
                return -1;
            }

            addr = virSocketAddrFormat(def->target.addr);
            if (addr == NULL)
                return -1;

            virBufferAsprintf(buf, " address='%s' port='%d'",
                              addr, port);
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
        if (!targetType) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not format console target type"));
            return -1;
        }

        virBufferAsprintf(buf,
                          "<target type='%s' port='%d'/>\n",
                          targetType, def->target.port);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        if (!targetType) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not format serial target type"));
            return -1;
        }

        virBufferAddLit(buf, "<target ");

        if (def->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE) {
            virBufferAsprintf(buf,
                              "type='%s' ",
                              targetType);
        }

        virBufferAsprintf(buf,
                          "port='%d'",
                          def->target.port);

        if (def->targetModel != VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE) {
            virBufferAddLit(buf, ">\n");

            virBufferAdjustIndent(buf, 2);
            virBufferAsprintf(buf,
                              "<model name='%s'/>\n",
                              virDomainChrSerialTargetModelTypeToString(def->targetModel));
            virBufferAdjustIndent(buf, -2);

            virBufferAddLit(buf, "</target>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }

        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        virBufferAsprintf(buf, "<target port='%d'/>\n",
                          def->target.port);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected char device type %1$d"),
                       def->deviceType);
        return -1;
    }

    return 0;
}

static int
virDomainChrDefFormat(virBuffer *buf,
                      virDomainChrDef *def,
                      unsigned int flags)
{
    const char *elementName = virDomainChrDeviceTypeToString(def->deviceType);
    bool tty_compat;

    if (!elementName) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected char device type %1$d"),
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
    if (virDomainChrAttrsDefFormat(buf, def->source, tty_compat) < 0)
        return -1;
    virBufferAddLit(buf, ">\n");

    virDomainChrSourceDefFormat(buf, def->source, flags);

    if (virDomainChrTargetDefFormat(buf, def, flags) < 0)
        return -1;

    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAsprintf(buf, "</%s>\n", elementName);

    return 0;
}

static int
virDomainSmartcardDefFormat(virBuffer *buf,
                            virDomainSmartcardDef *def,
                            unsigned int flags)
{
    const char *mode = virDomainSmartcardTypeToString(def->type);
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (!mode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected smartcard type %1$d"), def->type);
        return -1;
    }

    switch (def->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        for (i = 0; i < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; i++) {
            virBufferEscapeString(&childBuf, "<certificate>%s</certificate>\n",
                                  def->data.cert.file[i]);
        }
        virBufferEscapeString(&childBuf, "<database>%s</database>\n",
                              def->data.cert.database);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        virDomainChrSourceDefFormat(&childBuf, def->data.passthru, flags);
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainSmartcardType, def->type);
        return -1;
    }
    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virBufferAsprintf(&attrBuf, " mode='%s'", mode);
    if (def->type == VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH &&
        virDomainChrAttrsDefFormat(&attrBuf, def->data.passthru, false) < 0) {
        return -1;
    }

    virXMLFormatElement(buf, "smartcard", &attrBuf, &childBuf);

    return 0;
}

static int
virDomainSoundCodecDefFormat(virBuffer *buf,
                             virDomainSoundCodecDef *def)
{
    const char *type = virDomainSoundCodecTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected codec type %1$d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<codec type='%s'/>\n",  type);

    return 0;
}

static int
virDomainTPMDefFormatPrivateData(virBuffer *buf,
                                 const virDomainTPMDef *tpm,
                                 unsigned int flags,
                                 virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_STATUS) ||
        !xmlopt ||
        !xmlopt->privateData.tpmFormat)
        return 0;

    if (xmlopt->privateData.tpmFormat(tpm, &childBuf) < 0)
        return -1;

    virXMLFormatElement(buf, "privateData", NULL, &childBuf);
    return 0;
}


static int
virDomainTPMDefFormat(virBuffer *buf,
                      const virDomainTPMDef *def,
                      unsigned int flags,
                      virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) backendAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) backendChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);

    if (def->model != VIR_DOMAIN_TPM_MODEL_DEFAULT) {
        virBufferAsprintf(&attrBuf, " model='%s'",
                          virDomainTPMModelTypeToString(def->model));
    }

    virBufferAsprintf(&backendAttrBuf, " type='%s'",
                      virDomainTPMBackendTypeToString(def->type));

    switch (def->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        virBufferEscapeString(&backendChildBuf, "<device path='%s'/>\n",
                              def->data.passthrough.source->data.file.path);
        break;
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        if (def->data.emulator.version != VIR_DOMAIN_TPM_VERSION_DEFAULT) {
            virBufferAsprintf(&backendAttrBuf, " version='%s'",
                              virDomainTPMVersionTypeToString(def->data.emulator.version));
        }
        if (def->data.emulator.persistent_state)
            virBufferAddLit(&backendAttrBuf, " persistent_state='yes'");
        if (def->data.emulator.hassecretuuid) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            virBufferAsprintf(&backendChildBuf, "<encryption secret='%s'/>\n",
                              virUUIDFormat(def->data.emulator.secretuuid, uuidstr));
        }
        if (def->data.emulator.activePcrBanks) {
            g_auto(virBuffer) activePcrBanksBuf = VIR_BUFFER_INIT_CHILD(&backendChildBuf);
            ssize_t bank = -1;

            while ((bank = virBitmapNextSetBit(def->data.emulator.activePcrBanks, bank)) > -1)
                virBufferAsprintf(&activePcrBanksBuf, "<%s/>\n", virDomainTPMPcrBankTypeToString(bank));

            virXMLFormatElement(&backendChildBuf, "active_pcr_banks", NULL, &activePcrBanksBuf);
        }
        break;
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
        if (def->data.external.source->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
            virBufferAddLit(&backendChildBuf, "<source type='unix' mode='connect'");
            virBufferEscapeString(&backendChildBuf, " path='%s'/>\n",
                                  def->data.external.source->data.nix.path);
        }
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    virXMLFormatElement(&childBuf, "backend", &backendAttrBuf, &backendChildBuf);
    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);
    if (virDomainTPMDefFormatPrivateData(&childBuf, def, flags, xmlopt) < 0)
        return -1;

    virXMLFormatElement(buf, "tpm", &attrBuf, &childBuf);

    return 0;
}


static int
virDomainSoundDefFormat(virBuffer *buf,
                        virDomainSoundDef *def,
                        unsigned int flags)
{
    const char *model = virDomainSoundModelTypeToString(def->model);
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected sound model %1$d"), def->model);
        return -1;
    }

    for (i = 0; i < def->ncodecs; i++)
        virDomainSoundCodecDefFormat(&childBuf, def->codecs[i]);

    if (def->audioId > 0)
        virBufferAsprintf(&childBuf, "<audio id='%d'/>\n", def->audioId);

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virBufferAsprintf(&attrBuf, " model='%s'",  model);

    if (def->model == VIR_DOMAIN_SOUND_MODEL_USB &&
        def->multichannel != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&attrBuf, " multichannel='%s'",
                          virTristateBoolTypeToString(def->multichannel));
    }

    virXMLFormatElement(buf,  "sound", &attrBuf, &childBuf);

    return 0;
}


static void
virDomainAudioCommonFormat(virDomainAudioIOCommon *def,
                           virBuffer *childBuf,
                           virBuffer *backendAttrBuf,
                           const char *direction)
{
    g_auto(virBuffer) settingsBuf = VIR_BUFFER_INITIALIZER;

    if (def->fixedSettings == VIR_TRISTATE_BOOL_YES) {
        if (def->frequency)
            virBufferAsprintf(&settingsBuf, " frequency='%u'",
                              def->frequency);
        if (def->channels)
            virBufferAsprintf(&settingsBuf, " channels='%u'",
                              def->channels);
        if (def->format)
            virBufferAsprintf(&settingsBuf, " format='%s'",
                              virDomainAudioFormatTypeToString(def->format));
    }

    if (def->mixingEngine || def->fixedSettings ||
        def->voices || def->bufferLength ||
        virBufferUse(backendAttrBuf)) {
        virBufferAsprintf(childBuf, "<%s", direction);
        if (def->mixingEngine)
            virBufferAsprintf(childBuf, " mixingEngine='%s'",
                              virTristateBoolTypeToString(def->mixingEngine));
        if (def->fixedSettings)
            virBufferAsprintf(childBuf, " fixedSettings='%s'",
                              virTristateBoolTypeToString(def->fixedSettings));
        if (def->voices)
            virBufferAsprintf(childBuf, " voices='%u'",
                              def->voices);
        if (def->bufferLength)
            virBufferAsprintf(childBuf, " bufferLength='%u'",
                              def->bufferLength);
        if (virBufferUse(backendAttrBuf))
            virBufferAdd(childBuf, virBufferCurrentContent(backendAttrBuf), -1);
        if (def->fixedSettings == VIR_TRISTATE_BOOL_YES) {
            virBufferAddLit(childBuf, ">\n");
            virBufferAdjustIndent(childBuf, 2);
            virBufferAddLit(childBuf, "<settings");
            if (virBufferUse(&settingsBuf)) {
                virBufferAdd(childBuf, virBufferCurrentContent(&settingsBuf), -1);
            }
            virBufferAddLit(childBuf, "/>\n");
            virBufferAdjustIndent(childBuf, -2);
            virBufferAsprintf(childBuf, "</%s>\n", direction);
        } else {
            virBufferAddLit(childBuf, "/>\n");
        }
    }
}


static void
virDomainAudioALSAFormat(virDomainAudioIOALSA *def,
                         virBuffer *buf)
{
    virBufferEscapeString(buf, " dev='%s'", def->dev);
}


static void
virDomainAudioCoreAudioFormat(virDomainAudioIOCoreAudio *def,
                              virBuffer *buf)
{
    if (def->bufferCount)
        virBufferAsprintf(buf, " bufferCount='%u'", def->bufferCount);
}


static void
virDomainAudioJackFormat(virDomainAudioIOJack *def,
                         virBuffer *buf)
{
    virBufferEscapeString(buf, " serverName='%s'", def->serverName);
    virBufferEscapeString(buf, " clientName='%s'", def->clientName);
    virBufferEscapeString(buf, " connectPorts='%s'", def->connectPorts);
    if (def->exactName)
        virBufferAsprintf(buf, " exactName='%s'",
                          virTristateBoolTypeToString(def->exactName));
}


static void
virDomainAudioOSSFormat(virDomainAudioIOOSS *def,
                        virBuffer *buf)
{
    virBufferEscapeString(buf, " dev='%s'", def->dev);
    if (def->bufferCount)
        virBufferAsprintf(buf, " bufferCount='%u'", def->bufferCount);
    if (def->tryPoll)
        virBufferAsprintf(buf, " tryPoll='%s'",
                          virTristateBoolTypeToString(def->tryPoll));
}


static void
virDomainAudioPulseAudioFormat(virDomainAudioIOPulseAudio *def,
                               virBuffer *buf)
{
    virBufferEscapeString(buf, " name='%s'", def->name);
    virBufferEscapeString(buf, " streamName='%s'", def->streamName);
    if (def->latency)
        virBufferAsprintf(buf, " latency='%u'", def->latency);

}


static void
virDomainAudioSDLFormat(virDomainAudioIOSDL *def,
                        virBuffer *buf)
{
    if (def->bufferCount)
        virBufferAsprintf(buf, " bufferCount='%u'", def->bufferCount);
}


static int
virDomainAudioDefFormat(virBuffer *buf,
                        virDomainAudioDef *def)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) inputBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) outputBuf = VIR_BUFFER_INITIALIZER;
    const char *type = virDomainAudioTypeTypeToString(def->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected audio type %1$d"), def->type);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " id='%d' type='%s'", def->id, type);

    if (def->timerPeriod)
        virBufferAsprintf(&attrBuf, " timerPeriod='%u'", def->timerPeriod);

    switch (def->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        virDomainAudioALSAFormat(&def->backend.alsa.input, &inputBuf);
        virDomainAudioALSAFormat(&def->backend.alsa.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        virDomainAudioCoreAudioFormat(&def->backend.coreaudio.input, &inputBuf);
        virDomainAudioCoreAudioFormat(&def->backend.coreaudio.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_JACK:
        virDomainAudioJackFormat(&def->backend.jack.input, &inputBuf);
        virDomainAudioJackFormat(&def->backend.jack.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_OSS:
        if (def->backend.oss.tryMMap)
            virBufferAsprintf(&attrBuf, " tryMMap='%s'",
                              virTristateBoolTypeToString(def->backend.oss.tryMMap));
        if (def->backend.oss.exclusive)
            virBufferAsprintf(&attrBuf, " exclusive='%s'",
                              virTristateBoolTypeToString(def->backend.oss.exclusive));
        if (def->backend.oss.dspPolicySet)
            virBufferAsprintf(&attrBuf, " dspPolicy='%d'", def->backend.oss.dspPolicy);

        virDomainAudioOSSFormat(&def->backend.oss.input, &inputBuf);
        virDomainAudioOSSFormat(&def->backend.oss.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        virBufferEscapeString(&attrBuf, " serverName='%s'",
                              def->backend.pulseaudio.serverName);

        virDomainAudioPulseAudioFormat(&def->backend.pulseaudio.input, &inputBuf);
        virDomainAudioPulseAudioFormat(&def->backend.pulseaudio.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SDL:
        if (def->backend.sdl.driver)
            virBufferAsprintf(&attrBuf, " driver='%s'",
                              virDomainAudioSDLDriverTypeToString(
                                  def->backend.sdl.driver));

        virDomainAudioSDLFormat(&def->backend.sdl.input, &inputBuf);
        virDomainAudioSDLFormat(&def->backend.sdl.output, &outputBuf);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        virBufferEscapeString(&attrBuf, " path='%s'", def->backend.file.path);
        break;

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainAudioType, def->type);
        return -1;
    }

    virDomainAudioCommonFormat(&def->input, &childBuf, &inputBuf, "input");
    virDomainAudioCommonFormat(&def->output, &childBuf, &outputBuf, "output");

    virXMLFormatElement(buf, "audio", &attrBuf, &childBuf);

    return 0;
}


static int
virDomainMemballoonDefFormat(virBuffer *buf,
                             virDomainMemballoonDef *def,
                             unsigned int flags)
{
    const char *model = virDomainMemballoonModelTypeToString(def->model);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected memballoon model %1$d"), def->model);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " model='%s'", model);

    if (def->autodeflate != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(&attrBuf, " autodeflate='%s'",
                          virTristateSwitchTypeToString(def->autodeflate));

    if (def->free_page_reporting != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(&attrBuf, " freePageReporting='%s'",
                          virTristateSwitchTypeToString(def->free_page_reporting));

    if (def->period)
        virBufferAsprintf(&childrenBuf, "<stats period='%i'/>\n", def->period);

    virDomainDeviceInfoFormat(&childrenBuf, &def->info, flags);

    virDomainVirtioOptionsFormat(&driverAttrBuf, def->virtio);

    virXMLFormatElement(&childrenBuf, "driver", &driverAttrBuf, NULL);
    virXMLFormatElement(buf, "memballoon", &attrBuf, &childrenBuf);

    return 0;
}

static void
virDomainNVRAMDefFormat(virBuffer *buf,
                        virDomainNVRAMDef *def,
                        unsigned int flags)
{
    virBufferAddLit(buf, "<nvram>\n");
    virBufferAdjustIndent(buf, 2);
    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</nvram>\n");
}


static int
virDomainWatchdogDefFormat(virBuffer *buf,
                           virDomainWatchdogDef *def,
                           unsigned int flags)
{
    const char *model = virDomainWatchdogModelTypeToString(def->model);
    const char *action = virDomainWatchdogActionTypeToString(def->action);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected watchdog model %1$d"), def->model);
        return -1;
    }

    if (!action) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected watchdog action %1$d"), def->action);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " model='%s' action='%s'", model, action);

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virXMLFormatElement(buf, "watchdog", &attrBuf, &childBuf);

    return 0;
}

static void virDomainPanicDefFormat(virBuffer *buf, virDomainPanicDef *def)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (def->model)
        virBufferAsprintf(&attrBuf, " model='%s'",
                          virDomainPanicModelTypeToString(def->model));

    virDomainDeviceInfoFormat(&childrenBuf, &def->info, 0);

    virXMLFormatElement(buf, "panic", &attrBuf, &childrenBuf);
}

static void
virDomainShmemDefFormat(virBuffer *buf,
                        virDomainShmemDef *def,
                        unsigned int flags)
{
    virBufferEscapeString(buf, "<shmem name='%s'", def->name);
    if (def->role)
        virBufferEscapeString(buf, " role='%s'",
                              virDomainShmemRoleTypeToString(def->role));

    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    virBufferAsprintf(buf, "<model type='%s'/>\n",
                      virDomainShmemModelTypeToString(def->model));

    if (def->size)
        virBufferAsprintf(buf, "<size unit='M'>%llu</size>\n", def->size >> 20);

    if (def->server.enabled) {
        virBufferAddLit(buf, "<server");
        virBufferEscapeString(buf, " path='%s'", def->server.chr->data.nix.path);
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

    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</shmem>\n");
}

static int
virDomainRNGDefFormat(virBuffer *buf,
                      virDomainRNGDef *def,
                      unsigned int flags)
{
    const char *model = virDomainRNGModelTypeToString(def->model);
    const char *backend = virDomainRNGBackendTypeToString(def->backend);
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(buf, "<rng model='%s'>\n", model);
    virBufferAdjustIndent(buf, 2);
    if (def->rate) {
        virBufferAsprintf(buf, "<rate bytes='%u'", def->rate);
        if (def->period)
            virBufferAsprintf(buf, " period='%u'", def->period);
        virBufferAddLit(buf, "/>\n");
    }
    virBufferAsprintf(buf, "<backend model='%s'", backend);

    switch (def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        virBufferEscapeString(buf, ">%s</backend>\n", def->source.file);
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (virDomainChrAttrsDefFormat(buf, def->source.chardev, false) < 0)
            return -1;
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virDomainChrSourceDefFormat(buf, def->source.chardev, flags);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</backend>\n");
        break;

    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        virBufferAddLit(buf, "/>\n");
        break;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    virDomainVirtioOptionsFormat(&driverAttrBuf, def->virtio);

    virXMLFormatElement(buf, "driver", &driverAttrBuf, NULL);

    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</rng>\n");

    return 0;
}

void
virDomainRNGDefFree(virDomainRNGDef *def)
{
    if (!def)
        return;

    switch (def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        g_free(def->source.file);
        break;
    case VIR_DOMAIN_RNG_BACKEND_EGD:
        virObjectUnref(def->source.chardev);
        break;
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    virDomainDeviceInfoClear(&def->info);
    g_free(def->virtio);
    g_free(def);
}


static void
virDomainCryptoDefFormat(virBuffer *buf,
                         virDomainCryptoDef *def,
                         unsigned int flags)
{
    const char *model = virDomainCryptoModelTypeToString(def->model);
    const char *type = virDomainCryptoTypeTypeToString(def->model);
    const char *backend = virDomainCryptoBackendTypeToString(def->backend);
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virBufferAsprintf(&attrBuf, " model='%s' type='%s'", model, type);
    virBufferAsprintf(&childBuf, "<backend model='%s'", backend);
    if (def->queues)
        virBufferAsprintf(&childBuf, " queues='%d'", def->queues);
    virBufferAddLit(&childBuf, "/>\n");

    virDomainVirtioOptionsFormat(&driverAttrBuf, def->virtio);

    virXMLFormatElement(&childBuf, "driver", &driverAttrBuf, NULL);

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virXMLFormatElement(buf, "crypto", &attrBuf, &childBuf);
}

void
virDomainCryptoDefFree(virDomainCryptoDef *def)
{
    if (!def)
        return;

    virDomainDeviceInfoClear(&def->info);
    g_free(def->virtio);
    g_free(def);
}


static int
virDomainMemorySourceDefFormat(virBuffer *buf,
                               virDomainMemoryDef *def)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_autofree char *bitmap = NULL;

    switch (def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        if (def->source.dimm.nodes) {
            if (!(bitmap = virBitmapFormat(def->source.dimm.nodes)))
                return -1;

            virBufferAsprintf(&childBuf, "<nodemask>%s</nodemask>\n", bitmap);
        }

        if (def->source.dimm.pagesize)
            virBufferAsprintf(&childBuf, "<pagesize unit='KiB'>%llu</pagesize>\n",
                              def->source.dimm.pagesize);
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        if (def->source.virtio_mem.nodes) {
            if (!(bitmap = virBitmapFormat(def->source.virtio_mem.nodes)))
                return -1;

            virBufferAsprintf(&childBuf, "<nodemask>%s</nodemask>\n", bitmap);
        }

        if (def->source.virtio_mem.pagesize)
            virBufferAsprintf(&childBuf, "<pagesize unit='KiB'>%llu</pagesize>\n",
                              def->source.virtio_mem.pagesize);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        virBufferEscapeString(&childBuf, "<path>%s</path>\n", def->source.nvdimm.path);

        if (def->source.nvdimm.alignsize)
            virBufferAsprintf(&childBuf, "<alignsize unit='KiB'>%llu</alignsize>\n",
                              def->source.nvdimm.alignsize);

        if (def->source.nvdimm.pmem)
            virBufferAddLit(&childBuf, "<pmem/>\n");
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        virBufferEscapeString(&childBuf, "<path>%s</path>\n", def->source.virtio_pmem.path);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        if (def->source.sgx_epc.nodes) {
            if (!(bitmap = virBitmapFormat(def->source.sgx_epc.nodes)))
                return -1;

            virBufferAsprintf(&childBuf, "<nodemask>%s</nodemask>\n", bitmap);
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    virXMLFormatElement(buf, "source", NULL, &childBuf);

    return 0;
}


static void
virDomainMemoryTargetDefFormat(virBuffer *buf,
                               virDomainMemoryDef *def,
                               unsigned int flags)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    virBufferAsprintf(&childBuf, "<size unit='KiB'>%llu</size>\n", def->size);
    if (def->targetNode >= 0)
        virBufferAsprintf(&childBuf, "<node>%d</node>\n", def->targetNode);

    switch (def->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (def->target.nvdimm.labelsize) {
            g_auto(virBuffer) labelChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);

            virBufferAsprintf(&labelChildBuf, "<size unit='KiB'>%llu</size>\n",
                              def->target.nvdimm.labelsize);
            virXMLFormatElement(&childBuf, "label", NULL, &labelChildBuf);
        }
        if (def->target.nvdimm.readonly)
            virBufferAddLit(&childBuf, "<readonly/>\n");
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (def->target.virtio_pmem.address)
            virBufferAsprintf(&childBuf, "<address base='0x%llx'/>\n",
                              def->target.virtio_pmem.address);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        if (def->target.virtio_mem.blocksize) {
            virBufferAsprintf(&childBuf, "<block unit='KiB'>%llu</block>\n",
                              def->target.virtio_mem.blocksize);

            virBufferAsprintf(&childBuf, "<requested unit='KiB'>%llu</requested>\n",
                              def->target.virtio_mem.requestedsize);
            if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)) {
                virBufferAsprintf(&childBuf, "<current unit='KiB'>%llu</current>\n",
                                  def->target.virtio_mem.currentsize);
            }
        }
        if (def->target.virtio_mem.address)
            virBufferAsprintf(&childBuf, "<address base='0x%llx'/>\n",
                              def->target.virtio_mem.address);
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    virXMLFormatElement(buf, "target", NULL, &childBuf);
}

static int
virDomainMemoryDefFormat(virBuffer *buf,
                         virDomainMemoryDef *def,
                         unsigned int flags)
{
    const char *model = virDomainMemoryModelTypeToString(def->model);

    virBufferAsprintf(buf, "<memory model='%s'", model);
    if (def->access)
        virBufferAsprintf(buf, " access='%s'",
                          virDomainMemoryAccessTypeToString(def->access));
    if (def->discard)
        virBufferAsprintf(buf, " discard='%s'",
                          virTristateBoolTypeToString(def->discard));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (def->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        def->target.nvdimm.uuid) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(def->target.nvdimm.uuid, uuidstr);
        virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);
    }

    if (virDomainMemorySourceDefFormat(buf, def) < 0)
        return -1;

    virDomainMemoryTargetDefFormat(buf, def, flags);

    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</memory>\n");
    return 0;
}

static void
virDomainVideoAccelDefFormat(virBuffer *buf,
                             virDomainVideoAccelDef *def)
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
    virBufferEscapeString(buf, " rendernode='%s'", def->rendernode);
    virBufferAddLit(buf, "/>\n");
}

static void
virDomainVideoResolutionDefFormat(virBuffer *buf,
                                  virDomainVideoResolutionDef *def)
{
    virBufferAddLit(buf, "<resolution");
    if (def->x && def->y) {
        virBufferAsprintf(buf, " x='%u' y='%u'",
                          def->x, def->y);
    }
    virBufferAddLit(buf, "/>\n");
}

static int
virDomainVideoDefFormat(virBuffer *buf,
                        virDomainVideoDef *def,
                        unsigned int flags)
{
    const char *model = virDomainVideoTypeToString(def->type);
    g_auto(virBuffer) driverBuf = VIR_BUFFER_INITIALIZER;

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected video model %1$d"), def->type);
        return -1;
    }

    virBufferAddLit(buf, "<video>\n");
    virBufferAdjustIndent(buf, 2);
    virDomainVirtioOptionsFormat(&driverBuf, def->virtio);
    if (virBufferUse(&driverBuf) || (def->driver && def->driver->vgaconf) ||
        def->backend != VIR_DOMAIN_VIDEO_BACKEND_TYPE_DEFAULT) {
        virBufferAddLit(buf, "<driver");
        if (virBufferUse(&driverBuf))
            virBufferAddBuffer(buf, &driverBuf);
        if (def->driver && def->driver->vgaconf)
            virBufferAsprintf(buf, " vgaconf='%s'",
                              virDomainVideoVGAConfTypeToString(def->driver->vgaconf));
        if (def->backend != VIR_DOMAIN_VIDEO_BACKEND_TYPE_DEFAULT)
            virBufferAsprintf(buf, " name='%s'",
                              virDomainVideoBackendTypeToString(def->backend));
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
    if (def->blob != VIR_TRISTATE_SWITCH_ABSENT)
        virBufferAsprintf(buf, " blob='%s'", virTristateSwitchTypeToString(def->blob));
    if (def->accel || def->res) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        if (def->accel)
            virDomainVideoAccelDefFormat(buf, def->accel);
        if (def->res)
            virDomainVideoResolutionDefFormat(buf, def->res);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</model>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    virDomainDeviceInfoFormat(buf, &def->info, flags);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</video>\n");

    return 0;
}

static int
virDomainInputDefFormat(virBuffer *buf,
                        virDomainInputDef *def,
                        unsigned int flags)
{
    const char *type = virDomainInputTypeToString(def->type);
    const char *bus = virDomainInputBusTypeToString(def->bus);
    const char *grab = virDomainInputSourceGrabTypeToString(def->source.grab);
    const char *grabToggle = virDomainInputSourceGrabToggleTypeToString(def->source.grabToggle);
    const char *repeat = virTristateSwitchTypeToString(def->source.repeat);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) sourceAttrBuf = VIR_BUFFER_INITIALIZER;

    /* don't format keyboard into migratable XML for backward compatibility */
    if (flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE &&
        def->type == VIR_DOMAIN_INPUT_TYPE_KBD &&
        (def->bus == VIR_DOMAIN_INPUT_BUS_PS2 ||
         def->bus == VIR_DOMAIN_INPUT_BUS_XEN))
        return 0;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected input type %1$d"), def->type);
        return -1;
    }
    if (!bus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected input bus type %1$d"), def->bus);
        return -1;
    }

    virBufferAsprintf(&attrBuf, " type='%s'", type);
    if (def->bus != VIR_DOMAIN_INPUT_BUS_NONE)
        virBufferAsprintf(&attrBuf, " bus='%s'", bus);

    if (def->model) {
        const char *model = virDomainInputModelTypeToString(def->model);

        if (!model) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected input model %1$d"), def->model);
            return -1;
        }

        virBufferAsprintf(&attrBuf, " model='%s'", model);
    }

    virDomainVirtioOptionsFormat(&driverAttrBuf, def->virtio);

    virXMLFormatElement(&childBuf, "driver", &driverAttrBuf, NULL);

    if (def->type == VIR_DOMAIN_INPUT_TYPE_EVDEV)
        virBufferEscapeString(&sourceAttrBuf, " dev='%s'", def->source.evdev);
    else
        virBufferEscapeString(&sourceAttrBuf, " evdev='%s'", def->source.evdev);

    if (def->source.grab)
        virBufferAsprintf(&sourceAttrBuf, " grab='%s'", grab);
    if (def->source.grabToggle)
        virBufferAsprintf(&sourceAttrBuf, " grabToggle='%s'", grabToggle);
    if (def->source.repeat)
        virBufferAsprintf(&sourceAttrBuf, " repeat='%s'", repeat);

    virXMLFormatElement(&childBuf, "source", &sourceAttrBuf, NULL);

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virXMLFormatElement(buf, "input", &attrBuf, &childBuf);

    return 0;
}


static void
virDomainTimerDefFormat(virBuffer *buf,
                        virDomainTimerDef *def)
{
    virBuffer timerAttr = VIR_BUFFER_INITIALIZER;
    virBuffer timerChld = VIR_BUFFER_INIT_CHILD(buf);
    virBuffer catchupAttr = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&timerAttr, " name='%s'",
                      virDomainTimerNameTypeToString(def->name));

    if (def->present != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&timerAttr, " present='%s'",
                          virTristateBoolTypeToString(def->present));
    }

    if (def->tickpolicy) {
        virBufferAsprintf(&timerAttr, " tickpolicy='%s'",
                          virDomainTimerTickpolicyTypeToString(def->tickpolicy));
    }

    if (def->track != VIR_DOMAIN_TIMER_TRACK_NONE) {
        virBufferAsprintf(&timerAttr, " track='%s'",
                          virDomainTimerTrackTypeToString(def->track));
    }

    if (def->name == VIR_DOMAIN_TIMER_NAME_TSC) {
        if (def->frequency > 0)
            virBufferAsprintf(&timerAttr, " frequency='%llu'", def->frequency);

        if (def->mode) {
            virBufferAsprintf(&timerAttr, " mode='%s'",
                              virDomainTimerModeTypeToString(def->mode));
        }
    }

    if (def->catchup.threshold > 0)
        virBufferAsprintf(&catchupAttr, " threshold='%llu'", def->catchup.threshold);
    if (def->catchup.slew > 0)
        virBufferAsprintf(&catchupAttr, " slew='%llu'", def->catchup.slew);
    if (def->catchup.limit > 0)
        virBufferAsprintf(&catchupAttr, " limit='%llu'", def->catchup.limit);

    virXMLFormatElement(&timerChld, "catchup", &catchupAttr, NULL);
    virXMLFormatElement(buf, "timer", &timerAttr, &timerChld);
}


static void
virDomainClockDefFormat(virBuffer *buf,
                        const virDomainClockDef *def,
                        unsigned int flags)
{
    virBuffer clockAttr = VIR_BUFFER_INITIALIZER;
    virBuffer clockChld = VIR_BUFFER_INIT_CHILD(buf);
    size_t n;

    virBufferAsprintf(&clockAttr, " offset='%s'",
                      virDomainClockOffsetTypeToString(def->offset));
    switch (def->offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        if (def->data.utc_reset)
            virBufferAddLit(&clockAttr, " adjustment='reset'");
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
        virBufferAsprintf(&clockAttr, " adjustment='%lld' basis='%s'",
                          def->data.variable.adjustment,
                          virDomainClockBasisTypeToString(def->data.variable.basis));
        if (flags & VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST &&
            def->data.variable.adjustment0) {
            virBufferAsprintf(&clockAttr, " adjustment0='%lld'",
                              def->data.variable.adjustment0);
        }
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virBufferEscapeString(&clockAttr, " timezone='%s'", def->data.timezone);
        break;
    case VIR_DOMAIN_CLOCK_OFFSET_ABSOLUTE:
        virBufferAsprintf(&clockAttr, " start='%llu'", def->data.starttime);
        break;
    }

    for (n = 0; n < def->ntimers; n++) {
        virDomainTimerDefFormat(&clockChld, def->timers[n]);
    }

    virXMLFormatElement(buf, "clock", &clockAttr, &clockChld);
}


static void
virDomainGraphicsAuthDefFormatAttr(virBuffer *buf,
                                   virDomainGraphicsAuthDef *def,
                                   unsigned int flags)
{
    if (!def->passwd)
        return;

    if (flags & VIR_DOMAIN_DEF_FORMAT_SECURE)
        virBufferEscapeString(buf, " passwd='%s'",
                              def->passwd);

    if (def->expires) {
        g_autoptr(GDateTime) then = NULL;
        g_autofree char *thenstr = NULL;

        then = g_date_time_new_from_unix_utc(def->validTo);
        thenstr = g_date_time_format(then, "%Y-%m-%dT%H:%M:%S");
        virBufferAsprintf(buf, " passwdValidTo='%s'", thenstr);
    }

    if (def->connected)
        virBufferEscapeString(buf, " connected='%s'",
                              virDomainGraphicsAuthConnectedTypeToString(def->connected));
}


static void
virDomainGraphicsListenDefFormat(virBuffer *buf,
                                 virDomainGraphicsListenDef *def,
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
virDomainGraphicsListenDefFormatAddr(virBuffer *buf,
                                     virDomainGraphicsListenDef *glisten,
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
virDomainSpiceGLDefFormat(virBuffer *buf, virDomainGraphicsDef *def)
{
    if (def->data.spice.gl == VIR_TRISTATE_BOOL_ABSENT)
        return;

    virBufferAsprintf(buf, "<gl enable='%s'",
                      virTristateBoolTypeToString(def->data.spice.gl));
    virBufferEscapeString(buf, " rendernode='%s'", def->data.spice.rendernode);
    virBufferAddLit(buf, "/>\n");
}

static int
virDomainGraphicsDefFormat(virBuffer *buf,
                           virDomainGraphicsDef *def,
                           unsigned int flags)
{
    virDomainGraphicsListenDef *glisten = virDomainGraphicsGetListen(def, 0);
    const char *type = virDomainGraphicsTypeToString(def->type);
    bool children = false;
    size_t i;

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected net type %1$d"), def->type);
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

            if (flags & VIR_DOMAIN_DEF_FORMAT_STATUS)
                virBufferAsprintf(buf, " websocketGenerated='%s'",
                                  def->data.vnc.websocketGenerated ? "yes" : "no");

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

        if (def->data.vnc.powerControl)
            virBufferAsprintf(buf, " powerControl='%s'",
                              virTristateBoolTypeToString(def->data.vnc.powerControl));

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

        if (!children && def->data.sdl.gl != VIR_TRISTATE_BOOL_ABSENT) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }

        if (def->data.sdl.gl != VIR_TRISTATE_BOOL_ABSENT) {
            virBufferAsprintf(buf, "<gl enable='%s'",
                              virTristateBoolTypeToString(def->data.sdl.gl));
            virBufferAddLit(buf, "/>\n");
        }

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
                virBufferAddLit(buf, " autoport='no'");
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            /* If socket is auto-generated based on config option we don't
             * add any listen element into migratable XML because the original
             * listen type is "address".
             * We need to set autoport to make sure that libvirt on destination
             * will parse it as listen type "address", without autoport it is
             * parsed as listen type "none". */
            if ((flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE) &&
                glisten->fromConfig) {
                virBufferAddLit(buf, " autoport='yes'");
            }
            break;

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

    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        if (!def->data.egl_headless.rendernode)
            break;

        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }

        virBufferAddLit(buf, "<gl");
        virBufferEscapeString(buf, " rendernode='%s'",
                              def->data.egl_headless.rendernode);
        virBufferAddLit(buf, "/>\n");
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        if (def->data.dbus.p2p)
            virBufferAddLit(buf, " p2p='yes'");
        if (def->data.dbus.address)
            virBufferAsprintf(buf, " address='%s'",
                              def->data.dbus.address);

        if (!def->data.dbus.gl && def->data.dbus.audioId <= 0)
            break;

        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }

        if (def->data.dbus.gl) {
            virBufferAsprintf(buf, "<gl enable='%s'",
                              virTristateBoolTypeToString(def->data.dbus.gl));
            virBufferEscapeString(buf, " rendernode='%s'", def->data.dbus.rendernode);
            virBufferAddLit(buf, "/>\n");
        }

        if (def->data.dbus.audioId > 0)
            virBufferAsprintf(buf, "<audio id='%d'/>\n",
                              def->data.dbus.audioId);

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
                              virDomainMouseModeTypeToString(def->data.spice.mousemode));
        if (def->data.spice.copypaste)
            virBufferAsprintf(buf, "<clipboard copypaste='%s'/>\n",
                              virTristateBoolTypeToString(def->data.spice.copypaste));
        if (def->data.spice.filetransfer)
            virBufferAsprintf(buf, "<filetransfer enable='%s'/>\n",
                              virTristateBoolTypeToString(def->data.spice.filetransfer));

        virDomainSpiceGLDefFormat(buf, def);
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        if (!children) {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            children = true;
        }

        if (def->data.vnc.audioId > 0)
            virBufferAsprintf(buf, "<audio id='%d'/>\n",
                              def->data.vnc.audioId);
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
virDomainHostdevDefFormat(virBuffer *buf,
                          virDomainHostdevDef *def,
                          unsigned int flags,
                          virDomainXMLOption *xmlopt)
{
    const char *mode = virDomainHostdevModeTypeToString(def->mode);
    virDomainHostdevSubsysSCSI *scsisrc = &def->source.subsys.u.scsi;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &def->source.subsys.u.mdev;
    virDomainHostdevSubsysSCSIVHost *scsihostsrc = &def->source.subsys.u.scsi_host;
    const char *type;

    if (!mode) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev mode %1$d"), def->mode);
        return -1;
    }

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        type = virDomainHostdevSubsysTypeToString(def->source.subsys.type);
        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %1$d"),
                           def->source.subsys.type);
            return -1;
        }
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        type = virDomainHostdevCapsTypeToString(def->source.caps.type);
        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %1$d"),
                           def->source.caps.type);
            return -1;
        }
        break;
    default:
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hostdev mode %1$d"), def->mode);
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

        if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST &&
            scsihostsrc->model) {
            virBufferAsprintf(buf, " model='%s'",
                              virDomainHostdevSubsysSCSIVHostModelTypeToString(scsihostsrc->model));
        }

        if (def->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV) {
            virBufferAsprintf(buf, " model='%s'",
                              virMediatedDeviceModelTypeToString(mdevsrc->model));
            if (mdevsrc->display != VIR_TRISTATE_SWITCH_ABSENT)
                virBufferAsprintf(buf, " display='%s'",
                                  virTristateSwitchTypeToString(mdevsrc->display));
            if (mdevsrc->ramfb != VIR_TRISTATE_SWITCH_ABSENT)
                virBufferAsprintf(buf, " ramfb='%s'",
                                  virTristateSwitchTypeToString(mdevsrc->ramfb));
        }

    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    switch (def->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        if (virDomainHostdevDefFormatSubsys(buf, def, flags, false, xmlopt) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        if (virDomainHostdevDefFormatCaps(buf, def) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        break;
    }

    virDomainNetTeamingInfoFormat(def->teaming, buf);

    if (def->readonly)
        virBufferAddLit(buf, "<readonly/>\n");
    if (def->shareable)
        virBufferAddLit(buf, "<shareable/>\n");

    virDomainDeviceInfoFormat(buf, def->info, flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT
                                                    | VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</hostdev>\n");

    return 0;
}

static int
virDomainRedirdevDefFormat(virBuffer *buf,
                           virDomainRedirdevDef *def,
                           unsigned int flags)
{
    const char *bus;

    bus = virDomainRedirdevBusTypeToString(def->bus);

    virBufferAsprintf(buf, "<redirdev bus='%s'", bus);
    if (virDomainChrAttrsDefFormat(buf, def->source, false) < 0)
        return -1;
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    virDomainChrSourceDefFormat(buf, def->source, flags);

    virDomainDeviceInfoFormat(buf, &def->info, flags | VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</redirdev>\n");
    return 0;
}

static void
virDomainRedirFilterDefFormat(virBuffer *buf,
                              virDomainRedirFilterDef *filter)
{
    size_t i;

    /* no need format an empty redirfilter */
    if (filter->nusbdevs == 0)
        return;

    virBufferAddLit(buf, "<redirfilter>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < filter->nusbdevs; i++) {
        virDomainRedirFilterUSBDevDef *usbdev = filter->usbdevs[i];
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
}

static int
virDomainHubDefFormat(virBuffer *buf,
                      virDomainHubDef *def,
                      unsigned int flags)
{
    const char *type = virDomainHubTypeToString(def->type);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected hub type %1$d"), def->type);
        return -1;
    }

    virDomainDeviceInfoFormat(&childBuf, &def->info, flags);

    virBufferAsprintf(&attrBuf, " type='%s'", type);

    virXMLFormatElement(buf, "hub", &attrBuf, &childBuf);

    return 0;
}


static void
virDomainResourceDefFormat(virBuffer *buf,
                           virDomainResourceDef *def)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!def)
        return;

    if (def->partition)
        virBufferEscapeString(&childBuf, "<partition>%s</partition>\n", def->partition);

    if (def->appid)
        virBufferEscapeString(&childBuf, "<fibrechannel appid='%s'/>\n", def->appid);

    virXMLFormatElement(buf, "resource", NULL, &childBuf);
}


static int
virDomainHugepagesFormatBuf(virBuffer *buf,
                            virDomainHugePage *hugepage)
{
    virBufferAsprintf(buf, "<page size='%llu' unit='KiB'",
                      hugepage->size);

    if (hugepage->nodemask) {
        g_autofree char *nodeset = NULL;
        if (!(nodeset = virBitmapFormat(hugepage->nodemask)))
            return -1;
        virBufferAsprintf(buf, " nodeset='%s'", nodeset);
    }

    virBufferAddLit(buf, "/>\n");

    return 0;
}

static void
virDomainHugepagesFormat(virBuffer *buf,
                         virDomainHugePage *hugepages,
                         size_t nhugepages)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    if (nhugepages != 1 || hugepages[0].size != 0) {
        for (i = 0; i < nhugepages; i++)
            virDomainHugepagesFormatBuf(&childBuf, &hugepages[i]);
    }

    virXMLFormatElementEmpty(buf, "hugepages", NULL, &childBuf);
}


static int
virDomainLoaderDefFormatNvram(virBuffer *buf,
                              virDomainLoaderDef *loader,
                              virDomainXMLOption *xmlopt,
                              unsigned int flags)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBufDirect = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBufChild = VIR_BUFFER_INIT_CHILD(buf);
    virBuffer *childBuf = &childBufDirect;
    bool childNewline = false;

    virBufferEscapeString(&attrBuf, " template='%s'", loader->nvramTemplate);

    if (loader->nvram) {
        virStorageSource *src = loader->nvram;

        if (!loader->newStyleNVRAM) {
            virBufferEscapeString(&childBufDirect, "%s", src->path);
        } else {
            childNewline = true;
            childBuf = &childBufChild;

            virBufferAsprintf(&attrBuf, " type='%s'", virStorageTypeToString(src->type));

            if (virDomainDiskSourceFormat(&childBufChild, src, "source", 0,
                                          false, flags, false, false, xmlopt) < 0)
                return -1;
        }

        if (src->format &&
            src->format != VIR_STORAGE_FILE_RAW) {
            virBufferEscapeString(&attrBuf, " format='%s'",
                                  virStorageFileFormatTypeToString(src->format));
        }
    }

    virXMLFormatElementInternal(buf, "nvram", &attrBuf, childBuf, false, childNewline);

    return 0;
}


static int
virDomainLoaderDefFormat(virBuffer *buf,
                         virDomainLoaderDef *loader,
                         virDomainXMLOption *xmlopt,
                         unsigned int flags)
{
    g_auto(virBuffer) loaderAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) loaderChildBuf = VIR_BUFFER_INITIALIZER;

    if (loader->readonly != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(&loaderAttrBuf, " readonly='%s'",
                          virTristateBoolTypeToString(loader->readonly));

    if (loader->secure != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(&loaderAttrBuf, " secure='%s'",
                          virTristateBoolTypeToString(loader->secure));

    if (loader->type != VIR_DOMAIN_LOADER_TYPE_NONE)
        virBufferAsprintf(&loaderAttrBuf, " type='%s'",
                          virDomainLoaderTypeToString(loader->type));

    if (loader->stateless != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&loaderAttrBuf, " stateless='%s'",
                          virTristateBoolTypeToString(loader->stateless));
    }

    if (loader->format &&
        loader->format != VIR_STORAGE_FILE_RAW) {
        virBufferEscapeString(&loaderAttrBuf, " format='%s'",
                              virStorageFileFormatTypeToString(loader->format));
    }

    virBufferEscapeString(&loaderChildBuf, "%s", loader->path);

    virXMLFormatElementInternal(buf, "loader", &loaderAttrBuf, &loaderChildBuf, false, false);

    if (virDomainLoaderDefFormatNvram(buf, loader, xmlopt, flags) < 0)
        return -1;

    return 0;
}

static void
virDomainKeyWrapDefFormat(virBuffer *buf, virDomainKeyWrapDef *keywrap)
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
virDomainSecDefFormat(virBuffer *buf, virDomainSecDef *sec)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!sec)
        return;

    virBufferAsprintf(&attrBuf, " type='%s'",
                      virDomainLaunchSecurityTypeToString(sec->sectype));

    switch ((virDomainLaunchSecurity) sec->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV: {
        virDomainSEVDef *sev = &sec->data.sev;

        if (sev->kernel_hashes != VIR_TRISTATE_BOOL_ABSENT)
            virBufferAsprintf(&attrBuf, " kernelHashes='%s'",
                              virTristateBoolTypeToString(sev->kernel_hashes));

        if (sev->haveCbitpos)
            virBufferAsprintf(&childBuf, "<cbitpos>%d</cbitpos>\n", sev->cbitpos);

        if (sev->haveReducedPhysBits)
            virBufferAsprintf(&childBuf, "<reducedPhysBits>%d</reducedPhysBits>\n",
                              sev->reduced_phys_bits);
        virBufferAsprintf(&childBuf, "<policy>0x%04x</policy>\n", sev->policy);
        if (sev->dh_cert)
            virBufferEscapeString(&childBuf, "<dhCert>%s</dhCert>\n", sev->dh_cert);

        if (sev->session)
            virBufferEscapeString(&childBuf, "<session>%s</session>\n", sev->session);

        break;
    }

    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        break;

    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
        return;
    }

    virXMLFormatElement(buf, "launchSecurity", &attrBuf, &childBuf);
}


static void
virDomainPerfDefFormat(virBuffer *buf, virDomainPerfDef *perf)
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


static void
virDomainSchedulerFormat(virBuffer *buf,
                         const char *name,
                         virDomainThreadSchedParam *sched,
                         size_t id,
                         bool multiple_threads)
{
    switch (sched->policy) {
        case VIR_PROC_POLICY_BATCH:
        case VIR_PROC_POLICY_IDLE:
            virBufferAsprintf(buf, "<%ssched", name);
            if (multiple_threads)
                virBufferAsprintf(buf, " %ss='%zu'", name, id);
            virBufferAsprintf(buf, " scheduler='%s'/>\n",
                              virProcessSchedPolicyTypeToString(sched->policy));
            break;

        case VIR_PROC_POLICY_RR:
        case VIR_PROC_POLICY_FIFO:
            virBufferAsprintf(buf, "<%ssched", name);
            if (multiple_threads)
                virBufferAsprintf(buf, " %ss='%zu'", name, id);
            virBufferAsprintf(buf, " scheduler='%s' priority='%d'/>\n",
                              virProcessSchedPolicyTypeToString(sched->policy),
                              sched->priority);
            break;

        case VIR_PROC_POLICY_NONE:
        case VIR_PROC_POLICY_LAST:
            break;
        }

}


static int
virDomainCachetuneDefFormatHelper(unsigned int level,
                                  virCacheType type,
                                  unsigned int cache,
                                  unsigned long long size,
                                  void *opaque)
{
    const char *unit;
    virBuffer *buf = opaque;
    unsigned long long short_size = virFormatIntPretty(size, &unit);

    virBufferAsprintf(buf,
                      "<cache id='%u' level='%u' type='%s' "
                      "size='%llu' unit='%s'/>\n",
                      cache, level, virCacheTypeToString(type),
                      short_size, unit);

    return 0;
}


static int
virDomainResctrlMonDefFormatHelper(virDomainResctrlMonDef *domresmon,
                                   virResctrlMonitorType tag,
                                   virBuffer *buf)
{
    g_autofree char *vcpus = NULL;

    if (domresmon->tag != tag)
        return 0;

    virBufferAddLit(buf, "<monitor ");

    if (tag == VIR_RESCTRL_MONITOR_TYPE_CACHE) {
        virBufferAsprintf(buf, "level='%u' ",
                          VIR_DOMAIN_RESCTRL_MONITOR_CACHELEVEL);
    }

    vcpus = virBitmapFormat(domresmon->vcpus);
    if (!vcpus)
        return -1;

    virBufferAsprintf(buf, "vcpus='%s'/>\n", vcpus);

    return 0;
}


static int
virDomainCachetuneDefFormat(virBuffer *buf,
                            virDomainResctrlDef *resctrl,
                            unsigned int flags)
{
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    size_t i = 0;
    g_autofree char *vcpus = NULL;

    if (virResctrlAllocForeachCache(resctrl->alloc,
                                    virDomainCachetuneDefFormatHelper,
                                    &childrenBuf) < 0)
        return -1;

    for (i = 0; i < resctrl->nmonitors; i++) {
        if (virDomainResctrlMonDefFormatHelper(resctrl->monitors[i],
                                               VIR_RESCTRL_MONITOR_TYPE_CACHE,
                                               &childrenBuf) < 0)
            return -1;
    }

    if (!virBufferUse(&childrenBuf))
        return 0;

    vcpus = virBitmapFormat(resctrl->vcpus);
    if (!vcpus)
        return -1;

    virBufferAsprintf(&attrBuf, " vcpus='%s'", vcpus);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)) {
        const char *alloc_id = virResctrlAllocGetID(resctrl->alloc);
        if (!alloc_id)
            return -1;

        virBufferAsprintf(&attrBuf, " id='%s'", alloc_id);
    }

    virXMLFormatElement(buf, "cachetune", &attrBuf, &childrenBuf);

    return 0;
}


static int
virDomainMemorytuneDefFormatHelper(unsigned int id,
                                   unsigned int bandwidth,
                                   void *opaque)
{
    virBuffer *buf = opaque;

    virBufferAsprintf(buf,
                      "<node id='%u' bandwidth='%u'/>\n",
                      id, bandwidth);
    return 0;
}


static int
virDomainMemorytuneDefFormat(virBuffer *buf,
                            virDomainResctrlDef *resctrl,
                            unsigned int flags)
{
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_autofree char *vcpus = NULL;
    size_t i = 0;

    if (virResctrlAllocForeachMemory(resctrl->alloc,
                                     virDomainMemorytuneDefFormatHelper,
                                     &childrenBuf) < 0)
        return -1;

    for (i = 0; i < resctrl->nmonitors; i++) {
        if (virDomainResctrlMonDefFormatHelper(resctrl->monitors[i],
                                               VIR_RESCTRL_MONITOR_TYPE_MEMBW,
                                               &childrenBuf) < 0)
            return -1;
    }

    if (!virBufferUse(&childrenBuf))
        return 0;

    vcpus = virBitmapFormat(resctrl->vcpus);
    if (!vcpus)
        return -1;

    virBufferAsprintf(&attrBuf, " vcpus='%s'", vcpus);

    if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE)) {
        const char *alloc_id = virResctrlAllocGetID(resctrl->alloc);
        if (!alloc_id)
            return -1;

        virBufferAsprintf(&attrBuf, " id='%s'", alloc_id);
    }

    virXMLFormatElement(buf, "memorytune", &attrBuf, &childrenBuf);

    return 0;
}

static int
virDomainCputuneDefFormat(virBuffer *buf,
                          virDomainDef *def,
                          unsigned int flags)
{
    size_t i;
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);


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
        virDomainVcpuDef *vcpu = def->vcpus[i];

        if (!vcpu->cpumask)
            continue;

        if (!(cpumask = virBitmapFormat(vcpu->cpumask)))
            return -1;

        virBufferAsprintf(&childrenBuf,
                          "<vcpupin vcpu='%zu' cpuset='%s'/>\n", i, cpumask);

        VIR_FREE(cpumask);
    }

    if (def->cputune.emulatorpin) {
        char *cpumask;
        virBufferAddLit(&childrenBuf, "<emulatorpin ");

        if (!(cpumask = virBitmapFormat(def->cputune.emulatorpin)))
            return -1;

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
            return -1;

        virBufferAsprintf(&childrenBuf, "cpuset='%s'/>\n", cpumask);
        VIR_FREE(cpumask);
    }

    if (def->cputune.emulatorsched) {
        virDomainSchedulerFormat(&childrenBuf, "emulator",
                                 def->cputune.emulatorsched, 0, false);
    }

    for (i = 0; i < def->maxvcpus; i++) {
        virDomainSchedulerFormat(&childrenBuf, "vcpu",
                                 &def->vcpus[i]->sched, i, true);
    }

    for (i = 0; i < def->niothreadids; i++) {
        virDomainSchedulerFormat(&childrenBuf, "iothread",
                                 &def->iothreadids[i]->sched,
                                 def->iothreadids[i]->iothread_id,
                                 true);
    }

    for (i = 0; i < def->nresctrls; i++)
        virDomainCachetuneDefFormat(&childrenBuf, def->resctrls[i], flags);

    for (i = 0; i < def->nresctrls; i++)
        virDomainMemorytuneDefFormat(&childrenBuf, def->resctrls[i], flags);

    virXMLFormatElement(buf, "cputune", NULL, &childrenBuf);

    return 0;
}


static int
virDomainCpuDefFormat(virBuffer *buf,
                      const virDomainDef *def)
{
    virDomainVcpuDef *vcpu;
    size_t i;
    g_autofree char *cpumask = NULL;

    virBufferAddLit(buf, "<vcpu");
    virBufferAsprintf(buf, " placement='%s'",
                      virDomainCpuPlacementModeTypeToString(def->placement_mode));

    if (def->cpumask && !virBitmapIsAllSet(def->cpumask)) {
        if ((cpumask = virBitmapFormat(def->cpumask)) == NULL)
            return -1;
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

    return 0;
}


static bool
virDomainDefIothreadShouldFormat(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->niothreadids; i++) {
        if (!def->iothreadids[i]->autofill ||
            def->iothreadids[i]->set_poll_max_ns ||
            def->iothreadids[i]->set_poll_grow ||
            def->iothreadids[i]->set_poll_shrink ||
            def->iothreadids[i]->thread_pool_min >= 0 ||
            def->iothreadids[i]->thread_pool_max >= 0)
            return true;
    }

    return false;
}


static void
virDomainDefaultIOThreadDefFormat(virBuffer *buf,
                                  const virDomainDef *def)
{
    virBuffer attrBuf = VIR_BUFFER_INITIALIZER;

    if (!def->defaultIOThread)
        return;

    if (def->defaultIOThread->thread_pool_min >= 0) {
        virBufferAsprintf(&attrBuf, " thread_pool_min='%d'",
                          def->defaultIOThread->thread_pool_min);
    }

    if (def->defaultIOThread->thread_pool_max >= 0) {
        virBufferAsprintf(&attrBuf, " thread_pool_max='%d'",
                          def->defaultIOThread->thread_pool_max);
    }

    virXMLFormatElement(buf, "defaultiothread", &attrBuf, NULL);
}


static void
virDomainDefIOThreadsFormat(virBuffer *buf,
                            const virDomainDef *def)
{
    if (def->niothreadids > 0) {
        virBufferAsprintf(buf, "<iothreads>%zu</iothreads>\n",
                          def->niothreadids);
    }

    if (virDomainDefIothreadShouldFormat(def)) {
        g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
        size_t i;

        for (i = 0; i < def->niothreadids; i++) {
            virDomainIOThreadIDDef *iothread = def->iothreadids[i];
            g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
            g_auto(virBuffer) iothreadChildBuf = VIR_BUFFER_INIT_CHILD(&childrenBuf);
            g_auto(virBuffer) pollAttrBuf = VIR_BUFFER_INITIALIZER;

            virBufferAsprintf(&attrBuf, " id='%u'",
                              iothread->iothread_id);

            if (iothread->thread_pool_min >= 0) {
                virBufferAsprintf(&attrBuf, " thread_pool_min='%d'",
                                  iothread->thread_pool_min);
            }

            if (iothread->thread_pool_max >= 0) {
                virBufferAsprintf(&attrBuf, " thread_pool_max='%d'",
                                  iothread->thread_pool_max);
            }

            if (iothread->set_poll_max_ns)
                virBufferAsprintf(&pollAttrBuf, " max='%llu'", iothread->poll_max_ns);

            if (iothread->set_poll_grow)
                virBufferAsprintf(&pollAttrBuf, " grow='%llu'", iothread->poll_grow);

            if (iothread->set_poll_shrink)
                virBufferAsprintf(&pollAttrBuf, " shrink='%llu'", iothread->poll_shrink);

            virXMLFormatElement(&iothreadChildBuf, "poll", &pollAttrBuf, NULL);

            virXMLFormatElement(&childrenBuf, "iothread", &attrBuf, &iothreadChildBuf);
        }

        virXMLFormatElement(buf, "iothreadids", NULL, &childrenBuf);
    }

    virDomainDefaultIOThreadDefFormat(buf, def);
}


static void
virDomainIOMMUDefFormat(virBuffer *buf,
                        const virDomainIOMMUDef *iommu)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;

    if (iommu->intremap != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&driverAttrBuf, " intremap='%s'",
                          virTristateSwitchTypeToString(iommu->intremap));
    }
    if (iommu->caching_mode != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&driverAttrBuf, " caching_mode='%s'",
                          virTristateSwitchTypeToString(iommu->caching_mode));
    }
    if (iommu->eim != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&driverAttrBuf, " eim='%s'",
                          virTristateSwitchTypeToString(iommu->eim));
    }
    if (iommu->iotlb != VIR_TRISTATE_SWITCH_ABSENT) {
        virBufferAsprintf(&driverAttrBuf, " iotlb='%s'",
                          virTristateSwitchTypeToString(iommu->iotlb));
    }
    if (iommu->aw_bits > 0) {
        virBufferAsprintf(&driverAttrBuf, " aw_bits='%d'",
                          iommu->aw_bits);
    }

    virXMLFormatElement(&childBuf, "driver", &driverAttrBuf, NULL);

    virDomainDeviceInfoFormat(&childBuf, &iommu->info, 0);

    virBufferAsprintf(&attrBuf, " model='%s'",
                      virDomainIOMMUModelTypeToString(iommu->model));

    virXMLFormatElement(buf, "iommu", &attrBuf, &childBuf);
}


static void
virDomainMemtuneFormat(virBuffer *buf,
                       const virDomainMemtune *mem)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (virMemoryLimitIsSet(mem->hard_limit)) {
        virBufferAsprintf(&childBuf,
                          "<hard_limit unit='KiB'>%llu</hard_limit>\n",
                          mem->hard_limit);
    }
    if (virMemoryLimitIsSet(mem->soft_limit)) {
        virBufferAsprintf(&childBuf,
                          "<soft_limit unit='KiB'>%llu</soft_limit>\n",
                          mem->soft_limit);
    }
    if (mem->min_guarantee) {
        virBufferAsprintf(&childBuf,
                          "<min_guarantee unit='KiB'>%llu</min_guarantee>\n",
                          mem->min_guarantee);
    }
    if (virMemoryLimitIsSet(mem->swap_hard_limit)) {
        virBufferAsprintf(&childBuf,
                          "<swap_hard_limit unit='KiB'>%llu</swap_hard_limit>\n",
                          mem->swap_hard_limit);
    }

    virXMLFormatElement(buf, "memtune", NULL, &childBuf);
}


static void
virDomainMemorybackingFormat(virBuffer *buf,
                             const virDomainMemtune *mem)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) allocAttrBuf = VIR_BUFFER_INITIALIZER;

    if (mem->nhugepages)
        virDomainHugepagesFormat(&childBuf, mem->hugepages, mem->nhugepages);
    if (mem->nosharepages)
        virBufferAddLit(&childBuf, "<nosharepages/>\n");
    if (mem->locked)
        virBufferAddLit(&childBuf, "<locked/>\n");
    if (mem->source)
        virBufferAsprintf(&childBuf, "<source type='%s'/>\n",
                          virDomainMemorySourceTypeToString(mem->source));
    if (mem->access)
        virBufferAsprintf(&childBuf, "<access mode='%s'/>\n",
                          virDomainMemoryAccessTypeToString(mem->access));
    if (mem->allocation)
        virBufferAsprintf(&allocAttrBuf, " mode='%s'",
                          virDomainMemoryAllocationTypeToString(mem->allocation));
    if (mem->allocation_threads > 0)
        virBufferAsprintf(&allocAttrBuf, " threads='%u'", mem->allocation_threads);

    virXMLFormatElement(&childBuf, "allocation", &allocAttrBuf, NULL);

    if (mem->discard)
        virBufferAddLit(&childBuf, "<discard/>\n");

    virXMLFormatElement(buf, "memoryBacking", NULL, &childBuf);
}


static void
virDomainVsockDefFormat(virBuffer *buf,
                        virDomainVsockDef *vsock)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) cidAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) drvAttrBuf = VIR_BUFFER_INITIALIZER;

    if (vsock->model) {
        virBufferAsprintf(&attrBuf, " model='%s'",
                          virDomainVsockModelTypeToString(vsock->model));
    }

    if (vsock->auto_cid != VIR_TRISTATE_BOOL_ABSENT) {
        virBufferAsprintf(&cidAttrBuf, " auto='%s'",
                          virTristateBoolTypeToString(vsock->auto_cid));
    }
    if (vsock->guest_cid != 0)
        virBufferAsprintf(&cidAttrBuf, " address='%u'", vsock->guest_cid);
    virXMLFormatElement(&childBuf, "cid", &cidAttrBuf, NULL);

    virDomainDeviceInfoFormat(&childBuf, &vsock->info, 0);

    virDomainVirtioOptionsFormat(&drvAttrBuf, vsock->virtio);

    virXMLFormatElement(&childBuf, "driver", &drvAttrBuf, NULL);
    virXMLFormatElement(buf, "vsock", &attrBuf, &childBuf);
}


static void
virDomainDefFormatBlkiotune(virBuffer *buf,
                            virDomainDef *def)
{
    g_auto(virBuffer) childrenBuf = VIR_BUFFER_INIT_CHILD(buf);
    ssize_t n;

    if (def->blkio.weight)
        virBufferAsprintf(&childrenBuf, "<weight>%u</weight>\n",
                          def->blkio.weight);

    for (n = 0; n < def->blkio.ndevices; n++) {
        virBlkioDevice *dev = &def->blkio.devices[n];

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

    virXMLFormatElement(buf, "blkiotune", NULL, &childrenBuf);
}


static void
virDomainFeatureTCGFormat(virBuffer *buf,
                          const virDomainDef *def)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!def->tcg_features ||
        def->features[VIR_DOMAIN_FEATURE_TCG] != VIR_TRISTATE_SWITCH_ON)
        return;

    if (def->tcg_features->tb_cache > 0) {
        virBufferAsprintf(&childBuf,
                          "<tb-cache unit='KiB'>%lld</tb-cache>\n",
                          def->tcg_features->tb_cache);
    }

    virXMLFormatElement(buf, "tcg", NULL, &childBuf);
}


static int
virDomainDefFormatFeatures(virBuffer *buf,
                           virDomainDef *def)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        g_auto(virBuffer) tmpAttrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) tmpChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);
        const char *name = virDomainFeatureTypeToString(i);
        size_t j;

        switch ((virDomainFeature) i) {
        case VIR_DOMAIN_FEATURE_ACPI:
        case VIR_DOMAIN_FEATURE_PAE:
        case VIR_DOMAIN_FEATURE_VIRIDIAN:
        case VIR_DOMAIN_FEATURE_PRIVNET:
            /* NOTE: This is for old style <opt/> booleans. New XML
             * should use the explicit state=on|off output below */
            switch ((virTristateSwitch) def->features[i]) {
            case VIR_TRISTATE_SWITCH_ABSENT:
                break;

            case VIR_TRISTATE_SWITCH_ON:
               virBufferAsprintf(&childBuf, "<%s/>\n", name);
               break;

            case VIR_TRISTATE_SWITCH_LAST:
            case VIR_TRISTATE_SWITCH_OFF:
               virReportError(VIR_ERR_INTERNAL_ERROR,
                             _("Unexpected state of feature '%1$s'"), name);
               return -1;
               break;
            }

            break;

        case VIR_DOMAIN_FEATURE_VMCOREINFO:
        case VIR_DOMAIN_FEATURE_HAP:
        case VIR_DOMAIN_FEATURE_PMU:
        case VIR_DOMAIN_FEATURE_PVSPINLOCK:
        case VIR_DOMAIN_FEATURE_VMPORT:
        case VIR_DOMAIN_FEATURE_HTM:
        case VIR_DOMAIN_FEATURE_NESTED_HV:
        case VIR_DOMAIN_FEATURE_CCF_ASSIST:
            switch ((virTristateSwitch) def->features[i]) {
            case VIR_TRISTATE_SWITCH_LAST:
            case VIR_TRISTATE_SWITCH_ABSENT:
                break;

            case VIR_TRISTATE_SWITCH_ON:
            case VIR_TRISTATE_SWITCH_OFF:
                virBufferAsprintf(&tmpAttrBuf, " state='%s'",
                                  virTristateSwitchTypeToString(def->features[i]));

                virXMLFormatElement(&childBuf, name, &tmpAttrBuf, NULL);
                break;
            }

            break;

        case VIR_DOMAIN_FEATURE_SMM:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ABSENT)
                break;

            virBufferAsprintf(&tmpAttrBuf, " state='%s'",
                              virTristateSwitchTypeToString(def->features[i]));

            if (def->features[i] == VIR_TRISTATE_SWITCH_ON &&
                def->tseg_specified) {
                const char *unit;
                unsigned long long short_size = virFormatIntPretty(def->tseg_size,
                                                                   &unit);

                virBufferAsprintf(&tmpChildBuf, "<tseg unit='%s'>%llu</tseg>\n",
                                  unit, short_size);
            }

            virXMLFormatElement(&childBuf, "smm", &tmpAttrBuf, &tmpChildBuf);

            break;

        case VIR_DOMAIN_FEATURE_APIC:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                if (def->apic_eoi) {
                    virBufferAsprintf(&tmpAttrBuf, " eoi='%s'",
                                      virTristateSwitchTypeToString(def->apic_eoi));
                }

                virXMLFormatElementEmpty(&childBuf, "apic", &tmpAttrBuf, NULL);
            }
            break;

        case VIR_DOMAIN_FEATURE_HYPERV:
            if (def->features[i] == VIR_DOMAIN_HYPERV_MODE_NONE)
                break;

            virBufferAsprintf(&childBuf, "<hyperv mode='%s'>\n",
                              virDomainHyperVModeTypeToString(def->features[i]));
            virBufferAdjustIndent(&childBuf, 2);
            for (j = 0; j < VIR_DOMAIN_HYPERV_LAST; j++) {
                if (def->hyperv_features[j] == VIR_TRISTATE_SWITCH_ABSENT)
                    continue;

                virBufferAsprintf(&childBuf, "<%s state='%s'",
                                  virDomainHypervTypeToString(j),
                                  virTristateSwitchTypeToString(def->hyperv_features[j]));

                switch ((virDomainHyperv) j) {
                case VIR_DOMAIN_HYPERV_RELAXED:
                case VIR_DOMAIN_HYPERV_VAPIC:
                case VIR_DOMAIN_HYPERV_VPINDEX:
                case VIR_DOMAIN_HYPERV_RUNTIME:
                case VIR_DOMAIN_HYPERV_SYNIC:
                case VIR_DOMAIN_HYPERV_RESET:
                case VIR_DOMAIN_HYPERV_FREQUENCIES:
                case VIR_DOMAIN_HYPERV_REENLIGHTENMENT:
                case VIR_DOMAIN_HYPERV_TLBFLUSH:
                case VIR_DOMAIN_HYPERV_IPI:
                case VIR_DOMAIN_HYPERV_EVMCS:
                case VIR_DOMAIN_HYPERV_AVIC:
                    virBufferAddLit(&childBuf, "/>\n");
                    break;

                case VIR_DOMAIN_HYPERV_SPINLOCKS:
                    if (def->hyperv_features[j] != VIR_TRISTATE_SWITCH_ON) {
                        virBufferAddLit(&childBuf, "/>\n");
                        break;
                    }
                    virBufferAsprintf(&childBuf, " retries='%d'/>\n",
                                      def->hyperv_spinlocks);
                    break;

                case VIR_DOMAIN_HYPERV_STIMER:
                    if (def->hyperv_features[j] != VIR_TRISTATE_SWITCH_ON) {
                        virBufferAddLit(&childBuf, "/>\n");
                        break;
                    }
                    if (def->hyperv_stimer_direct == VIR_TRISTATE_SWITCH_ON) {
                        virBufferAddLit(&childBuf, ">\n");
                        virBufferAdjustIndent(&childBuf, 2);
                        virBufferAddLit(&childBuf, "<direct state='on'/>\n");
                        virBufferAdjustIndent(&childBuf, -2);
                        virBufferAddLit(&childBuf, "</stimer>\n");
                    } else {
                        virBufferAddLit(&childBuf, "/>\n");
                    }

                    break;

                case VIR_DOMAIN_HYPERV_VENDOR_ID:
                    if (def->hyperv_features[j] != VIR_TRISTATE_SWITCH_ON) {
                        virBufferAddLit(&childBuf, "/>\n");
                        break;
                    }
                    virBufferEscapeString(&childBuf, " value='%s'/>\n",
                                          def->hyperv_vendor_id);
                    break;

                case VIR_DOMAIN_HYPERV_LAST:
                    break;
                }
            }
            virBufferAdjustIndent(&childBuf, -2);
            virBufferAddLit(&childBuf, "</hyperv>\n");
            break;

        case VIR_DOMAIN_FEATURE_KVM:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                break;

            virBufferAddLit(&childBuf, "<kvm>\n");
            virBufferAdjustIndent(&childBuf, 2);
            for (j = 0; j < VIR_DOMAIN_KVM_LAST; j++) {
                switch ((virDomainKVM) j) {
                case VIR_DOMAIN_KVM_HIDDEN:
                case VIR_DOMAIN_KVM_DEDICATED:
                case VIR_DOMAIN_KVM_POLLCONTROL:
                case VIR_DOMAIN_KVM_PVIPI:
                    if (def->kvm_features->features[j])
                        virBufferAsprintf(&childBuf, "<%s state='%s'/>\n",
                                          virDomainKVMTypeToString(j),
                                          virTristateSwitchTypeToString(
                                              def->kvm_features->features[j]));
                    break;

                case VIR_DOMAIN_KVM_DIRTY_RING:
                    if (def->kvm_features->features[j] != VIR_TRISTATE_SWITCH_ABSENT) {
                        virBufferAsprintf(&childBuf, "<%s state='%s'",
                                          virDomainKVMTypeToString(j),
                                          virTristateSwitchTypeToString(def->kvm_features->features[j]));
                        if (def->kvm_features->dirty_ring_size > 0) {
                            virBufferAsprintf(&childBuf, " size='%d'/>\n",
                                              def->kvm_features->dirty_ring_size);
                        } else {
                            virBufferAddLit(&childBuf, "/>\n");
                        }
                    }
                    break;

                case VIR_DOMAIN_KVM_LAST:
                    break;
                }
            }
            virBufferAdjustIndent(&childBuf, -2);
            virBufferAddLit(&childBuf, "</kvm>\n");
            break;

        case VIR_DOMAIN_FEATURE_XEN:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                break;

            virBufferAddLit(&childBuf, "<xen>\n");
            virBufferAdjustIndent(&childBuf, 2);
            for (j = 0; j < VIR_DOMAIN_XEN_LAST; j++) {
                if (def->xen_features[j] == VIR_TRISTATE_SWITCH_ABSENT)
                    continue;

                virBufferAsprintf(&childBuf, "<%s state='%s'",
                                      virDomainXenTypeToString(j),
                                      virTristateSwitchTypeToString(
                                          def->xen_features[j]));

                switch ((virDomainXen) j) {
                case VIR_DOMAIN_XEN_E820_HOST:
                    virBufferAddLit(&childBuf, "/>\n");
                    break;
                case VIR_DOMAIN_XEN_PASSTHROUGH:
                    if (def->xen_features[j] != VIR_TRISTATE_SWITCH_ON) {
                        virBufferAddLit(&childBuf, "/>\n");
                        break;
                    }
                    if (def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SYNC_PT ||
                        def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SHARE_PT) {
                        virBufferEscapeString(&childBuf, " mode='%s'/>\n",
                                              virDomainXenPassthroughModeTypeToString(def->xen_passthrough_mode));
                    } else {
                        virBufferAddLit(&childBuf, "/>\n");
                    }
                    break;

                case VIR_DOMAIN_XEN_LAST:
                    break;
                }
            }
            virBufferAdjustIndent(&childBuf, -2);
            virBufferAddLit(&childBuf, "</xen>\n");
            break;

        case VIR_DOMAIN_FEATURE_CAPABILITIES:
            for (j = 0; j < VIR_DOMAIN_PROCES_CAPS_FEATURE_LAST; j++) {
                if (def->caps_features[j] != VIR_TRISTATE_SWITCH_ABSENT)
                    virBufferAsprintf(&tmpChildBuf, "<%s state='%s'/>\n",
                                      virDomainProcessCapsFeatureTypeToString(j),
                                      virTristateSwitchTypeToString(def->caps_features[j]));
            }

            /* the 'default' policy should be printed if any capability is present */
            if (def->features[i] != VIR_DOMAIN_CAPABILITIES_POLICY_DEFAULT ||
                virBufferUse(&tmpChildBuf))
                virBufferAsprintf(&tmpAttrBuf, " policy='%s'",
                                  virDomainCapabilitiesPolicyTypeToString(def->features[i]));

            virXMLFormatElement(&childBuf, "capabilities", &tmpAttrBuf, &tmpChildBuf);
            break;

        case VIR_DOMAIN_FEATURE_GIC:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                if (def->gic_version != VIR_GIC_VERSION_NONE)
                    virBufferAsprintf(&tmpAttrBuf, " version='%s'",
                                      virGICVersionTypeToString(def->gic_version));

                virXMLFormatElementEmpty(&childBuf, "gic", &tmpAttrBuf, NULL);
            }
            break;

        case VIR_DOMAIN_FEATURE_IOAPIC:
            if (def->features[i] == VIR_DOMAIN_IOAPIC_NONE)
                break;

            virBufferAsprintf(&childBuf, "<ioapic driver='%s'/>\n",
                              virDomainIOAPICTypeToString(def->features[i]));
            break;

        case VIR_DOMAIN_FEATURE_HPT:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                break;

            if (def->hpt_resizing != VIR_DOMAIN_HPT_RESIZING_NONE) {
                virBufferAsprintf(&tmpAttrBuf,
                                  " resizing='%s'",
                                  virDomainHPTResizingTypeToString(def->hpt_resizing));
            }
            if (def->hpt_maxpagesize > 0) {
                virBufferAsprintf(&tmpChildBuf,
                                  "<maxpagesize unit='KiB'>%llu</maxpagesize>\n",
                                  def->hpt_maxpagesize);
            }

            virXMLFormatElement(&childBuf, "hpt", &tmpAttrBuf, &tmpChildBuf);
            break;

        case VIR_DOMAIN_FEATURE_MSRS:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ON)
                break;

            virBufferAsprintf(&childBuf, "<msrs unknown='%s'/>\n",
                              virDomainMsrsUnknownTypeToString(def->msrs_features[VIR_DOMAIN_MSRS_UNKNOWN]));
            break;

        case VIR_DOMAIN_FEATURE_CFPC:
            if (def->features[i] == VIR_DOMAIN_CFPC_NONE)
                break;

            virBufferAsprintf(&childBuf, "<cfpc value='%s'/>\n",
                              virDomainCFPCTypeToString(def->features[i]));
            break;

        case VIR_DOMAIN_FEATURE_SBBC:
            if (def->features[i] == VIR_DOMAIN_SBBC_NONE)
                break;

            virBufferAsprintf(&childBuf, "<sbbc value='%s'/>\n",
                              virDomainSBBCTypeToString(def->features[i]));
            break;

        case VIR_DOMAIN_FEATURE_IBS:
            if (def->features[i] == VIR_DOMAIN_IBS_NONE)
                break;

            virBufferAsprintf(&childBuf, "<ibs value='%s'/>\n",
                              virDomainIBSTypeToString(def->features[i]));
            break;

        case VIR_DOMAIN_FEATURE_TCG:
            virDomainFeatureTCGFormat(&childBuf, def);
            break;

        case VIR_DOMAIN_FEATURE_ASYNC_TEARDOWN:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT)
                virBufferAsprintf(&childBuf, "<async-teardown enabled='%s'/>\n",
                                  virTristateBoolTypeToString(def->features[i]));
            break;

        case VIR_DOMAIN_FEATURE_LAST:
            break;
        }
    }

    virXMLFormatElement(buf, "features", NULL, &childBuf);
    return 0;
}

int
virDomainDefFormatInternal(virDomainDef *def,
                           virDomainXMLOption *xmlopt,
                           virBuffer *buf,
                           unsigned int flags)
{
    return virDomainDefFormatInternalSetRootName(def, xmlopt, buf,
                                                 "domain", flags);
}


/* This internal version appends to an existing buffer
 * (possibly with auto-indent), rather than flattening
 * to string.
 * Return -1 on failure.  */
int
virDomainDefFormatInternalSetRootName(virDomainDef *def,
                                      virDomainXMLOption *xmlopt,
                                      virBuffer *buf,
                                      const char *rootname,
                                      unsigned int flags)
{
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *type = NULL;
    int n;
    size_t i;
    bool migratable = !!(flags & VIR_DOMAIN_DEF_FORMAT_MIGRATABLE);

    virCheckFlags(VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS |
                  VIR_DOMAIN_DEF_FORMAT_STATUS |
                  VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                  VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                  VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST |
                  VIR_DOMAIN_DEF_FORMAT_VOLUME_TRANSLATED,
                  -1);

    if (!(type = virDomainVirtTypeToString(def->virtType))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain type %1$d"), def->virtType);
        return -1;
    }

    if (def->id == -1)
        flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    virBufferAsprintf(buf, "<%s type='%s'", rootname, type);
    if (!(flags & VIR_DOMAIN_DEF_FORMAT_INACTIVE))
        virBufferAsprintf(buf, " id='%d'", def->id);
    if (def->namespaceData && def->ns.format)
        virXMLNamespaceFormatNS(buf, &def->ns);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);

    if (def->genidRequested) {
        char genidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(def->genid, genidstr);
        virBufferAsprintf(buf, "<genid>%s</genid>\n", genidstr);
    }

    virBufferEscapeString(buf, "<title>%s</title>\n", def->title);

    virBufferEscapeString(buf, "<description>%s</description>\n",
                          def->description);

    if (virXMLFormatMetadata(buf, def->metadata) < 0)
        return -1;

    if (virDomainDefHasMemoryHotplug(def)) {
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) contentBuf = VIR_BUFFER_INITIALIZER;

        if (def->mem.memory_slots > 0)
            virBufferAsprintf(&attrBuf, " slots='%u'", def->mem.memory_slots);

        virBufferAddLit(&attrBuf, " unit='KiB'");
        virBufferAsprintf(&contentBuf, "%llu", def->mem.max_memory);

        virXMLFormatElementInternal(buf, "maxMemory", &attrBuf, &contentBuf, false, false);
    }

    virBufferAddLit(buf, "<memory");
    if (def->mem.dump_core)
        virBufferAsprintf(buf, " dumpCore='%s'",
                          virTristateSwitchTypeToString(def->mem.dump_core));
    virBufferAsprintf(buf, " unit='KiB'>%llu</memory>\n",
                      virDomainDefGetMemoryTotal(def));

    virBufferAsprintf(buf, "<currentMemory unit='KiB'>%llu</currentMemory>\n",
                      def->mem.cur_balloon);

    virDomainDefFormatBlkiotune(buf, def);

    virDomainMemtuneFormat(buf, &def->mem);
    virDomainMemorybackingFormat(buf, &def->mem);

    if (virDomainCpuDefFormat(buf, def) < 0)
        return -1;

    virDomainDefIOThreadsFormat(buf, def);

    if (virDomainCputuneDefFormat(buf, def, flags) < 0)
        return -1;

    if (virDomainNumatuneFormatXML(buf, def->numa) < 0)
        return -1;

    virDomainResourceDefFormat(buf, def->resource);

    for (i = 0; i < def->nsysinfo; i++) {
        if (virSysinfoFormat(buf, def->sysinfo[i]) < 0)
            return -1;
    }

    if (def->os.bootloader) {
        virBufferEscapeString(buf, "<bootloader>%s</bootloader>\n",
                              def->os.bootloader);
        virBufferEscapeString(buf,
                              "<bootloader_args>%s</bootloader_args>\n",
                              def->os.bootloaderArgs);
    }

    virBufferAddLit(buf, "<os");
    if (def->os.firmware && !migratable)
        virBufferAsprintf(buf, " firmware='%s'",
                          virDomainOsDefFirmwareTypeToString(def->os.firmware));
    virBufferAddLit(buf, ">\n");
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

    if (def->os.firmwareFeatures && !migratable) {
        virBufferAddLit(buf, "<firmware>\n");
        virBufferAdjustIndent(buf, 2);

        for (i = 0; i < VIR_DOMAIN_OS_DEF_FIRMWARE_FEATURE_LAST; i++) {
            if (def->os.firmwareFeatures[i] == VIR_TRISTATE_BOOL_ABSENT)
                continue;

            virBufferAsprintf(buf, "<feature enabled='%s' name='%s'/>\n",
                              virTristateBoolTypeToString(def->os.firmwareFeatures[i]),
                              virDomainOsDefFirmwareFeatureTypeToString(i));
        }

        virBufferAdjustIndent(buf, -2);

        virBufferAddLit(buf, "</firmware>\n");
    }

    virBufferEscapeString(buf, "<init>%s</init>\n",
                          def->os.init);
    for (i = 0; def->os.initargv && def->os.initargv[i]; i++)
        virBufferEscapeString(buf, "<initarg>%s</initarg>\n",
                              def->os.initargv[i]);
    for (i = 0; def->os.initenv && def->os.initenv[i]; i++)
        virBufferAsprintf(buf, "<initenv name='%s'>%s</initenv>\n",
                          def->os.initenv[i]->name, def->os.initenv[i]->value);
    if (def->os.initdir)
        virBufferEscapeString(buf, "<initdir>%s</initdir>\n",
                              def->os.initdir);
    if (def->os.inituser)
        virBufferAsprintf(buf, "<inituser>%s</inituser>\n", def->os.inituser);
    if (def->os.initgroup)
        virBufferAsprintf(buf, "<initgroup>%s</initgroup>\n", def->os.initgroup);

    if (def->os.loader &&
        virDomainLoaderDefFormat(buf, def->os.loader, xmlopt, flags) < 0)
        return -1;
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
                               _("unexpected boot device type %1$d"),
                               def->os.bootDevs[n]);
                return -1;
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
                           _("unexpected smbios mode %1$d"), def->os.smbios_mode);
            return -1;
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

    if (virDomainDefFormatFeatures(buf, def) < 0)
        return -1;

    if (virCPUDefFormatBufFull(buf, def->cpu, def->numa) < 0)
        return -1;

    virDomainClockDefFormat(buf, &def->clock, flags);

    if (virDomainEventActionDefFormat(buf, def->onPoweroff,
                                      "on_poweroff",
                                      virDomainLifecycleActionTypeToString) < 0)
        return -1;
    if (virDomainEventActionDefFormat(buf, def->onReboot,
                                      "on_reboot",
                                      virDomainLifecycleActionTypeToString) < 0)
        return -1;
    if (virDomainEventActionDefFormat(buf, def->onCrash,
                                      "on_crash",
                                      virDomainLifecycleActionTypeToString) < 0)
        return -1;
    if (def->onLockFailure != VIR_DOMAIN_LOCK_FAILURE_DEFAULT &&
        virDomainEventActionDefFormat(buf, def->onLockFailure,
                                      "on_lockfailure",
                                      virDomainLockFailureTypeToString) < 0)
        return -1;

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
        if (virDomainDiskDefFormat(buf, def->disks[n], flags, xmlopt) < 0)
            return -1;

    for (n = 0; n < def->ncontrollers; n++)
        if (virDomainControllerDefFormat(buf, def->controllers[n], flags) < 0)
            return -1;

    for (n = 0; n < def->nleases; n++)
        virDomainLeaseDefFormat(buf, def->leases[n]);

    for (n = 0; n < def->nfss; n++)
        if (virDomainFSDefFormat(buf, def->fss[n], flags) < 0)
            return -1;

    for (n = 0; n < def->nnets; n++)
        if (virDomainNetDefFormat(buf, def->nets[n], xmlopt, flags) < 0)
            return -1;

    for (n = 0; n < def->nsmartcards; n++)
        if (virDomainSmartcardDefFormat(buf, def->smartcards[n], flags) < 0)
            return -1;

    for (n = 0; n < def->nserials; n++)
        if (virDomainChrDefFormat(buf, def->serials[n], flags) < 0)
            return -1;

    for (n = 0; n < def->nparallels; n++)
        if (virDomainChrDefFormat(buf, def->parallels[n], flags) < 0)
            return -1;

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
            return -1;
    }

    for (n = 0; n < def->nchannels; n++)
        if (virDomainChrDefFormat(buf, def->channels[n], flags) < 0)
            return -1;

    for (n = 0; n < def->ninputs; n++) {
        if (virDomainInputDefFormat(buf, def->inputs[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->ntpms; n++) {
        if (virDomainTPMDefFormat(buf, def->tpms[n], flags, xmlopt) < 0)
            return -1;
    }

    for (n = 0; n < def->ngraphics; n++) {
        if (virDomainGraphicsDefFormat(buf, def->graphics[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->nsounds; n++) {
        if (virDomainSoundDefFormat(buf, def->sounds[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->naudios; n++) {
        if (virDomainAudioDefFormat(buf, def->audios[n]) < 0)
            return -1;
    }

    for (n = 0; n < def->nvideos; n++) {
        if (virDomainVideoDefFormat(buf, def->videos[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->nhostdevs; n++) {
        /* If parentnet != NONE, this is just a pointer to the
         * hostdev in a higher-level device (e.g. virDomainNetDef),
         * and will have already been formatted there.
         */
        if (!def->hostdevs[n]->parentnet &&
            virDomainHostdevDefFormat(buf, def->hostdevs[n], flags, xmlopt) < 0) {
            return -1;
        }
    }

    for (n = 0; n < def->nredirdevs; n++) {
        if (virDomainRedirdevDefFormat(buf, def->redirdevs[n], flags) < 0)
            return -1;
    }

    if (def->redirfilter)
        virDomainRedirFilterDefFormat(buf, def->redirfilter);

    for (n = 0; n < def->nhubs; n++) {
        if (virDomainHubDefFormat(buf, def->hubs[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->nwatchdogs; n++)
        virDomainWatchdogDefFormat(buf, def->watchdogs[n], flags);

    if (def->memballoon)
        virDomainMemballoonDefFormat(buf, def->memballoon, flags);

    for (n = 0; n < def->nrngs; n++) {
        if (virDomainRNGDefFormat(buf, def->rngs[n], flags))
            return -1;
    }

    if (def->nvram)
        virDomainNVRAMDefFormat(buf, def->nvram, flags);

    for (n = 0; n < def->npanics; n++)
        virDomainPanicDefFormat(buf, def->panics[n]);

    for (n = 0; n < def->nshmems; n++)
        virDomainShmemDefFormat(buf, def->shmems[n], flags);

    for (n = 0; n < def->nmems; n++) {
        if (virDomainMemoryDefFormat(buf, def->mems[n], flags) < 0)
            return -1;
    }

    for (n = 0; n < def->ncryptos; n++) {
        virDomainCryptoDefFormat(buf, def->cryptos[n], flags);
    }
    if (def->iommu)
        virDomainIOMMUDefFormat(buf, def->iommu);

    if (def->vsock)
        virDomainVsockDefFormat(buf, def->vsock);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</devices>\n");

    for (n = 0; n < def->nseclabels; n++)
        virSecurityLabelDefFormat(buf, def->seclabels[n], flags);

    if (def->keywrap)
        virDomainKeyWrapDefFormat(buf, def->keywrap);

    virDomainSecDefFormat(buf, def->sec);

    if (def->namespaceData && def->ns.format) {
        if ((def->ns.format)(buf, def->namespaceData) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAsprintf(buf, "</%s>\n", rootname);

    return 0;
}


/* Converts VIR_DOMAIN_XML_COMMON_FLAGS into VIR_DOMAIN_DEF_FORMAT_*
 * flags, and silently ignores any other flags.  Note that the caller
 * should validate the set of flags it is willing to accept; see also
 * the comment on VIR_DOMAIN_XML_COMMON_FLAGS about security
 * considerations with adding new flags. */
unsigned int virDomainDefFormatConvertXMLFlags(unsigned int flags)
{
    unsigned int formatFlags = 0;

    if (flags & VIR_DOMAIN_XML_SECURE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_SECURE;
    if (flags & VIR_DOMAIN_XML_INACTIVE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;
    if (flags & VIR_DOMAIN_XML_MIGRATABLE)
        formatFlags |= VIR_DOMAIN_DEF_FORMAT_MIGRATABLE;

    return formatFlags;
}


char *
virDomainDefFormat(virDomainDef *def,
                   virDomainXMLOption *xmlopt,
                   unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_DEF_FORMAT_COMMON_FLAGS, NULL);
    if (virDomainDefFormatInternal(def, xmlopt, &buf, flags) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *
virDomainObjFormat(virDomainObj *obj,
                   virDomainXMLOption *xmlopt,
                   unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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

    for (i = 0; i < obj->ndeprecations; i++) {
        virBufferEscapeString(&buf, "<deprecation>%s</deprecation>\n",
                              obj->deprecations[i]);
    }

    if (xmlopt->privateData.format &&
        xmlopt->privateData.format(&buf, obj) < 0)
        return NULL;

    if (virDomainDefFormatInternal(obj->def, xmlopt, &buf, flags) < 0)
        return NULL;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domstatus>\n");

    return virBufferContentAndReset(&buf);
}

static bool
virDomainDeviceIsUSB(virDomainDeviceDef *dev)
{
    int t = dev->type;
    if ((t == VIR_DOMAIN_DEVICE_DISK &&
         dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_USB) ||
        (t == VIR_DOMAIN_DEVICE_INPUT &&
         dev->data.input->bus == VIR_DOMAIN_INPUT_BUS_USB) ||
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


typedef struct _virDomainCompatibleDeviceData virDomainCompatibleDeviceData;
struct _virDomainCompatibleDeviceData {
    virDomainDeviceInfo *newInfo;
    virDomainDeviceInfo *oldInfo;
};

static int
virDomainDeviceInfoCheckBootIndex(virDomainDef *def G_GNUC_UNUSED,
                                  virDomainDeviceDef *device G_GNUC_UNUSED,
                                  virDomainDeviceInfo *info,
                                  void *opaque)
{
    virDomainCompatibleDeviceData *data = opaque;

    /* Ignore the device we're about to update */
    if (data->oldInfo == info)
        return 0;

    if (info->bootIndex == data->newInfo->bootIndex) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("boot order %1$u is already used by another device"),
                       data->newInfo->bootIndex);
        return -1;
    }
    return 0;
}

int
virDomainDefCompatibleDevice(virDomainDef *def,
                             virDomainDeviceDef *dev,
                             virDomainDeviceDef *oldDev,
                             virDomainDeviceAction action,
                             bool live)
{
    virDomainCompatibleDeviceData data = {
        .newInfo = virDomainDeviceGetInfo(dev),
        .oldInfo = NULL,
    };

    if (oldDev)
        data.oldInfo = virDomainDeviceGetInfo(oldDev);

    if (action == VIR_DOMAIN_DEVICE_ACTION_UPDATE &&
        live && data.newInfo && data.oldInfo) {

        if (data.newInfo->alias && data.oldInfo->alias &&
            STRNEQ(data.newInfo->alias, data.oldInfo->alias)) {
            virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                           _("changing device alias is not allowed"));
            return -1;
        }

        if (data.newInfo->acpiIndex != data.oldInfo->acpiIndex) {
            virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                           _("changing device 'acpi index' is not allowed"));
            return -1;
        }
    }

    if (!virDomainDefHasUSB(def) &&
        def->os.type != VIR_DOMAIN_OSTYPE_EXE &&
        virDomainDeviceIsUSB(dev)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Device configuration is not compatible: Domain has no USB bus support"));
        return -1;
    }

    if (data.newInfo && data.newInfo->bootIndex > 0) {
        if (def->os.nBootDevs > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("per-device boot elements cannot be used together with os/boot elements"));
            return -1;
        }
        if (virDomainDeviceInfoIterate(def,
                                       virDomainDeviceInfoCheckBootIndex,
                                       &data) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_MEMORY) {
        unsigned long long sz = dev->data.memory->size;

        if (!virDomainDefHasMemoryHotplug(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use/hotplug a memory device when domain 'maxMemory' is not defined"));
            return -1;
        }

        if (action == VIR_DOMAIN_DEVICE_ACTION_ATTACH &&
            (virDomainDefGetMemoryTotal(def) + sz) > def->mem.max_memory) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Attaching memory device with size '%1$llu' would exceed domain's maxMemory config size '%2$llu'"),
                           sz, def->mem.max_memory);
            return -1;
        }
    }

    return 0;
}

static int
virDomainDefSaveXML(virDomainDef *def,
                    const char *configDir,
                    const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *configFile = NULL;

    if (!configDir)
        return 0;

    if ((configFile = virDomainConfigFile(configDir, def->name)) == NULL)
        return -1;

    if (g_mkdir_with_parents(configDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("cannot create config directory '%1$s'"),
                             configDir);
        return -1;
    }

    virUUIDFormat(def->uuid, uuidstr);
    return virXMLSaveFile(configFile,
                           virXMLPickShellSafeComment(def->name, uuidstr), "edit",
                           xml);
}

int
virDomainDefSave(virDomainDef *def,
                 virDomainXMLOption *xmlopt,
                 const char *configDir)
{
    g_autofree char *xml = NULL;

    if (!(xml = virDomainDefFormat(def, xmlopt, VIR_DOMAIN_DEF_FORMAT_SECURE)))
        return -1;

    return virDomainDefSaveXML(def, configDir, xml);
}

int
virDomainObjSave(virDomainObj *obj,
                 virDomainXMLOption *xmlopt,
                 const char *statusDir)
{
    unsigned int flags = (VIR_DOMAIN_DEF_FORMAT_SECURE |
                          VIR_DOMAIN_DEF_FORMAT_STATUS |
                          VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                          VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                          VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST |
                          VIR_DOMAIN_DEF_FORMAT_VOLUME_TRANSLATED);

    g_autofree char *xml = NULL;

    if (!(xml = virDomainObjFormat(obj, xmlopt, flags)))
        return -1;

    return virDomainDefSaveXML(obj->def, statusDir, xml);
}


int
virDomainDeleteConfig(const char *configDir,
                      const char *autostartDir,
                      virDomainObj *dom)
{
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;

    if ((configFile = virDomainConfigFile(configDir, dom->def->name)) == NULL)
        return -1;
    if ((autostartLink = virDomainConfigFile(autostartDir,
                                             dom->def->name)) == NULL)
        return -1;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);
    dom->autostart = 0;

    if (unlink(configFile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("cannot remove config %1$s"),
                             configFile);
        return -1;
    }

    return 0;
}

char
*virDomainConfigFile(const char *dir,
                     const char *name)
{
    return g_strdup_printf("%s/%s.xml", dir, name);
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
virDiskNameToBusDeviceIndex(virDomainDiskDef *disk,
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
        case VIR_DOMAIN_DISK_BUS_NONE:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_LAST:
        default:
            *busIdx = 0;
            *devIdx = idx;
            break;
    }

    return 0;
}

int
virDomainFSInsert(virDomainDef *def, virDomainFSDef *fs)
{
    VIR_APPEND_ELEMENT(def->fss, def->nfss, fs);

    return 0;
}

virDomainFSDef *
virDomainFSRemove(virDomainDef *def, size_t i)
{
    virDomainFSDef *fs = def->fss[i];

    VIR_DELETE_ELEMENT(def->fss, i, def->nfss);
    return fs;
}

ssize_t
virDomainFSDefFind(virDomainDef *def,
                   virDomainFSDef *fs)
{
    size_t i = 0;

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *tmp = def->fss[i];

        if (fs->dst && STRNEQ_NULLABLE(fs->dst, tmp->dst))
            continue;

        if (fs->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            !virDomainDeviceInfoAddressIsEqual(&fs->info, &tmp->info))
            continue;

        if (fs->info.alias && STRNEQ_NULLABLE(fs->info.alias, tmp->info.alias))
            continue;

        return i;
    }
    return -1;
}

virDomainFSDef *
virDomainGetFilesystemForTarget(virDomainDef *def,
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
virDomainChrDefForeach(virDomainDef *def,
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
            return rc;
    }

    for (i = 0; i < def->nparallels; i++) {
        if ((iter)(def,
                   def->parallels[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            return rc;
    }

    for (i = 0; i < def->nchannels; i++) {
        if ((iter)(def,
                   def->channels[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            return rc;
    }
    for (i = 0; i < def->nconsoles; i++) {
        if (virDomainSkipBackcompatConsole(def, i, false))
            continue;
        if ((iter)(def,
                   def->consoles[i],
                   opaque) < 0)
            rc = -1;

        if (abortOnError && rc != 0)
            return rc;
    }

    return rc;
}


int
virDomainSmartcardDefForeach(virDomainDef *def,
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
            return rc;
    }

    return rc;
}


int
virDomainUSBDeviceDefForeach(virDomainDef *def,
                             virDomainUSBDeviceDefIterator iter,
                             void *opaque,
                             bool skipHubs)
{
    size_t i;

    /* usb-hub */
    if (!skipHubs) {
        for (i = 0; i < def->nhubs; i++) {
            virDomainHubDef *hub = def->hubs[i];
            if (hub->type == VIR_DOMAIN_HUB_TYPE_USB) {
                if (iter(&hub->info, opaque) < 0)
                    return -1;
            }
        }
    }

    /* usb-host */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            if (iter(hostdev->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-storage */
    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
            if (iter(&disk->info, opaque) < 0)
                return -1;
        }
    }

    /* TODO: add def->nets here when libvirt starts supporting usb-net */

    /* usb-ccid */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID) {
            if (iter(&cont->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-kbd, usb-mouse, usb-tablet */
    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDef *input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            if (iter(&input->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-serial */
    for (i = 0; i < def->nserials; i++) {
        virDomainChrDef *serial = def->serials[i];
        if (serial->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB) {
            if (iter(&serial->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-audio model=usb */
    for (i = 0; i < def->nsounds; i++) {
        virDomainSoundDef *sound = def->sounds[i];
        if (sound->model == VIR_DOMAIN_SOUND_MODEL_USB) {
            if (iter(&sound->info, opaque) < 0)
                return -1;
        }
    }

    /* usb-redir */
    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDef *redirdev = def->redirdevs[i];
        if (redirdev->bus == VIR_DOMAIN_REDIRDEV_BUS_USB) {
            if (iter(&redirdev->info, opaque) < 0)
                return -1;
        }
    }

    return 0;
}


/* Copy src into a new definition; with the quality of the copy
 * depending on the migratable flag (false for transitions between
 * persistent and active, true for transitions across save files or
 * snapshots).  */
virDomainDef *
virDomainDefCopy(virDomainDef *src,
                 virDomainXMLOption *xmlopt,
                 void *parseOpaque,
                 bool migratable)
{
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
    g_autofree char *xml = NULL;

    if (migratable)
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE | VIR_DOMAIN_DEF_FORMAT_MIGRATABLE;

    /* Easiest to clone via a round-trip through XML.  */
    if (!(xml = virDomainDefFormat(src, xmlopt, format_flags)))
        return NULL;

    return virDomainDefParseString(xml, xmlopt, parseOpaque, parse_flags);
}

virDomainDef *
virDomainObjCopyPersistentDef(virDomainObj *dom,
                              virDomainXMLOption *xmlopt,
                              void *parseOpaque)
{
    virDomainDef *cur;

    cur = virDomainObjGetPersistentDef(xmlopt, dom, parseOpaque);
    if (!cur) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to get persistent definition object"));
        return NULL;
    }

    return virDomainDefCopy(cur, xmlopt, parseOpaque, false);
}


virDomainState
virDomainObjGetState(virDomainObj *dom, int *reason)
{
    if (reason)
        *reason = dom->state.reason;

    return dom->state.state;
}


bool
virDomainObjIsFailedPostcopy(virDomainObj *dom,
                             virDomainJobObj *job)
{
    if (job && job->asyncPaused &&
        (job->asyncJob == VIR_ASYNC_JOB_MIGRATION_IN ||
         job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT))
        return true;

    return ((dom->state.state == VIR_DOMAIN_PAUSED &&
             dom->state.reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED) ||
            (dom->state.state == VIR_DOMAIN_RUNNING &&
             dom->state.reason == VIR_DOMAIN_RUNNING_POSTCOPY_FAILED));
}


bool
virDomainObjIsPostcopy(virDomainObj *dom,
                       virDomainJobObj *job)
{
    if (virDomainObjIsFailedPostcopy(dom, job))
        return true;

    return (dom->state.state == VIR_DOMAIN_PAUSED &&
            dom->state.reason == VIR_DOMAIN_PAUSED_POSTCOPY) ||
           (dom->state.state == VIR_DOMAIN_RUNNING &&
            dom->state.reason == VIR_DOMAIN_RUNNING_POSTCOPY);
}


void
virDomainObjSetState(virDomainObj *dom, virDomainState state, int reason)
{
    int last;

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
    case VIR_DOMAIN_LAST:
    default:
        VIR_ERROR(_("invalid domain state: %1$d"), state);
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
virDomainNetGetActualType(const virDomainNetDef *iface)
{
    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
        return iface->type;
    if (!iface->data.network.actual)
        return iface->type;
    return iface->data.network.actual->type;
}

const char *
virDomainNetGetActualBridgeName(const virDomainNetDef *iface)
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
virDomainNetGetActualBridgeMACTableManager(const virDomainNetDef *iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        (iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
         iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_NETWORK))
        return iface->data.network.actual->data.bridge.macTableManager;
    return 0;
}

const char *
virDomainNetGetActualDirectDev(const virDomainNetDef *iface)
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
virDomainNetGetActualDirectMode(const virDomainNetDef *iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.direct.mode;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        return iface->data.network.actual->data.direct.mode;
    return 0;
}

virDomainHostdevDef *
virDomainNetGetActualHostdev(virDomainNetDef *iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)
        return &iface->data.hostdev.def;
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual &&
        iface->data.network.actual->type == VIR_DOMAIN_NET_TYPE_HOSTDEV)
        return &iface->data.network.actual->data.hostdev.def;
    return NULL;
}

const virNetDevVPortProfile *
virDomainNetGetActualVirtPortProfile(const virDomainNetDef *iface)
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
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }
        return NULL;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        return NULL;
    }
}

/* Check whether the port is an ovs managed port */
bool
virDomainNetDefIsOvsport(const virDomainNetDef *net)
{
    const virNetDevVPortProfile *vport = virDomainNetGetActualVirtPortProfile(net);
    virDomainNetType actualType = virDomainNetGetActualType(net);

    return (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) && vport &&
        vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH;
}

const virNetDevBandwidth *
virDomainNetGetActualBandwidth(const virDomainNetDef *iface)
{
    /* if there is an ActualNetDef, *always* return
     * its bandwidth rather than the NetDef's bandwidth.
     */
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual)
        return iface->data.network.actual->bandwidth;
    return iface->bandwidth;
}

const virNetDevVlan *
virDomainNetGetActualVlan(const virDomainNetDef *iface)
{
    const virNetDevVlan *vlan = &iface->vlan;

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


virTristateBool
virDomainNetGetActualPortOptionsIsolated(const virDomainNetDef *iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual) {
        return iface->data.network.actual->isolatedPort;
    }
    return iface->isolatedPort;
}


bool
virDomainNetGetActualTrustGuestRxFilters(const virDomainNetDef *iface)
{
    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        iface->data.network.actual)
        return (iface->data.network.actual->trustGuestRxFilters
                == VIR_TRISTATE_BOOL_YES);
    return iface->trustGuestRxFilters == VIR_TRISTATE_BOOL_YES;
}

const char *
virDomainNetGetModelString(const virDomainNetDef *net)
{
    if (net->model)
        return virDomainNetModelTypeToString(net->model);
    return net->modelstr;
}

int
virDomainNetSetModelString(virDomainNetDef *net,
                           const char *model)
{
    size_t i;

    VIR_FREE(net->modelstr);
    net->model = VIR_DOMAIN_NET_MODEL_UNKNOWN;
    if (!model)
        return 0;

    for (i = 0; i < G_N_ELEMENTS(virDomainNetModelTypeList); i++) {
        if (STRCASEEQ(virDomainNetModelTypeList[i], model)) {
            net->model = i;
            return 0;
        }
    }

    if (strspn(model, NET_MODEL_CHARS) < strlen(model)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Model name contains invalid characters"));
        return -1;
    }

    net->modelstr = g_strdup(model);
    return 0;
}

bool
virDomainNetIsVirtioModel(const virDomainNetDef *net)
{
    return (net->model == VIR_DOMAIN_NET_MODEL_VIRTIO ||
            net->model == VIR_DOMAIN_NET_MODEL_VIRTIO_TRANSITIONAL ||
            net->model == VIR_DOMAIN_NET_MODEL_VIRTIO_NON_TRANSITIONAL);
}


/* Return listens[i] from the appropriate union for the graphics
 * type, or NULL if this is an unsuitable type, or the index is out of
 * bounds. If force0 is TRUE, i == 0, and there is no listen array,
 * allocate one with a single item. */
virDomainGraphicsListenDef *
virDomainGraphicsGetListen(virDomainGraphicsDef *def, size_t i)
{
    if (!def->listens || (def->nListens <= i))
        return NULL;

    return &def->listens[i];
}


int
virDomainGraphicsListenAppendAddress(virDomainGraphicsDef *def,
                                     const char *address)
{
    virDomainGraphicsListenDef glisten = { 0 };

    glisten.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;

    glisten.address = g_strdup(address);

    VIR_APPEND_ELEMENT_COPY(def->listens, def->nListens, glisten);

    return 0;
}


int
virDomainGraphicsListenAppendSocket(virDomainGraphicsDef *def,
                                    const char *socketPath)
{
    virDomainGraphicsListenDef glisten = { 0 };

    glisten.type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET;

    glisten.socket = g_strdup(socketPath);

    VIR_APPEND_ELEMENT_COPY(def->listens, def->nListens, glisten);

    return 0;
}


/**
 * virDomainNetFind:
 * @def: domain's def
 * @device: could be the interface name or MAC address
 *
 * Finds a domain's net def, given the interface name or MAC address
 *
 * Returns a pointer to the net def or NULL if not found (error is reported).
 */
virDomainNetDef *
virDomainNetFind(virDomainDef *def, const char *device)
{
    bool isMac = false;
    virMacAddr mac;
    size_t i;

    if (virMacAddrParse(device, &mac) == 0)
        isMac = true;

    if (isMac) {
        for (i = 0; i < def->nnets; i++) {
            if (virMacAddrCmp(&mac, &def->nets[i]->mac) == 0)
                return def->nets[i];
        }
    } else { /* ifname */
        virDomainNetDef *net = NULL;

        if ((net = virDomainNetFindByName(def, device)))
            return net;
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("'%1$s' is not a known interface"), device);
    return NULL;
}


/**
 * virDomainNetFindByName:
 * @def: domain's def
 * @ifname: interface name
 *
 * Finds a domain's net def given the interface name.
 *
 * Returns a pointer to the net def or NULL if not found.
 */
virDomainNetDef *
virDomainNetFindByName(virDomainDef *def,
                       const char *ifname)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (STREQ_NULLABLE(ifname, def->nets[i]->ifname))
            return def->nets[i];
    }

    return NULL;
}


virSecurityLabelDef *
virDomainDefGetSecurityLabelDef(const virDomainDef *def, const char *model)
{
    size_t i;
    virSecurityLabelDef *seclabel = NULL;

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


virSecurityDeviceLabelDef *
virDomainChrSourceDefGetSecurityLabelDef(virDomainChrSourceDef *def,
                                         const char *model)
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
    virDomainDeviceDef *dev;
} virDomainDefFindDeviceCallbackData;

static int
virDomainDefFindDeviceCallback(virDomainDef *def G_GNUC_UNUSED,
                               virDomainDeviceDef *dev,
                               virDomainDeviceInfo *info,
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
virDomainDefFindDevice(virDomainDef *def,
                       const char *devAlias,
                       virDomainDeviceDef *dev,
                       bool reportError)
{
    virDomainDefFindDeviceCallbackData data = { devAlias, dev };

    dev->type = VIR_DOMAIN_DEVICE_NONE;
    virDomainDeviceInfoIterateFlags(def, virDomainDefFindDeviceCallback,
                                    DOMAIN_DEVICE_ITERATE_ALL_CONSOLES,
                                    &data);

    if (dev->type == VIR_DOMAIN_DEVICE_NONE) {
        if (reportError) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("no device found with alias %1$s"), devAlias);
        } else {
            VIR_DEBUG("no device found with alias %s", devAlias);
        }
        return -1;
    }

    return 0;
}


virDomainAudioDef *
virDomainDefFindAudioByID(const virDomainDef *def,
                          int id)
{
    size_t i;
    if (id != 0) {
        for (i = 0; i < def->naudios; i++)
            if (def->audios[i]->id == id)
                return def->audios[i];
    } else if (def->naudios) {
        return def->audios[0];
    }

    return NULL;
}


bool
virDomainSoundModelSupportsCodecs(virDomainSoundDef *def)
{
    return def->model == VIR_DOMAIN_SOUND_MODEL_ICH6 ||
        def->model == VIR_DOMAIN_SOUND_MODEL_ICH9;
}

bool
virDomainAudioIOCommonIsSet(virDomainAudioIOCommon *common)
{
    return common->mixingEngine ||
        common->fixedSettings ||
        common->frequency ||
        common->channels ||
        common->voices ||
        common->format ||
        common->bufferLength;
}


static bool
virDomainAudioIOCommonIsEqual(virDomainAudioIOCommon *this,
                              virDomainAudioIOCommon *that)
{
    return this->mixingEngine == that->mixingEngine &&
        this->fixedSettings == that->fixedSettings &&
        this->frequency == that->frequency &&
        this->channels == that->channels &&
        this->voices == that->voices &&
        this->format == that->format &&
        this->bufferLength == that->bufferLength;
}

static bool
virDomainAudioIOALSAIsEqual(virDomainAudioIOALSA *this,
                            virDomainAudioIOALSA *that)
{
    return STREQ_NULLABLE(this->dev, that->dev);
}

static bool
virDomainAudioIOCoreAudioIsEqual(virDomainAudioIOCoreAudio *this,
                                 virDomainAudioIOCoreAudio *that)
{
    return this->bufferCount == that->bufferCount;
}

static bool
virDomainAudioIOJackIsEqual(virDomainAudioIOJack *this,
                            virDomainAudioIOJack *that)
{
    return STREQ_NULLABLE(this->serverName, that->serverName) &&
         STREQ_NULLABLE(this->clientName, that->clientName) &&
         STREQ_NULLABLE(this->connectPorts, that->connectPorts) &&
        this->exactName == that->exactName;
}

static bool
virDomainAudioIOOSSIsEqual(virDomainAudioIOOSS *this,
                           virDomainAudioIOOSS *that)
{
    return STREQ_NULLABLE(this->dev, that->dev) &&
        this->bufferCount == that->bufferCount &&
        this->tryPoll == that->tryPoll;
}

static bool
virDomainAudioIOPulseAudioIsEqual(virDomainAudioIOPulseAudio *this,
                                  virDomainAudioIOPulseAudio *that)
{
        return STREQ_NULLABLE(this->name, that->name) &&
            STREQ_NULLABLE(this->streamName, that->streamName) &&
            this->latency == that->latency;
}

static bool
virDomainAudioIOSDLIsEqual(virDomainAudioIOSDL *this,
                           virDomainAudioIOSDL *that)
{
    return this->bufferCount == that->bufferCount;
}


static bool
virDomainAudioBackendIsEqual(virDomainAudioDef *this,
                             virDomainAudioDef *that)
{
    if (this->type != that->type)
        return false;

    switch (this->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
        return true;

    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        return virDomainAudioIOALSAIsEqual(&this->backend.alsa.input,
                                           &that->backend.alsa.input) &&
            virDomainAudioIOALSAIsEqual(&this->backend.alsa.output,
                                        &that->backend.alsa.output);

    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        return virDomainAudioIOCoreAudioIsEqual(&this->backend.coreaudio.input,
                                                &that->backend.coreaudio.input) &&
            virDomainAudioIOCoreAudioIsEqual(&this->backend.coreaudio.output,
                                             &that->backend.coreaudio.output);

    case VIR_DOMAIN_AUDIO_TYPE_JACK:
        return virDomainAudioIOJackIsEqual(&this->backend.jack.input,
                                           &that->backend.jack.input) &&
            virDomainAudioIOJackIsEqual(&this->backend.jack.output,
                                        &that->backend.jack.output);

    case VIR_DOMAIN_AUDIO_TYPE_OSS:
        return virDomainAudioIOOSSIsEqual(&this->backend.oss.input,
                                          &that->backend.oss.input) &&
            virDomainAudioIOOSSIsEqual(&this->backend.oss.output,
                                       &that->backend.oss.output) &&
            this->backend.oss.tryMMap == that->backend.oss.tryMMap &&
            this->backend.oss.exclusive == that->backend.oss.exclusive &&
            this->backend.oss.dspPolicySet == that->backend.oss.dspPolicySet &&
            this->backend.oss.dspPolicy == that->backend.oss.dspPolicy;

    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        return virDomainAudioIOPulseAudioIsEqual(&this->backend.pulseaudio.input,
                                                 &that->backend.pulseaudio.input) &&
            virDomainAudioIOPulseAudioIsEqual(&this->backend.pulseaudio.output,
                                              &that->backend.pulseaudio.output) &&
            STREQ_NULLABLE(this->backend.pulseaudio.serverName,
                           that->backend.pulseaudio.serverName);

    case VIR_DOMAIN_AUDIO_TYPE_SDL:
        return virDomainAudioIOSDLIsEqual(&this->backend.sdl.input,
                                          &that->backend.sdl.input) &&
            virDomainAudioIOSDLIsEqual(&this->backend.sdl.output,
                                       &that->backend.sdl.output) &&
            this->backend.sdl.driver == that->backend.sdl.driver;

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        return true;

    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        return STREQ_NULLABLE(this->backend.file.path, that->backend.file.path);

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
    case VIR_DOMAIN_AUDIO_TYPE_LAST:
    default:
        return false;
    }
}


bool
virDomainAudioIsEqual(virDomainAudioDef *this,
                      virDomainAudioDef *that)
{
    return this->type == that->type &&
        this->id == that->id &&
        this->timerPeriod == that->timerPeriod &&
        virDomainAudioIOCommonIsEqual(&this->input, &that->input) &&
        virDomainAudioIOCommonIsEqual(&this->output, &that->output) &&
        virDomainAudioBackendIsEqual(this, that);
}


char *
virDomainObjGetMetadata(virDomainObj *vm,
                        int type,
                        const char *uri,
                        unsigned int flags)
{
    virDomainDef *def;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, NULL);

    if (type >= VIR_DOMAIN_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%1$d'"), type);
        return NULL;
    }

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        return NULL;

    switch ((virDomainMetadataType) type) {
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        ret = g_strdup(def->description);
        break;

    case VIR_DOMAIN_METADATA_TITLE:
        ret = g_strdup(def->title);
        break;

    case VIR_DOMAIN_METADATA_ELEMENT:
        if (!def->metadata)
            break;

        if (virXMLExtractNamespaceXML(def->metadata, uri, &ret) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_METADATA_LAST:
        break;
    }

    if (!ret)
        virReportError(VIR_ERR_NO_DOMAIN_METADATA, "%s",
                       _("Requested metadata element is not present"));

    return ret;
}


static int
virDomainDefSetMetadata(virDomainDef *def,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri)
{
    g_autoptr(xmlDoc) doc = NULL;
    xmlNodePtr old;
    g_autoptr(xmlNode) new = NULL;

    if (type >= VIR_DOMAIN_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%1$d'"), type);
        return -1;
    }

    switch ((virDomainMetadataType) type) {
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        g_clear_pointer(&def->description, g_free);

        if (STRNEQ_NULLABLE(metadata, ""))
            def->description = g_strdup(metadata);
        break;

    case VIR_DOMAIN_METADATA_TITLE:
        g_clear_pointer(&def->title, g_free);

        if (STRNEQ_NULLABLE(metadata, ""))
            def->title = g_strdup(metadata);
        break;

    case VIR_DOMAIN_METADATA_ELEMENT:
        if (metadata) {

            /* parse and modify the xml from the user */
            if (!(doc = virXMLParseStringCtxt(metadata, _("(metadata_xml)"), NULL)))
                return -1;

            if (virXMLInjectNamespace(doc->children, uri, key) < 0)
                return -1;

            /* create the root node if needed */
            if (!def->metadata)
                def->metadata = virXMLNewNode(NULL, "metadata");

            if (!(new = xmlCopyNode(doc->children, 1))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to copy XML node"));
                return -1;
            }
        }

        /* remove possible other nodes sharing the namespace */
        while ((old = virXMLFindChildNodeByNs(def->metadata, uri))) {
            xmlUnlinkNode(old);
            xmlFreeNode(old);
        }

        if (new) {
            if (!(xmlAddChild(def->metadata, new))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to add metadata to XML document"));
                return -1;
            }
            new = NULL;
        }
        break;

    case VIR_DOMAIN_METADATA_LAST:
        break;
    }

    return 0;
}


int
virDomainObjSetMetadata(virDomainObj *vm,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri,
                        virDomainXMLOption *xmlopt,
                        const char *stateDir,
                        const char *configDir,
                        unsigned int flags)
{
    virDomainDef *def;
    virDomainDef *persistentDef;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        return -1;

    if (def) {
        if (virDomainDefSetMetadata(def, type, metadata, key, uri) < 0)
            return -1;

        if (virDomainObjSave(vm, xmlopt, stateDir) < 0)
            return -1;
    }

    if (persistentDef) {
        if (virDomainDefSetMetadata(persistentDef, type, metadata, key,
                                    uri) < 0)
            return -1;

        if (virDomainDefSave(persistentDef, xmlopt, configDir) < 0)
            return -1;
    }

    return 0;
}


bool
virDomainDefNeedsPlacementAdvice(virDomainDef *def)
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
                       _("target '%1$s' duplicated for disk sources '%2$s' and '%3$s'"),
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


#define VIR_DOMAIN_SHORT_NAME_MAX 20

/**
 * virDomainDefGetShortName:
 * @def: domain definition
 *
 * Shorten domain name to avoid possible path length limitations.
 */
char *
virDomainDefGetShortName(const virDomainDef *def)
{
    wchar_t wshortname[VIR_DOMAIN_SHORT_NAME_MAX + 1] = {0};
    size_t len = 0;
    g_autofree char *shortname = NULL;

    /* No need to do the whole conversion thing when there are no multibyte
     * characters.  The same applies for illegal sequences as they can occur
     * with incompatible locales. */
    len = mbstowcs(NULL, def->name, 0);
    if ((len == (size_t) -1 && errno == EILSEQ) ||
        len == strlen(def->name)) {
        return g_strdup_printf("%d-%.*s", def->id, VIR_DOMAIN_SHORT_NAME_MAX,
                               def->name);
    }

    if (len == (size_t) -1) {
        virReportSystemError(errno, "%s",
                             _("Cannot convert domain name to wide character string"));
        return NULL;
    }

    if (mbstowcs(wshortname, def->name, VIR_DOMAIN_SHORT_NAME_MAX) == (size_t) -1) {
        virReportSystemError(errno, "%s",
                             _("Cannot convert domain name to wide character string"));
        return NULL;
    }

    len = wcstombs(NULL, wshortname, 0);
    if (len == (size_t) -1) {
        virReportSystemError(errno, "%s",
                             _("Cannot convert wide character string back to multi-byte domain name"));
        return NULL;
    }

    shortname = g_new0(char, len + 1);

    if (wcstombs(shortname, wshortname, len) == (size_t) -1) {
        virReportSystemError(errno, "%s",
                             _("Cannot convert wide character string back to multi-byte domain name"));
        return NULL;
    }

    return g_strdup_printf("%d-%s", def->id, shortname);
}

#undef VIR_DOMAIN_SHORT_NAME_MAX

int
virDomainGetBlkioParametersAssignFromDef(virDomainDef *def,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         int maxparams)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char *data = NULL;
    size_t i;

#define VIR_BLKIO_ASSIGN(param, format, name) \
    if (*nparams < maxparams) { \
        for (i = 0; i < def->blkio.ndevices; i++) { \
            if (!def->blkio.devices[i].param) \
                continue; \
            virBufferAsprintf(&buf, "%s," format ",", \
                              def->blkio.devices[i].path, \
                              def->blkio.devices[i].param); \
        } \
        virBufferTrim(&buf, ","); \
        data = virBufferContentAndReset(&buf); \
        if (virTypedParameterAssign(&(params[(*nparams)++]), name, \
                                    VIR_TYPED_PARAM_STRING, data) < 0) \
            goto error; \
        data = NULL; \
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
    return -1;
}


void
virDomainDefVcpuOrderClear(virDomainDef *def)
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
 */
void
virDomainDiskSetBlockIOTune(virDomainDiskDef *disk,
                            virDomainBlockIoTuneInfo *info)
{
    char *tmp_group = NULL;

    tmp_group = g_strdup(info->group_name);

    VIR_FREE(disk->blkdeviotune.group_name);
    disk->blkdeviotune = *info;
    disk->blkdeviotune.group_name = g_steal_pointer(&tmp_group);
}


/**
 * virDomainNetTypeSharesHostView:
 * @net: interface
 *
 * Some types of interfaces "share" the host view. For instance,
 * for macvtap interface, every domain RX is the host RX too. And
 * every domain TX is host TX too. IOW, for some types of
 * interfaces guest and host are on the same side of RX/TX
 * barrier. This is important so that we set up QoS correctly and
 * report proper stats.
 */
bool
virDomainNetTypeSharesHostView(const virDomainNetDef *net)
{
    virDomainNetType actualType = virDomainNetGetActualType(net);
    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        return true;
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (net->managed_tap == VIR_TRISTATE_BOOL_NO &&
            virNetDevMacVLanIsMacvtap(net->ifname))
            return true;
        break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }
    return false;
}

virNetworkPortDef *
virDomainNetDefToNetworkPort(virDomainDef *dom,
                             virDomainNetDef *iface)
{
    g_autoptr(virNetworkPortDef) port = NULL;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expected an interface of type 'network' not '%1$s'"),
                       virDomainNetTypeToString(iface->type));
        return NULL;
    }

    port = g_new0(virNetworkPortDef, 1);

    if (virUUIDGenerate(port->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Failed to generate UUID"));
        return NULL;
    }

    memcpy(port->owneruuid, dom->uuid, VIR_UUID_BUFLEN);
    port->ownername = g_strdup(dom->name);

    port->group = g_strdup(iface->data.network.portgroup);

    memcpy(&port->mac, &iface->mac, VIR_MAC_BUFLEN);

    port->virtPortProfile = virNetDevVPortProfileCopy(iface->virtPortProfile);

    if (virNetDevBandwidthCopy(&port->bandwidth, iface->bandwidth) < 0)
        return NULL;

    if (virNetDevVlanCopy(&port->vlan, &iface->vlan) < 0)
        return NULL;

    port->isolatedPort = iface->isolatedPort;
    port->trustGuestRxFilters = iface->trustGuestRxFilters;

    return g_steal_pointer(&port);
}

int
virDomainNetDefActualFromNetworkPort(virDomainNetDef *iface,
                                     virNetworkPortDef *port)
{
    virDomainActualNetDef *actual = NULL;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expected an interface of type 'network' not '%1$s'"),
                       virDomainNetTypeToString(iface->type));
        return -1;
    }

    actual = g_new0(virDomainActualNetDef, 1);

    switch ((virNetworkPortPlugType)port->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
        actual->type = VIR_DOMAIN_NET_TYPE_NETWORK;
        actual->data.bridge.brname = g_strdup(port->plug.bridge.brname);
        actual->data.bridge.macTableManager = port->plug.bridge.macTableManager;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        actual->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
        actual->data.bridge.brname = g_strdup(port->plug.bridge.brname);
        actual->data.bridge.macTableManager = port->plug.bridge.macTableManager;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        actual->type = VIR_DOMAIN_NET_TYPE_DIRECT;
        actual->data.direct.linkdev = g_strdup(port->plug.direct.linkdev);
        actual->data.direct.mode = port->plug.direct.mode;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        actual->type = VIR_DOMAIN_NET_TYPE_HOSTDEV;
        actual->data.hostdev.def.parentnet = iface;
        actual->data.hostdev.def.info = &iface->info;
        actual->data.hostdev.def.mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        switch (port->plug.hostdevpci.managed) {
        case VIR_TRISTATE_BOOL_YES:
            actual->data.hostdev.def.managed = true;
            break;
        case VIR_TRISTATE_BOOL_ABSENT:
        case VIR_TRISTATE_BOOL_NO:
        case VIR_TRISTATE_BOOL_LAST:
            actual->data.hostdev.def.managed = false;
            break;
        }
        actual->data.hostdev.def.source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
        actual->data.hostdev.def.source.subsys.u.pci.addr = port->plug.hostdevpci.addr;
        switch ((virNetworkForwardDriverNameType)port->plug.hostdevpci.driver) {
        case VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT:
            actual->data.hostdev.def.source.subsys.u.pci.backend =
                VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT;
            break;

        case VIR_NETWORK_FORWARD_DRIVER_NAME_KVM:
            actual->data.hostdev.def.source.subsys.u.pci.backend =
                VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM;
            break;

        case VIR_NETWORK_FORWARD_DRIVER_NAME_VFIO:
            actual->data.hostdev.def.source.subsys.u.pci.backend =
                VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
            break;

        case VIR_NETWORK_FORWARD_DRIVER_NAME_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardDriverNameType,
                                    port->plug.hostdevpci.driver);
            goto error;
        }

        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, port->plugtype);
        goto error;
    }

    actual->virtPortProfile = virNetDevVPortProfileCopy(port->virtPortProfile);

    if (virNetDevBandwidthCopy(&actual->bandwidth, port->bandwidth) < 0)
        goto error;

    if (virNetDevVlanCopy(&actual->vlan, &port->vlan) < 0)
        goto error;

    actual->isolatedPort = port->isolatedPort;
    actual->class_id = port->class_id;
    actual->trustGuestRxFilters = port->trustGuestRxFilters;

    virDomainActualNetDefFree(iface->data.network.actual);
    iface->data.network.actual = actual;

    return 0;

 error:
    virDomainActualNetDefFree(actual);
    return -1;
}

virNetworkPortDef *
virDomainNetDefActualToNetworkPort(virDomainDef *dom,
                                   virDomainNetDef *iface)
{
    virDomainActualNetDef *actual;
    g_autoptr(virNetworkPortDef) port = NULL;

    if (!iface->data.network.actual) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing actual data for interface '%1$s'"),
                       iface->ifname);
        return NULL;
    }

    actual = iface->data.network.actual;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expected an interface of type 'network' not '%1$s'"),
                       virDomainNetTypeToString(iface->type));
        return NULL;
    }

    port = g_new0(virNetworkPortDef, 1);

    if (virUUIDIsValid(iface->data.network.portid)) {
        memcpy(port->uuid, iface->data.network.portid, VIR_UUID_BUFLEN);
    } else if (virUUIDGenerate(port->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Failed to generate UUID"));
        return NULL;
    }

    memcpy(port->owneruuid, dom->uuid, VIR_UUID_BUFLEN);
    port->ownername = g_strdup(dom->name);

    port->group = g_strdup(iface->data.network.portgroup);

    memcpy(&port->mac, &iface->mac, VIR_MAC_BUFLEN);

    switch (virDomainNetGetActualType(iface)) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_NETWORK;
        port->plug.bridge.brname = g_strdup(actual->data.bridge.brname);
        port->plug.bridge.macTableManager = actual->data.bridge.macTableManager;
        break;

    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE;
        port->plug.bridge.brname = g_strdup(actual->data.bridge.brname);
        port->plug.bridge.macTableManager = actual->data.bridge.macTableManager;
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT:
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_DIRECT;
        port->plug.direct.linkdev = g_strdup(actual->data.direct.linkdev);
        port->plug.direct.mode = actual->data.direct.mode;
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        port->plugtype = VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI;
        if (actual->data.hostdev.def.mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            actual->data.hostdev.def.source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Actual interface '%1$s' hostdev was not a PCI device"),
                           iface->ifname);
            return NULL;
        }
        port->plug.hostdevpci.managed = virTristateBoolFromBool(actual->data.hostdev.def.managed);
        port->plug.hostdevpci.addr = actual->data.hostdev.def.source.subsys.u.pci.addr;
        switch (actual->data.hostdev.def.source.subsys.u.pci.backend) {
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
            port->plug.hostdevpci.driver = VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT;
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
            port->plug.hostdevpci.driver = VIR_NETWORK_FORWARD_DRIVER_NAME_KVM;
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
            port->plug.hostdevpci.driver = VIR_NETWORK_FORWARD_DRIVER_NAME_VFIO;
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Unexpected PCI backend 'xen'"));
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainHostdevSubsysPCIBackendType,
                                    actual->data.hostdev.def.source.subsys.u.pci.backend);
            return NULL;
        }

        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unexpected network port type %1$s"),
                       virDomainNetTypeToString(virDomainNetGetActualType(iface)));
        return NULL;

    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, port->plugtype);
        return NULL;
    }

    port->virtPortProfile = virNetDevVPortProfileCopy(actual->virtPortProfile);

    if (virNetDevBandwidthCopy(&port->bandwidth, actual->bandwidth) < 0)
        return NULL;

    if (virNetDevVlanCopy(&port->vlan, &actual->vlan) < 0)
        return NULL;

    port->isolatedPort = actual->isolatedPort;
    port->class_id = actual->class_id;
    port->trustGuestRxFilters = actual->trustGuestRxFilters;

    return g_steal_pointer(&port);
}


static int
virDomainNetCreatePort(virConnectPtr conn,
                       virDomainDef *dom,
                       virDomainNetDef *iface,
                       unsigned int flags)
{
    virErrorPtr save_err;
    g_autoptr(virNetwork) net = NULL;
    g_autoptr(virNetworkPortDef) portdef = NULL;
    g_autoptr(virNetworkPort) port = NULL;
    g_autofree char *portxml = NULL;

    if (!(net = virNetworkLookupByName(conn, iface->data.network.name)))
        return -1;

    if (flags & VIR_NETWORK_PORT_CREATE_RECLAIM) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        char macstr[VIR_MAC_STRING_BUFLEN];

        virUUIDFormat(iface->data.network.portid, uuidstr);
        virMacAddrFormat(&iface->mac, macstr);

        /* if the port is already registered, then we are done */
        if (virUUIDIsValid(iface->data.network.portid) &&
            (port = virNetworkPortLookupByUUID(net, iface->data.network.portid))) {
            VIR_DEBUG("network: %s domain: %s mac: %s port: %s - already registered, skipping",
                      iface->data.network.name, dom->name, macstr, uuidstr);
            return 0;
        }

        /* otherwise we need to create a new port */
        VIR_DEBUG("network: %s domain: %s mac: %s port: %s - not found, reclaiming",
                  iface->data.network.name, dom->name, macstr, uuidstr);
        if (!(portdef = virDomainNetDefActualToNetworkPort(dom, iface)))
            return -1;
    } else {
        if (!(portdef = virDomainNetDefToNetworkPort(dom, iface)))
            return -1;
    }

    if (!(portxml = virNetworkPortDefFormat(portdef)))
        return -1;

    /* prepare to re-use portdef */
    g_clear_pointer(&portdef, virNetworkPortDefFree);

    if (!(port = virNetworkPortCreateXML(net, portxml, flags)))
        return -1;

    /* prepare to re-use portxml */
    VIR_FREE(portxml);

    if (!(portxml = virNetworkPortGetXMLDesc(port, 0)) ||
        !(portdef = virNetworkPortDefParse(portxml, NULL, 0)) ||
        virDomainNetDefActualFromNetworkPort(iface, portdef) < 0) {
        virErrorPreserveLast(&save_err);
        virNetworkPortDelete(port, 0);
        virErrorRestore(&save_err);
        return -1;
    }

    virNetworkPortGetUUID(port, iface->data.network.portid);
    return 0;
}

int
virDomainNetAllocateActualDevice(virConnectPtr conn,
                                 virDomainDef *dom,
                                 virDomainNetDef *iface)
{
    return virDomainNetCreatePort(conn, dom, iface, 0);
}

void
virDomainNetNotifyActualDevice(virConnectPtr conn,
                               virDomainDef *dom,
                               virDomainNetDef *iface)
{
    virDomainNetType actualType = virDomainNetGetActualType(iface);

    if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK && conn
        && virDomainNetCreatePort(conn, dom, iface,
                                  VIR_NETWORK_PORT_CREATE_RECLAIM) < 0) {
        return;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
        actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        /*
         * NB: we can't notify the guest of any MTU change anyway,
         * so there is no point in trying to learn the actualMTU
         * (final arg to virNetDevTapReattachBridge())
         */
        ignore_value(virNetDevTapReattachBridge(iface->ifname,
                                                virDomainNetGetActualBridgeName(iface),
                                                &iface->mac, dom->uuid,
                                                virDomainNetGetActualVirtPortProfile(iface),
                                                virDomainNetGetActualVlan(iface),
                                                virDomainNetGetActualPortOptionsIsolated(iface),
                                                iface->mtu, NULL));
    }
}


int
virDomainNetReleaseActualDevice(virConnectPtr conn,
                                virDomainDef *dom G_GNUC_UNUSED,
                                virDomainNetDef *iface)
{
    virNetworkPtr net = NULL;
    virNetworkPortPtr port = NULL;
    int ret = -1;

    /* Port might not exist if a failure occurred during VM startup */
    if (!virUUIDIsValid(iface->data.network.portid)) {
        ret = 0;
        goto cleanup;
    }

    if (!(net = virNetworkLookupByName(conn, iface->data.network.name)))
        goto cleanup;

    if (!(port = virNetworkPortLookupByUUID(net, iface->data.network.portid)))
        goto cleanup;

    if (virNetworkPortDelete(port, 0) < 0)
        goto cleanup;

 cleanup:
    virObjectUnref(port);
    virObjectUnref(net);
    return ret;
}


static int
virDomainNetBandwidthToTypedParams(virNetDevBandwidth *bandwidth,
                                   virTypedParameterPtr *params,
                                   int *nparams)
{
    int maxparams = 0;

    if ((bandwidth->in != NULL) &&
        (virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_IN_AVERAGE,
                               bandwidth->in->average) < 0 ||
         virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_IN_PEAK,
                               bandwidth->in->peak) < 0 ||
         virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_IN_FLOOR,
                               bandwidth->in->floor) < 0 ||
         virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_IN_BURST,
                               bandwidth->in->burst) < 0))
        goto error;

    if ((bandwidth->out != NULL) &&
        (virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_OUT_AVERAGE,
                               bandwidth->out->average) < 0 ||
         virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_OUT_PEAK,
                               bandwidth->out->peak) < 0 ||
         virTypedParamsAddUInt(params, nparams, &maxparams,
                               VIR_NETWORK_PORT_BANDWIDTH_OUT_BURST,
                               bandwidth->out->burst) < 0))
        goto error;

    return 0;

 error:
    virTypedParamsFree(*params, *nparams);
    *params = NULL;
    *nparams = 0;
    return -1;
}


int
virDomainNetBandwidthUpdate(virDomainNetDef *iface,
                            virNetDevBandwidth *newBandwidth)
{
    virNetworkPtr net = NULL;
    virNetworkPortPtr port = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    g_autoptr(virConnect) conn = NULL;
    int ret = -1;

    if (!(conn = virGetConnectNetwork()))
        goto cleanup;

    if (!(net = virNetworkLookupByName(conn, iface->data.network.name)))
        goto cleanup;

    if (!(port = virNetworkPortLookupByUUID(net, iface->data.network.portid)))
        goto cleanup;

    if (virDomainNetBandwidthToTypedParams(newBandwidth, &params, &nparams) < 0)
        goto cleanup;

    if (virNetworkPortSetParameters(port, params, nparams, 0) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virTypedParamsFree(params, nparams);
    virObjectUnref(port);
    virObjectUnref(net);
    return ret;
}

/* virDomainNetResolveActualType:
 * @iface: the original NetDef from the domain
 *
 * Looks up the network reference by iface, and returns the actual
 * type of the connection without allocating any resources.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virDomainNetResolveActualType(virDomainNetDef *iface)
{
    g_autoptr(virNetworkDef) def = NULL;
    g_autofree char *xml = NULL;
    g_autoptr(virConnect) conn = NULL;
    g_autoptr(virNetwork) net = NULL;

    if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK)
        return iface->type;

    if (iface->data.network.actual)
        return iface->data.network.actual->type;

    if (!(conn = virGetConnectNetwork()))
        return -1;

    if (!(net = virNetworkLookupByName(conn, iface->data.network.name)))
        return -1;

    if (!(xml = virNetworkGetXMLDesc(net, 0)))
        return -1;

    if (!(def = virNetworkDefParse(xml, NULL, NULL, false)))
        return -1;

    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        /* for these forward types, the actual net type really *is*
         * NETWORK; we just keep the info from the portgroup in
         * iface->data.network.actual
         */
        return VIR_DOMAIN_NET_TYPE_NETWORK;
        break;

    case VIR_NETWORK_FORWARD_HOSTDEV:
        return VIR_DOMAIN_NET_TYPE_HOSTDEV;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->bridge) {
            /* <forward type='bridge'/> <bridge name='xxx'/>
             * is VIR_DOMAIN_NET_TYPE_BRIDGE
             */
            return VIR_DOMAIN_NET_TYPE_BRIDGE;
        }

        /* intentionally fall through to the direct case for
         * VIR_NETWORK_FORWARD_BRIDGE with no bridge device defined
         */
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
        /* <forward type='bridge|private|vepa|passthrough'> are all
         * VIR_DOMAIN_NET_TYPE_DIRECT.
         */
        return VIR_DOMAIN_NET_TYPE_DIRECT;
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return -1;
    }

    /* this line is unreachable due to the preceding switch, but the compiler
     * requires some kind of return at the end of the function.
     */
    return VIR_NETWORK_FORWARD_NONE;
}


static int
virDomainDiskAddISCSIPoolSourceHost(virStorageSource *src,
                                    virStoragePoolDef *pooldef)
{
    g_auto(GStrv) tokens = NULL;

    /* Only support one host */
    if (pooldef->source.nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return -1;
    }

    /* iscsi pool only supports one host */
    src->nhosts = 1;
    src->hosts = g_new0(virStorageNetHostDef, 1);

    src->hosts[0].name = g_strdup(pooldef->source.hosts[0].name);

    if (pooldef->source.hosts[0].port != 0)
        src->hosts[0].port = pooldef->source.hosts[0].port;
    else
        src->hosts[0].port = 3260;

    /* iscsi volume has name like "unit:0:0:1" */
    if (!(tokens = g_strsplit(src->srcpool->volume, ":", 0)))
        return -1;

    if (g_strv_length(tokens) != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected iscsi volume name '%1$s'"),
                       src->srcpool->volume);
        return -1;
    }

    /* iscsi pool has only one source device path */
    src->path = g_strdup_printf("%s/%s", pooldef->source.devices[0].path,
                                tokens[3]);

    /* Storage pool have not supported these 2 attributes yet,
     * use the defaults.
     */
    src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    src->hosts[0].socket = NULL;

    src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    return 0;
}


static int
virDomainDiskTranslateSourcePoolAuth(virStorageSource *src,
                                     virStoragePoolSource *source)
{
    /* Only necessary when authentication set */
    if (!source->auth)
        return 0;

    src->auth = virStorageAuthDefCopy(source->auth);
    if (!src->auth)
        return -1;
    /* A <disk> doesn't use <auth type='%s', so clear that out for the disk */
    src->auth->authType = VIR_STORAGE_AUTH_TYPE_NONE;
    return 0;
}


static int
virDomainDiskTranslateISCSIDirect(virStorageSource *src,
                                  virStoragePoolDef *pooldef)
{
    src->srcpool->actualtype = VIR_STORAGE_TYPE_NETWORK;
    src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    if (virDomainDiskTranslateSourcePoolAuth(src,
                                             &pooldef->source) < 0)
        return -1;

    /* Source pool may not fill in the secrettype field,
     * so we need to do so here
     */
    if (src->auth && !src->auth->secrettype) {
        const char *secrettype =
            virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_ISCSI);
        src->auth->secrettype = g_strdup(secrettype);
    }

    if (virDomainDiskAddISCSIPoolSourceHost(src, pooldef) < 0)
        return -1;

    if (!src->initiator.iqn && pooldef->source.initiator.iqn &&
        virStorageSourceInitiatorCopy(&src->initiator,
                                      &pooldef->source.initiator) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainStorageSourceTranslateSourcePool(virStorageSource *src,
                                          virConnectPtr conn)
{
    virStorageVolInfo info;
    g_autoptr(virStoragePoolDef) pooldef = NULL;
    g_autofree char *poolxml = NULL;
    g_autoptr(virStoragePool) pool = NULL;
    g_autoptr(virStorageVol) vol = NULL;

    if (!(pool = virStoragePoolLookupByName(conn, src->srcpool->pool)))
        return -1;

    if (virStoragePoolIsActive(pool) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("storage pool '%1$s' containing volume '%2$s' is not active"),
                       src->srcpool->pool, src->srcpool->volume);
        return -1;
    }

    if (!(vol = virStorageVolLookupByName(pool, src->srcpool->volume)))
        return -1;

    if (virStorageVolGetInfo(vol, &info) < 0)
        return -1;

    if (!(poolxml = virStoragePoolGetXMLDesc(pool, 0)))
        return -1;

    if (!(pooldef = virStoragePoolDefParse(poolxml, NULL, 0)))
        return -1;

    src->srcpool->pooltype = pooldef->type;
    src->srcpool->voltype = info.type;

    if (src->srcpool->mode && pooldef->type != VIR_STORAGE_POOL_ISCSI) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("disk source mode is only valid when storage pool is of iscsi type"));
        return -1;
    }

    VIR_FREE(src->path);
    virStorageNetHostDefFree(src->nhosts, src->hosts);
    src->nhosts = 0;
    src->hosts = NULL;
    g_clear_pointer(&src->auth, virStorageAuthDefFree);

    switch ((virStoragePoolType) pooldef->type) {
    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
    case VIR_STORAGE_POOL_LOGICAL:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_SCSI:
    case VIR_STORAGE_POOL_ZFS:
    case VIR_STORAGE_POOL_VSTORAGE:
        if (!(src->path = virStorageVolGetPath(vol)))
            return -1;

        switch (info.type) {
        case VIR_STORAGE_VOL_FILE:
            src->srcpool->actualtype = VIR_STORAGE_TYPE_FILE;
            break;

        case VIR_STORAGE_VOL_DIR:
            src->srcpool->actualtype = VIR_STORAGE_TYPE_DIR;
            break;

        case VIR_STORAGE_VOL_BLOCK:
            src->srcpool->actualtype = VIR_STORAGE_TYPE_BLOCK;
            break;

        case VIR_STORAGE_VOL_PLOOP:
            src->srcpool->actualtype = VIR_STORAGE_TYPE_FILE;
            break;

        case VIR_STORAGE_VOL_NETWORK:
        case VIR_STORAGE_VOL_NETDIR:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected storage volume type '%1$s' for storage pool type '%2$s'"),
                           virStorageVolTypeToString(info.type),
                           virStoragePoolTypeToString(pooldef->type));
            return -1;
        }

        break;

    case VIR_STORAGE_POOL_ISCSI_DIRECT:
        if (virDomainDiskTranslateISCSIDirect(src, pooldef) < 0)
            return -1;

        break;

    case VIR_STORAGE_POOL_ISCSI:
       switch (src->srcpool->mode) {
       case VIR_STORAGE_SOURCE_POOL_MODE_DEFAULT:
       case VIR_STORAGE_SOURCE_POOL_MODE_LAST:
           src->srcpool->mode = VIR_STORAGE_SOURCE_POOL_MODE_HOST;
           G_GNUC_FALLTHROUGH;
       case VIR_STORAGE_SOURCE_POOL_MODE_HOST:
           src->srcpool->actualtype = VIR_STORAGE_TYPE_BLOCK;
           if (!(src->path = virStorageVolGetPath(vol)))
               return -1;
           break;

       case VIR_STORAGE_SOURCE_POOL_MODE_DIRECT:
           if (virDomainDiskTranslateISCSIDirect(src, pooldef) < 0)
               return -1;
           break;
       }
       break;

    case VIR_STORAGE_POOL_MPATH:
    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_SHEEPDOG:
    case VIR_STORAGE_POOL_GLUSTER:
    case VIR_STORAGE_POOL_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("using '%1$s' pools for backing 'volume' disks isn't yet supported"),
                       virStoragePoolTypeToString(pooldef->type));
        return -1;
    }

    return 0;
}


int
virDomainDiskTranslateSourcePool(virDomainDiskDef *def)
{
    g_autoptr(virConnect) conn = NULL;
    virStorageSource *n;

    for (n = def->src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (n->type != VIR_STORAGE_TYPE_VOLUME || !n->srcpool || n->srcpool->actualtype != VIR_STORAGE_TYPE_NONE)
            continue;

        if (!conn) {
            if (!(conn = virGetConnectStorage()))
                return -1;
        }

        if (virDomainStorageSourceTranslateSourcePool(n, conn) < 0)
            return -1;

        /* The validity of 'startupPolicy' setting is checked only for the top
         * level image. For any other subsequent images we honour it only if
         * possible */
        if (n == def->src &&
            virDomainDiskDefValidateStartupPolicy(def) < 0)
            return -1;
    }

    return 0;
}


/**
 * virDomainDiskGetDetectZeroesMode:
 * @discard: disk/image sector discard setting
 * @detect_zeroes: disk/image zero sector detection mode
 *
 * As a convenience syntax, if discards are ignored and zero detection is set
 * to 'unmap', then simply behave like zero detection is set to 'on'.  But
 * don't change it in the XML for easier adjustments.  This behaviour is
 * documented.
 */
int
virDomainDiskGetDetectZeroesMode(virDomainDiskDiscard discard,
                                 virDomainDiskDetectZeroes detect_zeroes)
{
    if (discard != VIR_DOMAIN_DISK_DISCARD_UNMAP &&
        detect_zeroes == VIR_DOMAIN_DISK_DETECT_ZEROES_UNMAP)
        return VIR_DOMAIN_DISK_DETECT_ZEROES_ON;

    return detect_zeroes;
}


/**
 * virDomainDefHasManagedPR:
 * @def: domain definition
 *
 * Returns true if any of the domain disks requires the use of the managed
 * persistent reservations infrastructure.
 */
bool
virDomainDefHasManagedPR(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (virStorageSourceChainHasManagedPR(def->disks[i]->src))
            return true;
    }

    return false;
}


bool
virDomainDefHasNVMeDisk(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (virStorageSourceChainHasNVMe(def->disks[i]->src))
            return true;
    }

    return false;
}


bool
virDomainDefHasVFIOHostdev(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        if (virHostdevIsVFIODevice(def->hostdevs[i]))
            return true;
    }

    return false;
}


bool
virDomainDefHasMdevHostdev(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        if (virHostdevIsMdevDevice(def->hostdevs[i]))
            return true;
    }

    return false;
}


bool
virDomainDefHasVDPANet(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (virDomainNetGetActualType(def->nets[i]) == VIR_DOMAIN_NET_TYPE_VDPA)
            return true;
    }

    return false;
}


bool
virDomainDefHasOldStyleUEFI(const virDomainDef *def)
{
    return def->os.loader &&
           def->os.loader->type == VIR_DOMAIN_LOADER_TYPE_PFLASH;
}


bool
virDomainDefHasOldStyleROUEFI(const virDomainDef *def)
{
    return virDomainDefHasOldStyleUEFI(def) &&
           def->os.loader->readonly == VIR_TRISTATE_BOOL_YES;
}


/**
 * virDomainGraphicsDefHasOpenGL:
 * @def: domain definition
 *
 * Returns true if a domain config contains at least one <graphics> element
 * with OpenGL support enabled, false otherwise.
 */
bool
virDomainGraphicsDefHasOpenGL(const virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = def->graphics[i];

        /* we only care about OpenGL support for a given type here */
        switch (graphics->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
            continue;
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            if (graphics->data.sdl.gl == VIR_TRISTATE_BOOL_YES)
                return true;

            continue;
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            if (graphics->data.spice.gl == VIR_TRISTATE_BOOL_YES)
                return true;

            continue;
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
            return true;

        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
            if (graphics->data.dbus.gl == VIR_TRISTATE_BOOL_YES)
                return true;

            continue;
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
        }
    }

    return false;
}


bool
virDomainGraphicsSupportsRenderNode(const virDomainGraphicsDef *graphics)
{
    bool ret = false;

    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE ||
        graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS ||
        graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_DBUS)
        ret = true;

    return ret;
}


const char *
virDomainGraphicsGetRenderNode(const virDomainGraphicsDef *graphics)
{
    const char *ret = NULL;

    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        ret = graphics->data.spice.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        ret = graphics->data.egl_headless.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        ret = graphics->data.dbus.rendernode;
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return ret;
}


bool
virDomainGraphicsNeedsAutoRenderNode(const virDomainGraphicsDef *graphics)
{
    if (!virDomainGraphicsSupportsRenderNode(graphics))
        return false;

    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
        graphics->data.spice.gl != VIR_TRISTATE_BOOL_YES)
        return false;
    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_DBUS &&
        graphics->data.dbus.gl != VIR_TRISTATE_BOOL_YES)
        return false;

    if (virDomainGraphicsGetRenderNode(graphics))
        return false;

    return true;
}


bool
virDomainBlockIoTuneInfoHasBasic(const virDomainBlockIoTuneInfo *iotune)
{
    return iotune->total_bytes_sec ||
           iotune->read_bytes_sec ||
           iotune->write_bytes_sec ||
           iotune->total_iops_sec ||
           iotune->read_iops_sec ||
           iotune->write_iops_sec;
}


bool
virDomainBlockIoTuneInfoHasMax(const virDomainBlockIoTuneInfo *iotune)
{
    return iotune->total_bytes_sec_max ||
           iotune->read_bytes_sec_max ||
           iotune->write_bytes_sec_max ||
           iotune->total_iops_sec_max ||
           iotune->read_iops_sec_max ||
           iotune->write_iops_sec_max ||
           iotune->size_iops_sec;
}


bool
virDomainBlockIoTuneInfoHasMaxLength(const virDomainBlockIoTuneInfo *iotune)
{
    return iotune->total_bytes_sec_max_length ||
           iotune->read_bytes_sec_max_length ||
           iotune->write_bytes_sec_max_length ||
           iotune->total_iops_sec_max_length ||
           iotune->read_iops_sec_max_length ||
           iotune->write_iops_sec_max_length;
}


bool
virDomainBlockIoTuneInfoHasAny(const virDomainBlockIoTuneInfo *iotune)
{
    return virDomainBlockIoTuneInfoHasBasic(iotune) ||
           virDomainBlockIoTuneInfoHasMax(iotune) ||
           virDomainBlockIoTuneInfoHasMaxLength(iotune);
}


void
virDomainBlockIoTuneInfoCopy(const virDomainBlockIoTuneInfo *src,
                             virDomainBlockIoTuneInfo *dst)
{
    *dst = *src;
    dst->group_name = g_strdup(src->group_name);
}


bool
virDomainBlockIoTuneInfoEqual(const virDomainBlockIoTuneInfo *a,
                              const virDomainBlockIoTuneInfo *b)
{
    return a->total_bytes_sec == b->total_bytes_sec &&
        a->read_bytes_sec == b->read_bytes_sec &&
        a->write_bytes_sec == b->write_bytes_sec &&
        a->total_iops_sec == b->total_iops_sec &&
        a->read_iops_sec == b->read_iops_sec &&
        a->write_iops_sec == b->write_iops_sec &&
        a->total_bytes_sec_max == b->total_bytes_sec_max &&
        a->read_bytes_sec_max == b->read_bytes_sec_max &&
        a->write_bytes_sec_max == b->write_bytes_sec_max &&
        a->total_iops_sec_max == b->total_iops_sec_max &&
        a->read_iops_sec_max == b->read_iops_sec_max &&
        a->write_iops_sec_max == b->write_iops_sec_max &&
        a->size_iops_sec == b->size_iops_sec &&
        a->total_bytes_sec_max_length == b->total_bytes_sec_max_length &&
        a->read_bytes_sec_max_length == b->read_bytes_sec_max_length &&
        a->write_bytes_sec_max_length == b->write_bytes_sec_max_length &&
        a->total_iops_sec_max_length == b->total_iops_sec_max_length &&
        a->read_iops_sec_max_length == b->read_iops_sec_max_length &&
        a->write_iops_sec_max_length == b->write_iops_sec_max_length;
}


/**
 * virHostdevIsSCSIDevice:
 * @hostdev: host device to check
 *
 * Returns true if @hostdev is a SCSI device, false otherwise.
 */
bool
virHostdevIsSCSIDevice(const virDomainHostdevDef *hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI;
}


/**
 * virHostdevIsMdevDevice:
 * @hostdev: host device to check
 *
 * Returns true if @hostdev is a Mediated device, false otherwise.
 */
bool
virHostdevIsMdevDevice(const virDomainHostdevDef *hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV;
}


/**
 * virHostdevIsVFIODevice:
 * @hostdev: host device to check
 *
 * Returns true if @hostdev is a PCI device with VFIO backend, false otherwise.
 */
bool
virHostdevIsVFIODevice(const virDomainHostdevDef *hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
        hostdev->source.subsys.u.pci.backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
}


/**
 * virDomainObjGetMessages:
 * @vm: domain object
 * @msgs: pointer to a variable to store messages
 * @flags: zero or more virDomainMessageType flags
 *
 * Returns number of messages stored in @msgs, -1 otherwise.
 */
int
virDomainObjGetMessages(virDomainObj *vm,
                        char ***msgs,
                        unsigned int flags)
{
    size_t i = 0;
    size_t n = 0;
    int nmsgs = 0;
    int rv = -1;

    *msgs = NULL;

    if (!flags || (flags & VIR_DOMAIN_MESSAGE_TAINTING)) {
        nmsgs += __builtin_popcount(vm->taint);
        *msgs = g_renew(char *, *msgs, nmsgs+1);

        for (i = 0; i < VIR_DOMAIN_TAINT_LAST; i++) {
            if (vm->taint & (1 << i)) {
                (*msgs)[n++] = g_strdup_printf(
                    _("tainted: %1$s"),
                    _(virDomainTaintMessageTypeToString(i)));
            }
        }
    }

    if (!flags || (flags & VIR_DOMAIN_MESSAGE_DEPRECATION)) {
        nmsgs += vm->ndeprecations;
        *msgs = g_renew(char *, *msgs, nmsgs+1);

        for (i = 0; i < vm->ndeprecations; i++) {
            (*msgs)[n++] = g_strdup_printf(
                _("deprecated configuration: %1$s"),
                vm->deprecations[i]);
        }
    }

    if (*msgs)
        (*msgs)[nmsgs] = NULL;

    rv = nmsgs;

    return rv;
}

bool
virDomainDefHasSpiceGraphics(const virDomainDef *def)
{
    size_t i = 0;

    for (i = 0; i < def->ngraphics; i++) {
        if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            return true;
        }
    }

    return false;
}


ssize_t
virDomainWatchdogDefFind(const virDomainDef *def,
                         const virDomainWatchdogDef *watchdog)
{
    size_t i;

    for (i = 0; i < def->nwatchdogs; i++) {
        const virDomainWatchdogDef *tmp = def->watchdogs[i];

        if (tmp->model != watchdog->model)
            continue;

        if (tmp->action != watchdog->action)
            continue;

        if (watchdog->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            !virDomainDeviceInfoAddressIsEqual(&watchdog->info, &tmp->info))
            continue;

        if (watchdog->info.alias &&
            STRNEQ_NULLABLE(watchdog->info.alias, tmp->info.alias))
            continue;

        return i;
    }

    return -1;
}
