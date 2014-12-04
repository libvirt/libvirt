/*
 * qemu_capabilities.h: QEMU capabilities generation
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

/* Internal flags to keep track of qemu command line capabilities */
typedef enum {
    QEMU_CAPS_KQEMU              =  0, /* Whether KQEMU is compiled in */
    QEMU_CAPS_VNC_COLON          =  1, /* VNC takes or address + display */
    QEMU_CAPS_NO_REBOOT          =  2, /* Is the -no-reboot flag available */
    QEMU_CAPS_DRIVE              =  3, /* Is the new -drive arg available */
    QEMU_CAPS_DRIVE_BOOT         =  4, /* Does -drive support boot=on */
    QEMU_CAPS_NAME               =  5, /* Is the -name flag available */
    QEMU_CAPS_UUID               =  6, /* Is the -uuid flag available */
    QEMU_CAPS_DOMID              =  7, /* Xenner: -domid flag available */
    QEMU_CAPS_VNET_HDR           =  8,
    QEMU_CAPS_MIGRATE_KVM_STDIO  =  9, /* avoid kvm tcp migration bug */
    QEMU_CAPS_MIGRATE_QEMU_TCP   = 10, /* have qemu tcp migration */
    QEMU_CAPS_MIGRATE_QEMU_EXEC  = 11, /* have qemu exec migration */
    QEMU_CAPS_DRIVE_CACHE_V2     = 12, /* cache= flag wanting new v2 values */
    QEMU_CAPS_KVM                = 13, /* Whether KVM is enabled by default */
    QEMU_CAPS_DRIVE_FORMAT       = 14, /* Is -drive format= avail */
    QEMU_CAPS_VGA                = 15, /* Is -vga avail */

    /* features added in qemu-0.10.0 or later */
    QEMU_CAPS_0_10               = 16,
    QEMU_CAPS_NET_NAME           = QEMU_CAPS_0_10, /* -net ...,name=str */
    QEMU_CAPS_HOST_NET_ADD       = QEMU_CAPS_0_10, /* host_net_add command */

    QEMU_CAPS_PCIDEVICE          = 17, /* PCI device assignment supported */
    QEMU_CAPS_MEM_PATH           = 18, /* mmap'ped guest backing supported */
    QEMU_CAPS_DRIVE_SERIAL       = 19, /* -driver serial=  available */
    QEMU_CAPS_XEN_DOMID          = 20, /* -xen-domid */
    QEMU_CAPS_MIGRATE_QEMU_UNIX  = 21, /* qemu migration via unix sockets */
    QEMU_CAPS_CHARDEV            = 22, /* Is the new -chardev arg available */
    QEMU_CAPS_ENABLE_KVM         = 23, /* -enable-kvm flag */
    QEMU_CAPS_MONITOR_JSON       = 24, /* JSON mode for monitor */
    QEMU_CAPS_BALLOON            = 25, /* -balloon available */
    QEMU_CAPS_DEVICE             = 26, /* Is the new -device arg available */
    QEMU_CAPS_SDL                = 27, /* Is the new -sdl arg available */
    QEMU_CAPS_SMP_TOPOLOGY       = 28, /* -smp has sockets/cores/threads */
    QEMU_CAPS_NETDEV             = 29, /* -netdev flag & netdev_add/remove */
    QEMU_CAPS_RTC                = 30, /* The -rtc flag for clock options */
    QEMU_CAPS_VHOST_NET          = 31, /* vhost-net support available */
    QEMU_CAPS_RTC_TD_HACK        = 32, /* -rtc-td-hack available */
    QEMU_CAPS_NO_HPET            = 33, /* -no-hpet flag is supported */
    QEMU_CAPS_NO_KVM_PIT         = 34, /* -no-kvm-pit-reinjection supported */
    QEMU_CAPS_TDF                = 35, /* -tdf flag (user-mode pit catchup) */
    QEMU_CAPS_PCI_CONFIGFD       = 36, /* pci-assign.configfd */
    QEMU_CAPS_NODEFCONFIG        = 37, /* -nodefconfig */
    QEMU_CAPS_BOOT_MENU          = 38, /* -boot menu=on support */
    QEMU_CAPS_ENABLE_KQEMU       = 39, /* -enable-kqemu flag */
    QEMU_CAPS_FSDEV              = 40, /* -fstype filesystem passthrough */
    QEMU_CAPS_NESTING            = 41, /* -enable-nesting (SVM/VMX) */
    QEMU_CAPS_NAME_PROCESS       = 42, /* Is -name process= available */
    QEMU_CAPS_DRIVE_READONLY     = 43, /* -drive readonly=on|off */
    QEMU_CAPS_SMBIOS_TYPE        = 44, /* Is -smbios type= available */
    QEMU_CAPS_VGA_QXL            = 45, /* The 'qxl' arg for '-vga' */
    QEMU_CAPS_SPICE              = 46, /* Is -spice avail */
    QEMU_CAPS_VGA_NONE           = 47, /* The 'none' arg for '-vga' */
    QEMU_CAPS_MIGRATE_QEMU_FD    = 48, /* -incoming fd:n */
    QEMU_CAPS_BOOTINDEX          = 49, /* -device bootindex property */
    QEMU_CAPS_HDA_DUPLEX         = 50, /* -device hda-duplex */
    QEMU_CAPS_DRIVE_AIO          = 51, /* -drive aio= supported */
    QEMU_CAPS_PCI_MULTIBUS       = 52, /* bus=pci.0 vs bus=pci */
    QEMU_CAPS_PCI_BOOTINDEX      = 53, /* pci-assign.bootindex */
    QEMU_CAPS_CCID_EMULATED      = 54, /* -device ccid-card-emulated */
    QEMU_CAPS_CCID_PASSTHRU      = 55, /* -device ccid-card-passthru */
    QEMU_CAPS_CHARDEV_SPICEVMC   = 56, /* newer -chardev spicevmc */
    QEMU_CAPS_DEVICE_SPICEVMC    = 57, /* older -device spicevmc*/
    QEMU_CAPS_VIRTIO_TX_ALG      = 58, /* -device virtio-net-pci,tx=string */
    QEMU_CAPS_DEVICE_QXL_VGA     = 59, /* primary qxl device named qxl-vga? */
    QEMU_CAPS_PCI_MULTIFUNCTION  = 60, /* -device multifunction=on|off */
    QEMU_CAPS_VIRTIO_IOEVENTFD   = 61, /* virtio-{net|blk}-pci.ioeventfd=on */
    QEMU_CAPS_SGA                = 62, /* Serial Graphics Adapter */
    QEMU_CAPS_VIRTIO_BLK_EVENT_IDX = 63, /* virtio-blk-pci.event_idx */
    QEMU_CAPS_VIRTIO_NET_EVENT_IDX = 64, /* virtio-net-pci.event_idx */
    QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC = 65, /* Is cache=directsync supported? */
    QEMU_CAPS_PIIX3_USB_UHCI     = 66, /* -device piix3-usb-uhci */
    QEMU_CAPS_PIIX4_USB_UHCI     = 67, /* -device piix4-usb-uhci */
    QEMU_CAPS_USB_EHCI           = 68, /* -device usb-ehci */
    QEMU_CAPS_ICH9_USB_EHCI1     = 69, /* -device ich9-usb-ehci1 and friends */
    QEMU_CAPS_VT82C686B_USB_UHCI = 70, /* -device vt82c686b-usb-uhci */
    QEMU_CAPS_PCI_OHCI           = 71, /* -device pci-ohci */
    QEMU_CAPS_USB_REDIR          = 72, /* -device usb-redir */
    QEMU_CAPS_USB_HUB            = 73, /* -device usb-hub */
    QEMU_CAPS_NO_SHUTDOWN        = 74, /* usable -no-shutdown */
    QEMU_CAPS_DRIVE_CACHE_UNSAFE = 75, /* Is cache=unsafe supported? */
    QEMU_CAPS_PCI_ROMBAR         = 76, /* -device rombar=0|1 */
    QEMU_CAPS_ICH9_AHCI          = 77, /* -device ich9-ahci */
    QEMU_CAPS_NO_ACPI            = 78, /* -no-acpi */
    QEMU_CAPS_FSDEV_READONLY     = 79, /* -fsdev readonly supported */
    QEMU_CAPS_VIRTIO_BLK_SCSI    = 80, /* virtio-blk-pci.scsi */
    QEMU_CAPS_VIRTIO_BLK_SG_IO   = 81, /* SG_IO commands, since 0.11 */
    QEMU_CAPS_DRIVE_COPY_ON_READ = 82, /* -drive copy-on-read */
    QEMU_CAPS_CPU_HOST           = 83, /* support for -cpu host */
    QEMU_CAPS_FSDEV_WRITEOUT     = 84, /* -fsdev writeout supported */
    QEMU_CAPS_DRIVE_IOTUNE       = 85, /* -drive bps= and friends */
    QEMU_CAPS_WAKEUP             = 86, /* system_wakeup monitor command */
    QEMU_CAPS_SCSI_DISK_CHANNEL  = 87, /* Is scsi-disk.channel available? */
    QEMU_CAPS_SCSI_BLOCK         = 88, /* -device scsi-block */
    QEMU_CAPS_TRANSACTION        = 89, /* transaction monitor command */
    QEMU_CAPS_BLOCKJOB_SYNC      = 90, /* old block_job_cancel, block_stream */
    QEMU_CAPS_BLOCKJOB_ASYNC     = 91, /* new block-job-cancel, block-stream */
    QEMU_CAPS_SCSI_CD            = 92, /* -device scsi-cd */
    QEMU_CAPS_IDE_CD             = 93, /* -device ide-cd */
    QEMU_CAPS_NO_USER_CONFIG     = 94, /* -no-user-config */
    QEMU_CAPS_HDA_MICRO          = 95, /* -device hda-micro */
    QEMU_CAPS_DUMP_GUEST_MEMORY  = 96, /* dump-guest-memory command */
    QEMU_CAPS_NEC_USB_XHCI       = 97, /* -device nec-usb-xhci */
    QEMU_CAPS_VIRTIO_S390        = 98, /* -device virtio-*-s390 */
    QEMU_CAPS_BALLOON_EVENT      = 99, /* Async event for balloon changes */
    QEMU_CAPS_NETDEV_BRIDGE      = 100, /* bridge helper support */
    QEMU_CAPS_SCSI_LSI           = 101, /* -device lsi */
    QEMU_CAPS_VIRTIO_SCSI        = 102, /* -device virtio-scsi-* */
    QEMU_CAPS_BLOCKIO            = 103, /* -device ...logical_block_size & co */
    QEMU_CAPS_DISABLE_S3         = 104, /* S3 BIOS Advertisement on/off */
    QEMU_CAPS_DISABLE_S4         = 105, /* S4 BIOS Advertisement on/off */
    QEMU_CAPS_USB_REDIR_FILTER   = 106, /* usb-redir.filter */
    QEMU_CAPS_IDE_DRIVE_WWN      = 107, /* Is ide-drive.wwn available? */
    QEMU_CAPS_SCSI_DISK_WWN      = 108, /* Is scsi-disk.wwn available? */
    QEMU_CAPS_SECCOMP_SANDBOX    = 109, /* -sandbox */
    QEMU_CAPS_REBOOT_TIMEOUT     = 110, /* -boot reboot-timeout */
    QEMU_CAPS_DUMP_GUEST_CORE    = 111, /* dump-guest-core-parameter */
    QEMU_CAPS_SEAMLESS_MIGRATION = 112, /* seamless-migration for SPICE */
    QEMU_CAPS_BLOCK_COMMIT       = 113, /* block-commit */
    QEMU_CAPS_VNC                = 114, /* Is -vnc available? */
    QEMU_CAPS_DRIVE_MIRROR       = 115, /* drive-mirror monitor command */
    QEMU_CAPS_USB_REDIR_BOOTINDEX = 116, /* usb-redir.bootindex */
    QEMU_CAPS_USB_HOST_BOOTINDEX = 117, /* usb-host.bootindex */
    QEMU_CAPS_DISK_SNAPSHOT      = 118, /* blockdev-snapshot-sync command */
    QEMU_CAPS_DEVICE_QXL         = 119, /* -device qxl */
    QEMU_CAPS_DEVICE_VGA         = 120, /* -device VGA */
    QEMU_CAPS_DEVICE_CIRRUS_VGA  = 121, /* -device cirrus-vga */
    QEMU_CAPS_DEVICE_VMWARE_SVGA = 122, /* -device vmware-svga */
    QEMU_CAPS_DEVICE_VIDEO_PRIMARY = 123, /* safe to use -device XXX
                                           for primary video device */
    QEMU_CAPS_SCLP_S390          = 124, /* -device sclp* */
    QEMU_CAPS_DEVICE_USB_SERIAL  = 125, /* -device usb-serial */
    QEMU_CAPS_DEVICE_USB_NET     = 126, /* -device usb-net */
    QEMU_CAPS_ADD_FD             = 127, /* -add-fd */
    QEMU_CAPS_NBD_SERVER         = 128, /* nbd-server-start QMP command */
    QEMU_CAPS_DEVICE_VIRTIO_RNG  = 129, /* virtio-rng device */
    QEMU_CAPS_OBJECT_RNG_RANDOM  = 130, /* the rng-random backend for
                                           virtio rng */
    QEMU_CAPS_OBJECT_RNG_EGD     = 131, /* EGD protocol daemon for rng */
    QEMU_CAPS_VIRTIO_CCW         = 132, /* -device virtio-*-ccw */
    QEMU_CAPS_DTB                = 133, /* -dtb file */
    QEMU_CAPS_SCSI_MEGASAS       = 134, /* -device megasas */
    QEMU_CAPS_IPV6_MIGRATION     = 135, /* -incoming [::] */
    QEMU_CAPS_MACHINE_OPT        = 136, /* -machine xxxx*/
    QEMU_CAPS_MACHINE_USB_OPT    = 137, /* -machine xxx,usb=on/off */
    QEMU_CAPS_DEVICE_TPM_PASSTHROUGH = 138, /* -tpmdev passthrough */
    QEMU_CAPS_DEVICE_TPM_TIS     = 139, /* -device tpm_tis */
    QEMU_CAPS_DEVICE_NVRAM       = 140,  /* -global spapr-nvram.reg=xxxx */
    QEMU_CAPS_DEVICE_PCI_BRIDGE  = 141, /* -device pci-bridge */
    QEMU_CAPS_DEVICE_VFIO_PCI    = 142, /* -device vfio-pci */
    QEMU_CAPS_VFIO_PCI_BOOTINDEX = 143, /* bootindex param for vfio-pci device */
    QEMU_CAPS_DEVICE_SCSI_GENERIC = 144,  /* -device scsi-generic */
    QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX = 145,  /* -device scsi-generic.bootindex */
    QEMU_CAPS_MEM_MERGE          = 146, /* -machine mem-merge */
    QEMU_CAPS_VNC_WEBSOCKET      = 147, /* -vnc x:y,websocket */
    QEMU_CAPS_DRIVE_DISCARD      = 148, /* -drive discard=off(ignore)|on(unmap) */
    QEMU_CAPS_MLOCK              = 149, /* -realtime mlock=on|off */
    QEMU_CAPS_VNC_SHARE_POLICY   = 150, /* set display sharing policy */
    QEMU_CAPS_DEVICE_DEL_EVENT   = 151, /* DEVICE_DELETED event */
    QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE  = 152, /* -device i82801b11-bridge */
    QEMU_CAPS_I440FX_PCI_HOLE64_SIZE = 153, /* i440FX-pcihost.pci-hole64-size */
    QEMU_CAPS_Q35_PCI_HOLE64_SIZE = 154, /* q35-pcihost.pci-hole64-size */
    QEMU_CAPS_DEVICE_USB_STORAGE = 155, /* -device usb-storage */
    QEMU_CAPS_USB_STORAGE_REMOVABLE = 156, /* usb-storage.removable */
    QEMU_CAPS_DEVICE_VIRTIO_MMIO = 157, /* -device virtio-mmio */
    QEMU_CAPS_DEVICE_ICH9_INTEL_HDA = 158, /* -device ich9-intel-hda */
    QEMU_CAPS_KVM_PIT_TICK_POLICY = 159, /* kvm-pit.lost_tick_policy */
    QEMU_CAPS_BOOT_STRICT        = 160, /* -boot strict */
    QEMU_CAPS_DEVICE_PANIC       = 161, /* -device pvpanic */
    QEMU_CAPS_ENABLE_FIPS        = 162, /* -enable-fips */
    QEMU_CAPS_SPICE_FILE_XFER_DISABLE = 163, /* -spice disable-agent-file-xfer */
    QEMU_CAPS_CHARDEV_SPICEPORT  = 164, /* -chardev spiceport */
    QEMU_CAPS_DEVICE_USB_KBD     = 165, /* -device usb-kbd */
    QEMU_CAPS_HOST_PCI_MULTIDOMAIN = 166, /* support domain > 0 in host pci address */
    QEMU_CAPS_MSG_TIMESTAMP      = 167, /* -msg timestamp */
    QEMU_CAPS_ACTIVE_COMMIT      = 168, /* block-commit works without 'top' */
    QEMU_CAPS_CHANGE_BACKING_FILE = 169, /* change name of backing file in metadata */
    QEMU_CAPS_OBJECT_MEMORY_RAM  = 170, /* -object memory-backend-ram */
    QEMU_CAPS_NUMA               = 171, /* newer -numa handling with disjoint cpu ranges */
    QEMU_CAPS_OBJECT_MEMORY_FILE = 172, /* -object memory-backend-file */
    QEMU_CAPS_OBJECT_USB_AUDIO   = 173, /* usb-audio device support */
    QEMU_CAPS_RTC_RESET_REINJECTION = 174, /* rtc-reset-reinjection monitor command */
    QEMU_CAPS_SPLASH_TIMEOUT     = 175, /* -boot splash-time */
    QEMU_CAPS_OBJECT_IOTHREAD    = 176, /* -object iothread */
    QEMU_CAPS_MIGRATE_RDMA       = 177, /* have rdma migration */
    QEMU_CAPS_DEVICE_IVSHMEM     = 178, /* -device ivshmem */
    QEMU_CAPS_DRIVE_IOTUNE_MAX   = 179, /* -drive bps_max= and friends */
    QEMU_CAPS_VGA_VGAMEM         = 180, /* -device VGA.vgamem_mb */
    QEMU_CAPS_VMWARE_SVGA_VGAMEM = 181, /* -device vmware-svga.vgamem_mb */
    QEMU_CAPS_QXL_VGAMEM         = 182, /* -device qxl.vgamem_mb */
    QEMU_CAPS_QXL_VGA_VGAMEM     = 183, /* -device qxl-vga.vgamem_mb */

    QEMU_CAPS_LAST,                   /* this must always be the last item */
} virQEMUCapsFlags;

typedef struct _virQEMUCaps virQEMUCaps;
typedef virQEMUCaps *virQEMUCapsPtr;

typedef struct _virQEMUCapsCache virQEMUCapsCache;
typedef virQEMUCapsCache *virQEMUCapsCachePtr;

virQEMUCapsPtr virQEMUCapsNew(void);
virQEMUCapsPtr virQEMUCapsNewCopy(virQEMUCapsPtr qemuCaps);
virQEMUCapsPtr virQEMUCapsNewForBinary(const char *binary,
                                       const char *libDir,
                                       const char *cacheDir,
                                       uid_t runUid,
                                       gid_t runGid);

int virQEMUCapsInitQMPMonitor(virQEMUCapsPtr qemuCaps,
                              qemuMonitorPtr mon);

int virQEMUCapsProbeQMP(virQEMUCapsPtr qemuCaps,
                        qemuMonitorPtr mon);

void virQEMUCapsSet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

void virQEMUCapsSetList(virQEMUCapsPtr qemuCaps, ...) ATTRIBUTE_NONNULL(1);

void virQEMUCapsClear(virQEMUCapsPtr qemuCaps,
                      virQEMUCapsFlags flag) ATTRIBUTE_NONNULL(1);

bool virQEMUCapsGet(virQEMUCapsPtr qemuCaps,
                    virQEMUCapsFlags flag);

bool virQEMUCapsHasPCIMultiBus(virQEMUCapsPtr qemuCaps,
                               virDomainDefPtr def);

char *virQEMUCapsFlagsString(virQEMUCapsPtr qemuCaps);

const char *virQEMUCapsGetBinary(virQEMUCapsPtr qemuCaps);
virArch virQEMUCapsGetArch(virQEMUCapsPtr qemuCaps);
unsigned int virQEMUCapsGetVersion(virQEMUCapsPtr qemuCaps);
unsigned int virQEMUCapsGetKVMVersion(virQEMUCapsPtr qemuCaps);
int virQEMUCapsAddCPUDefinition(virQEMUCapsPtr qemuCaps,
                                const char *name);
size_t virQEMUCapsGetCPUDefinitions(virQEMUCapsPtr qemuCaps,
                                    char ***names);
size_t virQEMUCapsGetMachineTypes(virQEMUCapsPtr qemuCaps,
                                  char ***names);
const char *virQEMUCapsGetCanonicalMachine(virQEMUCapsPtr qemuCaps,
                                           const char *name);
int virQEMUCapsGetMachineMaxCpus(virQEMUCapsPtr qemuCaps,
                                 const char *name);
int virQEMUCapsGetMachineTypesCaps(virQEMUCapsPtr qemuCaps,
                                   size_t *nmachines,
                                   virCapsGuestMachinePtr **machines);

bool virQEMUCapsIsValid(virQEMUCapsPtr qemuCaps);


virQEMUCapsCachePtr virQEMUCapsCacheNew(const char *libDir,
                                        const char *cacheDir,
                                        uid_t uid, gid_t gid);
virQEMUCapsPtr virQEMUCapsCacheLookup(virQEMUCapsCachePtr cache,
                                      const char *binary);
virQEMUCapsPtr virQEMUCapsCacheLookupCopy(virQEMUCapsCachePtr cache,
                                          const char *binary);
virQEMUCapsPtr virQEMUCapsCacheLookupByArch(virQEMUCapsCachePtr cache,
                                            virArch arch);
void virQEMUCapsCacheFree(virQEMUCapsCachePtr cache);

virCapsPtr virQEMUCapsInit(virQEMUCapsCachePtr cache);

int virQEMUCapsGetDefaultVersion(virCapsPtr caps,
                                 virQEMUCapsCachePtr capsCache,
                                 unsigned int *version);

/* Only for use by test suite */
int virQEMUCapsParseHelpStr(const char *qemu,
                            const char *str,
                            virQEMUCapsPtr qemuCaps,
                            unsigned int *version,
                            bool *is_kvm,
                            unsigned int *kvm_version,
                            bool check_yajl,
                            const char *qmperr);
/* Only for use by test suite */
int virQEMUCapsParseDeviceStr(virQEMUCapsPtr qemuCaps, const char *str);

VIR_ENUM_DECL(virQEMUCaps);

bool virQEMUCapsUsedQMP(virQEMUCapsPtr qemuCaps);
bool virQEMUCapsSupportsChardev(virDomainDefPtr def,
                                virQEMUCapsPtr qemuCaps,
                                virDomainChrDefPtr chr);

bool virQEMUCapsIsMachineSupported(virQEMUCapsPtr qemuCaps,
                                   const char *canonical_machine);

const char *virQEMUCapsGetDefaultMachine(virQEMUCapsPtr qemuCaps);

int virQEMUCapsInitGuestFromBinary(virCapsPtr caps,
                                   const char *binary,
                                   virQEMUCapsPtr qemubinCaps,
                                   const char *kvmbin,
                                   virQEMUCapsPtr kvmbinCaps,
                                   virArch guestarch);

int virQEMUCapsFillDomainCaps(virDomainCapsPtr domCaps,
                              virQEMUCapsPtr qemuCaps,
                              char **loader,
                              size_t nloader);

#endif /* __QEMU_CAPABILITIES_H__*/
