/*
 * qemu_capabilities.h: QEMU capabilities generation
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_CAPABILITIES_H__
# define __QEMU_CAPABILITIES_H__

# include "bitmap.h"
# include "capabilities.h"

/* Internal flags to keep track of qemu command line capabilities */
enum qemuCapsFlags {
    QEMU_CAPS_KQEMU             =  0, /* Whether KQEMU is compiled in */
    QEMU_CAPS_VNC_COLON         =  1, /* Does the VNC take just port, or address + display */
    QEMU_CAPS_NO_REBOOT         =  2, /* Is the -no-reboot flag available */
    QEMU_CAPS_DRIVE             =  3, /* Is the new -drive arg available */
    QEMU_CAPS_DRIVE_BOOT        =  4, /* Does -drive support boot=on */
    QEMU_CAPS_NAME              =  5, /* Is the -name flag available */
    QEMU_CAPS_UUID              =  6, /* Is the -uuid flag available */
    QEMU_CAPS_DOMID             =  7, /* Xenner only, special -domid flag available */
    QEMU_CAPS_VNET_HDR          =  8,
    QEMU_CAPS_MIGRATE_KVM_STDIO =  9, /* Original migration code from KVM. Also had tcp, but we can't use that
                                       * since it had a design bug blocking the entire monitor console */
    QEMU_CAPS_MIGRATE_QEMU_TCP  = 10, /* New migration syntax after merge to QEMU with TCP transport */
    QEMU_CAPS_MIGRATE_QEMU_EXEC = 11, /* New migration syntax after merge to QEMU with EXEC transport */
    QEMU_CAPS_DRIVE_CACHE_V2    = 12, /* Is the cache= flag wanting new v2 values */
    QEMU_CAPS_KVM               = 13, /* Whether KVM is compiled in */
    QEMU_CAPS_DRIVE_FORMAT      = 14, /* Is -drive format= avail */
    QEMU_CAPS_VGA               = 15, /* Is -vga avail */

    /* features added in qemu-0.10.0 or later */
    QEMU_CAPS_0_10              = 16,
    QEMU_CAPS_NET_NAME          = QEMU_CAPS_0_10, /* -net ...,name=str */
    QEMU_CAPS_HOST_NET_ADD      = QEMU_CAPS_0_10, /* host_net_add monitor command */

    QEMU_CAPS_PCIDEVICE         = 17, /* PCI device assignment only supported by qemu-kvm */
    QEMU_CAPS_MEM_PATH          = 18, /* mmap'ped guest backing supported */
    QEMU_CAPS_DRIVE_SERIAL      = 19, /* -driver serial=  available */
    QEMU_CAPS_XEN_DOMID         = 20, /* -xen-domid (new style xen integration) */
    QEMU_CAPS_MIGRATE_QEMU_UNIX = 21, /* Does qemu support unix domain sockets for migration? */
    QEMU_CAPS_CHARDEV           = 22, /* Is the new -chardev arg available */
    QEMU_CAPS_ENABLE_KVM        = 23, /* Is the -enable-kvm flag available to "enable KVM full virtualization support" */
    QEMU_CAPS_MONITOR_JSON      = 24, /* JSON mode for monitor */
    QEMU_CAPS_BALLOON           = 25, /* -balloon available */
    QEMU_CAPS_DEVICE            = 26, /* Is the new -device arg available */
    QEMU_CAPS_SDL               = 27, /* Is the new -sdl arg available */
    QEMU_CAPS_SMP_TOPOLOGY      = 28, /* Is sockets=s,cores=c,threads=t available for -smp? */
    QEMU_CAPS_NETDEV            = 29, /* The -netdev flag & netdev_add/remove monitor commands */
    QEMU_CAPS_RTC               = 30, /* The -rtc flag for clock options */
    QEMU_CAPS_VHOST_NET         = 31, /* vhost-net support is available in qemu */
    QEMU_CAPS_RTC_TD_HACK       = 32, /* -rtc-td-hack available */
    QEMU_CAPS_NO_HPET           = 33, /* -no-hpet flag is supported */
    QEMU_CAPS_NO_KVM_PIT        = 34, /* -no-kvm-pit-reinjection supported */
    QEMU_CAPS_TDF               = 35, /* -tdf flag (user-mode pit catchup) */
    QEMU_CAPS_PCI_CONFIGFD      = 36, /* pci-assign.configfd */
    QEMU_CAPS_NODEFCONFIG       = 37, /* -nodefconfig */
    QEMU_CAPS_BOOT_MENU         = 38, /* -boot menu=on support */
    QEMU_CAPS_ENABLE_KQEMU      = 39, /* -enable-kqemu flag */
    QEMU_CAPS_FSDEV             = 40, /* -fstype filesystem passthrough */
    QEMU_CAPS_NESTING           = 41, /* -enable-nesting (SVM/VMX) */
    QEMU_CAPS_NAME_PROCESS      = 42, /* Is -name process= available */
    QEMU_CAPS_DRIVE_READONLY    = 43, /* -drive readonly=on|off */
    QEMU_CAPS_SMBIOS_TYPE       = 44, /* Is -smbios type= available */
    QEMU_CAPS_VGA_QXL           = 45, /* The 'qxl' arg for '-vga' */
    QEMU_CAPS_SPICE             = 46, /* Is -spice avail */
    QEMU_CAPS_VGA_NONE          = 47, /* The 'none' arg for '-vga' */
    QEMU_CAPS_MIGRATE_QEMU_FD   = 48, /* -incoming fd:n */
    QEMU_CAPS_BOOTINDEX         = 49, /* -device bootindex property */
    QEMU_CAPS_HDA_DUPLEX        = 50, /* -device hda-duplex */
    QEMU_CAPS_DRIVE_AIO         = 51, /* -drive aio= supported */
    QEMU_CAPS_PCI_MULTIBUS      = 52, /* bus=pci.0 vs bus=pci */
    QEMU_CAPS_PCI_BOOTINDEX     = 53, /* pci-assign.bootindex */
    QEMU_CAPS_CCID_EMULATED     = 54, /* -device ccid-card-emulated */
    QEMU_CAPS_CCID_PASSTHRU     = 55, /* -device ccid-card-passthru */
    QEMU_CAPS_CHARDEV_SPICEVMC  = 56, /* newer -chardev spicevmc */
    QEMU_CAPS_DEVICE_SPICEVMC   = 57, /* older -device spicevmc*/
    QEMU_CAPS_VIRTIO_TX_ALG     = 58, /* -device virtio-net-pci,tx=string */
    QEMU_CAPS_DEVICE_QXL_VGA    = 59, /* Is the primary and vga campatible qxl device named qxl-vga? */
    QEMU_CAPS_PCI_MULTIFUNCTION = 60, /* -device multifunction=on|off */
    QEMU_CAPS_VIRTIO_IOEVENTFD  = 61, /* IOeventFD feature: virtio-{net|blk}-pci.ioeventfd=on/off */

    QEMU_CAPS_LAST,                   /* this must always be the last item */
};

virBitmapPtr qemuCapsNew(void);

# define qemuCapsFree(caps)  virBitmapFree(caps)

void qemuCapsSet(virBitmapPtr caps,
                 enum qemuCapsFlags flag) ATTRIBUTE_NONNULL(1);

void qemuCapsSetList(virBitmapPtr caps, ...) ATTRIBUTE_NONNULL(1);

void qemuCapsClear(virBitmapPtr caps,
                   enum qemuCapsFlags flag) ATTRIBUTE_NONNULL(1);

bool qemuCapsGet(virBitmapPtr caps,
                 enum qemuCapsFlags flag);

virCapsPtr qemuCapsInit(virCapsPtr old_caps);

int qemuCapsProbeMachineTypes(const char *binary,
                              virCapsGuestMachinePtr **machines,
                              int *nmachines);

int qemuCapsProbeCPUModels(const char *qemu,
                           virBitmapPtr qemuCaps,
                           const char *arch,
                           unsigned int *count,
                           const char ***cpus);

int qemuCapsExtractVersion(virCapsPtr caps,
                           unsigned int *version);
int qemuCapsExtractVersionInfo(const char *qemu, const char *arch,
                               unsigned int *version,
                               virBitmapPtr *qemuCaps);

int qemuCapsParseHelpStr(const char *qemu,
                         const char *str,
                         virBitmapPtr qemuCaps,
                         unsigned int *version,
                         unsigned int *is_kvm,
                         unsigned int *kvm_version);
int qemuCapsParseDeviceStr(const char *str,
                           virBitmapPtr qemuCaps);

VIR_ENUM_DECL(qemuCaps);

#endif /* __QEMU_CAPABILITIES_H__*/
