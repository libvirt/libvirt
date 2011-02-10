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

# include "capabilities.h"

/* Internal flags to keep track of qemu command line capabilities */
enum qemuCapsFlags {
    QEMUD_CMD_FLAG_KQEMU          = (1 << 0), /* Whether KQEMU is compiled in */
    QEMUD_CMD_FLAG_VNC_COLON      = (1 << 1), /* Does the VNC take just port, or address + display */
    QEMUD_CMD_FLAG_NO_REBOOT      = (1 << 2), /* Is the -no-reboot flag available */
    QEMUD_CMD_FLAG_DRIVE          = (1 << 3), /* Is the new -drive arg available */
    QEMUD_CMD_FLAG_DRIVE_BOOT     = (1 << 4), /* Does -drive support boot=on */
    QEMUD_CMD_FLAG_NAME           = (1 << 5), /* Is the -name flag available */
    QEMUD_CMD_FLAG_UUID           = (1 << 6), /* Is the -uuid flag available */
    QEMUD_CMD_FLAG_DOMID          = (1 << 7), /* Xenner only, special -domid flag available */
    QEMUD_CMD_FLAG_VNET_HDR        = (1 << 8),
    QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO = (1 << 9),  /* Original migration code from KVM. Also had tcp, but we can't use that
                                                   * since it had a design bug blocking the entire monitor console */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP  = (1 << 10), /* New migration syntax after merge to QEMU with TCP transport */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC = (1 << 11), /* New migration syntax after merge to QEMU with EXEC transport */
    QEMUD_CMD_FLAG_DRIVE_CACHE_V2    = (1 << 12), /* Is the cache= flag wanting new v2 values */
    QEMUD_CMD_FLAG_KVM               = (1 << 13), /* Whether KVM is compiled in */
    QEMUD_CMD_FLAG_DRIVE_FORMAT      = (1 << 14), /* Is -drive format= avail */
    QEMUD_CMD_FLAG_VGA               = (1 << 15), /* Is -vga avail */

    /* features added in qemu-0.10.0 or later */
    QEMUD_CMD_FLAG_0_10         = (1 << 16),
    QEMUD_CMD_FLAG_NET_NAME     = QEMUD_CMD_FLAG_0_10, /* -net ...,name=str */
    QEMUD_CMD_FLAG_HOST_NET_ADD = QEMUD_CMD_FLAG_0_10, /* host_net_add monitor command */

    QEMUD_CMD_FLAG_PCIDEVICE     = (1 << 17), /* PCI device assignment only supported by qemu-kvm */
    QEMUD_CMD_FLAG_MEM_PATH      = (1 << 18), /* mmap'ped guest backing supported */
    QEMUD_CMD_FLAG_DRIVE_SERIAL  = (1 << 19), /* -driver serial=  available */
    QEMUD_CMD_FLAG_XEN_DOMID     = (1 << 20), /* -xen-domid (new style xen integration) */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_UNIX = (1 << 21), /* Does qemu support unix domain sockets for migration? */
    QEMUD_CMD_FLAG_CHARDEV       = (1 << 22), /* Is the new -chardev arg available */
    QEMUD_CMD_FLAG_ENABLE_KVM    = (1 << 23), /* Is the -enable-kvm flag available to "enable KVM full virtualization support" */
    QEMUD_CMD_FLAG_MONITOR_JSON  = (1 << 24), /* JSON mode for monitor */
    QEMUD_CMD_FLAG_BALLOON       = (1 << 25), /* -balloon available */
    QEMUD_CMD_FLAG_DEVICE        = (1 << 26), /* Is the new -device arg available */
    QEMUD_CMD_FLAG_SDL           = (1 << 27), /* Is the new -sdl arg available */
    QEMUD_CMD_FLAG_SMP_TOPOLOGY  = (1 << 28), /* Is sockets=s,cores=c,threads=t available for -smp? */
    QEMUD_CMD_FLAG_NETDEV        = (1 << 29), /* The -netdev flag & netdev_add/remove monitor commands */
    QEMUD_CMD_FLAG_RTC           = (1 << 30), /* The -rtc flag for clock options */
    QEMUD_CMD_FLAG_VNET_HOST     = (1LL << 31), /* vnet-host support is available in qemu */
    QEMUD_CMD_FLAG_RTC_TD_HACK   = (1LL << 32), /* -rtc-td-hack available */
    QEMUD_CMD_FLAG_NO_HPET       = (1LL << 33), /* -no-hpet flag is supported */
    QEMUD_CMD_FLAG_NO_KVM_PIT    = (1LL << 34), /* -no-kvm-pit-reinjection supported */
    QEMUD_CMD_FLAG_TDF           = (1LL << 35), /* -tdf flag (user-mode pit catchup) */
    QEMUD_CMD_FLAG_PCI_CONFIGFD  = (1LL << 36), /* pci-assign.configfd */
    QEMUD_CMD_FLAG_NODEFCONFIG   = (1LL << 37), /* -nodefconfig */
    QEMUD_CMD_FLAG_BOOT_MENU     = (1LL << 38), /* -boot menu=on support */
    QEMUD_CMD_FLAG_ENABLE_KQEMU  = (1LL << 39), /* -enable-kqemu flag */
    QEMUD_CMD_FLAG_FSDEV         = (1LL << 40), /* -fstype filesystem passthrough */
    QEMUD_CMD_FLAG_NESTING       = (1LL << 41), /* -enable-nesting (SVM/VMX) */
    QEMUD_CMD_FLAG_NAME_PROCESS  = (1LL << 42), /* Is -name process= available */
    QEMUD_CMD_FLAG_DRIVE_READONLY= (1LL << 43), /* -drive readonly=on|off */
    QEMUD_CMD_FLAG_SMBIOS_TYPE   = (1LL << 44), /* Is -smbios type= available */
    QEMUD_CMD_FLAG_VGA_QXL       = (1LL << 45), /* The 'qxl' arg for '-vga' */
    QEMUD_CMD_FLAG_SPICE         = (1LL << 46), /* Is -spice avail */
    QEMUD_CMD_FLAG_VGA_NONE      = (1LL << 47), /* The 'none' arg for '-vga' */
    QEMUD_CMD_FLAG_MIGRATE_QEMU_FD = (1LL << 48), /* -incoming fd:n */
    QEMUD_CMD_FLAG_BOOTINDEX     = (1LL << 49), /* -device bootindex property */
    QEMUD_CMD_FLAG_HDA_DUPLEX    = (1LL << 50), /* -device hda-duplex */
    QEMUD_CMD_FLAG_DRIVE_AIO     = (1LL << 51), /* -drive aio= supported */
    QEMUD_CMD_FLAG_PCI_MULTIBUS  = (1LL << 52), /* bus=pci.0 vs bus=pci */
    QEMUD_CMD_FLAG_PCI_BOOTINDEX = (1LL << 53), /* pci-assign.bootindex */
    QEMUD_CMD_FLAG_CCID_EMULATED = (1LL << 54), /* -device ccid-card-emulated */
    QEMUD_CMD_FLAG_CCID_PASSTHRU = (1LL << 55), /* -device ccid-card-passthru */
    QEMUD_CMD_FLAG_CHARDEV_SPICEVMC = (1LL << 56), /* newer -chardev spicevmc */
    QEMUD_CMD_FLAG_DEVICE_SPICEVMC = (1LL << 57), /* older -device spicevmc*/
};

virCapsPtr qemuCapsInit(virCapsPtr old_caps);

int qemuCapsProbeMachineTypes(const char *binary,
                              virCapsGuestMachinePtr **machines,
                              int *nmachines);

int qemuCapsProbeCPUModels(const char *qemu,
                           unsigned long long qemuCmdFlags,
                           const char *arch,
                           unsigned int *count,
                           const char ***cpus);

int qemuCapsExtractVersion(virCapsPtr caps,
                           unsigned int *version);
int qemuCapsExtractVersionInfo(const char *qemu, const char *arch,
                               unsigned int *version,
                               unsigned long long *qemuCmdFlags);

int qemuCapsParseHelpStr(const char *qemu,
                         const char *str,
                         unsigned long long *qemuCmdFlags,
                         unsigned int *version,
                         unsigned int *is_kvm,
                         unsigned int *kvm_version);
int qemuCapsParseDeviceStr(const char *str,
                           unsigned long long *qemuCmdFlags);


#endif /* __QEMU_CAPABILITIES_H__*/
