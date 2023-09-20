/*
 * qemu_validate.c: QEMU general validation functions
 *
 * Copyright IBM Corp, 2020
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

#include "qemu_validate.h"
#include "qemu_block.h"
#include "qemu_command.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "domain_conf.h"
#include "virbitmap.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU
#define QEMU_MAX_VCPUS_WITHOUT_EIM 255

VIR_LOG_INIT("qemu.qemu_validate");


static int
qemuValidateDomainDefPSeriesFeature(const virDomainDef *def,
                                    int feature)
{
    if (def->features[feature] == VIR_TRISTATE_SWITCH_ABSENT)
        return 0;

    if (!qemuDomainIsPSeries(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The '%1$s' feature is not supported for architecture '%2$s' or machine type '%3$s'"),
                       virDomainFeatureTypeToString(feature),
                       virArchToString(def->os.arch),
                       def->os.machine);
        return -1;
    }

    switch (feature) {
    case VIR_DOMAIN_FEATURE_HPT:
        if (def->features[feature] != VIR_TRISTATE_SWITCH_ON)
            break;

        if (def->hpt_resizing != VIR_DOMAIN_HPT_RESIZING_NONE) {
            if (!virDomainHPTResizingTypeToString(def->hpt_resizing)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid setting for HPT resizing"));
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_FEATURE_HTM:
    case VIR_DOMAIN_FEATURE_NESTED_HV:
    case VIR_DOMAIN_FEATURE_CCF_ASSIST:
        if (!virTristateSwitchTypeToString(def->features[feature])) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid setting for pseries feature '%1$s'"),
                           virDomainFeatureTypeToString(feature));

            return -1;
        }
        break;

    case VIR_DOMAIN_FEATURE_CFPC:
    case VIR_DOMAIN_FEATURE_SBBC:
    case VIR_DOMAIN_FEATURE_IBS:
        break;
    }

    return 0;
}


static int
qemuValidateDomainDefFeatures(const virDomainDef *def,
                              virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        const char *featureName = virDomainFeatureTypeToString(i);

        switch ((virDomainFeature) i) {
        case VIR_DOMAIN_FEATURE_IOAPIC:
            if (def->features[i] != VIR_DOMAIN_IOAPIC_NONE) {
                if (!ARCH_IS_X86(def->os.arch)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("The '%1$s' feature is not supported for architecture '%2$s' or machine type '%3$s'"),
                                   featureName,
                                   virArchToString(def->os.arch),
                                   def->os.machine);
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_FEATURE_HPT:
        case VIR_DOMAIN_FEATURE_HTM:
        case VIR_DOMAIN_FEATURE_NESTED_HV:
        case VIR_DOMAIN_FEATURE_CCF_ASSIST:
        case VIR_DOMAIN_FEATURE_CFPC:
        case VIR_DOMAIN_FEATURE_SBBC:
        case VIR_DOMAIN_FEATURE_IBS:
            if (qemuValidateDomainDefPSeriesFeature(def, i) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_GIC:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON &&
                !qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The '%1$s' feature is not supported for architecture '%2$s' or machine type '%3$s'"),
                               featureName,
                               virArchToString(def->os.arch),
                               def->os.machine);
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_VMPORT:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                !virQEMUCapsSupportsVmport(qemuCaps, def)) {

                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vmport is not available with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_VMCOREINFO:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMCOREINFO)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                              _("vmcoreinfo is not available with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_APIC:
            /* The kvm_pv_eoi feature is x86-only. */
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                def->apic_eoi != VIR_TRISTATE_SWITCH_ABSENT &&
                !ARCH_IS_X86(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The 'eoi' attribute of the '%1$s' feature is not supported for architecture '%2$s' or machine type '%3$s'"),
                                 featureName,
                                 virArchToString(def->os.arch),
                                 def->os.machine);
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_PVSPINLOCK:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                !ARCH_IS_X86(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The '%1$s' feature is not supported for architecture '%2$s' or machine type '%3$s'"),
                                 featureName,
                                 virArchToString(def->os.arch),
                                 def->os.machine);
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_HYPERV:
            if (def->features[i] != VIR_DOMAIN_HYPERV_MODE_NONE &&
                !ARCH_IS_X86(def->os.arch) && !qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Hyperv features are not supported for architecture '%1$s' or machine type '%2$s'"),
                                 virArchToString(def->os.arch),
                                 def->os.machine);
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_PMU:
            if (def->features[i] == VIR_TRISTATE_SWITCH_OFF &&
                ARCH_IS_PPC64(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PMU is always enabled for architecture '%1$s'"),
                                 virArchToString(def->os.arch));
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_TCG:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON) {
                if (def->virtType != VIR_DOMAIN_VIRT_QEMU) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("TCG features are incompatible with domain type '%1$s'"),
                                   virDomainVirtTypeToString(def->virtType));
                    return -1;
                }

                if ((def->tcg_features->tb_cache & 0x3ff) != 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("tb-cache size must be an integer multiple of MiB"));
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_FEATURE_ASYNC_TEARDOWN:
            if (def->features[i] == VIR_TRISTATE_BOOL_YES &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_RUN_WITH_ASYNC_TEARDOWN)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                              _("asynchronous teardown is not available with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_SMM:
        case VIR_DOMAIN_FEATURE_KVM:
        case VIR_DOMAIN_FEATURE_XEN:
        case VIR_DOMAIN_FEATURE_ACPI:
        case VIR_DOMAIN_FEATURE_PAE:
        case VIR_DOMAIN_FEATURE_HAP:
        case VIR_DOMAIN_FEATURE_VIRIDIAN:
        case VIR_DOMAIN_FEATURE_PRIVNET:
        case VIR_DOMAIN_FEATURE_CAPABILITIES:
        case VIR_DOMAIN_FEATURE_MSRS:
        case VIR_DOMAIN_FEATURE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefCpu(virQEMUDriver *driver,
                         const virDomainDef *def,
                         virQEMUCaps *qemuCaps)
{
    virCPUDef *cpu = def->cpu;

    if (!cpu)
        return 0;

    if (cpu->addr) {
        const virCPUMaxPhysAddrDef *addr = cpu->addr;

        if (!ARCH_IS_X86(def->os.arch)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CPU maximum physical address bits specification is not supported for '%1$s' architecture"),
                           virArchToString(def->os.arch));
            return -1;
        }

        switch (addr->mode) {
        case VIR_CPU_MAX_PHYS_ADDR_MODE_PASSTHROUGH:
            if (addr->bits != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("CPU maximum physical address bits number specification cannot be used with mode='%1$s'"),
                               virCPUMaxPhysAddrModeTypeToString(VIR_CPU_MAX_PHYS_ADDR_MODE_PASSTHROUGH));
                return -1;
            }
            break;

        case VIR_CPU_MAX_PHYS_ADDR_MODE_EMULATE:
            if (driver->hostcpu &&
                driver->hostcpu->addr &&
                cpu->addr->bits > driver->hostcpu->addr->bits) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("The number of virtual CPU address bits cannot exceed the number supported by the host CPU"));
                return -1;
            }
            break;

        case VIR_CPU_MAX_PHYS_ADDR_MODE_LAST:
            break;
        }
    }

    if (def->cpu->cache) {
        virCPUCacheDef *cache = def->cpu->cache;

        if (!ARCH_IS_X86(def->os.arch)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CPU cache specification is not supported for '%1$s' architecture"),
                           virArchToString(def->os.arch));
            return -1;
        }

        switch (cache->mode) {
        case VIR_CPU_CACHE_MODE_EMULATE:
            if (cache->level != 3) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("CPU cache mode '%1$s' can only be used with level='3'"),
                               virCPUCacheModeTypeToString(cache->mode));
                return -1;
            }
            break;

        case VIR_CPU_CACHE_MODE_PASSTHROUGH:
            if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH &&
                def->cpu->mode != VIR_CPU_MODE_MAXIMUM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("CPU cache mode '%1$s' can only be used with '%2$s' / '%3$s' CPUs"),
                               virCPUCacheModeTypeToString(cache->mode),
                               virCPUModeTypeToString(VIR_CPU_MODE_HOST_PASSTHROUGH),
                               virCPUModeTypeToString(VIR_CPU_MODE_MAXIMUM));
                return -1;
            }

            if (cache->level != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported CPU cache level for mode '%1$s'"),
                               virCPUCacheModeTypeToString(cache->mode));
                return -1;
            }
            break;

        case VIR_CPU_CACHE_MODE_DISABLE:
            if (cache->level != -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported CPU cache level for mode '%1$s'"),
                               virCPUCacheModeTypeToString(cache->mode));
                return -1;
            }
            break;

        case VIR_CPU_CACHE_MODE_LAST:
            break;
        }
    }

    if (cpu->model || cpu->mode != VIR_CPU_MODE_CUSTOM) {
        switch ((virCPUMode) cpu->mode) {
        case VIR_CPU_MODE_HOST_PASSTHROUGH:
            if (cpu->migratable &&
                cpu->migratable != VIR_TRISTATE_SWITCH_OFF &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MIGRATABLE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Migratable attribute for host-passthrough CPU is not supported by this QEMU binary"));
                return -1;
            }
            break;

        case VIR_CPU_MODE_HOST_MODEL:
            /* qemu_command.c will error out if cpu->mode is HOST_MODEL for
             * every arch but PPC64. However, we can't move this validation
             * here because non-PPC64 archs will translate HOST_MODEL to
             * something else during domain start, changing cpu->mode to
             * CUSTOM.
             */
            break;

        case VIR_CPU_MODE_MAXIMUM:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MAX)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("maximum CPU is not supported by QEMU binary"));
                return -1;
            }
            break;

        case VIR_CPU_MODE_CUSTOM:
        case VIR_CPU_MODE_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefIOThreads(const virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    size_t i;
    bool needsThreadPoolCap = false;

    for (i = 0; i < def->niothreadids; i++) {
        virDomainIOThreadIDDef *iothread = def->iothreadids[i];

        if (iothread->thread_pool_min != -1 || iothread->thread_pool_max != -1) {
            needsThreadPoolCap = true;
            break;
        }
    }

    if (def->defaultIOThread &&
        (def->defaultIOThread->thread_pool_min >= 0 ||
         def->defaultIOThread->thread_pool_max >= 0)) {
        needsThreadPoolCap = true;
    }

    if (needsThreadPoolCap &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_IOTHREAD_THREAD_POOL_MAX)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("thread_pool_min and thread_pool_max is not supported by this QEMU binary"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDefClockTimers(const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDef *timer = def->clock.timers[i];

        switch ((virDomainTimerNameType)timer->name) {
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%1$s'"),
                           virDomainTimerNameTypeToString(timer->name));
            return -1;

        case VIR_DOMAIN_TIMER_NAME_TSC:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
            if (!ARCH_IS_X86(def->os.arch) && timer->present == VIR_TRISTATE_BOOL_YES) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Configuring the '%1$s' timer is not supported for virtType=%2$s arch=%3$s machine=%4$s guests"),
                               virDomainTimerNameTypeToString(timer->name),
                               virDomainVirtTypeToString(def->virtType),
                               virArchToString(def->os.arch),
                               def->os.machine);
                return -1;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;

        case VIR_DOMAIN_TIMER_NAME_RTC:
            switch (timer->track) {
            case VIR_DOMAIN_TIMER_TRACK_NONE: /* unspecified - use hypervisor default */
            case VIR_DOMAIN_TIMER_TRACK_GUEST:
            case VIR_DOMAIN_TIMER_TRACK_WALL:
            case VIR_DOMAIN_TIMER_TRACK_REALTIME:
                break;
            case VIR_DOMAIN_TIMER_TRACK_BOOT:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported rtc timer track '%1$s'"),
                               virDomainTimerTrackTypeToString(timer->track));
                return -1;
            case VIR_DOMAIN_TIMER_TRACK_LAST:
                break;
            }

            switch (timer->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* This is the default - missed ticks delivered when
                   next scheduled, at normal rate */
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                /* deliver ticks at a faster rate until caught up */
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported rtc timer tickpolicy '%1$s'"),
                               virDomainTimerTickpolicyTypeToString(
                                   timer->tickpolicy));
                return -1;
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PIT:
            switch (timer->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM_PIT_TICK_POLICY)) {
                    /* can't catchup if we don't have kvm-pit */
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported pit tickpolicy '%1$s'"),
                                   virDomainTimerTickpolicyTypeToString(
                                       timer->tickpolicy));
                    return -1;
                }
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
                /* no way to support this mode for pit in qemu */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported pit tickpolicy '%1$s'"),
                               virDomainTimerTickpolicyTypeToString(
                                   timer->tickpolicy));
                return -1;
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            if (timer->present == VIR_TRISTATE_BOOL_YES) {
                if (def->os.arch != VIR_ARCH_I686 &&
                    def->os.arch != VIR_ARCH_X86_64) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("hpet timer is not supported by this architecture"));
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
            if (def->virtType != VIR_DOMAIN_VIRT_KVM ||
                !qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Configuring the '%1$s' timer is not supported for virtType=%2$s arch=%3$s machine=%4$s guests"),
                               virDomainTimerNameTypeToString(timer->name),
                               virDomainVirtTypeToString(def->virtType),
                               virArchToString(def->os.arch),
                               def->os.machine);
                return -1;
            }
            if (timer->present == VIR_TRISTATE_BOOL_NO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The '%1$s' timer can't be disabled"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_KVM_NO_ADJVTIME)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Configuring the '%1$s' timer is not supported with this QEMU binary"),
                               virDomainTimerNameTypeToString(timer->name));
                return -1;
            }

            switch (timer->tickpolicy) {
            case VIR_DOMAIN_TIMER_TICKPOLICY_NONE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The '%1$s' timer does not support tickpolicy '%2$s'"),
                               virDomainTimerNameTypeToString(timer->name),
                               virDomainTimerTickpolicyTypeToString(timer->tickpolicy));
                return -1;
            case VIR_DOMAIN_TIMER_TICKPOLICY_LAST:
                break;
            }
            break;
        }
    }

    switch ((virDomainClockOffsetType) def->clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_ABSOLUTE:
        /* maximum timestamp glib can convert is 9999-12-31T23:59:59 */
        if (def->clock.data.starttime > 253402300799) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The maximum 'start' value for <clock offset='absolute'> is 253402300799"));
            return -1;
        }

    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
    case VIR_DOMAIN_CLOCK_OFFSET_LAST:
        break;
    }

    return 0;
}


static int
qemuValidateDomainDefNvram(const virDomainDef *def,
                           virQEMUCaps *qemuCaps)
{
    virStorageSource *src = def->os.loader->nvram;

    if (!src)
        return 0;

    switch (src->type) {
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_NETWORK:
        break;

    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported nvram disk type '%1$s'"),
                       virStorageTypeToString(src->type));
        return -1;

    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportEnumRangeError(virStorageType, src->type);
        return -1;
    }

    if (src->sliceStorage) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("slices are not supported with NVRAM"));
        return -1;
    }

    if (src->pr) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("persistent reservations are not supported with NVRAM"));
        return -1;
    }

    if (src->backingStore) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("backingStore is not supported with NVRAM"));
        return -1;
    }

    if (qemuDomainValidateStorageSource(src, qemuCaps) < 0)
        return -1;

    return 0;
}


static int
qemuValidateDomainDefBoot(const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    if (def->os.bootloader || def->os.bootloaderArgs) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("bootloader is not supported by QEMU"));
        return -1;
    }

    if (def->os.loader) {
        if (def->os.loader->secure == VIR_TRISTATE_BOOL_YES) {
            /* These are the QEMU implementation limitations. But we
             * have to live with them for now. */

            if (!qemuDomainIsQ35(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Secure boot is supported with q35 machine types only"));
                return -1;
            }

            /* Now, technically it is possible to have secure boot on
             * 32bits too, but that would require some -cpu xxx magic
             * too. Not worth it unless we are explicitly asked. */
            if (def->os.arch != VIR_ARCH_X86_64) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Secure boot is supported for x86_64 architecture only"));
                return -1;
            }

            /* SMM will be enabled by qemuFirmwareFillDomain() if needed. */
            if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_NONE &&
                def->features[VIR_DOMAIN_FEATURE_SMM] != VIR_TRISTATE_SWITCH_ON) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Secure boot requires SMM feature enabled"));
                return -1;
            }
        }

        if (qemuValidateDomainDefNvram(def, qemuCaps) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuValidateDefGetVcpuHotplugGranularity:
 * @def: domain definition
 *
 * With QEMU 2.7 and newer, vCPUs can only be hotplugged in groups that
 * respect the guest's hotplug granularity; because of that, QEMU will
 * not allow guests to start unless the initial number of vCPUs is a
 * multiple of the hotplug granularity.
 *
 * Returns the vCPU hotplug granularity.
 */
static unsigned int
qemuValidateDefGetVcpuHotplugGranularity(const virDomainDef *def)
{
    /* If the guest CPU topology has not been configured, assume we
     * can hotplug vCPUs one at a time */
    if (!def->cpu || def->cpu->sockets == 0)
        return 1;

    /* For pSeries guests, hotplug can only be performed one core
     * at a time, so the vCPU hotplug granularity is the number
     * of threads per core */
    if (qemuDomainIsPSeries(def))
        return def->cpu->threads;

    /* In all other cases, we can hotplug vCPUs one at a time */
    return 1;
}


static int
qemuValidateDomainVCpuTopology(const virDomainDef *def, virQEMUCaps *qemuCaps)
{
    unsigned int maxCpus = virQEMUCapsGetMachineMaxCpus(qemuCaps, def->virtType,
                                                        def->os.machine);
    unsigned int topologycpus;
    unsigned int granularity;

    if (virDomainDefGetVcpus(def) == 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Domain requires at least 1 vCPU"));
        return -1;
    }

    if (maxCpus > 0 && virDomainDefGetVcpusMax(def) > maxCpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Maximum CPUs greater than specified machine type limit %1$u"),
                       maxCpus);
        return -1;
    }

    /* Starting from QEMU 2.5, max vCPU count and overall vCPU topology must agree. */
    if (virDomainDefGetVcpusTopology(def, &topologycpus) == 0) {
        if (topologycpus != virDomainDefGetVcpusMax(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU topology doesn't match maximum vcpu count"));
            return -1;
        }
    }

    /* vCPU hotplug granularity must be respected */
    granularity = qemuValidateDefGetVcpuHotplugGranularity(def);
    if ((virDomainDefGetVcpus(def) % granularity) != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vCPUs count must be a multiple of the vCPU hotplug granularity (%1$u)"),
                       granularity);
        return -1;
    }

    if (ARCH_IS_X86(def->os.arch) &&
        virDomainDefGetVcpusMax(def) > QEMU_MAX_VCPUS_WITHOUT_EIM) {
        if (!qemuDomainIsQ35(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("more than %1$d vCPUs are only supported on q35-based machine types"),
                           QEMU_MAX_VCPUS_WITHOUT_EIM);
            return -1;
        }
        if (!def->iommu || def->iommu->eim != VIR_TRISTATE_SWITCH_ON) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("more than %1$d vCPUs require extended interrupt mode enabled on the iommu device"),
                           QEMU_MAX_VCPUS_WITHOUT_EIM);
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefMemory(const virDomainDef *def,
                            virQEMUCaps *qemuCaps)
{
    const char *defaultRAMid = virQEMUCapsGetMachineDefaultRAMid(qemuCaps,
                                                                 def->virtType,
                                                                 def->os.machine);
    const long system_page_size = virGetSystemPageSizeKB();
    const virDomainMemtune *mem = &def->mem;

    if (mem->nhugepages == 0)
        return 0;

    if (mem->allocation == VIR_DOMAIN_MEMORY_ALLOCATION_ONDEMAND) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("hugepages are not allowed with memory allocation ondemand"));
        return -1;
    }

    if (mem->allocation_threads > 0 &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_MEMORY_BACKEND_PREALLOC_THREADS)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("preallocation threads are unsupported with this QEMU"));
        return -1;
    }

    if (mem->source == VIR_DOMAIN_MEMORY_SOURCE_ANONYMOUS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("hugepages are not allowed with anonymous memory source"));
        return -1;
    }

    if (mem->source == VIR_DOMAIN_MEMORY_SOURCE_MEMFD &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_MEMFD_HUGETLB)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("hugepages is not supported with memfd memory source"));
        return -1;
    }

    /* We can't guarantee any other mem.access if no guest NUMA
     * nodes are defined, unless defaultRAMid is provided. */
    if (!defaultRAMid &&
        mem->hugepages[0].size != system_page_size &&
        virDomainNumaGetNodeCount(def->numa) == 0 &&
        mem->access != VIR_DOMAIN_MEMORY_ACCESS_DEFAULT &&
        mem->access != VIR_DOMAIN_MEMORY_ACCESS_PRIVATE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("memory access mode '%1$s' not supported without guest numa node"),
                       virDomainMemoryAccessTypeToString(mem->access));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDefNuma(const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    if (virDomainNumaHasHMAT(def->numa)) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_NUMA_HMAT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("HMAT is not supported with this QEMU"));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefConsole(const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    size_t i;

    /* Explicit console devices */
    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDef *console = def->consoles[i];

        switch (console->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SCLPCONSOLE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclpconsole is not supported in this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SCLPLMCONSOLE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclplmconsole is not supported in this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported console target type %1$s"),
                           NULLSTR(virDomainChrConsoleTargetTypeToString(console->targetType)));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefSysinfo(const virSysinfoDef *def)
{
    size_t i;

    for (i = 0; i < def->nfw_cfgs; i++) {
        const virSysinfoFWCfgDef *f = &def->fw_cfgs[i];

        if (!STRPREFIX(f->name, "opt/")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid firmware name"));
            return -1;
        }

        if (STRPREFIX(f->name, "opt/ovmf/") ||
            STRPREFIX(f->name, "opt/org.qemu/")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("That firmware name is reserved"));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefPanic(const virDomainDef *def,
                           virQEMUCaps *qemuCaps)
{
    size_t i;

    for (i = 0; i < def->npanics; i++) {
        switch ((virDomainPanicModel) def->panics[i]->model) {
        case VIR_DOMAIN_PANIC_MODEL_S390:
            /* For s390 guests, the hardware provides the same
             * functionality as the pvpanic device. The address
             * cannot be configured by the user */
            if (!ARCH_IS_S390(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only S390 guests support panic device of model 's390'"));
                return -1;
            }
            if (def->panics[i]->info.type !=
                VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("setting the panic device address is not supported for model 's390'"));
                return -1;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_HYPERV:
            /* Panic with model 'hyperv' is not a device, it should
             * be configured in cpu commandline. The address
             * cannot be configured by the user */
            if (!ARCH_IS_X86(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only i686 and x86_64 guests support panic device of model 'hyperv'"));
                return -1;
            }
            if (def->panics[i]->info.type !=
                VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("setting the panic device address is not supported for model 'hyperv'"));
                return -1;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_PSERIES:
            /* For pSeries guests, the firmware provides the same
             * functionality as the pvpanic device. The address
             * cannot be configured by the user */
            if (!qemuDomainIsPSeries(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only pSeries guests support panic device of model 'pseries'"));
                return -1;
            }
            if (def->panics[i]->info.type !=
                VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("setting the panic device address is not supported for model 'pseries'"));
                return -1;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_ISA:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PANIC)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the QEMU binary does not support the ISA panic device"));
                return -1;
            }

            if (def->panics[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                def->panics[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("panic is supported only with ISA address type"));
                return -1;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_PVPANIC:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PANIC_PCI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the QEMU binary does not support the PCI pvpanic device"));
                return -1;
            }

            if (def->panics[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("pvpanic is supported only with PCI address type"));
                return -1;
            }
            break;

        /* default model value was changed before in post parse */
        case VIR_DOMAIN_PANIC_MODEL_DEFAULT:
        case VIR_DOMAIN_PANIC_MODEL_LAST:
            break;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefTPMs(const virDomainDef *def)
{
    const virDomainTPMDef *proxyTPM = NULL;
    const virDomainTPMDef *regularTPM = NULL;
    size_t i;

    for (i = 0; i < def->ntpms; i++) {
        virDomainTPMDef *tpm = def->tpms[i];

        if (tpm->model == VIR_DOMAIN_TPM_MODEL_SPAPR_PROXY) {
            if (proxyTPM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only a single TPM Proxy device is supported"));
                return -1;
            }
            proxyTPM = tpm;
        } else {
            if (regularTPM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only a single TPM non-proxy device is supported"));
                return -1;
            }
            regularTPM = tpm;
        }
    }

    return 0;
}


static int
qemuValidateDomainDefWatchdogs(const virDomainDef *def)
{
    g_autoptr(virBitmap) watchdogs = virBitmapNew(VIR_DOMAIN_WATCHDOG_MODEL_LAST);
    size_t i = 0;

    for (i = 0; i < def->nwatchdogs; i++) {
        if (def->watchdogs[i]->model == VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB)
            continue;

        if (virBitmapIsBitSet(watchdogs, def->watchdogs[i]->model)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("domain can only have one watchdog with model '%1$s'"),
                           virDomainWatchdogModelTypeToString(def->watchdogs[i]->model));
            return -1;
        }

        if (virBitmapSetBit(watchdogs, def->watchdogs[i]->model) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Integrity error in watchdog models"));
            return -1;
        }
    }

    return 0;
}


int
qemuValidateLifecycleAction(virDomainLifecycleAction onPoweroff,
                            virDomainLifecycleAction onReboot,
                            virDomainLifecycleAction onCrash)
{
    /* The qemu driver doesn't yet implement any meaningful handling for
     * VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME */
    if (onPoweroff == VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME ||
        onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME ||
        onCrash == VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("qemu driver doesn't support the 'rename-restart' action for 'on_reboot'/'on_poweroff'/'on_crash'"));
        return -1;
    }

    /* The qemu driver doesn't yet implement any meaningful handling for
     * VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE */
    if (onPoweroff == VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE ||
        onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("qemu driver doesn't support the 'preserve' action for 'on_reboot'/'on_poweroff'"));
        return -1;
    }

    /* the qemu driver can't meaningfully handle
     * onPoweroff -> reboot + onReboot -> destroy */
    if (onPoweroff == VIR_DOMAIN_LIFECYCLE_ACTION_RESTART &&
        onReboot == VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("qemu driver doesn't support 'onReboot' set to 'destroy and 'onPoweroff' set to 'reboot'"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainLifecycleAction(const virDomainDef *def)
{
    return qemuValidateLifecycleAction(def->onPoweroff,
                                       def->onReboot,
                                       def->onCrash);
}


int
qemuValidateDomainDef(const virDomainDef *def,
                      void *opaque,
                      void *parseOpaque)
{
    virQEMUDriver *driver = opaque;
    g_autoptr(virQEMUCaps) qemuCapsLocal = NULL;
    virQEMUCaps *qemuCaps = parseOpaque;
    size_t i;

    if (!qemuCaps) {
        if (!(qemuCapsLocal = virQEMUCapsCacheLookup(driver->qemuCapsCache,
                                                     def->emulator)))
            return -1;

        qemuCaps = qemuCapsLocal;
    }

    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Emulator '%1$s' does not support os type '%2$s'"),
                       def->emulator, virDomainOSTypeToString(def->os.type));
        return -1;
    }

    if (!virQEMUCapsIsArchSupported(qemuCaps, def->os.arch)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Emulator '%1$s' does not support arch '%2$s'"),
                       def->emulator, virArchToString(def->os.arch));
        return -1;
    }

    if (!virQEMUCapsIsVirtTypeSupported(qemuCaps, def->virtType)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Emulator '%1$s' does not support virt type '%2$s'"),
                       def->emulator, virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    if (!virQEMUCapsIsMachineSupported(qemuCaps, def->virtType, def->os.machine)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Emulator '%1$s' does not support machine type '%2$s'"),
                       def->emulator, def->os.machine);
        return -1;
    }

    if (virQEMUCapsMachineSupportsACPI(qemuCaps, def->virtType, def->os.machine) == VIR_TRISTATE_BOOL_NO &&
        def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("machine type '%1$s' does not support ACPI"),
                       def->os.machine);
        return -1;
    }

    if (def->mem.min_guarantee) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Parameter 'min_guarantee' not supported by QEMU."));
        return -1;
    }

    /* On x86, UEFI requires ACPI */
    if ((def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI ||
         virDomainDefHasOldStyleUEFI(def)) &&
        ARCH_IS_X86(def->os.arch) &&
        def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("UEFI requires ACPI on this architecture"));
        return -1;
    }

    /* On aarch64, ACPI requires UEFI */
    if (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON &&
        def->os.arch == VIR_ARCH_AARCH64 &&
        (def->os.firmware != VIR_DOMAIN_OS_DEF_FIRMWARE_EFI &&
         !virDomainDefHasOldStyleUEFI(def))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ACPI requires UEFI on this architecture"));
        return -1;
    }

    if (def->genidRequested &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMGENID)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("this QEMU does not support the 'genid' capability"));
        return -1;
    }

    /* Serial graphics adapter */
    if (def->os.bios.useserial == VIR_TRISTATE_BOOL_YES) {
        /* On x86 -machine graphics=off toggles the use of the
         * serial console in SeaBIOS (and theoretically other
         * firmwares).
         * On non-x86, it has also sorts of other effects
         * on QEMU device models created and so we don't
         * want to allow its use.
         */
        if (!ARCH_IS_X86(def->os.arch)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("BIOS serial console only supported on x86 architectures"));
            return -1;
        }
        if (!def->nserials) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("need at least one serial port to use BIOS serial output"));
            return -1;
        }
    }

    if (qemuValidateDomainLifecycleAction(def) < 0)
        return -1;

    if (qemuValidateDomainDefCpu(driver, def, qemuCaps) < 0)
        return -1;

    if (qemuDomainDefValidateMemoryHotplug(def, NULL) < 0)
        return -1;

    if (qemuValidateDomainDefIOThreads(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDefClockTimers(def, qemuCaps) < 0)
        return -1;

    if ((def->pm.s3 || def->pm.s4) && !ARCH_IS_X86(def->os.arch)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("setting ACPI S3/S4 not supported"));
        return -1;
    }

    if (qemuValidateDomainDefBoot(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainVCpuTopology(def, qemuCaps) < 0)
        return -1;

    if (def->nresctrls &&
        def->virtType != VIR_DOMAIN_VIRT_KVM) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cachetune is only supported for KVM domains"));
        return -1;
    }

    if (qemuValidateDomainDefFeatures(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDefMemory(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDefNuma(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDefConsole(def, qemuCaps) < 0)
        return -1;

    for (i = 0; i < def->nsysinfo; i++) {
        if (qemuValidateDomainDefSysinfo(def->sysinfo[i]) < 0)
            return -1;
    }

    if (qemuValidateDomainDefPanic(def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDefTPMs(def) < 0)
        return -1;

    if (qemuValidateDomainDefWatchdogs(def) < 0)
        return -1;

    if (def->sec) {
        switch ((virDomainLaunchSecurity) def->sec->sectype) {
        case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SEV launch security is not supported with this QEMU binary"));
                return -1;
            }

            if (def->sec->data.sev.kernel_hashes != VIR_TRISTATE_BOOL_ABSENT &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEV_GUEST_KERNEL_HASHES)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SEV measured direct kernel boot is not supported with this QEMU binary"));
                return -1;
            }
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_PV:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_CONFIDENTAL_GUEST_SUPPORT) ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_S390_PV_GUEST)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("S390 PV launch security is not supported with this QEMU binary"));
                return -1;
            }
            if (!virQEMUCapsGetKVMSupportsSecureGuest(qemuCaps)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("S390 PV launch security is not supported by this host or kernel"));
                return -1;
            }
            break;
        case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
        case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
            virReportEnumRangeError(virDomainLaunchSecurity, def->sec->sectype);
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefZPCIAddress(virDomainDeviceInfo *info,
                                       virQEMUCaps *qemuCaps)
{
    virZPCIDeviceAddress *zpci = &info->addr.pci.zpci;

    if (virZPCIDeviceAddressIsPresent(zpci) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ZPCI)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s",
                       _("This QEMU binary doesn't support zPCI"));
        return -1;
    }

    /* We don't need to check fid because fid covers
     * all range of uint32 type.
     */
    if (zpci->uid.isSet &&
        (zpci->uid.value > VIR_DOMAIN_DEVICE_ZPCI_MAX_UID ||
         zpci->uid.value == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid PCI address uid='0x%1$.4x', must be > 0x0000 and <= 0x%2$.4x"),
                       zpci->uid.value,
                       VIR_DOMAIN_DEVICE_ZPCI_MAX_UID);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefAddressDrive(virDomainDeviceInfo *info,
                                        const virDomainDef *def,
                                        virQEMUCaps *qemuCaps)
{
    virDomainControllerDef *controller = NULL;

    switch (info->addr.drive.diskbus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        /* Setting bus= attr for SCSI drives, causes a controller
         * to be created. Yes this is slightly odd. It is not possible
         * to have > 1 bus on a SCSI controller (yet). */
        if (info->addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("SCSI controller only supports 1 bus"));
            return -1;
        }

        /* We allow hotplug/hotunplug disks without a controller,
         * hence we don't error out if controller wasn't found. */
        if ((controller = virDomainDeviceFindSCSIController(def, &info->addr.drive))) {
            if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
                if (info->addr.drive.target != 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("target must be 0 for controller model 'lsilogic'"));
                    return -1;
                }
            } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_CHANNEL)) {
                if (info->addr.drive.target > 7) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU doesn't support target greater than 7"));
                    return -1;
                }

                if (info->addr.drive.bus != 0 &&
                    info->addr.drive.unit != 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU only supports both bus and unit equal to 0"));
                    return -1;
                }
            }
        }
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        /* We can only have 1 IDE controller (currently) */
        if (info->addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only 1 IDE controller is supported"));
            return -1;
        }

        if (info->addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for ide controller"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        /* We can only have 1 FDC controller (currently) */
        if (info->addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only 1 fdc controller is supported"));
            return -1;
        }

        /* We can only have 1 FDC bus (currently) */
        if (info->addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only 1 fdc bus is supported"));
            return -1;
        }

        if (info->addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for controller fdc"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_SATA:
        if (info->addr.drive.bus != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("bus must be 0 for sata controller"));
            return -1;
        }

        if (info->addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for sata controller"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_LAST:
        break;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefAddress(const virDomainDeviceDef *dev,
                                   virDomainDeviceInfo *info,
                                   const virDomainDef *def,
                                   virQEMUCaps *qemuCaps)
{
    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        if (qemuValidateDomainDeviceDefZPCIAddress(info, qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
        /* Address validation might happen before we have had a chance to
         * automatically assign addresses to devices for which the user
         * didn't specify one themselves */
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO: {
        virDomainDeviceSpaprVioAddress *addr = &(info->addr.spaprvio);

        if (addr->has_reg && addr->reg > 0xffffffff) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("spapr-vio reg='0x%1$llx' exceeds maximum possible value (0xffffffff)"),
                           addr->reg);
            return -1;
        }

        break;
        }

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'virtio-s390' addresses are no longer supported"));
        return -1;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        if (!qemuDomainIsS390CCW(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot use CCW address type for device '%1$s' using machine type '%2$s'"),
                           NULLSTR(info->alias), def->os.machine);
            return -1;
        }

        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        /* drive address validation needs a disk bus type filled in. We assume
         * that it's SCSI if it's not a disk since everything else would be
         * a SCSI host device. */
        if (dev->type == VIR_DOMAIN_DEVICE_DISK)
            info->addr.drive.diskbus = dev->data.disk->bus;
        else
            info->addr.drive.diskbus = VIR_DOMAIN_DISK_BUS_SCSI;

        if (qemuValidateDomainDeviceDefAddressDrive(info, def, qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
        /* No validation for these address types yet */
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceAddressType, info->type);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceInfo(const virDomainDeviceDef *dev,
                             const virDomainDef *def,
                             virQEMUCaps *qemuCaps)
{
    virDomainDeviceInfo *info;

    if (!(info = virDomainDeviceGetInfo(dev)))
        return 0;

    if (qemuValidateDomainDeviceDefAddress(dev, info, def, qemuCaps) < 0)
        return -1;

    if (info->acpiIndex) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_ACPI_INDEX)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ACPI index is not supported with this QEMU"));
            return -1;
        }

        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ACPI index is only supported for PCI devices"));
            return -1;
        }
    }

    if (info->romenabled || info->rombar || info->romfile) {
        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ROM tuning is only supported for PCI devices"));
            return -1;
        }
    }

    return 0;
}


static bool
qemuValidateNetSupportsCoalesce(virDomainNetType type)
{
    switch (type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        return true;
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_USER:
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
    return false;
}


/**
 * qemuValidateDomainDefVhostUserRequireSharedMemory:
 * @def: VM definition
 * @name: name of the attribute/element
 * @qemuCaps: capabilities of QEMU binary
 *
 * Check if the VM definition contains any form of shared memory
 * which is required by vhost-user devices to operate properly.
 *
 * On success returns 0, on error returns -1 and reports proper error
 * message.
 */
static int
qemuValidateDomainDefVhostUserRequireSharedMemory(const virDomainDef *def,
                                                  const char *name)
{
    size_t numa_nodes = virDomainNumaGetNodeCount(def->numa);
    size_t i;

    if (numa_nodes == 0 && def->mem.access != VIR_DOMAIN_MEMORY_ACCESS_SHARED) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("'%1$s' requires shared memory"), name);
        return -1;
    }

    for (i = 0; i < numa_nodes; i++) {
        virDomainMemoryAccess node_access =
            virDomainNumaGetNodeMemoryAccessMode(def->numa, i);

        switch (node_access) {
        case VIR_DOMAIN_MEMORY_ACCESS_DEFAULT:
            if (def->mem.access != VIR_DOMAIN_MEMORY_ACCESS_SHARED) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("'%1$s' requires shared memory"), name);
                return -1;
            }
            break;
        case VIR_DOMAIN_MEMORY_ACCESS_SHARED:
            break;
        case VIR_DOMAIN_MEMORY_ACCESS_PRIVATE:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("'%1$s' requires shared memory"), name);
            return -1;

        case VIR_DOMAIN_MEMORY_ACCESS_LAST:
        default:
            virReportEnumRangeError(virDomainMemoryAccess, node_access);
            return -1;

        }
    }
    return 0;
}


static int
qemuValidateDomainDeviceDefNetwork(const virDomainNetDef *net,
                                   virQEMUCaps *qemuCaps)
{
    bool hasIPv4 = false;
    bool hasIPv6 = false;
    size_t i;

    if (net->type == VIR_DOMAIN_NET_TYPE_USER) {
        if (net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV_STREAM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("the passt network backend is not supported with this QEMU binary"));
            return -1;
        }
        if (net->guestIP.nroutes) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid attempt to set network interface guest-side IP route, not supported by QEMU"));
            return -1;
        }

        for (i = 0; i < net->guestIP.nips; i++) {
            const virNetDevIPAddr *ip = net->guestIP.ips[i];

            if (VIR_SOCKET_ADDR_VALID(&net->guestIP.ips[i]->peer)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid attempt to set peer IP for guest"));
                return -1;
            }

            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
                if (hasIPv4) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only one IPv4 address per interface is allowed"));
                    return -1;
                }
                hasIPv4 = true;

                if (ip->prefix > 0 &&
                    (ip->prefix < 4 || ip->prefix > 27)) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("invalid prefix, must be in range of 4-27"));
                    return -1;
                }
            }

            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6)) {
                if (hasIPv6) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only one IPv6 address per interface is allowed"));
                    return -1;
                }
                hasIPv6 = true;

                if (ip->prefix && ip->prefix != 64) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported IPv6 address prefix='%1$u' - must be 64"),
                                   ip->prefix);
                    return -1;
                }

                if (ip->prefix > 120) {
                    virReportError(VIR_ERR_XML_ERROR, "%s",
                                   _("prefix too long"));
                    return -1;
                }
            }
        }
    } else if (net->type == VIR_DOMAIN_NET_TYPE_VDPA) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV_VHOST_VDPA)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vDPA devices are not supported with this QEMU binary"));
            return -1;
        }

        if (net->model != VIR_DOMAIN_NET_MODEL_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid model for interface of type '%1$s': '%2$s'"),
                           virDomainNetTypeToString(net->type),
                           virDomainNetModelTypeToString(net->model));
            return -1;
        }
    } else if (net->guestIP.nroutes || net->guestIP.nips) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Invalid attempt to set network interface guest-side IP route and/or address info, not supported by QEMU"));
        return -1;
    }

    if (virDomainNetIsVirtioModel(net)) {
        if (net->driver.virtio.rx_queue_size) {
            if (!VIR_IS_POW2(net->driver.virtio.rx_queue_size)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("rx_queue_size has to be a power of two"));
                return -1;
            }
        }

        if (net->driver.virtio.tx_queue_size) {
            if (!VIR_IS_POW2(net->driver.virtio.tx_queue_size)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("tx_queue_size has to be a power of two"));
                return -1;
            }
        }

        if (net->driver.virtio.rss &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_NET_RSS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio rss is not supported with this QEMU binary"));
            return -1;
        }

        if (net->driver.virtio.rss_hash_report &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_NET_RSS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio rss hash report is not supported with this QEMU binary"));
            return -1;
        }
    }

    if (net->mtu &&
        !qemuDomainNetSupportsMTU(net->type, net->backend.type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("setting MTU on interface type %1$s is not supported yet"),
                       virDomainNetTypeToString(net->type));
        return -1;
    }

    if (net->teaming) {
        if (net->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_PERSISTENT
            && !virDomainNetIsVirtioModel(net)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio-net teaming persistent interface must be <model type='virtio'/>, not '%1$s'"),
                           virDomainNetGetModelString(net));
            return -1;
        }
        if (net->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT &&
            net->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            net->type != VIR_DOMAIN_NET_TYPE_NETWORK) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio-net teaming transient interface must be type='hostdev', not '%1$s'"),
                           virDomainNetTypeToString(net->type));
            return -1;
        }
    }

   if (net->coalesce && !qemuValidateNetSupportsCoalesce(net->type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("coalesce settings on interface type %1$s are not supported"),
                       virDomainNetTypeToString(net->type));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainChrSourceReconnectDef(const virDomainChrSourceReconnectDef *def)
{
    if (def->enabled == VIR_TRISTATE_BOOL_YES &&
        def->timeout == 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("chardev reconnect source timeout cannot be '0'"));
        return -1;
    }

    return 0;
}


static int
qemuValidateChrSerialTargetTypeToAddressType(int targetType)
{
    switch ((virDomainChrSerialTargetType)targetType) {
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG:
        return VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
        return VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
        return VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO:
        return VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE:
        break;
    }

    return VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
}


static int
qemuValidateChrSerialTargetModelToTargetType(int targetModel)
{
    switch ((virDomainChrSerialTargetModel) targetModel) {
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_USB_SERIAL:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PCI_SERIAL:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPLMCONSOLE:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_DEBUGCON:
        return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG;
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE:
    case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_LAST:
        break;
    }

    return VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE;
}


static int
qemuValidateDomainChrTargetDef(const virDomainChrDef *chr)
{
    int expected;

    switch ((virDomainChrDeviceType)chr->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:

        /* Validate target type */
        switch ((virDomainChrSerialTargetType)chr->targetType) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG:

            expected = qemuValidateChrSerialTargetTypeToAddressType(chr->targetType);

            if (chr->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                chr->info.type != expected) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Target type '%1$s' requires address type '%2$s'"),
                               virDomainChrSerialTargetTypeToString(chr->targetType),
                               virDomainDeviceAddressTypeToString(expected));
                return -1;
            }
            break;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP:
            if (chr->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Target type '%1$s' cannot have an associated address"),
                               virDomainChrSerialTargetTypeToString(chr->targetType));
                return -1;
            }
            break;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST:
            break;
        }

        /* Validate target model */
        switch ((virDomainChrSerialTargetModel) chr->targetModel) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_USB_SERIAL:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PCI_SERIAL:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPLMCONSOLE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_DEBUGCON:

            expected = qemuValidateChrSerialTargetModelToTargetType(chr->targetModel);

            if (chr->targetType != expected) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Target model '%1$s' requires target type '%2$s'"),
                               virDomainChrSerialTargetModelTypeToString(chr->targetModel),
                               virDomainChrSerialTargetTypeToString(expected));
                return -1;
            }
            break;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_LAST:
            break;
        }
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        /* Nothing to do */
        break;
    }

    return 0;
}


static int
qemuValidateDomainChrSourceDef(const virDomainChrSourceDef *def,
                               const virDomainDef *vmdef,
                               virQEMUCaps *qemuCaps)
{
    switch ((virDomainChrType)def->type) {
    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (qemuValidateDomainChrSourceReconnectDef(&def->data.tcp.reconnect) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (qemuValidateDomainChrSourceReconnectDef(&def->data.nix.reconnect) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_QEMU_VDAGENT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("chardev '%1$s' not supported in this QEMU binary"),
                           virDomainChrTypeToString(def->type));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        if (!virDomainDefHasSpiceGraphics(vmdef)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("chardev '%1$s' not supported without spice graphics"),
                           virDomainChrTypeToString(def->type));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_DBUS:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    return 0;
}


static int
qemuValidateDomainChrDef(const virDomainChrDef *dev,
                         const virDomainDef *def,
                         virQEMUCaps *qemuCaps)
{
    if (qemuValidateDomainChrSourceDef(dev->source, def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainChrTargetDef(dev) < 0)
        return -1;

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL &&
        (ARCH_IS_S390(def->os.arch) || qemuDomainIsPSeries(def))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("parallel ports are not supported"));
            return -1;
    }

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        bool isCompatible = true;

        if (dev->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM) {
            if (dev->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011 &&
                !qemuDomainIsARMVirt(def)) {
                isCompatible = false;
            }
            if (dev->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A &&
                !qemuDomainIsRISCVVirt(def)) {
                isCompatible = false;
            }
        }

        if (!qemuDomainIsPSeries(def) &&
            (dev->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO ||
             dev->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY)) {
            isCompatible = false;
        }

        if (!ARCH_IS_S390(def->os.arch) &&
            (dev->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP ||
             dev->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE ||
             dev->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPLMCONSOLE)) {
            isCompatible = false;
        }

        if (!isCompatible) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Serial device with target type '%1$s' and target model '%2$s' not compatible with guest architecture or machine type"),
                           virDomainChrSerialTargetTypeToString(dev->targetType),
                           virDomainChrSerialTargetModelTypeToString(dev->targetModel));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainSmartcardDef(const virDomainSmartcardDef *smartcard,
                               const virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    if (def->nsmartcards > 1 ||
        smartcard->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID ||
        smartcard->info.addr.ccid.controller != 0 ||
        smartcard->info.addr.ccid.slot != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("this QEMU binary lacks multiple smartcard support"));
        return -1;
    }

    switch (smartcard->type) {
    case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_EMULATED)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU binary lacks smartcard host mode support"));
            return -1;
        }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_EMULATED)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU binary lacks smartcard host mode support"));
            return -1;
        }
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_PASSTHRU)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU binary lacks smartcard passthrough mode support"));
            return -1;
        }

        if (qemuValidateDomainChrSourceDef(smartcard->data.passthru, def, qemuCaps) < 0)
            return -1;
        break;

    case VIR_DOMAIN_SMARTCARD_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainSmartcardType, smartcard->type);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainRNGDef(const virDomainRNGDef *def,
                         const virDomainDef *vmdef,
                         virQEMUCaps *qemuCaps)
{
    virDomainCapsDeviceRNG rngCaps = { 0 };

    switch (def->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_RANDOM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the rng-random backend"));
            return -1;
        }
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_EGD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the rng-egd backend"));
            return -1;
        }

        if (qemuValidateDomainChrSourceDef(def->source.chardev,
                                           vmdef,
                                           qemuCaps) < 0)
            return -1;

        break;

    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_BUILTIN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the rng-builtin backend"));
            return -1;
        }
        break;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown rng-random backend"));
        return -1;
    }

    virQEMUCapsFillDomainDeviceRNGCaps(qemuCaps, &rngCaps);

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(rngCaps.model, def->model)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("domain configuration does not support rng model '%1$s'"),
                       virDomainRNGModelTypeToString(def->model));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainRedirdevDef(const virDomainRedirdevDef *dev,
                              const virDomainDef *def,
                              virQEMUCaps *qemuCaps)
{
    if (qemuValidateDomainChrSourceDef(dev->source, def, qemuCaps) < 0)
        return -1;

    if (dev->bus != VIR_DOMAIN_REDIRDEV_BUS_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Redirection bus %1$s is not supported by QEMU"),
                       virDomainRedirdevBusTypeToString(dev->bus));
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_REDIR)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("USB redirection is not supported by this version of QEMU"));
        return -1;
    }

    if (def->redirfilter && def->redirfilter->nusbdevs &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_REDIR_FILTER)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("USB redirection filter is not supported by this version of QEMU"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainWatchdogDef(const virDomainWatchdogDef *dev,
                              const virDomainDef *def)
{
    /* We could theoretically support different watchdogs having dump and
     * pause, but let's be honest, we support multiple watchdogs only
     * because we need to be able to add a second, implicit one, not because
     * it is a brilliant idea to have multiple watchdogs. */
    if (def->nwatchdogs &&
        def->watchdogs[0]->action != dev->action) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("watchdogs with different actions are not supported with this QEMU binary"));
        return -1;
    }

    switch (dev->model) {
    case VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB:
        if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog can go only on PCI bus"),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_WATCHDOG_MODEL_IB700:
        if (!qemuDomainIsI440FX(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog cannot be used with this machine type"),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }

        if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog does not support configuring the address"),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_WATCHDOG_MODEL_DIAG288:
        if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog is virtual and cannot go on any bus."),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        if (!(ARCH_IS_S390(def->os.arch))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog is allowed for s390 and s390x only"),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_WATCHDOG_MODEL_ITCO:
        if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog is part of the machine and cannot have any address set."),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        if (!qemuDomainIsQ35(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s model of watchdog is only part of q35 machine"),
                           virDomainWatchdogModelTypeToString(dev->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_WATCHDOG_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainWatchdogModel, dev->model);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainMdevDefVFIOPCI(const virDomainHostdevDef *hostdev,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    const virDomainHostdevSubsysMediatedDev *dev;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("VFIO PCI device assignment is not supported by this version of QEMU"));
        return -1;
    }

    /* VFIO-PCI does not support boot */
    if (hostdev->info->bootIndex) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("booting from assigned devices is not supported by mediated devices of model vfio-pci"));
        return -1;
    }

    dev = &hostdev->source.subsys.u.mdev;
    if (dev->display == VIR_TRISTATE_SWITCH_ABSENT)
        return 0;

    if (dev->model != VIR_MDEV_MODEL_TYPE_VFIO_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("<hostdev> attribute 'display' is only supported with model='vfio-pci'"));

        return -1;
    }

    if (dev->display == VIR_TRISTATE_SWITCH_ON) {
        if (def->ngraphics == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("graphics device is needed for attribute value 'display=on' in <hostdev>"));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainMdevDefVFIOAP(const virDomainHostdevDef *hostdev,
                                const virDomainDef *def,
                                virQEMUCaps *qemuCaps)
{
    size_t i;
    bool vfioap_found = false;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_AP)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("VFIO AP device assignment is not supported by this version of QEMU"));
        return -1;
    }

    /* VFIO-AP does not support boot */
    if (hostdev->info->bootIndex) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("booting from assigned devices is not supported by mediated devices of model vfio-ap"));
        return -1;
    }

    /* VFIO-AP is restricted to a single mediated device only */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hdev = def->hostdevs[i];

        if (virHostdevIsMdevDevice(hdev) &&
            hdev->source.subsys.u.mdev.model == VIR_MDEV_MODEL_TYPE_VFIO_AP) {
            if (vfioap_found) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only one hostdev of model vfio-ap is supported"));
                return -1;
            }
            vfioap_found = true;
        }
    }

    return 0;
}


static int
qemuValidateDomainMdevDef(const virDomainHostdevDef *hostdev,
                          const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    const virDomainHostdevSubsysMediatedDev *mdevsrc;

    mdevsrc = &hostdev->source.subsys.u.mdev;
    switch (mdevsrc->model) {
    case VIR_MDEV_MODEL_TYPE_VFIO_PCI:
        return qemuValidateDomainMdevDefVFIOPCI(hostdev, def, qemuCaps);
    case VIR_MDEV_MODEL_TYPE_VFIO_AP:
        return qemuValidateDomainMdevDefVFIOAP(hostdev, def, qemuCaps);
    case VIR_MDEV_MODEL_TYPE_VFIO_CCW:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_CCW)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VFIO CCW device assignment is not supported by this version of QEMU"));
            return -1;
        }
        break;
    case VIR_MDEV_MODEL_TYPE_LAST:
    default:
        virReportEnumRangeError(virMediatedDeviceModelType,
                                mdevsrc->model);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefHostdev(const virDomainHostdevDef *hostdev,
                                   const virDomainDef *def,
                                   virQEMUCaps *qemuCaps)
{
    int backend;

    /* forbid capabilities mode hostdev in this kind of hypervisor */
    if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not supported in %1$s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        switch (hostdev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (hostdev->source.subsys.u.usb.guestReset &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_HOST_GUESTS_RESETS_ALL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("guestReset is not supported with this version of QEMU"));
                return -1;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            backend = hostdev->source.subsys.u.pci.backend;

            if (backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("VFIO PCI device assignment is not supported by this version of qemu"));
                    return -1;
                }
            }

            if (hostdev->writeFiltering != VIR_TRISTATE_BOOL_ABSENT) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Write filtering of PCI device configuration space is not supported by qemu"));
                return -1;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            if (hostdev->info->bootIndex) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("booting from assigned devices is not supported by vhost SCSI devices"));
                return -1;
            }

            if (hostdev->source.subsys.u.scsi_host.protocol ==
                VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_SCSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("This QEMU doesn't support vhost-scsi devices"));
                return -1;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
            return qemuValidateDomainMdevDef(hostdev, def, qemuCaps);
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainHostdevSubsysType,
                                    hostdev->source.subsys.type);
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefVideo(const virDomainVideoDef *video,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    virDomainCapsDeviceVideo videoCaps = { 0 };

    /* there's no properties to validate for NONE video devices */
    if (video->type == VIR_DOMAIN_VIDEO_TYPE_NONE)
        return 0;

    virQEMUCapsFillDomainDeviceVideoCaps(qemuCaps, &videoCaps);

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(videoCaps.modelType, video->type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("domain configuration does not support video model '%1$s'"),
                       virDomainVideoTypeToString(video->type));
        return -1;
    }

    if (video->type != VIR_DOMAIN_VIDEO_TYPE_QXL &&
        video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
        if (!video->primary) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type '%1$s' is only valid as primary video device"),
                           virDomainVideoTypeToString(video->type));
            return -1;
        }

        if (video->heads != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type '%1$s' doesn't support multiple 'heads'"),
                           virDomainVideoTypeToString(video->type));
            return -1;
        }
    }

    if (video->accel && video->accel->accel2d == VIR_TRISTATE_BOOL_YES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("qemu does not support the accel2d setting"));
        return -1;
    }

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (video->vram > (UINT_MAX / 1024)) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("value for 'vram' must be less than '%1$u'"),
                           UINT_MAX / 1024);
            return -1;
        }
        if (video->ram > (UINT_MAX / 1024)) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("value for 'ram' must be less than '%1$u'"),
                           UINT_MAX / 1024);
            return -1;
        }
        if (video->vgamem) {
            if (video->vgamem < 1024) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("value for 'vgamem' must be at least 1 MiB (1024 KiB)"));
                return -1;
            }

            if (video->vgamem != VIR_ROUND_UP_POWER_OF_TWO(video->vgamem)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("value for 'vgamem' must be power of two"));
                return -1;
            }
        }
    }

    if (video->type != VIR_DOMAIN_VIDEO_TYPE_VGA &&
        video->type != VIR_DOMAIN_VIDEO_TYPE_QXL &&
        video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
        video->type != VIR_DOMAIN_VIDEO_TYPE_BOCHS) {
        if (video->res) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("model resolution is not supported"));
            return -1;
        }
    }

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_VGA ||
        video->type == VIR_DOMAIN_VIDEO_TYPE_VMVGA) {
        if (video->vram && video->vram < 1024) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("value for 'vram' must be at least 1 MiB (1024 KiB)"));
            return -1;
        }
    }

    if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
        if (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_USER_GPU)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU does not support 'vhost-user' video device"));
            return -1;
        }
    } else if (video->accel) {
        if (video->accel->accel3d == VIR_TRISTATE_BOOL_YES) {
            if (video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("3d acceleration is supported only with 'virtio' video device"));
                return -1;
            }

            if (!(virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_VIRGL) ||
                  virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_GL_PCI) ||
                  virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_VGA_GL))) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("3d acceleration is not supported by this QEMU binary"));
                return -1;
            }
        }
    }

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
        if (video->blob != VIR_TRISTATE_SWITCH_ABSENT) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_GPU_BLOB)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU does not support 'blob' for virtio-gpu devices"));
                return -1;
            }
            if (video->blob == VIR_TRISTATE_SWITCH_ON
                && def->mem.source != VIR_DOMAIN_MEMORY_SOURCE_MEMFD) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("'blob' support for virtio-gpu devices requires a memfd memory backend"));
                return -1;
            }
        }
    }

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_RAMFB &&
        video->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'address' is not supported for 'ramfb' video devices"));
        return -1;
    }


    return 0;
}


#define QEMU_SERIAL_PARAM_ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ .+"

static int
qemuValidateDomainDeviceDefDiskSerial(const char *value)
{
    if (strspn(value, QEMU_SERIAL_PARAM_ACCEPTED_CHARS) != strlen(value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("driver serial '%1$s' contains unsafe characters"),
                       value);
        return -1;
    }

    return 0;
}


static bool
qemuValidateDomainDeviceDefDiskIOThreads(const virDomainDef *def,
                                         const virDomainDiskDef *disk)
{
    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SATA:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("IOThreads not available for bus %1$s target %2$s"),
                       virDomainDiskBusTypeToString(disk->bus), disk->dst);
        return false;
    }

    /* Can we find the disk iothread in the iothreadid list? */
    if (!virDomainIOThreadIDFind(def, disk->iothread)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk iothread '%1$u' not defined in iothreadid"),
                       disk->iothread);
        return false;
    }

    return true;
}


static int
qemuValidateDomainDeviceDefDiskFrontend(const virDomainDiskDef *disk,
                                        const virDomainDef *def,
                                        virQEMUCaps *qemuCaps)
{
    if (disk->geometry.cylinders > 0 &&
        disk->geometry.heads > 0 &&
        disk->geometry.sectors > 0) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB ||
            disk->bus == VIR_DOMAIN_DISK_BUS_SD) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CHS geometry can not be set for '%1$s' bus"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }

        if (disk->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT &&
            disk->bus != VIR_DOMAIN_DISK_BUS_IDE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CHS translation mode can only be set for 'ide' bus not '%1$s'"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }
    }

    if (disk->serial && disk->bus == VIR_DOMAIN_DISK_BUS_SD) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Serial property not supported for drive bus '%1$s'"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO ||
         disk->bus == VIR_DOMAIN_DISK_BUS_SD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk type of '%1$s' does not support ejectable media"),
                       disk->dst);
        return -1;
    }

    if (disk->copy_on_read == VIR_TRISTATE_SWITCH_ON) {
        if (disk->src->readonly) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("copy_on_read is not compatible with read-only disk '%1$s'"),
                           disk->dst);
            return -1;
        }

        if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ||
            disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("copy_on_read is not supported with removable disk '%1$s'"),
                           disk->dst);
            return -1;
        }
    }

    if (disk->wwn) {
        if ((disk->bus != VIR_DOMAIN_DISK_BUS_IDE) &&
            (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only ide and scsi disk support wwn"));
            return -1;
        }
    }

    if (disk->vendor || disk->product) {
        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only scsi disk supports vendor and product"));
            return -1;
        }
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* make sure that both the bus supports type='lun' (SG_IO). */
        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO &&
            disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device='lun' is not supported for bus='%1$s'"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }

        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_BLOCK)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support scsi-block for lun passthrough"));
            return -1;
        }


        if (disk->copy_on_read == VIR_TRISTATE_SWITCH_ON) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("copy_on_read is not compatible with 'lun' disk '%1$s'"),
                           disk->dst);
            return -1;
        }

        if (disk->wwn) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn is not supported for lun device"));
            return -1;
        }
        if (disk->vendor || disk->product) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting vendor or product is not supported for lun device"));
            return -1;
        }
    }

    if (disk->rotation_rate) {
        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI &&
            disk->bus != VIR_DOMAIN_DISK_BUS_IDE &&
            disk->bus != VIR_DOMAIN_DISK_BUS_SATA) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("rotation rate is only valid for SCSI/IDE/SATA bus"));
            return -1;
        }

        if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("rotation rate is only valid for disk device"));
            return -1;
        }

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_ROTATION_RATE)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("rotation rate is not supported with this QEMU"));
            return -1;
        }
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for scsi disk"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for ide disk"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for fdc disk"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_SATA:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for sata disk"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (disk->queue_size > 0 &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_QUEUE_SIZE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("queue-size property isn't supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_USB:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support '-device usb-storage'"));
            return -1;
        }

        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for usb disk"));
            return -1;
        }

        break;

    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_LAST:
        break;
    }

    if (disk->src->readonly &&
        disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("readonly ide disks are not supported"));
            return -1;
        }

        if (disk->bus == VIR_DOMAIN_DISK_BUS_SATA) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("readonly sata disks are not supported"));
            return -1;
        }
    }

    switch (disk->iomode) {
    case VIR_DOMAIN_DISK_IO_NATIVE:
        if (disk->cachemode != VIR_DOMAIN_DISK_CACHE_DIRECTSYNC &&
            disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("io='native' needs either no disk cache or directsync cache mode"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_IO_URING:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_AIO_IO_URING)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("io uring is not supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_IO_THREADS:
    case VIR_DOMAIN_DISK_IO_DEFAULT:
    case VIR_DOMAIN_DISK_IO_LAST:
        break;
    }

    if (disk->serial &&
        disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
        disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("scsi-block 'lun' devices do not support the serial property"));
        return -1;
    }

    if (disk->serial &&
        qemuValidateDomainDeviceDefDiskSerial(disk->serial) < 0)
        return -1;

    if (disk->iothread && !qemuValidateDomainDeviceDefDiskIOThreads(def, disk))
        return -1;

    return 0;
}


/**
 * qemuValidateDomainDeviceDefDiskBlkdeviotune:
 * @disk: disk configuration
 *
 * Checks whether block io tuning settings make sense. Returns -1 on error and
 * reports a proper libvirt error.
 */
static int
qemuValidateDomainDeviceDefDiskBlkdeviotune(const virDomainDiskDef *disk,
                                            const virDomainDef *def)
{
    /* group_name by itself is ignored by qemu */
    if (disk->blkdeviotune.group_name &&
        !virDomainBlockIoTuneInfoHasAny(&disk->blkdeviotune)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("group_name can be configured only together with settings"));
        return -1;
    }

    /* setting throttling for the SD card didn't work, refuse it explicitly */
    if (disk->bus == VIR_DOMAIN_DISK_BUS_SD &&
        qemuDiskConfigBlkdeviotuneEnabled(disk)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("<iotune> is not supported with bus='sd'"));
        return -1;
    }

    /* checking def here is only for calling from tests */
    if (disk->blkdeviotune.group_name) {
        size_t i;

        for (i = 0; i < def->ndisks; i++) {
            virDomainDiskDef *d = def->disks[i];

            if (STREQ(d->dst, disk->dst) ||
                STRNEQ_NULLABLE(d->blkdeviotune.group_name,
                                disk->blkdeviotune.group_name))
                continue;

            if (!virDomainBlockIoTuneInfoEqual(&d->blkdeviotune,
                                               &disk->blkdeviotune)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("different iotunes for disks %1$s and %2$s"),
                               disk->dst, d->dst);
                return -1;
            }
        }
    }

    if (disk->blkdeviotune.total_bytes_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.read_bytes_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.write_bytes_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.total_iops_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.read_iops_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.write_iops_sec > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.total_bytes_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.read_bytes_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.write_bytes_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.total_iops_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.read_iops_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.write_iops_sec_max > QEMU_BLOCK_IOTUNE_MAX ||
        disk->blkdeviotune.size_iops_sec > QEMU_BLOCK_IOTUNE_MAX) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                      _("block I/O throttle limit must be no more than %1$llu using QEMU"),
                      QEMU_BLOCK_IOTUNE_MAX);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefDiskTransient(const virDomainDiskDef *disk,
                                         const virDomainDef *def,
                                         virQEMUCaps *qemuCaps)

{
    virStorageType actualType = virStorageSourceGetActualType(disk->src);

    if (!disk->transient)
        return 0;

    if (virStorageSourceIsEmpty(disk->src)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("transient disk '%1$s' must not be empty"), disk->dst);
        return -1;
    }

    if (disk->src->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("transient disk '%1$s' must not be read-only"), disk->dst);
        return -1;
    }

    if (actualType != VIR_STORAGE_TYPE_FILE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("transient disk supported only with 'file' type (%1$s)"),
                       disk->dst);
        return -1;
    }

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("transient disk supported only with 'disk' device (%1$s)"),
                       disk->dst);
        return -1;
    }

    if (disk->transientShareBacking == VIR_TRISTATE_BOOL_YES) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SET_ACTION) &&
            !qemuProcessRebootAllowed(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("transient disk backing image sharing with destroy action of lifecycle isn't supported by this QEMU binary"));
            return -1;
        }

        /* sharing the backing file requires hotplug of the disk in the qemu driver */
        switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_SCSI:
            break;

        case VIR_DOMAIN_DISK_BUS_IDE:
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
        case VIR_DOMAIN_DISK_BUS_NONE:
        case VIR_DOMAIN_DISK_BUS_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk bus '%1$s' doesn't support transiend disk backing image sharing"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }
    }

    return 0;
}


int
qemuValidateDomainDeviceDefDisk(const virDomainDiskDef *disk,
                                const virDomainDef *def,
                                virQEMUCaps *qemuCaps)
{
    const char *driverName = virDomainDiskGetDriver(disk);
    virStorageSource *n;
    int idx;
    int partition;

    if (qemuValidateDomainDeviceDefDiskFrontend(disk, def, qemuCaps) < 0)
        return -1;

    if (qemuValidateDomainDeviceDefDiskBlkdeviotune(disk, def) < 0)
        return -1;

    if (qemuValidateDomainDeviceDefDiskTransient(disk, def, qemuCaps) < 0)
        return -1;

    if (disk->src->shared && !disk->src->readonly &&
        !qemuBlockStorageSourceSupportsConcurrentAccess(disk->src)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("shared access for disk '%1$s' requires use of supported storage format"),
                       disk->dst);
        return -1;
    }

    if (driverName && STRNEQ(driverName, "qemu")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported driver name '%1$s' for disk '%2$s'"),
                       driverName, disk->dst);
        return -1;
    }

    if (virDiskNameParse(disk->dst, &idx, &partition) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid disk target '%1$s'"), disk->dst);
        return -1;
    }

    if (partition != 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid disk target '%1$s', partitions can't appear in disk targets"),
                       disk->dst);
        return -1;
    }

    if (disk->discard_no_unref != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_QCOW2_DISCARD_NO_UNREF)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'discard_no_unref' is not supported by this QEMU binary"));
        return -1;
    }

    for (n = disk->src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (qemuDomainValidateStorageSource(n, qemuCaps) < 0)
            return -1;
    }

    if (disk->bus == VIR_DOMAIN_DISK_BUS_SD &&
        disk->src && disk->src->encryption && disk->src->encryption->nsecrets > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("sd card '%1$s' does not support multiple encryption secrets"),
                       disk->dst);
        return -1;
    }

    if (disk->src->type == VIR_STORAGE_TYPE_VHOST_USER) {
        const char *vhosttype = virStorageTypeToString(disk->src->type);

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_USER_BLK)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s disk is not supported with this QEMU binary"),
                           vhosttype);
            return -1;
        }

        if (qemuValidateDomainDefVhostUserRequireSharedMemory(def, vhosttype) < 0)
            return -1;
    }

    if (disk->src->type == VIR_STORAGE_TYPE_VHOST_VDPA) {
        const char *vhosttype = virStorageTypeToString(disk->src->type);

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_BLK_VHOST_VDPA)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s disk is not supported with this QEMU binary"),
                           vhosttype);
            return -1;
        }

        if (qemuValidateDomainDefVhostUserRequireSharedMemory(def, vhosttype) < 0)
            return -1;

        if (disk->cachemode != VIR_DOMAIN_DISK_CACHE_DIRECTSYNC &&
            disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk type '%1$s' requires cache mode '%2$s' or '%3$s'"),
                           virStorageTypeToString(disk->src->type),
                           virDomainDiskCacheTypeToString(VIR_DOMAIN_DISK_CACHE_DIRECTSYNC),
                           virDomainDiskCacheTypeToString(VIR_DOMAIN_DISK_CACHE_DISABLE));
            return -1;
        }
    }

    return 0;
}


/**
 * @qemuCaps: QEMU capabilities
 * @model: SCSI model to check
 *
 * Using the @qemuCaps, let's ensure the provided @model can be supported
 *
 * Returns true if acceptable, false otherwise with error message set.
 */
static bool
qemuValidateCheckSCSIControllerModel(virQEMUCaps *qemuCaps,
                                    int model)
{
    switch ((virDomainControllerModelSCSI) model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the LSI 53C895A SCSI controller"));
            return false;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support virtio scsi controller"));
            return false;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
        /*TODO: need checking work here if necessary */
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_MPTSAS1068)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the LSI SAS1068 (MPT Fusion) controller"));
            return false;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_MEGASAS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the LSI SAS1078 (MegaRAID) controller"));
            return false;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_PVSCSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the pvscsi (VMware paravirtual SCSI) controller"));
            return false;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported controller model: %1$s"),
                       virDomainControllerModelSCSITypeToString(model));
        return false;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_NCR53C90)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the NCR53C90 (ESP) controller"));
        }
        return true;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DC390:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DC390)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the DC390 (ESP) controller"));
        }
        return true;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AM53C974:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_AM53C974)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support the AM53C974 (ESP) controller"));
        }
        return true;
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected SCSI controller model %1$d"),
                       model);
        return false;
    }

    return true;
}



static int
qemuValidateDomainDeviceDefControllerSATA(const virDomainControllerDef *controller,
                                          const virDomainDef *def,
                                          virQEMUCaps *qemuCaps)
{
    /* first SATA controller on Q35 machines is implicit */
    if (controller->idx == 0 && qemuDomainIsQ35(def))
        return 0;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_AHCI)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("SATA is not supported with this QEMU binary"));
        return -1;
    }
    return 0;
}


static int
qemuValidateDomainDeviceDefControllerIDE(const virDomainControllerDef *controller,
                                         const virDomainDef *def)
{
    /* first IDE controller is implicit on various machines */
    if (controller->idx == 0 && qemuDomainHasBuiltinIDE(def))
        return 0;

    /* Since we currently only support the integrated IDE
     * controller on various boards, if we ever get to here, it's
     * because some other machinetype had an IDE controller
     * specified, or one with a single IDE controller had multiple
     * IDE controllers specified.
     */
    if (qemuDomainHasBuiltinIDE(def))
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only a single IDE controller is supported for this machine type"));
    else
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IDE controllers are unsupported for this QEMU binary or machine type"));
    return -1;
}


/* qemuValidateCheckSCSIControllerIOThreads:
 * @controller: Pointer to controller def
 * @def: Pointer to domain def
 *
 * If this controller definition has iothreads set, let's make sure the
 * configuration is right before adding to the command line
 *
 * Returns true if either supported or there are no iothreads for controller;
 * otherwise, returns false if configuration is not quite right.
 */
static bool
qemuValidateCheckSCSIControllerIOThreads(const virDomainControllerDef *controller,
                                         const virDomainDef *def)
{
    if (!controller->iothread)
        return true;

    if (controller->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        controller->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
        controller->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
       virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("virtio-scsi IOThreads only available for virtio pci and virtio ccw controllers"));
       return false;
    }

    /* Can we find the controller iothread in the iothreadid list? */
    if (!virDomainIOThreadIDFind(def, controller->iothread)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("controller iothread '%1$u' not defined in iothreadid"),
                       controller->iothread);
        return false;
    }

    return true;
}


static int
qemuValidateDomainDeviceDefControllerSCSI(const virDomainControllerDef *controller,
                                          const virDomainDef *def)
{
    switch ((virDomainControllerModelSCSI) controller->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
            if (!qemuValidateCheckSCSIControllerIOThreads(controller, def))
                return -1;
            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_NCR53C90:
            if (controller->idx != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("ncr53c90 can only be used as first SCSI controller"));
                return -1;
            }
            if (!qemuDomainHasBuiltinESP(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("ncr53c90 SCSI controller is not a built-in for this machine"));
                return -1;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DC390:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AM53C974:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
            break;
    }

    return 0;
}


/**
 * virValidateControllerPCIModelNameToQEMUCaps:
 * @modelName: model name
 *
 * Maps model names for PCI controllers (virDomainControllerPCIModelName)
 * to the QEMU capabilities required to use them (virQEMUCapsFlags).
 *
 * Returns: the QEMU capability itself (>0) on success; 0 if no QEMU
 *          capability is needed; <0 on error.
 */
static int
virValidateControllerPCIModelNameToQEMUCaps(int modelName)
{
    switch ((virDomainControllerPCIModelName) modelName) {
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE:
        return QEMU_CAPS_DEVICE_PCI_BRIDGE;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE:
        return QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420:
        return QEMU_CAPS_DEVICE_IOH3420;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM:
        return QEMU_CAPS_DEVICE_X3130_UPSTREAM;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM:
        return QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB:
        return QEMU_CAPS_DEVICE_PXB;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB_PCIE:
        return QEMU_CAPS_DEVICE_PXB_PCIE;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_ROOT_PORT:
        return QEMU_CAPS_DEVICE_PCIE_ROOT_PORT;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE:
        return QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_PCI_BRIDGE:
        return QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE:
        return 0;
    case VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_LAST:
    default:
        return -1;
    }

    return -1;
}


static int
qemuValidateDomainDeviceDefControllerAttributes(const virDomainControllerDef *controller)
{
    if (!(controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
          (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI ||
           controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL ||
           controller->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL))) {
        if (controller->queues) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'queues' is only supported by virtio-scsi controller"));
            return -1;
        }
        if (controller->cmd_per_lun) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'cmd_per_lun' is only supported by virtio-scsi controller"));
            return -1;
        }
        if (controller->max_sectors) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'max_sectors' is only supported by virtio-scsi controller"));
            return -1;
        }
        if (controller->ioeventfd) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'ioeventfd' is only supported by virtio-scsi controller"));
            return -1;
        }
        if (controller->iothread) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'iothread' is only supported for virtio-scsi controller"));
            return -1;
        }
    }

    return 0;
}


#define virReportControllerMissingOption(cont, model, modelName, option) \
    virReportError(VIR_ERR_INTERNAL_ERROR, \
                   _("Required option '%1$s' is not set for PCI controller with index '%2$d', model '%3$s' and modelName '%4$s'"), \
                   (option), (cont->idx), (model), (modelName));
#define virReportControllerInvalidOption(cont, model, modelName, option) \
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                   _("Option '%1$s' is not valid for PCI controller with index '%2$d', model '%3$s' and modelName '%4$s'"), \
                   (option), (cont->idx), (model), (modelName));
#define virReportControllerInvalidValue(cont, model, modelName, option) \
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                   _("Option '%1$s' has invalid value for PCI controller with index '%2$d', model '%3$s' and modelName '%4$s'"), \
                   (option), (cont->idx), (model), (modelName));


static int
qemuValidateDomainDeviceDefControllerPCI(const virDomainControllerDef *cont,
                                         const virDomainDef *def,
                                         virQEMUCaps *qemuCaps)

{
    const virDomainPCIControllerOpts *pciopts = &cont->opts.pciopts;
    const char *model = virDomainControllerModelPCITypeToString(cont->model);
    const char *modelName = virDomainControllerPCIModelNameTypeToString(pciopts->modelName);
    int cap = virValidateControllerPCIModelNameToQEMUCaps(pciopts->modelName);

    if (!model) {
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }
    if (!modelName) {
        virReportEnumRangeError(virDomainControllerPCIModelName, pciopts->modelName);
        return -1;
    }

    /* modelName */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        /* modelName should have been set automatically */
        if (pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
            virReportControllerMissingOption(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        /* modelName must be set for pSeries guests, but it's an error
         * for it to be set for any other guest */
        if (qemuDomainIsPSeries(def)) {
            if (pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
                virReportControllerMissingOption(cont, model, modelName, "modelName");
                return -1;
            }
        } else {
            if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
                virReportControllerInvalidOption(cont, model, modelName, "modelName");
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
            virReportControllerInvalidOption(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* modelName (cont'd) */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE &&
            pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420 &&
            pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_ROOT_PORT) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB_PCIE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_PCI_BRIDGE) {
            virReportControllerInvalidValue(cont, model, modelName, "modelName");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* index */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (cont->idx == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Index for '%1$s' controllers must be > 0"),
                           model);
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        /* pSeries guests can have multiple PHBs, so it's expected that
         * the index will not be zero for some of them */
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
            pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE) {
            break;
        }

        /* For all other pci-root and pcie-root controllers, though,
         * the index must be zero */
        if (cont->idx != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Index for '%1$s' controllers must be 0"),
                           model);
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* targetIndex */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        /* PHBs for pSeries guests must have been assigned a targetIndex */
        if (pciopts->targetIndex == -1 &&
            pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE) {
            virReportControllerMissingOption(cont, model, modelName, "targetIndex");
            return -1;
        }

        /* targetIndex only applies to PHBs, so for any other pci-root
         * controller it being present is an error */
        if (pciopts->targetIndex != -1 &&
            pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE) {
            virReportControllerInvalidOption(cont, model, modelName, "targetIndex");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->targetIndex != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "targetIndex");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* pcihole64 */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        if (pciopts->pcihole64 ||  pciopts->pcihole64size != 0) {
            if (!qemuDomainIsI440FX(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Setting the 64-bit PCI hole size is not supported for machine '%1$s'"),
                               def->os.machine);
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        if (pciopts->pcihole64 || pciopts->pcihole64size != 0) {
            if (!qemuDomainIsQ35(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Setting the 64-bit PCI hole size is not supported for machine '%1$s'"),
                               def->os.machine);
                return -1;
            }
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->pcihole64 ||
            pciopts->pcihole64size != 0) {
            virReportControllerInvalidOption(cont, model, modelName, "pcihole64");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* busNr */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        if (pciopts->busNr == -1) {
            virReportControllerMissingOption(cont, model, modelName, "busNr");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->busNr != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "busNr");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* numaNode */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        /* numaNode can be used for these controllers, but it's not set
         * automatically so it can be missing */
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        /* Only PHBs support numaNode */
        if (pciopts->numaNode != -1 &&
            pciopts->modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE) {
            virReportControllerInvalidOption(cont, model, modelName, "numaNode");
            return -1;
        }

        /* However, the default PHB doesn't support numaNode */
        if (pciopts->numaNode != -1 &&
            pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE &&
            pciopts->targetIndex == 0) {
            virReportControllerInvalidOption(cont, model, modelName, "numaNode");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->numaNode != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "numaNode");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* chassisNr */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        if (pciopts->chassisNr == -1) {
            virReportControllerMissingOption(cont, model, modelName, "chassisNr");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->chassisNr != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "chassisNr");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        return -1;
    }

    /* chassis and port */
    switch ((virDomainControllerModelPCI) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        if (pciopts->chassis == -1) {
            virReportControllerMissingOption(cont, model, modelName, "chassis");
            return -1;
        }
        if (pciopts->port == -1) {
            virReportControllerMissingOption(cont, model, modelName, "port");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        if (pciopts->chassis != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "chassis");
            return -1;
        }
        if (pciopts->port != -1) {
            virReportControllerInvalidOption(cont, model, modelName, "port");
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    default:
        virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
    }

    /* hotplug */
    if (pciopts->hotplug != VIR_TRISTATE_SWITCH_ABSENT) {
        switch ((virDomainControllerModelPCI) cont->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX4_ACPI_ROOT_PCI_HOTPLUG)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("setting the '%1$s' property on a '%2$s' device is not supported by this QEMU binary"),
                               "hotplug", "pci-root");
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCIE_ROOT_PORT_HOTPLUG)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("setting the '%1$s' property on a '%2$s' device is not supported by this QEMU binary"),
                               "hotplug", modelName);
                return -1;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
            virReportControllerInvalidOption(cont, model, modelName, "hotplug");
            return -1;

        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
        default:
            virReportEnumRangeError(virDomainControllerModelPCI, cont->model);
        }
    }

    /* QEMU device availability */
    if (cap < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown QEMU device for '%1$s' controller"),
                       modelName);
        return -1;
    }
    if (cap > 0 && !virQEMUCapsGet(qemuCaps, cap)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The '%1$s' device is not supported by this QEMU binary"),
                       modelName);
        return -1;
    }

    /* PHBs didn't support numaNode from the very beginning, so an extra
     * capability check is required */
    if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
        pciopts->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE &&
        pciopts->numaNode != -1 &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPAPR_PCI_HOST_BRIDGE_NUMA_NODE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Option '%1$s' is not supported by '%2$s' device with this QEMU binary"),
                       "numaNode", modelName);
        return -1;
    }

    return 0;
}


#undef virReportControllerInvalidValue
#undef virReportControllerInvalidOption
#undef virReportControllerMissingOption


static int
qemuValidateDomainDeviceDefController(const virDomainControllerDef *controller,
                                      const virDomainDef *def,
                                      virQEMUCaps *qemuCaps)
{
    int ret = 0;

    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
        !qemuValidateCheckSCSIControllerModel(qemuCaps, controller->model))
        return -1;

    if (qemuValidateDomainDeviceDefControllerAttributes(controller) < 0)
        return -1;

    switch (controller->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
        ret = qemuValidateDomainDeviceDefControllerIDE(controller, def);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        ret = qemuValidateDomainDeviceDefControllerSCSI(controller, def);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        ret = qemuValidateDomainDeviceDefControllerPCI(controller, def,
                                                       qemuCaps);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        ret = qemuValidateDomainDeviceDefControllerSATA(controller, def,
                                                        qemuCaps);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        break;
    }

    return ret;
}


static int
qemuValidateDomainDeviceDefSPICEGraphics(const virDomainGraphicsDef *graphics,
                                         virQEMUDriver *driver,
                                         virQEMUCaps *qemuCaps)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainGraphicsListenDef *glisten = NULL;
    int tlsPort = graphics->data.spice.tlsPort;

    glisten = virDomainGraphicsGetListen((virDomainGraphicsDef *)graphics, 0);
    if (!glisten) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing listen element"));
        return -1;
    }

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        if (tlsPort > 0 && !cfg->spiceTLS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spice TLS port set in XML configuration, but TLS is disabled in qemu.conf"));
            return -1;
        }
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        break;
    }

    if (graphics->data.spice.gl == VIR_TRISTATE_BOOL_YES) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE_GL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support spice OpenGL"));
            return -1;
        }

        if (graphics->data.spice.rendernode &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE_RENDERNODE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support spice OpenGL rendernode"));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefVNCGraphics(const virDomainGraphicsDef *graphics,
                                       virQEMUCaps *qemuCaps)
{
    if (graphics->data.vnc.powerControl != VIR_TRISTATE_BOOL_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC_POWER_CONTROL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("VNC power control is not available"));
        return -1;
    }

    if (graphics->data.vnc.auth.passwd &&
        strlen(graphics->data.vnc.auth.passwd) > 8) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("VNC password is %1$zu characters long, only 8 permitted"),
                       strlen(graphics->data.vnc.auth.passwd));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefDBusGraphics(const virDomainGraphicsDef *graphics,
                                        const virDomainDef *def)
{
    if (graphics->data.dbus.audioId > 0) {
        virDomainAudioDef *audio = virDomainDefFindAudioByID(def, graphics->data.dbus.audioId);

        if (audio && audio->type != VIR_DOMAIN_AUDIO_TYPE_DBUS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The associated audio is not of 'dbus' kind."));
            return -1;
        }
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefGraphics(const virDomainGraphicsDef *graphics,
                                    const virDomainDef *def,
                                    virQEMUDriver *driver,
                                    virQEMUCaps *qemuCaps)
{
    virDomainCapsDeviceGraphics graphicsCaps = { 0 };
    bool have_egl_headless = false;
    size_t i;

    virQEMUCapsFillDomainDeviceGraphicsCaps(qemuCaps, &graphicsCaps);

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(graphicsCaps.type, graphics->type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%1$s graphics are not supported with this QEMU"),
                       virDomainGraphicsTypeToString(graphics->type));
        return -1;
    }

    for (i = 0; i < def->ngraphics; i++) {
        if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS) {
            have_egl_headless = true;
            break;
        }
    }

    /* Only VNC and SPICE can be paired with egl-headless, the other types
     * either don't make sense to pair with egl-headless or aren't even
     * supported by QEMU.
     */
    if (have_egl_headless) {
        if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS &&
            graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
            graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("graphics type 'egl-headless' is only supported with one of: 'vnc', 'spice' graphics types"));
            return -1;
        }

        /* '-spice gl=on' and '-display egl-headless' are mutually
         * exclusive
         */
        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE &&
            graphics->data.spice.gl == VIR_TRISTATE_BOOL_YES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("multiple OpenGL displays are not supported by QEMU"));
            return -1;
        }
    }

    switch (graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if (qemuValidateDomainDeviceDefSPICEGraphics(graphics, driver,
                                                     qemuCaps) < 0)
            return -1;

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        if (graphics->data.egl_headless.rendernode &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_EGL_HEADLESS_RENDERNODE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support OpenGL rendernode with egl-headless graphics type"));
            return -1;
        }

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if (qemuValidateDomainDeviceDefVNCGraphics(graphics, qemuCaps) < 0)
            return -1;

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        if (qemuValidateDomainDeviceDefDBusGraphics(graphics, def) < 0)
            return -1;

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        break;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefFS(virDomainFSDef *fs,
                              const virDomainDef *def,
                              virQEMUDriver *driver,
                              virQEMUCaps *qemuCaps)
{
    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only supports mount filesystem type"));
        return -1;
    }

    if (fs->space_hard_limit > 0 || fs->space_soft_limit > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("filesystem usage limits are not supported with QEMU"));
        return -1;
    }

    if (fs->multidevs != VIR_DOMAIN_FS_MULTIDEVS_DEFAULT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_FSDEV_MULTIDEVS)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("multidevs is not supported with this QEMU binary"));
        return -1;
    }

    if ((fs->fmode != 0) || (fs->dmode != 0)) {
        if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_MAPPED) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("fmode and dmode must be used with accessmode=mapped"));
            return -1;
        }
    }

    if (fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS &&
        fs->sandbox != VIR_DOMAIN_FS_SANDBOX_MODE_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("sandbox can only be used with driver=virtiofs"));
        return -1;
    }

    switch (fs->fsdriver) {
    case VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PATH:
        break;

    case VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE:
        if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only supports passthrough accessmode"));
            return -1;
        }
        break;

    case VIR_DOMAIN_FS_DRIVER_TYPE_LOOP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_NBD:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Filesystem driver type not supported"));
        return -1;

    case VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS:
        if (!fs->sock) {
            if (fs->readonly) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtiofs does not yet support read-only mode"));
                return -1;
            }
            if (!driver->privileged) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtiofs is not yet supported in session mode"));
                return -1;
            }
            if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtiofs only supports passthrough accessmode"));
                return -1;
            }
            if (fs->wrpolicy != VIR_DOMAIN_FS_WRPOLICY_DEFAULT) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtiofs does not support wrpolicy"));
                return -1;
            }
        }

        if (fs->readonly) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs does not support read-only access"));
            return -1;
        }

        if (fs->model != VIR_DOMAIN_FS_MODEL_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs does not support model"));
            return -1;
        }
        if (fs->format != VIR_STORAGE_FILE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs does not support format"));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_USER_FS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs is not supported with this QEMU binary"));
            return -1;
        }
        if (fs->multidevs != VIR_DOMAIN_FS_MULTIDEVS_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs does not support multidevs"));
            return -1;
        }
        if ((fs->fmode != 0) || (fs->dmode != 0)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtiofs does not support fmode and dmode"));
            return -1;
        }
        if (qemuValidateDomainDefVhostUserRequireSharedMemory(def, "virtiofs") < 0) {
            return -1;
        }
        if (fs->info.bootIndex &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VHOST_USER_FS_BOOTINDEX)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("setting virtiofs boot order is not supported with this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_FS_DRIVER_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainFSDriverType, fs->fsdriver);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefAudio(virDomainAudioDef *audio,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps G_GNUC_UNUSED)
{
    switch (audio->type) {
    case VIR_DOMAIN_AUDIO_TYPE_NONE:
    case VIR_DOMAIN_AUDIO_TYPE_ALSA:
    case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
    case VIR_DOMAIN_AUDIO_TYPE_JACK:
    case VIR_DOMAIN_AUDIO_TYPE_OSS:
    case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
    case VIR_DOMAIN_AUDIO_TYPE_SDL:
    case VIR_DOMAIN_AUDIO_TYPE_FILE:
        break;

    case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        if (!virDomainDefHasSpiceGraphics(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Spice audio is not supported without spice graphics"));
            return -1;
        }
        break;

    case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DISPLAY_DBUS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("D-Bus audio is not supported with this QEMU"));
            return -1;
        }
        break;

    case VIR_DOMAIN_AUDIO_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainAudioType, audio->type);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefCrypto(virDomainCryptoDef *crypto,
                                  const virDomainDef *def G_GNUC_UNUSED,
                                  virQEMUCaps *qemuCaps)
{
    virDomainCapsDeviceCrypto cryptoCaps = { 0 };

    switch (crypto->type) {
    case VIR_DOMAIN_CRYPTO_TYPE_QEMU:
        virQEMUCapsFillDomainDeviceCryptoCaps(qemuCaps, &cryptoCaps);
        break;

    case VIR_DOMAIN_CRYPTO_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainCryptoType, crypto->type);
        return -1;
    }

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(cryptoCaps.model, crypto->model)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("crypto model %1$s is not supported"),
                       virDomainCryptoModelTypeToString(crypto->model));
        return -1;
    }

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(cryptoCaps.type, crypto->type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("crypto type %1$s is not supported"),
                       virDomainCryptoTypeTypeToString(crypto->type));
        return -1;
    }

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(cryptoCaps.backendModel, crypto->backend)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("crypto backend %1$s is not supported"),
                       virDomainCryptoBackendTypeToString(crypto->backend));
        return -1;
    }

    return 0;
}


static int
qemuSoundCodecTypeToCaps(int type)
{
    switch (type) {
    case VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX:
        return QEMU_CAPS_HDA_DUPLEX;
    case VIR_DOMAIN_SOUND_CODEC_TYPE_MICRO:
        return QEMU_CAPS_HDA_MICRO;
    case VIR_DOMAIN_SOUND_CODEC_TYPE_OUTPUT:
        return QEMU_CAPS_HDA_OUTPUT;
    default:
        return -1;
    }
}


static int
qemuValidateDomainDeviceDefSound(virDomainSoundDef *sound,
                                 virQEMUCaps *qemuCaps)
{
    size_t i;

    switch (sound->model) {
    case VIR_DOMAIN_SOUND_MODEL_USB:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_USB_AUDIO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("usb-audio controller is not supported by this QEMU binary"));
            return -1;
        }
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH9:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ICH9_INTEL_HDA)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The ich9-intel-hda audio controller is not supported in this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_SOUND_MODEL_ES1370:
    case VIR_DOMAIN_SOUND_MODEL_AC97:
    case VIR_DOMAIN_SOUND_MODEL_ICH6:
    case VIR_DOMAIN_SOUND_MODEL_SB16:
    case VIR_DOMAIN_SOUND_MODEL_PCSPK:
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH7:
    case VIR_DOMAIN_SOUND_MODEL_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("sound card model '%1$s' is not supported by qemu"),
                       virDomainSoundModelTypeToString(sound->model));
        return -1;
    }

    if (virDomainSoundModelSupportsCodecs(sound)) {
        for (i = 0; i < sound->ncodecs; i++) {
            const char *stype;
            int type, flags;

            type = sound->codecs[i]->type;
            stype = qemuSoundCodecTypeToString(type);
            flags = qemuSoundCodecTypeToCaps(type);

            if (flags == -1 || !virQEMUCapsGet(qemuCaps, flags)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("%1$s not supported in this QEMU binary"), stype);
                return -1;
            }
        }
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefVsock(virQEMUCaps *qemuCaps)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VHOST_VSOCK)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vsock device is not supported with this QEMU binary"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefTPM(virDomainTPMDef *tpm,
                               const virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    virDomainCapsDeviceTPM tpmCaps = { 0 };

    virQEMUCapsFillDomainDeviceTPMCaps(qemuCaps, &tpmCaps);

    if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR) {
        const virDomainTPMVersion version = tpm->data.emulator.version;

        if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(tpmCaps.backendVersion, version)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("TPM version '%1$s' is not supported"),
                           virDomainTPMVersionTypeToString(version));
            return -1;
        }

        switch (version) {
        case VIR_DOMAIN_TPM_VERSION_1_2:
            /* TPM 1.2 + CRB do not work */
            if (tpm->model == VIR_DOMAIN_TPM_MODEL_CRB) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported interface '%1$s' for TPM 1.2"),
                               virDomainTPMModelTypeToString(tpm->model));
                return -1;
            }
            /* TPM 1.2 + SPAPR do not work with any 'type' (backend) */
            if (tpm->model == VIR_DOMAIN_TPM_MODEL_SPAPR) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("TPM 1.2 is not supported with the SPAPR device model"));
                return -1;
            }
            /* TPM 1.2 + ARM does not work */
            if (qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("TPM 1.2 is not supported on ARM"));
                return -1;
            }
            break;
        case VIR_DOMAIN_TPM_VERSION_2_0:
        case VIR_DOMAIN_TPM_VERSION_DEFAULT:
        case VIR_DOMAIN_TPM_VERSION_LAST:
            break;
        }
    }

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(tpmCaps.backendModel, tpm->type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The QEMU executable %1$s does not support TPM backend type %2$s"),
                       def->emulator,
                       virDomainTPMBackendTypeToString(tpm->type));
        return -1;
    }

    if (ARCH_IS_PPC64(def->os.arch) &&
        tpm->model == VIR_DOMAIN_TPM_MODEL_SPAPR_PROXY &&
        tpm->type != VIR_DOMAIN_TPM_TYPE_PASSTHROUGH) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("TPM Proxy model %1$s requires 'Passthrough' backend"),
                        virDomainTPMModelTypeToString(tpm->model));
        return -1;
    }

    if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(tpmCaps.model, tpm->model)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The QEMU executable %1$s does not support TPM model %2$s"),
                       def->emulator,
                       virDomainTPMModelTypeToString(tpm->model));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefInput(const virDomainInputDef *input,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    const char *baseName;
    int cap;
    int ccwCap;

    if (input->bus == VIR_DOMAIN_INPUT_BUS_PS2 && !ARCH_IS_X86(def->os.arch) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_I8042)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%1$s is not supported by this QEMU binary"),
                       virDomainInputBusTypeToString(input->bus));
        return -1;
    }

    if (input->bus == VIR_DOMAIN_INPUT_BUS_USB &&
        input->type == VIR_DOMAIN_INPUT_TYPE_KBD &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_KBD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb keyboard is not supported by this QEMU binary"));
        return -1;
    }

    if (input->bus != VIR_DOMAIN_INPUT_BUS_VIRTIO)
        return 0;

    /* model=virtio-(non-)transitional is unsupported */
    switch ((virDomainInputModel)input->model) {
    case VIR_DOMAIN_INPUT_MODEL_VIRTIO_TRANSITIONAL:
    case VIR_DOMAIN_INPUT_MODEL_VIRTIO_NON_TRANSITIONAL:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("virtio (non-)transitional models are not supported for input type=%1$s"),
                       virDomainInputTypeToString(input->type));
        return -1;
    case VIR_DOMAIN_INPUT_MODEL_VIRTIO:
    case VIR_DOMAIN_INPUT_MODEL_DEFAULT:
        break;
    case VIR_DOMAIN_INPUT_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainInputModel,
                                input->model);
        return -1;
    }

    switch ((virDomainInputType)input->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
        baseName = "virtio-mouse";
        cap = QEMU_CAPS_VIRTIO_MOUSE;
        ccwCap = QEMU_CAPS_DEVICE_VIRTIO_MOUSE_CCW;
        break;
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
        baseName = "virtio-tablet";
        cap = QEMU_CAPS_VIRTIO_TABLET;
        ccwCap = QEMU_CAPS_DEVICE_VIRTIO_TABLET_CCW;
        break;
    case VIR_DOMAIN_INPUT_TYPE_KBD:
        baseName = "virtio-keyboard";
        cap = QEMU_CAPS_VIRTIO_KEYBOARD;
        ccwCap = QEMU_CAPS_DEVICE_VIRTIO_KEYBOARD_CCW;
        break;
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        baseName = "virtio-input-host";
        cap = QEMU_CAPS_VIRTIO_INPUT_HOST;
        ccwCap = QEMU_CAPS_LAST;
        break;
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        baseName = "input-linux";
        cap = QEMU_CAPS_INPUT_LINUX;
        ccwCap = QEMU_CAPS_LAST;
        break;
    case VIR_DOMAIN_INPUT_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainInputType,
                                input->type);
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, cap) ||
        (input->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
         !virQEMUCapsGet(qemuCaps, ccwCap))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%1$s is not supported by this QEMU binary"),
                       baseName);
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefMemballoon(const virDomainMemballoonDef *memballoon,
                                      virQEMUCaps *qemuCaps)
{
    if (!memballoon ||
        memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_NONE) {
        return 0;
    }

    if (memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_TRANSITIONAL &&
        memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_NON_TRANSITIONAL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Memory balloon device type '%1$s' is not supported by this version of qemu"),
                       virDomainMemballoonModelTypeToString(memballoon->model));
        return -1;
    }

    if (memballoon->autodeflate != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("deflate-on-oom is not supported by this QEMU binary"));
        return -1;
    }

    if (memballoon->free_page_reporting != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BALLOON_FREE_PAGE_REPORTING)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("freePageReporting is not supported by this QEMU binary"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefIOMMU(const virDomainIOMMUDef *iommu,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    switch (iommu->model) {
    case VIR_DOMAIN_IOMMU_MODEL_INTEL:
        if (!qemuDomainIsQ35(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is only supported with Q35 machines"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_INTEL_IOMMU)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is not supported with this QEMU binary"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_IOMMU_MODEL_SMMUV3:
        if (!qemuDomainIsARMVirt(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is only supported with ARM Virt machines"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_VIRT_IOMMU)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is not supported with this QEMU binary"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_IOMMU_MODEL_VIRTIO:
        if (!qemuDomainIsARMVirt(def) &&
            !qemuDomainIsQ35(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is only supported with Q35 and ARM Virt machines"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_IOMMU_PCI) ||
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_IOMMU_BOOT_BYPASS)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' is not supported with this QEMU binary"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        if (def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' requires ACPI"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        if (iommu->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            iommu->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("IOMMU device: '%1$s' needs a PCI address"),
                           virDomainIOMMUModelTypeToString(iommu->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_IOMMU_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainIOMMUModel, iommu->model);
        return -1;
    }

    /* These capability checks ensure we're not trying to use features
     * of Intel IOMMU that the QEMU binary does not support, but they
     * also make sure we report an error when trying to use features
     * that are not implemented by SMMUv3 */

    if (iommu->intremap != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_INTREMAP)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu: interrupt remapping is not supported with this QEMU binary"));
        return -1;
    }
    if (iommu->caching_mode != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_CACHING_MODE))  {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu: caching mode is not supported with this QEMU binary"));
        return -1;
    }
    if (iommu->eim != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_EIM))  {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu: eim is not supported with this QEMU binary"));
        return -1;
    }
    if (iommu->iotlb != VIR_TRISTATE_SWITCH_ABSENT &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_DEVICE_IOTLB)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu: device IOTLB is not supported with this QEMU binary"));
        return -1;
    }
    if (iommu->aw_bits > 0 &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_AW_BITS)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu: aw_bits is not supported with this QEMU binary"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefNVRAM(virDomainNVRAMDef *nvram,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps)
{
    if (!nvram)
        return 0;

    if (qemuDomainIsPSeries(def)) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVRAM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("nvram device is not supported by this QEMU binary"));
            return -1;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nvram device is only supported for PPC64"));
        return -1;
    }

    if (!(nvram->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO &&
          nvram->info.addr.spaprvio.has_reg)) {

        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("nvram address type must be spaprvio"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefHub(virDomainHubDef *hub,
                               virQEMUCaps *qemuCaps)
{
    if (hub->type != VIR_DOMAIN_HUB_TYPE_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hub type %1$s not supported"),
                       virDomainHubTypeToString(hub->type));
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_HUB)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb-hub not supported by QEMU binary"));
        return -1;
    }

    return 0;
}


static int
qemuValidateDomainDeviceDefMemory(virDomainMemoryDef *mem,
                                  virQEMUCaps *qemuCaps)
{
    virSGXCapability *sgxCaps;
    ssize_t node = -1;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PC_DIMM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("memory hotplug isn't supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("nvdimm isn't supported by this QEMU binary"));
            return -1;
        }

        if (mem->target.nvdimm.readonly &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVDIMM_UNARMED)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("nvdimm readonly property is not available with this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_PMEM_PCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-pmem isn't supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MEM_PCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-mem isn't supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SGX_EPC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("sgx epc isn't supported by this QEMU binary"));
            return -1;
        }

        sgxCaps = virQEMUCapsGetSGXCapabilities(qemuCaps);

        if (sgxCaps->nSgxSections == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU version didn't provide SGX EPC NUMA info"));
            return -1;
        }

        if (mem->source.sgx_epc.nodes) {
            while ((node = virBitmapNextSetBit(mem->source.sgx_epc.nodes, node)) >= 0) {
                if (mem->size > sgxCaps->sgxSections[node].size) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("sgx epc size %1$lld on host node %2$zd is less than requested size %3$lld"),
                                   sgxCaps->sgxSections[node].size, node, mem->size);
                    return -1;
                }
            }
        } else {
            /* allocate epc from host node 0 by default if user doesn't
             * specify it. */
            if (mem->size > sgxCaps->sgxSections[0].size) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("sgx epc size %1$lld on host node %2$d is less than requested size %3$lld"),
                               sgxCaps->sgxSections[0].size, 0, mem->size);
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
qemuValidateDomainDeviceDefShmem(virDomainShmemDef *shmem,
                                 virQEMUCaps *qemuCaps)
{
    switch (shmem->model) {
    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ivshmem device is no longer supported"));
        return -1;

    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_PLAIN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' is not supported by this QEMU binary"),
                           virDomainShmemModelTypeToString(shmem->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' is not supported by this QEMU binary"),
                           virDomainShmemModelTypeToString(shmem->model));
            return -1;
        }
        break;

    case VIR_DOMAIN_SHMEM_MODEL_LAST:
        virReportEnumRangeError(virDomainShmemModel, shmem->model);
        return -1;
    }

    return 0;
}


int
qemuValidateDomainDeviceDef(const virDomainDeviceDef *dev,
                            const virDomainDef *def,
                            void *opaque,
                            void *parseOpaque)
{
    virQEMUDriver *driver = opaque;
    g_autoptr(virQEMUCaps) qemuCapsLocal = NULL;
    virQEMUCaps *qemuCaps = parseOpaque;

    if (!qemuCaps) {
        if (!(qemuCapsLocal = virQEMUCapsCacheLookup(driver->qemuCapsCache,
                                                     def->emulator)))
            return -1;

        qemuCaps = qemuCapsLocal;
    }

    if (qemuValidateDomainDeviceInfo(dev, def, qemuCaps) < 0)
        return -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_NET:
        return qemuValidateDomainDeviceDefNetwork(dev->data.net, qemuCaps);

    case VIR_DOMAIN_DEVICE_CHR:
        return qemuValidateDomainChrDef(dev->data.chr, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_SMARTCARD:
        return qemuValidateDomainSmartcardDef(dev->data.smartcard, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_RNG:
        return qemuValidateDomainRNGDef(dev->data.rng, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        return qemuValidateDomainRedirdevDef(dev->data.redirdev, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_WATCHDOG:
        return qemuValidateDomainWatchdogDef(dev->data.watchdog, def);

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        return qemuValidateDomainDeviceDefHostdev(dev->data.hostdev, def,
                                                 qemuCaps);

    case VIR_DOMAIN_DEVICE_VIDEO:
        return qemuValidateDomainDeviceDefVideo(dev->data.video, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_DISK:
        return qemuValidateDomainDeviceDefDisk(dev->data.disk, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        return qemuValidateDomainDeviceDefController(dev->data.controller, def,
                                                    qemuCaps);

    case VIR_DOMAIN_DEVICE_VSOCK:
        return qemuValidateDomainDeviceDefVsock(qemuCaps);

    case VIR_DOMAIN_DEVICE_TPM:
        return qemuValidateDomainDeviceDefTPM(dev->data.tpm, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_GRAPHICS:
        return qemuValidateDomainDeviceDefGraphics(dev->data.graphics, def,
                                                  driver, qemuCaps);

    case VIR_DOMAIN_DEVICE_INPUT:
        return qemuValidateDomainDeviceDefInput(dev->data.input, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        return qemuValidateDomainDeviceDefMemballoon(dev->data.memballoon, qemuCaps);

    case VIR_DOMAIN_DEVICE_IOMMU:
        return qemuValidateDomainDeviceDefIOMMU(dev->data.iommu, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_FS:
        return qemuValidateDomainDeviceDefFS(dev->data.fs, def, driver, qemuCaps);

    case VIR_DOMAIN_DEVICE_NVRAM:
        return qemuValidateDomainDeviceDefNVRAM(dev->data.nvram, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_HUB:
        return qemuValidateDomainDeviceDefHub(dev->data.hub, qemuCaps);

    case VIR_DOMAIN_DEVICE_SOUND:
        return qemuValidateDomainDeviceDefSound(dev->data.sound, qemuCaps);

    case VIR_DOMAIN_DEVICE_MEMORY:
        return qemuValidateDomainDeviceDefMemory(dev->data.memory, qemuCaps);

    case VIR_DOMAIN_DEVICE_SHMEM:
        return qemuValidateDomainDeviceDefShmem(dev->data.shmem, qemuCaps);

    case VIR_DOMAIN_DEVICE_AUDIO:
        return qemuValidateDomainDeviceDefAudio(dev->data.audio, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_CRYPTO:
        return qemuValidateDomainDeviceDefCrypto(dev->data.crypto, def, qemuCaps);

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    return 0;
}
