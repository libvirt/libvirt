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
#include "qemu_domain.h"

#define VIR_FROM_THIS VIR_FROM_QEMU


static int
qemuValidateDomainDefPSeriesFeature(const virDomainDef *def,
                                    virQEMUCapsPtr qemuCaps,
                                    int feature)
{
    const char *str;

    if (def->features[feature] != VIR_TRISTATE_SWITCH_ABSENT &&
        !qemuDomainIsPSeries(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The '%s' feature is not supported for "
                         "architecture '%s' or machine type '%s'"),
                       virDomainFeatureTypeToString(feature),
                       virArchToString(def->os.arch),
                       def->os.machine);
        return -1;
    }

    if (def->features[feature] == VIR_TRISTATE_SWITCH_ABSENT)
        return 0;

    switch (feature) {
    case VIR_DOMAIN_FEATURE_HPT:
        if (def->features[feature] != VIR_TRISTATE_SWITCH_ON)
            break;

        if (def->hpt_resizing != VIR_DOMAIN_HPT_RESIZING_NONE) {
            if (!virQEMUCapsGet(qemuCaps,
                                QEMU_CAPS_MACHINE_PSERIES_RESIZE_HPT)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("HTP resizing is not supported by this "
                                "QEMU binary"));
                return -1;
            }

            str = virDomainHPTResizingTypeToString(def->hpt_resizing);
            if (!str) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Invalid setting for HPT resizing"));
                return -1;
            }
        }

        if (def->hpt_maxpagesize > 0 &&
            !virQEMUCapsGet(qemuCaps,
                            QEMU_CAPS_MACHINE_PSERIES_CAP_HPT_MAX_PAGE_SIZE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Configuring the page size for HPT guests "
                             "is not supported by this QEMU binary"));
            return -1;
        }
        break;

    case VIR_DOMAIN_FEATURE_HTM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_CAP_HTM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("HTM configuration is not supported by this "
                             "QEMU binary"));
            return -1;
        }

        str = virTristateSwitchTypeToString(def->features[feature]);
        if (!str) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid setting for HTM state"));
            return -1;
        }

        break;

    case VIR_DOMAIN_FEATURE_NESTED_HV:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_CAP_NESTED_HV)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Nested HV configuration is not supported by "
                             "this QEMU binary"));
            return -1;
        }

        str = virTristateSwitchTypeToString(def->features[feature]);
        if (!str) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid setting for nested HV state"));
            return -1;
        }

        break;

    case VIR_DOMAIN_FEATURE_CCF_ASSIST:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_PSERIES_CAP_CCF_ASSIST)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ccf-assist configuration is not supported by "
                           "this QEMU binary"));
            return -1;
        }

        str = virTristateSwitchTypeToString(def->features[feature]);
        if (!str) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Invalid setting for ccf-assist state"));
            return -1;
        }

        break;
    }

    return 0;
}


int
qemuValidateDomainDefFeatures(const virDomainDef *def,
                              virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_FEATURE_LAST; i++) {
        const char *featureName = virDomainFeatureTypeToString(i);

        switch ((virDomainFeature) i) {
        case VIR_DOMAIN_FEATURE_IOAPIC:
            if (def->features[i] != VIR_DOMAIN_IOAPIC_NONE) {
                if (!ARCH_IS_X86(def->os.arch)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("The '%s' feature is not supported for "
                                     "architecture '%s' or machine type '%s'"),
                                   featureName,
                                   virArchToString(def->os.arch),
                                   def->os.machine);
                    return -1;
                }

                if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_KERNEL_IRQCHIP)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("I/O APIC tuning is not supported by "
                                     "this QEMU binary"));
                    return -1;
                }

                switch ((virDomainIOAPIC) def->features[i]) {
                case VIR_DOMAIN_IOAPIC_QEMU:
                    if (!virQEMUCapsGet(qemuCaps,
                                        QEMU_CAPS_MACHINE_KERNEL_IRQCHIP_SPLIT)) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("split I/O APIC is not supported by this "
                                         "QEMU binary"));
                        return -1;
                    }
                    break;
                case VIR_DOMAIN_IOAPIC_KVM:
                case VIR_DOMAIN_IOAPIC_NONE:
                case VIR_DOMAIN_IOAPIC_LAST:
                    break;
                }
            }
            break;

        case VIR_DOMAIN_FEATURE_HPT:
        case VIR_DOMAIN_FEATURE_HTM:
        case VIR_DOMAIN_FEATURE_NESTED_HV:
        case VIR_DOMAIN_FEATURE_CCF_ASSIST:
            if (qemuValidateDomainDefPSeriesFeature(def, qemuCaps, i) < 0)
                return -1;
            break;

        case VIR_DOMAIN_FEATURE_GIC:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON &&
                !qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The '%s' feature is not supported for "
                                 "architecture '%s' or machine type '%s'"),
                               featureName,
                               virArchToString(def->os.arch),
                               def->os.machine);
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_SMM:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_SMM_OPT)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("smm is not available with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_KVM:
            if (def->kvm_features[VIR_DOMAIN_KVM_DEDICATED] == VIR_TRISTATE_SWITCH_ON &&
                (!def->cpu || def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("kvm-hint-dedicated=on is only applicable "
                                 "for cpu host-passthrough"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_VMPORT:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                !virQEMUCapsSupportsVmport(qemuCaps, def)) {

                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vmport is not available "
                                 "with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_VMCOREINFO:
            if (def->features[i] == VIR_TRISTATE_SWITCH_ON &&
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMCOREINFO)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                              _("vmcoreinfo is not available "
                                "with this QEMU binary"));
                return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_APIC:
            /* The kvm_pv_eoi feature is x86-only. */
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                def->apic_eoi != VIR_TRISTATE_SWITCH_ABSENT &&
                !ARCH_IS_X86(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("The 'eoi' attribute of the '%s' feature "
                                 "is not supported for architecture '%s' or "
                                 "machine type '%s'"),
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
                               _("The '%s' feature is not supported for "
                                 "architecture '%s' or machine type '%s'"),
                                 featureName,
                                 virArchToString(def->os.arch),
                                 def->os.machine);
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_HYPERV:
            if (def->features[i] != VIR_TRISTATE_SWITCH_ABSENT &&
                !ARCH_IS_X86(def->os.arch) && !qemuDomainIsARMVirt(def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Hyperv features are not supported for "
                                 "architecture '%s' or machine type '%s'"),
                                 virArchToString(def->os.arch),
                                 def->os.machine);
                 return -1;
            }
            break;

        case VIR_DOMAIN_FEATURE_PMU:
            if (def->features[i] == VIR_TRISTATE_SWITCH_OFF &&
                ARCH_IS_PPC64(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PMU is always enabled for architecture '%s'"),
                                 virArchToString(def->os.arch));
                 return -1;
            }
            break;

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
