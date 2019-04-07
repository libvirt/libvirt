/*
 * cpu_x86_data.h: x86 specific CPU data
 *
 * Copyright (C) 2009-2010, 2013 Red Hat, Inc.
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

#ifndef LIBVIRT_CPU_X86_DATA_H
# define LIBVIRT_CPU_X86_DATA_H


typedef struct _virCPUx86CPUID virCPUx86CPUID;
struct _virCPUx86CPUID {
    uint32_t eax_in;
    uint32_t ecx_in;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

# define CPUX86_BASIC    0x0
# define CPUX86_KVM      0x40000000
# define CPUX86_EXTENDED 0x80000000

# define VIR_CPU_x86_KVM_CLOCKSOURCE  "__kvm_clocksource"
# define VIR_CPU_x86_KVM_NOP_IO_DELAY "__kvm_no_io_delay"
# define VIR_CPU_x86_KVM_MMU_OP       "__kvm_mmu_op"
# define VIR_CPU_x86_KVM_CLOCKSOURCE2 "__kvm_clocksource2"
# define VIR_CPU_x86_KVM_ASYNC_PF     "__kvm_async_pf"
# define VIR_CPU_x86_KVM_STEAL_TIME   "__kvm_steal_time"
# define VIR_CPU_x86_KVM_PV_EOI       "__kvm_pv_eoi"
# define VIR_CPU_x86_KVM_PV_UNHALT    "__kvm_pv_unhalt"
# define VIR_CPU_x86_KVM_CLOCKSOURCE_STABLE_BIT "__kvm_clocksource_stable"

/*
 * The following HyperV feature names suffixes must exactly match corresponding
 * ones defined for virDomainHyperv in domain_conf.c.
 * E.g "__kvm_runtime" -> "runtime", "__kvm_hv_spinlocks" -> "spinlocks" etc.
*/
# define VIR_CPU_x86_KVM_HV_RUNTIME   "__kvm_hv_runtime"
# define VIR_CPU_x86_KVM_HV_SYNIC     "__kvm_hv_synic"
# define VIR_CPU_x86_KVM_HV_STIMER    "__kvm_hv_stimer"
# define VIR_CPU_x86_KVM_HV_RELAXED   "__kvm_hv_relaxed"
# define VIR_CPU_x86_KVM_HV_SPINLOCKS  "__kvm_hv_spinlocks"
# define VIR_CPU_x86_KVM_HV_VAPIC     "__kvm_hv_vapic"
# define VIR_CPU_x86_KVM_HV_VPINDEX   "__kvm_hv_vpindex"
# define VIR_CPU_x86_KVM_HV_RESET     "__kvm_hv_reset"
# define VIR_CPU_x86_KVM_HV_FREQUENCIES "__kvm_hv_frequencies"
# define VIR_CPU_x86_KVM_HV_REENLIGHTENMENT "__kvm_hv_reenlightenment"
# define VIR_CPU_x86_KVM_HV_TLBFLUSH  "__kvm_hv_tlbflush"
# define VIR_CPU_x86_KVM_HV_IPI       "__kvm_hv_ipi"
# define VIR_CPU_x86_KVM_HV_EVMCS     "__kvm_hv_evmcs"


# define VIR_CPU_X86_DATA_INIT { 0 }

typedef struct _virCPUx86Data virCPUx86Data;
struct _virCPUx86Data {
    size_t len;
    virCPUx86CPUID *data;
};

#endif /* LIBVIRT_CPU_X86_DATA_H */
