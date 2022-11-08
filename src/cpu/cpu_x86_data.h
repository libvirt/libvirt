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

#pragma once

typedef struct _virCPUx86CPUID virCPUx86CPUID;
struct _virCPUx86CPUID {
    uint32_t eax_in;
    uint32_t ecx_in;
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

typedef struct _virCPUx86MSR virCPUx86MSR;
struct _virCPUx86MSR {
    uint32_t index;
    uint32_t eax;
    uint32_t edx;
};

#define CPUX86_BASIC    0x0
#define CPUX86_KVM      0x40000000
#define CPUX86_EXTENDED 0x80000000

#define VIR_CPU_x86_KVM_PV_UNHALT   "kvm_pv_unhalt"

/*
 * The following HyperV feature names suffixes must exactly match corresponding
 * ones defined for virDomainHyperv in domain_conf.c.
 * E.g "hv-runtime" -> "runtime", "hv-spinlocks" -> "spinlocks" etc.
*/
#define VIR_CPU_x86_HV_RUNTIME   "hv-runtime"
#define VIR_CPU_x86_HV_SYNIC     "hv-synic"
#define VIR_CPU_x86_HV_STIMER    "hv-stimer"
#define VIR_CPU_x86_HV_RELAXED   "hv-relaxed"
#define VIR_CPU_x86_HV_SPINLOCKS "hv-spinlocks"
#define VIR_CPU_x86_HV_VAPIC     "hv-vapic"
#define VIR_CPU_x86_HV_VPINDEX   "hv-vpindex"
#define VIR_CPU_x86_HV_RESET     "hv-reset"
#define VIR_CPU_x86_HV_FREQUENCIES "hv-frequencies"
#define VIR_CPU_x86_HV_REENLIGHTENMENT "hv-reenlightenment"
#define VIR_CPU_x86_HV_TLBFLUSH  "hv-tlbflush"
#define VIR_CPU_x86_HV_IPI       "hv-ipi"
#define VIR_CPU_x86_HV_EVMCS     "hv-evmcs"
#define VIR_CPU_x86_HV_AVIC      "hv-avic"

/* Hyper-V Synthetic Timer option */
#define VIR_CPU_x86_HV_STIMER_DIRECT "hv-stimer-direct"

#define VIR_CPU_X86_DATA_INIT { 0 }

typedef enum {
    VIR_CPU_X86_DATA_NONE = 0,
    VIR_CPU_X86_DATA_CPUID,
    VIR_CPU_X86_DATA_MSR,
} virCPUx86DataType;

typedef struct _virCPUx86DataItem virCPUx86DataItem;
struct _virCPUx86DataItem {
    virCPUx86DataType type;
    union {
        virCPUx86CPUID cpuid;
        virCPUx86MSR msr;
    } data;
};

typedef struct _virCPUx86Data virCPUx86Data;
struct _virCPUx86Data {
    size_t len;
    virCPUx86DataItem *items;
};
