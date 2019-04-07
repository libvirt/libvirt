/*
 * cpu_x86.h: CPU driver for CPUs with x86 compatible CPUID instruction
 *
 * Copyright (C) 2009 Red Hat, Inc.
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

#ifndef LIBVIRT_CPU_X86_H
# define LIBVIRT_CPU_X86_H

# include "cpu.h"
# include "cpu_x86_data.h"

extern struct cpuArchDriver cpuDriverX86;

int virCPUx86DataAddCPUID(virCPUDataPtr cpuData,
                          const virCPUx86CPUID *cpuid);

int virCPUx86DataSetSignature(virCPUDataPtr cpuData,
                              unsigned int family,
                              unsigned int model,
                              unsigned int stepping);

uint32_t virCPUx86DataGetSignature(virCPUDataPtr cpuData,
                                   unsigned int *family,
                                   unsigned int *model,
                                   unsigned int *stepping);

int virCPUx86DataSetVendor(virCPUDataPtr cpuData,
                           const char *vendor);

int virCPUx86DataAddFeature(virCPUDataPtr cpuData,
                            const char *name);

#endif /* LIBVIRT_CPU_X86_H */
