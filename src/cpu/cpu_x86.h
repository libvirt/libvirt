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

#pragma once

#include "cpu.h"
#include "cpu_x86_data.h"

extern struct cpuArchDriver cpuDriverX86;

int virCPUx86DataAdd(virCPUData *cpuData,
                     const virCPUx86DataItem *cpuid);

int virCPUx86DataSetSignature(virCPUData *cpuData,
                              unsigned int family,
                              unsigned int model,
                              unsigned int stepping);

uint32_t virCPUx86DataGetSignature(virCPUData *cpuData,
                                   unsigned int *family,
                                   unsigned int *model,
                                   unsigned int *stepping);

int virCPUx86DataSetVendor(virCPUData *cpuData,
                           const char *vendor);

bool virCPUx86FeatureFilterSelectMSR(const char *name,
                                     virCPUFeaturePolicy policy,
                                     void *opaque);

bool virCPUx86FeatureFilterDropMSR(const char *name,
                                   virCPUFeaturePolicy policy,
                                   void *opaque);
