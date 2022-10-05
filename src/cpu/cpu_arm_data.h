/*
 * cpu_arm_data.h: 64-bit arm CPU specific data
 *
 * Copyright (C) 2020 Huawei Technologies Co., Ltd.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#define VIR_CPU_ARM_DATA_INIT { 0 }

typedef struct _virCPUarmData virCPUarmData;
struct _virCPUarmData {
    unsigned long long vendor_id;
    unsigned long long pvr;
    char **features;
};
