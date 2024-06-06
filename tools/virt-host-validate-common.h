/*
 * virt-host-validate-common.h: Sanity check helper APIs
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 */

#pragma once

#include "internal.h"
#include "virbitmap.h"
#include "virenum.h"
#include "virt-validate-common.h"

typedef enum {
    VIR_HOST_VALIDATE_CPU_FLAG_VMX = 0,
    VIR_HOST_VALIDATE_CPU_FLAG_SVM,
    VIR_HOST_VALIDATE_CPU_FLAG_SIE,
    VIR_HOST_VALIDATE_CPU_FLAG_FACILITY_158,
    VIR_HOST_VALIDATE_CPU_FLAG_SEV,

    VIR_HOST_VALIDATE_CPU_FLAG_LAST,
} virHostValidateCPUFlag;

VIR_ENUM_DECL(virHostValidateCPUFlag);

int virHostValidateDeviceExists(const char *hvname,
                                const char *dev_name,
                                virValidateLevel level,
                                const char *hint);

int virHostValidateDeviceAccessible(const char *hvname,
                                    const char *dev_name,
                                    virValidateLevel level,
                                    const char *hint);

virBitmap *virHostValidateGetCPUFlags(void);

int virHostValidateLinuxKernel(const char *hvname,
                               int version,
                               virValidateLevel level,
                               const char *hint);

int virHostValidateNamespace(const char *hvname,
                             const char *ns_name,
                             virValidateLevel level,
                             const char *hint);

int virHostValidateCGroupControllers(const char *hvname,
                                     int controllers,
                                     virValidateLevel level);

int virHostValidateIOMMU(const char *hvname,
                         virValidateLevel level);

int virHostValidateSecureGuests(const char *hvname,
                                virValidateLevel level);

bool virHostKernelModuleIsLoaded(const char *module);
