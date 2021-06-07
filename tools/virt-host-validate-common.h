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

typedef enum {
    VIR_HOST_VALIDATE_FAIL,
    VIR_HOST_VALIDATE_WARN,
    VIR_HOST_VALIDATE_NOTE,

    VIR_HOST_VALIDATE_LAST,
} virHostValidateLevel;

typedef enum {
    VIR_HOST_VALIDATE_CPU_FLAG_VMX = 0,
    VIR_HOST_VALIDATE_CPU_FLAG_SVM,
    VIR_HOST_VALIDATE_CPU_FLAG_SIE,
    VIR_HOST_VALIDATE_CPU_FLAG_FACILITY_158,
    VIR_HOST_VALIDATE_CPU_FLAG_SEV,

    VIR_HOST_VALIDATE_CPU_FLAG_LAST,
} virHostValidateCPUFlag;

VIR_ENUM_DECL(virHostValidateCPUFlag);

/**
 * VIR_HOST_VALIDATE_FAILURE
 * @level: the virHostValidateLevel to be checked
 *
 * This macro is to be used in to return a failures based on the
 * virHostValidateLevel use in the function.
 *
 * If the virHostValidateLevel is VIR_HOST_VALIDATE_FAIL, -1 is returned.
 * 0 is returned otherwise (as the virHosValidateLevel is then either a
 * Warn or a Note).
 */

#define VIR_HOST_VALIDATE_FAILURE(level) (level == VIR_HOST_VALIDATE_FAIL) ? -1 : 0

void virHostMsgSetQuiet(bool quietFlag);

void virHostMsgCheck(const char *prefix,
                     const char *format,
                     ...) G_GNUC_PRINTF(2, 3);

void virHostMsgPass(void);
void virHostMsgFail(virHostValidateLevel level,
                    const char *format,
                    ...) G_GNUC_PRINTF(2, 3);

int virHostValidateDeviceExists(const char *hvname,
                                const char *dev_name,
                                virHostValidateLevel level,
                                const char *hint);

int virHostValidateDeviceAccessible(const char *hvname,
                                    const char *dev_name,
                                    virHostValidateLevel level,
                                    const char *hint);

virBitmap *virHostValidateGetCPUFlags(void);

int virHostValidateLinuxKernel(const char *hvname,
                               int version,
                               virHostValidateLevel level,
                               const char *hint);

int virHostValidateNamespace(const char *hvname,
                             const char *ns_name,
                             virHostValidateLevel level,
                             const char *hint);

int virHostValidateCGroupControllers(const char *hvname,
                                     int controllers,
                                     virHostValidateLevel level);

int virHostValidateIOMMU(const char *hvname,
                         virHostValidateLevel level);

int virHostValidateSecureGuests(const char *hvname,
                                virHostValidateLevel level);

bool virHostKernelModuleIsLoaded(const char *module);
