/*
 * virt-validate-common.h: Sanity check helper APIs
 *
 * Copyright (C) 2012-2024 Red Hat, Inc.
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

typedef enum {
    VIR_VALIDATE_FAIL,
    VIR_VALIDATE_WARN,
    VIR_VALIDATE_NOTE,

    VIR_VALIDATE_LAST,
} virValidateLevel;

/**
 * VIR_VALIDATE_FAILURE
 * @level: the virValidateLevel to be checked
 *
 * This macro is to be used in to return a failures based on the
 * virValidateLevel use in the function.
 *
 * If the virValidateLevel is VIR_VALIDATE_FAIL, -1 is returned.
 * 0 is returned otherwise (as the virValidateLevel is then either a
 * Warn or a Note).
 */

#define VIR_VALIDATE_FAILURE(level) (level == VIR_VALIDATE_FAIL) ? -1 : 0

void virValidateSetQuiet(bool quietFlag);

void virValidateCheck(const char *prefix,
                      const char *format,
                      ...) G_GNUC_PRINTF(2, 3);

void virValidatePass(void);
void virValidateFail(virValidateLevel level,
                     const char *format,
                     ...) G_GNUC_PRINTF(2, 3);
