/*
 * virtpm.h: TPM support
 *
 * Copyright (C) 2013 IBM Corporation
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

char *virTPMCreateCancelPath(const char *devpath) ATTRIBUTE_MOCKABLE;

char *virTPMGetSwtpm(void);
char *virTPMGetSwtpmSetup(void);
char *virTPMGetSwtpmIoctl(void);

bool virTPMHasSwtpm(void);

typedef enum {
    VIR_TPM_SWTPM_FEATURE_CMDARG_PWD_FD,
    VIR_TPM_SWTPM_FEATURE_CMDARG_MIGRATION,
    VIR_TPM_SWTPM_FEATURE_NVRAM_BACKEND_DIR,
    VIR_TPM_SWTPM_FEATURE_NVRAM_BACKEND_FILE,
    VIR_TPM_SWTPM_FEATURE_CMDARG_PRINT_INFO,
    VIR_TPM_SWTPM_FEATURE_TPMSTATE_OPT_LOCK,

    VIR_TPM_SWTPM_FEATURE_LAST
} virTPMSwtpmFeature;

typedef enum {
    VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_PWDFILE_FD,
    VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_CREATE_CONFIG_FILES,
    VIR_TPM_SWTPM_SETUP_FEATURE_TPM12_NOT_NEED_ROOT,
    VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_RECONFIGURE_PCR_BANKS,
    VIR_TPM_SWTPM_SETUP_FEATURE_TPM_1_2,
    VIR_TPM_SWTPM_SETUP_FEATURE_TPM_2_0,
    VIR_TPM_SWTPM_SETUP_FEATURE_CMDARG_PROFILE,

    VIR_TPM_SWTPM_SETUP_FEATURE_LAST
} virTPMSwtpmSetupFeature;

VIR_ENUM_DECL(virTPMSwtpmFeature);
VIR_ENUM_DECL(virTPMSwtpmSetupFeature);

bool virTPMSwtpmCapsGet(virTPMSwtpmFeature cap);
bool virTPMSwtpmSetupCapsGet(virTPMSwtpmSetupFeature cap);
