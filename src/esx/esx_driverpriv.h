/*
 * esx_driverpriv.h: private declarations for ESX driver
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef LIBVIRT_ESX_DRIVERPRIV_H_ALLOW
# error "esx_driverpriv.h may only be included by esx_driver.c or test suites"
#endif /* LIBVIRT_ESX_DRIVERPRIV_H_ALLOW */

#pragma once

#include "esx_vi.h"

typedef struct _esxVMX_Data esxVMX_Data;

struct _esxVMX_Data {
    esxVI_Context *ctx;
    char *datastorePathWithoutFileName;
};


int
esxParseVMXFileName(const char *fileName,
                    void *opaque,
                    char **out,
                    bool allow_missing);
