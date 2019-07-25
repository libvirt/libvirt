/*
 * qemu_extdevice.c: QEMU external devices support
 *
 * Copyright (C) 2014, 2018 IBM Corporation
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

#include <config.h>

#include "qemu_extdevice.h"
#include "qemu_domain.h"
#include "qemu_tpm.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virtpm.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_extdevice");

int
qemuExtDeviceLogCommand(qemuDomainLogContextPtr logCtxt,
                        virCommandPtr cmd,
                        const char *info)
{
    int ret = -1;
    char *timestamp = NULL;
    char *logline = NULL;
    int logFD;

    logFD = qemuDomainLogContextGetWriteFD(logCtxt);

    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf(&logline, "%s: Starting external device: %s\n",
                    timestamp, info) < 0)
        goto cleanup;

    if (safewrite(logFD, logline, strlen(logline)) < 0)
        goto cleanup;

    virCommandWriteArgLog(cmd, logFD);

    ret = 0;

 cleanup:
    VIR_FREE(timestamp);
    VIR_FREE(logline);

    return ret;
}


/*
 * qemuExtDevicesInitPaths:
 *
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Initialize paths of external devices so that it is known where state is
 * stored and we can remove directories and files in case of domain XML
 * changes.
 */
int
qemuExtDevicesInitPaths(virQEMUDriverPtr driver,
                        virDomainDefPtr def)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMInitPaths(driver, def);

    return ret;
}


/*
 * qemuExtDevicesPrepareHost:
 *
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Prepare host storage paths for external devices.
 */
int
qemuExtDevicesPrepareHost(virQEMUDriverPtr driver,
                          virDomainDefPtr def)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMPrepareHost(driver, def);

    return ret;
}


void
qemuExtDevicesCleanupHost(virQEMUDriverPtr driver,
                          virDomainDefPtr def)
{
    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return;

    if (def->tpm)
        qemuExtTPMCleanupHost(def);
}


int
qemuExtDevicesStart(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    qemuDomainLogContextPtr logCtxt)
{
    int ret = 0;

    if (qemuExtDevicesInitPaths(driver, vm->def) < 0)
        return -1;

    if (vm->def->tpm)
        ret = qemuExtTPMStart(driver, vm, logCtxt);

    return ret;
}


void
qemuExtDevicesStop(virQEMUDriverPtr driver,
                   virDomainObjPtr vm)
{
    if (qemuExtDevicesInitPaths(driver, vm->def) < 0)
        return;

    if (vm->def->tpm)
        qemuExtTPMStop(driver, vm);
}


bool
qemuExtDevicesHasDevice(virDomainDefPtr def)
{
    if (def->tpm && def->tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR)
        return true;

    return false;
}


int
qemuExtDevicesSetupCgroup(virQEMUDriverPtr driver,
                          virDomainDefPtr def,
                          virCgroupPtr cgroup)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMSetupCgroup(driver, def, cgroup);

    return ret;
}
