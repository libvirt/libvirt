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
#include "qemu_vhost_user_gpu.h"
#include "qemu_domain.h"
#include "qemu_tpm.h"
#include "qemu_slirp.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virtpm.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_extdevice");

int
qemuExtDeviceLogCommand(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        virCommandPtr cmd,
                        const char *info)
{
    VIR_AUTOFREE(char *) timestamp = virTimeStringNow();
    VIR_AUTOFREE(char *) cmds = virCommandToString(cmd, false);

    if (!timestamp || !cmds)
        return -1;

    return qemuDomainLogAppendMessage(driver, vm,
                                      _("%s: Starting external device: %s\n%s\n"),
                                      timestamp, info, cmds);
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
static int
qemuExtDevicesInitPaths(virQEMUDriverPtr driver,
                        virDomainDefPtr def)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMInitPaths(driver, def);

    return ret;
}


/*
 * qemuExtDevicesPrepareDomain:
 *
 * @driver: QEMU driver
 * @vm: domain
 *
 * Code that modifies live XML of a domain which is about to start.
 */
int
qemuExtDevicesPrepareDomain(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < vm->def->nvideos; i++) {
        virDomainVideoDefPtr video = vm->def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            if ((ret = qemuExtVhostUserGPUPrepareDomain(driver, video)) < 0)
                break;
        }
    }

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
                          virDomainObjPtr vm)
{
    virDomainDefPtr def = vm->def;
    size_t i;

    if (def->tpm &&
        qemuExtTPMPrepareHost(driver, def) < 0)
        return -1;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        qemuSlirpPtr slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp && qemuSlirpOpen(slirp, driver, def) < 0)
            return -1;
    }

    return 0;
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
                    bool incomingMigration)
{
    virDomainDefPtr def = vm->def;
    int ret = 0;
    size_t i;

    if (qemuExtDevicesInitPaths(driver, vm->def) < 0)
        return -1;

    for (i = 0; i < vm->def->nvideos; i++) {
        virDomainVideoDefPtr video = vm->def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            ret = qemuExtVhostUserGPUStart(driver, vm, video);
            if (ret < 0)
                return ret;
        }
    }

    if (vm->def->tpm)
        ret = qemuExtTPMStart(driver, vm, incomingMigration);

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        qemuSlirpPtr slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp &&
            qemuSlirpStart(slirp, vm, driver, net, false, incomingMigration) < 0)
            return -1;
    }

    return ret;
}


void
qemuExtDevicesStop(virQEMUDriverPtr driver,
                   virDomainObjPtr vm)
{
    virDomainDefPtr def = vm->def;
    size_t i;

    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDefPtr video = def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER)
            qemuExtVhostUserGPUStop(driver, vm, video);
    }

    if (def->tpm)
        qemuExtTPMStop(driver, vm);

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        qemuSlirpPtr slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp)
            qemuSlirpStop(slirp, vm, driver, net, false);
    }
}


bool
qemuExtDevicesHasDevice(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER)
            return true;
    }

    if (def->tpm && def->tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR)
        return true;

    return false;
}


int
qemuExtDevicesSetupCgroup(virQEMUDriverPtr driver,
                          virDomainDefPtr def,
                          virCgroupPtr cgroup)
{
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDefPtr video = def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER &&
            qemuExtVhostUserGPUSetupCgroup(driver, def, video, cgroup) < 0)
            return -1;
    }

    if (def->tpm &&
        qemuExtTPMSetupCgroup(driver, def, cgroup) < 0)
        return -1;

    return 0;
}
