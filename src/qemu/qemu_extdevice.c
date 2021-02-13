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

#include "qemu_command.h"
#include "qemu_extdevice.h"
#include "qemu_vhost_user_gpu.h"
#include "qemu_dbus.h"
#include "qemu_domain.h"
#include "qemu_tpm.h"
#include "qemu_slirp.h"
#include "qemu_virtiofs.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virtpm.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_extdevice");

int
qemuExtDeviceLogCommand(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virCommand *cmd,
                        const char *info)
{
    g_autofree char *timestamp = virTimeStringNow();
    g_autofree char *cmds = virCommandToString(cmd, false);

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
qemuExtDevicesInitPaths(virQEMUDriver *driver,
                        virDomainDef *def)
{
    if (def->ntpms > 0)
        return qemuExtTPMInitPaths(driver, def);

    return 0;
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
qemuExtDevicesPrepareDomain(virQEMUDriver *driver,
                            virDomainObj *vm)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < vm->def->nvideos; i++) {
        virDomainVideoDef *video = vm->def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            if ((ret = qemuExtVhostUserGPUPrepareDomain(driver, video)) < 0)
                break;
        }
    }

    for (i = 0; i < vm->def->nfss; i++) {
        virDomainFSDef *fs = vm->def->fss[i];

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
            if (qemuVirtioFSPrepareDomain(driver, fs) < 0)
                return -1;
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
qemuExtDevicesPrepareHost(virQEMUDriver *driver,
                          virDomainObj *vm)
{
    virDomainDef *def = vm->def;
    size_t i;

    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return -1;

    if (def->ntpms > 0 &&
        qemuExtTPMPrepareHost(driver, def) < 0)
        return -1;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        qemuSlirp *slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp && qemuSlirpOpen(slirp, driver, def) < 0)
            return -1;
    }

    return 0;
}


void
qemuExtDevicesCleanupHost(virQEMUDriver *driver,
                          virDomainDef *def)
{
    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return;

    if (def->ntpms > 0)
        qemuExtTPMCleanupHost(def);
}


int
qemuExtDevicesStart(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virLogManager *logManager,
                    bool incomingMigration)
{
    virDomainDef *def = vm->def;
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDef *video = def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER) {
            if (qemuExtVhostUserGPUStart(driver, vm, video) < 0)
                return -1;
        }
    }

    if (def->ntpms > 0 && qemuExtTPMStart(driver, vm, incomingMigration) < 0)
        return -1;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        qemuSlirp *slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp &&
            qemuSlirpStart(slirp, vm, driver, net, incomingMigration) < 0)
            return -1;
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
            if (fs->sock)
                QEMU_DOMAIN_FS_PRIVATE(fs)->vhostuser_fs_sock = g_strdup(fs->sock);
            else if (qemuVirtioFSStart(logManager, driver, vm, fs) < 0)
                return -1;
        }
    }

    return 0;
}


void
qemuExtDevicesStop(virQEMUDriver *driver,
                   virDomainObj *vm)
{
    virDomainDef *def = vm->def;
    size_t i;

    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDef *video = def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER)
            qemuExtVhostUserGPUStop(driver, vm, video);
    }

    if (def->ntpms > 0)
        qemuExtTPMStop(driver, vm);

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        virDomainNetType actualType = virDomainNetGetActualType(net);
        qemuSlirp *slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp)
            qemuSlirpStop(slirp, vm, driver, net);
        if (actualType == VIR_DOMAIN_NET_TYPE_ETHERNET && net->downscript)
            virNetDevRunEthernetScript(net->ifname, net->downscript);
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (!fs->sock &&
            fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS)
            qemuVirtioFSStop(driver, vm, fs);
    }
}


bool
qemuExtDevicesHasDevice(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER)
            return true;
    }

    for (i = 0; i < def->ntpms; i++) {
        if (def->tpms[i]->type == VIR_DOMAIN_TPM_TYPE_EMULATOR)
            return true;
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS)
            return true;
    }

    return false;
}


int
qemuExtDevicesSetupCgroup(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virCgroup *cgroup)
{
    virDomainDef *def = vm->def;
    size_t i;

    if (qemuDBusSetupCgroup(driver, vm, cgroup) < 0)
        return -1;

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDef *video = def->videos[i];

        if (video->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER &&
            qemuExtVhostUserGPUSetupCgroup(driver, def, video, cgroup) < 0)
            return -1;
    }

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        qemuSlirp *slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp && qemuSlirpSetupCgroup(slirp, cgroup) < 0)
            return -1;
    }

    if (def->ntpms > 0 &&
        qemuExtTPMSetupCgroup(driver, def, cgroup) < 0)
        return -1;

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (!fs->sock &&
            fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS &&
            qemuVirtioFSSetupCgroup(vm, fs, cgroup) < 0)
            return -1;
    }

    return 0;
}
