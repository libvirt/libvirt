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
#include "qemu_dbus.h"
#include "qemu_domain.h"
#include "qemu_tpm.h"
#include "qemu_passt.h"
#include "qemu_slirp.h"
#include "qemu_virtiofs.h"

#include "virlog.h"
#include "virtime.h"

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
                                      _("%1$s: Starting external device: %2$s\n%3$s\n"),
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
int
qemuExtDevicesInitPaths(virQEMUDriver *driver,
                        virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ntpms; i++) {
        virDomainTPMDef *tpm = def->tpms[i];

        if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR &&
            qemuExtTPMInitPaths(driver, def, tpm) < 0)
            return -1;
    }

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

    if (qemuExtDevicesInitPaths(driver, vm->def) < 0)
        return -1;

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

    for (i = 0; i < def->ntpms; i++) {
        virDomainTPMDef *tpm = def->tpms[i];

        if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR &&
            qemuExtTPMPrepareHost(driver, def, tpm) < 0)
            return -1;
    }

    return 0;
}


void
qemuExtDevicesCleanupHost(virQEMUDriver *driver,
                          virDomainDef *def,
                          virDomainUndefineFlagsValues flags,
                          bool outgoingMigration)
{
    size_t i;

    if (qemuExtDevicesInitPaths(driver, def) < 0)
        return;

    for (i = 0; i < def->ntpms; i++) {
        virDomainTPMDef *tpm = def->tpms[i];

        if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR)
            qemuExtTPMCleanupHost(tpm, flags, outgoingMigration);
    }
}


int
qemuExtDevicesStart(virQEMUDriver *driver,
                    virDomainObj *vm,
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

    for (i = 0; i < def->ntpms; i++) {
        virDomainTPMDef *tpm = def->tpms[i];

        if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR &&
            qemuExtTPMStart(driver, vm, tpm, incomingMigration) < 0)
            return -1;
    }

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];

        if (net->type != VIR_DOMAIN_NET_TYPE_USER)
            continue;

        if (net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {
            if (qemuPasstStart(vm, net) < 0)
                return -1;
        } else {
            if (qemuSlirpStart(vm, net, incomingMigration) < 0)
                return -1;
        }
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS && !fs->sock) {
            if (qemuVirtioFSStart(driver, vm, fs) < 0)
                return -1;
        }
    }

    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDef *graphics = def->graphics[i];

        if (graphics->type != VIR_DOMAIN_GRAPHICS_TYPE_DBUS)
            continue;

        if (graphics->data.dbus.p2p || graphics->data.dbus.fromConfig)
            continue;

        if (qemuDBusStart(driver, vm) < 0)
            return -1;
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        if (qemuNbdkitStartStorageSource(driver, vm, disk->src) < 0)
            return -1;
    }

    if (def->os.loader && def->os.loader->nvram) {
        if (qemuNbdkitStartStorageSource(driver, vm, def->os.loader->nvram) < 0)
            return -1;
    }

    return 0;
}


void
qemuExtDevicesStop(virQEMUDriver *driver,
                   virDomainObj *vm,
                   bool outgoingMigration)
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

    for (i = 0; i < def->ntpms; i++) {
        if (def->tpms[i]->type == VIR_DOMAIN_TPM_TYPE_EMULATOR)
            qemuExtTPMStop(driver, vm, outgoingMigration);
    }

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        virDomainNetType actualType = virDomainNetGetActualType(net);
        qemuSlirp *slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

        if (slirp)
            qemuSlirpStop(slirp, vm, driver, net);

        if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
            net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {
            qemuPasstStop(vm, net);
        }

        if (actualType == VIR_DOMAIN_NET_TYPE_ETHERNET && net->downscript)
            virNetDevRunEthernetScript(net->ifname, net->downscript);
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (!fs->sock &&
            fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS)
            qemuVirtioFSStop(driver, vm, fs);
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        qemuNbdkitStopStorageSource(disk->src, vm);
    }

    if (def->os.loader && def->os.loader->nvram)
        qemuNbdkitStopStorageSource(def->os.loader->nvram, vm);
}


bool
qemuExtDevicesHasDevice(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->backend == VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER)
            return true;
    }

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];

        if (QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp)
            return true;

        if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
            net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST)
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

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        virStorageSource *backing;

        for (backing = disk->src; backing; backing = backing->backingStore) {
            qemuDomainStorageSourcePrivate* priv =
                QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(backing);
            if (priv && priv->nbdkitProcess)
                return true;
        }
    }


    return false;
}


/* recursively setup nbdkit cgroups for backing chain of src */
static int
qemuExtDevicesSetupCgroupNbdkit(virStorageSource *src,
                                virCgroup *cgroup)
{
    virStorageSource *backing;

    for (backing = src; backing; backing = backing->backingStore) {
        qemuDomainStorageSourcePrivate *priv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);

        if (priv && priv->nbdkitProcess &&
            qemuNbdkitProcessSetupCgroup(priv->nbdkitProcess, cgroup) < 0)
            return -1;
    }

    return 0;
}


int
qemuExtDevicesSetupCgroup(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virCgroup *cgroup)
{
    virDomainDef *def = vm->def;
    size_t i;

    /* Don't forget to adjust qemuExtDevicesHasDevice() accordingly.
     * Otherwise, this function might not be called at all. */

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

        if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
            net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST &&
            qemuPasstSetupCgroup(vm, net, cgroup) < 0) {
            return -1;
        }
    }

    for (i = 0; i < def->ntpms; i++) {
        if (def->tpms[i]->type == VIR_DOMAIN_TPM_TYPE_EMULATOR &&
            qemuExtTPMSetupCgroup(driver, def, cgroup) < 0)
            return -1;
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        if (qemuExtDevicesSetupCgroupNbdkit(disk->src, cgroup) < 0)
            return -1;
    }

    if (def->os.loader && def->os.loader->nvram) {
        if (qemuExtDevicesSetupCgroupNbdkit(def->os.loader->nvram, cgroup) < 0)
            return -1;
    }

    for (i = 0; i < def->nfss; i++) {
        virDomainFSDef *fs = def->fss[i];

        if (!fs->sock &&
            fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS &&
            qemuVirtioFSSetupCgroup(vm, fs, cgroup) < 0)
            return -1;
    }

    return 0;
}
