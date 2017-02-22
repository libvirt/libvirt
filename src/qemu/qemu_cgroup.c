/*
 * qemu_cgroup.c: QEMU cgroup management
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_cgroup.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "vircgroup.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "domain_audit.h"
#include "virscsi.h"
#include "virstring.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virnuma.h"
#include "virsystemd.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_cgroup");

const char *const defaultDeviceACL[] = {
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet",
    NULL,
};
#define DEVICE_PTY_MAJOR 136
#define DEVICE_SND_MAJOR 116


static int
qemuSetupImagePathCgroup(virDomainObjPtr vm,
                         const char *path,
                         bool readonly)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int perms = VIR_CGROUP_DEVICE_READ;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (!readonly)
        perms |= VIR_CGROUP_DEVICE_WRITE;

    VIR_DEBUG("Allow path %s, perms: %s",
              path, virCgroupGetDevicePermsString(perms));

    ret = virCgroupAllowDevicePath(priv->cgroup, path, perms, true);

    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             virCgroupGetDevicePermsString(perms),
                             ret == 0);

    return ret;
}


static int
qemuSetupImageCgroupInternal(virDomainObjPtr vm,
                             virStorageSourcePtr src,
                             bool forceReadonly)
{
    if (!src->path || !virStorageSourceIsLocalStorage(src)) {
        VIR_DEBUG("Not updating cgroups for disk path '%s', type: %s",
                  NULLSTR(src->path), virStorageTypeToString(src->type));
        return 0;
    }

    return qemuSetupImagePathCgroup(vm, src->path, src->readonly || forceReadonly);
}


int
qemuSetupImageCgroup(virDomainObjPtr vm,
                     virStorageSourcePtr src)
{
    return qemuSetupImageCgroupInternal(vm, src, false);
}


int
qemuTeardownImageCgroup(virDomainObjPtr vm,
                        virStorageSourcePtr src)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int perms = VIR_CGROUP_DEVICE_READ |
                VIR_CGROUP_DEVICE_WRITE |
                VIR_CGROUP_DEVICE_MKNOD;
    int ret;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (!src->path || !virStorageSourceIsLocalStorage(src)) {
        VIR_DEBUG("Not updating cgroups for disk path '%s', type: %s",
                  NULLSTR(src->path), virStorageTypeToString(src->type));
        return 0;
    }

    VIR_DEBUG("Deny path %s", src->path);

    ret = virCgroupDenyDevicePath(priv->cgroup, src->path, perms, true);

    virDomainAuditCgroupPath(vm, priv->cgroup, "deny", src->path,
                             virCgroupGetDevicePermsString(perms), ret == 0);

    return ret;
}


int
qemuSetupDiskCgroup(virDomainObjPtr vm,
                    virDomainDiskDefPtr disk)
{
    virStorageSourcePtr next;
    bool forceReadonly = false;

    for (next = disk->src; next; next = next->backingStore) {
        if (qemuSetupImageCgroupInternal(vm, next, forceReadonly) < 0)
            return -1;

        /* setup only the top level image for read-write */
        forceReadonly = true;
    }

    return 0;
}


int
qemuTeardownDiskCgroup(virDomainObjPtr vm,
                       virDomainDiskDefPtr disk)
{
    virStorageSourcePtr next;

    for (next = disk->src; next; next = next->backingStore) {
        if (qemuTeardownImageCgroup(vm, next) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSetupChrSourceCgroup(virDomainObjPtr vm,
                         virDomainChrSourceDefPtr source)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", source->data.file.path);

    ret = virCgroupAllowDevicePath(priv->cgroup, source->data.file.path,
                                   VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                             source->data.file.path, "rw", ret == 0);

    return ret;
}


static int
qemuTeardownChrSourceCgroup(virDomainObjPtr vm,
                            virDomainChrSourceDefPtr source)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", source->data.file.path);

    ret = virCgroupDenyDevicePath(priv->cgroup, source->data.file.path,
                                  VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "deny",
                             source->data.file.path, "rw", ret == 0);

    return ret;
}


static int
qemuSetupChardevCgroupCB(virDomainDefPtr def ATTRIBUTE_UNUSED,
                         virDomainChrDefPtr dev,
                         void *opaque)
{
    virDomainObjPtr vm = opaque;

    return qemuSetupChrSourceCgroup(vm, dev->source);
}


static int
qemuSetupTPMCgroup(virDomainObjPtr vm)
{
    int ret = 0;
    virDomainTPMDefPtr dev = vm->def->tpm;

    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = qemuSetupChrSourceCgroup(vm, &dev->data.passthrough.source);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
qemuSetupInputCgroup(virDomainObjPtr vm,
                     virDomainInputDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        VIR_DEBUG("Process path '%s' for input device", dev->source.evdev);
        ret = virCgroupAllowDevicePath(priv->cgroup, dev->source.evdev,
                                       VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", dev->source.evdev, "rw", ret == 0);
        break;
    }

    return ret;
}


int
qemuSetupHostdevCgroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char **path = NULL;
    int *perms = NULL;
    size_t i, npaths = 0;
    int rv, ret = -1;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (qemuDomainGetHostdevPath(NULL, dev, false, &npaths, &path, &perms) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        VIR_DEBUG("Cgroup allow %s perms=%d", path[i], perms[i]);
        rv = virCgroupAllowDevicePath(priv->cgroup, path[i], perms[i], false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path[i],
                                 virCgroupGetDevicePermsString(perms[i]),
                                 ret == 0);
        if (rv < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < npaths; i++)
        VIR_FREE(path[i]);
    VIR_FREE(path);
    VIR_FREE(perms);
    return ret;
}

int
qemuTeardownHostdevCgroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char **path = NULL;
    size_t i, npaths = 0;
    int rv, ret = -1;

    /* currently this only does something for PCI devices using vfio
     * for device assignment, but it is called for *all* hostdev
     * devices.
     */

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (dev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        dev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
        dev->source.subsys.u.pci.backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO &&
        qemuDomainGetHostdevPath(vm->def, dev, true,
                                 &npaths, &path, NULL) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        VIR_DEBUG("Cgroup deny %s", path[i]);
        rv = virCgroupDenyDevicePath(priv->cgroup, path[i],
                                     VIR_CGROUP_DEVICE_RWM, false);
        virDomainAuditCgroupPath(vm, priv->cgroup,
                                 "deny", path[i], "rwm", rv == 0);
        if (rv < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < npaths; i++)
        VIR_FREE(path[i]);
    VIR_FREE(path);
    return ret;
}


static int
qemuSetupGraphicsCgroup(virDomainObjPtr vm,
                        virDomainGraphicsDefPtr gfx)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *rendernode = gfx->data.spice.rendernode;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (gfx->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE ||
        gfx->data.spice.gl != VIR_TRISTATE_BOOL_YES ||
        !rendernode)
        return 0;

    ret = virCgroupAllowDevicePath(priv->cgroup, rendernode,
                                   VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", rendernode,
                             "rw", ret == 0);
    return ret;
}


static int
qemuSetupBlkioCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_BLKIO)) {
        if (vm->def->blkio.weight || vm->def->blkio.ndevices) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available on this host"));
            return -1;
        } else {
            return 0;
        }
    }

    if (vm->def->blkio.weight != 0 &&
        virCgroupSetBlkioWeight(priv->cgroup, vm->def->blkio.weight) < 0)
        return -1;

    if (vm->def->blkio.ndevices) {
        for (i = 0; i < vm->def->blkio.ndevices; i++) {
            virBlkioDevicePtr dev = &vm->def->blkio.devices[i];
            if (dev->weight &&
                (virCgroupSetBlkioDeviceWeight(priv->cgroup, dev->path,
                                               dev->weight) < 0 ||
                 virCgroupGetBlkioDeviceWeight(priv->cgroup, dev->path,
                                               &dev->weight) < 0))
                return -1;

            if (dev->riops &&
                (virCgroupSetBlkioDeviceReadIops(priv->cgroup, dev->path,
                                                 dev->riops) < 0 ||
                 virCgroupGetBlkioDeviceReadIops(priv->cgroup, dev->path,
                                                 &dev->riops) < 0))
                return -1;

            if (dev->wiops &&
                (virCgroupSetBlkioDeviceWriteIops(priv->cgroup, dev->path,
                                                  dev->wiops) < 0 ||
                 virCgroupGetBlkioDeviceWriteIops(priv->cgroup, dev->path,
                                                  &dev->wiops) < 0))
                return -1;

            if (dev->rbps &&
                (virCgroupSetBlkioDeviceReadBps(priv->cgroup, dev->path,
                                                dev->rbps) < 0 ||
                 virCgroupGetBlkioDeviceReadBps(priv->cgroup, dev->path,
                                                &dev->rbps) < 0))
                return -1;

            if (dev->wbps &&
                (virCgroupSetBlkioDeviceWriteBps(priv->cgroup, dev->path,
                                                 dev->wbps) < 0 ||
                 virCgroupGetBlkioDeviceWriteBps(priv->cgroup, dev->path,
                                                 &dev->wbps) < 0))
                return -1;
        }
    }

    return 0;
}


static int
qemuSetupMemoryCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
        if (virMemoryLimitIsSet(vm->def->mem.hard_limit) ||
            virMemoryLimitIsSet(vm->def->mem.soft_limit) ||
            virMemoryLimitIsSet(vm->def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory cgroup is not available on this host"));
            return -1;
        } else {
            return 0;
        }
    }

    if (virMemoryLimitIsSet(vm->def->mem.hard_limit))
        if (virCgroupSetMemoryHardLimit(priv->cgroup, vm->def->mem.hard_limit) < 0)
            return -1;

    if (virMemoryLimitIsSet(vm->def->mem.soft_limit))
        if (virCgroupSetMemorySoftLimit(priv->cgroup, vm->def->mem.soft_limit) < 0)
            return -1;

    if (virMemoryLimitIsSet(vm->def->mem.swap_hard_limit))
        if (virCgroupSetMemSwapHardLimit(priv->cgroup, vm->def->mem.swap_hard_limit) < 0)
            return -1;

    return 0;
}


static int
qemuSetupFirmwareCgroup(virDomainObjPtr vm)
{
    if (!vm->def->os.loader)
        return 0;

    if (vm->def->os.loader->path &&
        qemuSetupImagePathCgroup(vm, vm->def->os.loader->path,
                                 vm->def->os.loader->readonly == VIR_TRISTATE_BOOL_YES) < 0)
        return -1;

    if (vm->def->os.loader->nvram &&
        qemuSetupImagePathCgroup(vm, vm->def->os.loader->nvram, false) < 0)
        return -1;

    return 0;
}


int
qemuSetupRNGCgroup(virDomainObjPtr vm,
                   virDomainRNGDefPtr rng)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM) {
        VIR_DEBUG("Setting Cgroup ACL for RNG device");
        rv = virCgroupAllowDevicePath(priv->cgroup,
                                      rng->source.file,
                                      VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                                 rng->source.file,
                                 "rw", rv == 0);
        if (rv < 0 &&
            !virLastErrorIsSystemErrno(ENOENT))
            return -1;
    }

    return 0;
}


int
qemuTeardownRNGCgroup(virDomainObjPtr vm,
                      virDomainRNGDefPtr rng)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM) {
        VIR_DEBUG("Tearing down Cgroup ACL for RNG device");
        rv = virCgroupDenyDevicePath(priv->cgroup,
                                     rng->source.file,
                                     VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "deny",
                                 rng->source.file,
                                 "rw", rv == 0);
        if (rv < 0 &&
            !virLastErrorIsSystemErrno(ENOENT))
            return -1;
    }

    return 0;
}


int
qemuSetupChardevCgroup(virDomainObjPtr vm,
                       virDomainChrDefPtr dev)
{
    return qemuSetupChrSourceCgroup(vm, dev->source);
}


int
qemuTeardownChardevCgroup(virDomainObjPtr vm,
                          virDomainChrDefPtr dev)
{
    return qemuTeardownChrSourceCgroup(vm, dev->source);
}


static int
qemuSetupDevicesCgroup(virQEMUDriverPtr driver,
                       virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    const char *const *deviceACL = NULL;
    int rv = -1;
    int ret = -1;
    size_t i;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    rv = virCgroupDenyAllDevices(priv->cgroup);
    virDomainAuditCgroup(vm, priv->cgroup, "deny", "all", rv == 0);
    if (rv < 0) {
        if (virLastErrorIsSystemErrno(EPERM)) {
            virResetLastError();
            VIR_WARN("Group devices ACL is not accessible, disabling whitelisting");
            return 0;
        }

        goto cleanup;
    }

    if (qemuSetupFirmwareCgroup(vm) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuSetupDiskCgroup(vm, vm->def->disks[i]) < 0)
            goto cleanup;
    }

    rv = virCgroupAllowDevice(priv->cgroup, 'c', DEVICE_PTY_MAJOR, -1,
                              VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_PTY_MAJOR,
                              "pty", "rw", rv == 0);
    if (rv < 0)
        goto cleanup;

    cfg = virQEMUDriverGetConfig(driver);
    deviceACL = cfg->cgroupDeviceACL ?
                (const char *const *)cfg->cgroupDeviceACL :
                defaultDeviceACL;

    if (vm->def->nsounds &&
        ((!vm->def->ngraphics && cfg->nogfxAllowHostAudio) ||
         (vm->def->graphics &&
          ((vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
           cfg->vncAllowHostAudio) ||
           (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL))))) {
        rv = virCgroupAllowDevice(priv->cgroup, 'c', DEVICE_SND_MAJOR, -1,
                                  VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_SND_MAJOR,
                                  "sound", "rw", rv == 0);
        if (rv < 0)
            goto cleanup;
    }

    for (i = 0; deviceACL[i] != NULL; i++) {
        if (!virFileExists(deviceACL[i])) {
            VIR_DEBUG("Ignoring non-existent device %s", deviceACL[i]);
            continue;
        }

        rv = virCgroupAllowDevicePath(priv->cgroup, deviceACL[i],
                                      VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", deviceACL[i], "rw", rv == 0);
        if (rv < 0 &&
            !virLastErrorIsSystemErrno(ENOENT))
            goto cleanup;
    }

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuSetupChardevCgroupCB,
                               vm) < 0)
        goto cleanup;

    if (vm->def->tpm && qemuSetupTPMCgroup(vm) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (qemuSetupHostdevCgroup(vm, vm->def->hostdevs[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->ngraphics; i++) {
        if (qemuSetupGraphicsCgroup(vm, vm->def->graphics[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->ninputs; i++) {
        if (qemuSetupInputCgroup(vm, vm->def->inputs[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->nrngs; i++) {
        if (qemuSetupRNGCgroup(vm, vm->def->rngs[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}


int
qemuSetupCpusetMems(virDomainObjPtr vm)
{
    virCgroupPtr cgroup_temp = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainNumatuneMemMode mode;
    char *mem_mask = NULL;
    int ret = -1;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mode) < 0 ||
        mode != VIR_DOMAIN_NUMATUNE_MEM_STRICT)
        return 0;

    if (virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                            priv->autoNodeset,
                                            &mem_mask, -1) < 0)
        goto cleanup;

    if (mem_mask)
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, mem_mask) < 0)
            goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(mem_mask);
    virCgroupFree(&cgroup_temp);
    return ret;
}


static int
qemuSetupCpusetCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virCgroupSetCpusetMemoryMigrate(priv->cgroup, true) < 0)
        return -1;

    return 0;
}


static int
qemuSetupCpuCgroup(virQEMUDriverPtr driver,
                   virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virObjectEventPtr event = NULL;
    virTypedParameterPtr eventParams = NULL;
    int eventNparams = 0;
    int eventMaxparams = 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
       if (vm->def->cputune.sharesSpecified) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("CPU tuning is not available on this host"));
           return -1;
       } else {
           return 0;
       }
    }

    if (vm->def->cputune.sharesSpecified) {
        unsigned long long val;
        if (virCgroupSetCpuShares(priv->cgroup, vm->def->cputune.shares) < 0)
            return -1;

        if (virCgroupGetCpuShares(priv->cgroup, &val) < 0)
            return -1;
        if (vm->def->cputune.shares != val) {
            vm->def->cputune.shares = val;
            if (virTypedParamsAddULLong(&eventParams, &eventNparams,
                                        &eventMaxparams,
                                        VIR_DOMAIN_TUNABLE_CPU_CPU_SHARES,
                                        val) < 0)
                return -1;

            event = virDomainEventTunableNewFromObj(vm, eventParams, eventNparams);
        }

        qemuDomainEventQueue(driver, event);
    }

    return 0;
}


static int
qemuInitCgroup(virQEMUDriverPtr driver,
               virDomainObjPtr vm,
               size_t nnicindexes,
               int *nicindexes)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!virQEMUDriverIsPrivileged(driver))
        goto done;

    if (!virCgroupAvailable())
        goto done;

    virCgroupFree(&priv->cgroup);

    if (!vm->def->resource) {
        virDomainResourceDefPtr res;

        if (VIR_ALLOC(res) < 0)
            goto cleanup;

        if (VIR_STRDUP(res->partition, "/machine") < 0) {
            VIR_FREE(res);
            goto cleanup;
        }

        vm->def->resource = res;
    }

    if (vm->def->resource->partition[0] != '/') {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Resource partition '%s' must start with '/'"),
                       vm->def->resource->partition);
        goto cleanup;
    }

    /*
     * We need to do this because of systemd-machined, because
     * CreateMachine requires the name to be a valid hostname.
     */
    priv->machineName = virSystemdMakeMachineName("qemu",
                                                  vm->def->id,
                                                  vm->def->name,
                                                  virQEMUDriverIsPrivileged(driver));
    if (!priv->machineName)
        goto cleanup;

    if (virCgroupNewMachine(priv->machineName,
                            "qemu",
                            vm->def->uuid,
                            NULL,
                            vm->pid,
                            false,
                            nnicindexes, nicindexes,
                            vm->def->resource->partition,
                            cfg->cgroupControllers,
                            &priv->cgroup) < 0) {
        if (virCgroupNewIgnoreError())
            goto done;

        goto cleanup;
    }

 done:
    ret = 0;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static void
qemuRestoreCgroupState(virDomainObjPtr vm)
{
    char *mem_mask = NULL;
    char *nodeset = NULL;
    int empty = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i = 0;
    virBitmapPtr all_nodes;
    virCgroupPtr cgroup_temp = NULL;

    if (!virNumaIsAvailable() ||
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return;

    if (!(all_nodes = virNumaGetHostMemoryNodeset()))
        goto error;

    if (!(mem_mask = virBitmapFormat(all_nodes)))
        goto error;

    if ((empty = virCgroupHasEmptyTasks(priv->cgroup,
                                        VIR_CGROUP_CONTROLLER_CPUSET)) <= 0)
        goto error;

    if (virCgroupSetCpusetMems(priv->cgroup, mem_mask) < 0)
        goto error;

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
            virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
            goto cleanup;

        VIR_FREE(nodeset);
        virCgroupFree(&cgroup_temp);
    }

    for (i = 0; i < vm->def->niothreadids; i++) {
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                               vm->def->iothreadids[i]->iothread_id,
                               false, &cgroup_temp) < 0 ||
            virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
            virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
            virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
            goto cleanup;

        VIR_FREE(nodeset);
        virCgroupFree(&cgroup_temp);
    }

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_temp) < 0 ||
        virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0 ||
        virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0 ||
        virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(mem_mask);
    VIR_FREE(nodeset);
    virBitmapFree(all_nodes);
    virCgroupFree(&cgroup_temp);
    return;

 error:
    virResetLastError();
    VIR_DEBUG("Couldn't restore cgroups to meaningful state");
    goto cleanup;
}

int
qemuConnectCgroup(virQEMUDriverPtr driver,
                  virDomainObjPtr vm)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!virQEMUDriverIsPrivileged(driver))
        goto done;

    if (!virCgroupAvailable())
        goto done;

    virCgroupFree(&priv->cgroup);

    if (virCgroupNewDetectMachine(vm->def->name,
                                  "qemu",
                                  vm->def->id,
                                  virQEMUDriverIsPrivileged(driver),
                                  vm->pid,
                                  cfg->cgroupControllers,
                                  &priv->cgroup) < 0)
        goto cleanup;

    priv->machineName = virSystemdGetMachineNameByPID(vm->pid);
    if (!priv->machineName)
        virResetLastError();

    qemuRestoreCgroupState(vm);

 done:
    ret = 0;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}

int
qemuSetupCgroup(virQEMUDriverPtr driver,
                virDomainObjPtr vm,
                size_t nnicindexes,
                int *nicindexes)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!vm->pid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup cgroups until process is started"));
        return -1;
    }

    if (qemuInitCgroup(driver, vm, nnicindexes, nicindexes) < 0)
        return -1;

    if (!priv->cgroup)
        return 0;

    if (qemuSetupDevicesCgroup(driver, vm) < 0)
        goto cleanup;

    if (qemuSetupBlkioCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupMemoryCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupCpuCgroup(driver, vm) < 0)
        goto cleanup;

    if (qemuSetupCpusetCgroup(vm) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}

int
qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                      unsigned long long period,
                      long long quota)
{
    unsigned long long old_period;

    if (period == 0 && quota == 0)
        return 0;

    if (period) {
        /* get old period, and we can rollback if set quota failed */
        if (virCgroupGetCpuCfsPeriod(cgroup, &old_period) < 0)
            return -1;

        if (virCgroupSetCpuCfsPeriod(cgroup, period) < 0)
            return -1;
    }

    if (quota &&
        virCgroupSetCpuCfsQuota(cgroup, quota) < 0)
        goto error;

    return 0;

 error:
    if (period) {
        virErrorPtr saved = virSaveLastError();
        ignore_value(virCgroupSetCpuCfsPeriod(cgroup, old_period));
        if (saved) {
            virSetError(saved);
            virFreeError(saved);
        }
    }

    return -1;
}


int
qemuSetupCgroupCpusetCpus(virCgroupPtr cgroup,
                          virBitmapPtr cpumask)
{
    int ret = -1;
    char *new_cpus = NULL;

    if (!(new_cpus = virBitmapFormat(cpumask)))
        goto cleanup;

    if (virCgroupSetCpusetCpus(cgroup, new_cpus) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(new_cpus);
    return ret;
}


int
qemuSetupGlobalCpuCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long period = vm->def->cputune.global_period;
    long long quota = vm->def->cputune.global_quota;
    char *mem_mask = NULL;
    virDomainNumatuneMemMode mem_mode;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;


    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                            priv->autoNodeset,
                                            &mem_mask, -1) < 0)
        goto cleanup;

    if (period || quota) {
        if (qemuSetupCgroupVcpuBW(priv->cgroup, period, quota) < 0)
            goto cleanup;
    }

    VIR_FREE(mem_mask);

    return 0;

 cleanup:
    VIR_FREE(mem_mask);

    return -1;
}


int
qemuRemoveCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    if (virCgroupTerminateMachine(priv->machineName) < 0) {
        if (!virCgroupNewIgnoreError())
            VIR_DEBUG("Failed to terminate cgroup for %s", vm->def->name);
    }

    VIR_FREE(priv->machineName);

    return virCgroupRemove(priv->cgroup);
}


static void
qemuCgroupEmulatorAllNodesDataFree(qemuCgroupEmulatorAllNodesDataPtr data)
{
    if (!data)
        return;

    virCgroupFree(&data->emulatorCgroup);
    VIR_FREE(data->emulatorMemMask);
    VIR_FREE(data);
}


/**
 * qemuCgroupEmulatorAllNodesAllow:
 * @cgroup: domain cgroup pointer
 * @retData: filled with structure used to roll back the operation
 *
 * Allows all NUMA nodes for the qemu emulator thread temporarily. This is
 * necessary when hotplugging cpus since it requires memory allocated in the
 * DMA region. Afterwards the operation can be reverted by
 * qemuCgroupEmulatorAllNodesRestore.
 *
 * Returns 0 on success -1 on error
 */
int
qemuCgroupEmulatorAllNodesAllow(virCgroupPtr cgroup,
                                qemuCgroupEmulatorAllNodesDataPtr *retData)
{
    qemuCgroupEmulatorAllNodesDataPtr data = NULL;
    char *all_nodes_str = NULL;
    virBitmapPtr all_nodes = NULL;
    int ret = -1;

    if (!virNumaIsAvailable() ||
        !virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (!(all_nodes = virNumaGetHostMemoryNodeset()))
        goto cleanup;

    if (!(all_nodes_str = virBitmapFormat(all_nodes)))
        goto cleanup;

    if (VIR_ALLOC(data) < 0)
        goto cleanup;

    if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &data->emulatorCgroup) < 0)
        goto cleanup;

    if (virCgroupGetCpusetMems(data->emulatorCgroup, &data->emulatorMemMask) < 0 ||
        virCgroupSetCpusetMems(data->emulatorCgroup, all_nodes_str) < 0)
        goto cleanup;

    VIR_STEAL_PTR(*retData, data);
    ret = 0;

 cleanup:
    VIR_FREE(all_nodes_str);
    virBitmapFree(all_nodes);
    qemuCgroupEmulatorAllNodesDataFree(data);

    return ret;
}


/**
 * qemuCgroupEmulatorAllNodesRestore:
 * @data: data structure created by qemuCgroupEmulatorAllNodesAllow
 *
 * Rolls back the setting done by qemuCgroupEmulatorAllNodesAllow and frees the
 * associated data.
 */
void
qemuCgroupEmulatorAllNodesRestore(qemuCgroupEmulatorAllNodesDataPtr data)
{
    virErrorPtr err;

    if (!data)
        return;

    err = virSaveLastError();
    virCgroupSetCpusetMems(data->emulatorCgroup, data->emulatorMemMask);
    virSetError(err);
    virFreeError(err);

    qemuCgroupEmulatorAllNodesDataFree(data);
}
