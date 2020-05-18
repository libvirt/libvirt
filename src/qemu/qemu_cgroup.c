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
 */

#include <config.h>

#include "qemu_cgroup.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_extdevice.h"
#include "qemu_hostdev.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "domain_audit.h"
#include "domain_cgroup.h"
#include "virscsi.h"
#include "virstring.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virnuma.h"
#include "virdevmapper.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_cgroup");

const char *const defaultDeviceACL[] = {
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm",
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
    VIR_AUTOSTRINGLIST targetPaths = NULL;
    size_t i;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (!readonly)
        perms |= VIR_CGROUP_DEVICE_WRITE;

    VIR_DEBUG("Allow path %s, perms: %s",
              path, virCgroupGetDevicePermsString(perms));

    rv = virCgroupAllowDevicePath(priv->cgroup, path, perms, true);

    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             virCgroupGetDevicePermsString(perms),
                             rv);
    if (rv < 0)
        return -1;

    if (rv > 0) {
        /* @path is neither character device nor block device. */
        return 0;
    }

    if (virDevMapperGetTargets(path, &targetPaths) < 0 &&
        errno != ENOSYS && errno != EBADF) {
        virReportSystemError(errno,
                             _("Unable to get devmapper targets for %s"),
                             path);
        return -1;
    }

    for (i = 0; targetPaths && targetPaths[i]; i++) {
        rv = virCgroupAllowDevicePath(priv->cgroup, targetPaths[i], perms, false);

        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", targetPaths[i],
                                 virCgroupGetDevicePermsString(perms),
                                 rv);
        if (rv < 0)
            return -1;
    }

    return 0;
}


static int
qemuSetupImageCgroupInternal(virDomainObjPtr vm,
                             virStorageSourcePtr src,
                             bool forceReadonly)
{
    g_autofree char *path = NULL;
    bool readonly = src->readonly || forceReadonly;

    if (src->type == VIR_STORAGE_TYPE_NVME) {
        /* Even though disk is R/O we can't make it so in
         * CGroups. QEMU will try to do some ioctl()-s over the
         * device and such operations are considered R/W by the
         * kernel */
        readonly = false;

        if (!(path = virPCIDeviceAddressGetIOMMUGroupDev(&src->nvme->pciAddr)))
            return -1;

        if (qemuSetupImagePathCgroup(vm, QEMU_DEV_VFIO, false) < 0)
            return -1;
    } else {
        if (!src->path || !virStorageSourceIsLocalStorage(src)) {
            VIR_DEBUG("Not updating cgroups for disk path '%s', type: %s",
                      NULLSTR(src->path), virStorageTypeToString(src->type));
            return 0;
        }

        path = g_strdup(src->path);
    }

    if (virStoragePRDefIsManaged(src->pr) &&
        virFileExists(QEMU_DEVICE_MAPPER_CONTROL_PATH) &&
        qemuSetupImagePathCgroup(vm, QEMU_DEVICE_MAPPER_CONTROL_PATH, false) < 0)
        return -1;

    return qemuSetupImagePathCgroup(vm, path, readonly);
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
    g_autofree char *path = NULL;
    int perms = VIR_CGROUP_DEVICE_RWM;
    bool hasPR = false;
    bool hasNVMe = false;
    size_t i;
    int ret;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    for (i = 0; i < vm->def->ndisks; i++) {
        virStorageSourcePtr diskSrc = vm->def->disks[i]->src;

        if (src == diskSrc)
            continue;

        if (virStoragePRDefIsManaged(diskSrc->pr))
            hasPR = true;

        if (virStorageSourceChainHasNVMe(diskSrc))
            hasNVMe = true;
    }

    if (src->type == VIR_STORAGE_TYPE_NVME) {
        if (!(path = virPCIDeviceAddressGetIOMMUGroupDev(&src->nvme->pciAddr)))
            return -1;

        if (!hasNVMe &&
            !qemuDomainNeedsVFIO(vm->def)) {
            ret = virCgroupDenyDevicePath(priv->cgroup, QEMU_DEV_VFIO, perms, true);
            virDomainAuditCgroupPath(vm, priv->cgroup, "deny",
                                     QEMU_DEV_VFIO,
                                     virCgroupGetDevicePermsString(perms), ret);
            if (ret < 0)
                return -1;
        }
    } else {
        if (!src->path || !virStorageSourceIsLocalStorage(src)) {
            VIR_DEBUG("Not updating cgroups for disk path '%s', type: %s",
                      NULLSTR(src->path), virStorageTypeToString(src->type));
            return 0;
        }

        path = g_strdup(src->path);
    }

    if (!hasPR &&
        virFileExists(QEMU_DEVICE_MAPPER_CONTROL_PATH)) {
        VIR_DEBUG("Disabling device mapper control");
        ret = virCgroupDenyDevicePath(priv->cgroup,
                                      QEMU_DEVICE_MAPPER_CONTROL_PATH,
                                      perms, true);
        virDomainAuditCgroupPath(vm, priv->cgroup, "deny",
                                 QEMU_DEVICE_MAPPER_CONTROL_PATH,
                                 virCgroupGetDevicePermsString(perms), ret);
        if (ret < 0)
            return ret;
    }

    VIR_DEBUG("Deny path %s", path);

    ret = virCgroupDenyDevicePath(priv->cgroup, path, perms, true);

    virDomainAuditCgroupPath(vm, priv->cgroup, "deny", path,
                             virCgroupGetDevicePermsString(perms), ret);

    /* If you're looking for a counter part to
     * qemuSetupImagePathCgroup you're at the right place.
     * However, we can't just blindly deny all the device mapper
     * targets of src->path because they might still be used by
     * another disk in domain. Just like we are not removing
     * disks from namespace. */

    return ret;
}


int
qemuSetupImageChainCgroup(virDomainObjPtr vm,
                          virStorageSourcePtr src)
{
    virStorageSourcePtr next;
    bool forceReadonly = false;

    for (next = src; virStorageSourceIsBacking(next); next = next->backingStore) {
        if (qemuSetupImageCgroupInternal(vm, next, forceReadonly) < 0)
            return -1;

        /* setup only the top level image for read-write */
        forceReadonly = true;
    }

    return 0;
}


int
qemuTeardownImageChainCgroup(virDomainObjPtr vm,
                             virStorageSourcePtr src)
{
    virStorageSourcePtr next;

    for (next = src; virStorageSourceIsBacking(next); next = next->backingStore) {
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
                             source->data.file.path, "rw", ret);

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
                             source->data.file.path, "rw", ret);

    return ret;
}


static int
qemuSetupChardevCgroupCB(virDomainDefPtr def G_GNUC_UNUSED,
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
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


int
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
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", dev->source.evdev, "rw", ret);
        break;
    }

    return ret;
}


int
qemuTeardownInputCgroup(virDomainObjPtr vm,
                        virDomainInputDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        VIR_DEBUG("Process path '%s' for input device", dev->source.evdev);
        ret = virCgroupDenyDevicePath(priv->cgroup, dev->source.evdev,
                                      VIR_CGROUP_DEVICE_RWM, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "deny", dev->source.evdev, "rwm", ret);
        break;
    }

    return ret;
}


/**
 * qemuSetupHostdevCgroup:
 * vm: domain object
 * @dev: device to allow
 *
 * For given host device @dev allow access to in Cgroups.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuSetupHostdevCgroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *path = NULL;
    int perms;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (qemuDomainGetHostdevPath(dev, &path, &perms) < 0)
        return -1;

    if (path) {
        VIR_DEBUG("Cgroup allow %s perms=%d", path, perms);
        rv = virCgroupAllowDevicePath(priv->cgroup, path, perms, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                                 virCgroupGetDevicePermsString(perms),
                                 rv);
        if (rv < 0)
            return -1;
    }

    if (qemuHostdevNeedsVFIO(dev)) {
        VIR_DEBUG("Cgroup allow %s perms=%d", QEMU_DEV_VFIO, VIR_CGROUP_DEVICE_RW);
        rv = virCgroupAllowDevicePath(priv->cgroup, QEMU_DEV_VFIO,
                                      VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                                 QEMU_DEV_VFIO, "rw", rv);
        if (rv < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuTeardownHostdevCgroup:
 * @vm: doamin object
 * @dev: device to tear down
 *
 * For given host device @dev deny access to it in CGroups.
 * Note, @dev must not be in @vm's definition.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuTeardownHostdevCgroup(virDomainObjPtr vm,
                          virDomainHostdevDefPtr dev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *path = NULL;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (qemuDomainGetHostdevPath(dev, &path, NULL) < 0)
        return -1;

    if (path) {
        VIR_DEBUG("Cgroup deny %s", path);
        rv = virCgroupDenyDevicePath(priv->cgroup, path,
                                     VIR_CGROUP_DEVICE_RWM, false);
        virDomainAuditCgroupPath(vm, priv->cgroup,
                                 "deny", path, "rwm", rv);
        if (rv < 0)
            return -1;
    }

    if (qemuHostdevNeedsVFIO(dev) &&
        !qemuDomainNeedsVFIO(vm->def)) {
        VIR_DEBUG("Cgroup deny " QEMU_DEV_VFIO);
        rv = virCgroupDenyDevicePath(priv->cgroup, QEMU_DEV_VFIO,
                                     VIR_CGROUP_DEVICE_RWM, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "deny",
                                 QEMU_DEV_VFIO, "rwm", rv);
        if (rv < 0)
            return -1;
    }

    return 0;
}


int
qemuSetupMemoryDevicesCgroup(virDomainObjPtr vm,
                             virDomainMemoryDefPtr mem)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rv;

    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    VIR_DEBUG("Setting devices Cgroup for NVDIMM device: %s", mem->nvdimmPath);
    rv = virCgroupAllowDevicePath(priv->cgroup, mem->nvdimmPath,
                                  VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                             mem->nvdimmPath, "rw", rv);

    return rv;
}


int
qemuTeardownMemoryDevicesCgroup(virDomainObjPtr vm,
                                virDomainMemoryDefPtr mem)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rv;

    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    rv = virCgroupDenyDevicePath(priv->cgroup, mem->nvdimmPath,
                                 VIR_CGROUP_DEVICE_RWM, false);
    virDomainAuditCgroupPath(vm, priv->cgroup,
                             "deny", mem->nvdimmPath, "rwm", rv);
    return rv;
}


static int
qemuSetupGraphicsCgroup(virDomainObjPtr vm,
                        virDomainGraphicsDefPtr gfx)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);
    int ret;

    if (!rendernode ||
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    ret = virCgroupAllowDevicePath(priv->cgroup, rendernode,
                                   VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", rendernode,
                             "rw", ret);
    return ret;
}


static int
qemuSetupVideoCgroup(virDomainObjPtr vm,
                     virDomainVideoDefPtr def)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainVideoAccelDefPtr accel = def->accel;
    int ret;

    if (!accel)
        return 0;

    if (!accel->rendernode ||
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    ret = virCgroupAllowDevicePath(priv->cgroup, accel->rendernode,
                                   VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", accel->rendernode,
                             "rw", ret);
    return ret;
}


static int
qemuSetupBlkioCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

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

    return virDomainCgroupSetupBlkio(priv->cgroup, vm->def->blkio);
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

    return virDomainCgroupSetupMemtune(priv->cgroup, vm->def->mem);
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
                                 "rw", rv);
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
                                 "rw", rv);
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
qemuSetupSEVCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    ret = virCgroupAllowDevicePath(priv->cgroup, "/dev/sev",
                                   VIR_CGROUP_DEVICE_RW, false);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", "/dev/sev",
                             "rw", ret);
    return ret;
}

static int
qemuSetupDevicesCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    const char *const *deviceACL = NULL;
    int rv = -1;
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

        return -1;
    }

    if (qemuSetupFirmwareCgroup(vm) < 0)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuSetupImageChainCgroup(vm, vm->def->disks[i]->src) < 0)
            return -1;
    }

    rv = virCgroupAllowDevice(priv->cgroup, 'c', DEVICE_PTY_MAJOR, -1,
                              VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_PTY_MAJOR,
                              "pty", "rw", rv == 0);
    if (rv < 0)
        return -1;

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
            return -1;
    }

    for (i = 0; deviceACL[i] != NULL; i++) {
        if (!virFileExists(deviceACL[i])) {
            VIR_DEBUG("Ignoring non-existent device %s", deviceACL[i]);
            continue;
        }

        rv = virCgroupAllowDevicePath(priv->cgroup, deviceACL[i],
                                      VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", deviceACL[i], "rw", rv);
        if (rv < 0 &&
            !virLastErrorIsSystemErrno(ENOENT))
            return -1;
    }

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuSetupChardevCgroupCB,
                               vm) < 0)
        return -1;

    if (vm->def->tpm && qemuSetupTPMCgroup(vm) < 0)
        return -1;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        /* This may allow /dev/vfio/vfio multiple times, but that
         * is not a problem. Kernel will have only one record. */
        if (qemuSetupHostdevCgroup(vm, vm->def->hostdevs[i]) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->nmems; i++) {
        if (qemuSetupMemoryDevicesCgroup(vm, vm->def->mems[i]) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->ngraphics; i++) {
        if (qemuSetupGraphicsCgroup(vm, vm->def->graphics[i]) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->nvideos; i++) {
        if (qemuSetupVideoCgroup(vm, vm->def->videos[i]) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->ninputs; i++) {
        if (qemuSetupInputCgroup(vm, vm->def->inputs[i]) < 0)
            return -1;
    }

    for (i = 0; i < vm->def->nrngs; i++) {
        if (qemuSetupRNGCgroup(vm, vm->def->rngs[i]) < 0)
            return -1;
    }

    if (vm->def->sev && qemuSetupSEVCgroup(vm) < 0)
        return -1;

    return 0;
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
qemuSetupCpuCgroup(virDomainObjPtr vm)
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
        if (virCgroupSetupCpuShares(priv->cgroup, vm->def->cputune.shares,
                                    &val) < 0)
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

        virObjectEventStateQueue(priv->driver->domainEventState, event);
    }

    return 0;
}


static int
qemuInitCgroup(virDomainObjPtr vm,
               size_t nnicindexes,
               int *nicindexes)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    if (!priv->driver->privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    virCgroupFree(&priv->cgroup);

    if (!vm->def->resource) {
        virDomainResourceDefPtr res;

        if (VIR_ALLOC(res) < 0)
            return -1;

        res->partition = g_strdup("/machine");

        vm->def->resource = res;
    }

    if (vm->def->resource->partition[0] != '/') {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Resource partition '%s' must start with '/'"),
                       vm->def->resource->partition);
        return -1;
    }

    if (virCgroupNewMachine(priv->machineName,
                            "qemu",
                            vm->def->uuid,
                            NULL,
                            vm->pid,
                            false,
                            nnicindexes, nicindexes,
                            vm->def->resource->partition,
                            cfg->cgroupControllers,
                            cfg->maxThreadsPerProc,
                            &priv->cgroup) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;

        return -1;
    }

    return 0;
}

static void
qemuRestoreCgroupState(virDomainObjPtr vm)
{
    g_autofree char *mem_mask = NULL;
    g_autofree char *nodeset = NULL;
    int empty = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i = 0;
    g_autoptr(virBitmap) all_nodes = NULL;
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
    virCgroupFree(&cgroup_temp);
    return;

 error:
    virResetLastError();
    VIR_DEBUG("Couldn't restore cgroups to meaningful state");
    goto cleanup;
}

int
qemuConnectCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    if (!priv->driver->privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    virCgroupFree(&priv->cgroup);

    if (virCgroupNewDetectMachine(vm->def->name,
                                  "qemu",
                                  vm->pid,
                                  cfg->cgroupControllers,
                                  priv->machineName,
                                  &priv->cgroup) < 0)
        return -1;

    qemuRestoreCgroupState(vm);
    return 0;
}

int
qemuSetupCgroup(virDomainObjPtr vm,
                size_t nnicindexes,
                int *nicindexes)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!vm->pid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup cgroups until process is started"));
        return -1;
    }

    if (qemuInitCgroup(vm, nnicindexes, nicindexes) < 0)
        return -1;

    if (!priv->cgroup)
        return 0;

    if (qemuSetupDevicesCgroup(vm) < 0)
        return -1;

    if (qemuSetupBlkioCgroup(vm) < 0)
        return -1;

    if (qemuSetupMemoryCgroup(vm) < 0)
        return -1;

    if (qemuSetupCpuCgroup(vm) < 0)
        return -1;

    if (qemuSetupCpusetCgroup(vm) < 0)
        return -1;

    return 0;
}

int
qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                      unsigned long long period,
                      long long quota)
{
    return virCgroupSetupCpuPeriodQuota(cgroup, period, quota);
}


int
qemuSetupCgroupCpusetCpus(virCgroupPtr cgroup,
                          virBitmapPtr cpumask)
{
    return virCgroupSetupCpusetCpus(cgroup, cpumask);
}


int
qemuSetupCgroupForExtDevices(virDomainObjPtr vm,
                             virQEMUDriverPtr driver)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup_temp = NULL;
    int ret = -1;

    if (!qemuExtDevicesHasDevice(vm->def) ||
        priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &cgroup_temp) < 0)
        goto cleanup;

    ret = qemuExtDevicesSetupCgroup(driver, vm, cgroup_temp);

 cleanup:
    virCgroupFree(&cgroup_temp);

    return ret;
}


int
qemuSetupGlobalCpuCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long period = vm->def->cputune.global_period;
    long long quota = vm->def->cputune.global_quota;
    g_autofree char *mem_mask = NULL;
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
        return -1;

    if (period || quota) {
        if (qemuSetupCgroupVcpuBW(priv->cgroup, period, quota) < 0)
            return -1;
    }

    return 0;
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
    g_autofree char *all_nodes_str = NULL;
    g_autoptr(virBitmap) all_nodes = NULL;
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

    *retData = g_steal_pointer(&data);
    ret = 0;

 cleanup:
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

    virErrorPreserveLast(&err);
    virCgroupSetCpusetMems(data->emulatorCgroup, data->emulatorMemMask);
    virErrorRestore(&err);

    qemuCgroupEmulatorAllNodesDataFree(data);
}
