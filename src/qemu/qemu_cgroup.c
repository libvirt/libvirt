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
#include "qemu_extdevice.h"
#include "qemu_hostdev.h"
#include "virlog.h"
#include "virerror.h"
#include "domain_audit.h"
#include "domain_cgroup.h"
#include "virfile.h"
#include "virdevmapper.h"
#include "virglibutil.h"

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
qemuCgroupAllowDevicePath(virDomainObj *vm,
                          const char *path,
                          int perms,
                          bool ignoreEacces)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret;

    VIR_DEBUG("Allow path %s, perms: %s",
              path, virCgroupGetDevicePermsString(perms));

    ret = virCgroupAllowDevicePath(priv->cgroup, path, perms, ignoreEacces);

    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             virCgroupGetDevicePermsString(perms), ret);
    return ret;
}


static int
qemuCgroupAllowDevicesPaths(virDomainObj *vm,
                            const char *const *deviceACL,
                            int perms,
                            bool ignoreEacces)
{
    size_t i;

    for (i = 0; deviceACL[i] != NULL; i++) {
        if (!virFileExists(deviceACL[i])) {
            VIR_DEBUG("Ignoring non-existent device %s", deviceACL[i]);
            continue;
        }

        if (qemuCgroupAllowDevicePath(vm, deviceACL[i], perms, ignoreEacces) < 0)
            return -1;
    }

    return 0;
}


static int
qemuCgroupDenyDevicePath(virDomainObj *vm,
                         const char *path,
                         int perms,
                         bool ignoreEacces)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    const char *const *deviceACL = (const char *const *)cfg->cgroupDeviceACL;
    int ret;

    if (!deviceACL)
        deviceACL = defaultDeviceACL;

    if (g_strv_contains(deviceACL, path)) {
        VIR_DEBUG("Skipping deny of path %s in CGroups because it's in cgroupDeviceACL",
                  path);
        return 0;
    }

    VIR_DEBUG("Deny path %s, perms: %s",
              path, virCgroupGetDevicePermsString(perms));

    ret = virCgroupDenyDevicePath(priv->cgroup, path, perms, ignoreEacces);

    virDomainAuditCgroupPath(vm, priv->cgroup, "deny", path,
                             virCgroupGetDevicePermsString(perms), ret);
    return ret;
}


static int
qemuCgroupDenyDevicesPaths(virDomainObj *vm,
                           const char *const *paths,
                           int perms,
                           bool ignoreEacces)
{
    size_t i;

    for (i = 0; paths[i] != NULL; i++) {
        if (!virFileExists(paths[i])) {
            VIR_DEBUG("Ignoring non-existent device %s", paths[i]);
            continue;
        }

        if (qemuCgroupDenyDevicePath(vm, paths[i], perms, ignoreEacces) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSetupImagePathCgroup(virDomainObj *vm,
                         const char *path,
                         bool readonly)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int perms = VIR_CGROUP_DEVICE_READ;
    g_autoptr(virGSListString) targetPaths = NULL;
    GSList *n;
    int rv;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (!readonly)
        perms |= VIR_CGROUP_DEVICE_WRITE;

    rv = qemuCgroupAllowDevicePath(vm, path, perms, true);
    if (rv < 0)
        return -1;

    if (rv > 0) {
        /* @path is neither character device nor block device. */
        return 0;
    }

    if (virDevMapperGetTargets(path, &targetPaths) < 0 &&
        errno != ENOSYS) {
        virReportSystemError(errno,
                             _("Unable to get devmapper targets for %1$s"),
                             path);
        return -1;
    }

    for (n = targetPaths; n; n = n->next) {
        if (qemuCgroupAllowDevicePath(vm, n->data, perms, false) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSetupImageCgroupInternal(virDomainObj *vm,
                             virStorageSource *src,
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
        if (!src->path ||
            !virStorageSourceIsLocalStorage(src) ||
            virStorageSourceIsFD(src)) {
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
qemuSetupImageCgroup(virDomainObj *vm,
                     virStorageSource *src)
{
    return qemuSetupImageCgroupInternal(vm, src, false);
}


int
qemuTeardownImageCgroup(virDomainObj *vm,
                        virStorageSource *src)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
        virStorageSource *diskSrc = vm->def->disks[i]->src;

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
            ret = qemuCgroupDenyDevicePath(vm, QEMU_DEV_VFIO, perms, true);

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
        ret = qemuCgroupDenyDevicePath(vm, QEMU_DEVICE_MAPPER_CONTROL_PATH,
                                       perms, true);

        if (ret < 0)
            return ret;
    }

    VIR_DEBUG("Deny path %s", path);

    ret = qemuCgroupDenyDevicePath(vm, path, perms, true);

    /* If you're looking for a counter part to
     * qemuSetupImagePathCgroup you're at the right place.
     * However, we can't just blindly deny all the device mapper
     * targets of src->path because they might still be used by
     * another disk in domain. Just like we are not removing
     * disks from namespace. */

    return ret;
}


int
qemuSetupImageChainCgroup(virDomainObj *vm,
                          virStorageSource *src)
{
    virStorageSource *next;
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
qemuTeardownImageChainCgroup(virDomainObj *vm,
                             virStorageSource *src)
{
    virStorageSource *next;

    for (next = src; virStorageSourceIsBacking(next); next = next->backingStore) {
        if (qemuTeardownImageCgroup(vm, next) < 0)
            return -1;
    }

    return 0;
}


static int
qemuSetupChrSourceCgroup(virDomainObj *vm,
                         virDomainChrSourceDef *source)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", source->data.file.path);

    return qemuCgroupAllowDevicePath(vm, source->data.file.path,
                                     VIR_CGROUP_DEVICE_RW, false);
}


static int
qemuTeardownChrSourceCgroup(virDomainObj *vm,
                            virDomainChrSourceDef *source)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", source->data.file.path);

    return qemuCgroupDenyDevicePath(vm, source->data.file.path,
                                    VIR_CGROUP_DEVICE_RW, false);
}


static int
qemuSetupChardevCgroupCB(virDomainDef *def G_GNUC_UNUSED,
                         virDomainChrDef *dev,
                         void *opaque)
{
    virDomainObj *vm = opaque;

    return qemuSetupChrSourceCgroup(vm, dev->source);
}


static int
qemuSetupTPMCgroup(virDomainObj *vm,
                   virDomainTPMDef *dev)
{
    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        return qemuSetupChrSourceCgroup(vm, dev->data.passthrough.source);
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return 0;
}


int
qemuSetupInputCgroup(virDomainObj *vm,
                     virDomainInputDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        return qemuCgroupAllowDevicePath(vm, dev->source.evdev,
                                         VIR_CGROUP_DEVICE_RW, false);
        break;
    }

    return ret;
}


int
qemuTeardownInputCgroup(virDomainObj *vm,
                        virDomainInputDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
        return qemuCgroupDenyDevicePath(vm, dev->source.evdev,
                                        VIR_CGROUP_DEVICE_RWM, false);
        break;
    }

    return 0;
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
qemuSetupHostdevCgroup(virDomainObj *vm,
                       virDomainHostdevDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *path = NULL;
    int perms;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (qemuDomainGetHostdevPath(dev, &path, &perms) < 0)
        return -1;

    if (path &&
        qemuCgroupAllowDevicePath(vm, path, perms, false) < 0) {
        return -1;
    }

    if (qemuHostdevNeedsVFIO(dev) &&
        qemuCgroupAllowDevicePath(vm, QEMU_DEV_VFIO,
                                  VIR_CGROUP_DEVICE_RW, false) < 0) {
        return -1;
    }

    return 0;
}


/**
 * qemuTeardownHostdevCgroup:
 * @vm: domain object
 * @dev: device to tear down
 *
 * For given host device @dev deny access to it in CGroups.
 * Note, @dev must not be in @vm's definition.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuTeardownHostdevCgroup(virDomainObj *vm,
                          virDomainHostdevDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *path = NULL;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    /* Skip tearing down Cgroup for hostdevs that represents absent
     * PCI devices, e.g. SR-IOV virtual functions that were removed from
     * the host while the domain was still running. */
    if (virHostdevIsPCIDevice(dev)) {
        const virDomainHostdevSubsysPCI *pcisrc = &dev->source.subsys.u.pci;

        if (!virPCIDeviceExists(&pcisrc->addr))
            return 0;
    }

    if (qemuDomainGetHostdevPath(dev, &path, NULL) < 0)
        return -1;

    if (path &&
        qemuCgroupDenyDevicePath(vm, path, VIR_CGROUP_DEVICE_RWM, false) < 0) {
        return -1;
    }

    if (qemuHostdevNeedsVFIO(dev) &&
        !qemuDomainNeedsVFIO(vm->def) &&
        qemuCgroupDenyDevicePath(vm, QEMU_DEV_VFIO,
                                 VIR_CGROUP_DEVICE_RWM, false) < 0) {
        return -1;
    }

    return 0;
}


int
qemuSetupMemoryDevicesCgroup(virDomainObj *vm,
                             virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    const char *const sgxPaths[] = { QEMU_DEV_SGX_VEPVC,
                                     QEMU_DEV_SGX_PROVISION, NULL };

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (qemuCgroupAllowDevicePath(vm, mem->source.nvdimm.path,
                                      VIR_CGROUP_DEVICE_RW, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (qemuCgroupAllowDevicePath(vm, mem->source.virtio_pmem.path,
                                      VIR_CGROUP_DEVICE_RW, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        if (qemuCgroupAllowDevicesPaths(vm, sgxPaths,
                                        VIR_CGROUP_DEVICE_RW, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


int
qemuTeardownMemoryDevicesCgroup(virDomainObj *vm,
                                virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    const char *const sgxPaths[] = { QEMU_DEV_SGX_VEPVC,
                                     QEMU_DEV_SGX_PROVISION, NULL };

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        if (qemuCgroupDenyDevicePath(vm, mem->source.nvdimm.path,
                                     VIR_CGROUP_DEVICE_RWM, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (qemuCgroupDenyDevicePath(vm, mem->source.virtio_pmem.path,
                                     VIR_CGROUP_DEVICE_RWM, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        if (qemuCgroupDenyDevicesPaths(vm, sgxPaths,
                                       VIR_CGROUP_DEVICE_RW, false) < 0)
            return -1;
        break;
    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


static int
qemuSetupGraphicsCgroup(virDomainObj *vm,
                        virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);

    if (!rendernode ||
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    return qemuCgroupAllowDevicePath(vm, rendernode, VIR_CGROUP_DEVICE_RW, false);
}


static int
qemuSetupVideoCgroup(virDomainObj *vm,
                     virDomainVideoDef *def)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainVideoAccelDef *accel = def->accel;
    int ret;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (accel && accel->rendernode) {
        ret = qemuCgroupAllowDevicePath(vm, accel->rendernode,
                                        VIR_CGROUP_DEVICE_RW, false);
        if (ret != 0)
            return ret;
    }
    if (def->blob == VIR_TRISTATE_SWITCH_ON) {
        ret = qemuCgroupAllowDevicePath(vm, QEMU_DEV_UDMABUF,
                                        VIR_CGROUP_DEVICE_RW, false);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static int
qemuSetupFirmwareCgroup(virDomainObj *vm)
{
    if (!vm->def->os.loader)
        return 0;

    if (vm->def->os.loader->path &&
        qemuSetupImagePathCgroup(vm, vm->def->os.loader->path,
                                 vm->def->os.loader->readonly == VIR_TRISTATE_BOOL_YES) < 0)
        return -1;

    if (vm->def->os.loader->nvram &&
        qemuSetupImageCgroup(vm, vm->def->os.loader->nvram) < 0)
        return -1;

    return 0;
}


int
qemuSetupRNGCgroup(virDomainObj *vm,
                   virDomainRNGDef *rng)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM &&
        qemuCgroupAllowDevicePath(vm, rng->source.file,
                                  VIR_CGROUP_DEVICE_RW, false) < 0) {
        return -1;
    }

    return 0;
}


int
qemuTeardownRNGCgroup(virDomainObj *vm,
                      virDomainRNGDef *rng)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM &&
        qemuCgroupDenyDevicePath(vm, rng->source.file,
                                 VIR_CGROUP_DEVICE_RW, false) < 0) {
        return -1;
    }

    return 0;
}


int
qemuSetupChardevCgroup(virDomainObj *vm,
                       virDomainChrDef *dev)
{
    return qemuSetupChrSourceCgroup(vm, dev->source);
}


int
qemuTeardownChardevCgroup(virDomainObj *vm,
                          virDomainChrDef *dev)
{
    return qemuTeardownChrSourceCgroup(vm, dev->source);
}


static int
qemuSetupSEVCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    return qemuCgroupAllowDevicePath(vm, "/dev/sev",
                                     VIR_CGROUP_DEVICE_RW, false);
}

static int
qemuSetupDevicesCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    const char *const *deviceACL = (const char *const *) cfg->cgroupDeviceACL;
    int rv = -1;
    size_t i;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    rv = virCgroupDenyAllDevices(priv->cgroup);
    virDomainAuditCgroup(vm, priv->cgroup, "deny", "all", rv == 0);
    if (rv < 0) {
        if (virLastErrorIsSystemErrno(EPERM)) {
            virResetLastError();
            VIR_WARN("Group devices ACL is not accessible, disabling filtering");
            return 0;
        }

        return -1;
    }

    if (!deviceACL)
        deviceACL = defaultDeviceACL;

    if (qemuCgroupAllowDevicesPaths(vm, deviceACL, VIR_CGROUP_DEVICE_RW, false) < 0)
        return -1;

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

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuSetupChardevCgroupCB,
                               vm) < 0)
        return -1;

    for (i = 0; i < vm->def->ntpms; i++) {
        if (qemuSetupTPMCgroup(vm, vm->def->tpms[i]) < 0)
            return -1;
    }

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

    if (vm->def->sec &&
        vm->def->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV &&
        qemuSetupSEVCgroup(vm) < 0)
        return -1;

    return 0;
}


static int
qemuSetupCgroupAppid(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int inode = -1;
    const char *path = "/sys/class/fc/fc_udev_device/appid_store";
    g_autofree char *appid = NULL;
    virDomainResourceDef *resource = vm->def->resource;

    if (!resource || !resource->appid)
        return 0;

    inode = virCgroupGetInode(priv->cgroup);
    if (inode < 0)
        return -1;

    appid = g_strdup_printf("%X:%s", inode, resource->appid);

    if (virFileWriteStr(path, appid, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to write '%1$s' to '%2$s'"), appid, path);
        return -1;
    }

    return 0;
}


int
qemuSetupCgroup(virDomainObj *vm,
                size_t nnicindexes,
                int *nicindexes)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    if (virDomainCgroupSetupCgroup("qemu",
                                   vm,
                                   nnicindexes,
                                   nicindexes,
                                   &priv->cgroup,
                                   cfg->cgroupControllers,
                                   cfg->maxThreadsPerProc,
                                   priv->driver->privileged,
                                   priv->machineName) < 0)

        return -1;

    if (!priv->cgroup)
        return 0;

    if (qemuSetupDevicesCgroup(vm) < 0)
        return -1;

    if (qemuSetupCgroupAppid(vm) < 0)
        return -1;

    return 0;
}

int
qemuSetupCgroupForExtDevices(virDomainObj *vm,
                             virQEMUDriver *driver)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCgroup) cgroup_temp = NULL;

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
        return -1;

    return qemuExtDevicesSetupCgroup(driver, vm, cgroup_temp);
}
