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
        errno != ENOSYS) {
        virReportSystemError(errno,
                             _("Unable to get devmapper targets for %s"),
                             path);
        return -1;
    }

    for (n = targetPaths; n; n = n->next) {
        rv = virCgroupAllowDevicePath(priv->cgroup, n->data, perms, false);

        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", n->data,
                                 virCgroupGetDevicePermsString(perms),
                                 rv);
        if (rv < 0)
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
qemuTeardownChrSourceCgroup(virDomainObj *vm,
                            virDomainChrSourceDef *source)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
        VIR_DEBUG("Process path '%s' for input device", dev->source.evdev);
        ret = virCgroupAllowDevicePath(priv->cgroup, dev->source.evdev,
                                       VIR_CGROUP_DEVICE_RW, false);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", dev->source.evdev, "rw", ret);
        break;
    }

    return ret;
}


int
qemuTeardownInputCgroup(virDomainObj *vm,
                        virDomainInputDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = 0;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_INPUT_TYPE_EVDEV:
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
qemuSetupHostdevCgroup(virDomainObj *vm,
                       virDomainHostdevDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
    int rv;

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
qemuSetupMemoryDevicesCgroup(virDomainObj *vm,
                             virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rv;

    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        mem->model != VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM)
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
qemuTeardownMemoryDevicesCgroup(virDomainObj *vm,
                                virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rv;

    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM &&
        mem->model != VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM)
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
qemuSetupGraphicsCgroup(virDomainObj *vm,
                        virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuSetupVideoCgroup(virDomainObj *vm,
                     virDomainVideoDef *def)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainVideoAccelDef *accel = def->accel;
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
qemuSetupBlkioCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_BLKIO)) {
        if (vm->def->blkio.weight || vm->def->blkio.ndevices) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available on this host"));
            return -1;
        }
        return 0;
    }

    return virDomainCgroupSetupBlkio(priv->cgroup, vm->def->blkio);
}


static int
qemuSetupMemoryCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
        if (virMemoryLimitIsSet(vm->def->mem.hard_limit) ||
            virMemoryLimitIsSet(vm->def->mem.soft_limit) ||
            virMemoryLimitIsSet(vm->def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory cgroup is not available on this host"));
            return -1;
        }
        return 0;
    }

    return virDomainCgroupSetupMemtune(priv->cgroup, vm->def->mem);
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
        qemuSetupImagePathCgroup(vm, vm->def->os.loader->nvram, false) < 0)
        return -1;

    return 0;
}


int
qemuSetupRNGCgroup(virDomainObj *vm,
                   virDomainRNGDef *rng)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuTeardownRNGCgroup(virDomainObj *vm,
                      virDomainRNGDef *rng)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuSetupDevicesCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
            VIR_WARN("Group devices ACL is not accessible, disabling filtering");
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
qemuSetupCpusetCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virCgroupSetCpusetMemoryMigrate(priv->cgroup, true) < 0)
        return -1;

    return 0;
}


static int
qemuSetupCpuCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
       if (vm->def->cputune.sharesSpecified) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("CPU tuning is not available on this host"));
           return -1;
       }
       return 0;
    }

    if (vm->def->cputune.sharesSpecified) {
        if (virCgroupSetCpuShares(priv->cgroup, vm->def->cputune.shares) < 0)
            return -1;
    }

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
                             _("Unable to write '%s' to '%s'"), appid, path);
        return -1;
    }

    return 0;
}


static int
qemuInitCgroup(virDomainObj *vm,
               size_t nnicindexes,
               int *nicindexes)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    if (!priv->driver->privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    virCgroupFree(priv->cgroup);
    priv->cgroup = NULL;

    if (!vm->def->resource)
        vm->def->resource = g_new0(virDomainResourceDef, 1);

    if (!vm->def->resource->partition)
        vm->def->resource->partition = g_strdup("/machine");

    if (!g_path_is_absolute(vm->def->resource->partition)) {
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

static int
qemuRestoreCgroupThread(virCgroup *cgroup,
                        virCgroupThreadName thread,
                        int id)
{
    g_autoptr(virCgroup) cgroup_temp = NULL;
    g_autofree char *nodeset = NULL;

    if (virCgroupNewThread(cgroup, thread, id, false, &cgroup_temp) < 0)
        return -1;

    if (virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0)
        return -1;

    if (virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0)
        return -1;

    if (virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
        return -1;

    return 0;
}

static void
qemuRestoreCgroupState(virDomainObj *vm)
{
    g_autofree char *mem_mask = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    size_t i = 0;
    g_autoptr(virBitmap) all_nodes = NULL;

    if (!virNumaIsAvailable() ||
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return;

    if (!(all_nodes = virNumaGetHostMemoryNodeset()))
        goto error;

    if (!(mem_mask = virBitmapFormat(all_nodes)))
        goto error;

    if (virCgroupHasEmptyTasks(priv->cgroup,
                               VIR_CGROUP_CONTROLLER_CPUSET) <= 0)
        goto error;

    if (virCgroupSetCpusetMems(priv->cgroup, mem_mask) < 0)
        goto error;

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (qemuRestoreCgroupThread(priv->cgroup,
                                    VIR_CGROUP_THREAD_VCPU, i) < 0)
            return;
    }

    for (i = 0; i < vm->def->niothreadids; i++) {
        if (qemuRestoreCgroupThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                                    vm->def->iothreadids[i]->iothread_id) < 0)
            return;
    }

    if (qemuRestoreCgroupThread(priv->cgroup,
                                VIR_CGROUP_THREAD_EMULATOR, 0) < 0)
        return;

    return;

 error:
    virResetLastError();
    VIR_DEBUG("Couldn't restore cgroups to meaningful state");
    return;
}

int
qemuConnectCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    if (!priv->driver->privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    virCgroupFree(priv->cgroup);
    priv->cgroup = NULL;

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
qemuSetupCgroup(virDomainObj *vm,
                size_t nnicindexes,
                int *nicindexes)
{
    qemuDomainObjPrivate *priv = vm->privateData;

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

    if (qemuSetupCgroupAppid(vm) < 0)
        return -1;

    return 0;
}

int
qemuSetupCgroupVcpuBW(virCgroup *cgroup,
                      unsigned long long period,
                      long long quota)
{
    return virCgroupSetupCpuPeriodQuota(cgroup, period, quota);
}


int
qemuSetupCgroupCpusetCpus(virCgroup *cgroup,
                          virBitmap *cpumask)
{
    return virCgroupSetupCpusetCpus(cgroup, cpumask);
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


int
qemuSetupGlobalCpuCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuRemoveCgroup(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    if (virCgroupTerminateMachine(priv->machineName) < 0) {
        if (!virCgroupNewIgnoreError())
            VIR_DEBUG("Failed to terminate cgroup for %s", vm->def->name);
    }

    return virCgroupRemove(priv->cgroup);
}


static void
qemuCgroupEmulatorAllNodesDataFree(qemuCgroupEmulatorAllNodesData *data)
{
    if (!data)
        return;

    virCgroupFree(data->emulatorCgroup);
    g_free(data->emulatorMemMask);
    g_free(data);
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
qemuCgroupEmulatorAllNodesAllow(virCgroup *cgroup,
                                qemuCgroupEmulatorAllNodesData **retData)
{
    qemuCgroupEmulatorAllNodesData *data = NULL;
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

    data = g_new0(qemuCgroupEmulatorAllNodesData, 1);

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
qemuCgroupEmulatorAllNodesRestore(qemuCgroupEmulatorAllNodesData *data)
{
    virErrorPtr err;

    if (!data)
        return;

    virErrorPreserveLast(&err);
    virCgroupSetCpusetMems(data->emulatorCgroup, data->emulatorMemMask);
    virErrorRestore(&err);

    qemuCgroupEmulatorAllNodesDataFree(data);
}
