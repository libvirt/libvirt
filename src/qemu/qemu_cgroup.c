/*
 * qemu_cgroup.c: QEMU cgroup management
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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

#define VIR_FROM_THIS VIR_FROM_QEMU

static const char *const defaultDeviceACL[] = {
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet", "/dev/vfio/vfio",
    NULL,
};
#define DEVICE_PTY_MAJOR 136
#define DEVICE_SND_MAJOR 116

static int
qemuSetupDiskPathAllow(virDomainDiskDefPtr disk,
                       const char *path,
                       size_t depth ATTRIBUTE_UNUSED,
                       void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    VIR_DEBUG("Process path %s for disk", path);
    ret = virCgroupAllowDevicePath(priv->cgroup, path,
                                   (disk->readonly ? VIR_CGROUP_DEVICE_READ
                                    : VIR_CGROUP_DEVICE_RW));
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             disk->readonly ? "r" : "rw", ret == 0);

    /* Get this for root squash NFS */
    if (ret < 0 &&
        virLastErrorIsSystemErrno(EACCES)) {
        VIR_DEBUG("Ignoring EACCES for %s", path);
        virResetLastError();
        ret = 0;
    }
    return ret;
}


int
qemuSetupDiskCgroup(virDomainObjPtr vm,
                    virDomainDiskDefPtr disk)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    return virDomainDiskDefForeachPath(disk, true, qemuSetupDiskPathAllow, vm);
}


static int
qemuTeardownDiskPathDeny(virDomainDiskDefPtr disk ATTRIBUTE_UNUSED,
                         const char *path,
                         size_t depth ATTRIBUTE_UNUSED,
                         void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    VIR_DEBUG("Process path %s for disk", path);
    ret = virCgroupDenyDevicePath(priv->cgroup, path,
                                  VIR_CGROUP_DEVICE_RWM);
    virDomainAuditCgroupPath(vm, priv->cgroup, "deny", path, "rwm", ret == 0);

    /* Get this for root squash NFS */
    if (ret < 0 &&
        virLastErrorIsSystemErrno(EACCES)) {
        VIR_DEBUG("Ignoring EACCES for %s", path);
        virResetLastError();
        ret = 0;
    }
    return ret;
}


int
qemuTeardownDiskCgroup(virDomainObjPtr vm,
                       virDomainDiskDefPtr disk)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    return virDomainDiskDefForeachPath(disk,
                                       true,
                                       qemuTeardownDiskPathDeny,
                                       vm);
}

static int
qemuSetupChrSourceCgroup(virDomainDefPtr def ATTRIBUTE_UNUSED,
                         virDomainChrSourceDefPtr dev,
                         void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (dev->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", dev->data.file.path);

    ret = virCgroupAllowDevicePath(priv->cgroup, dev->data.file.path,
                                   VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                             dev->data.file.path, "rw", ret == 0);

    return ret;
}

static int
qemuSetupChardevCgroup(virDomainDefPtr def,
                       virDomainChrDefPtr dev,
                       void *opaque)
{
    return qemuSetupChrSourceCgroup(def, &dev->source, opaque);
}


static int
qemuSetupTPMCgroup(virDomainDefPtr def,
                   virDomainTPMDefPtr dev,
                   void *opaque)
{
    int ret = 0;

    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        ret = qemuSetupChrSourceCgroup(def, &dev->data.passthrough.source,
                                       opaque);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}


static int
qemuSetupHostUsbDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                             const char *path,
                             void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    VIR_DEBUG("Process path '%s' for USB device", path);
    ret = virCgroupAllowDevicePath(priv->cgroup, path,
                                   VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path, "rw", ret == 0);

    return ret;
}

static int
qemuSetupHostScsiDeviceCgroup(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
                              const char *path,
                              void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    VIR_DEBUG("Process path '%s' for SCSI device", path);

    ret = virCgroupAllowDevicePath(priv->cgroup, path,
                                   virSCSIDeviceGetReadonly(dev) ?
                                   VIR_CGROUP_DEVICE_READ :
                                   VIR_CGROUP_DEVICE_RW);

    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             virSCSIDeviceGetReadonly(dev) ? "r" : "rw", ret == 0);

    return ret;
}

int
qemuSetupHostdevCGroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virPCIDevicePtr pci = NULL;
    virUSBDevicePtr usb = NULL;
    virSCSIDevicePtr scsi = NULL;
    char *path = NULL;

    /* currently this only does something for PCI devices using vfio
     * for device assignment, but it is called for *all* hostdev
     * devices.
     */

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (dev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {

        switch (dev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            if (dev->source.subsys.u.pci.backend
                == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                int rv;

                pci = virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                                      dev->source.subsys.u.pci.addr.bus,
                                      dev->source.subsys.u.pci.addr.slot,
                                      dev->source.subsys.u.pci.addr.function);
                if (!pci)
                    goto cleanup;

                if (!(path = virPCIDeviceGetIOMMUGroupDev(pci)))
                    goto cleanup;

                VIR_DEBUG("Cgroup allow %s for PCI device assignment", path);
                rv = virCgroupAllowDevicePath(priv->cgroup, path,
                                              VIR_CGROUP_DEVICE_RW);
                virDomainAuditCgroupPath(vm, priv->cgroup,
                                         "allow", path, "rw", rv == 0);
                if (rv < 0)
                    goto cleanup;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            /* NB: hostdev->missing wasn't previously checked in the
             * case of hotplug, only when starting a domain. Now it is
             * always checked, and the cgroup setup skipped if true.
             */
            if (dev->missing)
                break;
            if ((usb = virUSBDeviceNew(dev->source.subsys.u.usb.bus,
                                       dev->source.subsys.u.usb.device,
                                       NULL)) == NULL) {
                goto cleanup;
            }

            /* oddly, qemuSetupHostUsbDeviceCgroup doesn't ever
             * reference the usb object we just created
             */
            if (virUSBDeviceFileIterate(usb, qemuSetupHostUsbDeviceCgroup,
                                        vm) < 0) {
                goto cleanup;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            if ((scsi = virSCSIDeviceNew(dev->source.subsys.u.scsi.adapter,
                                         dev->source.subsys.u.scsi.bus,
                                         dev->source.subsys.u.scsi.target,
                                         dev->source.subsys.u.scsi.unit,
                                         dev->readonly)) == NULL)
                goto cleanup;

            if (virSCSIDeviceFileIterate(scsi,
                                         qemuSetupHostScsiDeviceCgroup,
                                         vm) < 0)
                goto cleanup;

        default:
            break;
        }
    }

    ret = 0;
cleanup:
    virPCIDeviceFree(pci);
    virUSBDeviceFree(usb);
    virSCSIDeviceFree(scsi);
    VIR_FREE(path);
    return ret;
}

int
qemuTeardownHostdevCgroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virPCIDevicePtr pci = NULL;
    char *path = NULL;

    /* currently this only does something for PCI devices using vfio
     * for device assignment, but it is called for *all* hostdev
     * devices.
     */

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (dev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {

        switch (dev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            if (dev->source.subsys.u.pci.backend
                == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                int rv;

                pci = virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                                      dev->source.subsys.u.pci.addr.bus,
                                      dev->source.subsys.u.pci.addr.slot,
                                      dev->source.subsys.u.pci.addr.function);
                if (!pci)
                    goto cleanup;

                if (!(path = virPCIDeviceGetIOMMUGroupDev(pci)))
                    goto cleanup;

                VIR_DEBUG("Cgroup deny %s for PCI device assignment", path);
                rv = virCgroupDenyDevicePath(priv->cgroup, path,
                                             VIR_CGROUP_DEVICE_RWM);
                virDomainAuditCgroupPath(vm, priv->cgroup,
                                         "deny", path, "rwm", rv == 0);
                if (rv < 0)
                    goto cleanup;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            /* nothing to tear down for USB */
            break;
        default:
            break;
        }
    }

    ret = 0;
cleanup:
    virPCIDeviceFree(pci);
    VIR_FREE(path);
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
            virBlkioDeviceWeightPtr dw = &vm->def->blkio.devices[i];
            if (!dw->weight)
                continue;
            if (virCgroupSetBlkioDeviceWeight(priv->cgroup, dw->path,
                                              dw->weight) < 0)
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
        if (vm->def->mem.hard_limit != 0 ||
            vm->def->mem.soft_limit != 0 ||
            vm->def->mem.swap_hard_limit != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory cgroup is not available on this host"));
            return -1;
        } else {
            return 0;
        }
    }

    if (vm->def->mem.hard_limit != 0 &&
        virCgroupSetMemoryHardLimit(priv->cgroup, vm->def->mem.hard_limit) < 0)
        return -1;

    if (vm->def->mem.soft_limit != 0 &&
        virCgroupSetMemorySoftLimit(priv->cgroup, vm->def->mem.soft_limit) < 0)
        return -1;

    if (vm->def->mem.swap_hard_limit != 0 &&
        virCgroupSetMemSwapHardLimit(priv->cgroup, vm->def->mem.swap_hard_limit) < 0)
        return -1;

    return 0;
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

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuSetupDiskCgroup(vm, vm->def->disks[i]) < 0)
            goto cleanup;
    }

    rv = virCgroupAllowDeviceMajor(priv->cgroup, 'c', DEVICE_PTY_MAJOR,
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
        rv = virCgroupAllowDeviceMajor(priv->cgroup, 'c', DEVICE_SND_MAJOR,
                                       VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_SND_MAJOR,
                                  "sound", "rw", rv == 0);
        if (rv < 0)
            goto cleanup;
    }

    for (i = 0; deviceACL[i] != NULL; i++) {
        if (!virFileExists(deviceACL[i])) {
            VIR_DEBUG("Ignoring non-existant device %s", deviceACL[i]);
            continue;
        }

        rv = virCgroupAllowDevicePath(priv->cgroup, deviceACL[i],
                                      VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", deviceACL[i], "rw", rv == 0);
        if (rv < 0 &&
            !virLastErrorIsSystemErrno(ENOENT))
            goto cleanup;
    }

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuSetupChardevCgroup,
                               vm) < 0)
        goto cleanup;

    if (vm->def->tpm &&
        (qemuSetupTPMCgroup(vm->def,
                            vm->def->tpm,
                            vm) < 0))
        goto cleanup;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (qemuSetupHostdevCGroup(vm, vm->def->hostdevs[i]) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int
qemuSetupCpusetCgroup(virDomainObjPtr vm,
                      virBitmapPtr nodemask,
                      virCapsPtr caps)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *mem_mask = NULL;
    char *cpu_mask = NULL;
    int ret = -1;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if ((vm->def->numatune.memory.nodemask ||
         (vm->def->numatune.memory.placement_mode ==
          VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)) &&
        vm->def->numatune.memory.mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {

        if (vm->def->numatune.memory.placement_mode ==
            VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)
            mem_mask = virBitmapFormat(nodemask);
        else
            mem_mask = virBitmapFormat(vm->def->numatune.memory.nodemask);

        if (!mem_mask) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to convert memory nodemask"));
            goto cleanup;
        }

        if (virCgroupSetCpusetMems(priv->cgroup, mem_mask) < 0)
            goto cleanup;
    }

    if (vm->def->cpumask ||
        (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)) {

        if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
            virBitmapPtr cpumap;
            if (!(cpumap = virCapabilitiesGetCpusForNodemask(caps, nodemask)))
                goto cleanup;
            cpu_mask = virBitmapFormat(cpumap);
            virBitmapFree(cpumap);
        } else {
            cpu_mask = virBitmapFormat(vm->def->cpumask);
        }

        if (!cpu_mask) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to convert cpu mask"));
            goto cleanup;
        }

        if (virCgroupSetCpusetCpus(priv->cgroup, cpu_mask) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(mem_mask);
    VIR_FREE(cpu_mask);
    return ret;
}


static int
qemuSetupCpuCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
       if (vm->def->cputune.shares) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("CPU tuning is not available on this host"));
           return -1;
       } else {
           return 0;
       }
    }

    if (vm->def->cputune.shares &&
        virCgroupSetCpuShares(priv->cgroup, vm->def->cputune.shares) < 0)
        return -1;

    return 0;
}


static int
qemuInitCgroup(virQEMUDriverPtr driver,
               virDomainObjPtr vm)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!cfg->privileged)
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

    if (virCgroupNewMachine(vm->def->name,
                            "qemu",
                            cfg->privileged,
                            vm->def->uuid,
                            NULL,
                            vm->pid,
                            false,
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


int
qemuConnectCgroup(virQEMUDriverPtr driver,
                  virDomainObjPtr vm)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!cfg->privileged)
        goto done;

    if (!virCgroupAvailable())
        goto done;

    virCgroupFree(&priv->cgroup);

    if (virCgroupNewDetectMachine(vm->def->name,
                                  "qemu",
                                  vm->pid,
                                  vm->def->resource ?
                                  vm->def->resource->partition :
                                  NULL,
                                  cfg->cgroupControllers,
                                  &priv->cgroup) < 0)
        goto cleanup;

done:
    ret = 0;
cleanup:
    virObjectUnref(cfg);
    return ret;
}

int
qemuSetupCgroup(virQEMUDriverPtr driver,
                virDomainObjPtr vm,
                virBitmapPtr nodemask)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    int ret = -1;

    if (!vm->pid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup cgroups until process is started"));
        return -1;
    }

    if (qemuInitCgroup(driver, vm) < 0)
        return -1;

    if (!priv->cgroup)
        return 0;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (qemuSetupDevicesCgroup(driver, vm) < 0)
        goto cleanup;

    if (qemuSetupBlkioCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupMemoryCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupCpuCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupCpusetCgroup(vm, nodemask, caps) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virObjectUnref(caps);
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
qemuSetupCgroupVcpuPin(virCgroupPtr cgroup,
                       virDomainVcpuPinDefPtr *vcpupin,
                       int nvcpupin,
                       int vcpuid)
{
    size_t i;

    for (i = 0; i < nvcpupin; i++) {
        if (vcpuid == vcpupin[i]->vcpuid) {
            return qemuSetupCgroupEmulatorPin(cgroup, vcpupin[i]->cpumask);
        }
    }

    return -1;
}

int
qemuSetupCgroupEmulatorPin(virCgroupPtr cgroup,
                           virBitmapPtr cpumask)
{
    int ret = -1;
    char *new_cpus = NULL;

    new_cpus = virBitmapFormat(cpumask);
    if (!new_cpus) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to convert cpu mask"));
        goto cleanup;
    }

    if (virCgroupSetCpusetCpus(cgroup, new_cpus) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(new_cpus);
    return ret;
}

int
qemuSetupCgroupForVcpu(virDomainObjPtr vm)
{
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    size_t i, j;
    unsigned long long period = vm->def->cputune.period;
    long long quota = vm->def->cputune.quota;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    /* We are trying to setup cgroups for CPU pinning, which can also be done
     * with virProcessInfoSetAffinity, thus the lack of cgroups is not fatal
     * here.
     */
    if (priv->cgroup == NULL)
        return 0;

    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        /* If we don't know VCPU<->PID mapping or all vcpu runs in the same
         * thread, we cannot control each vcpu.
         */
        VIR_WARN("Unable to get vcpus' pids.");
        return 0;
    }

    for (i = 0; i < priv->nvcpupids; i++) {
        if (virCgroupNewVcpu(priv->cgroup, i, true, &cgroup_vcpu) < 0)
            goto cleanup;

        /* move the thread for vcpu to sub dir */
        if (virCgroupAddTask(cgroup_vcpu, priv->vcpupids[i]) < 0)
            goto cleanup;

        if (period || quota) {
            if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
                goto cleanup;
        }

        /* Set vcpupin in cgroup if vcpupin xml is provided */
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            /* find the right CPU to pin, otherwise
             * qemuSetupCgroupVcpuPin will fail. */
            for (j = 0; j < def->cputune.nvcpupin; j++) {
                if (def->cputune.vcpupin[j]->vcpuid != i)
                    continue;

                if (qemuSetupCgroupVcpuPin(cgroup_vcpu,
                                           def->cputune.vcpupin,
                                           def->cputune.nvcpupin,
                                           i) < 0)
                    goto cleanup;

                break;
            }
        }

        virCgroupFree(&cgroup_vcpu);
    }

    return 0;

cleanup:
    if (cgroup_vcpu) {
        virCgroupRemove(cgroup_vcpu);
        virCgroupFree(&cgroup_vcpu);
    }

    return -1;
}

int
qemuSetupCgroupForEmulator(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virBitmapPtr nodemask)
{
    virBitmapPtr cpumask = NULL;
    virBitmapPtr cpumap = NULL;
    virCgroupPtr cgroup_emulator = NULL;
    virDomainDefPtr def = vm->def;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long period = vm->def->cputune.emulator_period;
    long long quota = vm->def->cputune.emulator_quota;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    if (virCgroupNewEmulator(priv->cgroup, true, &cgroup_emulator) < 0)
        goto cleanup;

    if (virCgroupMoveTask(priv->cgroup, cgroup_emulator) < 0)
        goto cleanup;

    if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        if (!(cpumap = qemuPrepareCpumap(driver, nodemask)))
            goto cleanup;
        cpumask = cpumap;
    } else if (def->cputune.emulatorpin) {
        cpumask = def->cputune.emulatorpin->cpumask;
    } else if (def->cpumask) {
        cpumask = def->cpumask;
    }

    if (cpumask) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET) &&
            qemuSetupCgroupEmulatorPin(cgroup_emulator, cpumask) < 0)
            goto cleanup;
    }

    if (period || quota) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
            qemuSetupCgroupVcpuBW(cgroup_emulator, period,
                                  quota) < 0)
            goto cleanup;
    }

    virCgroupFree(&cgroup_emulator);
    virBitmapFree(cpumap);
    return 0;

cleanup:
    virBitmapFree(cpumap);

    if (cgroup_emulator) {
        virCgroupRemove(cgroup_emulator);
        virCgroupFree(&cgroup_emulator);
    }

    return -1;
}

int
qemuRemoveCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    return virCgroupRemove(priv->cgroup);
}

int
qemuAddToCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    return 0;
}
