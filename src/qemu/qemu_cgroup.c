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
    int rc;

    VIR_DEBUG("Process path %s for disk", path);
    rc = virCgroupAllowDevicePath(priv->cgroup, path,
                                  (disk->readonly ? VIR_CGROUP_DEVICE_READ
                                   : VIR_CGROUP_DEVICE_RW));
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             disk->readonly ? "r" : "rw", rc);
    if (rc < 0) {
        if (rc == -EACCES) { /* Get this for root squash NFS */
            VIR_DEBUG("Ignoring EACCES for %s", path);
        } else {
            virReportSystemError(-rc,
                                 _("Unable to allow access for disk path %s"),
                                 path);
            return -1;
        }
    }
    return 0;
}


int qemuSetupDiskCgroup(virDomainObjPtr vm,
                        virDomainDiskDefPtr disk)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    return virDomainDiskDefForeachPath(disk,
                                       true,
                                       qemuSetupDiskPathAllow,
                                       vm);
}


static int
qemuTeardownDiskPathDeny(virDomainDiskDefPtr disk ATTRIBUTE_UNUSED,
                         const char *path,
                         size_t depth ATTRIBUTE_UNUSED,
                         void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    VIR_DEBUG("Process path %s for disk", path);
    rc = virCgroupDenyDevicePath(priv->cgroup, path,
                                 VIR_CGROUP_DEVICE_RWM);
    virDomainAuditCgroupPath(vm, priv->cgroup, "deny", path, "rwm", rc);
    if (rc < 0) {
        if (rc == -EACCES) { /* Get this for root squash NFS */
            VIR_DEBUG("Ignoring EACCES for %s", path);
        } else {
            virReportSystemError(-rc,
                                 _("Unable to deny access for disk path %s"),
                                 path);
            return -1;
        }
    }
    return 0;
}


int qemuTeardownDiskCgroup(virDomainObjPtr vm,
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
qemuSetupChrSourceCgroup(virDomainDefPtr def,
                         virDomainChrSourceDefPtr dev,
                         void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (dev->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", dev->data.file.path);

    rc = virCgroupAllowDevicePath(priv->cgroup, dev->data.file.path,
                                  VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                             dev->data.file.path, "rw", rc);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s for %s"),
                             dev->data.file.path, def->name);
        return -1;
    }

    return 0;
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
    int rc = 0;

    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        rc = qemuSetupChrSourceCgroup(def, &dev->data.passthrough.source,
                                      opaque);
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return rc;
}


static int
qemuSetupHostUsbDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                             const char *path,
                             void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    VIR_DEBUG("Process path '%s' for USB device", path);
    rc = virCgroupAllowDevicePath(priv->cgroup, path,
                                  VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path, "rw", rc);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s"),
                             path);
        return -1;
    }

    return 0;
}

static int
qemuSetupHostScsiDeviceCgroup(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
                              const char *path,
                              void *opaque)
{
    virDomainObjPtr vm = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    VIR_DEBUG("Process path '%s' for SCSI device", path);

    rc = virCgroupAllowDevicePath(priv->cgroup, path,
                                  virSCSIDeviceGetReadonly(dev) ?
                                  VIR_CGROUP_DEVICE_READ :
                                  VIR_CGROUP_DEVICE_RW);

    virDomainAuditCgroupPath(vm, priv->cgroup, "allow", path,
                             virSCSIDeviceGetReadonly(dev) ? "r" : "rw", rc);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s"),
                             path);
        return -1;
    }

    return 0;
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
                int rc;

                pci = virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                                      dev->source.subsys.u.pci.addr.bus,
                                      dev->source.subsys.u.pci.addr.slot,
                                      dev->source.subsys.u.pci.addr.function);
                if (!pci)
                    goto cleanup;

                if (!(path = virPCIDeviceGetIOMMUGroupDev(pci)))
                    goto cleanup;

                VIR_DEBUG("Cgroup allow %s for PCI device assignment", path);
                rc = virCgroupAllowDevicePath(priv->cgroup, path,
                                              VIR_CGROUP_DEVICE_RW);
                virDomainAuditCgroupPath(vm, priv->cgroup,
                                         "allow", path, "rw", rc);
                if (rc < 0) {
                    virReportSystemError(-rc,
                                         _("Unable to allow access "
                                           "for device path %s"),
                                         path);
                    goto cleanup;
                }
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
                int rc;

                pci = virPCIDeviceNew(dev->source.subsys.u.pci.addr.domain,
                                      dev->source.subsys.u.pci.addr.bus,
                                      dev->source.subsys.u.pci.addr.slot,
                                      dev->source.subsys.u.pci.addr.function);
                if (!pci)
                    goto cleanup;

                if (!(path = virPCIDeviceGetIOMMUGroupDev(pci)))
                    goto cleanup;

                VIR_DEBUG("Cgroup deny %s for PCI device assignment", path);
                rc = virCgroupDenyDevicePath(priv->cgroup, path,
                                             VIR_CGROUP_DEVICE_RWM);
                virDomainAuditCgroupPath(vm, priv->cgroup,
                                         "deny", path, "rwm", rc);
                if (rc < 0) {
                    virReportSystemError(-rc,
                                         _("Unable to deny access "
                                           "for device path %s"),
                                         path);
                    goto cleanup;
                }
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
    int rc = -1;
    int i;

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

    if (vm->def->blkio.weight != 0) {
        rc = virCgroupSetBlkioWeight(priv->cgroup, vm->def->blkio.weight);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io weight for domain %s"),
                                 vm->def->name);
            return -1;
        }
    }

    if (vm->def->blkio.ndevices) {
        for (i = 0; i < vm->def->blkio.ndevices; i++) {
            virBlkioDeviceWeightPtr dw = &vm->def->blkio.devices[i];
            if (!dw->weight)
                continue;
            rc = virCgroupSetBlkioDeviceWeight(priv->cgroup, dw->path,
                                               dw->weight);
            if (rc != 0) {
                virReportSystemError(-rc,
                                     _("Unable to set io device weight "
                                       "for domain %s"),
                                     vm->def->name);
                return -1;
            }
        }
    }

    return 0;
}


static int
qemuSetupMemoryCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long hard_limit;
    int rc;
    int i;

    if (!virCgroupHasController(priv->cgroup,VIR_CGROUP_CONTROLLER_MEMORY)) {
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

    hard_limit = vm->def->mem.hard_limit;
    if (!hard_limit) {
        /* If there is no hard_limit set, set a reasonable one to avoid
         * system thrashing caused by exploited qemu.  A 'reasonable
         * limit' has been chosen:
         *     (1 + k) * (domain memory + total video memory) + (32MB for
         *     cache per each disk) + F
         * where k = 0.5 and F = 200MB.  The cache for disks is important as
         * kernel cache on the host side counts into the RSS limit. */
        hard_limit = vm->def->mem.max_balloon;
        for (i = 0; i < vm->def->nvideos; i++)
            hard_limit += vm->def->videos[i]->vram;
        hard_limit = hard_limit * 1.5 + 204800;
        hard_limit += vm->def->ndisks * 32768;
    }

    rc = virCgroupSetMemoryHardLimit(priv->cgroup, hard_limit);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to set memory hard limit for domain %s"),
                             vm->def->name);
        return -1;
    }
    if (vm->def->mem.soft_limit != 0) {
        rc = virCgroupSetMemorySoftLimit(priv->cgroup, vm->def->mem.soft_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set memory soft limit for domain %s"),
                                 vm->def->name);
            return -1;
        }
    }

    if (vm->def->mem.swap_hard_limit != 0) {
        rc = virCgroupSetMemSwapHardLimit(priv->cgroup, vm->def->mem.swap_hard_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set swap hard limit for domain %s"),
                                 vm->def->name);
            return -1;
        }
    }

    return 0;
}


static int
qemuSetupDevicesCgroup(virQEMUDriverPtr driver,
                       virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    const char *const *deviceACL = NULL;
    int rc = -1;
    int ret = -1;
    int i;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    rc = virCgroupDenyAllDevices(priv->cgroup);
    virDomainAuditCgroup(vm, priv->cgroup, "deny", "all", rc == 0);
    if (rc != 0) {
        if (rc == -EPERM) {
            VIR_WARN("Group devices ACL is not accessible, disabling whitelisting");
            return 0;
        }

        virReportSystemError(-rc,
                             _("Unable to deny all devices for %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuSetupDiskCgroup(vm, vm->def->disks[i]) < 0)
            goto cleanup;
    }

    rc = virCgroupAllowDeviceMajor(priv->cgroup, 'c', DEVICE_PTY_MAJOR,
                                   VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_PTY_MAJOR,
                              "pty", "rw", rc == 0);
    if (rc != 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to allow /dev/pts/ devices"));
        goto cleanup;
    }

    cfg = virQEMUDriverGetConfig(driver);
    deviceACL = cfg->cgroupDeviceACL ?
                (const char *const *)cfg->cgroupDeviceACL :
                defaultDeviceACL;

    if (vm->def->nsounds &&
        (!vm->def->ngraphics ||
         ((vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
           cfg->vncAllowHostAudio) ||
           (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL)))) {
        rc = virCgroupAllowDeviceMajor(priv->cgroup, 'c', DEVICE_SND_MAJOR,
                                       VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupMajor(vm, priv->cgroup, "allow", DEVICE_SND_MAJOR,
                                  "sound", "rw", rc == 0);
        if (rc != 0) {
            virReportSystemError(-rc, "%s",
                                     _("unable to allow /dev/snd/ devices"));
            goto cleanup;
        }
    }

    for (i = 0; deviceACL[i] != NULL; i++) {
        if (access(deviceACL[i], F_OK) < 0) {
            VIR_DEBUG("Ignoring non-existant device %s",
                      deviceACL[i]);
            continue;
        }

        rc = virCgroupAllowDevicePath(priv->cgroup, deviceACL[i],
                                      VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", deviceACL[i], "rw", rc);
        if (rc < 0 &&
            rc != -ENOENT) {
            virReportSystemError(-rc,
                                 _("unable to allow device %s"),
                                 deviceACL[i]);
            goto cleanup;
        }
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
                      virBitmapPtr nodemask)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *mask = NULL;
    int rc;
    int ret = -1;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if ((vm->def->numatune.memory.nodemask ||
         (vm->def->numatune.memory.placement_mode ==
          VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)) &&
        vm->def->numatune.memory.mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {

        if (vm->def->numatune.memory.placement_mode ==
            VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)
            mask = virBitmapFormat(nodemask);
        else
            mask = virBitmapFormat(vm->def->numatune.memory.nodemask);

        if (!mask) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to convert memory nodemask"));
            goto cleanup;
        }

        rc = virCgroupSetCpusetMems(priv->cgroup, mask);

        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set cpuset.mems for domain %s"),
                                 vm->def->name);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    VIR_FREE(mask);
    return ret;
}


static int
qemuSetupCpuCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc = -1;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
       if (vm->def->cputune.shares) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("CPU tuning is not available on this host"));
           return -1;
       } else {
           return 0;
       }
    }

    if (vm->def->cputune.shares) {
        rc = virCgroupSetCpuShares(priv->cgroup, vm->def->cputune.shares);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu shares for domain %s"),
                                 vm->def->name);
            return -1;
        }
    }

    return 0;
}


int qemuInitCgroup(virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   bool startup)
{
    int rc = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr parent = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!cfg->privileged)
        goto done;

    virCgroupFree(&priv->cgroup);

    if (!vm->def->resource && startup) {
        virDomainResourceDefPtr res;

        if (VIR_ALLOC(res) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (VIR_STRDUP(res->partition, "/machine") < 0) {
            VIR_FREE(res);
            goto cleanup;
        }

        vm->def->resource = res;
    }

    if (vm->def->resource &&
        vm->def->resource->partition) {
        if (vm->def->resource->partition[0] != '/') {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Resource partition '%s' must start with '/'"),
                           vm->def->resource->partition);
            goto cleanup;
        }
        /* We only auto-create the default partition. In other
         * cases we expec the sysadmin/app to have done so */
        rc = virCgroupNewPartition(vm->def->resource->partition,
                                   STREQ(vm->def->resource->partition, "/machine"),
                                   cfg->cgroupControllers,
                                   &parent);
        if (rc != 0) {
            if (rc == -ENXIO ||
                rc == -EPERM ||
                rc == -EACCES) { /* No cgroups mounts == success */
                VIR_DEBUG("No cgroups present/configured/accessible, ignoring error");
                goto done;
            }

            virReportSystemError(-rc,
                                 _("Unable to initialize %s cgroup"),
                                 vm->def->resource->partition);
            goto cleanup;
        }

        rc = virCgroupNewDomainPartition(parent,
                                         "qemu",
                                         vm->def->name,
                                         true,
                                         &priv->cgroup);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 vm->def->name);
            goto cleanup;
        }
    } else {
        rc = virCgroupNewDriver("qemu",
                                true,
                                cfg->cgroupControllers,
                                &parent);
        if (rc != 0) {
            if (rc == -ENXIO ||
                rc == -EPERM ||
                rc == -EACCES) { /* No cgroups mounts == success */
                VIR_DEBUG("No cgroups present/configured/accessible, ignoring error");
                goto done;
            }

            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 vm->def->name);
            goto cleanup;
        }

        rc = virCgroupNewDomainDriver(parent,
                                      vm->def->name,
                                      true,
                                      &priv->cgroup);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 vm->def->name);
            goto cleanup;
        }
    }

done:
    rc = 0;
cleanup:
    virCgroupFree(&parent);
    virObjectUnref(cfg);
    return rc;
}


int qemuSetupCgroup(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    virBitmapPtr nodemask)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (qemuInitCgroup(driver, vm, true) < 0)
        return -1;

    if (!priv->cgroup)
        return 0;

    if (qemuSetupDevicesCgroup(driver, vm) < 0)
        goto cleanup;

    if (qemuSetupBlkioCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupMemoryCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupCpuCgroup(vm) < 0)
        goto cleanup;

    if (qemuSetupCpusetCgroup(vm, nodemask) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    return ret;
}

int qemuSetupCgroupVcpuBW(virCgroupPtr cgroup, unsigned long long period,
                          long long quota)
{
    int rc;
    unsigned long long old_period;

    if (period == 0 && quota == 0)
        return 0;

    if (period) {
        /* get old period, and we can rollback if set quota failed */
        rc = virCgroupGetCpuCfsPeriod(cgroup, &old_period);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to get cpu bandwidth period"));
            return -1;
        }

        rc = virCgroupSetCpuCfsPeriod(cgroup, period);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to set cpu bandwidth period"));
            return -1;
        }
    }

    if (quota) {
        rc = virCgroupSetCpuCfsQuota(cgroup, quota);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to set cpu bandwidth quota"));
            goto cleanup;
        }
    }

    return 0;

cleanup:
    if (period) {
        rc = virCgroupSetCpuCfsPeriod(cgroup, old_period);
        if (rc < 0)
            virReportSystemError(-rc, "%s",
                                 _("Unable to rollback cpu bandwidth period"));
    }

    return -1;
}

int qemuSetupCgroupVcpuPin(virCgroupPtr cgroup,
                           virDomainVcpuPinDefPtr *vcpupin,
                           int nvcpupin,
                           int vcpuid)
{
    int i;

    for (i = 0; i < nvcpupin; i++) {
        if (vcpuid == vcpupin[i]->vcpuid) {
            return qemuSetupCgroupEmulatorPin(cgroup, vcpupin[i]->cpumask);
        }
    }

    return -1;
}

int qemuSetupCgroupEmulatorPin(virCgroupPtr cgroup,
                               virBitmapPtr cpumask)
{
    int rc = 0;
    char *new_cpus = NULL;

    new_cpus = virBitmapFormat(cpumask);
    if (!new_cpus) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to convert cpu mask"));
        rc = -1;
        goto cleanup;
    }

    rc = virCgroupSetCpusetCpus(cgroup, new_cpus);
    if (rc < 0) {
        virReportSystemError(-rc,
                             "%s",
                             _("Unable to set cpuset.cpus"));
        goto cleanup;
    }

cleanup:
    VIR_FREE(new_cpus);
    return rc;
}

int qemuSetupCgroupForVcpu(virDomainObjPtr vm)
{
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    int rc;
    unsigned int i, j;
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
        rc = virCgroupNewVcpu(priv->cgroup, i, true, &cgroup_vcpu);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 _("Unable to create vcpu cgroup for %s(vcpu:"
                                   " %d)"),
                                 vm->def->name, i);
            goto cleanup;
        }

        /* move the thread for vcpu to sub dir */
        rc = virCgroupAddTask(cgroup_vcpu, priv->vcpupids[i]);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 _("unable to add vcpu %d task %d to cgroup"),
                                 i, priv->vcpupids[i]);
            goto cleanup;
        }

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

int qemuSetupCgroupForEmulator(virQEMUDriverPtr driver,
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
    int rc;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupNewEmulator(priv->cgroup, true, &cgroup_emulator);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to create emulator cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

    rc = virCgroupMoveTask(priv->cgroup, cgroup_emulator);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to move tasks from domain cgroup to "
                               "emulator cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

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
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            rc = qemuSetupCgroupEmulatorPin(cgroup_emulator, cpumask);
            if (rc < 0)
                goto cleanup;
        }
        cpumask = NULL; /* sanity */
    }

    if (period || quota) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
            if ((rc = qemuSetupCgroupVcpuBW(cgroup_emulator, period,
                                            quota)) < 0)
                goto cleanup;
        }
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

    return rc;
}

int qemuRemoveCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    return virCgroupRemove(priv->cgroup);
}

int qemuAddToCgroup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupAddTask(priv->cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("unable to add domain %s task %d to cgroup"),
                             vm->def->name, getpid());
        return -1;
    }

    return 0;
}
