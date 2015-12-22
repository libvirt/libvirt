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

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_cgroup");

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
qemuSetImageCgroupInternal(virDomainObjPtr vm,
                           virStorageSourcePtr src,
                           bool deny,
                           bool forceReadonly)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int perms = VIR_CGROUP_DEVICE_READ;
    int ret;

    if (!virCgroupHasController(priv->cgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES))
        return 0;

    if (!src->path || !virStorageSourceIsLocalStorage(src)) {
        VIR_DEBUG("Not updating cgroups for disk path '%s', type: %s",
                  NULLSTR(src->path), virStorageTypeToString(src->type));
        return 0;
    }

    if (deny) {
        perms |= VIR_CGROUP_DEVICE_WRITE | VIR_CGROUP_DEVICE_MKNOD;

        VIR_DEBUG("Deny path %s", src->path);

        ret = virCgroupDenyDevicePath(priv->cgroup, src->path, perms);
    } else {
        if (!src->readonly && !forceReadonly)
            perms |= VIR_CGROUP_DEVICE_WRITE;

        VIR_DEBUG("Allow path %s, perms: %s",
                  src->path, virCgroupGetDevicePermsString(perms));

        ret = virCgroupAllowDevicePath(priv->cgroup, src->path, perms);
    }

    virDomainAuditCgroupPath(vm, priv->cgroup,
                             deny ? "deny" : "allow",
                             src->path,
                             virCgroupGetDevicePermsString(perms),
                             ret == 0);

    /* Get this for root squash NFS */
    if (ret < 0 &&
        virLastErrorIsSystemErrno(EACCES)) {
        VIR_DEBUG("Ignoring EACCES for %s", src->path);
        virResetLastError();
        ret = 0;
    }

    return ret;
}


int
qemuSetImageCgroup(virDomainObjPtr vm,
                   virStorageSourcePtr src,
                   bool deny)
{
    return qemuSetImageCgroupInternal(vm, src, deny, false);
}


int
qemuSetupDiskCgroup(virDomainObjPtr vm,
                    virDomainDiskDefPtr disk)
{
    virStorageSourcePtr next;
    bool forceReadonly = false;

    for (next = disk->src; next; next = next->backingStore) {
        if (qemuSetImageCgroupInternal(vm, next, false, forceReadonly) < 0)
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
        if (qemuSetImageCgroup(vm, next, true) < 0)
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

    if (source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    VIR_DEBUG("Process path '%s' for device", source->data.file.path);

    ret = virCgroupAllowDevicePath(priv->cgroup, source->data.file.path,
                                   VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                             source->data.file.path, "rw", ret == 0);

    return ret;
}

static int
qemuSetupChardevCgroup(virDomainDefPtr def ATTRIBUTE_UNUSED,
                       virDomainChrDefPtr dev,
                       void *opaque)
{
    virDomainObjPtr vm = opaque;

    return qemuSetupChrSourceCgroup(vm, &dev->source);
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

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        VIR_DEBUG("Process path '%s' for input device", dev->source.evdev);
        ret = virCgroupAllowDevicePath(priv->cgroup, dev->source.evdev,
                                       VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupPath(vm, priv->cgroup, "allow", dev->source.evdev, "rw", ret == 0);
        break;
    }

    return ret;
}


static int
qemuSetupHostUSBDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
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
qemuSetupHostSCSIDeviceCgroup(virSCSIDevicePtr dev ATTRIBUTE_UNUSED,
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
qemuSetupHostdevCgroup(virDomainObjPtr vm,
                       virDomainHostdevDefPtr dev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
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
            if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                int rv;

                pci = virPCIDeviceNew(pcisrc->addr.domain,
                                      pcisrc->addr.bus,
                                      pcisrc->addr.slot,
                                      pcisrc->addr.function);
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
            if ((usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device,
                                       NULL)) == NULL) {
                goto cleanup;
            }

            /* oddly, qemuSetupHostUSBDeviceCgroup doesn't ever
             * reference the usb object we just created
             */
            if (virUSBDeviceFileIterate(usb, qemuSetupHostUSBDeviceCgroup,
                                        vm) < 0) {
                goto cleanup;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
            if (scsisrc->protocol ==
                VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
                virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &scsisrc->u.iscsi;
                /* Follow qemuSetupDiskCgroup() and qemuSetImageCgroupInternal()
                 * which does nothing for non local storage
                 */
                VIR_DEBUG("Not updating cgroups for hostdev iSCSI path '%s'",
                          iscsisrc->path);
            } else {
                virDomainHostdevSubsysSCSIHostPtr scsihostsrc =
                    &scsisrc->u.host;
                if ((scsi = virSCSIDeviceNew(NULL,
                                             scsihostsrc->adapter,
                                             scsihostsrc->bus,
                                             scsihostsrc->target,
                                             scsihostsrc->unit,
                                             dev->readonly,
                                             dev->shareable)) == NULL)
                    goto cleanup;

                if (virSCSIDeviceFileIterate(scsi,
                                             qemuSetupHostSCSIDeviceCgroup,
                                             vm) < 0)
                    goto cleanup;
            }
            break;
        }

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
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
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
            if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                int rv;

                pci = virPCIDeviceNew(pcisrc->addr.domain,
                                      pcisrc->addr.bus,
                                      pcisrc->addr.slot,
                                      pcisrc->addr.function);
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
            VIR_DEBUG("Ignoring non-existent device %s", deviceACL[i]);
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

    if (vm->def->tpm && qemuSetupTPMCgroup(vm) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (qemuSetupHostdevCgroup(vm, vm->def->hostdevs[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->ninputs; i++) {
        if (qemuSetupInputCgroup(vm, vm->def->inputs[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->nrngs; i++) {
        if (vm->def->rngs[i]->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM) {
            VIR_DEBUG("Setting Cgroup ACL for RNG device");
            rv = virCgroupAllowDevicePath(priv->cgroup,
                                          vm->def->rngs[i]->source.file,
                                          VIR_CGROUP_DEVICE_RW);
            virDomainAuditCgroupPath(vm, priv->cgroup, "allow",
                                     vm->def->rngs[i]->source.file,
                                     "rw", rv == 0);
            if (rv < 0 &&
                !virLastErrorIsSystemErrno(ENOENT))
                goto cleanup;
        }
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

    if (virCgroupNewMachine(vm->def->name,
                            "qemu",
                            true,
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

    if (!(all_nodes = virNumaGetHostNodeset()))
        goto error;

    if (!(mem_mask = virBitmapFormat(all_nodes)))
        goto error;

    if ((empty = virCgroupHasEmptyTasks(priv->cgroup,
                                        VIR_CGROUP_CONTROLLER_CPUSET)) <= 0)
        goto error;

    if (virCgroupSetCpusetMems(priv->cgroup, mem_mask) < 0)
        goto error;

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        virDomainVcpuInfoPtr vcpu = virDomainDefGetVcpu(vm->def, i);

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
                                  vm->pid,
                                  cfg->cgroupControllers,
                                  &priv->cgroup) < 0)
        goto cleanup;

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
qemuSetupCgroupForVcpu(virDomainObjPtr vm)
{
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    size_t i, j;
    unsigned long long period = vm->def->cputune.period;
    long long quota = vm->def->cputune.quota;
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
     * not initialized either, then there's nothing to do anyway. CPU pinning
     * will be set via virProcessSetAffinity.
     */
    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    /* If vCPU<->pid mapping is missing we can't do vCPU pinning */
    if (!qemuDomainHasVcpuPids(vm))
        return 0;

    if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                            priv->autoNodeset,
                                            &mem_mask, -1) < 0)
        goto cleanup;

    for (i = 0; i < virDomainDefGetVcpusMax(def); i++) {
        virDomainVcpuInfoPtr vcpu = virDomainDefGetVcpu(def, i);

        if (!vcpu->online)
            continue;

        virCgroupFree(&cgroup_vcpu);
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i,
                               true, &cgroup_vcpu) < 0)
            goto cleanup;

        if (period || quota) {
            if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
                goto cleanup;
        }

        /* Set vcpupin in cgroup if vcpupin xml is provided */
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            virBitmapPtr cpumap = NULL;

            if (mem_mask &&
                virCgroupSetCpusetMems(cgroup_vcpu, mem_mask) < 0)
                goto cleanup;

            /* try to use the default cpu maps */
            if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
                cpumap = priv->autoCpuset;
            else
                cpumap = vm->def->cpumask;

            /* lookup a more specific pinning info */
            for (j = 0; j < def->cputune.nvcpupin; j++) {
                if (def->cputune.vcpupin[j]->id == i) {
                    cpumap = def->cputune.vcpupin[j]->cpumask;
                    break;
                }
            }

            if (cpumap && qemuSetupCgroupCpusetCpus(cgroup_vcpu, cpumap) < 0)
                goto cleanup;
        }

        /* move the thread for vcpu to sub dir */
        if (virCgroupAddTask(cgroup_vcpu,
                             qemuDomainGetVcpuPid(vm, i)) < 0)
            goto cleanup;

    }
    virCgroupFree(&cgroup_vcpu);
    VIR_FREE(mem_mask);

    return 0;

 cleanup:
    if (cgroup_vcpu) {
        virCgroupRemove(cgroup_vcpu);
        virCgroupFree(&cgroup_vcpu);
    }
    VIR_FREE(mem_mask);

    return -1;
}

int
qemuSetupCgroupForEmulator(virDomainObjPtr vm)
{
    virBitmapPtr cpumask = NULL;
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

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           true, &cgroup_emulator) < 0)
        goto cleanup;

    if (virCgroupMoveTask(priv->cgroup, cgroup_emulator) < 0)
        goto cleanup;

    if (def->cputune.emulatorpin)
        cpumask = def->cputune.emulatorpin;
    else if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
        cpumask = priv->autoCpuset;
    else if (def->cpumask)
        cpumask = def->cpumask;

    if (cpumask) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET) &&
            qemuSetupCgroupCpusetCpus(cgroup_emulator, cpumask) < 0)
            goto cleanup;
    }

    if (period || quota) {
        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) &&
            qemuSetupCgroupVcpuBW(cgroup_emulator, period,
                                  quota) < 0)
            goto cleanup;
    }

    virCgroupFree(&cgroup_emulator);
    return 0;

 cleanup:
    if (cgroup_emulator) {
        virCgroupRemove(cgroup_emulator);
        virCgroupFree(&cgroup_emulator);
    }

    return -1;
}

int
qemuSetupCgroupForIOThreads(virDomainObjPtr vm)
{
    virCgroupPtr cgroup_iothread = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    size_t i;
    unsigned long long period = vm->def->cputune.period;
    long long quota = vm->def->cputune.quota;
    char *mem_mask = NULL;
    virDomainNumatuneMemMode mem_mode;

    if (def->niothreadids == 0)
        return 0;

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

    for (i = 0; i < def->niothreadids; i++) {
        /* IOThreads are numbered 1..n, although the array is 0..n-1,
         * so we will account for that here
         */
        if (virCgroupNewThread(priv->cgroup, VIR_CGROUP_THREAD_IOTHREAD,
                               def->iothreadids[i]->iothread_id,
                               true, &cgroup_iothread) < 0)
            goto cleanup;

        if (period || quota) {
            if (qemuSetupCgroupVcpuBW(cgroup_iothread, period, quota) < 0)
                goto cleanup;
        }

        /* Set iothreadpin in cgroup if iothreadpin xml is provided */
        if (virCgroupHasController(priv->cgroup,
                                   VIR_CGROUP_CONTROLLER_CPUSET)) {
            virBitmapPtr cpumask = NULL;

            if (mem_mask &&
                virCgroupSetCpusetMems(cgroup_iothread, mem_mask) < 0)
                goto cleanup;

            if (def->iothreadids[i]->cpumask)
                cpumask = def->iothreadids[i]->cpumask;
            else if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
                cpumask = priv->autoCpuset;
            else
                cpumask = def->cpumask;

            if (cpumask &&
                qemuSetupCgroupCpusetCpus(cgroup_iothread, cpumask) < 0)
                goto cleanup;
        }

        /* move the thread for iothread to sub dir */
        if (virCgroupAddTask(cgroup_iothread,
                             def->iothreadids[i]->thread_id) < 0)
            goto cleanup;

        virCgroupFree(&cgroup_iothread);
    }
    VIR_FREE(mem_mask);

    return 0;

 cleanup:
    if (cgroup_iothread) {
        virCgroupRemove(cgroup_iothread);
        virCgroupFree(&cgroup_iothread);
    }
    VIR_FREE(mem_mask);

    return -1;
}

int
qemuRemoveCgroup(virQEMUDriverPtr driver,
                 virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    if (virCgroupTerminateMachine(vm->def->name,
                                  "qemu",
                                  virQEMUDriverIsPrivileged(driver)) < 0) {
        if (!virCgroupNewIgnoreError())
            VIR_DEBUG("Failed to terminate cgroup for %s", vm->def->name);
    }

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
