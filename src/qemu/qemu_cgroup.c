/*
 * qemu_cgroup.c: QEMU cgroup management
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_cgroup.h"
#include "qemu_domain.h"
#include "cgroup.h"
#include "logging.h"
#include "memory.h"
#include "virterror_internal.h"
#include "util.h"
#include "domain_audit.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static const char *const defaultDeviceACL[] = {
    "/dev/null", "/dev/full", "/dev/zero",
    "/dev/random", "/dev/urandom",
    "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
    "/dev/rtc", "/dev/hpet",
    NULL,
};
#define DEVICE_PTY_MAJOR 136
#define DEVICE_SND_MAJOR 116

bool qemuCgroupControllerActive(struct qemud_driver *driver,
                                int controller)
{
    if (driver->cgroup == NULL)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;
    if (!virCgroupMounted(driver->cgroup, controller))
        return false;
    if (driver->cgroupControllers & (1 << controller))
        return true;
    return false;
}

static int
qemuSetupDiskPathAllow(virDomainDiskDefPtr disk,
                       const char *path,
                       size_t depth ATTRIBUTE_UNUSED,
                       void *opaque)
{
    qemuCgroupData *data = opaque;
    int rc;

    VIR_DEBUG("Process path %s for disk", path);
    rc = virCgroupAllowDevicePath(data->cgroup, path,
                                  (disk->readonly ? VIR_CGROUP_DEVICE_READ
                                   : VIR_CGROUP_DEVICE_RW));
    virDomainAuditCgroupPath(data->vm, data->cgroup, "allow", path,
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


int qemuSetupDiskCgroup(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        virCgroupPtr cgroup,
                        virDomainDiskDefPtr disk)
{
    qemuCgroupData data = { vm, cgroup };
    return virDomainDiskDefForeachPath(disk,
                                       driver->allowDiskFormatProbing,
                                       true,
                                       driver->user, driver->group,
                                       qemuSetupDiskPathAllow,
                                       &data);
}


static int
qemuTeardownDiskPathDeny(virDomainDiskDefPtr disk ATTRIBUTE_UNUSED,
                         const char *path,
                         size_t depth ATTRIBUTE_UNUSED,
                         void *opaque)
{
    qemuCgroupData *data = opaque;
    int rc;

    VIR_DEBUG("Process path %s for disk", path);
    rc = virCgroupDenyDevicePath(data->cgroup, path,
                                 VIR_CGROUP_DEVICE_RWM);
    virDomainAuditCgroupPath(data->vm, data->cgroup, "deny", path, "rwm", rc);
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


int qemuTeardownDiskCgroup(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           virCgroupPtr cgroup,
                           virDomainDiskDefPtr disk)
{
    qemuCgroupData data = { vm, cgroup };
    return virDomainDiskDefForeachPath(disk,
                                       driver->allowDiskFormatProbing,
                                       true,
                                       driver->user, driver->group,
                                       qemuTeardownDiskPathDeny,
                                       &data);
}


static int
qemuSetupChardevCgroup(virDomainDefPtr def,
                       virDomainChrDefPtr dev,
                       void *opaque)
{
    qemuCgroupData *data = opaque;
    int rc;

    if (dev->source.type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;


    VIR_DEBUG("Process path '%s' for disk", dev->source.data.file.path);
    rc = virCgroupAllowDevicePath(data->cgroup, dev->source.data.file.path,
                                  VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(data->vm, data->cgroup, "allow",
                             dev->source.data.file.path, "rw", rc);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s for %s"),
                             dev->source.data.file.path, def->name);
        return -1;
    }

    return 0;
}


int qemuSetupHostUsbDeviceCgroup(usbDevice *dev ATTRIBUTE_UNUSED,
                                 const char *path,
                                 void *opaque)
{
    qemuCgroupData *data = opaque;
    int rc;

    VIR_DEBUG("Process path '%s' for USB device", path);
    rc = virCgroupAllowDevicePath(data->cgroup, path,
                                  VIR_CGROUP_DEVICE_RW);
    virDomainAuditCgroupPath(data->vm, data->cgroup, "allow", path, "rw", rc);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s"),
                             path);
        return -1;
    }

    return 0;
}

int qemuSetupCgroup(struct qemud_driver *driver,
                    virDomainObjPtr vm)
{
    virCgroupPtr cgroup = NULL;
    int rc;
    unsigned int i;
    const char *const *deviceACL =
        driver->cgroupDeviceACL ?
        (const char *const *)driver->cgroupDeviceACL :
        defaultDeviceACL;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 1);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to create cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        qemuCgroupData data = { vm, cgroup };
        rc = virCgroupDenyAllDevices(cgroup);
        virDomainAuditCgroup(vm, cgroup, "deny", "all", rc == 0);
        if (rc != 0) {
            if (rc == -EPERM) {
                VIR_WARN("Group devices ACL is not accessible, disabling whitelisting");
                goto done;
            }

            virReportSystemError(-rc,
                                 _("Unable to deny all devices for %s"), vm->def->name);
            goto cleanup;
        }

        for (i = 0; i < vm->def->ndisks ; i++) {
            if (qemuSetupDiskCgroup(driver, vm, cgroup, vm->def->disks[i]) < 0)
                goto cleanup;
        }

        rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_PTY_MAJOR,
                                       VIR_CGROUP_DEVICE_RW);
        virDomainAuditCgroupMajor(vm, cgroup, "allow", DEVICE_PTY_MAJOR,
                                  "pty", "rw", rc == 0);
        if (rc != 0) {
            virReportSystemError(-rc, "%s",
                                 _("unable to allow /dev/pts/ devices"));
            goto cleanup;
        }

        if (vm->def->nsounds &&
            (!vm->def->ngraphics ||
             ((vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
               driver->vncAllowHostAudio) ||
              (vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL)))) {
            rc = virCgroupAllowDeviceMajor(cgroup, 'c', DEVICE_SND_MAJOR,
                                           VIR_CGROUP_DEVICE_RW);
            virDomainAuditCgroupMajor(vm, cgroup, "allow", DEVICE_SND_MAJOR,
                                      "sound", "rw", rc == 0);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to allow /dev/snd/ devices"));
                goto cleanup;
            }
        }

        for (i = 0; deviceACL[i] != NULL ; i++) {
            rc = virCgroupAllowDevicePath(cgroup, deviceACL[i],
                                          VIR_CGROUP_DEVICE_RW);
            virDomainAuditCgroupPath(vm, cgroup, "allow", deviceACL[i], "rw", rc);
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
                                   &data) < 0)
            goto cleanup;

        for (i = 0; i < vm->def->nhostdevs; i++) {
            virDomainHostdevDefPtr hostdev = vm->def->hostdevs[i];
            usbDevice *usb;

            if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
                continue;
            if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
                continue;

            if ((usb = usbGetDevice(hostdev->source.subsys.u.usb.bus,
                                    hostdev->source.subsys.u.usb.device)) == NULL)
                goto cleanup;

            if (usbDeviceFileIterate(usb, qemuSetupHostUsbDeviceCgroup,
                                     &data) < 0)
                goto cleanup;
        }
    }

    if (vm->def->blkio.weight != 0) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            rc = virCgroupSetBlkioWeight(cgroup, vm->def->blkio.weight);
            if(rc != 0) {
                virReportSystemError(-rc,
                                     _("Unable to set io weight for domain %s"),
                                     vm->def->name);
                goto cleanup;
            }
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Block I/O tuning is not available on this host"));
            goto cleanup;
        }
    }

    if (vm->def->blkio.ndevices) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            for (i = 0; i < vm->def->blkio.ndevices; i++) {
                virBlkioDeviceWeightPtr dw = &vm->def->blkio.devices[i];
                if (!dw->weight)
                    continue;
                rc = virCgroupSetBlkioDeviceWeight(cgroup, dw->path,
                                                   dw->weight);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set io device weight "
                                           "for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Block I/O tuning is not available on this host"));
            goto cleanup;
        }
    }

    if (vm->def->mem.hard_limit != 0 ||
        vm->def->mem.soft_limit != 0 ||
        vm->def->mem.swap_hard_limit != 0) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_MEMORY)) {
            if (vm->def->mem.hard_limit != 0) {
                rc = virCgroupSetMemoryHardLimit(cgroup, vm->def->mem.hard_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set memory hard limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }
            if (vm->def->mem.soft_limit != 0) {
                rc = virCgroupSetMemorySoftLimit(cgroup, vm->def->mem.soft_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set memory soft limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }

            if (vm->def->mem.swap_hard_limit != 0) {
                rc = virCgroupSetMemSwapHardLimit(cgroup, vm->def->mem.swap_hard_limit);
                if (rc != 0) {
                    virReportSystemError(-rc,
                                         _("Unable to set swap hard limit for domain %s"),
                                         vm->def->name);
                    goto cleanup;
                }
            }
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Memory cgroup is not available on this host"));
        }
    }

    if (vm->def->cputune.shares != 0) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
            rc = virCgroupSetCpuShares(cgroup, vm->def->cputune.shares);
            if(rc != 0) {
                virReportSystemError(-rc,
                                     _("Unable to set io cpu shares for domain %s"),
                                     vm->def->name);
                goto cleanup;
            }
        } else {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("CPU tuning is not available on this host"));
        }
    }

    if (vm->def->numatune.memory.nodemask &&
        vm->def->numatune.memory.mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT &&
        qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPUSET)) {
        char *mask = virDomainCpuSetFormat(vm->def->numatune.memory.nodemask, VIR_DOMAIN_CPUMASK_LEN);
        if (!mask) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("failed to convert memory nodemask"));
            goto cleanup;
        }

        rc = virCgroupSetCpusetMems(cgroup, mask);
        VIR_FREE(mask);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set cpuset.mems for domain %s"),
                                 vm->def->name);
            goto cleanup;
        }
    }
done:
    virCgroupFree(&cgroup);
    return 0;

cleanup:
    if (cgroup) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }
    return -1;
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
            virReportSystemError(-rc,
                                 _("%s"),
                                 "Unable to rollback cpu bandwidth period");
    }

    return -1;
}

int qemuSetupCgroupForVcpu(struct qemud_driver *driver, virDomainObjPtr vm)
{
    virCgroupPtr cgroup = NULL;
    virCgroupPtr cgroup_vcpu = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;
    unsigned int i;
    unsigned long long period = vm->def->cputune.period;
    long long quota = vm->def->cputune.quota;
    long long vm_quota = 0;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to find cgroup for %s"),
                             vm->def->name);
        goto cleanup;
    }

    /* Set cpu bandwidth for the vm */
    if (period || quota) {
        if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
            /* Ensure that we can multiply by vcpus without overflowing. */
            if (quota > LLONG_MAX / vm->def->vcpus) {
                virReportSystemError(EINVAL,
                                     _("%s"),
                                     "Unable to set cpu bandwidth quota");
                goto cleanup;
            }

            if (quota > 0)
                vm_quota = quota * vm->def->vcpus;
            else
                vm_quota = quota;
            if (qemuSetupCgroupVcpuBW(cgroup, period, vm_quota) < 0)
                goto cleanup;
        }
    }

    if (priv->nvcpupids == 0 || priv->vcpupids[0] == vm->pid) {
        /* If we does not know VCPU<->PID mapping or all vcpu runs in the same
         * thread, we cannot control each vcpu.
         */
        virCgroupFree(&cgroup);
        return 0;
    }

    for (i = 0; i < priv->nvcpupids; i++) {
        rc = virCgroupForVcpu(cgroup, i, &cgroup_vcpu, 1);
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
            if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
                if (qemuSetupCgroupVcpuBW(cgroup_vcpu, period, quota) < 0)
                    goto cleanup;
            }
        }

        virCgroupFree(&cgroup_vcpu);
    }

    virCgroupFree(&cgroup_vcpu);
    virCgroupFree(&cgroup);
    return 0;

cleanup:
    virCgroupFree(&cgroup_vcpu);
    if (cgroup) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    return -1;
}


int qemuRemoveCgroup(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int quiet)
{
    virCgroupPtr cgroup;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0);
    if (rc != 0) {
        if (!quiet)
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s"),
                            vm->def->name);
        return rc;
    }

    rc = virCgroupRemove(cgroup);
    virCgroupFree(&cgroup);
    return rc;
}

int qemuAddToCgroup(struct qemud_driver *driver,
                    virDomainDefPtr def)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rc;

    if (driver->cgroup == NULL)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(driver->cgroup, def->name, &cgroup, 0);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("unable to find cgroup for domain %s"),
                             def->name);
        goto cleanup;
    }

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("unable to add domain %s task %d to cgroup"),
                             def->name, getpid());
        goto cleanup;
    }

    ret = 0;

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}
