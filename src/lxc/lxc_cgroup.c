/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_cgroup.c: LXC cgroup helpers
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

#include "lxc_cgroup.h"
#include "lxc_container.h"
#include "domain_cgroup.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_cgroup");

static int virLXCCgroupSetupCpuTune(virDomainDef *def,
                                    virCgroup *cgroup)
{
    if (def->cputune.sharesSpecified) {
        if (virCgroupSetCpuShares(cgroup, def->cputune.shares) < 0)
            return -1;
    }

    return virCgroupSetupCpuPeriodQuota(cgroup, def->cputune.period,
                                        def->cputune.quota);
}


static int virLXCCgroupSetupCpusetTune(virDomainDef *def,
                                       virCgroup *cgroup,
                                       virBitmap *nodemask)
{
    g_autofree char *mask = NULL;
    virDomainNumatuneMemMode mode;

    if (def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
        def->cpumask &&
        virCgroupSetupCpusetCpus(cgroup, def->cpumask) < 0) {
        return -1;
    }

    if (virDomainNumatuneGetMode(def->numa, -1, &mode) < 0 ||
        mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        return 0;
    }

    if (virDomainNumatuneMaybeFormatNodeset(def->numa, nodemask,
                                            &mask, -1) < 0)
        return -1;

    if (mask && virCgroupSetCpusetMems(cgroup, mask) < 0)
        return -1;

    return 0;
}


static int virLXCCgroupSetupBlkioTune(virDomainDef *def,
                                      virCgroup *cgroup)
{
    return virDomainCgroupSetupBlkio(cgroup, def->blkio);
}


static int virLXCCgroupSetupMemTune(virDomainDef *def,
                                    virCgroup *cgroup)
{
    if (virCgroupSetMemory(cgroup, virDomainDefGetMemoryInitial(def)) < 0)
        return -1;

    return virDomainCgroupSetupMemtune(cgroup, def->mem);
}


static int virLXCCgroupGetMemSwapUsage(virCgroup *cgroup,
                                       struct virLXCMeminfo *meminfo)
{
    return virCgroupGetMemSwapUsage(cgroup, &meminfo->swapusage);
}


static int virLXCCgroupGetMemSwapTotal(virCgroup *cgroup,
                                       struct virLXCMeminfo *meminfo)
{
    return virCgroupGetMemSwapHardLimit(cgroup, &meminfo->swaptotal);
}


static int virLXCCgroupGetMemUsage(virCgroup *cgroup,
                                   struct virLXCMeminfo *meminfo)
{
    int ret;
    unsigned long memUsage;

    ret = virCgroupGetMemoryUsage(cgroup, &memUsage);
    meminfo->memusage = (unsigned long long)memUsage;

    return ret;
}


static int virLXCCgroupGetMemTotal(virCgroup *cgroup,
                                   struct virLXCMeminfo *meminfo)
{
    return virCgroupGetMemoryHardLimit(cgroup, &meminfo->memtotal);
}


static int virLXCCgroupGetMemStat(virCgroup *cgroup,
                                  struct virLXCMeminfo *meminfo)
{
    return virCgroupGetMemoryStat(cgroup,
                                  &meminfo->cached,
                                  &meminfo->active_anon,
                                  &meminfo->inactive_anon,
                                  &meminfo->active_file,
                                  &meminfo->inactive_file,
                                  &meminfo->unevictable);
}


int virLXCCgroupGetMeminfo(struct virLXCMeminfo *meminfo)
{
    g_autoptr(virCgroup) cgroup = NULL;

    if (virCgroupNewSelf(&cgroup) < 0)
        return -1;

    if (virLXCCgroupGetMemStat(cgroup, meminfo) < 0)
        return -1;

    if (virLXCCgroupGetMemTotal(cgroup, meminfo) < 0)
        return -1;

    if (virLXCCgroupGetMemUsage(cgroup, meminfo) < 0)
        return -1;

    if (virLXCCgroupGetMemSwapTotal(cgroup, meminfo) < 0)
        return -1;

    if (virLXCCgroupGetMemSwapUsage(cgroup, meminfo) < 0)
        return -1;

    return 0;
}



typedef struct _virLXCCgroupDevicePolicy virLXCCgroupDevicePolicy;
struct _virLXCCgroupDevicePolicy {
    char type;
    int major;
    int minor;
};


int
virLXCSetupHostUSBDeviceCgroup(virUSBDevice *dev G_GNUC_UNUSED,
                               const char *path,
                               void *opaque)
{
    virCgroup *cgroup = opaque;

    VIR_DEBUG("Process path '%s' for USB device", path);
    if (virCgroupAllowDevicePath(cgroup, path,
                                 VIR_CGROUP_DEVICE_RWM, false) < 0)
        return -1;

    return 0;
}


int
virLXCTeardownHostUSBDeviceCgroup(virUSBDevice *dev G_GNUC_UNUSED,
                                  const char *path,
                                  void *opaque)
{
    virCgroup *cgroup = opaque;

    VIR_DEBUG("Process path '%s' for USB device", path);
    if (virCgroupDenyDevicePath(cgroup, path,
                                VIR_CGROUP_DEVICE_RWM, false) < 0)
        return -1;

    return 0;
}


static int virLXCCgroupSetupDeviceACL(virDomainDef *def,
                                      virCgroup *cgroup)
{
    int capMknod = def->caps_features[VIR_DOMAIN_PROCES_CAPS_FEATURE_MKNOD];
    size_t i;
    static virLXCCgroupDevicePolicy devices[] = {
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_TTY},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_PTMX},
        {'c', LXC_DEV_MAJ_FUSE, LXC_DEV_MIN_FUSE},
        {0,   0, 0}};

    if (virCgroupDenyAllDevices(cgroup) < 0)
        return -1;

    /* white list mknod if CAP_MKNOD has to be kept */
    if (capMknod == VIR_TRISTATE_SWITCH_ON) {
        if (virCgroupAllowAllDevices(cgroup,
                                    VIR_CGROUP_DEVICE_MKNOD) < 0)
            return -1;
    }

    for (i = 0; devices[i].type != 0; i++) {
        virLXCCgroupDevicePolicy *dev = &devices[i];
        if (virCgroupAllowDevice(cgroup,
                                 dev->type,
                                 dev->major,
                                 dev->minor,
                                 VIR_CGROUP_DEVICE_RWM) < 0)
            return -1;
    }

    VIR_DEBUG("Allowing any disk block devs");
    for (i = 0; i < def->ndisks; i++) {
        if (virStorageSourceIsEmpty(def->disks[i]->src) ||
            !virStorageSourceIsBlockLocal(def->disks[i]->src))
            continue;

        if (virCgroupAllowDevicePath(cgroup,
                                     virDomainDiskGetSource(def->disks[i]),
                                     (def->disks[i]->src->readonly ?
                                      VIR_CGROUP_DEVICE_READ :
                                      VIR_CGROUP_DEVICE_RW) |
                                     VIR_CGROUP_DEVICE_MKNOD, false) < 0)
            return -1;
    }

    VIR_DEBUG("Allowing any filesystem block devs");
    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_BLOCK)
            continue;

        if (virCgroupAllowDevicePath(cgroup,
                                     def->fss[i]->src->path,
                                     def->fss[i]->readonly ?
                                     VIR_CGROUP_DEVICE_READ :
                                     VIR_CGROUP_DEVICE_RW, false) < 0)
            return -1;
    }

    VIR_DEBUG("Allowing any hostdev block devs");
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        virDomainHostdevSubsysUSB *usbsrc = &hostdev->source.subsys.u.usb;
        virUSBDevice *usb;

        switch (hostdev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
                continue;
            if (hostdev->missing)
                continue;

            if ((usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device,
                                       NULL)) == NULL)
                return -1;

            if (virUSBDeviceFileIterate(usb, virLXCSetupHostUSBDeviceCgroup,
                                        cgroup) < 0) {
                virUSBDeviceFree(usb);
                return -1;
            }
            virUSBDeviceFree(usb);
            break;
        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
            switch (hostdev->source.caps.type) {
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
                if (virCgroupAllowDevicePath(cgroup,
                                             hostdev->source.caps.u.storage.block,
                                             VIR_CGROUP_DEVICE_RW |
                                             VIR_CGROUP_DEVICE_MKNOD, false) < 0)
                    return -1;
                break;
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
                if (virCgroupAllowDevicePath(cgroup,
                                             hostdev->source.caps.u.misc.chardev,
                                             VIR_CGROUP_DEVICE_RW |
                                             VIR_CGROUP_DEVICE_MKNOD, false) < 0)
                    return -1;
                break;
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
            default:
                break;
            }
        default:
        case VIR_DOMAIN_HOSTDEV_MODE_LAST:
            break;
        }
    }

    if (virCgroupAllowDevice(cgroup, 'c', LXC_DEV_MAJ_PTY, -1,
                             VIR_CGROUP_DEVICE_RWM) < 0)
        return -1;

    VIR_DEBUG("Allowing timers char devices");

    /* Sync'ed with Host clock */
    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDef *timer = def->clock.timers[i];
        const char *dev = NULL;

        /* Check if "present" is set to "no" otherwise enable it. */
        if (timer->present == VIR_TRISTATE_BOOL_NO)
            continue;

        switch ((virDomainTimerNameType)timer->name) {
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_TSC:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        case VIR_DOMAIN_TIMER_NAME_RTC:
            dev = "/dev/rtc0";
            break;
        case VIR_DOMAIN_TIMER_NAME_HPET:
            dev = "/dev/hpet";
            break;
        }

        if (!dev)
            continue;

        if (!virFileExists(dev)) {
            VIR_DEBUG("Ignoring non-existent device %s", dev);
            continue;
        }

        if (virCgroupAllowDevicePath(cgroup, dev,
                                     VIR_CGROUP_DEVICE_READ,
                                     false) < 0)
            return -1;
    }

    VIR_DEBUG("Device ACL setup complete");

    return 0;
}


virCgroup *virLXCCgroupCreate(virDomainDef *def,
                                pid_t initpid,
                                size_t nnicindexes,
                                int *nicindexes)
{
    virCgroup *cgroup = NULL;
    g_autofree char *machineName = virLXCDomainGetMachineName(def, 0);

    if (!machineName)
        return NULL;

    if (!g_path_is_absolute(def->resource->partition)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Resource partition '%1$s' must start with '/'"),
                       def->resource->partition);
        return NULL;
    }

    if (virCgroupNewMachine(machineName,
                            "lxc",
                            def->uuid,
                            NULL,
                            initpid,
                            true,
                            nnicindexes, nicindexes,
                            def->resource->partition,
                            -1,
                            0,
                            &cgroup) < 0)
        return NULL;

    /* setup control group permissions for user namespace */
    if (def->idmap.uidmap) {
        if (virCgroupSetOwner(cgroup,
                              def->idmap.uidmap[0].target,
                              def->idmap.gidmap[0].target,
                              (1 << VIR_CGROUP_CONTROLLER_SYSTEMD)) < 0) {
            virCgroupFree(cgroup);
            return NULL;
        }
    }

    return cgroup;
}


int virLXCCgroupSetup(virDomainDef *def,
                      virCgroup *cgroup,
                      virBitmap *nodemask)
{
    if (virLXCCgroupSetupCpuTune(def, cgroup) < 0)
        return -1;

    if (virLXCCgroupSetupCpusetTune(def, cgroup, nodemask) < 0)
        return -1;

    if (virLXCCgroupSetupBlkioTune(def, cgroup) < 0)
        return -1;

    if (virLXCCgroupSetupMemTune(def, cgroup) < 0)
        return -1;

    if (virLXCCgroupSetupDeviceACL(def, cgroup) < 0)
        return -1;

    return 0;
}
