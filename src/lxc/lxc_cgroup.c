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
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "vircgroup.h"
#include "virstring.h"
#include "virsystemd.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_cgroup");

static int virLXCCgroupSetupCpuTune(virDomainDefPtr def,
                                    virCgroupPtr cgroup)
{
    int ret = -1;

    if (def->cputune.sharesSpecified) {
        unsigned long long val;
        if (virCgroupSetCpuShares(cgroup, def->cputune.shares) < 0)
            goto cleanup;

        if (virCgroupGetCpuShares(cgroup, &val) < 0)
            goto cleanup;
        def->cputune.shares = val;
    }

    if (def->cputune.quota != 0 &&
        virCgroupSetCpuCfsQuota(cgroup, def->cputune.quota) < 0)
        goto cleanup;

    if (def->cputune.period != 0 &&
        virCgroupSetCpuCfsPeriod(cgroup, def->cputune.period) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}


static int virLXCCgroupSetupCpusetTune(virDomainDefPtr def,
                                       virCgroupPtr cgroup,
                                       virBitmapPtr nodemask)
{
    int ret = -1;
    char *mask = NULL;
    virDomainNumatuneMemMode mode;

    if (def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
        def->cpumask) {
        if (!(mask = virBitmapFormat(def->cpumask)))
            return -1;

        if (virCgroupSetCpusetCpus(cgroup, mask) < 0)
            goto cleanup;
        /* free mask to make sure we won't use it in a wrong way later */
        VIR_FREE(mask);
    }

    if (virDomainNumatuneGetMode(def->numa, -1, &mode) < 0 ||
        mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        ret = 0;
        goto cleanup;
    }

    if (virDomainNumatuneMaybeFormatNodeset(def->numa, nodemask,
                                            &mask, -1) < 0)
        goto cleanup;

    if (mask && virCgroupSetCpusetMems(cgroup, mask) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(mask);
    return ret;
}


static int virLXCCgroupSetupBlkioTune(virDomainDefPtr def,
                                      virCgroupPtr cgroup)
{
    size_t i;

    if (def->blkio.weight &&
        virCgroupSetBlkioWeight(cgroup, def->blkio.weight) < 0)
        return -1;

    if (def->blkio.ndevices) {
        for (i = 0; i < def->blkio.ndevices; i++) {
            virBlkioDevicePtr dev = &def->blkio.devices[i];

            if (dev->weight &&
                (virCgroupSetBlkioDeviceWeight(cgroup, dev->path,
                                               dev->weight) < 0 ||
                 virCgroupGetBlkioDeviceWeight(cgroup, dev->path,
                                               &dev->weight) < 0))
                return -1;

            if (dev->riops &&
                (virCgroupSetBlkioDeviceReadIops(cgroup, dev->path,
                                                 dev->riops) < 0 ||
                 virCgroupGetBlkioDeviceReadIops(cgroup, dev->path,
                                                 &dev->riops) < 0))
                return -1;

            if (dev->wiops &&
                (virCgroupSetBlkioDeviceWriteIops(cgroup, dev->path,
                                                  dev->wiops) < 0 ||
                 virCgroupGetBlkioDeviceWriteIops(cgroup, dev->path,
                                                  &dev->wiops) < 0))
                return -1;

            if (dev->rbps &&
                (virCgroupSetBlkioDeviceReadBps(cgroup, dev->path,
                                                dev->rbps) < 0 ||
                 virCgroupGetBlkioDeviceReadBps(cgroup, dev->path,
                                                &dev->rbps) < 0))
                return -1;

            if (dev->wbps &&
                (virCgroupSetBlkioDeviceWriteBps(cgroup, dev->path,
                                                 dev->wbps) < 0 ||
                 virCgroupGetBlkioDeviceWriteBps(cgroup, dev->path,
                                                 &dev->wbps) < 0))
                return -1;
        }
    }

    return 0;
}


static int virLXCCgroupSetupMemTune(virDomainDefPtr def,
                                    virCgroupPtr cgroup)
{
    int ret = -1;

    if (virCgroupSetMemory(cgroup, virDomainDefGetMemoryInitial(def)) < 0)
        goto cleanup;

    if (virMemoryLimitIsSet(def->mem.hard_limit))
        if (virCgroupSetMemoryHardLimit(cgroup, def->mem.hard_limit) < 0)
            goto cleanup;

    if (virMemoryLimitIsSet(def->mem.soft_limit))
        if (virCgroupSetMemorySoftLimit(cgroup, def->mem.soft_limit) < 0)
            goto cleanup;

    if (virMemoryLimitIsSet(def->mem.swap_hard_limit))
        if (virCgroupSetMemSwapHardLimit(cgroup, def->mem.swap_hard_limit) < 0)
            goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}


static int virLXCCgroupGetMemSwapUsage(virCgroupPtr cgroup,
                                       virLXCMeminfoPtr meminfo)
{
    return virCgroupGetMemSwapUsage(cgroup, &meminfo->swapusage);
}


static int virLXCCgroupGetMemSwapTotal(virCgroupPtr cgroup,
                                       virLXCMeminfoPtr meminfo)
{
    return virCgroupGetMemSwapHardLimit(cgroup, &meminfo->swaptotal);
}


static int virLXCCgroupGetMemUsage(virCgroupPtr cgroup,
                                   virLXCMeminfoPtr meminfo)
{
    int ret;
    unsigned long memUsage;

    ret = virCgroupGetMemoryUsage(cgroup, &memUsage);
    meminfo->memusage = (unsigned long long)memUsage;

    return ret;
}


static int virLXCCgroupGetMemTotal(virCgroupPtr cgroup,
                                   virLXCMeminfoPtr meminfo)
{
    return virCgroupGetMemoryHardLimit(cgroup, &meminfo->memtotal);
}


static int virLXCCgroupGetMemStat(virCgroupPtr cgroup,
                                  virLXCMeminfoPtr meminfo)
{
    return virCgroupGetMemoryStat(cgroup,
                                  &meminfo->cached,
                                  &meminfo->inactive_anon,
                                  &meminfo->active_anon,
                                  &meminfo->inactive_file,
                                  &meminfo->active_file,
                                  &meminfo->unevictable);
}


int virLXCCgroupGetMeminfo(virLXCMeminfoPtr meminfo)
{
    int ret = -1;
    virCgroupPtr cgroup;

    if (virCgroupNewSelf(&cgroup) < 0)
        return -1;

    if (virLXCCgroupGetMemStat(cgroup, meminfo) < 0)
        goto cleanup;

    if (virLXCCgroupGetMemTotal(cgroup, meminfo) < 0)
        goto cleanup;

    if (virLXCCgroupGetMemUsage(cgroup, meminfo) < 0)
        goto cleanup;

    if (virLXCCgroupGetMemSwapTotal(cgroup, meminfo) < 0)
        goto cleanup;

    if (virLXCCgroupGetMemSwapUsage(cgroup, meminfo) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCgroupFree(&cgroup);
    return ret;
}



typedef struct _virLXCCgroupDevicePolicy virLXCCgroupDevicePolicy;
typedef virLXCCgroupDevicePolicy *virLXCCgroupDevicePolicyPtr;

struct _virLXCCgroupDevicePolicy {
    char type;
    int major;
    int minor;
};


int
virLXCSetupHostUSBDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                               const char *path,
                               void *opaque)
{
    virCgroupPtr cgroup = opaque;

    VIR_DEBUG("Process path '%s' for USB device", path);
    if (virCgroupAllowDevicePath(cgroup, path,
                                 VIR_CGROUP_DEVICE_RWM, false) < 0)
        return -1;

    return 0;
}


int
virLXCTeardownHostUSBDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                                  const char *path,
                                  void *opaque)
{
    virCgroupPtr cgroup = opaque;

    VIR_DEBUG("Process path '%s' for USB device", path);
    if (virCgroupDenyDevicePath(cgroup, path,
                                VIR_CGROUP_DEVICE_RWM, false) < 0)
        return -1;

    return 0;
}


static int virLXCCgroupSetupDeviceACL(virDomainDefPtr def,
                                      virCgroupPtr cgroup)
{
    int capMknod = def->caps_features[VIR_DOMAIN_CAPS_FEATURE_MKNOD];
    int ret = -1;
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
        goto cleanup;

    /* white list mknod if CAP_MKNOD has to be kept */
    if (capMknod == VIR_TRISTATE_SWITCH_ON) {
        if (virCgroupAllowAllDevices(cgroup,
                                    VIR_CGROUP_DEVICE_MKNOD) < 0)
            goto cleanup;
    }

    for (i = 0; devices[i].type != 0; i++) {
        virLXCCgroupDevicePolicyPtr dev = &devices[i];
        if (virCgroupAllowDevice(cgroup,
                                 dev->type,
                                 dev->major,
                                 dev->minor,
                                 VIR_CGROUP_DEVICE_RWM) < 0)
            goto cleanup;
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
            goto cleanup;
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
            goto cleanup;
    }

    VIR_DEBUG("Allowing any hostdev block devs");
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        virDomainHostdevSubsysUSBPtr usbsrc = &hostdev->source.subsys.u.usb;
        virUSBDevicePtr usb;

        switch (hostdev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
                continue;
            if (hostdev->missing)
                continue;

            if ((usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device,
                                       NULL)) == NULL)
                goto cleanup;

            if (virUSBDeviceFileIterate(usb, virLXCSetupHostUSBDeviceCgroup,
                                        cgroup) < 0) {
                virUSBDeviceFree(usb);
                goto cleanup;
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
                    goto cleanup;
                break;
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
                if (virCgroupAllowDevicePath(cgroup,
                                             hostdev->source.caps.u.misc.chardev,
                                             VIR_CGROUP_DEVICE_RW |
                                             VIR_CGROUP_DEVICE_MKNOD, false) < 0)
                    goto cleanup;
                break;
            default:
                break;
            }
        default:
            break;
        }
    }

    if (virCgroupAllowDevice(cgroup, 'c', LXC_DEV_MAJ_PTY, -1,
                             VIR_CGROUP_DEVICE_RWM) < 0)
        goto cleanup;

    VIR_DEBUG("Device whitelist complete");

    ret = 0;
 cleanup:
    return ret;
}


virCgroupPtr virLXCCgroupCreate(virDomainDefPtr def,
                                pid_t initpid,
                                size_t nnicindexes,
                                int *nicindexes)
{
    virCgroupPtr cgroup = NULL;
    char *machineName = virLXCDomainGetMachineName(def, 0);

    if (!machineName)
        goto cleanup;

    if (def->resource->partition[0] != '/') {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Resource partition '%s' must start with '/'"),
                       def->resource->partition);
        goto cleanup;
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
                            &cgroup) < 0)
        goto cleanup;

    /* setup control group permissions for user namespace */
    if (def->idmap.uidmap) {
        if (virCgroupSetOwner(cgroup,
                              def->idmap.uidmap[0].target,
                              def->idmap.gidmap[0].target,
                              (1 << VIR_CGROUP_CONTROLLER_SYSTEMD)) < 0) {
            virCgroupFree(&cgroup);
            cgroup = NULL;
            goto cleanup;
        }
    }

 cleanup:
    VIR_FREE(machineName);

    return cgroup;
}


int virLXCCgroupSetup(virDomainDefPtr def,
                      virCgroupPtr cgroup,
                      virBitmapPtr nodemask)
{
    int ret = -1;

    if (virLXCCgroupSetupCpuTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupCpusetTune(def, cgroup, nodemask) < 0)
        goto cleanup;

    if (virLXCCgroupSetupBlkioTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupMemTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupDeviceACL(def, cgroup) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}
