/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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

#define VIR_FROM_THIS VIR_FROM_LXC

static int virLXCCgroupSetupCpuTune(virDomainDefPtr def,
                                    virCgroupPtr cgroup)
{
    int ret = -1;
    if (def->cputune.shares != 0) {
        int rc = virCgroupSetCpuShares(cgroup, def->cputune.shares);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu shares for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    if (def->cputune.quota != 0) {
        int rc = virCgroupSetCpuCfsQuota(cgroup, def->cputune.quota);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu quota for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    if (def->cputune.period != 0) {
        int rc = virCgroupSetCpuCfsPeriod(cgroup, def->cputune.period);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu period for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    ret = 0;
cleanup:
    return ret;
}


static int virLXCCgroupSetupCpusetTune(virDomainDefPtr def,
                                       virCgroupPtr cgroup,
                                       virBitmapPtr nodemask)
{
    int rc = 0;
    char *mask = NULL;

    if (def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO &&
        def->cpumask) {
        mask = virBitmapFormat(def->cpumask);
        if (!mask) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to convert cpumask"));
            return -1;
        }

        rc = virCgroupSetCpusetCpus(cgroup, mask);
        if (rc < 0) {
            virReportSystemError(-rc, "%s",
                                 _("Unable to set cpuset.cpus"));
            goto cleanup;
        }
    }

    if ((def->numatune.memory.nodemask ||
         (def->numatune.memory.placement_mode ==
          VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)) &&
          def->numatune.memory.mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        if (def->numatune.memory.placement_mode ==
            VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)
            mask = virBitmapFormat(nodemask);
        else
            mask = virBitmapFormat(def->numatune.memory.nodemask);

        if (!mask) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to convert memory nodemask"));
            return -1;
        }

        rc = virCgroupSetCpusetMems(cgroup, mask);
        if (rc < 0)
            virReportSystemError(-rc, "%s", _("Unable to set cpuset.mems"));
    }

cleanup:
    VIR_FREE(mask);
    return rc;
}


static int virLXCCgroupSetupBlkioTune(virDomainDefPtr def,
                                      virCgroupPtr cgroup)
{
    int ret = -1;

    if (def->blkio.weight) {
        int rc = virCgroupSetBlkioWeight(cgroup, def->blkio.weight);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set Blkio weight for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    return ret;
}


static int virLXCCgroupSetupMemTune(virDomainDefPtr def,
                                    virCgroupPtr cgroup)
{
    int ret = -1;
    int rc;

    rc = virCgroupSetMemory(cgroup, def->mem.max_balloon);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to set memory limit for domain %s"),
                             def->name);
        goto cleanup;
    }

    if (def->mem.hard_limit) {
        rc = virCgroupSetMemoryHardLimit(cgroup, def->mem.hard_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set memory hard limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    if (def->mem.soft_limit) {
        rc = virCgroupSetMemorySoftLimit(cgroup, def->mem.soft_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set memory soft limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    if (def->mem.swap_hard_limit) {
        rc = virCgroupSetMemSwapHardLimit(cgroup, def->mem.swap_hard_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set swap hard limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

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
    meminfo->memusage = (unsigned long long) memUsage;

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
    int ret = 0;
    FILE *statfd = NULL;
    char *statFile = NULL;
    char *line = NULL;
    size_t n;

    ret = virCgroupPathOfController(cgroup, VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.stat", &statFile);
    if (ret != 0) {
        virReportSystemError(-ret, "%s",
                             _("cannot get the path of MEMORY cgroup controller"));
        return ret;
    }

    statfd = fopen(statFile, "r");
    if (statfd == NULL) {
        ret = -errno;
        goto cleanup;
    }

    while (getline(&line, &n, statfd) > 0) {

        char *value = strchr(line, ' ');
        char *nl = value ? strchr(line, '\n') : NULL;
        unsigned long long stat_value;

        if (!value)
            continue;

        if (nl)
            *nl = '\0';

        *value = '\0';

        if (virStrToLong_ull(value + 1, NULL, 10, &stat_value) < 0) {
            ret = -EINVAL;
            goto cleanup;
        }
        if (STREQ(line, "cache"))
            meminfo->cached = stat_value >> 10;
        else if (STREQ(line, "inactive_anon"))
            meminfo->inactive_anon = stat_value >> 10;
        else if (STREQ(line, "active_anon"))
            meminfo->active_anon = stat_value >> 10;
        else if (STREQ(line, "inactive_file"))
            meminfo->inactive_file = stat_value >> 10;
        else if (STREQ(line, "active_file"))
            meminfo->active_file = stat_value >> 10;
        else if (STREQ(line, "unevictable"))
            meminfo->unevictable = stat_value >> 10;
    }
    ret = 0;

cleanup:
    VIR_FREE(line);
    VIR_FREE(statFile);
    VIR_FORCE_FCLOSE(statfd);
    return ret;
}


int virLXCCgroupGetMeminfo(virLXCMeminfoPtr meminfo)
{
    int ret;
    virCgroupPtr cgroup;

    ret = virCgroupNewSelf(&cgroup);
    if (ret < 0) {
        virReportSystemError(-ret, "%s",
                             _("Unable to get cgroup for container"));
        return ret;
    }

    ret = virLXCCgroupGetMemStat(cgroup, meminfo);
    if (ret < 0) {
        virReportSystemError(-ret, "%s",
                             _("Unable to get memory cgroup stat info"));
        goto cleanup;
    }

    ret = virLXCCgroupGetMemTotal(cgroup, meminfo);
    if (ret < 0) {
        virReportSystemError(-ret, "%s",
                             _("Unable to get memory cgroup total"));
        goto cleanup;
    }

    ret = virLXCCgroupGetMemUsage(cgroup, meminfo);
    if (ret < 0) {
        virReportSystemError(-ret, "%s",
                             _("Unable to get memory cgroup stat usage"));
        goto cleanup;
    }

    virLXCCgroupGetMemSwapTotal(cgroup, meminfo);
    virLXCCgroupGetMemSwapUsage(cgroup, meminfo);

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
virLXCSetupHostUsbDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                               const char *path,
                               void *opaque)
{
    virCgroupPtr cgroup = opaque;
    int rc;

    VIR_DEBUG("Process path '%s' for USB device", path);
    rc = virCgroupAllowDevicePath(cgroup, path,
                                  VIR_CGROUP_DEVICE_RW);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to allow device %s"),
                             path);
        return -1;
    }

    return 0;
}


int
virLXCTeardownHostUsbDeviceCgroup(virUSBDevicePtr dev ATTRIBUTE_UNUSED,
                                  const char *path,
                                  void *opaque)
{
    virCgroupPtr cgroup = opaque;
    int rc;

    VIR_DEBUG("Process path '%s' for USB device", path);
    rc = virCgroupDenyDevicePath(cgroup, path,
                                 VIR_CGROUP_DEVICE_RW);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to deny device %s"),
                             path);
        return -1;
    }

    return 0;
}


static int virLXCCgroupSetupDeviceACL(virDomainDefPtr def,
                                      virCgroupPtr cgroup)
{
    int ret = -1;
    int rc;
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

    rc = virCgroupDenyAllDevices(cgroup);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to deny devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    for (i = 0; devices[i].type != 0; i++) {
        virLXCCgroupDevicePolicyPtr dev = &devices[i];
        rc = virCgroupAllowDevice(cgroup,
                                  dev->type,
                                  dev->major,
                                  dev->minor,
                                  VIR_CGROUP_DEVICE_RWM);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %c:%d:%d for domain %s"),
                                 dev->type, dev->major, dev->minor, def->name);
            goto cleanup;
        }
    }

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->type != VIR_DOMAIN_DISK_TYPE_BLOCK)
            continue;

        rc = virCgroupAllowDevicePath(cgroup,
                                      def->disks[i]->src,
                                      (def->disks[i]->readonly ?
                                       VIR_CGROUP_DEVICE_READ :
                                       VIR_CGROUP_DEVICE_RW) |
                                      VIR_CGROUP_DEVICE_MKNOD);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %s for domain %s"),
                                 def->disks[i]->src, def->name);
            goto cleanup;
        }
    }

    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_BLOCK)
            continue;

        rc = virCgroupAllowDevicePath(cgroup,
                                      def->fss[i]->src,
                                      def->fss[i]->readonly ?
                                      VIR_CGROUP_DEVICE_READ :
                                      VIR_CGROUP_DEVICE_RW);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %s for domain %s"),
                                 def->fss[i]->src, def->name);
            goto cleanup;
        }
    }

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        virUSBDevicePtr usb;

        switch (hostdev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
                continue;
            if (hostdev->missing)
                continue;

            if ((usb = virUSBDeviceNew(hostdev->source.subsys.u.usb.bus,
                                       hostdev->source.subsys.u.usb.device,
                                       NULL)) == NULL)
                goto cleanup;

            if (virUSBDeviceFileIterate(usb, virLXCSetupHostUsbDeviceCgroup,
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
                                             VIR_CGROUP_DEVICE_MKNOD) < 0)
                    goto cleanup;
                break;
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
                if (virCgroupAllowDevicePath(cgroup,
                                             hostdev->source.caps.u.misc.chardev,
                                             VIR_CGROUP_DEVICE_RW |
                                             VIR_CGROUP_DEVICE_MKNOD) < 0)
                    goto cleanup;
                break;
            default:
                break;
            }
        default:
            break;
        }
    }

    rc = virCgroupAllowDeviceMajor(cgroup, 'c', LXC_DEV_MAJ_PTY,
                                   VIR_CGROUP_DEVICE_RWM);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to allow PTY devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    ret = 0;
cleanup:
    return ret;
}


virCgroupPtr virLXCCgroupCreate(virDomainDefPtr def, bool startup)
{
    int rc;
    virCgroupPtr parent = NULL;
    virCgroupPtr cgroup = NULL;

    if (!def->resource && startup) {
        virDomainResourceDefPtr res;

        if (VIR_ALLOC(res) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (VIR_STRDUP(res->partition, "/machine") < 0) {
            VIR_FREE(res);
            goto cleanup;
        }

        def->resource = res;
    }

    if (def->resource &&
        def->resource->partition) {
        if (def->resource->partition[0] != '/') {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Resource partition '%s' must start with '/'"),
                           def->resource->partition);
            goto cleanup;
        }
        /* We only auto-create the default partition. In other
         * cases we expec the sysadmin/app to have done so */
        rc = virCgroupNewPartition(def->resource->partition,
                                   STREQ(def->resource->partition, "/machine"),
                                   -1,
                                   &parent);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to initialize %s cgroup"),
                                 def->resource->partition);
            goto cleanup;
        }

        rc = virCgroupNewDomainPartition(parent,
                                         "lxc",
                                         def->name,
                                         true,
                                         &cgroup);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 def->name);
            goto cleanup;
        }
    } else {
        rc = virCgroupNewDriver("lxc",
                                true,
                                -1,
                                &parent);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 def->name);
            goto cleanup;
        }

        rc = virCgroupNewDomainDriver(parent,
                                      def->name,
                                      true,
                                      &cgroup);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to create cgroup for %s"),
                                 def->name);
            goto cleanup;
        }
    }

cleanup:
    virCgroupFree(&parent);
    return cgroup;
}


virCgroupPtr virLXCCgroupJoin(virDomainDefPtr def)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rc;

    if (!(cgroup = virLXCCgroupCreate(def, true)))
        return NULL;

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to add task %d to cgroup for domain %s"),
                             getpid(), def->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret < 0) {
        virCgroupFree(&cgroup);
        return NULL;
    }

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
