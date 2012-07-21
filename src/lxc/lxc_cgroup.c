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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "lxc_cgroup.h"
#include "lxc_container.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "cgroup.h"

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


typedef struct _virLXCCgroupDevicePolicy virLXCCgroupDevicePolicy;
typedef virLXCCgroupDevicePolicy *virLXCCgroupDevicePolicyPtr;

struct _virLXCCgroupDevicePolicy {
    char type;
    int major;
    int minor;
};



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

    for (i = 0 ; i < def->nfss ; i++) {
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


int virLXCCgroupSetup(virDomainDefPtr def)
{
    virCgroupPtr driver = NULL;
    virCgroupPtr cgroup = NULL;
    int rc = -1;

    rc = virCgroupForDriver("lxc", &driver, 1, 0);
    if (rc != 0) {
        /* Skip all if no driver cgroup is configured */
        if (rc == -ENXIO || rc == -ENOENT)
            return 0;

        virReportSystemError(-rc, "%s",
                             _("Unable to get cgroup for driver"));
        return rc;
    }

    rc = virCgroupForDomain(driver, def->name, &cgroup, 1);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to create cgroup for domain %s"),
                             def->name);
        goto cleanup;
    }

    if (virLXCCgroupSetupCpuTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupBlkioTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupMemTune(def, cgroup) < 0)
        goto cleanup;

    if (virLXCCgroupSetupDeviceACL(def, cgroup) < 0)
        goto cleanup;

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to add task %d to cgroup for domain %s"),
                             getpid(), def->name);
    }

cleanup:
    virCgroupFree(&cgroup);
    virCgroupFree(&driver);

    return rc;
}
