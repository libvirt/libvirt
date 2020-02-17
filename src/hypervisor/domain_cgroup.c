/*
 * domain_cgroup.c: cgroup functions shared between hypervisor drivers
 *
 * Copyright IBM Corp. 2020
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

#include "domain_cgroup.h"
#include "domain_driver.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN


int
virDomainCgroupSetupBlkio(virCgroupPtr cgroup, virDomainBlkiotune blkio)
{
    size_t i;

    if (blkio.weight != 0 &&
        virCgroupSetBlkioWeight(cgroup, blkio.weight) < 0)
        return -1;

    if (blkio.ndevices) {
        for (i = 0; i < blkio.ndevices; i++) {
            virBlkioDevicePtr dev = &blkio.devices[i];

            if (dev->weight &&
                virCgroupSetupBlkioDeviceWeight(cgroup, dev->path,
                                                &dev->weight) < 0)
                return -1;

            if (dev->riops &&
                virCgroupSetupBlkioDeviceReadIops(cgroup, dev->path,
                                                  &dev->riops) < 0)
                return -1;

            if (dev->wiops &&
                virCgroupSetupBlkioDeviceWriteIops(cgroup, dev->path,
                                                   &dev->wiops) < 0)
                return -1;

            if (dev->rbps &&
                virCgroupSetupBlkioDeviceReadBps(cgroup, dev->path,
                                                 &dev->rbps) < 0)
                return -1;

            if (dev->wbps &&
                virCgroupSetupBlkioDeviceWriteBps(cgroup, dev->path,
                                                  &dev->wbps) < 0)
                return -1;
        }
    }

    return 0;
}


int
virDomainCgroupSetupMemtune(virCgroupPtr cgroup, virDomainMemtune mem)
{
    if (virMemoryLimitIsSet(mem.hard_limit))
        if (virCgroupSetMemoryHardLimit(cgroup, mem.hard_limit) < 0)
            return -1;

    if (virMemoryLimitIsSet(mem.soft_limit))
        if (virCgroupSetMemorySoftLimit(cgroup, mem.soft_limit) < 0)
            return -1;

    if (virMemoryLimitIsSet(mem.swap_hard_limit))
        if (virCgroupSetMemSwapHardLimit(cgroup, mem.swap_hard_limit) < 0)
            return -1;

    return 0;
}


int
virDomainCgroupSetupDomainBlkioParameters(virCgroupPtr cgroup,
                                          virDomainDefPtr def,
                                          virTypedParameterPtr params,
                                          int nparams)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
            if (virCgroupSetBlkioWeight(cgroup, params[i].value.ui) < 0)
                ret = -1;
        } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
            size_t ndevices;
            virBlkioDevicePtr devices = NULL;
            size_t j;

            if (virDomainDriverParseBlkioDeviceStr(params[i].value.s,
                                                   param->field,
                                                   &devices,
                                                   &ndevices) < 0) {
                ret = -1;
                continue;
            }

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetupBlkioDeviceWeight(cgroup, devices[j].path,
                                                        &devices[j].weight) < 0) {
                        ret = -1;
                        break;
                    }
                }
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetupBlkioDeviceReadIops(cgroup, devices[j].path,
                                                          &devices[j].riops) < 0) {
                        ret = -1;
                        break;
                    }
                }
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetupBlkioDeviceWriteIops(cgroup, devices[j].path,
                                                           &devices[j].wiops) < 0) {
                        ret = -1;
                        break;
                    }
                }
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetupBlkioDeviceReadBps(cgroup, devices[j].path,
                                                         &devices[j].rbps) < 0) {
                        ret = -1;
                        break;
                    }
                }
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                for (j = 0; j < ndevices; j++) {
                    if (virCgroupSetupBlkioDeviceWriteBps(cgroup, devices[j].path,
                                                          &devices[j].wbps) < 0) {
                        ret = -1;
                        break;
                    }
                }
            } else {
                virReportError(VIR_ERR_INVALID_ARG, _("Unknown blkio parameter %s"),
                               param->field);
                ret = -1;
                virBlkioDeviceArrayClear(devices, ndevices);
                g_free(devices);

                continue;
            }

            if (j != ndevices ||
                virDomainDriverMergeBlkioDevice(&def->blkio.devices,
                                                &def->blkio.ndevices,
                                                devices, ndevices,
                                                param->field) < 0)
                ret = -1;

            virBlkioDeviceArrayClear(devices, ndevices);
            g_free(devices);
        }
    }

    return ret;
}
