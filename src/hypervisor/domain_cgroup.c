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

#include "virutil.h"

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


int
virDomainCgroupSetMemoryLimitParameters(virCgroupPtr cgroup,
                                        virDomainObjPtr vm,
                                        virDomainDefPtr liveDef,
                                        virDomainDefPtr persistentDef,
                                        virTypedParameterPtr params,
                                        int nparams)
{
    unsigned long long swap_hard_limit;
    unsigned long long hard_limit = 0;
    unsigned long long soft_limit = 0;
    bool set_swap_hard_limit = false;
    bool set_hard_limit = false;
    bool set_soft_limit = false;
    int rc;

#define VIR_GET_LIMIT_PARAMETER(PARAM, VALUE) \
    if ((rc = virTypedParamsGetULLong(params, nparams, PARAM, &VALUE)) < 0) \
        return -1; \
 \
    if (rc == 1) \
        set_ ## VALUE = true;

    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_HARD_LIMIT, hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SOFT_LIMIT, soft_limit)

#undef VIR_GET_LIMIT_PARAMETER

    /* Swap hard limit must be greater than hard limit. */
    if (set_swap_hard_limit || set_hard_limit) {
        unsigned long long mem_limit = vm->def->mem.hard_limit;
        unsigned long long swap_limit = vm->def->mem.swap_hard_limit;

        if (set_swap_hard_limit)
            swap_limit = swap_hard_limit;

        if (set_hard_limit)
            mem_limit = hard_limit;

        if (mem_limit > swap_limit) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("memory hard_limit tunable value must be lower "
                             "than or equal to swap_hard_limit"));
            return -1;
        }
    }

#define VIR_SET_MEM_PARAMETER(FUNC, VALUE) \
    if (set_ ## VALUE) { \
        if (liveDef) { \
            if ((rc = FUNC(cgroup, VALUE)) < 0) \
                return -1; \
            liveDef->mem.VALUE = VALUE; \
        } \
 \
        if (persistentDef) \
            persistentDef->mem.VALUE = VALUE; \
    }

    /* Soft limit doesn't clash with the others */
    VIR_SET_MEM_PARAMETER(virCgroupSetMemorySoftLimit, soft_limit);

    /* set hard limit before swap hard limit if decreasing it */
    if (liveDef && liveDef->mem.hard_limit > hard_limit) {
        VIR_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);
        /* inhibit changing the limit a second time */
        set_hard_limit = false;
    }

    VIR_SET_MEM_PARAMETER(virCgroupSetMemSwapHardLimit, swap_hard_limit);

    /* otherwise increase it after swap hard limit */
    VIR_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);

#undef VIR_SET_MEM_PARAMETER

    return 0;
}
