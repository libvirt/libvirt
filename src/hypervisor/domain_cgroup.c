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
#include "util/virnuma.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN
VIR_LOG_INIT("domain.cgroup");

int
virDomainCgroupSetupBlkio(virCgroup *cgroup, virDomainBlkiotune blkio)
{
    size_t i;

    if (blkio.weight != 0 &&
        virCgroupSetBlkioWeight(cgroup, blkio.weight) < 0)
        return -1;

    if (blkio.ndevices) {
        for (i = 0; i < blkio.ndevices; i++) {
            virBlkioDevice *dev = &blkio.devices[i];

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
virDomainCgroupSetupMemtune(virCgroup *cgroup, virDomainMemtune mem)
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
virDomainCgroupSetupDomainBlkioParameters(virCgroup *cgroup,
                                          virDomainDef *def,
                                          virTypedParameterPtr params,
                                          int nparams)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
            if (virCgroupSetBlkioWeight(cgroup, params[i].value.ui) < 0 ||
                virCgroupGetBlkioWeight(cgroup, &def->blkio.weight) < 0)
                ret = -1;
        } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                   STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
            size_t ndevices;
            virBlkioDevice *devices = NULL;
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
                virReportError(VIR_ERR_INVALID_ARG, _("Unknown blkio parameter %1$s"),
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
virDomainCgroupSetMemoryLimitParameters(virCgroup *cgroup,
                                        virDomainObj *vm,
                                        virDomainDef *liveDef,
                                        virDomainDef *persistentDef,
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
        set_ ## VALUE = true

    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit);
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_HARD_LIMIT, hard_limit);
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SOFT_LIMIT, soft_limit);

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
                           _("memory hard_limit tunable value must be lower than or equal to swap_hard_limit"));
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


int
virDomainCgroupSetupBlkioCgroup(virDomainObj *vm,
                                virCgroup *cgroup)
{
    if (!virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
        if (vm->def->blkio.weight || vm->def->blkio.ndevices) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available on this host"));
            return -1;
        }
        return 0;
    }

    return virDomainCgroupSetupBlkio(cgroup, vm->def->blkio);
}


int
virDomainCgroupSetupMemoryCgroup(virDomainObj *vm,
                                 virCgroup *cgroup)
{
    if (!virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
        if (virMemoryLimitIsSet(vm->def->mem.hard_limit) ||
            virMemoryLimitIsSet(vm->def->mem.soft_limit) ||
            virMemoryLimitIsSet(vm->def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory cgroup is not available on this host"));
            return -1;
        }
        return 0;
    }

    return virDomainCgroupSetupMemtune(cgroup, vm->def->mem);
}


int
virDomainCgroupSetupCpusetCgroup(virCgroup *cgroup)
{
    if (!virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (virCgroupSetCpusetMemoryMigrate(cgroup, true) < 0)
        return -1;

    return 0;
}


int
virDomainCgroupSetupCpuCgroup(virDomainObj *vm,
                              virCgroup *cgroup)
{
    if (!virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        if (vm->def->cputune.sharesSpecified) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU tuning is not available on this host"));
            return -1;
        }
        return 0;
    }

    if (vm->def->cputune.sharesSpecified) {
        if (virCgroupSetCpuShares(cgroup, vm->def->cputune.shares) < 0)
            return -1;
    }

    return 0;
}


int
virDomainCgroupInitCgroup(const char *prefix,
                          virDomainObj *vm,
                          size_t nnicindexes,
                          int *nicindexes,
                          virCgroup **cgroup,
                          int cgroupControllers,
                          unsigned int maxThreadsPerProc,
                          bool privileged,
                          char *machineName)
{
    if (!privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    g_clear_pointer(cgroup, virCgroupFree);

    if (!vm->def->resource)
        vm->def->resource = g_new0(virDomainResourceDef, 1);

    if (!vm->def->resource->partition)
        vm->def->resource->partition = g_strdup("/machine");

    if (!g_path_is_absolute(vm->def->resource->partition)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Resource partition '%1$s' must start with '/'"),
                       vm->def->resource->partition);
        return -1;
    }

    if (virCgroupNewMachine(machineName,
                            prefix,
                            vm->def->uuid,
                            NULL,
                            vm->pid,
                            false,
                            nnicindexes, nicindexes,
                            vm->def->resource->partition,
                            cgroupControllers,
                            maxThreadsPerProc,
                            cgroup) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;

        return -1;
    }

    return 0;
}


void
virDomainCgroupRestoreCgroupState(virDomainObj *vm,
                                  virCgroup *cgroup)
{
    g_autofree char *mem_mask = NULL;
    size_t i = 0;
    g_autoptr(virBitmap) all_nodes = NULL;

    if (!virNumaIsAvailable() ||
        !virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return;

    if (!(all_nodes = virNumaGetHostMemoryNodeset()))
        goto error;

    if (!(mem_mask = virBitmapFormat(all_nodes)))
        goto error;

    if (virCgroupHasEmptyTasks(cgroup, VIR_CGROUP_CONTROLLER_CPUSET) <= 0)
        goto error;

    if (virCgroupSetCpusetMems(cgroup, mem_mask) < 0)
        goto error;

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (virDomainCgroupRestoreCgroupThread(cgroup,
                                               VIR_CGROUP_THREAD_VCPU,
                                               i) < 0)
            return;
    }

    for (i = 0; i < vm->def->niothreadids; i++) {
        if (virDomainCgroupRestoreCgroupThread(cgroup,
                                               VIR_CGROUP_THREAD_IOTHREAD,
                                               vm->def->iothreadids[i]->iothread_id) < 0)
            return;
    }

    if (virDomainCgroupRestoreCgroupThread(cgroup,
                                           VIR_CGROUP_THREAD_EMULATOR,
                                           0) < 0)
        return;

    return;

 error:
    virResetLastError();
    VIR_DEBUG("Couldn't restore cgroups to meaningful state");
    return;
}


int
virDomainCgroupRestoreCgroupThread(virCgroup *cgroup,
                                   virCgroupThreadName thread,
                                   int id)
{
    g_autoptr(virCgroup) cgroup_temp = NULL;
    g_autofree char *nodeset = NULL;

    if (virCgroupNewThread(cgroup, thread, id, false, &cgroup_temp) < 0)
        return -1;

    if (virCgroupSetCpusetMemoryMigrate(cgroup_temp, true) < 0)
        return -1;

    if (virCgroupGetCpusetMems(cgroup_temp, &nodeset) < 0)
        return -1;

    if (virCgroupSetCpusetMems(cgroup_temp, nodeset) < 0)
        return -1;

    return 0;
}


int
virDomainCgroupConnectCgroup(const char *prefix,
                             virDomainObj *vm,
                             virCgroup **cgroup,
                             int cgroupControllers,
                             bool privileged,
                             char *machineName)
{
    if (!privileged)
        return 0;

    if (!virCgroupAvailable())
        return 0;

    g_clear_pointer(cgroup, virCgroupFree);

    if (virCgroupNewDetectMachine(vm->def->name,
                                  prefix,
                                  vm->pid,
                                  cgroupControllers,
                                  machineName,
                                  cgroup) < 0)
        return -1;

    virDomainCgroupRestoreCgroupState(vm, *cgroup);
    return 0;
}


int
virDomainCgroupSetupCgroup(const char *prefix,
                           virDomainObj *vm,
                           size_t nnicindexes,
                           int *nicindexes,
                           virCgroup **cgroup,
                           int cgroupControllers,
                           unsigned int maxThreadsPerProc,
                           bool privileged,
                           char *machineName)
{
    if (vm->pid == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup cgroups until process is started"));
        return -1;
    }

    if (virDomainCgroupInitCgroup(prefix,
                                  vm,
                                  nnicindexes,
                                  nicindexes,
                                  cgroup,
                                  cgroupControllers,
                                  maxThreadsPerProc,
                                  privileged,
                                  machineName) < 0)
        return -1;

    if (!*cgroup)
        return 0;

    if (virDomainCgroupSetupBlkioCgroup(vm, *cgroup) < 0)
        return -1;

    if (virDomainCgroupSetupMemoryCgroup(vm, *cgroup) < 0)
        return -1;

    if (virDomainCgroupSetupCpuCgroup(vm, *cgroup) < 0)
        return -1;

    if (virDomainCgroupSetupCpusetCgroup(*cgroup) < 0)
        return -1;

    return 0;
}


int
virDomainCgroupSetupVcpuBW(virCgroup *cgroup,
                           unsigned long long period,
                           long long quota)
{
    return virCgroupSetupCpuPeriodQuota(cgroup, period, quota);
}


int
virDomainCgroupSetupCpusetCpus(virCgroup *cgroup,
                               virBitmap *cpumask)
{
    return virCgroupSetupCpusetCpus(cgroup, cpumask);
}


int
virDomainCgroupSetupGlobalCpuCgroup(virDomainObj *vm,
                                    virCgroup *cgroup)
{
    unsigned long long period = vm->def->cputune.global_period;
    long long quota = vm->def->cputune.global_quota;

    if ((period || quota) &&
        !virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    if (virDomainCgroupSetupVcpuBW(cgroup, period, quota) < 0)
        return -1;

    return 0;
}


int
virDomainCgroupRemoveCgroup(virDomainObj *vm,
                            virCgroup *cgroup,
                            char *machineName)
{
    if (cgroup == NULL)
        return 0;               /* Not supported, so claim success */

    if (virCgroupTerminateMachine(machineName) < 0) {
        if (!virCgroupNewIgnoreError())
            VIR_DEBUG("Failed to terminate cgroup for %s", vm->def->name);
    }

    return virCgroupRemove(cgroup);
}


void
virDomainCgroupEmulatorAllNodesDataFree(virCgroupEmulatorAllNodesData *data)
{
    if (!data)
        return;

    virCgroupFree(data->emulatorCgroup);
    g_free(data->emulatorMemMask);
    g_free(data);
}


/**
 * virDomainCgroupEmulatorAllNodesAllow:
 * @cgroup: domain cgroup pointer
 * @retData: filled with structure used to roll back the operation
 *
 * Allows all NUMA nodes for the cloud hypervisor thread temporarily. This is
 * necessary when hotplugging cpus since it requires memory allocated in the
 * DMA region. Afterwards the operation can be reverted by
 * virDomainCgroupEmulatorAllNodesRestore.
 *
 * Returns 0 on success -1 on error
 */
int
virDomainCgroupEmulatorAllNodesAllow(virCgroup *cgroup,
                                     virCgroupEmulatorAllNodesData **retData)
{
    virCgroupEmulatorAllNodesData *data = NULL;
    g_autofree char *all_nodes_str = NULL;

    g_autoptr(virBitmap) all_nodes = NULL;
    int ret = -1;

    if (!virNumaIsAvailable() ||
        !virCgroupHasController(cgroup, VIR_CGROUP_CONTROLLER_CPUSET))
        return 0;

    if (!(all_nodes = virNumaGetHostMemoryNodeset()))
        goto cleanup;

    if (!(all_nodes_str = virBitmapFormat(all_nodes)))
        goto cleanup;

    data = g_new0(virCgroupEmulatorAllNodesData, 1);

    if (virCgroupNewThread(cgroup, VIR_CGROUP_THREAD_EMULATOR, 0,
                           false, &data->emulatorCgroup) < 0)
        goto cleanup;

    if (virCgroupGetCpusetMems(data->emulatorCgroup, &data->emulatorMemMask) < 0
        || virCgroupSetCpusetMems(data->emulatorCgroup, all_nodes_str) < 0)
        goto cleanup;

    *retData = g_steal_pointer(&data);
    ret = 0;

 cleanup:
    virDomainCgroupEmulatorAllNodesDataFree(data);

    return ret;
}


/**
 * virDomainCgroupEmulatorAllNodesRestore:
 * @data: data structure created by virDomainCgroupEmulatorAllNodesAllow
 *
 * Rolls back the setting done by virDomainCgroupEmulatorAllNodesAllow and frees the
 * associated data.
 */
void
virDomainCgroupEmulatorAllNodesRestore(virCgroupEmulatorAllNodesData *data)
{
    virError *err;

    if (!data)
        return;

    virErrorPreserveLast(&err);
    virCgroupSetCpusetMems(data->emulatorCgroup, data->emulatorMemMask);
    virErrorRestore(&err);

    virDomainCgroupEmulatorAllNodesDataFree(data);
}
