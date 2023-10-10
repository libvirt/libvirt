/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_process.c: Process controller for Cloud-Hypervisor driver
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

#include <unistd.h>
#include <fcntl.h>

#include "ch_domain.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "domain_cgroup.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_process");

#define START_SOCKET_POSTFIX ": starting up socket\n"
#define START_VM_POSTFIX ": starting up vm\n"


static virCHMonitor *
virCHProcessConnectMonitor(virCHDriver *driver,
                           virDomainObj *vm)
{
    virCHMonitor *monitor = NULL;
    virCHDriverConfig *cfg = virCHDriverGetConfig(driver);

    monitor = virCHMonitorNew(vm, cfg->stateDir);

    virObjectUnref(cfg);
    return monitor;
}

static void
virCHProcessUpdateConsoleDevice(virDomainObj *vm,
                                virJSONValue *config,
                                const char *device)
{
    const char *path;
    virDomainChrDef *chr = NULL;
    virJSONValue *dev, *file;

    if (!config)
        return;

    dev = virJSONValueObjectGet(config, device);
    if (!dev) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing '%1$s' in 'config' from cloud-hypervisor"),
                       device);
        return;
    }

    file = virJSONValueObjectGet(dev, "file");
    if (!file) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'file' in '%1$s' from cloud-hypervisor"),
                       device);
        return;
    }

    path = virJSONValueGetString(file);
    if (!path) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse contents of 'file' field in '%1$s' from cloud-hypervisor"),
                       device);
        return;
    }

    if (STREQ(device, "console")) {
        chr = vm->def->consoles[0];
    } else if (STREQ(device, "serial")) {
        chr = vm->def->serials[0];
    }

    if (chr && chr->source)
        chr->source->data.file.path = g_strdup(path);
}

static void
virCHProcessUpdateConsole(virDomainObj *vm,
                          virJSONValue *info)
{
    virJSONValue *config;

    config = virJSONValueObjectGet(info, "config");
    if (!config) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing 'config' in info query result from cloud-hypervisor"));
        return;
    }

    if (vm->def->nconsoles > 0)
        virCHProcessUpdateConsoleDevice(vm, config, "console");
    if (vm->def->nserials > 0)
        virCHProcessUpdateConsoleDevice(vm, config, "serial");
}

static int
virCHProcessUpdateInfo(virDomainObj *vm)
{
    g_autoptr(virJSONValue) info = NULL;
    virCHDomainObjPrivate *priv = vm->privateData;
    if (virCHMonitorGetInfo(priv->monitor, &info) < 0)
        return -1;

    virCHProcessUpdateConsole(vm, info);

    return 0;
}

static int
virCHProcessGetAllCpuAffinity(virBitmap **cpumapRet)
{
    *cpumapRet = NULL;

    if (!virHostCPUHasBitmap())
        return 0;

    if (!(*cpumapRet = virHostCPUGetOnlineBitmap()))
        return -1;

    return 0;
}

#if defined(WITH_SCHED_GETAFFINITY) || defined(WITH_BSD_CPU_AFFINITY)
static int
virCHProcessInitCpuAffinity(virDomainObj *vm)
{
    g_autoptr(virBitmap) cpumapToSet = NULL;
    virDomainNumatuneMemMode mem_mode;
    virCHDomainObjPrivate *priv = vm->privateData;

    if (!vm->pid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot setup CPU affinity until process is started"));
        return -1;
    }

    if (virDomainNumaGetNodeCount(vm->def->numa) <= 1 &&
        virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
        mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        virBitmap *nodeset = NULL;

        if (virDomainNumatuneMaybeGetNodeset(vm->def->numa,
                                             priv->autoNodeset,
                                             &nodeset, -1) < 0)
            return -1;

        if (virNumaNodesetToCPUset(nodeset, &cpumapToSet) < 0)
            return -1;
    } else if (vm->def->cputune.emulatorpin) {
        if (!(cpumapToSet = virBitmapNewCopy(vm->def->cputune.emulatorpin)))
            return -1;
    } else {
        if (virCHProcessGetAllCpuAffinity(&cpumapToSet) < 0)
            return -1;
    }

    if (cpumapToSet && virProcessSetAffinity(vm->pid, cpumapToSet, false) < 0) {
        return -1;
    }

    return 0;
}
#else /* !defined(WITH_SCHED_GETAFFINITY) && !defined(WITH_BSD_CPU_AFFINITY) */
static int
virCHProcessInitCpuAffinity(virDomainObj *vm G_GNUC_UNUSED)
{
    return 0;
}
#endif /* !defined(WITH_SCHED_GETAFFINITY) && !defined(WITH_BSD_CPU_AFFINITY) */

/**
 * virCHProcessSetupPid:
 *
 * This function sets resource properties (affinity, cgroups,
 * scheduler) for any PID associated with a domain.  It should be used
 * to set up emulator PIDs as well as vCPU and I/O thread pids to
 * ensure they are all handled the same way.
 *
 * Returns 0 on success, -1 on error.
 */
static int
virCHProcessSetupPid(virDomainObj *vm,
                     pid_t pid,
                     virCgroupThreadName nameval,
                     int id,
                     virBitmap *cpumask,
                     unsigned long long period,
                     long long quota,
                     virDomainThreadSchedParam *sched)
{
    virCHDomainObjPrivate *priv = vm->privateData;
    virDomainNumatuneMemMode mem_mode;
    g_autoptr(virCgroup) cgroup = NULL;
    virBitmap *use_cpumask = NULL;
    virBitmap *affinity_cpumask = NULL;
    g_autoptr(virBitmap) hostcpumap = NULL;
    g_autofree char *mem_mask = NULL;
    int ret = -1;

    if ((period || quota) &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        goto cleanup;
    }

    /* Infer which cpumask shall be used. */
    if (cpumask) {
        use_cpumask = cpumask;
    } else if (vm->def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        use_cpumask = priv->autoCpuset;
    } else if (vm->def->cpumask) {
        use_cpumask = vm->def->cpumask;
    } else {
        /* we can't assume cloud-hypervisor itself is running on all pCPUs,
         * so we need to explicitly set the spawned instance to all pCPUs. */
        if (virCHProcessGetAllCpuAffinity(&hostcpumap) < 0)
            goto cleanup;
        affinity_cpumask = hostcpumap;
    }

    /*
     * If CPU cgroup controller is not initialized here, then we need
     * neither period nor quota settings.  And if CPUSET controller is
     * not initialized either, then there's nothing to do anyway.
     */
    if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU) ||
        virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {

        if (virDomainNumatuneGetMode(vm->def->numa, -1, &mem_mode) == 0 &&
            (mem_mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT ||
             mem_mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) &&
            virDomainNumatuneMaybeFormatNodeset(vm->def->numa,
                                                priv->autoNodeset,
                                                &mem_mask, -1) < 0)
            goto cleanup;

        if (virCgroupNewThread(priv->cgroup, nameval, id, true, &cgroup) < 0)
            goto cleanup;

        /* Move the thread to the sub dir before changing the settings so that
         * all take effect even with cgroupv2. */
        VIR_INFO("Adding pid %d to cgroup", pid);
        if (virCgroupAddThread(cgroup, pid) < 0)
            goto cleanup;

        if (virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUSET)) {
            if (use_cpumask &&
                virDomainCgroupSetupCpusetCpus(cgroup, use_cpumask) < 0)
                goto cleanup;

            if (mem_mask && virCgroupSetCpusetMems(cgroup, mem_mask) < 0)
                goto cleanup;

        }

        if (virDomainCgroupSetupVcpuBW(cgroup, period, quota) < 0)
            goto cleanup;
    }

    if (!affinity_cpumask)
        affinity_cpumask = use_cpumask;

    /* Setup legacy affinity. */
    if (affinity_cpumask
        && virProcessSetAffinity(pid, affinity_cpumask, false) < 0)
        goto cleanup;

    /* Set scheduler type and priority, but not for the main thread. */
    if (sched &&
        nameval != VIR_CGROUP_THREAD_EMULATOR &&
        virProcessSetScheduler(pid, sched->policy, sched->priority) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0 && cgroup)
        virCgroupRemove(cgroup);

    return ret;
}

static int
virCHProcessSetupIOThread(virDomainObj *vm,
                          virDomainIOThreadInfo *iothread)
{
    virCHDomainObjPrivate *priv = vm->privateData;

    return virCHProcessSetupPid(vm, iothread->iothread_id,
                                VIR_CGROUP_THREAD_IOTHREAD,
                                iothread->iothread_id,
                                priv->autoCpuset, /* This should be updated when CLH supports accepting
                                                     iothread settings from input domain definition */
                                vm->def->cputune.iothread_period,
                                vm->def->cputune.iothread_quota,
                                NULL); /* CLH doesn't allow choosing a scheduler for iothreads.*/
}

static int
virCHProcessSetupIOThreads(virDomainObj *vm)
{
    virCHDomainObjPrivate *priv = vm->privateData;
    virDomainIOThreadInfo **iothreads = NULL;
    size_t i;
    int niothreads;

    if ((niothreads = virCHMonitorGetIOThreads(priv->monitor, &iothreads)) < 0)
        return -1;

    for (i = 0; i < niothreads; i++) {
        VIR_DEBUG("IOThread index = %zu , tid = %d", i, iothreads[i]->iothread_id);
        if (virCHProcessSetupIOThread(vm, iothreads[i]) < 0)
            return -1;
    }
    return 0;
}

static int
virCHProcessSetupEmulatorThread(virDomainObj *vm,
                         virCHMonitorEmuThreadInfo emuthread)
{
    return virCHProcessSetupPid(vm, emuthread.tid,
                               VIR_CGROUP_THREAD_EMULATOR, 0,
                               vm->def->cputune.emulatorpin,
                               vm->def->cputune.emulator_period,
                               vm->def->cputune.emulator_quota,
                               vm->def->cputune.emulatorsched);
}

static int
virCHProcessSetupEmulatorThreads(virDomainObj *vm)
{
    int thd_index = 0;
    virCHDomainObjPrivate *priv = vm->privateData;

    /* Cloud-hypervisor start 4 Emulator threads by default:
     * vmm
     * cloud-hypervisor
     * http-server
     * signal_handler */
    for (thd_index = 0; thd_index < priv->monitor->nthreads; thd_index++) {
        if (priv->monitor->threads[thd_index].type == virCHThreadTypeEmulator) {
            VIR_DEBUG("Setup tid = %d (%s) Emulator thread",
                      priv->monitor->threads[thd_index].emuInfo.tid,
                      priv->monitor->threads[thd_index].emuInfo.thrName);

            if (virCHProcessSetupEmulatorThread(vm,
                                                priv->monitor->threads[thd_index].emuInfo) < 0)
                return -1;
        }
    }
    return 0;
}

/**
 * virCHProcessSetupVcpu:
 * @vm: domain object
 * @vcpuid: id of VCPU to set defaults
 *
 * This function sets resource properties (cgroups, affinity, scheduler) for a
 * vCPU. This function expects that the vCPU is online and the vCPU pids were
 * correctly detected at the point when it's called.
 *
 * Returns 0 on success, -1 on error.
 */
int
virCHProcessSetupVcpu(virDomainObj *vm,
                      unsigned int vcpuid)
{
    pid_t vcpupid = virCHDomainGetVcpuPid(vm, vcpuid);
    virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, vcpuid);

    return virCHProcessSetupPid(vm, vcpupid, VIR_CGROUP_THREAD_VCPU,
                                vcpuid, vcpu->cpumask,
                                vm->def->cputune.period,
                                vm->def->cputune.quota, &vcpu->sched);
}

static int
virCHProcessSetupVcpus(virDomainObj *vm)
{
    virDomainVcpuDef *vcpu;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    size_t i;

    if ((vm->def->cputune.period || vm->def->cputune.quota) &&
        !virCgroupHasController(((virCHDomainObjPrivate *) vm->privateData)->
                                cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cgroup cpu is required for scheduler tuning"));
        return -1;
    }

    if (!virCHDomainHasVcpuPids(vm)) {
        /* If any CPU has custom affinity that differs from the
         * VM default affinity, we must reject it */
        for (i = 0; i < maxvcpus; i++) {
            vcpu = virDomainDefGetVcpu(vm->def, i);

            if (!vcpu->online)
                continue;

            if (vcpu->cpumask &&
                !virBitmapEqual(vm->def->cpumask, vcpu->cpumask)) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("cpu affinity is not supported"));
                return -1;
            }
        }

        return 0;
    }

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);

        if (!vcpu->online)
            continue;

        if (virCHProcessSetupVcpu(vm, i) < 0)
            return -1;
    }

    return 0;
}

/**
 * virCHProcessStart:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @reason: reason for switching vm to running state
 *
 * Starts Cloud-Hypervisor listen on a local socket
 *
 * Returns 0 on success or -1 in case of error
 */
int
virCHProcessStart(virCHDriver *driver,
                  virDomainObj *vm,
                  virDomainRunningReason reason)
{
    int ret = -1;
    virCHDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(priv->driver);
    g_autofree int *nicindexes = NULL;
    size_t nnicindexes = 0;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("VM is already active"));
        return -1;
    }

    if (!priv->monitor) {
        /* And we can get the first monitor connection now too */
        if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create connection to CH socket"));
            goto cleanup;
        }

        if (virCHMonitorCreateVM(driver, priv->monitor,
                                 &nnicindexes, &nicindexes) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create guest VM"));
            goto cleanup;
        }
    }

    vm->pid = priv->monitor->pid;
    vm->def->id = vm->pid;
    priv->machineName = virCHDomainGetMachineName(vm);

    if (virDomainCgroupSetupCgroup("ch", vm,
                                   nnicindexes, nicindexes,
                                   &priv->cgroup,
                                   cfg->cgroupControllers,
                                   0, /*maxThreadsPerProc*/
                                   priv->driver->privileged,
                                   priv->machineName) < 0)
        goto cleanup;

    if (virCHProcessInitCpuAffinity(vm) < 0)
        goto cleanup;

    if (virCHMonitorBootVM(priv->monitor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to boot guest VM"));
        goto cleanup;
    }

    virCHDomainRefreshThreadInfo(vm);

    VIR_DEBUG("Setting emulator tuning/settings");
    if (virCHProcessSetupEmulatorThreads(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting iothread tuning/settings");
    if (virCHProcessSetupIOThreads(vm) < 0)
        goto cleanup;

    VIR_DEBUG("Setting global CPU cgroup (if required)");
    if (virDomainCgroupSetupGlobalCpuCgroup(vm,
                                            priv->cgroup) < 0)
        goto cleanup;

    VIR_DEBUG("Setting vCPU tuning/settings");
    if (virCHProcessSetupVcpus(vm) < 0)
        goto cleanup;

    virCHProcessUpdateInfo(vm);
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    return 0;

 cleanup:
    if (ret)
        virCHProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);

    return ret;
}

int
virCHProcessStop(virCHDriver *driver G_GNUC_UNUSED,
                 virDomainObj *vm,
                 virDomainShutoffReason reason)
{
    int ret;
    int retries = 0;
    virCHDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);

    if (priv->monitor) {
        g_clear_pointer(&priv->monitor, virCHMonitorClose);
    }

 retry:
    if ((ret = virDomainCgroupRemoveCgroup(vm,
                                           priv->cgroup,
                                           priv->machineName)) < 0) {
        if (ret == -EBUSY && (retries++ < 5)) {
            g_usleep(200*1000);
            goto retry;
        }
        VIR_WARN("Failed to remove cgroup for %s",
                 vm->def->name);
    }

    vm->pid = 0;
    vm->def->id = -1;
    g_clear_pointer(&priv->machineName, g_free);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}
