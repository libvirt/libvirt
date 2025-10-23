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
#include <poll.h>

#include "ch_alias.h"
#include "ch_domain.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "domain_cgroup.h"
#include "domain_interface.h"
#include "domain_logcontext.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virjson.h"
#include "virlog.h"
#include "virnuma.h"
#include "virpidfile.h"
#include "virstring.h"
#include "ch_interface.h"
#include "ch_hostdev.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_process");

#define START_SOCKET_POSTFIX ": starting up socket\n"
#define START_VM_POSTFIX ": starting up vm\n"


static virCHMonitor *
virCHProcessConnectMonitor(virCHDriver *driver,
                           virDomainObj *vm,
                           int logfile)
{
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(driver);

    return virCHMonitorNew(vm, cfg, logfile);
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

    /* This method is used to extract pty info from cloud-hypervisor and capture
     * it in domain configuration. This step can be skipped for serial devices
     * with unix backend.*/
    if (STREQ(device, "serial") &&
        vm->def->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX)
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

int
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
    int ret = -1;

    if ((niothreads = virCHMonitorGetIOThreads(priv->monitor, &iothreads)) < 0)
        return -1;

    for (i = 0; i < niothreads; i++) {
        VIR_DEBUG("IOThread index = %zu , tid = %d", i, iothreads[i]->iothread_id);
        if (virCHProcessSetupIOThread(vm, iothreads[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < niothreads; i++) {
        virDomainIOThreadInfoFree(iothreads[i]);
    }
    g_free(iothreads);
    return ret;
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
static int
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
        !virCgroupHasController(CH_DOMAIN_PRIVATE(vm)->cgroup,
                                VIR_CGROUP_CONTROLLER_CPU)) {
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

static int
virCHProcessSetup(virDomainObj *vm)
{
    virCHDomainObjPrivate *priv = vm->privateData;

    virCHDomainRefreshThreadInfo(vm);

    VIR_DEBUG("Setting emulator tuning/settings");
    if (virCHProcessSetupEmulatorThreads(vm) < 0)
        return -1;

    VIR_DEBUG("Setting iothread tuning/settings");
    if (virCHProcessSetupIOThreads(vm) < 0)
        return -1;

    VIR_DEBUG("Setting global CPU cgroup (if required)");
    if (virDomainCgroupSetupGlobalCpuCgroup(vm,
                                            priv->cgroup) < 0)
        return -1;

    VIR_DEBUG("Setting vCPU tuning/settings");
    if (virCHProcessSetupVcpus(vm) < 0)
        return -1;

    virCHProcessUpdateInfo(vm);
    return 0;
}


/**
 * chMonitorSocketConnect:
 * @mon: pointer to monitor object
 *
 * Connects to the monitor socket. Caller is responsible for closing the socketfd
 *
 * Returns socket fd on success, -1 on error
 */
static int
chMonitorSocketConnect(virCHMonitor *mon)
{
    struct sockaddr_un server_addr = { };
    int sock;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        virReportSystemError(errno, "%s", _("Failed to open a UNIX socket"));
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(server_addr.sun_path, mon->socketpath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("UNIX socket path '%1$s' too long"),
                       mon->socketpath);
        goto error;
    }

    if (connect(sock, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) == -1) {
        virReportSystemError(errno, "%s", _("Failed to connect to mon socket"));
        goto error;
    }

    return sock;
 error:
    VIR_FORCE_CLOSE(sock);
    return -1;
}


#define PKT_TIMEOUT_MS 500 /* ms */

static char *
chSocketRecv(int sock, bool use_timeout)
{
    struct pollfd pfds[1];
    char *buf = NULL;
    size_t buf_len = 1024;
    int timeout = PKT_TIMEOUT_MS;
    int ret;

    buf = g_new0(char, buf_len);

    pfds[0].fd = sock;
    pfds[0].events = POLLIN;

    if (!use_timeout)
        timeout = -1;

    do {
        ret = poll(pfds, G_N_ELEMENTS(pfds), timeout);
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        if (ret < 0) {
            virReportSystemError(errno, _("Poll on sock %1$d failed"), sock);
        } else if (ret == 0) {
            virReportSystemError(errno, _("Poll on sock %1$d timed out"), sock);
        }
        return NULL;
    }

    do {
        ret = recv(sock, buf, buf_len - 1, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        virReportSystemError(errno, _("recv on sock %1$d failed"), sock);
        return NULL;
    }

    return g_steal_pointer(&buf);
}

#undef PKT_TIMEOUT_MS

static int
chSocketProcessHttpResponse(int sock, bool use_poll_timeout)
{
    g_autofree char *response = NULL;
    int http_res;

    response = chSocketRecv(sock, use_poll_timeout);
    if (response == NULL) {
        return -1;
    }

    /* Parse the HTTP response code */
    if (sscanf(response, "HTTP/1.%*d %d", &http_res) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to parse HTTP response code"));
        return -1;
    }
    if (http_res != 204 && http_res != 200) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Unexpected response from CH: %1$s"), response);
        return -1;
    }

    return 0;
}

static int
chCloseFDs(int *fds, size_t nfds)
{
    size_t i;
    for (i = 0; i < nfds; i++) {
        VIR_FORCE_CLOSE(fds[i]);
    }
    return 0;
}

int
chProcessAddNetworkDevice(virCHDriver *driver,
                          virCHMonitor *mon,
                          virDomainDef *vmdef,
                          virDomainNetDef *net,
                          int **nicindexes,
                          size_t *nnicindexes)
{
    VIR_AUTOCLOSE mon_sockfd = -1;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) http_headers = VIR_BUFFER_INITIALIZER;
    g_autofree int *tapfds = NULL;
    g_autofree char *payload = NULL;
    g_autofree char *response = NULL;
    size_t tapfd_len;
    size_t payload_len;
    int saved_errno;
    int rc;

    if (!virBitmapIsBitSet(driver->chCaps, CH_MULTIFD_IN_ADDNET)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Guest networking is not supported by this version of ch"));
        return -1;
    }

    if ((mon_sockfd = chMonitorSocketConnect(mon)) < 0) {
        VIR_WARN("chProcessAddNetworkDevices failed");
        return -1;
    }

    virBufferAddLit(&http_headers, "PUT /api/v1/vm.add-net HTTP/1.1\r\n");
    virBufferAddLit(&http_headers, "Host: localhost\r\n");
    virBufferAddLit(&http_headers, "Content-Type: application/json\r\n");


    if (net->driver.virtio.queues == 0) {
        /* "queues" here refers to queue pairs. When 0, initialize
            * queue pairs to 1.
            */
        net->driver.virtio.queues = 1;
    }
    tapfd_len = net->driver.virtio.queues;

    if (virCHDomainValidateActualNetDef(net) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("net definition failed validation"));
        return -1;
    }

    tapfds = g_new0(int, tapfd_len);
    memset(tapfds, -1, (tapfd_len) * sizeof(int));

    /* Connect Guest interfaces */
    if (virCHConnetNetworkInterfaces(driver, vmdef, net, tapfds,
                                     nicindexes, nnicindexes) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to connect network interfaces"));
        return -1;
    }

    chAssignDeviceNetAlias(vmdef, net);
    if (virCHMonitorBuildNetJson(net, &payload) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to build net json"));
        return -1;
    }

    virBufferAsprintf(&buf, "%s", virBufferCurrentContent(&http_headers));
    virBufferAsprintf(&buf, "Content-Length: %zu\r\n\r\n", strlen(payload));
    virBufferAsprintf(&buf, "%s", payload);
    payload_len = virBufferUse(&buf);
    payload = virBufferContentAndReset(&buf);

    rc = virSocketSendMsgWithFDs(mon_sockfd, payload, payload_len,
                                 tapfds, tapfd_len);
    saved_errno = errno;

    /* Close sent tap fds in Libvirt, as they have been dup()ed in CH */
    chCloseFDs(tapfds, tapfd_len);

    if (rc < 0) {
        virReportSystemError(saved_errno, "%s",
                                _("Failed to send net-add request to CH"));
        return -1;
    }

    if (chSocketProcessHttpResponse(mon_sockfd, true) < 0)
        return -1;

    return 0;
}

/**
 * chProcessAddNetworkDevices:
 * @driver: pointer to ch driver object
 * @mon: pointer to the monitor object
 * @vmdef: pointer to domain definition
 * @nicindexes: returned array of FDs of guest interfaces
 * @nnicindexes: returned number of network indexes
 *
 * Send tap fds to CH process via AddNet api. Capture the network indexes of
 * guest interfaces in nicindexes.
 *
 * Returns 0 on success, -1 on error.
 */
static int
chProcessAddNetworkDevices(virCHDriver *driver,
                           virCHMonitor *mon,
                           virDomainDef *vmdef,
                           int **nicindexes,
                           size_t *nnicindexes)
{
    size_t i = 0;

    for (i = 0; i < vmdef->nnets; i++) {
       if (chProcessAddNetworkDevice(driver, mon, vmdef, vmdef->nets[i],
                                     nicindexes, nnicindexes) < 0) {
        return -1;
       }
    }

    return 0;
}

/**
 * virCHRestoreCreateNetworkDevices:
 * @driver: pointer to driver structure
 * @vmdef: pointer to domain definition
 * @vmtapfds: returned array of FDs of guest interfaces
 * @nvmtapfds: returned number of network indexes
 * @nicindexes: returned array of network indexes
 * @nnicindexes: returned number of network indexes
 *
 * Create network devices for the domain. This function is called during
 * domain restore.
 *
 * Returns 0 on success or -1 in case of error
*/
static int
virCHRestoreCreateNetworkDevices(virCHDriver *driver,
                                 virDomainDef *vmdef,
                                 int **vmtapfds,
                                 size_t *nvmtapfds,
                                 int **nicindexes,
                                 size_t *nnicindexes)
{
    size_t i, j;
    size_t tapfd_len;
    size_t index_vmtapfds;
    for (i = 0; i < vmdef->nnets; i++) {
        g_autofree int *tapfds = NULL;
        tapfd_len = vmdef->nets[i]->driver.virtio.queues;
        if (virCHDomainValidateActualNetDef(vmdef->nets[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("net definition failed validation"));
            return -1;
        }
        tapfds = g_new0(int, tapfd_len);
        memset(tapfds, -1, (tapfd_len) * sizeof(int));

        /* Connect Guest interfaces */
        if (virCHConnetNetworkInterfaces(driver, vmdef, vmdef->nets[i], tapfds,
                                          nicindexes, nnicindexes) < 0)
            return -1;

        index_vmtapfds = *nvmtapfds;
        VIR_EXPAND_N(*vmtapfds, *nvmtapfds, tapfd_len);
        for (j = 0; j < tapfd_len; j++) {
            VIR_APPEND_ELEMENT_INPLACE(*vmtapfds, index_vmtapfds, tapfds[j]);
        }
    }
    return 0;
}

/**
 * virCHProcessStartValidate:
 * @driver: pointer to driver structure
 * @vm: domain object
 *
 * Checks done before starting a VM.
 *
 * Returns 0 on success or -1 in case of error
 */
static int
virCHProcessStartValidate(virCHDriver *driver,
                          virDomainObj *vm)
{
    if (vm->def->virtType == VIR_DOMAIN_VIRT_KVM) {
        VIR_DEBUG("Checking for KVM availability");
        if (!virCapabilitiesDomainSupported(driver->caps, -1,
                                            VIR_ARCH_NONE, VIR_DOMAIN_VIRT_KVM, false)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Domain requires KVM, but it is not available. Check that virtualization is enabled in the host BIOS, and host configuration is setup to load the kvm modules."));
            return -1;
        }
    } else if (vm->def->virtType == VIR_DOMAIN_VIRT_HYPERV) {
        VIR_DEBUG("Checking for mshv availability");
        if (!virCapabilitiesDomainSupported(driver->caps, -1,
                                            VIR_ARCH_NONE, VIR_DOMAIN_VIRT_HYPERV, false)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Domain requires MSHV device, but it is not available. Check that virtualization is enabled in the host BIOS, and host configuration is setup to load the mshv modules."));
            return -1;
        }

    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("virt type '%1$s' is not supported"),
                       virDomainVirtTypeToString(vm->def->virtType));
        return -1;
    }

    return 0;
}

static int
virCHProcessPrepareDomainHostdevs(virDomainObj *vm)
{
    size_t i;

    for (i = 0; i < vm->def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = vm->def->hostdevs[i];

        if (virCHDomainPrepareHostdev(hostdev) < 0)
            return -1;
    }

    return 0;
}

/**
 * virCHProcessPrepareHost:
 * @driver: ch driver
 * @vm: domain object
 *
 * This function groups all code that modifies host system to prepare
 * environment for a domain which is about to start.
 *
 * This function MUST be called only after virCHProcessPrepareDomain().
 */
static int
virCHProcessPrepareHost(virCHDriver *driver, virDomainObj *vm)
{
    unsigned int hostdev_flags = 0;
    virCHDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(driver);

    if (virCHHostdevPrepareDomainDevices(driver, vm->def, hostdev_flags) < 0)
        return -1;

    VIR_FREE(priv->pidfile);
    if (!(priv->pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name))) {
        virReportSystemError(errno, "%s",
                             _("Failed to build pidfile path."));
        return -1;
    }

    if (unlink(priv->pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot remove stale PID file %1$s"),
                             priv->pidfile);
        return -1;
    }

    /* Ensure no historical cgroup for this VM is lying around */
    VIR_DEBUG("Ensuring no historical cgroup is lying around");
    virDomainCgroupRemoveCgroup(vm, priv->cgroup, priv->machineName);

    return 0;
}

/**
 * virCHProcessPrepareDomain:
 * @vm: domain object
 *
 * This function groups all code that modifies only live XML of a domain which
 * is about to start and it's the only place to do those modifications.
 *
 * This function MUST be called before virCHProcessPrepareHost().
 *
 */
static int
virCHProcessPrepareDomain(virDomainObj *vm)
{
    if (chAssignDeviceAliases(vm->def) < 0)
        return -1;

    if (virCHProcessPrepareDomainHostdevs(vm) < 0)
        return -1;

    return 0;
}

/**
 * virCHProcessStart:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @reason: reason for switching vm to running state
 *
 * Starts Cloud-Hypervisor listening on a local socket
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
    g_autoptr(domainLogContext) logCtxt = NULL;
    int logfile = -1;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("VM is already active"));
        return -1;
    }

    if (virCHProcessStartValidate(driver, vm) < 0) {
        return -1;
    }

    VIR_DEBUG("Creating domain log file for %s domain", vm->def->name);
    if (!(logCtxt = domainLogContextNew(cfg->stdioLogD, cfg->logDir,
                                        CH_DRIVER_NAME,
                                        vm, driver->privileged,
                                        vm->def->name))) {
        virLastErrorPrefixMessage("%s", _("can't connect to virtlogd"));
        return -1;
    }
    logfile = domainLogContextGetWriteFD(logCtxt);

    if (virCHProcessPrepareDomain(vm) < 0) {
        return -1;
    }

    if (virCHProcessPrepareHost(driver, vm) < 0)
        return -1;

    if (!priv->monitor) {
        /* And we can get the first monitor connection now too */
        if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm, logfile))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create connection to CH socket"));
            goto cleanup;
        }

        if (virCHMonitorCreateVM(driver, priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create guest VM"));
            goto cleanup;
        }
    }

    vm->def->id = vm->pid;
    priv->machineName = virCHDomainGetMachineName(vm);

    if (chProcessAddNetworkDevices(driver, priv->monitor, vm->def,
                                   &nicindexes, &nnicindexes) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed while adding guest interfaces"));
        goto cleanup;
    }

    if (virDomainCgroupSetupCgroup("ch", vm,
                                   nnicindexes, nicindexes,
                                   &priv->cgroup,
                                   cfg->cgroupControllers,
                                   0, /*maxThreadsPerProc*/
                                   priv->driver->privileged,
                                   false,
                                   priv->machineName) < 0)
        goto cleanup;

    if (virCHProcessInitCpuAffinity(vm) < 0)
        goto cleanup;

    /* Bring up netdevs before starting CPUs */
    if (virDomainInterfaceStartDevices(vm->def) < 0)
        return -1;

    if (virCHMonitorBootVM(priv->monitor, logCtxt) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to boot guest VM"));
        goto cleanup;
    }

    if (virCHProcessSetup(vm) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    return 0;

 cleanup:
    if (ret)
        virCHProcessStop(driver, vm,
                         VIR_DOMAIN_SHUTOFF_FAILED,
                         VIR_CH_PROCESS_STOP_FORCE);

    return ret;
}

int
virCHProcessStop(virCHDriver *driver,
                 virDomainObj *vm,
                 virDomainShutoffReason reason,
                 unsigned int flags)
{
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(driver);
    int ret;
    int retries = 0;
    unsigned int hostdev_flags = VIR_HOSTDEV_SP_PCI;
    virCHDomainObjPrivate *priv = vm->privateData;
    virDomainDef *def = vm->def;
    virErrorPtr orig_err = NULL;
    size_t i;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d flags=0x%x",
              vm->def->name, (int)vm->pid, (int)reason, flags);

    virErrorPreserveLast(&orig_err);

    if (priv->monitor) {
        bool force = false;

        if (flags & VIR_CH_PROCESS_STOP_FORCE)
            force = true;

        virProcessKillPainfully(vm->pid, force);
        g_clear_pointer(&priv->monitor, virCHMonitorClose);
    }

    /* de-activate netdevs after stopping vm */
    ignore_value(virDomainInterfaceStopDevices(vm->def));

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];
        virDomainInterfaceDeleteDevice(def, net, false, cfg->stateDir);
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

    if (priv->pidfile) {
        if (unlink(priv->pidfile) < 0 &&
            errno != ENOENT)
            VIR_WARN("Failed to remove PID file for %s: %s",
                     vm->def->name, g_strerror(errno));

        g_clear_pointer(&priv->pidfile, g_free);
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    virHostdevReAttachDomainDevices(driver->hostdevMgr, CH_DRIVER_NAME, def,
                                    hostdev_flags);

    virErrorRestore(&orig_err);
    return 0;
}

/**
 * virCHProcessStartRestore:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @from: directory path to restore the VM from
 *
 * Starts Cloud-Hypervisor process with the restored VM
 *
 * Returns 0 on success or -1 in case of error
 */
int
virCHProcessStartRestore(virCHDriver *driver, virDomainObj *vm, const char *from)
{
    virCHDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(priv->driver);
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) http_headers = VIR_BUFFER_INITIALIZER;
    g_autofree char *payload = NULL;
    g_autofree char *response = NULL;
    VIR_AUTOCLOSE mon_sockfd = -1;
    g_autofree int *tapfds = NULL;
    g_autofree int *nicindexes = NULL;
    size_t payload_len;
    size_t ntapfds = 0;
    size_t nnicindexes = 0;
    int ret = -1;
    g_autoptr(domainLogContext) logCtxt = NULL;
    int logfile = -1;

    VIR_DEBUG("Creating domain log file for %s domain", vm->def->name);
    if (!(logCtxt = domainLogContextNew(cfg->stdioLogD, cfg->logDir,
                                        CH_DRIVER_NAME,
                                        vm, driver->privileged,
                                        vm->def->name))) {
        virLastErrorPrefixMessage("%s", _("can't connect to virtlogd"));
        return -1;
    }
    logfile = domainLogContextGetWriteFD(logCtxt);

    if (!priv->monitor) {
        /* Get the first monitor connection if not already */
        if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm, logfile))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create connection to CH socket"));
            goto cleanup;
        }
    }

    vm->def->id = vm->pid;
    priv->machineName = virCHDomainGetMachineName(vm);

    if (virCHMonitorBuildRestoreJson(vm->def, from, &payload) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to restore domain"));
        goto cleanup;
    }

    virBufferAddLit(&http_headers, "PUT /api/v1/vm.restore HTTP/1.1\r\n");
    virBufferAddLit(&http_headers, "Host: localhost\r\n");
    virBufferAddLit(&http_headers, "Content-Type: application/json\r\n");
    virBufferAsprintf(&buf, "%s", virBufferCurrentContent(&http_headers));
    virBufferAsprintf(&buf, "Content-Length: %zu\r\n\r\n", strlen(payload));
    virBufferAsprintf(&buf, "%s", payload);
    payload_len = virBufferUse(&buf);
    payload = virBufferContentAndReset(&buf);

    if ((mon_sockfd = chMonitorSocketConnect(priv->monitor)) < 0)
        goto cleanup;

    if (virCHRestoreCreateNetworkDevices(driver, vm->def, &tapfds, &ntapfds, &nicindexes, &nnicindexes) < 0)
        goto cleanup;

    if (virDomainCgroupSetupCgroup("ch", vm,
                                   nnicindexes, nicindexes,
                                   &priv->cgroup,
                                   cfg->cgroupControllers,
                                   0, /*maxThreadsPerProc*/
                                   priv->driver->privileged,
                                   false,
                                   priv->machineName) < 0)
        goto cleanup;

    /* Bring up netdevs before restoring vm */
    if (virDomainInterfaceStartDevices(vm->def) < 0)
        goto cleanup;

    if (virSocketSendMsgWithFDs(mon_sockfd, payload, payload_len, tapfds, ntapfds) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to send restore request to CH"));
        goto cleanup;
    }

    /* Restore is a synchronous operation in CH. so, pass false to wait until there's a response */
    if (chSocketProcessHttpResponse(mon_sockfd, false) < 0)
        goto cleanup;

    if (virCHProcessSetup(vm) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
    ret = 0;

 cleanup:
    if (tapfds)
        chCloseFDs(tapfds, ntapfds);
    if (ret)
        virCHProcessStop(driver, vm,
                         VIR_DOMAIN_SHUTOFF_FAILED,
                         VIR_CH_PROCESS_STOP_FORCE);
    return ret;
}
