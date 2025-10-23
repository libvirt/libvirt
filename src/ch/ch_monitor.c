/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_monitor.c: Manage Cloud-Hypervisor interactions
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

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>

#include "datatypes.h"
#include "ch_conf.h"
#include "ch_domain.h"
#include "ch_events.h"
#include "ch_interface.h"
#include "ch_monitor.h"
#include "domain_interface.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_monitor");

static virClass *virCHMonitorClass;
static void virCHMonitorDispose(void *obj);
static void virCHMonitorThreadInfoFree(virCHMonitor *mon);

static int virCHMonitorOnceInit(void)
{
    if (!VIR_CLASS_NEW(virCHMonitor, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCHMonitor);

int virCHMonitorShutdownVMM(virCHMonitor *mon);
int virCHMonitorPutNoContent(virCHMonitor *mon, const char *endpoint,
                             domainLogContext *logCtxt);
static int
virCHMonitorPut(virCHMonitor *mon,
                const char *endpoint,
                virJSONValue *payload,
                domainLogContext *logCtxt,
                virJSONValue **answer);

static int
virCHMonitorBuildCPUJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) cpus = NULL;
    unsigned int maxvcpus = 0;
    unsigned int nvcpus = 0;
    virDomainVcpuDef *vcpu;
    size_t i;

    /* count maximum allowed number vcpus and enabled vcpus when boot.*/
    maxvcpus = virDomainDefGetVcpusMax(vmdef);
    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vmdef, i);
        if (vcpu->online)
            nvcpus++;
    }

    if (maxvcpus != 0 || nvcpus != 0) {
        cpus = virJSONValueNewObject();
        if (virJSONValueObjectAppendNumberInt(cpus, "boot_vcpus", nvcpus) < 0)
            return -1;
        if (virJSONValueObjectAppendNumberInt(cpus, "max_vcpus", vmdef->maxvcpus) < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "cpus", &cpus) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildConsoleJson(virJSONValue *content,
                             virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) console = virJSONValueNewObject();
    g_autoptr(virJSONValue) serial = virJSONValueNewObject();

    if (vmdef->nconsoles &&
        vmdef->consoles[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
        if (virJSONValueObjectAppendString(console, "mode", "Pty") < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "console", &console) < 0)
            return -1;
    }

    if (vmdef->nserials) {
        if (vmdef->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY) {
            if (virJSONValueObjectAppendString(serial, "mode", "Pty") < 0)
                return -1;
        } else if (vmdef->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_UNIX) {
            if (virJSONValueObjectAppendString(serial, "mode", "Socket") < 0)
                return -1;
            if (virJSONValueObjectAppendString(serial,
                                               "socket",
                                               vmdef->serials[0]->source->data.file.path) < 0)
                return -1;
        }

        if (virJSONValueObjectAppend(content, "serial", &serial) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildPayloadJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) payload = virJSONValueNewObject();

    if (vmdef->os.kernel == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Kernel image path is not defined. With sev_snp=on, pass an igvm path"));
        return -1;
    }

    if (vmdef->sec &&
        vmdef->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV_SNP) {
        if (virJSONValueObjectAppendString(payload, "igvm", vmdef->os.kernel) < 0)
            return -1;

        if (vmdef->sec->data.sev_snp.host_data) {
            size_t len;
            const size_t host_data_len = 32;
            g_autofree unsigned char *buf = NULL;
            g_autofree char *host_data = NULL;

            /* Libvirt provided host_data is base64 encoded and cloud-hypervisor
               requires host_data as hex encoded. Base64 decode and hex encode
               before sending to cloud-hypervisor.*/
            buf = g_base64_decode(vmdef->sec->data.sev_snp.host_data, &len);
            if (len != host_data_len) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid host_data provided. Expected '%1$zu' bytes"),
                               host_data_len);
                return -1;
            }

            host_data = virStringFormatHex(buf, host_data_len);
            if (virJSONValueObjectAppendString(payload, "host_data",
                                               host_data) < 0)
                return -1;
        }
    } else {
        if (virJSONValueObjectAdd(&payload,
                                  "s:kernel", vmdef->os.kernel,
                                  "S:cmdline", vmdef->os.cmdline,
                                  "S:initramfs", vmdef->os.initrd,
                                  NULL) < 0)
            return -1;
    }

    if (virJSONValueObjectAppend(content, "payload", &payload) < 0)
        return -1;

    return 0;
}

static int
virCHMonitorBuildKernelRelatedJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) kernel = virJSONValueNewObject();
    g_autoptr(virJSONValue) cmdline = virJSONValueNewObject();
    g_autoptr(virJSONValue) initramfs = virJSONValueNewObject();

    if (vmdef->os.kernel == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Kernel image path in this domain is not defined"));
        return -1;
    } else {
        if (virJSONValueObjectAppendString(kernel, "path", vmdef->os.kernel) < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "kernel", &kernel) < 0)
            return -1;
    }

    if (vmdef->os.cmdline) {
        if (virJSONValueObjectAppendString(cmdline, "args", vmdef->os.cmdline) < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "cmdline", &cmdline) < 0)
            return -1;
    }

    if (vmdef->os.initrd != NULL) {
        if (virJSONValueObjectAppendString(initramfs, "path", vmdef->os.initrd) < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "initramfs", &initramfs) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildMemoryJson(virJSONValue *content, virDomainDef *vmdef)
{
    unsigned long long total_memory = virDomainDefGetMemoryInitial(vmdef) * 1024;

    if (total_memory != 0) {
        g_autoptr(virJSONValue) memory = virJSONValueNewObject();

        if (virJSONValueObjectAppendNumberUlong(memory, "size", total_memory) < 0)
            return -1;

        if (virJSONValueObjectAppend(content, "memory", &memory) < 0)
            return -1;
    }

    return 0;
}

static virJSONValue*
virCHMonitorBuildDiskJson(virDomainDiskDef *diskdef)
{
    g_autoptr(virJSONValue) disk = virJSONValueNewObject();

    if (!diskdef->src)
        return NULL;

    switch (diskdef->src->type) {
    case VIR_STORAGE_TYPE_FILE:
        if (!diskdef->src->path) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Missing disk file path in domain"));
            return NULL;
        }
        if (!diskdef->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing disk alias"));
            return NULL;
        }
        if (diskdef->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Only virtio bus types are supported for '%1$s'"),
                           diskdef->src->path);
            return NULL;
        }
        if (virJSONValueObjectAppendString(disk, "path", diskdef->src->path) < 0)
            return NULL;
        if (diskdef->src->readonly) {
            if (virJSONValueObjectAppendBoolean(disk, "readonly", true) < 0)
                return NULL;
        }
        if (virJSONValueObjectAppendString(disk, "id", diskdef->info.alias) < 0) {
            return NULL;
        }

        break;
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_NETWORK:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_LAST:
    default:
        virReportEnumRangeError(virStorageType, diskdef->src->type);
        return NULL;
    }

    return g_steal_pointer(&disk);
}

static int
virCHMonitorBuildDisksJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) disks = NULL;
    size_t i;

    if (vmdef->ndisks > 0) {
        disks = virJSONValueNewArray();

        for (i = 0; i < vmdef->ndisks; i++) {
            g_autoptr(virJSONValue) disk = NULL;

            if ((disk = virCHMonitorBuildDiskJson(vmdef->disks[i])) == NULL)
                return -1;
            if (virJSONValueArrayAppend(disks, &disk) < 0)
                return -1;
        }
        if (virJSONValueObjectAppend(content, "disks", &disks) < 0)
            return -1;
    }

    return 0;
}

int
virCHMonitorAddDisk(virCHMonitor *monitor,
                    virDomainDiskDef *diskdef)
{
    g_autoptr(virJSONValue) disk = virCHMonitorBuildDiskJson(diskdef);
    g_autoptr(virJSONValue) response = NULL;

    if (!disk) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not build disk json"));
        return -1;
    }

    return virCHMonitorPut(monitor,
                           URL_VM_ADD_DISK,
                           disk,
                           NULL,
                           NULL);
}

static int
virCHMonitorBuildRngJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) rng = virJSONValueNewObject();

    if (vmdef->nrngs == 0) {
        return 0;
    }

    if (vmdef->rngs[0]->model != VIR_DOMAIN_RNG_MODEL_VIRTIO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only virtio model is supported for RNG devices"));
        return -1;
    }

    switch (vmdef->rngs[0]->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (virJSONValueObjectAppendString(rng, "src", vmdef->rngs[0]->source.file) < 0)
            return -1;

        if (virJSONValueObjectAppend(content, "rng", &rng) < 0)
            return -1;

        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only RANDOM backend is supported for RNG devices"));
        return -1;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    return 0;
}

/**
 * virCHMonitorBuildNetJson:
 * @net: pointer to a guest network definition
 * @jsonstr: returned network json
 *
 * Build net json to send to CH
 * Returns 0 on success or -1 in case of error
 */
int
virCHMonitorBuildNetJson(virDomainNetDef *net,
                         char **jsonstr)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    g_autoptr(virJSONValue) net_json = virJSONValueNewObject();
    virDomainNetType actualType = virDomainNetGetActualType(net);

    if (virJSONValueObjectAppendString(net_json, "id", net->info.alias) < 0)
        return -1;

    if (actualType == VIR_DOMAIN_NET_TYPE_ETHERNET &&
        net->guestIP.nips == 1) {
        const virNetDevIPAddr *ip;
        g_autofree char *addr = NULL;
        virSocketAddr netmask;
        g_autofree char *netmaskStr = NULL;

        ip = net->guestIP.ips[0];

        if (!(addr = virSocketAddrFormat(&ip->address)))
            return -1;

        if (virJSONValueObjectAppendString(net_json, "ip", addr) < 0)
            return -1;

        if (virSocketAddrPrefixToNetmask(ip->prefix, &netmask, AF_INET) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to translate net prefix %1$d to netmask"),
                           ip->prefix);
            return -1;
        }

        if (!(netmaskStr = virSocketAddrFormat(&netmask)))
            return -1;

        if (virJSONValueObjectAppendString(net_json, "mask", netmaskStr) < 0)
            return -1;
    }

    if (virJSONValueObjectAppendString(net_json, "mac",
                                       virMacAddrFormat(&net->mac, macaddr)) < 0)
        return -1;

    if (net->virtio != NULL) {
        if (net->virtio->iommu == VIR_TRISTATE_SWITCH_ON) {
            if (virJSONValueObjectAppendBoolean(net_json, "iommu", true) < 0)
                return -1;
        }
    }

    /* Cloud-Hypervisor expects number of queues. 1 for rx and 1 for tx.
     * Multiply queue pairs by 2 to provide total number of queues to CH
     */
    if (net->driver.virtio.queues) {
        if (virJSONValueObjectAppendNumberInt(net_json, "num_queues",
                                              2 * net->driver.virtio.queues) < 0)
            return -1;
    }

    if (net->driver.virtio.rx_queue_size || net->driver.virtio.tx_queue_size) {
        if (net->driver.virtio.rx_queue_size !=
            net->driver.virtio.tx_queue_size) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio rx_queue_size option %1$d is not same with tx_queue_size %2$d"),
                           net->driver.virtio.rx_queue_size,
                           net->driver.virtio.tx_queue_size);
            return -1;
        }
        if (virJSONValueObjectAppendNumberInt(net_json, "queue_size",
                                              net->driver.virtio.rx_queue_size) < 0)
            return -1;
    }

    if (net->mtu) {
        if (virJSONValueObjectAppendNumberInt(net_json, "mtu", net->mtu) < 0)
            return -1;
    }

    if (!(*jsonstr = virJSONValueToString(net_json, false)))
        return -1;

    return 0;
}

static int
virCHMonitorBuildDeviceJson(virJSONValue *devices,
                            virDomainHostdevDef *hostdevdef)
{
    g_autoptr(virJSONValue) device = NULL;


    if (hostdevdef->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdevdef->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
        g_autofree char *name = NULL;
        g_autofree char *path = NULL;
        virDomainHostdevSubsysPCI *pcisrc = &hostdevdef->source.subsys.u.pci;

        device = virJSONValueNewObject();
        name = virPCIDeviceAddressAsString(&pcisrc->addr);
        path = g_strdup_printf("/sys/bus/pci/devices/%s/", name);
        if (!virFileExists(path)) {
            virReportError(VIR_ERR_DEVICE_MISSING,
                           _("host pci device %1$s not found"), path);
            return -1;
        }
        if (virJSONValueObjectAppendString(device, "path", path) < 0)
            return -1;
        if (virJSONValueArrayAppend(devices, &device) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildDevicesJson(virJSONValue *content,
                             virDomainDef *vmdef)
{
    size_t i;

    g_autoptr(virJSONValue) devices = NULL;

    if (vmdef->nhostdevs == 0)
        return 0;

    devices = virJSONValueNewArray();
    for (i = 0; i < vmdef->nhostdevs; i++) {
        if (virCHMonitorBuildDeviceJson(devices, vmdef->hostdevs[i]) < 0)
            return -1;
    }
    if (virJSONValueObjectAppend(content, "devices", &devices) < 0)
        return -1;

    return 0;
}

static int
virCHMonitorBuildPlatformJson(virJSONValue *content, virDomainDef *vmdef)
{
    if (vmdef->sec &&
        vmdef->sec->sectype == VIR_DOMAIN_LAUNCH_SECURITY_SEV_SNP) {
        g_autoptr(virJSONValue) platform = virJSONValueNewObject();

        if (virJSONValueObjectAppendBoolean(platform, "sev_snp", 1) < 0)
            return -1;

        if (virJSONValueObjectAppend(content, "platform", &platform) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildVMJson(virCHDriver *driver, virDomainDef *vmdef,
                        char **jsonstr)
{
    g_autoptr(virJSONValue) content = virJSONValueNewObject();

    if (vmdef == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VM is not defined"));
        return -1;
    }

    if (virCHMonitorBuildConsoleJson(content, vmdef) < 0)
        return -1;

    if (virCHMonitorBuildCPUJson(content, vmdef) < 0)
        return -1;

    if (virCHMonitorBuildMemoryJson(content, vmdef) < 0)
        return -1;

    if (virBitmapIsBitSet(driver->chCaps, CH_KERNEL_API_DEPRCATED)) {
        if (virCHMonitorBuildPayloadJson(content, vmdef) < 0)
            return -1;
    } else if (virCHMonitorBuildKernelRelatedJson(content, vmdef) < 0) {
            return -1;
    }

    if (virCHMonitorBuildPlatformJson(content, vmdef) < 0)
        return -1;

    if (virCHMonitorBuildDisksJson(content, vmdef) < 0)
        return -1;

    if (virCHMonitorBuildRngJson(content, vmdef) < 0)
        return -1;

    if (virCHMonitorBuildDevicesJson(content, vmdef) < 0)
        return -1;

    if (!(*jsonstr = virJSONValueToString(content, false)))
        return -1;

    return 0;
}

static virJSONValue*
virCHMonitorBuildKeyValueJson(const char *key,
                              const char *value)
{
    g_autoptr(virJSONValue) content = virJSONValueNewObject();

    if (virJSONValueObjectAppendString(content, key, value) < 0)
        return NULL;

    return g_steal_pointer(&content);
}

static int
virCHMonitorBuildKeyValueStringJson(char **jsonstr,
                                    const char *key,
                                    const char *value)
{
    g_autoptr(virJSONValue) content = virCHMonitorBuildKeyValueJson(key, value);

    if (!(*jsonstr = virJSONValueToString(content, false)))
        return -1;

    return 0;
}

int virCHMonitorRemoveDevice(virCHMonitor *mon,
                             const char* device_id)
{
    g_autoptr(virJSONValue) payload = virCHMonitorBuildKeyValueJson("id", device_id);

    VIR_DEBUG("Remove device %s", device_id);

    return virCHMonitorPut(mon, URL_VM_REMOVE_DEVICE, payload, NULL, NULL);
}

static int
chMonitorCreateSocket(const char *socket_path)
{
    struct sockaddr_un addr = { 0 };
    socklen_t addrlen = sizeof(addr);
    int fd;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create UNIX socket"));
        goto error;
    }

    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, socket_path) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("UNIX socket path '%1$s' too long"),
                       socket_path);
        goto error;
    }

    if (unlink(socket_path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to unlink %1$s"),
                             socket_path);
        goto error;
    }

    if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        virReportSystemError(errno,
                             _("Unable to bind to UNIX socket path '%1$s'"),
                             socket_path);
        goto error;
    }

    if (listen(fd, 1) < 0) {
        virReportSystemError(errno,
                             _("Unable to listen to UNIX socket path '%1$s'"),
                             socket_path);
        goto error;
    }

    /* We run cloud-hypervisor with umask 0002. Compensate for the umask
     * libvirtd might be running under to get the same permission
     * cloud-hypervisor would have. */
    if (virFileUpdatePerm(socket_path, 0002, 0664) < 0)
        goto error;

    return fd;

 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}

virCHMonitor *
virCHMonitorNew(virDomainObj *vm, virCHDriverConfig *cfg, int logfile)
{
    virCHDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCHMonitor) mon = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int socket_fd = 0;
    int event_monitor_fd;
    int rv;

    if (virCHMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(virCHMonitorClass)))
        return NULL;

    /* avoid VIR_FORCE_CLOSE()-ing garbage fd value in virCHMonitorClose */
    mon->eventmonitorfd = -1;

    if (!vm->def) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VM is not defined"));
        return NULL;
    }

    /* prepare to launch Cloud-Hypervisor socket */
    mon->socketpath = g_strdup_printf("%s/%s-socket", cfg->stateDir, vm->def->name);
    if (g_mkdir_with_parents(cfg->stateDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Cannot create socket directory '%1$s'"),
                             cfg->stateDir);
        return NULL;
    }

    if (g_mkdir_with_parents(cfg->saveDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Cannot create save directory '%1$s'"),
                             cfg->saveDir);
        return NULL;
    }

    /* Event monitor file to listen for VM state changes */
    mon->eventmonitorpath = g_strdup_printf("%s/%s-event-monitor-fifo",
                                            cfg->stateDir, vm->def->name);
    if (virFileExists(mon->eventmonitorpath)) {
        VIR_WARN("Monitor file (%s) already exists, trying to delete!",
                  mon->eventmonitorpath);
        if (virFileRemove(mon->eventmonitorpath, -1, -1) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to remove the file: %1$s"),
                           mon->eventmonitorpath);
            return NULL;
        }
    }

    if (mkfifo(mon->eventmonitorpath, S_IWUSR | S_IRUSR) < 0 &&
            errno != EEXIST) {
        virReportSystemError(errno, "%s",
                             _("Cannot create monitor FIFO"));
        return NULL;
    }

    cmd = virCommandNew(vm->def->emulator);
    virCommandSetOutputFD(cmd, &logfile);
    virCommandSetErrorFD(cmd, &logfile);
    virCommandNonblockingFDs(cmd);
    virCommandSetUmask(cmd, 0x002);

    socket_fd = chMonitorCreateSocket(mon->socketpath);
    if (socket_fd < 0) {
        virReportSystemError(errno,
                             _("Cannot create socket '%1$s'"),
                             mon->socketpath);
        return NULL;
    }

    if (cfg->logLevel == VIR_CH_LOGLEVEL_INFO) {
        virCommandAddArg(cmd, "-v");
    } else if (cfg->logLevel == VIR_CH_LOGLEVEL_DEBUG) {
        virCommandAddArg(cmd, "-vv");
    }

    virCommandAddArg(cmd, "--api-socket");
    virCommandAddArgFormat(cmd, "fd=%d", socket_fd);
    virCommandPassFD(cmd, socket_fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandAddArg(cmd, "--event-monitor");
    virCommandAddArgFormat(cmd, "path=%s", mon->eventmonitorpath);
    virCommandSetPidFile(cmd, priv->pidfile);
    virCommandDaemonize(cmd);

    /* launch Cloud-Hypervisor socket */
    if (virCommandRun(cmd, NULL) < 0) {
        VIR_DEBUG("CH vm=%p name=%s failed to spawn",
                  vm, vm->def->name);
        return NULL;
    }

    if ((rv = virPidFileReadPath(priv->pidfile, &vm->pid)) < 0) {
        virReportSystemError(-rv,
                             _("Domain %1$s didn't show up"),
                             vm->def->name);
        return NULL;
    }
    VIR_DEBUG("CH vm=%p name=%s running with pid=%lld",
              vm, vm->def->name, (long long)vm->pid);

    /* open the reader end of fifo before start Event Handler */
    while ((event_monitor_fd = open(mon->eventmonitorpath, O_RDONLY)) < 0) {
        if (errno == EINTR) {
            /* 100 milli seconds */
            g_usleep(100000);
            continue;
        }
        /* Any other error should be a BUG(kernel/libc/libvirtd)
         * (ENOMEM can happen on exceeding per-user limits)
         */
        VIR_ERROR(_("%1$s: Failed to open the event monitor FIFO(%2$s) read end!"),
                  vm->def->name, mon->eventmonitorpath);
        /* CH process(Writer) is blocked at this point as EventHandler(Reader)
         * fails to open the FIFO.
         */
        return NULL;
    }
    mon->eventmonitorfd = event_monitor_fd;
    VIR_DEBUG("%s: Opened the event monitor FIFO(%s)", vm->def->name, mon->eventmonitorpath);

    /* now has its own reference */
    mon->vm = virObjectRef(vm);

    if (virCHStartEventHandler(mon) < 0)
        return NULL;

    /* get a curl handle */
    mon->handle = curl_easy_init();

    return g_steal_pointer(&mon);
}

static void virCHMonitorDispose(void *opaque)
{
    virCHMonitor *mon = opaque;

    VIR_DEBUG("mon=%p", mon);
    virCHMonitorThreadInfoFree(mon);
    virObjectUnref(mon->vm);
}

void virCHMonitorClose(virCHMonitor *mon)
{
    if (!mon)
        return;

    if (mon->handle)
        curl_easy_cleanup(mon->handle);

    if (mon->socketpath) {
        if (virFileRemove(mon->socketpath, -1, -1) < 0 &&
            errno != ENOENT) {
            VIR_WARN("Unable to remove CH socket file '%s': %s",
                     mon->socketpath, g_strerror(errno));
        }
        g_clear_pointer(&mon->socketpath, g_free);
    }

    virCHStopEventHandler(mon);
    if (mon->eventmonitorfd >= 0) {
        VIR_FORCE_CLOSE(mon->eventmonitorfd);
    }
    if (mon->eventmonitorpath) {
        if (virFileRemove(mon->eventmonitorpath, -1, -1) < 0) {
            VIR_WARN("Unable to remove CH event monitor file '%s'",
                     mon->eventmonitorpath);
        }
        g_clear_pointer(&mon->eventmonitorpath, g_free);
    }

    virObjectUnref(mon);
}

static int
virCHMonitorCurlPerform(CURL *handle)
{
    CURLcode errorCode;
    long responseCode = 0;

    errorCode = curl_easy_perform(handle);

    if (errorCode != CURLE_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("curl_easy_perform() returned an error: %1$s (%2$d)"),
                       curl_easy_strerror(errorCode), errorCode);
        return -1;
    }

    errorCode = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE,
                                  &responseCode);

    if (errorCode != CURLE_OK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned an error: %1$s (%2$d)"),
                       curl_easy_strerror(errorCode),
                       errorCode);
        return -1;
    }

    if (responseCode < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned a negative response code"));
        return -1;
    }

    return responseCode;
}

struct curl_data {
    char *content;
    size_t size;
};

static size_t
curl_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t content_size = size * nmemb;
    struct curl_data *data = userp;

    if (content_size == 0)
        return content_size;

    data->content = g_realloc(data->content, data->size + content_size);

    memcpy(&(data->content[data->size]), contents, content_size);
    data->size += content_size;

    return content_size;
}

static int
virCHMonitorPut(virCHMonitor *mon,
                const char *endpoint,
                virJSONValue *payload,
                domainLogContext *logCtxt,
                virJSONValue **answer)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mon);
    g_autofree char *url = NULL;
    g_autofree char *payload_str = NULL;
    int responseCode = 0;
    int ret = -1;
    struct curl_data data = {0};
    struct curl_slist *headers = NULL;

    url = g_strdup_printf("%s/%s", URL_ROOT, endpoint);

    /* reset all options of a libcurl session handle at first */
    curl_easy_reset(mon->handle);

    curl_easy_setopt(mon->handle, CURLOPT_UNIX_SOCKET_PATH, mon->socketpath);
    curl_easy_setopt(mon->handle, CURLOPT_URL, url);
    curl_easy_setopt(mon->handle, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, NULL);
    curl_easy_setopt(mon->handle, CURLOPT_INFILESIZE, 0L);

    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(mon->handle, CURLOPT_WRITEFUNCTION, curl_callback);
    curl_easy_setopt(mon->handle, CURLOPT_WRITEDATA, (void *)&data);

    if (payload) {
        payload_str = virJSONValueToString(payload, false);
        curl_easy_setopt(mon->handle, CURLOPT_POSTFIELDS, payload_str);
        curl_easy_setopt(mon->handle, CURLOPT_CUSTOMREQUEST, "PUT");
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }

    responseCode = virCHMonitorCurlPerform(mon->handle);

    data.content = g_realloc(data.content, data.size + 1);
    data.content[data.size] = '\0';

    if (logCtxt && data.size) {
        /* Do this to append a NULL char at the end of data */
        domainLogContextWrite(logCtxt, "HTTP response code from CH: %d\n", responseCode);
        domainLogContextWrite(logCtxt, "Response = %s\n", data.content);
    }

    if (responseCode != 200 && responseCode != 204) {
        ret = -1;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid HTTP response code from CH: %1$d"),
                       responseCode);
        goto cleanup;
    }

    if (answer)
        *answer = virJSONValueFromString(data.content);

    ret = 0;

 cleanup:
    curl_slist_free_all(headers);
    g_free(data.content);
    return ret;
}

int
virCHMonitorPutNoContent(virCHMonitor *mon,
                         const char *endpoint,
                         domainLogContext *logCtxt)
{
    return virCHMonitorPut(mon, endpoint, NULL, logCtxt, NULL);
}

static int
virCHMonitorGet(virCHMonitor *mon, const char *endpoint, virJSONValue **response)
{
    g_autofree char *url = NULL;
    int responseCode = 0;
    int ret = -1;
    struct curl_slist *headers = NULL;
    struct curl_data data = {0};

    url = g_strdup_printf("%s/%s", URL_ROOT, endpoint);

    VIR_WITH_OBJECT_LOCK_GUARD(mon) {
        /* reset all options of a libcurl session handle at first */
        curl_easy_reset(mon->handle);

        curl_easy_setopt(mon->handle, CURLOPT_UNIX_SOCKET_PATH, mon->socketpath);
        curl_easy_setopt(mon->handle, CURLOPT_URL, url);

        if (response) {
            headers = curl_slist_append(headers, "Accept: application/json");
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(mon->handle, CURLOPT_WRITEFUNCTION, curl_callback);
            curl_easy_setopt(mon->handle, CURLOPT_WRITEDATA, (void *)&data);
        }

        responseCode = virCHMonitorCurlPerform(mon->handle);
    }

    if (responseCode == 200 || responseCode == 204) {
        if (response) {
            data.content = g_realloc(data.content, data.size + 1);
            data.content[data.size] = 0;
            *response = virJSONValueFromString(data.content);
            if (!*response)
                goto cleanup;
        }
        ret = 0;
    }

 cleanup:
    g_free(data.content);
    curl_slist_free_all(headers);
    /* reset the libcurl handle to avoid leaking a stack pointer to data */
    curl_easy_reset(mon->handle);

    return ret;
}

static void
virCHMonitorThreadInfoFree(virCHMonitor *mon)
{
    mon->nthreads = 0;
    VIR_FREE(mon->threads);
}

static size_t
virCHMonitorRefreshThreadInfo(virCHMonitor *mon)
{
    virCHMonitorThreadInfo *info = NULL;
    g_autofree pid_t *tids = NULL;
    virDomainObj *vm = mon->vm;
    size_t ntids = 0;
    size_t i;


    virCHMonitorThreadInfoFree(mon);
    if (virProcessGetPids(vm->pid, &ntids, &tids) < 0)
        return 0;

    info = g_new0(virCHMonitorThreadInfo, ntids);
    for (i = 0; i < ntids; i++) {
        g_autofree char *proc = NULL;
        g_autofree char *data = NULL;

        proc = g_strdup_printf("/proc/%d/task/%d/comm",
                               (int)vm->pid, (int)tids[i]);

        if (virFileReadAll(proc, (1 << 16), &data) < 0) {
            continue;
        }

        VIR_DEBUG("VM PID: %d, TID %d, COMM: %s",
                  (int)vm->pid, (int)tids[i], data);
        if (STRPREFIX(data, "vcpu")) {
            int cpuid;
            char *tmp;

            if (virStrToLong_i(data + 4, &tmp, 0, &cpuid) < 0) {
                VIR_WARN("Index is not specified correctly");
                continue;
            }
            info[i].type = virCHThreadTypeVcpu;
            info[i].vcpuInfo.tid = tids[i];
            info[i].vcpuInfo.online = true;
            info[i].vcpuInfo.cpuid = cpuid;
            VIR_DEBUG("vcpu%d -> tid: %d", cpuid, tids[i]);
        } else if (STRPREFIX(data, "_disk") || STRPREFIX(data, "_net") ||
                   STRPREFIX(data, "_rng")) {
            /* Prefixes used by cloud-hypervisor for IO Threads are captured at
             * https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/vmm/src/device_manager.rs */
            info[i].type = virCHThreadTypeIO;
            info[i].ioInfo.tid = tids[i];
            virStrcpy(info[i].ioInfo.thrName, data, VIRCH_THREAD_NAME_LEN - 1);
        } else {
            info[i].type = virCHThreadTypeEmulator;
            info[i].emuInfo.tid = tids[i];
            virStrcpy(info[i].emuInfo.thrName, data, VIRCH_THREAD_NAME_LEN - 1);
        }
        mon->nthreads++;

    }
    mon->threads = info;

    return mon->nthreads;
}

/**
 * virCHMonitorGetThreadInfo:
 * @mon: Pointer to the monitor
 * @refresh: Refresh thread info or not
 *
 * Retrieve thread info and store to @threads
 *
 * Returns count of threads on success.
 */
size_t
virCHMonitorGetThreadInfo(virCHMonitor *mon,
                          bool refresh,
                          virCHMonitorThreadInfo **threads)
{
    int nthreads = 0;

    if (refresh)
        nthreads = virCHMonitorRefreshThreadInfo(mon);

    *threads = mon->threads;

    return nthreads;
}

int
virCHMonitorShutdownVMM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VMM_SHUTDOWN, NULL);
}

int
virCHMonitorCreateVM(virCHDriver *driver, virCHMonitor *mon)
{
    g_autofree char *url = NULL;
    int responseCode = 0;
    int ret = -1;
    g_autofree char *payload = NULL;
    struct curl_slist *headers = NULL;

    url = g_strdup_printf("%s/%s", URL_ROOT, URL_VM_CREATE);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (virCHMonitorBuildVMJson(driver, mon->vm->def, &payload) != 0)
        return -1;

    VIR_WITH_OBJECT_LOCK_GUARD(mon) {
        /* reset all options of a libcurl session handle at first */
        curl_easy_reset(mon->handle);

        curl_easy_setopt(mon->handle, CURLOPT_UNIX_SOCKET_PATH, mon->socketpath);
        curl_easy_setopt(mon->handle, CURLOPT_URL, url);
        curl_easy_setopt(mon->handle, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(mon->handle, CURLOPT_POSTFIELDS, payload);

        responseCode = virCHMonitorCurlPerform(mon->handle);
    }

    if (responseCode == 200 || responseCode == 204)
        ret = 0;

    curl_slist_free_all(headers);
    return ret;
}

int
virCHMonitorBootVM(virCHMonitor *mon, domainLogContext *logCtxt)
{
    return virCHMonitorPutNoContent(mon, URL_VM_BOOT, logCtxt);
}

int
virCHMonitorShutdownVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_SHUTDOWN, NULL);
}

int
virCHMonitorRebootVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_REBOOT, NULL);
}

int
virCHMonitorSuspendVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_Suspend, NULL);
}

int
virCHMonitorResumeVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_RESUME, NULL);
}

int
virCHMonitorSaveVM(virCHMonitor *mon,
                   const char *to)
{
    g_autofree char *url = NULL;
    int responseCode = 0;
    int ret = -1;
    g_autofree char *payload = NULL;
    g_autofree char *path_url = NULL;
    struct curl_slist *headers = NULL;
    struct curl_data data = {0};

    url = g_strdup_printf("%s/%s", URL_ROOT, URL_VM_SAVE);

    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    path_url = g_strdup_printf("file://%s", to);
    if (virCHMonitorBuildKeyValueStringJson(&payload, "destination_url", path_url) != 0)
        return -1;


    VIR_WITH_OBJECT_LOCK_GUARD(mon) {
        /* reset all options of a libcurl session handle at first */
        curl_easy_reset(mon->handle);

        curl_easy_setopt(mon->handle, CURLOPT_UNIX_SOCKET_PATH, mon->socketpath);
        curl_easy_setopt(mon->handle, CURLOPT_URL, url);
        curl_easy_setopt(mon->handle, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(mon->handle, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(mon->handle, CURLOPT_WRITEFUNCTION, curl_callback);
        curl_easy_setopt(mon->handle, CURLOPT_WRITEDATA, (void *)&data);

        responseCode = virCHMonitorCurlPerform(mon->handle);
    }

    if (responseCode == 200 || responseCode == 204) {
        ret = 0;
    } else {
        data.content = g_realloc(data.content, data.size + 1);
        data.content[data.size] = 0;
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       data.content);
        g_free(data.content);
    }

    /* reset the libcurl handle to avoid leaking a stack pointer to data */
    curl_easy_reset(mon->handle);
    curl_slist_free_all(headers);
    return ret;
}

int
virCHMonitorBuildRestoreJson(virDomainDef *vmdef,
                             const char *from,
                             char **jsonstr)
{
    size_t i;
    g_autoptr(virJSONValue) restore_json = virJSONValueNewObject();
    g_autofree char *path_url = g_strdup_printf("file://%s", from);

    if (virJSONValueObjectAppendString(restore_json, "source_url", path_url))
        return -1;

    /* Pass the netconfig needed to restore with new netfds */
    if (vmdef->nnets) {
        g_autoptr(virJSONValue) nets = virJSONValueNewArray();
        for (i = 0; i < vmdef->nnets; i++) {
            g_autoptr(virJSONValue) net_json = virJSONValueNewObject();
            g_autofree char *id = g_strdup_printf("%s_%zu", CH_NET_ID_PREFIX, i);
            if (virJSONValueObjectAppendString(net_json, "id", id) < 0)
                return -1;
            if (virJSONValueObjectAppendNumberInt(net_json, "num_fds", vmdef->nets[i]->driver.virtio.queues))
                return -1;
            if (virJSONValueArrayAppend(nets, &net_json) < 0)
                return -1;
        }
        if (virJSONValueObjectAppend(restore_json, "net_fds", &nets))
            return -1;
    }

    if (!(*jsonstr = virJSONValueToString(restore_json, false)))
        return -1;

    return 0;
}

/**
 * virCHMonitorGetInfo:
 * @mon: Pointer to the monitor
 * @info: Get VM info
 *
 * Retrieve the VM info and store in @info
 *
 * Returns 0 on success.
 */
int
virCHMonitorGetInfo(virCHMonitor *mon, virJSONValue **info)
{
    return virCHMonitorGet(mon, URL_VM_INFO, info);
}

/**
 * virCHMonitorGetIOThreads:
 * @mon: Pointer to the monitor
 * @iothreads: Location to return array of IOThreadInfo data
 *
 * Retrieve the list of iothreads defined/running for the machine
 *
 * Returns count of IOThreadInfo structures on success
 *        -1 on error.
 */
int
virCHMonitorGetIOThreads(virCHMonitor *mon,
                         virDomainIOThreadInfo ***iothreads)
{
    size_t nthreads = 0;
    int niothreads = 0;
    int thd_index;
    virDomainIOThreadInfo **iothreadinfolist = NULL;
    virDomainIOThreadInfo *iothreadinfo = NULL;

    *iothreads = NULL;
    nthreads = virCHMonitorRefreshThreadInfo(mon);

    iothreadinfolist = g_new0(virDomainIOThreadInfo*, nthreads + 1);

    for (thd_index = 0; thd_index < nthreads; thd_index++) {
        g_autoptr(virBitmap) map = NULL;

        if (mon->threads[thd_index].type == virCHThreadTypeIO) {
            iothreadinfo = g_new0(virDomainIOThreadInfo, 1);

            iothreadinfo->iothread_id = mon->threads[thd_index].ioInfo.tid;

            if (!(map = virProcessGetAffinity(iothreadinfo->iothread_id)))
                goto error;

            virBitmapToData(map, &(iothreadinfo->cpumap), &(iothreadinfo->cpumaplen));

            /* Append to iothreadinfolist */
            iothreadinfolist[niothreads] = g_steal_pointer(&iothreadinfo);
            niothreads++;
        }
    }

    VIR_DEBUG("niothreads = %d", niothreads);
    *iothreads = g_steal_pointer(&iothreadinfolist);
    return niothreads;

 error:
    if (iothreadinfolist) {
        for (thd_index = 0; thd_index < niothreads; thd_index++)
            virDomainIOThreadInfoFree(iothreadinfolist[thd_index]);
        VIR_FREE(iothreadinfolist);
    }
    virDomainIOThreadInfoFree(iothreadinfo);
    return -1;
}
