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

#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>

#include "ch_monitor.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virjson.h"
#include "virlog.h"
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
int virCHMonitorPutNoContent(virCHMonitor *mon, const char *endpoint);

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
virCHMonitorBuildPTYJson(virJSONValue *content, virDomainDef *vmdef)
{
    if (vmdef->nconsoles) {
        g_autoptr(virJSONValue) pty = virJSONValueNewObject();
        if (virJSONValueObjectAppendString(pty, "mode", "Pty") < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "console", &pty) < 0)
            return -1;
    }

    if (vmdef->nserials) {
        g_autoptr(virJSONValue) pty = virJSONValueNewObject();
        if (virJSONValueObjectAppendString(pty, "mode", "Pty") < 0)
            return -1;
        if (virJSONValueObjectAppend(content, "serial", &pty) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildPayloadJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) payload = virJSONValueNewObject();


    if (vmdef->os.kernel == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Kernel image path in this domain is not defined"));
        return -1;
    } else {
        if (virJSONValueObjectAppendString(payload, "kernel", vmdef->os.kernel) < 0)
            return -1;
    }

    if (vmdef->os.cmdline) {
        if (virJSONValueObjectAppendString(payload, "cmdline", vmdef->os.cmdline) < 0)
            return -1;
    }

    if (vmdef->os.initrd != NULL) {
        if (virJSONValueObjectAppendString(payload, "initramfs", vmdef->os.initrd) < 0)
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

static int
virCHMonitorBuildDiskJson(virJSONValue *disks, virDomainDiskDef *diskdef)
{
    g_autoptr(virJSONValue) disk = virJSONValueNewObject();

    if (!diskdef->src)
        return -1;

    switch (diskdef->src->type) {
    case VIR_STORAGE_TYPE_FILE:
        if (!diskdef->src->path) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Missing disk file path in domain"));
            return -1;
        }
        if (diskdef->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Only virtio bus types are supported for '%1$s'"),
                           diskdef->src->path);
            return -1;
        }
        if (virJSONValueObjectAppendString(disk, "path", diskdef->src->path) < 0)
            return -1;
        if (diskdef->src->readonly) {
            if (virJSONValueObjectAppendBoolean(disk, "readonly", true) < 0)
                return -1;
        }
        if (virJSONValueArrayAppend(disks, &disk) < 0)
            return -1;

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
        return -1;
    }

    return 0;
}

static int
virCHMonitorBuildDisksJson(virJSONValue *content, virDomainDef *vmdef)
{
    g_autoptr(virJSONValue) disks = NULL;
    size_t i;

    if (vmdef->ndisks > 0) {
        disks = virJSONValueNewArray();

        for (i = 0; i < vmdef->ndisks; i++) {
            if (virCHMonitorBuildDiskJson(disks, vmdef->disks[i]) < 0)
                return -1;
        }
        if (virJSONValueObjectAppend(content, "disks", &disks) < 0)
            return -1;
    }

    return 0;
}

static int
virCHMonitorBuildNetJson(virJSONValue *nets,
                         virDomainNetDef *netdef,
                         size_t *nnicindexes,
                         int **nicindexes)
{
    virDomainNetType netType = virDomainNetGetActualType(netdef);
    char macaddr[VIR_MAC_STRING_BUFLEN];
    g_autoptr(virJSONValue) net = NULL;

    // check net type at first
    net = virJSONValueNewObject();

    switch (netType) {
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (netdef->guestIP.nips == 1) {
                const virNetDevIPAddr *ip = netdef->guestIP.ips[0];
                g_autofree char *addr = NULL;
                virSocketAddr netmask;
                g_autofree char *netmaskStr = NULL;

                if (!(addr = virSocketAddrFormat(&ip->address)))
                    return -1;
                if (virJSONValueObjectAppendString(net, "ip", addr) < 0)
                    return -1;

                if (virSocketAddrPrefixToNetmask(ip->prefix, &netmask, AF_INET) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Failed to translate net prefix %1$d to netmask"),
                                   ip->prefix);
                    return -1;
                }
                if (!(netmaskStr = virSocketAddrFormat(&netmask)))
                    return -1;
                if (virJSONValueObjectAppendString(net, "mask", netmaskStr) < 0)
                    return -1;
            } else if (netdef->guestIP.nips > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("ethernet type supports a single guest ip"));
            }

            /* network and bridge use a tap device, and direct uses a
             * macvtap device
             */
            if (nicindexes && nnicindexes && netdef->ifname) {
                int nicindex = 0;

                if (virNetDevGetIndex(netdef->ifname, &nicindex) < 0)
                    return -1;

                VIR_APPEND_ELEMENT(*nicindexes, *nnicindexes, nicindex);
            }
            break;
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
            if ((virDomainChrType)netdef->data.vhostuser->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vhost_user type support UNIX socket in this CH"));
                return -1;
            } else {
                if (virJSONValueObjectAppendString(net, "vhost_socket", netdef->data.vhostuser->data.nix.path) < 0)
                    return -1;
                if (virJSONValueObjectAppendBoolean(net, "vhost_user", true) < 0)
                    return -1;
            }
            break;
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_DIRECT:
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainNetType, netType);
            return -1;
    }

    if (netdef->ifname != NULL) {
        if (virJSONValueObjectAppendString(net, "tap", netdef->ifname) < 0)
            return -1;
    }
    if (virJSONValueObjectAppendString(net, "mac", virMacAddrFormat(&netdef->mac, macaddr)) < 0)
        return -1;


    if (netdef->virtio != NULL) {
        if (netdef->virtio->iommu == VIR_TRISTATE_SWITCH_ON) {
            if (virJSONValueObjectAppendBoolean(net, "iommu", true) < 0)
                return -1;
        }
    }
    if (netdef->driver.virtio.queues) {
        if (virJSONValueObjectAppendNumberInt(net, "num_queues", netdef->driver.virtio.queues) < 0)
            return -1;
    }

    if (netdef->driver.virtio.rx_queue_size || netdef->driver.virtio.tx_queue_size) {
        if (netdef->driver.virtio.rx_queue_size != netdef->driver.virtio.tx_queue_size) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
               _("virtio rx_queue_size option %1$d is not same with tx_queue_size %2$d"),
               netdef->driver.virtio.rx_queue_size,
               netdef->driver.virtio.tx_queue_size);
            return -1;
        }
        if (virJSONValueObjectAppendNumberInt(net, "queue_size", netdef->driver.virtio.rx_queue_size) < 0)
            return -1;
    }

    if (virJSONValueArrayAppend(nets, &net) < 0)
        return -1;

    return 0;
}

static int
virCHMonitorBuildNetsJson(virJSONValue *content,
                          virDomainDef *vmdef,
                          size_t *nnicindexes,
                          int **nicindexes)
{
    g_autoptr(virJSONValue) nets = NULL;
    size_t i;

    if (vmdef->nnets > 0) {
        nets = virJSONValueNewArray();

        for (i = 0; i < vmdef->nnets; i++) {
            if (virCHMonitorBuildNetJson(nets, vmdef->nets[i],
                                         nnicindexes, nicindexes) < 0)
                return -1;
        }
        if (virJSONValueObjectAppend(content, "net", &nets) < 0)
            return -1;
    }

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
virCHMonitorBuildVMJson(virCHDriver *driver,
                        virDomainDef *vmdef,
                        char **jsonstr,
                        size_t *nnicindexes,
                        int **nicindexes)
{
    g_autoptr(virJSONValue) content = virJSONValueNewObject();

    if (vmdef == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VM is not defined"));
        return -1;
    }

    if (virCHMonitorBuildPTYJson(content, vmdef) < 0)
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


    if (virCHMonitorBuildDisksJson(content, vmdef) < 0)
        return -1;


    if (virCHMonitorBuildNetsJson(content, vmdef, nnicindexes, nicindexes) < 0)
        return -1;

    if (virCHMonitorBuildDevicesJson(content, vmdef) < 0)
        return -1;

    if (!(*jsonstr = virJSONValueToString(content, false)))
        return -1;

    return 0;
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
virCHMonitorNew(virDomainObj *vm, const char *socketdir)
{
    g_autoptr(virCHMonitor) mon = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int socket_fd = 0;

    if (virCHMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(virCHMonitorClass)))
        return NULL;

    if (!vm->def) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VM is not defined"));
        return NULL;
    }

    /* prepare to launch Cloud-Hypervisor socket */
    mon->socketpath = g_strdup_printf("%s/%s-socket", socketdir, vm->def->name);
    if (g_mkdir_with_parents(socketdir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Cannot create socket directory '%1$s'"),
                             socketdir);
        return NULL;
    }

    cmd = virCommandNew(vm->def->emulator);
    virCommandSetUmask(cmd, 0x002);
    socket_fd = chMonitorCreateSocket(mon->socketpath);
    if (socket_fd < 0) {
        virReportSystemError(errno,
                             _("Cannot create socket '%1$s'"),
                             mon->socketpath);
        return NULL;
    }

    virCommandAddArg(cmd, "--api-socket");
    virCommandAddArgFormat(cmd, "fd=%d", socket_fd);
    virCommandPassFD(cmd, socket_fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);

    /* launch Cloud-Hypervisor socket */
    if (virCommandRunAsync(cmd, &mon->pid) < 0)
        return NULL;

    /* get a curl handle */
    mon->handle = curl_easy_init();

    /* now has its own reference */
    mon->vm = virObjectRef(vm);

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

    if (mon->pid > 0) {
        /* try cleaning up the Cloud-Hypervisor process */
        virProcessAbort(mon->pid);
        mon->pid = 0;
    }

    if (mon->handle)
        curl_easy_cleanup(mon->handle);

    if (mon->socketpath) {
        if (virFileRemove(mon->socketpath, -1, -1) < 0) {
            VIR_WARN("Unable to remove CH socket file '%s'",
                     mon->socketpath);
        }
        g_free(mon->socketpath);
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

int
virCHMonitorPutNoContent(virCHMonitor *mon, const char *endpoint)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(mon);
    g_autofree char *url = NULL;
    int responseCode = 0;
    int ret = -1;

    url = g_strdup_printf("%s/%s", URL_ROOT, endpoint);

    /* reset all options of a libcurl session handle at first */
    curl_easy_reset(mon->handle);

    curl_easy_setopt(mon->handle, CURLOPT_UNIX_SOCKET_PATH, mon->socketpath);
    curl_easy_setopt(mon->handle, CURLOPT_URL, url);
    curl_easy_setopt(mon->handle, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(mon->handle, CURLOPT_HTTPHEADER, NULL);

    responseCode = virCHMonitorCurlPerform(mon->handle);

    if (responseCode == 200 || responseCode == 204)
        ret = 0;

    return ret;
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
    return virCHMonitorPutNoContent(mon, URL_VMM_SHUTDOWN);
}

int
virCHMonitorCreateVM(virCHDriver *driver,
                     virCHMonitor *mon,
                     size_t *nnicindexes,
                     int **nicindexes)
{
    g_autofree char *url = NULL;
    int responseCode = 0;
    int ret = -1;
    g_autofree char *payload = NULL;
    struct curl_slist *headers = NULL;

    url = g_strdup_printf("%s/%s", URL_ROOT, URL_VM_CREATE);
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (virCHMonitorBuildVMJson(driver, mon->vm->def, &payload,
                                nnicindexes, nicindexes) != 0)
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
virCHMonitorBootVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_BOOT);
}

int
virCHMonitorShutdownVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_SHUTDOWN);
}

int
virCHMonitorRebootVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_REBOOT);
}

int
virCHMonitorSuspendVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_Suspend);
}

int
virCHMonitorResumeVM(virCHMonitor *mon)
{
    return virCHMonitorPutNoContent(mon, URL_VM_RESUME);
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

            if (virBitmapToData(map, &(iothreadinfo->cpumap),
                                &(iothreadinfo->cpumaplen)) < 0) {
                goto error;
            }

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
