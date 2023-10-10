/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_domain.c: Domain manager functions for Cloud-Hypervisor driver
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

#include "ch_domain.h"
#include "domain_driver.h"
#include "virchrdev.h"
#include "virlog.h"
#include "virtime.h"
#include "virsystemd.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_domain");

void
virCHDomainRemoveInactive(virCHDriver *driver,
                          virDomainObj *vm)
{
    if (vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
    }
}

static void *
virCHDomainObjPrivateAlloc(void *opaque)
{
    virCHDomainObjPrivate *priv;

    priv = g_new0(virCHDomainObjPrivate, 1);

    if (!(priv->chrdevs = virChrdevAlloc())) {
        g_free(priv);
        return NULL;
    }
    priv->driver = opaque;

    return priv;
}

static void
virCHDomainObjPrivateFree(void *data)
{
    virCHDomainObjPrivate *priv = data;

    virChrdevFree(priv->chrdevs);
    g_free(priv->machineName);
    g_free(priv);
}

static int
virCHDomainDefPostParseBasic(virDomainDef *def,
                             void *opaque G_GNUC_UNUSED)
{
    /* check for emulator and create a default one if needed */
    if (!def->emulator) {
        if (!(def->emulator = g_find_program_in_path(CH_CMD))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("No emulator found for cloud-hypervisor"));
            return 1;
        }
    }

    return 0;
}

static virClass *virCHDomainVcpuPrivateClass;

static void
virCHDomainVcpuPrivateDispose(void *obj G_GNUC_UNUSED)
{
}

static int
virCHDomainVcpuPrivateOnceInit(void)
{
    if (!VIR_CLASS_NEW(virCHDomainVcpuPrivate, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virCHDomainVcpuPrivate);

static virObject *
virCHDomainVcpuPrivateNew(void)
{
    virCHDomainVcpuPrivate *priv;

    if (virCHDomainVcpuPrivateInitialize() < 0)
        return NULL;

    if (!(priv = virObjectNew(virCHDomainVcpuPrivateClass)))
        return NULL;

    return (virObject *) priv;
}


static int
virCHDomainDefPostParse(virDomainDef *def,
                        unsigned int parseFlags G_GNUC_UNUSED,
                        void *opaque,
                        void *parseOpaque G_GNUC_UNUSED)
{
    virCHDriver *driver = opaque;
    g_autoptr(virCaps) caps = virCHDriverGetCapabilities(driver, false);
    if (!caps)
        return -1;
    if (!virCapabilitiesDomainSupported(caps, def->os.type,
                                        def->os.arch,
                                        def->virtType))
        return -1;

    return 0;
}

virDomainXMLPrivateDataCallbacks virCHDriverPrivateDataCallbacks = {
    .alloc = virCHDomainObjPrivateAlloc,
    .free = virCHDomainObjPrivateFree,
    .vcpuNew = virCHDomainVcpuPrivateNew,
};

static int
chValidateDomainDeviceDef(const virDomainDeviceDef *dev,
                          const virDomainDef *def,
                          void *opaque,
                          void *parseOpaque G_GNUC_UNUSED)
{
    virCHDriver *driver = opaque;
    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_CHR:
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cloud-Hypervisor doesn't support '%1$s' device"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;

    case VIR_DOMAIN_DEVICE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected VIR_DOMAIN_DEVICE_NONE"));
        return -1;

    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceType, dev->type);
        return -1;
    }

    if (!virBitmapIsBitSet(driver->chCaps, CH_SERIAL_CONSOLE_IN_PARALLEL)) {
        if ((def->nconsoles &&
                def->consoles[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY)
            && (def->nserials &&
                def->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only a single console or serial can be configured for this domain"));
            return -1;
        }
    }


    if (def->nconsoles > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only a single console can be configured for this domain"));
        return -1;
    }

    if (def->nserials > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only a single serial can be configured for this domain"));
        return -1;
    }

    if (def->nconsoles && def->consoles[0]->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Console can only be enabled for a PTY"));
        return -1;
    }

    if (def->nserials && def->serials[0]->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Serial can only be enabled for a PTY"));
        return -1;
    }
    return 0;
}

int
virCHDomainRefreshThreadInfo(virDomainObj *vm)
{
    unsigned int maxvcpus = virDomainDefGetVcpusMax(vm->def);
    virCHMonitorThreadInfo *info = NULL;
    size_t nthreads;
    size_t ncpus = 0;
    size_t i;

    nthreads = virCHMonitorGetThreadInfo(virCHDomainGetMonitor(vm),
                                         true, &info);

    for (i = 0; i < nthreads; i++) {
        virCHDomainVcpuPrivate *vcpupriv;
        virDomainVcpuDef *vcpu;
        virCHMonitorCPUInfo *vcpuInfo;

        if (info[i].type != virCHThreadTypeVcpu)
            continue;

        /* TODO: hotplug support */
        vcpuInfo = &info[i].vcpuInfo;
        vcpu = virDomainDefGetVcpu(vm->def, vcpuInfo->cpuid);
        vcpupriv = CH_DOMAIN_VCPU_PRIVATE(vcpu);
        vcpupriv->tid = vcpuInfo->tid;
        ncpus++;
    }

    /* TODO: Remove the warning when hotplug is implemented.*/
    if (ncpus != maxvcpus)
        VIR_WARN("Mismatch in the number of cpus, expected: %u, actual: %zu",
                 maxvcpus, ncpus);

    return 0;
}

virDomainDefParserConfig virCHDriverDomainDefParserConfig = {
    .domainPostParseBasicCallback = virCHDomainDefPostParseBasic,
    .domainPostParseCallback = virCHDomainDefPostParse,
    .deviceValidateCallback = chValidateDomainDeviceDef,
    .features = VIR_DOMAIN_DEF_FEATURE_NO_STUB_CONSOLE,
};

virCHMonitor *
virCHDomainGetMonitor(virDomainObj *vm)
{
    return CH_DOMAIN_PRIVATE(vm)->monitor;
}

pid_t
virCHDomainGetVcpuPid(virDomainObj *vm,
                      unsigned int vcpuid)
{
    virDomainVcpuDef *vcpu = virDomainDefGetVcpu(vm->def, vcpuid);

    return CH_DOMAIN_VCPU_PRIVATE(vcpu)->tid;
}

bool
virCHDomainHasVcpuPids(virDomainObj *vm)
{
    size_t i;
    size_t maxvcpus = virDomainDefGetVcpusMax(vm->def);
    virDomainVcpuDef *vcpu;

    for (i = 0; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);

        if (CH_DOMAIN_VCPU_PRIVATE(vcpu)->tid > 0)
            return true;
    }

    return false;
}

char *
virCHDomainGetMachineName(virDomainObj *vm)
{
    virCHDomainObjPrivate *priv = CH_DOMAIN_PRIVATE(vm);
    virCHDriver *driver = priv->driver;
    char *ret = NULL;

    if (vm->pid != 0) {
        ret = virSystemdGetMachineNameByPID(vm->pid);
        if (!ret)
            virResetLastError();
    }

    if (!ret)
        ret = virDomainDriverGenerateMachineName("ch",
                                                 NULL,
                                                 vm->def->id, vm->def->name,
                                                 driver->privileged);

    return ret;
}

/**
 * virCHDomainObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be released by calling virDomainObjEndAPI().
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
virDomainObj *
virCHDomainObjFromDomain(virDomainPtr domain)
{
    virDomainObj *vm;
    virCHDriver *driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}
