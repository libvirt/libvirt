/*
 * bhyve_capabilities.c: bhyve capabilities module
 *
 * Copyright (C) 2014 Roman Bogorodskiy
 * Copyright (C) 2014 Semihalf
 * Copyright (C) 2016 Fabian Freyer
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
 *
 */
#include <config.h>
#include <sys/utsname.h>

#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "nodeinfo.h"
#include "bhyve_utils.h"
#include "domain_conf.h"
#include "vircommand.h"
#include "bhyve_capabilities.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_capabilities");

static int
virBhyveCapsInitCPU(virCapsPtr caps,
                  virArch arch)
{
    virCPUDefPtr cpu = NULL;
    virCPUDataPtr data = NULL;
    virNodeInfo nodeinfo;
    int ret = -1;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    cpu->arch = arch;

    if (nodeGetInfo(&nodeinfo))
        goto error;

    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->sockets = nodeinfo.sockets;
    cpu->cores = nodeinfo.cores;
    cpu->threads = nodeinfo.threads;
    caps->host.cpu = cpu;

    if (!(data = cpuNodeData(arch)) ||
        cpuDecode(cpu, data, NULL, 0, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    cpuDataFree(data);

    return ret;

 error:
    virCPUDefFree(cpu);
    goto cleanup;
}

virCapsPtr
virBhyveCapsBuild(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                         VIR_ARCH_X86_64,
                                         "bhyve",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_BHYVE,
                                      NULL, NULL, 0, NULL) == NULL)
        goto error;

    if (virBhyveCapsInitCPU(caps, virArchFromHost()) < 0)
        VIR_WARN("Failed to get host CPU: %s", virGetLastErrorMessage());

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

virDomainCapsPtr
virBhyveDomainCapsBuild(const char *emulatorbin,
                        const char *machine,
                        virArch arch,
                        virDomainVirtType virttype)
{
    virDomainCapsPtr caps = NULL;

    if (!(caps = virDomainCapsNew(emulatorbin, machine, arch, virttype)))
        goto cleanup;

    caps->os.supported = true;
    caps->disk.supported = true;
    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM);

    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.bus,
                             VIR_DOMAIN_DISK_BUS_SATA,
                             VIR_DOMAIN_DISK_BUS_VIRTIO);

 cleanup:
    return caps;
}

int
virBhyveProbeGrubCaps(virBhyveGrubCapsFlags *caps)
{
    char *binary, *help;
    virCommandPtr cmd;
    int ret, exit;

    ret = 0;
    *caps = 0;
    cmd = NULL;
    help = NULL;

    binary = virFindFileInPath("grub-bhyve");
    if (binary == NULL)
        goto out;
    if (!virFileIsExecutable(binary))
        goto out;

    cmd = virCommandNew(binary);
    virCommandAddArg(cmd, "--help");
    virCommandSetOutputBuffer(cmd, &help);
    if (virCommandRun(cmd, &exit) < 0) {
        ret = -1;
        goto out;
    }

    if (strstr(help, "--cons-dev") != NULL)
        *caps |= BHYVE_GRUB_CAP_CONSDEV;

 out:
    VIR_FREE(help);
    virCommandFree(cmd);
    VIR_FREE(binary);
    return ret;
}

static int
bhyveProbeCapsRTC_UTC(unsigned int *caps, char *binary)
{
    char *help;
    virCommandPtr cmd = NULL;
    int ret = 0, exit;

    cmd = virCommandNew(binary);
    virCommandAddArg(cmd, "-h");
    virCommandSetErrorBuffer(cmd, &help);
    if (virCommandRun(cmd, &exit) < 0) {
        ret = -1;
        goto out;
    }

    if (strstr(help, "-u:") != NULL)
        *caps |= BHYVE_CAP_RTC_UTC;

 out:
    VIR_FREE(help);
    virCommandFree(cmd);
    return ret;
}

static int
bhyveProbeCapsAHCI32Slot(unsigned int *caps, char *binary)
{
    char *error;
    virCommandPtr cmd = NULL;
    int ret = 0, exit;

    cmd = virCommandNew(binary);
    virCommandAddArgList(cmd, "-s", "0,ahci", NULL);
    virCommandSetErrorBuffer(cmd, &error);
    if (virCommandRun(cmd, &exit) < 0) {
        ret = -1;
        goto out;
    }

    if (strstr(error, "pci slot 0:0: unknown device \"ahci\"") == NULL)
        *caps |= BHYVE_CAP_AHCI32SLOT;

 out:
    VIR_FREE(error);
    virCommandFree(cmd);
    return ret;
}


int
virBhyveProbeCaps(unsigned int *caps)
{
    char *binary;
    int ret = 0;

    binary = virFindFileInPath("bhyve");
    if (binary == NULL)
        goto out;
    if (!virFileIsExecutable(binary))
        goto out;

    if ((ret = bhyveProbeCapsRTC_UTC(caps, binary)))
        goto out;

    if ((ret = bhyveProbeCapsAHCI32Slot(caps, binary)))
        goto out;

 out:
    VIR_FREE(binary);
    return ret;
}
