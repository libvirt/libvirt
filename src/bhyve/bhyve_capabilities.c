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
#include <dirent.h>
#include <stdio.h>
#include <sys/types.h>

#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "nodeinfo.h"
#include "domain_conf.h"
#include "vircommand.h"
#include "bhyve_capabilities.h"
#include "bhyve_conf.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_capabilities");

static int
virBhyveCapsInitCPU(virCapsPtr caps,
                    virArch arch)
{
    virNodeInfo nodeinfo;

    if (nodeGetInfo(&nodeinfo))
        return -1;

    if (!(caps->host.cpu = virCPUGetHost(arch, VIR_CPU_TYPE_HOST,
                                         &nodeinfo, NULL, 0)))
        return -1;

    return 0;
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

int
virBhyveDomainCapsFill(virDomainCapsPtr caps,
                       unsigned int bhyvecaps,
                       virDomainCapsStringValuesPtr firmwares)
{
    caps->disk.supported = true;
    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM);

    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.bus,
                             VIR_DOMAIN_DISK_BUS_SATA,
                             VIR_DOMAIN_DISK_BUS_VIRTIO);

    caps->os.supported = true;

    if (bhyvecaps & BHYVE_CAP_LPC_BOOTROM) {
        caps->os.loader.supported = true;
        VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.type,
                                 VIR_DOMAIN_LOADER_TYPE_PFLASH);
        VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.readonly,
                                 VIR_TRISTATE_BOOL_YES);

        caps->os.loader.values.values = firmwares->values;
        caps->os.loader.values.nvalues = firmwares->nvalues;
    }


    if (bhyvecaps & BHYVE_CAP_FBUF) {
        caps->graphics.supported = true;
        caps->video.supported = true;
        VIR_DOMAIN_CAPS_ENUM_SET(caps->graphics.type, VIR_DOMAIN_GRAPHICS_TYPE_VNC);
        VIR_DOMAIN_CAPS_ENUM_SET(caps->video.modelType, VIR_DOMAIN_VIDEO_TYPE_GOP);
    }
    return 0;
}


virDomainCapsPtr
virBhyveDomainCapsBuild(bhyveConnPtr conn,
                        const char *emulatorbin,
                        const char *machine,
                        virArch arch,
                        virDomainVirtType virttype)
{
    virDomainCapsPtr caps = NULL;
    unsigned int bhyve_caps = 0;
    DIR *dir;
    struct dirent *entry;
    size_t firmwares_alloc = 0;
    virBhyveDriverConfigPtr cfg = virBhyveDriverGetConfig(conn);
    const char *firmware_dir = cfg->firmwareDir;
    virDomainCapsStringValuesPtr firmwares = NULL;

    if (!(caps = virDomainCapsNew(emulatorbin, machine, arch, virttype)))
        goto cleanup;

    if (virBhyveProbeCaps(&bhyve_caps)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed probing capabilities"));
        goto cleanup;
    }

    if (VIR_ALLOC(firmwares) < 0)
        goto cleanup;

    if (virDirOpenIfExists(&dir, firmware_dir) > 0) {
        while ((virDirRead(dir, &entry, firmware_dir)) > 0) {
            if (VIR_RESIZE_N(firmwares->values,
                firmwares_alloc, firmwares->nvalues, 1) < 0)
                goto cleanup;

            if (virAsprintf(
                    &firmwares->values[firmwares->nvalues],
                    "%s/%s", firmware_dir, entry->d_name) < 0)
                goto cleanup;

            firmwares->nvalues++;
        }
    } else {
        VIR_WARN("Cannot open firmware directory %s", firmware_dir);
    }

    if (virBhyveDomainCapsFill(caps, bhyve_caps, firmwares) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(firmwares);
    VIR_DIR_CLOSE(dir);
    virObjectUnref(cfg);
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

static int
bhyveProbeCapsNetE1000(unsigned int *caps, char *binary)
{
    char *error;
    virCommandPtr cmd = NULL;
    int ret = -1, exit;

    cmd = virCommandNew(binary);
    virCommandAddArgList(cmd, "-s", "0,e1000", NULL);
    virCommandSetErrorBuffer(cmd, &error);
    if (virCommandRun(cmd, &exit) < 0)
        goto cleanup;

    if (strstr(error, "pci slot 0:0: unknown device \"e1000\"") == NULL)
        *caps |= BHYVE_CAP_NET_E1000;

    ret = 0;
 cleanup:
    VIR_FREE(error);
    virCommandFree(cmd);
    return ret;
}

static int
bhyveProbeCapsLPC_Bootrom(unsigned int *caps, char *binary)
{
    char *error;
    virCommandPtr cmd = NULL;
    int ret = -1, exit;

    cmd = virCommandNew(binary);
    virCommandAddArgList(cmd, "-l", "bootrom", NULL);
    virCommandSetErrorBuffer(cmd, &error);
    if (virCommandRun(cmd, &exit) < 0)
        goto cleanup;

    if (strstr(error, "bhyve: invalid lpc device configuration 'bootrom'") == NULL)
        *caps |= BHYVE_CAP_LPC_BOOTROM;

    ret = 0;
 cleanup:
    VIR_FREE(error);
    virCommandFree(cmd);
    return ret;
}


static int
bhyveProbeCapsFramebuffer(unsigned int *caps, char *binary)
{
    char *error;
    virCommandPtr cmd = NULL;
    int ret = -1, exit;

    cmd = virCommandNew(binary);
    virCommandAddArgList(cmd, "-s", "0,fbuf", NULL);
    virCommandSetErrorBuffer(cmd, &error);
    if (virCommandRun(cmd, &exit) < 0)
        goto cleanup;

    if (strstr(error, "pci slot 0:0: unknown device \"fbuf\"") == NULL)
        *caps |= BHYVE_CAP_FBUF;

    ret = 0;
 cleanup:
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

    if ((ret = bhyveProbeCapsNetE1000(caps, binary)))
        goto out;

    if ((ret = bhyveProbeCapsLPC_Bootrom(caps, binary)))
        goto out;

    if ((ret = bhyveProbeCapsFramebuffer(caps, binary)))
        goto out;

 out:
    VIR_FREE(binary);
    return ret;
}
