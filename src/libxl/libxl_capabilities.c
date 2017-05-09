/*
 * libxl_capabilities.c: libxl capabilities generation
 *
 * Copyright (C) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Jim Fehlig <jfehlig@suse.com>
 */

#include <config.h>

#include <libxl.h>
#include <regex.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
#include "virstring.h"
#include "domain_conf.h"
#include "capabilities.h"
#include "domain_capabilities.h"
#include "vircommand.h"
#include "libxl_capabilities.h"
#include "cpu/cpu_x86.h"
#include "cpu/cpu_x86_data.h"


#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_capabilities");

/* see xen-unstable.hg/xen/include/asm-x86/cpufeature.h */
#define LIBXL_X86_FEATURE_PAE_MASK (1 << 6)
#define LIBXL_X86_FEATURE_LM_MASK  (1 << 29)

enum libxlHwcapVersion {
    LIBXL_HWCAP_V0 = 0,    /* for Xen 4.4 .. 4.6 */
    LIBXL_HWCAP_V1,        /* for Xen 4.7 and up */
};

struct guest_arch {
    virArch arch;
    int bits;
    int hvm;
    int pae;
    int nonpae;
    int ia64_be;
};

#define XEN_CAP_REGEX "(xen|hvm)-[[:digit:]]+\\.[[:digit:]]+-(aarch64|armv7l|x86_32|x86_64|ia64|powerpc64)(p|be)?"

static int
libxlCapsAddCPUID(virCPUDataPtr data, virCPUx86CPUID *cpuid, ssize_t ncaps)
{
    size_t i;

    for (i = 0; i < ncaps; i++) {
        virCPUx86CPUID *c = &cpuid[i];

        if (virCPUx86DataAddCPUID(data, c) < 0) {
            VIR_DEBUG("Failed to add CPUID(%x,%x)", c->eax_in, c->ecx_in);
            return -1;
        }
    }

    return 0;
}

/*
 * The words represented in physinfo.hw_cap are host CPUID (sub) leafs.
 * Position of these hasn't changed much up until Xen 4.7 with a rework
 * on how CPUID is handled internally. As a side-effect it got normalized
 * and also added more feature words. Although cannot be relied upon as
 * stable interface, and hence we version changes in position of the features
 * across all supported versions of the libxl driver until libxl exposes a
 * stable representation of these capabilities. Fortunately not a lot of
 * variation happened so it's still trivial to keep track of these leafs
 * to describe host CPU in libvirt capabilities. v0 stands for Xen 4.4
 * up to 4.6, while v1 is meant for Xen 4.7, as depicted in the table below:
 *
 *              | v0 (Xen 4.4 - 4.6) |   v1 (Xen >= 4.7)    |
 *              ---------------------------------------------
 *       word 0 | CPUID.00000001.EDX | CPUID.00000001.EDX   |
 *       word 1 | CPUID.80000001.EDX | CPUID.00000001.ECX   |
 *       word 2 | CPUID.80860001     | CPUID.80000001.EDX   |
 *       word 3 | -     Linux    -   | CPUID.80000001.ECX   |
 *       word 4 | CPUID.00000001.ECX | CPUID.0000000D:1.EAX |
 *       word 5 | CPUID.C0000001     | CPUID.00000007:0.EBX |
 *       word 6 | CPUID.80000001.ECX | CPUID.00000007:0.ECX |
 *       word 7 | CPUID.00000007.EBX | CPUID.80000007.EDX   |
 *       word 8 | - Non existent -   | CPUID.80000008.EBX   |
 *
 */
static virCPUDataPtr
libxlCapsNodeData(virCPUDefPtr cpu, libxl_hwcap hwcap,
                  enum libxlHwcapVersion version)
{
    ssize_t ncaps;
    virCPUDataPtr cpudata = NULL;
    virCPUx86CPUID cpuid[] = {
        { .eax_in = 0x00000001,
          .edx = hwcap[0] },
        { .eax_in = 0x00000001,
          .ecx = (version > LIBXL_HWCAP_V0 ? hwcap[1] : hwcap[4]) },
        { .eax_in = 0x80000001,
          .edx = (version > LIBXL_HWCAP_V0 ? hwcap[2] : hwcap[1]) },
        { .eax_in = 0x80000001,
          .ecx = (version > LIBXL_HWCAP_V0 ? hwcap[3] : hwcap[6]) },
        { .eax_in = 0x00000007,
          .ebx = (version > LIBXL_HWCAP_V0 ? hwcap[5] : hwcap[7]) },
    };
    virCPUx86CPUID cpuid_ver1[] = {
        { .eax_in = 0x0000000D, .ecx_in = 1U, .eax = hwcap[4] },
        { .eax_in = 0x00000007, .ecx_in = 0U, .ecx = hwcap[6] },
        { .eax_in = 0x80000007, .ecx_in = 0U, .edx = hwcap[7] },
    };

    if (!(cpudata = virCPUDataNew(cpu->arch)))
        goto error;

    ncaps = ARRAY_CARDINALITY(cpuid);
    if (libxlCapsAddCPUID(cpudata, cpuid, ncaps) < 0)
        goto error;

    ncaps = ARRAY_CARDINALITY(cpuid_ver1);
    if (version > LIBXL_HWCAP_V0 &&
        libxlCapsAddCPUID(cpudata, cpuid_ver1, ncaps) < 0)
        goto error;

    return cpudata;

 error:
    virCPUDataFree(cpudata);
    return NULL;
}

/* hw_caps is an array of 32-bit words whose meaning is listed in
 * xen-unstable.hg/xen/include/asm-x86/cpufeature.h.  Each feature
 * is defined in the form X*32+Y, corresponding to the Y'th bit in
 * the X'th 32-bit word of hw_cap.
 */
static int
libxlCapsInitCPU(virCapsPtr caps, libxl_physinfo *phy_info,
                 enum libxlHwcapVersion version)
{
    virCPUDataPtr data = NULL;
    virCPUDefPtr cpu = NULL;
    int ret = -1;
    int host_pae;
    int host_lm;

    /* On ARM hw_cap vector is zeroed out but not on x86 */
    if (!phy_info->hw_cap[0])
        return 0;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    host_pae = phy_info->hw_cap[0] & LIBXL_X86_FEATURE_PAE_MASK;
    if (host_pae &&
        virCapabilitiesAddHostFeature(caps, "pae") < 0)
        goto error;

    host_lm = (phy_info->hw_cap[version > LIBXL_HWCAP_V0 ? 2 : 1]
                & LIBXL_X86_FEATURE_LM_MASK);
    if (host_lm)
        cpu->arch = VIR_ARCH_X86_64;
    else
        cpu->arch = VIR_ARCH_I686;

    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->cores = phy_info->cores_per_socket;
    cpu->threads = phy_info->threads_per_core;
    cpu->sockets = phy_info->nr_cpus / (cpu->cores * cpu->threads);
    caps->host.cpu = cpu;

    ret = 0;

    if (!(data = libxlCapsNodeData(cpu, phy_info->hw_cap, version)) ||
        cpuDecode(cpu, data, NULL, 0, NULL) < 0) {
        VIR_WARN("Failed to initialize host cpu features");
        goto error;
    }

 cleanup:
    virCPUDataFree(data);

    return ret;

 error:
    virCPUDefFree(cpu);
    goto cleanup;
}

static int
libxlCapsInitHost(libxl_ctx *ctx, virCapsPtr caps)
{
    const libxl_version_info *ver_info;
    enum libxlHwcapVersion version;
    libxl_physinfo phy_info;
    int ret = -1;

    libxl_physinfo_init(&phy_info);
    if (libxl_get_physinfo(ctx, &phy_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get node physical info from libxenlight"));
        goto cleanup;
    }

    if ((ver_info = libxl_get_version_info(ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get version info from libxenlight"));
        goto cleanup;
    }

    version = (ver_info->xen_version_minor >= 7);
    if (libxlCapsInitCPU(caps, &phy_info, version) < 0)
        goto cleanup;

    if (virCapabilitiesSetNetPrefix(caps, LIBXL_GENERATED_PREFIX_XEN) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    libxl_physinfo_dispose(&phy_info);
    return ret;
}

static int
libxlCapsInitNuma(libxl_ctx *ctx, virCapsPtr caps)
{
    libxl_numainfo *numa_info = NULL;
    libxl_cputopology *cpu_topo = NULL;
    int nr_nodes = 0, nr_cpus = 0, nr_siblings = 0;
    virCapsHostNUMACellCPUPtr *cpus = NULL;
    virCapsHostNUMACellSiblingInfoPtr siblings = NULL;
    int *nr_cpus_node = NULL;
    size_t i;
    int ret = -1;

    /* Let's try to fetch all the topology information */
    numa_info = libxl_get_numainfo(ctx, &nr_nodes);
    if (numa_info == NULL || nr_nodes == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_numainfo failed"));
        goto cleanup;
    } else {
        cpu_topo = libxl_get_cpu_topology(ctx, &nr_cpus);
        if (cpu_topo == NULL || nr_cpus == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("libxl_get_cpu_topology failed"));
            goto cleanup;
        }
    }

    if (VIR_ALLOC_N(cpus, nr_nodes) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(nr_cpus_node, nr_nodes) < 0)
        goto cleanup;

    /* For each node, prepare a list of CPUs belonging to that node */
    for (i = 0; i < nr_cpus; i++) {
        int node = cpu_topo[i].node;

        if (cpu_topo[i].core == LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
            continue;

        nr_cpus_node[node]++;

        if (nr_cpus_node[node] == 1) {
            if (VIR_ALLOC(cpus[node]) < 0)
                goto cleanup;
        } else {
            if (VIR_REALLOC_N(cpus[node], nr_cpus_node[node]) < 0)
                goto cleanup;
        }

        /* Mapping between what libxl tells and what libvirt wants */
        cpus[node][nr_cpus_node[node]-1].id = i;
        cpus[node][nr_cpus_node[node]-1].socket_id = cpu_topo[i].socket;
        cpus[node][nr_cpus_node[node]-1].core_id = cpu_topo[i].core;
        /* Allocate the siblings maps. We will be filling them later */
        cpus[node][nr_cpus_node[node]-1].siblings = virBitmapNew(nr_cpus);
        if (!cpus[node][nr_cpus_node[node]-1].siblings) {
            virReportOOMError();
            goto cleanup;
        }
    }

    /* Let's now populate the siblings bitmaps */
    for (i = 0; i < nr_cpus; i++) {
        int node = cpu_topo[i].node;
        size_t j;

        if (cpu_topo[i].core == LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
            continue;

        for (j = 0; j < nr_cpus_node[node]; j++) {
            if (cpus[node][j].socket_id == cpu_topo[i].socket &&
                cpus[node][j].core_id == cpu_topo[i].core)
                ignore_value(virBitmapSetBit(cpus[node][j].siblings, i));
        }
    }

    for (i = 0; i < nr_nodes; i++) {
        if (numa_info[i].size == LIBXL_NUMAINFO_INVALID_ENTRY)
            continue;

        nr_siblings = numa_info[i].num_dists;
        if (nr_siblings) {
            size_t j;

            if (VIR_ALLOC_N(siblings, nr_siblings) < 0)
                goto cleanup;

            for (j = 0; j < nr_siblings; j++) {
                siblings[j].node = j;
                siblings[j].distance = numa_info[i].dists[j];
            }
        }

        if (virCapabilitiesAddHostNUMACell(caps, i,
                                           numa_info[i].size / 1024,
                                           nr_cpus_node[i], cpus[i],
                                           nr_siblings, siblings,
                                           0, NULL) < 0) {
            virCapabilitiesClearHostNUMACellCPUTopology(cpus[i],
                                                        nr_cpus_node[i]);
            goto cleanup;
        }

        /* This is safe, as the CPU list is now stored in the NUMA cell */
        cpus[i] = NULL;
    }

    ret = 0;

 cleanup:
    if (ret != 0) {
        for (i = 0; cpus && i < nr_nodes; i++)
            VIR_FREE(cpus[i]);
        virCapabilitiesFreeNUMAInfo(caps);
        VIR_FREE(siblings);
    }

    VIR_FREE(cpus);
    VIR_FREE(nr_cpus_node);
    libxl_cputopology_list_free(cpu_topo, nr_cpus);
    libxl_numainfo_list_free(numa_info, nr_nodes);

    return ret;
}

static int
libxlCapsInitGuests(libxl_ctx *ctx, virCapsPtr caps)
{
    const libxl_version_info *ver_info;
    int err;
    regex_t regex;
    char *str, *token;
    regmatch_t subs[4];
    char *saveptr = NULL;
    size_t i;

    struct guest_arch guest_archs[32];
    int nr_guest_archs = 0;

    memset(guest_archs, 0, sizeof(guest_archs));

    if ((ver_info = libxl_get_version_info(ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get version info from libxenlight"));
        return -1;
    }

    if (!ver_info->capabilities) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get capabilities from libxenlight"));
        return -1;
    }

    err = regcomp(&regex, XEN_CAP_REGEX, REG_EXTENDED);
    if (err != 0) {
        char error[100];
        regerror(err, &regex, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %s"), error);
        return -1;
    }

    /* Format of capabilities string is documented in the code in
     * xen-unstable.hg/xen/arch/.../setup.c.
     *
     * It is a space-separated list of supported guest architectures.
     *
     * For x86:
     *    TYP-VER-ARCH[p]
     *    ^   ^   ^    ^
     *    |   |   |    +-- PAE supported
     *    |   |   +------- x86_32 or x86_64
     *    |   +----------- the version of Xen, eg. "3.0"
     *    +--------------- "xen" or "hvm" for para or full virt respectively
     *
     * For IA64:
     *    TYP-VER-ARCH[be]
     *    ^   ^   ^    ^
     *    |   |   |    +-- Big-endian supported
     *    |   |   +------- always "ia64"
     *    |   +----------- the version of Xen, eg. "3.0"
     *    +--------------- "xen" or "hvm" for para or full virt respectively
     */

    /* Split capabilities string into tokens. strtok_r is OK here because
     * we "own" the buffer.  Parse out the features from each token.
     */
    for (str = ver_info->capabilities, nr_guest_archs = 0;
         nr_guest_archs < sizeof(guest_archs) / sizeof(guest_archs[0])
                 && (token = strtok_r(str, " ", &saveptr)) != NULL;
         str = NULL) {
        if (regexec(&regex, token, sizeof(subs) / sizeof(subs[0]),
                    subs, 0) == 0) {
            int hvm = STRPREFIX(&token[subs[1].rm_so], "hvm");
            virArch arch;
            int pae = 0, nonpae = 0, ia64_be = 0;

            if (STRPREFIX(&token[subs[2].rm_so], "x86_32")) {
                arch = VIR_ARCH_I686;
                if (subs[3].rm_so != -1 &&
                    STRPREFIX(&token[subs[3].rm_so], "p"))
                    pae = 1;
                else
                    nonpae = 1;
            } else if (STRPREFIX(&token[subs[2].rm_so], "x86_64")) {
                arch = VIR_ARCH_X86_64;
            } else if (STRPREFIX(&token[subs[2].rm_so], "ia64")) {
                arch = VIR_ARCH_ITANIUM;
                if (subs[3].rm_so != -1 &&
                    STRPREFIX(&token[subs[3].rm_so], "be"))
                    ia64_be = 1;
            } else if (STRPREFIX(&token[subs[2].rm_so], "powerpc64")) {
                arch = VIR_ARCH_PPC64;
            } else if (STRPREFIX(&token[subs[2].rm_so], "armv7l")) {
                arch = VIR_ARCH_ARMV7L;
            } else if (STRPREFIX(&token[subs[2].rm_so], "aarch64")) {
                arch = VIR_ARCH_AARCH64;
            } else {
                continue;
            }

            /* Search for existing matching (model,hvm) tuple */
            for (i = 0; i < nr_guest_archs; i++) {
                if ((guest_archs[i].arch == arch) &&
                    guest_archs[i].hvm == hvm)
                    break;
            }

            /* Too many arch flavours - highly unlikely ! */
            if (i >= ARRAY_CARDINALITY(guest_archs))
                continue;
            /* Didn't find a match, so create a new one */
            if (i == nr_guest_archs)
                nr_guest_archs++;

            guest_archs[i].arch = arch;
            guest_archs[i].hvm = hvm;

            /* Careful not to overwrite a previous positive
               setting with a negative one here - some archs
               can do both pae & non-pae, but Xen reports
               separately capabilities so we're merging archs */
            if (pae)
                guest_archs[i].pae = pae;
            if (nonpae)
                guest_archs[i].nonpae = nonpae;
            if (ia64_be)
                guest_archs[i].ia64_be = ia64_be;
        }
    }
    regfree(&regex);

    for (i = 0; i < nr_guest_archs; ++i) {
        virCapsGuestPtr guest;
        char const *const xen_machines[] = {guest_archs[i].hvm ? "xenfv" : "xenpv"};
        virCapsGuestMachinePtr *machines;

        if ((machines = virCapabilitiesAllocMachines(xen_machines, 1)) == NULL)
            return -1;

        if ((guest = virCapabilitiesAddGuest(caps,
                                             guest_archs[i].hvm ? VIR_DOMAIN_OSTYPE_HVM : VIR_DOMAIN_OSTYPE_XEN,
                                             guest_archs[i].arch,
                                             LIBXL_EXECBIN_DIR "/qemu-system-i386",
                                             (guest_archs[i].hvm ?
                                              LIBXL_FIRMWARE_DIR "/hvmloader" :
                                              NULL),
                                             1,
                                             machines)) == NULL) {
            virCapabilitiesFreeMachines(machines, 1);
            return -1;
        }
        machines = NULL;

        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_XEN,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            return -1;

        if (guest_archs[i].pae &&
            virCapabilitiesAddGuestFeature(guest,
                                           "pae",
                                           1,
                                           0) == NULL)
            return -1;

        if (guest_archs[i].nonpae &&
            virCapabilitiesAddGuestFeature(guest,
                                           "nonpae",
                                           1,
                                           0) == NULL)
            return -1;

        if (guest_archs[i].ia64_be &&
            virCapabilitiesAddGuestFeature(guest,
                                           "ia64_be",
                                           1,
                                           0) == NULL)
            return -1;

        if (guest_archs[i].hvm) {
            if (virCapabilitiesAddGuestFeature(guest,
                                               "acpi",
                                               1,
                                               1) == NULL)
                return -1;

            if (virCapabilitiesAddGuestFeature(guest, "apic",
                                               1,
                                               0) == NULL)
                return -1;

            if (virCapabilitiesAddGuestFeature(guest,
                                               "hap",
                                               1,
                                               1) == NULL)
                return -1;
        }
    }

    return 0;
}

static int
libxlMakeDomainOSCaps(const char *machine,
                      virDomainCapsOSPtr os,
                      virFirmwarePtr *firmwares,
                      size_t nfirmwares)
{
    virDomainCapsLoaderPtr capsLoader = &os->loader;
    size_t i;

    os->supported = true;

    if (STREQ(machine, "xenpv"))
        return 0;

    capsLoader->supported = true;
    if (VIR_ALLOC_N(capsLoader->values.values, nfirmwares) < 0)
        return -1;

    for (i = 0; i < nfirmwares; i++) {
        if (VIR_STRDUP(capsLoader->values.values[capsLoader->values.nvalues],
                       firmwares[i]->name) < 0)
            return -1;
        capsLoader->values.nvalues++;
    }

    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->type,
                             VIR_DOMAIN_LOADER_TYPE_ROM,
                             VIR_DOMAIN_LOADER_TYPE_PFLASH);
    VIR_DOMAIN_CAPS_ENUM_SET(capsLoader->readonly,
                             VIR_TRISTATE_BOOL_YES);

    return 0;
}

static int
libxlMakeDomainDeviceDiskCaps(virDomainCapsDeviceDiskPtr dev)
{
    dev->supported = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM);

    VIR_DOMAIN_CAPS_ENUM_SET(dev->bus,
                             VIR_DOMAIN_DISK_BUS_IDE,
                             VIR_DOMAIN_DISK_BUS_SCSI,
                             VIR_DOMAIN_DISK_BUS_XEN);

    return 0;
}

static int
libxlMakeDomainDeviceGraphicsCaps(virDomainCapsDeviceGraphicsPtr dev)
{
    dev->supported = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->type,
                             VIR_DOMAIN_GRAPHICS_TYPE_SDL,
                             VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                             VIR_DOMAIN_GRAPHICS_TYPE_SPICE);

    return 0;
}

static int
libxlMakeDomainDeviceVideoCaps(virDomainCapsDeviceVideoPtr dev)
{
    dev->supported = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType,
                             VIR_DOMAIN_VIDEO_TYPE_VGA,
                             VIR_DOMAIN_VIDEO_TYPE_CIRRUS,
                             VIR_DOMAIN_VIDEO_TYPE_XEN);

    return 0;
}

static int
libxlMakeDomainDeviceHostdevCaps(virDomainCapsDeviceHostdevPtr dev)
{
    dev->supported = true;
    /* VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES is for containers only */
    VIR_DOMAIN_CAPS_ENUM_SET(dev->mode,
                             VIR_DOMAIN_HOSTDEV_MODE_SUBSYS);

    VIR_DOMAIN_CAPS_ENUM_SET(dev->startupPolicy,
                             VIR_DOMAIN_STARTUP_POLICY_DEFAULT,
                             VIR_DOMAIN_STARTUP_POLICY_MANDATORY,
                             VIR_DOMAIN_STARTUP_POLICY_REQUISITE,
                             VIR_DOMAIN_STARTUP_POLICY_OPTIONAL);

    VIR_DOMAIN_CAPS_ENUM_SET(dev->subsysType,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI);

#ifdef LIBXL_HAVE_PVUSB
    VIR_DOMAIN_CAPS_ENUM_SET(dev->subsysType,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB);
#endif

    /* No virDomainHostdevCapsType for libxl */
    virDomainCapsEnumClear(&dev->capsType);

    virDomainCapsEnumClear(&dev->pciBackend);
    VIR_DOMAIN_CAPS_ENUM_SET(dev->pciBackend,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN);
    return 0;
}

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx)
{
    virCapsPtr caps;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    if ((caps = virCapabilitiesNew(virArchFromHost(), false, false)) == NULL)
#else
    if ((caps = virCapabilitiesNew(virArchFromHost(), true, true)) == NULL)
#endif
        return NULL;

    if (libxlCapsInitHost(ctx, caps) < 0)
        goto error;

    if (libxlCapsInitNuma(ctx, caps) < 0)
        goto error;

    if (libxlCapsInitGuests(ctx, caps) < 0)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

/*
 * Currently Xen has no interface to report maxvcpus supported
 * for the various domain types (PV, HVM, PVH). HVM_MAX_VCPUS
 * is defined in $xensrc/xen/include/public/hvm/hvm_info_table.h
 * PV has no equivalent and is relunctantly set here until Xen
 * can report such capabilities.
 */
#define HVM_MAX_VCPUS 128
#define PV_MAX_VCPUS  512

int
libxlMakeDomainCapabilities(virDomainCapsPtr domCaps,
                            virFirmwarePtr *firmwares,
                            size_t nfirmwares)
{
    virDomainCapsOSPtr os = &domCaps->os;
    virDomainCapsDeviceDiskPtr disk = &domCaps->disk;
    virDomainCapsDeviceGraphicsPtr graphics = &domCaps->graphics;
    virDomainCapsDeviceVideoPtr video = &domCaps->video;
    virDomainCapsDeviceHostdevPtr hostdev = &domCaps->hostdev;

    if (STREQ(domCaps->machine, "xenfv"))
        domCaps->maxvcpus = HVM_MAX_VCPUS;
    else
        domCaps->maxvcpus = PV_MAX_VCPUS;

    if (libxlMakeDomainOSCaps(domCaps->machine, os, firmwares, nfirmwares) < 0 ||
        libxlMakeDomainDeviceDiskCaps(disk) < 0 ||
        libxlMakeDomainDeviceGraphicsCaps(graphics) < 0 ||
        libxlMakeDomainDeviceVideoCaps(video) < 0 ||
        libxlMakeDomainDeviceHostdevCaps(hostdev) < 0)
        return -1;
    return 0;
}

#define LIBXL_QEMU_DM_STR  "Options specific to the Xen version:"

int
libxlDomainGetEmulatorType(const virDomainDef *def)
{
    int ret = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
    virCommandPtr cmd = NULL;
    char *output = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (def->emulator) {
            if (!virFileExists(def->emulator))
                goto cleanup;

            cmd = virCommandNew(def->emulator);

            virCommandAddArgList(cmd, "-help", NULL);
            virCommandSetOutputBuffer(cmd, &output);

            if (virCommandRun(cmd, NULL) < 0)
                goto cleanup;

            if (strstr(output, LIBXL_QEMU_DM_STR))
                ret = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
        }
    }

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}
