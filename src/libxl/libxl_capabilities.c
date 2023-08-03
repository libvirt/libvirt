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
 */

#include <config.h>

#include <libxl.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
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

struct guest_arch {
    virArch arch;
    int hvm;
    int pvh;
    int pae;
    int nonpae;
    int ia64_be;
};

#define XEN_CAP_REGEX "(xen|hvm)-[[:digit:]]+\\.[[:digit:]]+-(aarch64|armv7l|x86_32|x86_64|ia64|powerpc64)(p|be)?"

static int
libxlCapsAddCPUID(virCPUData *data, virCPUx86CPUID *cpuid, ssize_t ncaps)
{
    virCPUx86DataItem item = { 0 };
    size_t i;

    item.type = VIR_CPU_X86_DATA_CPUID;
    for (i = 0; i < ncaps; i++) {
        item.data.cpuid = cpuid[i];

        if (virCPUx86DataAdd(data, &item) < 0) {
            VIR_DEBUG("Failed to add CPUID(%x,%x)",
                      cpuid[i].eax_in, cpuid[i].ecx_in);
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
 * to describe host CPU in libvirt capabilities.
 *
 *              |       Xen >= 4.7     |
 *              ------------------------
 *       word 0 | CPUID.00000001.EDX   |
 *       word 1 | CPUID.00000001.ECX   |
 *       word 2 | CPUID.80000001.EDX   |
 *       word 3 | CPUID.80000001.ECX   |
 *       word 4 | CPUID.0000000D:1.EAX |
 *       word 5 | CPUID.00000007:0.EBX |
 *       word 6 | CPUID.00000007:0.ECX |
 *       word 7 | CPUID.80000007.EDX   |
 *       word 8 | CPUID.80000008.EBX   |
 *
 */
static virCPUData *
libxlCapsNodeData(virCPUDef *cpu, libxl_hwcap hwcap)
{
    ssize_t ncaps;
    g_autoptr(virCPUData) cpudata = NULL;
    virCPUx86CPUID cpuid[] = {
        { .eax_in = 0x00000001, .edx = hwcap[0] },
        { .eax_in = 0x00000001, .ecx = hwcap[1] },
        { .eax_in = 0x80000001, .edx = hwcap[2] },
        { .eax_in = 0x80000001, .ecx = hwcap[3] },
        { .eax_in = 0x00000007, .ebx = hwcap[5] },
        { .eax_in = 0x0000000D, .ecx_in = 1U, .eax = hwcap[4] },
        { .eax_in = 0x00000007, .ecx_in = 0U, .ecx = hwcap[6] },
        { .eax_in = 0x80000007, .ecx_in = 0U, .edx = hwcap[7] },
    };

    if (!(cpudata = virCPUDataNew(cpu->arch)))
        return NULL;

    ncaps = G_N_ELEMENTS(cpuid);
    if (libxlCapsAddCPUID(cpudata, cpuid, ncaps) < 0)
        return NULL;

    return g_steal_pointer(&cpudata);
}

/* hw_caps is an array of 32-bit words whose meaning is listed in
 * xen-unstable.hg/xen/include/asm-x86/cpufeature.h.  Each feature
 * is defined in the form X*32+Y, corresponding to the Y'th bit in
 * the X'th 32-bit word of hw_cap.
 */
static int
libxlCapsInitCPU(virCaps *caps, libxl_physinfo *phy_info)
{
    g_autoptr(virCPUData) data = NULL;
    g_autoptr(virCPUDef) cpu = NULL;
    int host_pae;
    int host_lm;

    /* On ARM hw_cap vector is zeroed out but not on x86 */
    if (!phy_info->hw_cap[0])
        return 0;

    cpu = virCPUDefNew();

    host_pae = phy_info->hw_cap[0] & LIBXL_X86_FEATURE_PAE_MASK;
    if (host_pae &&
        virCapabilitiesAddHostFeature(caps, "pae") < 0)
        return -1;

    host_lm = (phy_info->hw_cap[2] & LIBXL_X86_FEATURE_LM_MASK);
    if (host_lm)
        cpu->arch = VIR_ARCH_X86_64;
    else
        cpu->arch = VIR_ARCH_I686;

    cpu->type = VIR_CPU_TYPE_HOST;
    cpu->cores = phy_info->cores_per_socket;
    cpu->threads = phy_info->threads_per_core;
    cpu->dies = 1;
    cpu->sockets = phy_info->nr_cpus / (cpu->cores * cpu->threads);

    if (!(data = libxlCapsNodeData(cpu, phy_info->hw_cap)) ||
        cpuDecode(cpu, data, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to initialize host cpu features"));
        return -1;
    }

    caps->host.cpu = g_steal_pointer(&cpu);
    return 0;
}

static int
libxlCapsInitHost(libxl_ctx *ctx, virCaps *caps)
{
    libxl_physinfo phy_info;
    int ret = -1;

    libxl_physinfo_init(&phy_info);
    if (libxl_get_physinfo(ctx, &phy_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get node physical info from libxenlight"));
        goto cleanup;
    }

    if (libxlCapsInitCPU(caps, &phy_info) < 0)
        goto cleanup;

    if (virCapabilitiesSetNetPrefix(caps, LIBXL_GENERATED_PREFIX_XEN) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    libxl_physinfo_dispose(&phy_info);
    return ret;
}

static int
libxlCapsInitNuma(libxl_ctx *ctx, virCaps *caps)
{
    libxl_numainfo *numa_info = NULL;
    libxl_cputopology *cpu_topo = NULL;
    int nr_nodes = 0, nr_cpus = 0, nr_distances = 0;
    virCapsHostNUMACellCPU **cpus = NULL;
    virNumaDistance *distances = NULL;
    int *nr_cpus_node = NULL;
    size_t i;
    int ret = -1;

    /* Let's try to fetch all the topology information */
    numa_info = libxl_get_numainfo(ctx, &nr_nodes);
    if (numa_info == NULL || nr_nodes == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_numainfo failed"));
        goto cleanup;
    }

    cpu_topo = libxl_get_cpu_topology(ctx, &nr_cpus);
    if (cpu_topo == NULL || nr_cpus == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_cpu_topology failed"));
        goto cleanup;
    }

    cpus = g_new0(virCapsHostNUMACellCPU *, nr_nodes);

    nr_cpus_node = g_new0(int, nr_nodes);

    /* For each node, prepare a list of CPUs belonging to that node */
    for (i = 0; i < nr_cpus; i++) {
        int node = cpu_topo[i].node;

        if (cpu_topo[i].core == LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
            continue;

        nr_cpus_node[node]++;

        if (nr_cpus_node[node] == 1) {
            cpus[node] = g_new0(virCapsHostNUMACellCPU, 1);
        } else {
            VIR_REALLOC_N(cpus[node], nr_cpus_node[node]);
        }

        /* Mapping between what libxl tells and what libvirt wants */
        cpus[node][nr_cpus_node[node]-1].id = i;
        cpus[node][nr_cpus_node[node]-1].socket_id = cpu_topo[i].socket;
        cpus[node][nr_cpus_node[node]-1].core_id = cpu_topo[i].core;
        /* Until Xen reports die_id, 0 is better than random garbage */
        cpus[node][nr_cpus_node[node]-1].die_id = 0;
        /* Allocate the siblings maps. We will be filling them later */
        cpus[node][nr_cpus_node[node]-1].siblings = virBitmapNew(nr_cpus);
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

    caps->host.numa = virCapabilitiesHostNUMANew();
    for (i = 0; i < nr_nodes; i++) {
        if (numa_info[i].size == LIBXL_NUMAINFO_INVALID_ENTRY)
            continue;

        nr_distances = numa_info[i].num_dists;
        if (nr_distances) {
            size_t j;

            distances = g_new0(virNumaDistance, nr_distances);

            for (j = 0; j < nr_distances; j++) {
                distances[j].cellid = j;
                distances[j].value = numa_info[i].dists[j];
            }
        }

        virCapabilitiesHostNUMAAddCell(caps->host.numa, i,
                                       numa_info[i].size / 1024,
                                       nr_cpus_node[i], &cpus[i],
                                       nr_distances, &distances,
                                       0, NULL,
                                       NULL);

        /* This is safe, as the CPU list is now stored in the NUMA cell */
        cpus[i] = NULL;
    }

    ret = 0;

 cleanup:
    if (ret != 0) {
        for (i = 0; cpus && i < nr_nodes; i++)
            VIR_FREE(cpus[i]);
        if (caps->host.numa) {
            g_clear_pointer(&caps->host.numa, virCapabilitiesHostNUMAUnref);
        }
        VIR_FREE(distances);
    }

    VIR_FREE(cpus);
    VIR_FREE(nr_cpus_node);
    libxl_cputopology_list_free(cpu_topo, nr_cpus);
    libxl_numainfo_list_free(numa_info, nr_nodes);

    return ret;
}

static int
libxlCapsInitGuests(libxl_ctx *ctx, virCaps *caps)
{
    const libxl_version_info *ver_info;
    g_autoptr(GRegex) regex = NULL;
    g_autoptr(GError) err = NULL;
    g_autoptr(GMatchInfo) info = NULL;
    char *str, *token;
    char *saveptr = NULL;
    size_t i;

    struct guest_arch guest_archs[32] = { 0 };
    int nr_guest_archs = 0;

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

    regex = g_regex_new(XEN_CAP_REGEX, 0, 0, &err);
    if (!regex) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %1$s"), err->message);
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
         nr_guest_archs < G_N_ELEMENTS(guest_archs)
                 && (token = strtok_r(str, " ", &saveptr)) != NULL;
         str = NULL) {
        if (g_regex_match(regex, token, 0, &info)) {
            g_autofree char *modestr = g_match_info_fetch(info, 1);
            g_autofree char *archstr = g_match_info_fetch(info, 2);
            g_autofree char *suffixstr = g_match_info_fetch(info, 3);
            int hvm = STRPREFIX(modestr, "hvm");
            virArch arch;
            int pae = 0, nonpae = 0, ia64_be = 0;

            if (STRPREFIX(archstr, "x86_32")) {
                arch = VIR_ARCH_I686;
                if (suffixstr != NULL && STRPREFIX(suffixstr, "p"))
                    pae = 1;
                else
                    nonpae = 1;
            } else if (STRPREFIX(archstr, "x86_64")) {
                arch = VIR_ARCH_X86_64;
            } else if (STRPREFIX(archstr, "ia64")) {
                arch = VIR_ARCH_ITANIUM;
                if (suffixstr != NULL && STRPREFIX(suffixstr, "be"))
                    ia64_be = 1;
            } else if (STRPREFIX(archstr, "powerpc64")) {
                arch = VIR_ARCH_PPC64;
            } else if (STRPREFIX(archstr, "armv7l")) {
                arch = VIR_ARCH_ARMV7L;
            } else if (STRPREFIX(archstr, "aarch64")) {
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
            if (i >= G_N_ELEMENTS(guest_archs))
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

            /*
             * Xen 4.10 introduced support for the PVH guest type, which
             * requires hardware virtualization support similar to the
             * HVM guest type. Add a PVH guest type for each new HVM
             * guest type.
             */
#ifdef WITH_XEN_PVH
            if (hvm && i == nr_guest_archs-1) {
                /* Ensure we have not exhausted the guest_archs array */
                if (nr_guest_archs >= G_N_ELEMENTS(guest_archs))
                    continue;
                i = nr_guest_archs;
                nr_guest_archs++;

                guest_archs[i].arch = arch;
                guest_archs[i].hvm = 0;
                guest_archs[i].pvh = 1;
            }
#endif
        }
    }

    for (i = 0; i < nr_guest_archs; ++i) {
        virCapsGuest *guest;
        virCapsGuestMachine **machines;
        int nmachines;
        virDomainOSType ostype = VIR_DOMAIN_OSTYPE_XEN;
        const char *loader = NULL;

        if (guest_archs[i].hvm) {
            char const *const xen_machines[] = { "xenfv", NULL };

            ostype = VIR_DOMAIN_OSTYPE_HVM;
            loader = LIBXL_FIRMWARE_DIR "/hvmloader";

            machines = virCapabilitiesAllocMachines(xen_machines, &nmachines);
        } else if (guest_archs[i].pvh) {
            char const *const xen_machines[] = { "xenpvh", NULL };

            ostype = VIR_DOMAIN_OSTYPE_XENPVH;
            machines = virCapabilitiesAllocMachines(xen_machines, &nmachines);
        } else {
            char const *const xen_machines[] = { "xenpv", NULL };

            ostype = VIR_DOMAIN_OSTYPE_XEN;
            machines = virCapabilitiesAllocMachines(xen_machines, &nmachines);
        }

        guest = virCapabilitiesAddGuest(caps, ostype, guest_archs[i].arch,
                                        LIBXL_EXECBIN_DIR "/qemu-system-i386",
                                        loader, nmachines, machines);

        virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_XEN,
                                      NULL, NULL, 0, NULL);

        if (guest_archs[i].pae)
            virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_PAE);

        if (guest_archs[i].nonpae)
            virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_NONPAE);

        if (guest_archs[i].ia64_be)
            virCapabilitiesAddGuestFeature(guest, VIR_CAPS_GUEST_FEATURE_TYPE_IA64_BE);

        if (guest_archs[i].hvm) {
            virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_ACPI,
                                                     true, true);

            virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_APIC,
                                                     true, false);
        }

        if (guest_archs[i].hvm || guest_archs[i].pvh) {
            virCapabilitiesAddGuestFeatureWithToggle(guest, VIR_CAPS_GUEST_FEATURE_TYPE_HAP,
                                                     true, true);
        }
    }

    return 0;
}

static int
libxlMakeDomainOSCaps(const char *machine,
                      virDomainCapsOS *os,
                      virFirmware **firmwares,
                      size_t nfirmwares)
{
    virDomainCapsLoader *capsLoader = &os->loader;
    size_t i;

    os->supported = VIR_TRISTATE_BOOL_YES;
    capsLoader->supported = VIR_TRISTATE_BOOL_NO;
    capsLoader->type.report = true;
    capsLoader->readonly.report = true;

    if (STREQ(machine, "xenpv") || STREQ(machine, "xenpvh"))
        return 0;

    capsLoader->supported = VIR_TRISTATE_BOOL_YES;
    capsLoader->values.values = g_new0(char *, nfirmwares);

    for (i = 0; i < nfirmwares; i++) {
        capsLoader->values.values[capsLoader->values.nvalues] = g_strdup(firmwares[i]->name);
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
libxlMakeDomainDeviceDiskCaps(virDomainCapsDeviceDisk *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->diskDevice.report = true;
    dev->bus.report = true;
    dev->model.report = true;

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
libxlMakeDomainDeviceGraphicsCaps(virDomainCapsDeviceGraphics *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->type.report = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->type,
                             VIR_DOMAIN_GRAPHICS_TYPE_SDL,
                             VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                             VIR_DOMAIN_GRAPHICS_TYPE_SPICE);

    return 0;
}

static int
libxlMakeDomainDeviceVideoCaps(virDomainCapsDeviceVideo *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->modelType.report = true;

    VIR_DOMAIN_CAPS_ENUM_SET(dev->modelType,
                             VIR_DOMAIN_VIDEO_TYPE_VGA,
                             VIR_DOMAIN_VIDEO_TYPE_CIRRUS,
                             VIR_DOMAIN_VIDEO_TYPE_XEN);

    return 0;
}

static int
libxlMakeDomainDeviceHostdevCaps(virDomainCapsDeviceHostdev *dev)
{
    dev->supported = VIR_TRISTATE_BOOL_YES;
    dev->mode.report = true;
    dev->startupPolicy.report = true;
    dev->subsysType.report = true;
    dev->capsType.report = true;
    dev->pciBackend.report = true;

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

    VIR_DOMAIN_CAPS_ENUM_SET(dev->subsysType,
                             VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB);

    /* No virDomainHostdevCapsType for libxl */
    virDomainCapsEnumClear(&dev->capsType);

    virDomainCapsEnumClear(&dev->pciBackend);
    VIR_DOMAIN_CAPS_ENUM_SET(dev->pciBackend,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN);
    return 0;
}

virCaps *
libxlMakeCapabilities(libxl_ctx *ctx)
{
    g_autoptr(virCaps) caps = NULL;

#ifdef LIBXL_HAVE_NO_SUSPEND_RESUME
    if ((caps = virCapabilitiesNew(virArchFromHost(), false, false)) == NULL)
#else
    if ((caps = virCapabilitiesNew(virArchFromHost(), true, true)) == NULL)
#endif
        return NULL;

    if (libxlCapsInitHost(ctx, caps) < 0)
        return NULL;

    if (libxlCapsInitNuma(ctx, caps) < 0)
        return NULL;

    if (libxlCapsInitGuests(ctx, caps) < 0)
        return NULL;

    return g_steal_pointer(&caps);
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
libxlMakeDomainCapabilities(virDomainCaps *domCaps,
                            virFirmware **firmwares,
                            size_t nfirmwares)
{
    virDomainCapsOS *os = &domCaps->os;
    virDomainCapsDeviceDisk *disk = &domCaps->disk;
    virDomainCapsDeviceGraphics *graphics = &domCaps->graphics;
    virDomainCapsDeviceVideo *video = &domCaps->video;
    virDomainCapsDeviceHostdev *hostdev = &domCaps->hostdev;

    if (STREQ(domCaps->machine, "xenfv"))
        domCaps->maxvcpus = HVM_MAX_VCPUS;
    else
        domCaps->maxvcpus = PV_MAX_VCPUS;

    if (libxlMakeDomainOSCaps(domCaps->machine, os, firmwares, nfirmwares) < 0 ||
        libxlMakeDomainDeviceDiskCaps(disk) < 0 ||
        libxlMakeDomainDeviceGraphicsCaps(graphics) < 0 ||
        libxlMakeDomainDeviceVideoCaps(video) < 0)
        return -1;
    if (STRNEQ(domCaps->machine, "xenpvh") &&
        libxlMakeDomainDeviceHostdevCaps(hostdev) < 0)
        return -1;

    domCaps->features[VIR_DOMAIN_CAPS_FEATURE_IOTHREADS] = VIR_TRISTATE_BOOL_NO;
    domCaps->features[VIR_DOMAIN_CAPS_FEATURE_VMCOREINFO] = VIR_TRISTATE_BOOL_NO;
    domCaps->features[VIR_DOMAIN_CAPS_FEATURE_GENID] = VIR_TRISTATE_BOOL_NO;
    domCaps->gic.supported = VIR_TRISTATE_BOOL_NO;

    return 0;
}

#define LIBXL_QEMU_DM_STR  "Options specific to the Xen version:"

int
libxlDomainGetEmulatorType(const virDomainDef *def)
{
    int ret = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (def->emulator) {
            if (!virFileExists(def->emulator))
                return ret;

            cmd = virCommandNew(def->emulator);

            virCommandAddArgList(cmd, "-help", NULL);
            virCommandSetOutputBuffer(cmd, &output);

            if (virCommandRun(cmd, NULL) < 0)
                return ret;

            if (strstr(output, LIBXL_QEMU_DM_STR))
                ret = LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL;
        }
    }

    return ret;
}
