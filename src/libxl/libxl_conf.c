/*
 * libxl_conf.c: libxl configuration management
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (c) 2011-2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2011 Univention GmbH.
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
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 *     Markus Groß <gross@univention.de>
 */

#include <config.h>

#include <regex.h>
#include <libxl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "datatypes.h"
#include "virfile.h"
#include "virstring.h"
#include "viralloc.h"
#include "viruuid.h"
#include "capabilities.h"
#include "libxl_domain.h"
#include "libxl_conf.h"
#include "libxl_utils.h"
#include "virstoragefile.h"


#define VIR_FROM_THIS VIR_FROM_LIBXL

/* see xen-unstable.hg/xen/include/asm-x86/cpufeature.h */
#define LIBXL_X86_FEATURE_PAE_MASK 0x40


struct guest_arch {
    virArch arch;
    int bits;
    int hvm;
    int pae;
    int nonpae;
    int ia64_be;
};

#define XEN_CAP_REGEX "(xen|hvm)-[[:digit:]]+\\.[[:digit:]]+-(x86_32|x86_64|ia64|powerpc64)(p|be)?"


static virClassPtr libxlDriverConfigClass;
static void libxlDriverConfigDispose(void *obj);

static int libxlConfigOnceInit(void)
{
    if (!(libxlDriverConfigClass = virClassNew(virClassForObject(),
                                               "libxlDriverConfig",
                                               sizeof(libxlDriverConfig),
                                               libxlDriverConfigDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlConfig)

static void
libxlDriverConfigDispose(void *obj)
{
    libxlDriverConfigPtr cfg = obj;

    virObjectUnref(cfg->caps);
    libxl_ctx_free(cfg->ctx);
    xtl_logger_destroy(cfg->logger);
    if (cfg->logger_file)
        VIR_FORCE_FCLOSE(cfg->logger_file);

    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->saveDir);
}

static int
libxlCapsInitHost(libxl_ctx *ctx, virCapsPtr caps)
{
    libxl_physinfo phy_info;
    int host_pae;

    if (libxl_get_physinfo(ctx, &phy_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get node physical info from libxenlight"));
        return -1;
    }

    /* hw_caps is an array of 32-bit words whose meaning is listed in
     * xen-unstable.hg/xen/include/asm-x86/cpufeature.h.  Each feature
     * is defined in the form X*32+Y, corresponding to the Y'th bit in
     * the X'th 32-bit word of hw_cap.
     */
    host_pae = phy_info.hw_cap[0] & LIBXL_X86_FEATURE_PAE_MASK;
    if (host_pae &&
        virCapabilitiesAddHostFeature(caps, "pae") < 0)
        return -1;

    return 0;
}

static int
libxlCapsInitNuma(libxl_ctx *ctx, virCapsPtr caps)
{
    libxl_numainfo *numa_info = NULL;
    libxl_cputopology *cpu_topo = NULL;
    int nr_nodes = 0, nr_cpus = 0;
    virCapsHostNUMACellCPUPtr *cpus = NULL;
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

        if (virCapabilitiesAddHostNUMACell(caps, i, nr_cpus_node[i],
                                           numa_info[i].size / 1024,
                                           cpus[i]) < 0) {
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
    virArch hostarch = caps->host.arch;

    struct guest_arch guest_archs[32];
    int nr_guest_archs = 0;

    memset(guest_archs, 0, sizeof(guest_archs));

    if ((ver_info = libxl_get_version_info(ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to get version info from libxenlight"));
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
            }
            else if (STRPREFIX(&token[subs[2].rm_so], "x86_64")) {
                arch = VIR_ARCH_X86_64;
            }
            else if (STRPREFIX(&token[subs[2].rm_so], "ia64")) {
                arch = VIR_ARCH_ITANIUM;
                if (subs[3].rm_so != -1 &&
                    STRPREFIX(&token[subs[3].rm_so], "be"))
                    ia64_be = 1;
            }
            else if (STRPREFIX(&token[subs[2].rm_so], "powerpc64")) {
                arch = VIR_ARCH_PPC64;
            } else {
                /* XXX arm ? */
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
                                             guest_archs[i].hvm ? "hvm" : "xen",
                                             guest_archs[i].arch,
                                             ((hostarch == VIR_ARCH_X86_64) ?
                                              "/usr/lib64/xen/bin/qemu-dm" :
                                              "/usr/lib/xen/bin/qemu-dm"),
                                             (guest_archs[i].hvm ?
                                              "/usr/lib/xen/boot/hvmloader" :
                                              NULL),
                                             1,
                                             machines)) == NULL) {
            virCapabilitiesFreeMachines(machines, 1);
            return -1;
        }
        machines = NULL;

        if (virCapabilitiesAddGuestDomain(guest,
                                          "xen",
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
                                               0,
                                               1) == NULL)
                return -1;
        }
    }

    return 0;
}

static int
libxlMakeDomCreateInfo(libxl_ctx *ctx,
                       virDomainDefPtr def,
                       libxl_domain_create_info *c_info)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    libxl_domain_create_info_init(c_info);

    if (STREQ(def->os.type, "hvm"))
        c_info->type = LIBXL_DOMAIN_TYPE_HVM;
    else
        c_info->type = LIBXL_DOMAIN_TYPE_PV;

    if (VIR_STRDUP(c_info->name, def->name) < 0)
        goto error;

    if (def->nseclabels &&
        def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (libxl_flask_context_to_sid(ctx,
                                       def->seclabels[0]->label,
                                       strlen(def->seclabels[0]->label),
                                       &c_info->ssidref)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to resolve security label '%s'"),
                           def->seclabels[0]->label);
        }
    }

    virUUIDFormat(def->uuid, uuidstr);
    if (libxl_uuid_from_string(&c_info->uuid, uuidstr)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to parse UUID '%s'"), uuidstr);
        goto error;
    }

    return 0;

error:
    libxl_domain_create_info_dispose(c_info);
    return -1;
}

static int
libxlMakeChrdevStr(virDomainChrDefPtr def, char **buf)
{
    virDomainChrSourceDef srcdef = def->source;
    const char *type = virDomainChrTypeToString(srcdef.type);

    if (!type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("unknown chrdev type"));
        return -1;
    }

    switch (srcdef.type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (VIR_STRDUP(*buf, type) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (virAsprintf(buf, "%s:%s", type, srcdef.data.file.path) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (VIR_STRDUP(*buf, srcdef.data.file.path) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = srcdef.data.udp.connectHost;
        const char *bindHost = srcdef.data.udp.bindHost;
        const char *bindService  = srcdef.data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        if (virAsprintf(buf, "udp:%s:%s@%s:%s",
                        connectHost,
                        srcdef.data.udp.connectService,
                        bindHost,
                        bindService) < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_TCP: {
        const char *prefix;

        if (srcdef.data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET)
            prefix = "telnet";
        else
            prefix = "tcp";

        if (virAsprintf(buf, "%s:%s:%s%s",
                        prefix,
                        srcdef.data.tcp.host,
                        srcdef.data.tcp.service,
                        srcdef.data.tcp.listen ? ",server,nowait" : "") < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (virAsprintf(buf, "unix:%s%s",
                        srcdef.data.nix.path,
                        srcdef.data.nix.listen ? ",server,nowait" : "") < 0)
            return -1;
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%s'"), type);
        return -1;
    }

    return 0;
}

static int
libxlMakeDomBuildInfo(virDomainObjPtr vm, libxl_domain_config *d_config)
{
    virDomainDefPtr def = vm->def;
    libxlDomainObjPrivatePtr priv = vm->privateData;
    libxl_domain_build_info *b_info = &d_config->b_info;
    int hvm = STREQ(def->os.type, "hvm");
    size_t i;

    libxl_domain_build_info_init(b_info);

    if (hvm)
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_HVM);
    else
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_PV);

    b_info->max_vcpus = def->maxvcpus;
    if (libxl_cpu_bitmap_alloc(priv->ctx, &b_info->avail_vcpus, def->maxvcpus))
        goto error;
    libxl_bitmap_set_none(&b_info->avail_vcpus);
    for (i = 0; i < def->vcpus; i++)
        libxl_bitmap_set((&b_info->avail_vcpus), i);

    if (def->clock.ntimers > 0 &&
        def->clock.timers[0]->name == VIR_DOMAIN_TIMER_NAME_TSC) {
        switch (def->clock.timers[0]->mode) {
            case VIR_DOMAIN_TIMER_MODE_NATIVE:
                b_info->tsc_mode = 2;
                break;
            case VIR_DOMAIN_TIMER_MODE_PARAVIRT:
                b_info->tsc_mode = 3;
                break;
            default:
                b_info->tsc_mode = 1;
        }
    }
    b_info->sched_params.weight = 1000;
    b_info->max_memkb = def->mem.max_balloon;
    b_info->target_memkb = def->mem.cur_balloon;
    if (hvm) {
        char bootorder[VIR_DOMAIN_BOOT_LAST + 1];

        libxl_defbool_set(&b_info->u.hvm.pae,
                          def->features[VIR_DOMAIN_FEATURE_PAE] ==
                          VIR_DOMAIN_FEATURE_STATE_ON);
        libxl_defbool_set(&b_info->u.hvm.apic,
                          def->features[VIR_DOMAIN_FEATURE_APIC] ==
                          VIR_DOMAIN_FEATURE_STATE_ON);
        libxl_defbool_set(&b_info->u.hvm.acpi,
                          def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                          VIR_DOMAIN_FEATURE_STATE_ON);
        for (i = 0; i < def->clock.ntimers; i++) {
            if (def->clock.timers[i]->name == VIR_DOMAIN_TIMER_NAME_HPET &&
                def->clock.timers[i]->present == 1) {
                libxl_defbool_set(&b_info->u.hvm.hpet, 1);
            }
        }
        for (i = 0; i < def->os.nBootDevs; i++) {
            switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootorder[i] = 'a';
                    break;
                default:
                case VIR_DOMAIN_BOOT_DISK:
                    bootorder[i] = 'c';
                    break;
                case VIR_DOMAIN_BOOT_CDROM:
                    bootorder[i] = 'd';
                    break;
                case VIR_DOMAIN_BOOT_NET:
                    bootorder[i] = 'n';
                    break;
            }
        }
        if (def->os.nBootDevs == 0) {
            bootorder[0] = 'c';
            bootorder[1] = '\0';
        }
        else {
            bootorder[def->os.nBootDevs] = '\0';
        }
        if (VIR_STRDUP(b_info->u.hvm.boot, bootorder) < 0)
            goto error;

        if (def->nserials) {
            if (def->nserials > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s",
                               _("Only one serial device is supported by libxl"));
                goto error;
            }
            if (libxlMakeChrdevStr(def->serials[0], &b_info->u.hvm.serial) < 0)
                goto error;
        }

        if (def->nparallels) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s",
                           _("Parallel devices are not supported by libxl"));
            goto error;
        }

        /*
         * The following comment and calculation were taken directly from
         * libxenlight's internal function libxl_get_required_shadow_memory():
         *
         * 256 pages (1MB) per vcpu, plus 1 page per MiB of RAM for the P2M map,
         * plus 1 page per MiB of RAM to shadow the resident processes.
         */
        b_info->shadow_memkb = 4 * (256 * libxl_bitmap_count_set(&b_info->avail_vcpus) +
                                    2 * (b_info->max_memkb / 1024));
    } else {
        /*
         * For compatibility with the legacy xen toolstack, default to pygrub
         * if bootloader is not specified AND direct kernel boot is not specified.
         */
        if (def->os.bootloader) {
            if (VIR_STRDUP(b_info->u.pv.bootloader, def->os.bootloader) < 0)
                goto error;
        } else if (def->os.kernel == NULL) {
            if (VIR_STRDUP(b_info->u.pv.bootloader, LIBXL_BOOTLOADER_PATH) < 0)
                goto error;
        }
        if (def->os.bootloaderArgs) {
            if (!(b_info->u.pv.bootloader_args =
                  virStringSplit(def->os.bootloaderArgs, " \t\n", 0)))
                goto error;
        }
        if (VIR_STRDUP(b_info->u.pv.cmdline, def->os.cmdline) < 0)
            goto error;
        if (def->os.kernel) {
            /* libxl_init_build_info() sets VIR_STRDUP(kernel.path, "hvmloader") */
            VIR_FREE(b_info->u.pv.kernel);
            if (VIR_STRDUP(b_info->u.pv.kernel, def->os.kernel) < 0)
                goto error;
        }
        if (VIR_STRDUP(b_info->u.pv.ramdisk, def->os.initrd) < 0)
            goto error;
    }

    return 0;

error:
    libxl_domain_build_info_dispose(b_info);
    return -1;
}

int
libxlMakeDisk(virDomainDiskDefPtr l_disk, libxl_device_disk *x_disk)
{
    libxl_device_disk_init(x_disk);

    if (VIR_STRDUP(x_disk->pdev_path, l_disk->src) < 0)
        return -1;

    if (VIR_STRDUP(x_disk->vdev, l_disk->dst) < 0)
        return -1;

    if (l_disk->driverName) {
        if (STREQ(l_disk->driverName, "tap") ||
            STREQ(l_disk->driverName, "tap2")) {
            switch (l_disk->format) {
            case VIR_STORAGE_FILE_QCOW:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW;
                x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
                break;
            case VIR_STORAGE_FILE_QCOW2:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW2;
                x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
                break;
            case VIR_STORAGE_FILE_VHD:
                x_disk->format = LIBXL_DISK_FORMAT_VHD;
                x_disk->backend = LIBXL_DISK_BACKEND_TAP;
                break;
            case VIR_STORAGE_FILE_NONE:
                /* No subtype specified, default to raw/tap */
            case VIR_STORAGE_FILE_RAW:
                x_disk->format = LIBXL_DISK_FORMAT_RAW;
                x_disk->backend = LIBXL_DISK_BACKEND_TAP;
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(l_disk->format),
                               l_disk->driverName);
                return -1;
            }
        } else if (STREQ(l_disk->driverName, "qemu")) {
            x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
            switch (l_disk->format) {
            case VIR_STORAGE_FILE_QCOW:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW;
                break;
            case VIR_STORAGE_FILE_QCOW2:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW2;
                break;
            case VIR_STORAGE_FILE_VHD:
                x_disk->format = LIBXL_DISK_FORMAT_VHD;
                break;
            case VIR_STORAGE_FILE_NONE:
                /* No subtype specified, default to raw */
            case VIR_STORAGE_FILE_RAW:
                x_disk->format = LIBXL_DISK_FORMAT_RAW;
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(l_disk->format),
                               l_disk->driverName);
                return -1;
            }
        } else if (STREQ(l_disk->driverName, "file")) {
            if (l_disk->format != VIR_STORAGE_FILE_NONE &&
                l_disk->format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(l_disk->format),
                               l_disk->driverName);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_TAP;
        } else if (STREQ(l_disk->driverName, "phy")) {
            if (l_disk->format != VIR_STORAGE_FILE_NONE &&
                l_disk->format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(l_disk->format),
                               l_disk->driverName);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_PHY;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight does not support disk driver %s"),
                           l_disk->driverName);
            return -1;
        }
    } else {
        /*
         * If driverName is not specified, default to raw as per
         * xl-disk-configuration.txt in the xen documentation and let
         * libxl pick a suitable backend.
         */
        x_disk->format = LIBXL_DISK_FORMAT_RAW;
        x_disk->backend = LIBXL_DISK_BACKEND_UNKNOWN;
    }

    /* XXX is this right? */
    x_disk->removable = 1;
    x_disk->readwrite = !l_disk->readonly;
    x_disk->is_cdrom = l_disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ? 1 : 0;
    if (l_disk->transient) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight does not support transient disks"));
        return -1;
    }

    return 0;
}

static int
libxlMakeDiskList(virDomainDefPtr def, libxl_domain_config *d_config)
{
    virDomainDiskDefPtr *l_disks = def->disks;
    int ndisks = def->ndisks;
    libxl_device_disk *x_disks;
    size_t i;

    if (VIR_ALLOC_N(x_disks, ndisks) < 0)
        return -1;

    for (i = 0; i < ndisks; i++) {
        if (libxlMakeDisk(l_disks[i], &x_disks[i]) < 0)
            goto error;
    }

    d_config->disks = x_disks;
    d_config->num_disks = ndisks;

    return 0;

error:
    for (i = 0; i < ndisks; i++)
        libxl_device_disk_dispose(&x_disks[i]);
    VIR_FREE(x_disks);
    return -1;
}

int
libxlMakeNic(virDomainNetDefPtr l_nic, libxl_device_nic *x_nic)
{
    /* TODO: Where is mtu stored?
     *
     * x_nics[i].mtu = 1492;
     */

    libxl_device_nic_init(x_nic);

    virMacAddrGetRaw(&l_nic->mac, x_nic->mac);

    if (l_nic->model && !STREQ(l_nic->model, "netfront")) {
        if (VIR_STRDUP(x_nic->model, l_nic->model) < 0)
            return -1;
        x_nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
    } else {
        x_nic->nictype = LIBXL_NIC_TYPE_VIF;
    }

    if (VIR_STRDUP(x_nic->ifname, l_nic->ifname) < 0)
        return -1;

    switch (l_nic->type) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            if (VIR_STRDUP(x_nic->bridge, l_nic->data.bridge.brname) < 0)
                return -1;
            /* fallthrough */
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (VIR_STRDUP(x_nic->script, l_nic->script) < 0)
                return -1;
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                    _("libxenlight does not support network device type %s"),
                    virDomainNetTypeToString(l_nic->type));
            return -1;
    }

    return 0;
}

static int
libxlMakeNicList(virDomainDefPtr def,  libxl_domain_config *d_config)
{
    virDomainNetDefPtr *l_nics = def->nets;
    int nnics = def->nnets;
    libxl_device_nic *x_nics;
    size_t i;

    if (VIR_ALLOC_N(x_nics, nnics) < 0)
        return -1;

    for (i = 0; i < nnics; i++) {
        if (libxlMakeNic(l_nics[i], &x_nics[i]))
            goto error;
    }

    d_config->nics = x_nics;
    d_config->num_nics = nnics;

    return 0;

error:
    for (i = 0; i < nnics; i++)
        libxl_device_nic_dispose(&x_nics[i]);
    VIR_FREE(x_nics);
    return -1;
}

int
libxlMakeVfb(libxlDriverPrivatePtr driver,
             virDomainGraphicsDefPtr l_vfb,
             libxl_device_vfb *x_vfb)
{
    unsigned short port;
    const char *listenAddr;

    libxl_device_vfb_init(x_vfb);

    switch (l_vfb->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            libxl_defbool_set(&x_vfb->sdl.enable, 1);
            if (VIR_STRDUP(x_vfb->sdl.display, l_vfb->data.sdl.display) < 0)
                return -1;
            if (VIR_STRDUP(x_vfb->sdl.xauthority, l_vfb->data.sdl.xauth) < 0)
                return -1;
            break;
        case  VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            libxl_defbool_set(&x_vfb->vnc.enable, 1);
            /* driver handles selection of free port */
            libxl_defbool_set(&x_vfb->vnc.findunused, 0);
            if (l_vfb->data.vnc.autoport) {

                if (virPortAllocatorAcquire(driver->reservedVNCPorts, &port) < 0)
                    return -1;
                l_vfb->data.vnc.port = port;
            }
            x_vfb->vnc.display = l_vfb->data.vnc.port - LIBXL_VNC_PORT_MIN;

            listenAddr = virDomainGraphicsListenGetAddress(l_vfb, 0);
            if (listenAddr) {
                /* libxl_device_vfb_init() does VIR_STRDUP("127.0.0.1") */
                VIR_FREE(x_vfb->vnc.listen);
                if (VIR_STRDUP(x_vfb->vnc.listen, listenAddr) < 0)
                    return -1;
            }
            if (VIR_STRDUP(x_vfb->keymap, l_vfb->data.vnc.keymap) < 0)
                return -1;
            break;
    }

    return 0;
}

static int
libxlMakeVfbList(libxlDriverPrivatePtr driver,
                 virDomainDefPtr def,
                 libxl_domain_config *d_config)
{
    virDomainGraphicsDefPtr *l_vfbs = def->graphics;
    int nvfbs = def->ngraphics;
    libxl_device_vfb *x_vfbs;
    libxl_device_vkb *x_vkbs;
    size_t i;

    if (nvfbs == 0)
        return 0;

    if (VIR_ALLOC_N(x_vfbs, nvfbs) < 0)
        return -1;
    if (VIR_ALLOC_N(x_vkbs, nvfbs) < 0) {
        VIR_FREE(x_vfbs);
        return -1;
    }

    for (i = 0; i < nvfbs; i++) {
        libxl_device_vkb_init(&x_vkbs[i]);

        if (libxlMakeVfb(driver, l_vfbs[i], &x_vfbs[i]) < 0)
            goto error;
    }

    d_config->vfbs = x_vfbs;
    d_config->vkbs = x_vkbs;
    d_config->num_vfbs = d_config->num_vkbs = nvfbs;

    return 0;

error:
    for (i = 0; i < nvfbs; i++) {
        libxl_device_vfb_dispose(&x_vfbs[i]);
        libxl_device_vkb_dispose(&x_vkbs[i]);
    }
    VIR_FREE(x_vfbs);
    VIR_FREE(x_vkbs);
    return -1;
}

static int
libxlGetAutoballoonConf(libxlDriverConfigPtr cfg, bool *autoballoon)
{
    regex_t regex;
    int res;

    if ((res = regcomp(&regex,
                      "(^| )dom0_mem=((|min:|max:)[0-9]+[bBkKmMgG]?,?)+($| )",
                       REG_NOSUB | REG_EXTENDED)) != 0) {
        char error[100];
        regerror(res, &regex, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %s"),
                       error);

        return -1;
    }

    res = regexec(&regex, cfg->verInfo->commandline, 0, NULL, 0);
    regfree(&regex);
    *autoballoon = res == REG_NOMATCH;
    return 0;
}

libxlDriverConfigPtr
libxlDriverConfigNew(void)
{
    libxlDriverConfigPtr cfg;
    char *log_file = NULL;
    char ebuf[1024];
    unsigned int free_mem;

    if (libxlConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(libxlDriverConfigClass)))
        return NULL;

    if (VIR_STRDUP(cfg->configDir, LIBXL_CONFIG_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->autostartDir, LIBXL_AUTOSTART_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->logDir, LIBXL_LOG_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->stateDir, LIBXL_STATE_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->libDir, LIBXL_LIB_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->saveDir, LIBXL_SAVE_DIR) < 0)
        goto error;

    if (virAsprintf(&log_file, "%s/libxl-driver.log", cfg->logDir) < 0)
        goto error;

    if ((cfg->logger_file = fopen(log_file, "a")) == NULL)  {
        VIR_ERROR(_("Failed to create log file '%s': %s"),
                  log_file, virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    VIR_FREE(log_file);

    cfg->logger =
        (xentoollog_logger *)xtl_createlogger_stdiostream(cfg->logger_file,
                                                          XTL_DEBUG, 0);
    if (!cfg->logger) {
        VIR_ERROR(_("cannot create logger for libxenlight, disabling driver"));
        goto error;
    }

    if (libxl_ctx_alloc(&cfg->ctx, LIBXL_VERSION, 0, cfg->logger)) {
        VIR_ERROR(_("cannot initialize libxenlight context, probably not "
                    "running in a Xen Dom0, disabling driver"));
        goto error;
    }

    if ((cfg->verInfo = libxl_get_version_info(cfg->ctx)) == NULL) {
        VIR_ERROR(_("cannot version information from libxenlight, "
                    "disabling driver"));
        goto error;
    }
    cfg->version = (cfg->verInfo->xen_version_major * 1000000) +
        (cfg->verInfo->xen_version_minor * 1000);

    /* This will fill xenstore info about free and dom0 memory if missing,
     * should be called before starting first domain */
    if (libxl_get_free_memory(cfg->ctx, &free_mem)) {
        VIR_ERROR(_("Unable to configure libxl's memory management parameters"));
        goto error;
    }

    /* setup autoballoon */
    if (libxlGetAutoballoonConf(cfg, &cfg->autoballoon) < 0)
        goto error;

    return cfg;

error:
    VIR_FREE(log_file);
    virObjectUnref(cfg);
    return NULL;
}

libxlDriverConfigPtr
libxlDriverConfigGet(libxlDriverPrivatePtr driver)
{
    libxlDriverConfigPtr cfg;

    libxlDriverLock(driver);
    cfg = virObjectRef(driver->config);
    libxlDriverUnlock(driver);
    return cfg;
}

virCapsPtr
libxlMakeCapabilities(libxl_ctx *ctx)
{
    virCapsPtr caps;

    if ((caps = virCapabilitiesNew(virArchFromHost(), 1, 1)) == NULL)
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

int
libxlBuildDomainConfig(libxlDriverPrivatePtr driver,
                       virDomainObjPtr vm, libxl_domain_config *d_config)
{
    virDomainDefPtr def = vm->def;
    libxlDomainObjPrivatePtr priv = vm->privateData;

    libxl_domain_config_init(d_config);

    if (libxlMakeDomCreateInfo(priv->ctx, def, &d_config->c_info) < 0)
        return -1;

    if (libxlMakeDomBuildInfo(vm, d_config) < 0)
        return -1;

    if (libxlMakeDiskList(def, d_config) < 0)
        return -1;

    if (libxlMakeNicList(def, d_config) < 0)
        return -1;

    if (libxlMakeVfbList(driver, def, d_config) < 0)
        return -1;

    d_config->on_reboot = def->onReboot;
    d_config->on_poweroff = def->onPoweroff;
    d_config->on_crash = def->onCrash;

    return 0;
}
