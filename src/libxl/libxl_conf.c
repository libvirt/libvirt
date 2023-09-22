/*
 * libxl_conf.c: libxl configuration management
 *
 * Copyright (C) 2012-2014, 2016 Red Hat, Inc.
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
 */

#include <config.h>

#include <libxl.h>
#include <sys/types.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "virfile.h"
#include "viridentity.h"
#include "virstring.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virsocketaddr.h"
#include "libxl_api_wrapper.h"
#include "libxl_domain.h"
#include "libxl_conf.h"
#include "libxl_utils.h"
#include "virsecret.h"
#include "cpu/cpu.h"
#include "xen_common.h"
#include "xen_xl.h"
#include "virnetdevvportprofile.h"
#include "virenum.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_conf");


static virClass *libxlDriverConfigClass;
static void libxlDriverConfigDispose(void *obj);

static int libxlConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(libxlDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(libxlConfig);

static void
libxlDriverConfigDispose(void *obj)
{
    libxlDriverConfig *cfg = obj;

    virObjectUnref(cfg->caps);
    libxl_ctx_free(cfg->ctx);
    if (cfg->logger)
        libxlLoggerFree(cfg->logger);

    g_free(cfg->configBaseDir);
    g_free(cfg->configDir);
    g_free(cfg->autostartDir);
    g_free(cfg->logDir);
    g_free(cfg->stateDir);
    g_free(cfg->libDir);
    g_free(cfg->saveDir);
    g_free(cfg->autoDumpDir);
    g_free(cfg->lockManagerName);
    g_free(cfg->channelDir);
    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);
}


static libxl_action_on_shutdown
libxlActionFromVirLifecycle(virDomainLifecycleAction action)
{
    switch (action) {
    case VIR_DOMAIN_LIFECYCLE_ACTION_DESTROY:
        return LIBXL_ACTION_ON_SHUTDOWN_DESTROY;

    case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART:
        return LIBXL_ACTION_ON_SHUTDOWN_RESTART;

    case VIR_DOMAIN_LIFECYCLE_ACTION_RESTART_RENAME:
        return LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME;

    case VIR_DOMAIN_LIFECYCLE_ACTION_PRESERVE:
        return LIBXL_ACTION_ON_SHUTDOWN_PRESERVE;

    case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_DESTROY:
        return LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY;

    case VIR_DOMAIN_LIFECYCLE_ACTION_COREDUMP_RESTART:
        return LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART;

    case VIR_DOMAIN_LIFECYCLE_ACTION_LAST:
        break;
    }

    return 0;
}


static int
libxlMakeDomCreateInfo(libxl_ctx *ctx,
                       virDomainDef *def,
                       libxl_domain_create_info *c_info)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM ||
        def->os.type == VIR_DOMAIN_OSTYPE_XENPVH) {
#ifdef WITH_XEN_PVH
        c_info->type = def->os.type == VIR_DOMAIN_OSTYPE_HVM ?
            LIBXL_DOMAIN_TYPE_HVM : LIBXL_DOMAIN_TYPE_PVH;
#else
        if (def->os.type == VIR_DOMAIN_OSTYPE_XENPVH) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("PVH guest os type not supported"));
            return -1;
        }
        c_info->type = LIBXL_DOMAIN_TYPE_HVM;
#endif
        switch ((virTristateSwitch) def->features[VIR_DOMAIN_FEATURE_HAP]) {
        case VIR_TRISTATE_SWITCH_OFF:
            libxl_defbool_set(&c_info->hap, false);
            break;

        case VIR_TRISTATE_SWITCH_ON:
            libxl_defbool_set(&c_info->hap, true);
            break;

        case VIR_TRISTATE_SWITCH_ABSENT:
        case VIR_TRISTATE_SWITCH_LAST:
            break;
        }
    } else {
        c_info->type = LIBXL_DOMAIN_TYPE_PV;
    }

#ifdef LIBXL_HAVE_CREATEINFO_PASSTHROUGH
    if (def->features[VIR_DOMAIN_FEATURE_XEN] == VIR_TRISTATE_SWITCH_ON) {
        switch ((virTristateSwitch) def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH]) {
        case VIR_TRISTATE_SWITCH_ON:
            if (def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SYNC_PT)
                c_info->passthrough = LIBXL_PASSTHROUGH_SYNC_PT;
            else if (def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SHARE_PT)
                c_info->passthrough = LIBXL_PASSTHROUGH_SHARE_PT;
            else
                c_info->passthrough = LIBXL_PASSTHROUGH_ENABLED;
            break;
        case VIR_TRISTATE_SWITCH_OFF:
            c_info->passthrough = LIBXL_PASSTHROUGH_DISABLED;
            break;
        case VIR_TRISTATE_SWITCH_ABSENT:
        case VIR_TRISTATE_SWITCH_LAST:
            break;
        }
    }
#endif

    c_info->name = g_strdup(def->name);

    if (def->nseclabels &&
        def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_STATIC) {
        if (libxl_flask_context_to_sid(ctx,
                                       def->seclabels[0]->label,
                                       strlen(def->seclabels[0]->label),
                                       &c_info->ssidref)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight failed to resolve security label '%1$s'"),
                           def->seclabels[0]->label);
        }
    }

    virUUIDFormat(def->uuid, uuidstr);
    if (libxl_uuid_from_string(&c_info->uuid, uuidstr)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to parse UUID '%1$s'"), uuidstr);
        goto error;
    }

    return 0;

 error:
    libxl_domain_create_info_dispose(c_info);
    return -1;
}

static int
libxlMakeChrdevStr(virDomainChrDef *def, char **buf)
{
    virDomainChrSourceDef *srcdef = def->source;
    const char *type = virDomainChrTypeToString(srcdef->type);

    if (!type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("unknown chrdev type"));
        return -1;
    }

    switch (srcdef->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        *buf = g_strdup(type);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        *buf = g_strdup_printf("%s:%s", type, srcdef->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        *buf = g_strdup(srcdef->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = srcdef->data.udp.connectHost;
        const char *bindHost = srcdef->data.udp.bindHost;
        const char *bindService  = srcdef->data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        *buf = g_strdup_printf("udp:%s:%s@%s:%s", connectHost,
                               srcdef->data.udp.connectService, bindHost, bindService);
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_TCP: {
        const char *prefix;

        if (srcdef->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET)
            prefix = "telnet";
        else
            prefix = "tcp";

        *buf = g_strdup_printf("%s:%s:%s%s", prefix, srcdef->data.tcp.host,
                               srcdef->data.tcp.service,
                               srcdef->data.tcp.listen ? ",server,nowait" : "");
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        *buf = g_strdup_printf("unix:%s%s", srcdef->data.nix.path,
                               srcdef->data.nix.listen ? ",server,nowait" : "");
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%1$s'"), type);
        return -1;
    }

    return 0;
}

static int
libxlSetVcpuAffinities(virDomainDef *def,
                       libxl_ctx *ctx,
                       libxl_domain_build_info *b_info)
{
    libxl_bitmap *vcpu_affinity_array;
    unsigned int vcpuid;
    unsigned int vcpu_idx = 0;
    virDomainVcpuDef *vcpu;
    bool has_vcpu_pin = false;

    /* Get highest vcpuid with cpumask */
    for (vcpuid = 0; vcpuid < b_info->max_vcpus; vcpuid++) {
        vcpu = virDomainDefGetVcpu(def, vcpuid);
        if (!vcpu)
            continue;
        if (!vcpu->cpumask)
            continue;
        vcpu_idx = vcpuid;
        has_vcpu_pin = true;
    }
    /* Nothing to do */
    if (!has_vcpu_pin)
        return 0;

    /* Adjust index */
    vcpu_idx++;

    b_info->num_vcpu_hard_affinity = vcpu_idx;
    /* Will be released by libxl_domain_config_dispose */
    b_info->vcpu_hard_affinity = g_new0(libxl_bitmap, vcpu_idx);
    vcpu_affinity_array = b_info->vcpu_hard_affinity;

    for (vcpuid = 0; vcpuid < vcpu_idx; vcpuid++) {
        libxl_bitmap *map = &vcpu_affinity_array[vcpuid];
        libxl_bitmap_init(map);
        /* libxl owns the bitmap */
        if (libxl_cpu_bitmap_alloc(ctx, map, 0))
            return -1;
        vcpu = virDomainDefGetVcpu(def, vcpuid);
        /* Apply the given mask, or allow unhandled vcpus to run anywhere */
        if (vcpu && vcpu->cpumask)
            virBitmapToDataBuf(vcpu->cpumask, map->map, map->size);
        else
            libxl_bitmap_set_any(map);
    }
    libxl_defbool_set(&b_info->numa_placement, false);
    return 0;
}

static int
libxlMakeDomBuildInfo(virDomainDef *def,
                      libxlDriverConfig *cfg,
                      virCaps *caps,
                      libxl_domain_config *d_config)
{
    virDomainClockDef clock = def->clock;
    libxl_ctx *ctx = cfg->ctx;
    libxl_domain_build_info *b_info = &d_config->b_info;
    bool hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;
    bool pvh = def->os.type == VIR_DOMAIN_OSTYPE_XENPVH;
    size_t i;
    size_t nusbdevice = 0;

    if (hvm) {
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_HVM);
    } else if (pvh) {
#ifdef WITH_XEN_PVH
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_PVH);
#else
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                _("PVH guest os type not supported"));
        return -1;
#endif
    } else {
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_PV);
    }

    b_info->max_vcpus = virDomainDefGetVcpusMax(def);
    if (libxl_cpu_bitmap_alloc(ctx, &b_info->avail_vcpus, b_info->max_vcpus))
        return -1;
    libxl_bitmap_set_none(&b_info->avail_vcpus);
    for (i = 0; i < virDomainDefGetVcpus(def); i++)
        libxl_bitmap_set((&b_info->avail_vcpus), i);

    if (libxlSetVcpuAffinities(def, ctx, b_info))
        return -1;

    switch ((virDomainClockOffsetType) clock.offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
        if (clock.data.variable.basis == VIR_DOMAIN_CLOCK_BASIS_LOCALTIME)
            libxl_defbool_set(&b_info->localtime, true);
        b_info->rtc_timeoffset = clock.data.variable.adjustment;
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
        libxl_defbool_set(&b_info->localtime, true);
        break;

    /* Nothing to do since UTC is the default in libxl */
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported clock offset '%1$s'"),
                       virDomainClockOffsetTypeToString(clock.offset));
        return -1;

    case VIR_DOMAIN_CLOCK_OFFSET_ABSOLUTE:
    case VIR_DOMAIN_CLOCK_OFFSET_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unexpected clock offset '%1$d'"), clock.offset);
        return -1;
    }

    for (i = 0; i < clock.ntimers; i++) {
        switch ((virDomainTimerNameType) clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_TSC:
            switch (clock.timers[i]->mode) {
            case VIR_DOMAIN_TIMER_MODE_NATIVE:
                b_info->tsc_mode = LIBXL_TSC_MODE_NATIVE;
                break;
            case VIR_DOMAIN_TIMER_MODE_PARAVIRT:
                b_info->tsc_mode = LIBXL_TSC_MODE_NATIVE_PARAVIRT;
                break;
            case VIR_DOMAIN_TIMER_MODE_EMULATE:
                b_info->tsc_mode = LIBXL_TSC_MODE_ALWAYS_EMULATE;
                break;
            case VIR_DOMAIN_TIMER_MODE_NONE:
            case VIR_DOMAIN_TIMER_MODE_AUTO:
            case VIR_DOMAIN_TIMER_MODE_SMPSAFE:
                b_info->tsc_mode = LIBXL_TSC_MODE_DEFAULT;
            case VIR_DOMAIN_TIMER_MODE_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            if (!hvm) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported timer type (name) '%1$s'"),
                               virDomainTimerNameTypeToString(clock.timers[i]->name));
                return -1;
            }
            if (clock.timers[i]->present == VIR_TRISTATE_BOOL_YES)
                libxl_defbool_set(&b_info->u.hvm.hpet, 1);
            break;

        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%1$s'"),
                           virDomainTimerNameTypeToString(clock.timers[i]->name));
            return -1;

        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        }
    }

    if (def->cputune.sharesSpecified)
        b_info->sched_params.weight = def->cputune.shares;

    /* Xen requires the memory sizes to be rounded to 1MiB increments */
    virDomainDefSetMemoryTotal(def,
                               VIR_ROUND_UP(virDomainDefGetMemoryInitial(def), 1024));
    def->mem.cur_balloon = VIR_ROUND_UP(def->mem.cur_balloon, 1024);
    b_info->max_memkb = virDomainDefGetMemoryInitial(def);
    b_info->target_memkb = def->mem.cur_balloon;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_XENBUS) {
            if (def->controllers[i]->opts.xenbusopts.maxEventChannels > 0)
                b_info->event_channels = def->controllers[i]->opts.xenbusopts.maxEventChannels;

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
            if (def->controllers[i]->opts.xenbusopts.maxGrantFrames > 0)
                b_info->max_grant_frames = def->controllers[i]->opts.xenbusopts.maxGrantFrames;
#endif
        }
    }

    if (hvm || pvh) {
        if (caps &&
            def->cpu && def->cpu->mode == (VIR_CPU_MODE_HOST_PASSTHROUGH)) {
            bool hasHwVirt = false;
            bool svm = false, vmx = false;
            char xlCPU[32];

            /* enable nested HVM only if global nested_hvm option enable it and
             * host support it */
            if (ARCH_IS_X86(def->os.arch)) {
                vmx = virCPUCheckFeature(caps->host.arch, caps->host.cpu, "vmx");
                svm = virCPUCheckFeature(caps->host.arch, caps->host.cpu, "svm");
                hasHwVirt = cfg->nested_hvm && (vmx | svm);
            }

            if (def->cpu->nfeatures) {
                for (i = 0; i < def->cpu->nfeatures; i++) {

                    switch (def->cpu->features[i].policy) {

                        case VIR_CPU_FEATURE_DISABLE:
                        case VIR_CPU_FEATURE_FORBID:
                            if ((vmx && STREQ(def->cpu->features[i].name, "vmx")) ||
                                (svm && STREQ(def->cpu->features[i].name, "svm"))) {
                                hasHwVirt = false;
                                continue;
                            }

                            g_snprintf(xlCPU,
                                       sizeof(xlCPU),
                                       "%s=0",
                                       xenTranslateCPUFeature(
                                           def->cpu->features[i].name,
                                           false));
                            if (libxl_cpuid_parse_config(&b_info->cpuid, xlCPU)) {
                                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                        _("unsupported cpu feature '%1$s'"),
                                        def->cpu->features[i].name);
                                return -1;
                            }
                            break;

                        case VIR_CPU_FEATURE_FORCE:
                        case VIR_CPU_FEATURE_REQUIRE:
                            if ((vmx && STREQ(def->cpu->features[i].name, "vmx")) ||
                                (svm && STREQ(def->cpu->features[i].name, "svm"))) {
                                hasHwVirt = true;
                                continue;
                            }

                            g_snprintf(xlCPU,
                                       sizeof(xlCPU),
                                       "%s=1",
                                       xenTranslateCPUFeature(
                                           def->cpu->features[i].name, false));
                            if (libxl_cpuid_parse_config(&b_info->cpuid, xlCPU)) {
                                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                        _("unsupported cpu feature '%1$s'"),
                                        def->cpu->features[i].name);
                                return -1;
                            }
                            break;
                        case VIR_CPU_FEATURE_OPTIONAL:
                        case VIR_CPU_FEATURE_LAST:
                            break;
                    }
                }
            }
#ifdef LIBXL_HAVE_BUILDINFO_NESTED_HVM
            libxl_defbool_set(&b_info->nested_hvm, hasHwVirt);
#else
            if (hvm) {
                libxl_defbool_set(&b_info->u.hvm.nested_hvm, hasHwVirt);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("unsupported nested HVM setting for %1$s machine on this Xen version"),
                        def->os.machine);
                return -1;
            }
#endif
        }

        if (def->cpu && def->cpu->mode == VIR_CPU_MODE_CUSTOM) {
            VIR_WARN("Ignoring CPU with mode=custom, update your config to "
                     "mode=host-passthrough to avoid risk of changed guest "
                     "semantics when mode=custom is supported in the future");
        }
    }

    if (hvm) {
        char bootorder[VIR_DOMAIN_BOOT_LAST + 1];

        libxl_defbool_set(&b_info->u.hvm.pae,
                          def->features[VIR_DOMAIN_FEATURE_PAE] ==
                          VIR_TRISTATE_SWITCH_ON);
#ifdef LIBXL_HAVE_BUILDINFO_APIC
        libxl_defbool_set(&b_info->apic,
                          def->features[VIR_DOMAIN_FEATURE_APIC] ==
                          VIR_TRISTATE_SWITCH_ON);
        /*
         * Strictly speaking b_info->acpi was introduced earlier (Xen 4.8), but
         * there is no separate #define in libxl.h.
         */
        libxl_defbool_set(&b_info->acpi,
                          def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                          VIR_TRISTATE_SWITCH_ON);
#else
        libxl_defbool_set(&b_info->u.hvm.apic,
                          def->features[VIR_DOMAIN_FEATURE_APIC] ==
                          VIR_TRISTATE_SWITCH_ON);
        libxl_defbool_set(&b_info->u.hvm.acpi,
                          def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                          VIR_TRISTATE_SWITCH_ON);
#endif

        /* copy SLIC table path to acpi_firmware */
        b_info->u.hvm.acpi_firmware = g_strdup(def->os.slic_table);

        if (def->nsounds > 0) {
            /*
             * Use first sound device.  man xl.cfg(5) describes soundhw as
             * a single device.  From the man page: soundhw=DEVICE
             */
            virDomainSoundDef *snd = def->sounds[0];
            const char *model = virDomainSoundModelTypeToString(snd->model);

            if (snd->model == VIR_DOMAIN_SOUND_MODEL_ICH6)
                model = "hda";

            b_info->u.hvm.soundhw = g_strdup(model);
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
                case VIR_DOMAIN_BOOT_LAST:
                    break;
            }
        }
        if (def->os.nBootDevs == 0) {
            bootorder[0] = 'c';
            bootorder[1] = '\0';
        } else {
            bootorder[def->os.nBootDevs] = '\0';
        }
        b_info->u.hvm.boot = g_strdup(bootorder);

        b_info->cmdline = g_strdup(def->os.cmdline);
        b_info->kernel = g_strdup(def->os.kernel);
        b_info->ramdisk = g_strdup(def->os.initrd);

        /*
         * libxl allows specifying the type of firmware and an optional path.
         * If the path is not explicitly specified, a default path for the given
         * firmware type is used. For EFI, it's LIBXL_FIRMWARE_DIR/ovmf.bin.
         * Currently libxl does not support specifying nvram for EFI firmwares.
         */
        if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI) {
            if (def->os.loader == NULL)
                def->os.loader = virDomainLoaderDefNew();
            if (def->os.loader->path == NULL)
                def->os.loader->path = g_strdup(cfg->firmwares[0]->name);
            if (def->os.loader->type == VIR_DOMAIN_LOADER_TYPE_NONE)
                def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
            if (def->os.loader->readonly == VIR_TRISTATE_BOOL_ABSENT)
                def->os.loader->readonly = VIR_TRISTATE_BOOL_YES;
            b_info->u.hvm.bios = LIBXL_BIOS_TYPE_OVMF;
            b_info->u.hvm.system_firmware = g_strdup(def->os.loader->path);
            def->os.firmware = VIR_DOMAIN_OS_DEF_FIRMWARE_NONE;
        } else if (virDomainDefHasOldStyleUEFI(def)) {
            b_info->u.hvm.bios = LIBXL_BIOS_TYPE_OVMF;
            b_info->u.hvm.system_firmware = g_strdup(def->os.loader->path);
        }

        if (def->os.loader) {
            if (!def->os.loader->format)
                def->os.loader->format = VIR_STORAGE_FILE_RAW;

            if (def->os.loader->format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported loader format '%1$s'"),
                               virStorageFileFormatTypeToString(def->os.loader->format));
                return -1;
            }
        }

        if (def->emulator) {
            if (!virFileExists(def->emulator)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("emulator '%1$s' not found"),
                               def->emulator);
                return -1;
            }

            if (!virFileIsExecutable(def->emulator)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("emulator '%1$s' is not executable"),
                               def->emulator);
                return -1;
            }

            VIR_FREE(b_info->device_model);
            b_info->device_model = g_strdup(def->emulator);

            b_info->device_model_version = libxlDomainGetEmulatorType(def);
        }

        if (def->nserials) {
            if (def->nserials == 1) {
                if (libxlMakeChrdevStr(def->serials[0], &b_info->u.hvm.serial) <
                    0)
                    return -1;
            } else {
                b_info->u.hvm.serial_list = *g_new0(libxl_string_list, def->nserials + 1);
                for (i = 0; i < def->nserials; i++) {
                    if (libxlMakeChrdevStr(def->serials[i],
                                           &b_info->u.hvm.serial_list[i]) < 0)
                    {
                        libxl_string_list_dispose(&b_info->u.hvm.serial_list);
                        return -1;
                    }
                }
                b_info->u.hvm.serial_list[i] = NULL;
            }
        }

        if (def->nparallels) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s",
                           _("Parallel devices are not supported by libxl"));
            return -1;
        }

        /* Disable VNC and SDL until explicitly enabled */
        libxl_defbool_set(&b_info->u.hvm.vnc.enable, 0);
        libxl_defbool_set(&b_info->u.hvm.sdl.enable, 0);

        for (i = 0; i < def->ninputs; i++) {
            char **usbdevice;

            if (def->inputs[i]->bus != VIR_DOMAIN_INPUT_BUS_USB)
                continue;

            VIR_EXPAND_N(b_info->u.hvm.usbdevice_list, nusbdevice, 1);
            usbdevice = &b_info->u.hvm.usbdevice_list[nusbdevice - 1];
            switch (def->inputs[i]->type) {
                case VIR_DOMAIN_INPUT_TYPE_MOUSE:
                    VIR_FREE(*usbdevice);
                    *usbdevice = g_strdup("mouse");
                    break;
                case VIR_DOMAIN_INPUT_TYPE_TABLET:
                    VIR_FREE(*usbdevice);
                    *usbdevice = g_strdup("tablet");
                    break;
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("Unknown input device type"));
                    return -1;
            }
        }

        /* NULL-terminate usbdevice_list */
        if (nusbdevice > 0)
            VIR_EXPAND_N(b_info->u.hvm.usbdevice_list, nusbdevice, 1);
    } else if (pvh) {
        b_info->cmdline = g_strdup(def->os.cmdline);
        b_info->kernel = g_strdup(def->os.kernel);
        b_info->ramdisk = g_strdup(def->os.initrd);
#ifdef LIBXL_HAVE_BUILDINFO_BOOTLOADER
        b_info->bootloader = g_strdup(def->os.bootloader);
        if (def->os.bootloaderArgs) {
            if (!(b_info->bootloader_args =
                  g_strsplit(def->os.bootloaderArgs, " \t\n", 0)))
                return -1;
        }
#endif
    } else {
        /*
         * For compatibility with the legacy xen toolstack, default to pygrub
         * if bootloader is not specified AND direct kernel boot is not specified.
         */
        if (def->os.bootloader) {
            b_info->u.pv.bootloader = g_strdup(def->os.bootloader);
        } else if (def->os.kernel == NULL) {
            b_info->u.pv.bootloader = g_strdup(LIBXL_BOOTLOADER_PATH);
        }
        if (def->os.bootloaderArgs) {
            if (!(b_info->u.pv.bootloader_args =
                  g_strsplit(def->os.bootloaderArgs, " \t\n", 0)))
                return -1;
        }
        b_info->u.pv.cmdline = g_strdup(def->os.cmdline);
        if (def->os.kernel) {
            /* libxl_init_build_info() sets kernel.path = g_strdup("hvmloader") */
            VIR_FREE(b_info->u.pv.kernel);
            b_info->u.pv.kernel = g_strdup(def->os.kernel);
        }
        b_info->u.pv.ramdisk = g_strdup(def->os.initrd);

        if (def->features[VIR_DOMAIN_FEATURE_XEN] == VIR_TRISTATE_SWITCH_ON) {
            switch ((virTristateSwitch) def->xen_features[VIR_DOMAIN_XEN_E820_HOST]) {
                case VIR_TRISTATE_SWITCH_ON:
                    libxl_defbool_set(&b_info->u.pv.e820_host, true);
                    break;
                case VIR_TRISTATE_SWITCH_OFF:
                    libxl_defbool_set(&b_info->u.pv.e820_host, false);
                    break;
                case VIR_TRISTATE_SWITCH_ABSENT:
                case VIR_TRISTATE_SWITCH_LAST:
                    break;
            }
        }
    }

    /* only the 'xen' balloon device model is supported */
    if (def->memballoon) {
        switch (def->memballoon->model) {
        case VIR_DOMAIN_MEMBALLOON_MODEL_XEN:
            break;
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO:
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_TRANSITIONAL:
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_NON_TRANSITIONAL:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported balloon device model '%1$s'"),
                           virDomainMemballoonModelTypeToString(def->memballoon->model));
            return -1;
        case VIR_DOMAIN_MEMBALLOON_MODEL_NONE:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s",
                           _("balloon device cannot be disabled"));
            return -1;
        case VIR_DOMAIN_MEMBALLOON_MODEL_LAST:
        default:
            virReportEnumRangeError(virDomainMemballoonModel, def->memballoon->model);
            return -1;
        }
    }

    /* Allow libxl to calculate shadow memory requirements */
    b_info->shadow_memkb =
        libxl_get_required_shadow_memory(b_info->max_memkb,
                                         b_info->max_vcpus);

    if (def->namespaceData) {
        libxlDomainXmlNsDef *nsdata = def->namespaceData;

        if (nsdata->num_args > 0)
            b_info->extra = g_strdupv(nsdata->args);
    }

    return 0;
}

static int
libxlMakeVnumaList(virDomainDef *def,
                   libxl_ctx *ctx,
                   libxl_domain_config *d_config)
{
    int ret = -1;
    size_t i, j;
    size_t nr_nodes;
    size_t num_vnuma;
    bool simulate = false;
    virBitmap *bitmap = NULL;
    virDomainNuma *numa = def->numa;
    libxl_domain_build_info *b_info = &d_config->b_info;
    libxl_physinfo physinfo;
    libxl_vnode_info *vnuma_nodes = NULL;

    if (!numa)
        return 0;

    num_vnuma = virDomainNumaGetNodeCount(numa);
    if (!num_vnuma)
        return 0;

    libxl_physinfo_init(&physinfo);
    if (libxl_get_physinfo(ctx, &physinfo) < 0) {
        libxl_physinfo_dispose(&physinfo);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        return -1;
    }
    nr_nodes = physinfo.nr_nodes;
    libxl_physinfo_dispose(&physinfo);

    if (num_vnuma > nr_nodes) {
        VIR_WARN("Number of configured numa cells %zu exceeds available physical nodes %zu. All cells will use physical node 0",
                 num_vnuma, nr_nodes);
        simulate = true;
    }

    /*
     * allocate the vnuma_nodes for assignment under b_info.
     */
    vnuma_nodes = g_new0(libxl_vnode_info, num_vnuma);

    /*
     * parse the vnuma vnodes data.
     */
    for (i = 0; i < num_vnuma; i++) {
        int cpu;
        libxl_bitmap vcpu_bitmap;
        libxl_vnode_info *p = &vnuma_nodes[i];

        libxl_vnode_info_init(p);

        /* pnode */
        p->pnode = simulate ? 0 : i;

        /* memory size */
        p->memkb = virDomainNumaGetNodeMemorySize(numa, i);

        /* vcpus */
        bitmap = virDomainNumaGetNodeCpumask(numa, i);
        if (bitmap == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("vnuma sibling %1$zu missing vcpus set"), i);
            goto cleanup;
        }

        if ((cpu = virBitmapNextSetBit(bitmap, -1)) < 0)
            goto cleanup;

        libxl_bitmap_init(&vcpu_bitmap);
        if (libxl_cpu_bitmap_alloc(ctx, &vcpu_bitmap, b_info->max_vcpus))
            abort();

        do {
            libxl_bitmap_set(&vcpu_bitmap, cpu);
        } while ((cpu = virBitmapNextSetBit(bitmap, cpu)) >= 0);

        libxl_bitmap_copy_alloc(ctx, &p->vcpus, &vcpu_bitmap);
        libxl_bitmap_dispose(&vcpu_bitmap);

        /* vdistances */
        p->distances = g_new0(uint32_t, num_vnuma);
        p->num_distances = num_vnuma;

        for (j = 0; j < num_vnuma; j++)
            p->distances[j] = virDomainNumaGetNodeDistance(numa, i, j);
    }

    b_info->vnuma_nodes = vnuma_nodes;
    b_info->num_vnuma_nodes = num_vnuma;

    ret = 0;

 cleanup:
    if (ret) {
        for (i = 0; i < num_vnuma; i++) {
            libxl_vnode_info *p = &vnuma_nodes[i];

            VIR_FREE(p->distances);
        }
        VIR_FREE(vnuma_nodes);
    }

    return ret;
}

static void
libxlDiskSetDiscard(libxl_device_disk *x_disk, virDomainDiskDiscard discard)
{
    if (!x_disk->readwrite)
        return;
    switch (discard) {
    case VIR_DOMAIN_DISK_DISCARD_DEFAULT:
    case VIR_DOMAIN_DISK_DISCARD_LAST:
        break;
    case VIR_DOMAIN_DISK_DISCARD_UNMAP:
        libxl_defbool_set(&x_disk->discard_enable, true);
        break;
    case VIR_DOMAIN_DISK_DISCARD_IGNORE:
        libxl_defbool_set(&x_disk->discard_enable, false);
        break;
    }
}

static char *
libxlMakeNetworkDiskSrcStr(virStorageSource *src,
                           const char *username,
                           const char *secret)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    switch ((virStorageNetProtocol) src->protocol) {
    case VIR_STORAGE_NET_PROTOCOL_NBD:
    case VIR_STORAGE_NET_PROTOCOL_HTTP:
    case VIR_STORAGE_NET_PROTOCOL_HTTPS:
    case VIR_STORAGE_NET_PROTOCOL_FTP:
    case VIR_STORAGE_NET_PROTOCOL_FTPS:
    case VIR_STORAGE_NET_PROTOCOL_TFTP:
    case VIR_STORAGE_NET_PROTOCOL_ISCSI:
    case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
    case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
    case VIR_STORAGE_NET_PROTOCOL_SSH:
    case VIR_STORAGE_NET_PROTOCOL_VXHS:
    case VIR_STORAGE_NET_PROTOCOL_NFS:
    case VIR_STORAGE_NET_PROTOCOL_LAST:
    case VIR_STORAGE_NET_PROTOCOL_NONE:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Unsupported network block protocol '%1$s'"),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;

    case VIR_STORAGE_NET_PROTOCOL_RBD:
        if (strchr(src->path, ':')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("':' not allowed in RBD source volume name '%1$s'"),
                           src->path);
            return NULL;
        }

        virBufferStrcat(&buf, "rbd:", src->volume, "/", src->path, NULL);

        if (username) {
            virBufferEscape(&buf, '\\', ":", ":id=%s", username);
            virBufferEscape(&buf, '\\', ":",
                            ":key=%s:auth_supported=cephx\\;none",
                            secret);
        } else {
            virBufferAddLit(&buf, ":auth_supported=none");
        }

        if (src->nhosts > 0) {
            virBufferAddLit(&buf, ":mon_host=");
            for (i = 0; i < src->nhosts; i++) {
                if (i)
                    virBufferAddLit(&buf, "\\;");

                /* assume host containing : is ipv6 */
                if (strchr(src->hosts[i].name, ':'))
                    virBufferEscape(&buf, '\\', ":", "[%s]",
                                    src->hosts[i].name);
                else
                    virBufferAsprintf(&buf, "%s", src->hosts[i].name);

                if (src->hosts[i].port)
                    virBufferAsprintf(&buf, "\\:%u", src->hosts[i].port);
            }
        }

        if (src->configFile)
            virBufferEscape(&buf, '\\', ":", ":conf=%s", src->configFile);

        return virBufferContentAndReset(&buf);
    }

    return NULL;
}

static int
libxlMakeNetworkDiskSrc(virStorageSource *src, char **srcstr)
{
    g_autoptr(virConnect) conn = NULL;
    g_autofree char *base64secret = NULL;
    char *username = NULL;

    *srcstr = NULL;
    if (src->auth && src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
        g_autofree uint8_t *secret = NULL;
        size_t secretlen = 0;
        VIR_IDENTITY_AUTORESTORE virIdentity *oldident = virIdentityElevateCurrent();

        if (!oldident)
            return -1;

        username = src->auth->username;
        if (!(conn = virConnectOpen("xen:///system")))
            return -1;

        if (virSecretGetSecretString(conn, &src->auth->seclookupdef,
                                     VIR_SECRET_USAGE_TYPE_CEPH,
                                     &secret, &secretlen) < 0)
            return -1;

        /* RBD expects an encoded secret */
        base64secret = g_base64_encode(secret, secretlen);
        virSecureErase(secret, secretlen);
    }

    *srcstr = libxlMakeNetworkDiskSrcStr(src, username, base64secret);
    virSecureEraseString(base64secret);

    if (!*srcstr)
        return -1;

    return 0;
}

int
libxlMakeDisk(virDomainDiskDef *l_disk, libxl_device_disk *x_disk)
{
    const char *driver = virDomainDiskGetDriver(l_disk);
    int format = virDomainDiskGetFormat(l_disk);
    virStorageType actual_type = virStorageSourceGetActualType(l_disk->src);

    if (actual_type == VIR_STORAGE_TYPE_NETWORK) {
        if (STRNEQ_NULLABLE(driver, "qemu")) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("only the 'qemu' driver can be used with network disks"));
            return -1;
        }
        if (libxlMakeNetworkDiskSrc(l_disk->src, &x_disk->pdev_path) < 0)
            return -1;
    } else {
        x_disk->pdev_path = g_strdup(virDomainDiskGetSource(l_disk));
    }

    x_disk->vdev = g_strdup(l_disk->dst);

    if (driver) {
        if (STREQ(driver, "tap") || STREQ(driver, "tap2")) {
            switch (format) {
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
            case VIR_STORAGE_FILE_RAW:
                x_disk->format = LIBXL_DISK_FORMAT_RAW;
                x_disk->backend = LIBXL_DISK_BACKEND_TAP;
                break;
            case VIR_STORAGE_FILE_QED:
                x_disk->format = LIBXL_DISK_FORMAT_QED;
                x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %1$s with disk driver %2$s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
        } else if (STREQ(driver, "qemu")) {
            x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
            switch (format) {
            case VIR_STORAGE_FILE_QCOW:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW;
                break;
            case VIR_STORAGE_FILE_QCOW2:
                x_disk->format = LIBXL_DISK_FORMAT_QCOW2;
                break;
            case VIR_STORAGE_FILE_QED:
                x_disk->format = LIBXL_DISK_FORMAT_QED;
                break;
            case VIR_STORAGE_FILE_VHD:
                x_disk->format = LIBXL_DISK_FORMAT_VHD;
                break;
            case VIR_STORAGE_FILE_RAW:
                x_disk->format = LIBXL_DISK_FORMAT_RAW;
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %1$s with disk driver %2$s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
        } else if (STREQ(driver, "file")) {
            if (format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %1$s with disk driver %2$s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
        } else if (STREQ(driver, "phy")) {
            if (format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %1$s with disk driver %2$s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_PHY;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight does not support disk driver %1$s"),
                           driver);
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
    x_disk->readwrite = !l_disk->src->readonly;
    x_disk->is_cdrom = l_disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ? 1 : 0;
    libxlDiskSetDiscard(x_disk, l_disk->discard);
    /* An empty CDROM must have the empty format, otherwise libxl fails. */
    if (x_disk->is_cdrom && !x_disk->pdev_path)
        x_disk->format = LIBXL_DISK_FORMAT_EMPTY;
    if (l_disk->transient) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight does not support transient disks"));
        return -1;
    }

    x_disk->backend_domname = g_strdup(l_disk->domain_name);

    return 0;
}

static int
libxlMakeDiskList(virDomainDef *def, libxl_domain_config *d_config)
{
    virDomainDiskDef **l_disks = def->disks;
    int ndisks = def->ndisks;
    size_t i;

    d_config->disks = g_new0(libxl_device_disk, ndisks);
    d_config->num_disks = ndisks;

    for (i = 0; i < ndisks; i++) {
        libxl_device_disk_init(&d_config->disks[i]);
        if (libxlMakeDisk(l_disks[i], &d_config->disks[i]) < 0)
            return -1;
    }

    return 0;
}

/*
 * Update libvirt disk config with libxl disk config.
 *
 * This function can be used to update the libvirt disk config with default
 * values selected by libxl. Currently only the backend type is selected by
 * libxl when not explicitly specified by the user.
 */
void
libxlUpdateDiskDef(virDomainDiskDef *l_disk, libxl_device_disk *x_disk)
{
    const char *driver = NULL;

    if (virDomainDiskGetDriver(l_disk))
        return;

    switch (x_disk->backend) {
    case LIBXL_DISK_BACKEND_QDISK:
        driver = "qemu";
        break;
    case LIBXL_DISK_BACKEND_TAP:
        driver = "tap";
        break;
    case LIBXL_DISK_BACKEND_PHY:
        driver = "phy";
        break;
    case LIBXL_DISK_BACKEND_UNKNOWN:
#ifdef LIBXL_HAVE_DEVICE_DISK_SPECIFICATION
    case LIBXL_DISK_BACKEND_STANDALONE:
#endif
    default:
        break;
    }
    if (driver)
        virDomainDiskSetDriver(l_disk, driver);
}

int
libxlMakeNic(virDomainDef *def,
             virDomainNetDef *l_nic,
             libxl_device_nic *x_nic,
             bool attach)
{
    virDomainNetType actual_type = virDomainNetGetActualType(l_nic);
    virNetworkPtr network = NULL;
    virConnectPtr conn = NULL;
    const virNetDevBandwidth *actual_bw;
    const virNetDevVPortProfile *port_profile;
    const virNetDevVlan *virt_vlan;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    const char *script = NULL;
    int ret = -1;

    /* TODO: Where is mtu stored?
     *
     * x_nics[i].mtu = 1492;
     */

    if (l_nic->script && !(actual_type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
                           actual_type == VIR_DOMAIN_NET_TYPE_ETHERNET)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("specifying a script is only supported with interface types bridge and ethernet"));
        return -1;
    }

    virMacAddrGetRaw(&l_nic->mac, x_nic->mac);

    /*
     * The nictype field of libxl_device_nic structure tells Xen which type of
     * NIC device to create for the domain. LIBXL_NIC_TYPE_VIF specifies a
     * PV NIC. LIBXL_NIC_TYPE_VIF_IOEMU specifies a PV and emulated NIC,
     * allowing the domain to choose which NIC to use and unplug the unused
     * one. LIBXL_NIC_TYPE_VIF_IOEMU is only valid for HVM domains. Further,
     * if hotplugging the NIC, emulated NICs are currently not supported.
     * Alternatively one could set LIBXL_NIC_TYPE_UNKNOWN and let libxl decide,
     * but its behaviour might not be consistent across all libvirt supported
     * versions. The other nictype values are well established already, hence
     * we manually select our own default and mimic xl/libxl behaviour starting
     * xen commit 32e9d0f ("libxl: nic type defaults to vif in hotplug for
     * hvm guest").
     */
    if (virDomainNetGetModelString(l_nic)) {
        if ((def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
            def->os.type == VIR_DOMAIN_OSTYPE_XENPVH) &&
            l_nic->model != VIR_DOMAIN_NET_MODEL_NETFRONT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only model 'netfront' is supported for Xen PV(H) domains"));
            return -1;
        }
        x_nic->model = g_strdup(virDomainNetGetModelString(l_nic));
        if (l_nic->model == VIR_DOMAIN_NET_MODEL_NETFRONT)
            x_nic->nictype = LIBXL_NIC_TYPE_VIF;
        else
            x_nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
    } else {
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM && !attach)
            x_nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
        else
            x_nic->nictype = LIBXL_NIC_TYPE_VIF;
    }

    x_nic->ifname = g_strdup(l_nic->ifname);

    port_profile = virDomainNetGetActualVirtPortProfile(l_nic);
    virt_vlan = virDomainNetGetActualVlan(l_nic);
    script = l_nic->script;
    switch (actual_type) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            virBufferAddStr(&buf, virDomainNetGetActualBridgeName(l_nic));
            /*
             * A bit of special handling if vif will be connected to an
             * openvswitch bridge
             */
            if (port_profile &&
                port_profile->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                /*
                 * If a custom script is not specified for openvswitch, use
                 * Xen's vif-openvswitch script
                 */
                if (!script)
                    script = "vif-openvswitch";
                /*
                 * libxl_device_nic->bridge supports an extended format for
                 * specifying VLAN tags and trunks when using openvswitch
                 *
                 * BRIDGE_NAME[.VLAN][:TRUNK:TRUNK]
                 *
                 * See Xen's networking wiki for more details
                 * https://wiki.xenproject.org/wiki/Xen_Networking#Open_vSwitch
                 */
                if (virt_vlan && virt_vlan->nTags > 0) {
                    if (virt_vlan->trunk) {
                        for (i = 0; i < virt_vlan->nTags; i++)
                            virBufferAsprintf(&buf, ":%d", virt_vlan->tag[i]);
                    } else {
                        virBufferAsprintf(&buf, ".%d", virt_vlan->tag[0]);
                    }
                }
            }
            x_nic->bridge = virBufferContentAndReset(&buf);
            G_GNUC_FALLTHROUGH;
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            x_nic->script = g_strdup(script);
            if (l_nic->guestIP.nips > 0) {
                x_nic->ip = xenMakeIPList(&l_nic->guestIP);
                if (!x_nic->ip)
                    goto cleanup;
            }
            break;
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        {
            if (!(conn = virGetConnectNetwork()))
                goto cleanup;

            if (!(network =
                  virNetworkLookupByName(conn, l_nic->data.network.name))) {
                goto cleanup;
            }

            if (l_nic->guestIP.nips > 0) {
                x_nic->ip = xenMakeIPList(&l_nic->guestIP);
                if (!x_nic->ip)
                    goto cleanup;
            }

            if (!(x_nic->bridge = virNetworkGetBridgeName(network)))
                goto cleanup;
            break;
        }
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_DIRECT:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("unsupported interface type %1$s"),
                    virDomainNetTypeToString(l_nic->type));
            goto cleanup;
    }

    if (l_nic->domain_name)
        x_nic->backend_domname = g_strdup(l_nic->domain_name);

    /*
     * Set bandwidth.
     * From $xen-sources/docs/misc/xl-network-configuration.markdown:
     *
     *
     * Specifies the rate at which the outgoing traffic will be limited to.
     * The default if this keyword is not specified is unlimited.
     *
     * The rate may be specified as "<RATE>/s" or optionally "<RATE>/s@<INTERVAL>".
     *
     * `RATE` is in bytes and can accept suffixes:
     *     GB, MB, KB, B for bytes.
     *     Gb, Mb, Kb, b for bits.
     * `INTERVAL` is in microseconds and can accept suffixes: ms, us, s.
     *     It determines the frequency at which the vif transmission credit
     *     is replenished. The default is 50ms.

     * Vif rate limiting is credit-based. It means that for "1MB/s@20ms",
     * the available credit will be equivalent of the traffic you would have
     * done at "1MB/s" during 20ms. This will results in a credit of 20,000
     * bytes replenished every 20,000 us.
     *
     *
     * libvirt doesn't support the notion of rate limiting over an interval.
     * Similar to xl's behavior when interval is not specified, set a default
     * interval of 50ms and calculate the number of bytes per interval based
     * on the specified average bandwidth.
     */
    actual_bw = virDomainNetGetActualBandwidth(l_nic);
    if (actual_bw && actual_bw->out && actual_bw->out->average) {
        uint64_t bytes_per_sec = actual_bw->out->average * 1024;
        uint64_t bytes_per_interval =
            (((uint64_t) bytes_per_sec * 50000UL) / 1000000UL);

        x_nic->rate_bytes_per_interval = bytes_per_interval;
        x_nic->rate_interval_usecs =  50000UL;
    }

    ret = 0;

 cleanup:
    virObjectUnref(network);
    virObjectUnref(conn);

    return ret;
}

static int
libxlMakeNicList(virDomainDef *def,  libxl_domain_config *d_config)
{
    virDomainNetDef **l_nics = def->nets;
    size_t nnics = def->nnets;
    libxl_device_nic *x_nics;
    size_t i, nvnics = 0;
    int ret = -1;

    x_nics = g_new0(libxl_device_nic, nnics);

    for (i = 0; i < nnics; i++) {
        if (virDomainNetGetActualType(l_nics[i]) == VIR_DOMAIN_NET_TYPE_HOSTDEV)
            continue;

        libxl_device_nic_init(&x_nics[nvnics]);
        if (libxlMakeNic(def, l_nics[i], &x_nics[nvnics], false))
            goto out;
        /*
         * The devid (at least right now) will not get initialized by
         * libxl in the setup case but is required for starting the
         * device-model.
         */
        if (x_nics[nvnics].devid < 0)
            x_nics[nvnics].devid = nvnics;

        nvnics++;
    }
    ret = 0;

 out:
    VIR_SHRINK_N(x_nics, nnics, nnics - nvnics);
    d_config->nics = x_nics;
    d_config->num_nics = nvnics;

    return ret;
}

int
libxlMakeVfb(virPortAllocatorRange *graphicsports,
             virDomainGraphicsDef *l_vfb,
             libxl_device_vfb *x_vfb)
{
    unsigned short port;
    virDomainGraphicsListenDef *glisten = NULL;

    libxl_device_vfb_init(x_vfb);

    switch (l_vfb->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            libxl_defbool_set(&x_vfb->sdl.enable, 1);
            libxl_defbool_set(&x_vfb->vnc.enable, 0);
            libxl_defbool_set(&x_vfb->sdl.opengl, 0);
            x_vfb->sdl.display = g_strdup(l_vfb->data.sdl.display);
            x_vfb->sdl.xauthority = g_strdup(l_vfb->data.sdl.xauth);
            break;
        case  VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            libxl_defbool_set(&x_vfb->vnc.enable, 1);
            libxl_defbool_set(&x_vfb->sdl.enable, 0);
            /* driver handles selection of free port */
            libxl_defbool_set(&x_vfb->vnc.findunused, 0);
            if (l_vfb->data.vnc.autoport) {

                if (virPortAllocatorAcquire(graphicsports, &port) < 0)
                    return -1;
                l_vfb->data.vnc.port = port;
            }
            x_vfb->vnc.display = l_vfb->data.vnc.port - LIBXL_VNC_PORT_MIN;

            if ((glisten = virDomainGraphicsGetListen(l_vfb, 0))) {
                if (glisten->address) {
                    /* libxl_device_vfb_init() does g_strdup("127.0.0.1") */
                    VIR_FREE(x_vfb->vnc.listen);
                    x_vfb->vnc.listen = g_strdup(glisten->address);
                } else {
                    glisten->address = g_strdup(VIR_LOOPBACK_IPV4_ADDR);
                }
            }

            x_vfb->vnc.passwd = g_strdup(l_vfb->data.vnc.auth.passwd);
            x_vfb->keymap = g_strdup(l_vfb->data.vnc.keymap);
            break;

        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
        case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
    }

    return 0;
}

static int
libxlMakeVfbList(virPortAllocatorRange *graphicsports,
                 virDomainDef *def,
                 libxl_domain_config *d_config)
{
    virDomainGraphicsDef **l_vfbs = def->graphics;
    int nvfbs = def->ngraphics;
    libxl_device_vfb *x_vfbs;
    libxl_device_vkb *x_vkbs;
    size_t i;

    if (nvfbs == 0)
        return 0;

    x_vfbs = g_new0(libxl_device_vfb, nvfbs);
    x_vkbs = g_new0(libxl_device_vkb, nvfbs);

    for (i = 0; i < nvfbs; i++) {
        libxl_device_vkb_init(&x_vkbs[i]);

        if (libxlMakeVfb(graphicsports, l_vfbs[i], &x_vfbs[i]) < 0)
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

/*
 * Populate vfb info in libxl_domain_build_info struct for HVM domains.
 * Prior to calling this function, libxlMakeVfbList must be called to
 * populate libxl_domain_config->vfbs.
 */
static int
libxlMakeBuildInfoVfb(virPortAllocatorRange *graphicsports,
                      virDomainDef *def,
                      libxl_domain_config *d_config)
{
    libxl_domain_build_info *b_info = &d_config->b_info;
    libxl_device_vfb x_vfb;
    size_t i;

    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM)
        return 0;

    if (def->ngraphics == 0)
        return 0;

    /*
     * Prefer SPICE, otherwise use first libxl_device_vfb device in
     * libxl_domain_config->vfbs. Prior to calling this function,
     */
    for (i = 0; i < def->ngraphics; i++) {
        virDomainGraphicsDef *l_vfb = def->graphics[i];
        unsigned short port;
        virDomainGraphicsListenDef *glisten = NULL;

        if (l_vfb->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
            continue;

        libxl_defbool_set(&b_info->u.hvm.spice.enable, true);

        if (l_vfb->data.spice.autoport) {
            if (virPortAllocatorAcquire(graphicsports, &port) < 0)
                return -1;
            l_vfb->data.spice.port = port;
        }
        b_info->u.hvm.spice.port = l_vfb->data.spice.port;

        if ((glisten = virDomainGraphicsGetListen(l_vfb, 0))) {
            if (glisten->address) {
                b_info->u.hvm.spice.host = g_strdup(glisten->address);
            } else {
                b_info->u.hvm.spice.host = g_strdup(VIR_LOOPBACK_IPV4_ADDR);
                glisten->address = g_strdup(VIR_LOOPBACK_IPV4_ADDR);
            }
        }

        b_info->u.hvm.keymap = g_strdup(l_vfb->data.spice.keymap);

        if (l_vfb->data.spice.auth.passwd) {
            b_info->u.hvm.spice.passwd = g_strdup(l_vfb->data.spice.auth.passwd);
            libxl_defbool_set(&b_info->u.hvm.spice.disable_ticketing, false);
        } else {
            libxl_defbool_set(&b_info->u.hvm.spice.disable_ticketing, true);
        }

        switch (l_vfb->data.spice.mousemode) {
            /* client mouse mode is default in xl.cfg */
        case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
        case VIR_DOMAIN_MOUSE_MODE_CLIENT:
            libxl_defbool_set(&b_info->u.hvm.spice.agent_mouse, true);
            break;
        case VIR_DOMAIN_MOUSE_MODE_SERVER:
            libxl_defbool_set(&b_info->u.hvm.spice.agent_mouse, false);
            break;
        case VIR_DOMAIN_MOUSE_MODE_LAST:
            break;
        }

        if (l_vfb->data.spice.copypaste == VIR_TRISTATE_BOOL_YES) {
            libxl_defbool_set(&b_info->u.hvm.spice.vdagent, true);
            libxl_defbool_set(&b_info->u.hvm.spice.clipboard_sharing, true);
        } else {
            libxl_defbool_set(&b_info->u.hvm.spice.vdagent, false);
            libxl_defbool_set(&b_info->u.hvm.spice.clipboard_sharing, false);
        }

        return 0;
    }

    x_vfb = d_config->vfbs[0];

    if (libxl_defbool_val(x_vfb.vnc.enable)) {
        libxl_defbool_set(&b_info->u.hvm.vnc.enable, true);
        b_info->u.hvm.vnc.listen = g_strdup(x_vfb.vnc.listen);
        b_info->u.hvm.vnc.passwd = g_strdup(x_vfb.vnc.passwd);
        b_info->u.hvm.vnc.display = x_vfb.vnc.display;
        libxl_defbool_set(&b_info->u.hvm.vnc.findunused,
                          libxl_defbool_val(x_vfb.vnc.findunused));
    } else if (libxl_defbool_val(x_vfb.sdl.enable)) {
        libxl_defbool_set(&b_info->u.hvm.sdl.enable, true);
        libxl_defbool_set(&b_info->u.hvm.sdl.opengl,
                          libxl_defbool_val(x_vfb.sdl.opengl));
        b_info->u.hvm.sdl.display = g_strdup(x_vfb.sdl.display);
        b_info->u.hvm.sdl.xauthority = g_strdup(x_vfb.sdl.xauthority);
    }

    b_info->u.hvm.keymap = g_strdup(x_vfb.keymap);

    return 0;
}

/*
 * Get domain0 autoballoon configuration.  Honor user-specified
 * setting in libxl.conf first.  If not specified, autoballooning
 * is disabled when domain0's memory is set with 'dom0_mem'.
 * Otherwise autoballooning is enabled.
 */
static int
libxlGetAutoballoonConf(libxlDriverConfig *cfg,
                        virConf *conf)
{
    g_autoptr(GRegex) regex = NULL;
    g_autoptr(GError) err = NULL;
    int res;

    res = virConfGetValueBool(conf, "autoballoon", &cfg->autoballoon);
    if (res < 0)
        return -1;
    else if (res == 1)
        return 0;

    regex = g_regex_new("(^| )dom0_mem=((|min:|max:)[0-9]+[bBkKmMgG]?,?)+($| )",
                        0, 0, &err);
    if (!regex) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %1$s"), err->message);
        return -1;
    }

    cfg->autoballoon = !g_regex_match(regex, cfg->verInfo->commandline, 0, NULL);
    return 0;
}

libxlDriverConfig *
libxlDriverConfigNew(void)
{
    libxlDriverConfig *cfg;

    if (libxlConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(libxlDriverConfigClass)))
        return NULL;

    cfg->configBaseDir = g_strdup(LIBXL_CONFIG_BASE_DIR);
    cfg->configDir = g_strdup(LIBXL_CONFIG_DIR);
    cfg->autostartDir = g_strdup(LIBXL_AUTOSTART_DIR);
    cfg->logDir = g_strdup(LIBXL_LOG_DIR);
    cfg->stateDir = g_strdup(LIBXL_STATE_DIR);
    cfg->libDir = g_strdup(LIBXL_LIB_DIR);
    cfg->saveDir = g_strdup(LIBXL_SAVE_DIR);
    cfg->autoDumpDir = g_strdup(LIBXL_DUMP_DIR);
    cfg->channelDir = g_strdup(LIBXL_CHANNEL_DIR);

#ifdef DEFAULT_LOADER_NVRAM
    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0) {
        virObjectUnref(cfg);
        return NULL;
    }
#else
    cfg->firmwares = g_new0(virFirmware *, 1);
    cfg->nfirmwares = 1;
    cfg->firmwares[0] = g_new0(virFirmware, 1);
    cfg->firmwares[0]->name = g_strdup(LIBXL_FIRMWARE_DIR "/ovmf.bin");
#endif

    /* Always add hvmloader to firmwares */
    VIR_REALLOC_N(cfg->firmwares, cfg->nfirmwares + 1);
    cfg->nfirmwares++;
    cfg->firmwares[cfg->nfirmwares - 1] = g_new0(virFirmware, 1);
    cfg->firmwares[cfg->nfirmwares - 1]->name = g_strdup(LIBXL_FIRMWARE_DIR "/hvmloader");

    /* defaults for keepalive messages */
    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;

    return cfg;
}

int
libxlDriverConfigInit(libxlDriverConfig *cfg)
{
    uint64_t free_mem;

    if (g_mkdir_with_parents(cfg->logDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("failed to create log dir '%1$s'"),
                             cfg->logDir);
        return -1;
    }

    cfg->logger = libxlLoggerNew(cfg->logDir, virLogGetDefaultPriority());
    if (!cfg->logger) {
        VIR_ERROR(_("cannot create logger for libxenlight, disabling driver"));
        return -1;
    }

    if (libxl_ctx_alloc(&cfg->ctx, LIBXL_VERSION, 0, (xentoollog_logger *)cfg->logger)) {
        VIR_ERROR(_("cannot initialize libxenlight context, probably not running in a Xen Dom0, disabling driver"));
        return -1;
    }

    if ((cfg->verInfo = libxl_get_version_info(cfg->ctx)) == NULL) {
        VIR_ERROR(_("cannot version information from libxenlight, disabling driver"));
        return -1;
    }
    cfg->version = (cfg->verInfo->xen_version_major * 1000000) +
        (cfg->verInfo->xen_version_minor * 1000);

    /* This will fill xenstore info about free and dom0 memory if missing,
     * should be called before starting first domain */
    if (libxlGetFreeMemoryWrapper(cfg->ctx, &free_mem)) {
        VIR_ERROR(_("Unable to configure libxl's memory management parameters"));
        return -1;
    }

    return 0;
}

libxlDriverConfig *
libxlDriverConfigGet(libxlDriverPrivate *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->config);
}

int libxlDriverConfigLoadFile(libxlDriverConfig *cfg,
                              const char *filename)
{
    g_autoptr(virConf) conf = NULL;

    /* Check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read libxl config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        return -1;

    /* setup autoballoon */
    if (libxlGetAutoballoonConf(cfg, conf) < 0)
        return -1;

    if (virConfGetValueString(conf, "lock_manager", &cfg->lockManagerName) < 0)
        return -1;

    if (virConfGetValueInt(conf, "keepalive_interval", &cfg->keepAliveInterval) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "keepalive_count", &cfg->keepAliveCount) < 0)
        return -1;

    if (virConfGetValueBool(conf, "nested_hvm", &cfg->nested_hvm) < 0)
        return -1;

    return 0;
}

/*
 * dom0's maximum memory can be controlled by the user with the 'dom0_mem' Xen
 * command line parameter. E.g. to set dom0's initial memory to 4G and max
 * memory to 8G: dom0_mem=4G,max:8G
 * Supported unit suffixes are [bBkKmMgGtT]. If not specified the default
 * unit is kilobytes.
 *
 * If not constrained by the user, dom0 can effectively use all host memory.
 * This function returns the configured maximum memory for dom0 in kilobytes,
 * either the user-specified value or total physical memory as a default.
 */
int
libxlDriverGetDom0MaxmemConf(libxlDriverConfig *cfg,
                             unsigned long long *maxmem)
{
    g_auto(GStrv) cmd_tokens = NULL;
    size_t i;
    size_t j;
    libxl_physinfo physinfo;

    if (cfg->verInfo->commandline == NULL ||
        !(cmd_tokens = g_strsplit(cfg->verInfo->commandline, " ", 0)))
        goto physmem;

    for (i = 0; cmd_tokens[i] != NULL; i++) {
        g_auto(GStrv) mem_tokens = NULL;

        if (!STRPREFIX(cmd_tokens[i], "dom0_mem="))
            continue;

        if (!(mem_tokens = g_strsplit(cmd_tokens[i], ",", 0)))
            break;
        for (j = 0; mem_tokens[j] != NULL; j++) {
            if (STRPREFIX(mem_tokens[j], "max:")) {
                char *p = mem_tokens[j] + 4;
                unsigned long long multiplier = 1;

                while (g_ascii_isdigit(*p))
                    p++;
                if (virStrToLong_ull(mem_tokens[j] + 4, &p, 10, maxmem) < 0)
                    break;
                if (*p) {
                    switch (*p) {
                    case 'm':
                    case 'M':
                        multiplier = 1024;
                        break;
                    case 'g':
                    case 'G':
                        multiplier = 1024 * 1024;
                        break;
                    case 't':
                    case 'T':
                        multiplier = 1024 * 1024 * 1024;
                        break;
                    }
                }
                *maxmem = *maxmem * multiplier;
                return 0;
            }
        }
    }

 physmem:
    /* No 'max' specified in dom0_mem, so dom0 can use all physical memory */
    libxl_physinfo_init(&physinfo);
    if (libxl_get_physinfo(cfg->ctx, &physinfo)) {
        VIR_WARN("libxl_get_physinfo failed");
        return -1;
    }
    *maxmem = (physinfo.total_pages * cfg->verInfo->pagesize) / 1024;
    libxl_physinfo_dispose(&physinfo);
    return 0;
}


static int
libxlPrepareChannel(virDomainChrDef *channel,
                    const char *channelDir,
                    const char *domainName)
{
    if (channel->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN &&
        channel->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        !channel->source->data.nix.path) {
        const char *target = channel->target.name;
        if (!target)
            target = "unknown.sock";
        channel->source->data.nix.path = g_strdup_printf("%s/%s-%s", channelDir,
                                                         domainName,
                                                         target);

        channel->source->data.nix.listen = true;
    }

    return 0;
}

static int
libxlMakeChannel(virDomainChrDef *l_channel,
                 libxl_device_channel *x_channel)
{
    libxl_device_channel_init(x_channel);

    if (l_channel->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("channel target type not supported"));
        return -1;
    }

    switch (l_channel->source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        x_channel->connection = LIBXL_CHANNEL_CONNECTION_PTY;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        x_channel->connection = LIBXL_CHANNEL_CONNECTION_SOCKET;
        x_channel->u.socket.path = g_strdup(l_channel->source->data.nix.path);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("channel source type not supported"));
        break;
    }

    if (!l_channel->target.name) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("channel target name missing"));
        return -1;
    }

    x_channel->name = g_strdup(l_channel->target.name);

    return 0;
}

static int
libxlMakeChannelList(const char *channelDir,
                     virDomainDef *def,
                     libxl_domain_config *d_config)
{
    virDomainChrDef **l_channels = def->channels;
    size_t nchannels = def->nchannels;
    libxl_device_channel *x_channels;
    size_t i, nvchannels = 0;

    x_channels = g_new0(libxl_device_channel, nchannels);

    for (i = 0; i < nchannels; i++) {
        if (l_channels[i]->deviceType != VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL)
            continue;

        if (libxlPrepareChannel(l_channels[i], channelDir, def->name) < 0)
            goto error;

        if (libxlMakeChannel(l_channels[i], &x_channels[nvchannels]) < 0)
            goto error;

        nvchannels++;
    }

    VIR_SHRINK_N(x_channels, nchannels, nchannels - nvchannels);
    d_config->channels = x_channels;
    d_config->num_channels = nvchannels;

    return 0;

 error:
    for (i = 0; i < nchannels; i++)
        libxl_device_channel_dispose(&x_channels[i]);
    VIR_FREE(x_channels);
    return -1;
}

int
libxlMakeUSBController(virDomainControllerDef *controller,
                       libxl_device_usbctrl *usbctrl)
{
    usbctrl->devid = controller->idx;

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
        return -1;

    if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT) {
        usbctrl->version = 2;
        usbctrl->type = LIBXL_USBCTRL_TYPE_QUSB;
    } else {
        switch (controller->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1:
            usbctrl->version = 1;
            usbctrl->type = LIBXL_USBCTRL_TYPE_QUSB;
            break;

        case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2:
            usbctrl->version = 2;
            usbctrl->type = LIBXL_USBCTRL_TYPE_QUSB;
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported usb model"));
            return -1;
        }
    }

    if (controller->opts.usbopts.ports == -1)
        usbctrl->ports = 8;
    else
        usbctrl->ports = controller->opts.usbopts.ports;

    return 0;
}

static int
libxlMakeDefaultUSBControllers(virDomainDef *def,
                               libxl_domain_config *d_config)
{
    virDomainControllerDef *l_controller = NULL;
    libxl_device_usbctrl *x_controllers = NULL;
    size_t nusbdevs = 0;
    size_t ncontrollers;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            nusbdevs++;
    }

    /* No controllers needed if there are no USB devs */
    if (nusbdevs == 0)
        return 0;

    /* Create USB controllers with 8 ports */
    ncontrollers = VIR_DIV_UP(nusbdevs, 8);
    x_controllers = g_new0(libxl_device_usbctrl, ncontrollers);

    for (i = 0; i < ncontrollers; i++) {
        if (!(l_controller = virDomainControllerDefNew(VIR_DOMAIN_CONTROLLER_TYPE_USB)))
            goto error;

        l_controller->model = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2;
        l_controller->idx = i;
        l_controller->opts.usbopts.ports = 8;

        libxl_device_usbctrl_init(&x_controllers[i]);

        if (libxlMakeUSBController(l_controller, &x_controllers[i]) < 0)
            goto error;

        virDomainControllerInsert(def, l_controller);

        l_controller = NULL;
    }

    d_config->usbctrls = x_controllers;
    d_config->num_usbctrls = ncontrollers;
    return 0;

 error:
     virDomainControllerDefFree(l_controller);
     for (i = 0; i < ncontrollers; i++)
         libxl_device_usbctrl_dispose(&x_controllers[i]);
     VIR_FREE(x_controllers);
     return -1;
}

static int
libxlMakeUSBControllerList(virDomainDef *def, libxl_domain_config *d_config)
{
    virDomainControllerDef **l_controllers = def->controllers;
    size_t ncontrollers = def->ncontrollers;
    size_t nusbctrls = 0;
    libxl_device_usbctrl *x_usbctrls;
    size_t i, j;

    for (i = 0; i < ncontrollers; i++) {
        if (l_controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB)
            nusbctrls++;
    }

    if (nusbctrls == 0)
        return libxlMakeDefaultUSBControllers(def, d_config);

    x_usbctrls = g_new0(libxl_device_usbctrl, nusbctrls);

    for (i = 0, j = 0; i < ncontrollers && j < nusbctrls; i++) {
        if (l_controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
            continue;

        libxl_device_usbctrl_init(&x_usbctrls[j]);

        if (libxlMakeUSBController(l_controllers[i],
                                   &x_usbctrls[j]) < 0)
            goto error;

        j++;
    }

    d_config->usbctrls = x_usbctrls;
    d_config->num_usbctrls = nusbctrls;

    return 0;

 error:
    for (i = 0; i < nusbctrls; i++)
        libxl_device_usbctrl_dispose(&x_usbctrls[i]);

    VIR_FREE(x_usbctrls);
    return -1;
}

int
libxlMakeUSB(virDomainHostdevDef *hostdev, libxl_device_usbdev *usbdev)
{
    virDomainHostdevSubsysUSB *usbsrc = &hostdev->source.subsys.u.usb;
    virUSBDevice *usb = NULL;
    int ret = -1;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return ret;
    if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
        return ret;

    if (usbsrc->bus > 0 && usbsrc->device > 0) {
        usbdev->u.hostdev.hostbus = usbsrc->bus;
        usbdev->u.hostdev.hostaddr = usbsrc->device;
    } else {
        if (virHostdevFindUSBDevice(hostdev, true, &usb) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to find USB device busnum:devnum for %1$x:%2$x"),
                           usbsrc->vendor, usbsrc->product);
            goto cleanup;
        }

        usbdev->u.hostdev.hostbus = virUSBDeviceGetBus(usb);
        usbdev->u.hostdev.hostaddr = virUSBDeviceGetDevno(usb);
    }

    ret = 0;

 cleanup:
    virUSBDeviceFree(usb);

    return ret;
}

static int
libxlMakeUSBList(virDomainDef *def, libxl_domain_config *d_config)
{
    virDomainHostdevDef **l_hostdevs = def->hostdevs;
    size_t nhostdevs = def->nhostdevs;
    size_t nusbdevs = 0;
    libxl_device_usbdev *x_usbdevs;
    size_t i, j;

    if (nhostdevs == 0)
        return 0;

    x_usbdevs = g_new0(libxl_device_usbdev, nhostdevs);

    for (i = 0, j = 0; i < nhostdevs; i++) {
        if (l_hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (l_hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        libxl_device_usbdev_init(&x_usbdevs[j]);

        if (libxlMakeUSB(l_hostdevs[i], &x_usbdevs[j]) < 0)
            goto error;

        nusbdevs++;
        j++;
    }

    VIR_SHRINK_N(x_usbdevs, nhostdevs, nhostdevs - nusbdevs);
    d_config->usbdevs = x_usbdevs;
    d_config->num_usbdevs = nusbdevs;

    return 0;

 error:
    for (i = 0; i < nusbdevs; i++)
        libxl_device_usbdev_dispose(&x_usbdevs[i]);

    VIR_FREE(x_usbdevs);
    return -1;
}

int
libxlMakePCI(virDomainHostdevDef *hostdev, libxl_device_pci *pcidev)
{
    virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return -1;
    if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
        return -1;

    pcidev->domain = pcisrc->addr.domain;
    pcidev->bus = pcisrc->addr.bus;
    pcidev->dev = pcisrc->addr.slot;
    pcidev->func = pcisrc->addr.function;
    pcidev->permissive = hostdev->writeFiltering == VIR_TRISTATE_BOOL_NO;

    return 0;
}

static int
libxlMakePCIList(virDomainDef *def, libxl_domain_config *d_config)
{
    virDomainHostdevDef **l_hostdevs = def->hostdevs;
    size_t nhostdevs = def->nhostdevs;
    size_t npcidevs = 0;
    libxl_device_pci *x_pcidevs;
    size_t i, j;

    if (nhostdevs == 0)
        return 0;

    x_pcidevs = g_new0(libxl_device_pci, nhostdevs);

    for (i = 0, j = 0; i < nhostdevs; i++) {
        if (l_hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (l_hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        libxl_device_pci_init(&x_pcidevs[j]);

        if (libxlMakePCI(l_hostdevs[i], &x_pcidevs[j]) < 0)
            goto error;

        npcidevs++;
        j++;
    }

    VIR_SHRINK_N(x_pcidevs, nhostdevs, nhostdevs - npcidevs);
    d_config->pcidevs = x_pcidevs;
    d_config->num_pcidevs = npcidevs;

    return 0;

 error:
    for (i = 0; i < npcidevs; i++)
        libxl_device_pci_dispose(&x_pcidevs[i]);

    VIR_FREE(x_pcidevs);
    return -1;
}

static int
libxlMakeVideo(virDomainDef *def, libxl_domain_config *d_config)

{
    libxl_domain_build_info *b_info = &d_config->b_info;
    int dm_type = libxlDomainGetEmulatorType(def);

    if (d_config->c_info.type != LIBXL_DOMAIN_TYPE_HVM)
        return 0;

    /*
     * Take the first defined video device (graphics card) to display
     * on the first graphics device (display).
     */
    if (def->nvideos) {
        switch (def->videos[0]->type) {
        case VIR_DOMAIN_VIDEO_TYPE_VGA:
        case VIR_DOMAIN_VIDEO_TYPE_XEN:
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_STD;
            if (dm_type == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
                if (def->videos[0]->vram < 16 * 1024) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("videoram must be at least 16MB for VGA"));
                    return -1;
                }
            } else {
                if (def->videos[0]->vram < 8 * 1024) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("videoram must be at least 8MB for VGA"));
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_CIRRUS;
            if (dm_type == LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN) {
                if (def->videos[0]->vram < 8 * 1024) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("videoram must be at least 8MB for CIRRUS"));
                    return -1;
                }
            } else {
                if (def->videos[0]->vram < 4 * 1024) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("videoram must be at least 4MB for CIRRUS"));
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_VIDEO_TYPE_QXL:
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_QXL;
            if (def->videos[0]->vram < 128 * 1024) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("videoram must be at least 128MB for QXL"));
                return -1;
            }
            break;

        case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
        case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        case VIR_DOMAIN_VIDEO_TYPE_VBOX:
        case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
        case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
        case VIR_DOMAIN_VIDEO_TYPE_GOP:
        case VIR_DOMAIN_VIDEO_TYPE_NONE:
        case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
        case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
        case VIR_DOMAIN_VIDEO_TYPE_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type %1$s is not supported by libxl"),
                           virDomainVideoTypeToString(def->videos[0]->type));
            return -1;
        }
        /* vram validated for each video type, now set it */
        b_info->video_memkb = def->videos[0]->vram;
    } else {
        libxl_defbool_set(&b_info->u.hvm.nographic, 1);
        b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_NONE;
    }

    return 0;
}

int
libxlDriverNodeGetInfo(libxlDriverPrivate *driver, virNodeInfoPtr info)
{
    libxl_physinfo phy_info;
    virArch hostarch = virArchFromHost();
    libxlDriverConfig *cfg = libxlDriverConfigGet(driver);
    int ret = -1;

    libxl_physinfo_init(&phy_info);
    if (libxl_get_physinfo(cfg->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        goto cleanup;
    }

    if (virStrcpyStatic(info->model, virArchToString(hostarch)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("host arch %1$s is too big for destination"),
                       virArchToString(hostarch));
        goto cleanup;
    }

    info->memory = phy_info.total_pages * (cfg->verInfo->pagesize / 1024);
    info->cpus = phy_info.nr_cpus;
    info->nodes = phy_info.nr_nodes;
    info->cores = phy_info.cores_per_socket;
    info->threads = phy_info.threads_per_core;
    info->sockets = 1;
    info->mhz = phy_info.cpu_khz / 1000;

    ret = 0;

 cleanup:
    libxl_physinfo_dispose(&phy_info);
    virObjectUnref(cfg);
    return ret;
}

int
libxlBuildDomainConfig(virPortAllocatorRange *graphicsports,
                       virDomainDef *def,
                       libxlDriverConfig *cfg,
                       libxl_domain_config *d_config)
{
    virCaps *caps = cfg->caps;
    libxl_ctx *ctx = cfg->ctx;

    if (libxlMakeDomCreateInfo(ctx, def, &d_config->c_info) < 0)
        return -1;

    if (libxlMakeDomBuildInfo(def, cfg, caps, d_config) < 0)
        return -1;

    if (libxlMakeVnumaList(def, ctx, d_config) < 0)
        return -1;

    if (libxlMakeDiskList(def, d_config) < 0)
        return -1;

    if (libxlMakeNicList(def, d_config) < 0)
        return -1;

    if (libxlMakeVfbList(graphicsports, def, d_config) < 0)
        return -1;

    if (libxlMakeBuildInfoVfb(graphicsports, def, d_config) < 0)
        return -1;

    if (libxlMakePCIList(def, d_config) < 0)
        return -1;

    if (libxlMakeUSBControllerList(def, d_config) < 0)
        return -1;

    if (libxlMakeUSBList(def, d_config) < 0)
        return -1;

    if (libxlMakeChannelList(cfg->channelDir, def, d_config) < 0)
        return -1;

    /*
     * Now that any potential VFBs are defined, update the build info with
     * the data of the primary display. Some day libxl might implicitly do
     * so but as it does not right now, better be explicit.
     */
    if (libxlMakeVideo(def, d_config) < 0)
        return -1;

    d_config->on_reboot = libxlActionFromVirLifecycle(def->onReboot);
    d_config->on_poweroff = libxlActionFromVirLifecycle(def->onPoweroff);
    d_config->on_crash = libxlActionFromVirLifecycle(def->onCrash);

    return 0;
}

virDomainXMLOption *
libxlCreateXMLConf(libxlDriverPrivate *driver)
{
    libxlDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&libxlDomainDefParserConfig,
                                 &libxlDomainXMLPrivateDataCallbacks,
                                 &libxlDriverDomainXMLNamespace,
                                 NULL, NULL, NULL);
}
