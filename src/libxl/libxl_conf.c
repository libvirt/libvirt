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
#include "virconf.h"
#include "virfile.h"
#include "virstring.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "libxl_domain.h"
#include "libxl_conf.h"
#include "libxl_utils.h"
#include "virstoragefile.h"
#include "secret_util.h"


#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_conf");


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
    libxlLoggerFree(cfg->logger);

    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->saveDir);
    VIR_FREE(cfg->autoDumpDir);
    VIR_FREE(cfg->lockManagerName);
    VIR_FREE(cfg->channelDir);
    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);
}


static libxl_action_on_shutdown
libxlActionFromVirLifecycle(virDomainLifecycleAction action)
{
    switch (action) {
    case VIR_DOMAIN_LIFECYCLE_DESTROY:
        return LIBXL_ACTION_ON_SHUTDOWN_DESTROY;

    case VIR_DOMAIN_LIFECYCLE_RESTART:
        return  LIBXL_ACTION_ON_SHUTDOWN_RESTART;

    case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
        return LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME;

    case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        return LIBXL_ACTION_ON_SHUTDOWN_PRESERVE;

    case VIR_DOMAIN_LIFECYCLE_LAST:
        break;
    }

    return 0;
}


static libxl_action_on_shutdown
libxlActionFromVirLifecycleCrash(virDomainLifecycleCrashAction action)
{

    switch (action) {
    case VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY:
        return LIBXL_ACTION_ON_SHUTDOWN_DESTROY;

    case VIR_DOMAIN_LIFECYCLE_CRASH_RESTART:
        return  LIBXL_ACTION_ON_SHUTDOWN_RESTART;

    case VIR_DOMAIN_LIFECYCLE_CRASH_RESTART_RENAME:
        return LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME;

    case VIR_DOMAIN_LIFECYCLE_CRASH_PRESERVE:
        return LIBXL_ACTION_ON_SHUTDOWN_PRESERVE;

    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY:
        return LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY;

    case VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART:
        return LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART;

    case VIR_DOMAIN_LIFECYCLE_CRASH_LAST:
        break;
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

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        c_info->type = LIBXL_DOMAIN_TYPE_HVM;
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
    virDomainChrSourceDefPtr srcdef = def->source;
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
        if (VIR_STRDUP(*buf, type) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (virAsprintf(buf, "%s:%s", type, srcdef->data.file.path) < 0)
            return -1;
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (VIR_STRDUP(*buf, srcdef->data.file.path) < 0)
            return -1;
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

        if (virAsprintf(buf, "udp:%s:%s@%s:%s",
                        connectHost,
                        srcdef->data.udp.connectService,
                        bindHost,
                        bindService) < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_TCP: {
        const char *prefix;

        if (srcdef->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET)
            prefix = "telnet";
        else
            prefix = "tcp";

        if (virAsprintf(buf, "%s:%s:%s%s",
                        prefix,
                        srcdef->data.tcp.host,
                        srcdef->data.tcp.service,
                        srcdef->data.tcp.listen ? ",server,nowait" : "") < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (virAsprintf(buf, "unix:%s%s",
                        srcdef->data.nix.path,
                        srcdef->data.nix.listen ? ",server,nowait" : "") < 0)
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
libxlMakeDomBuildInfo(virDomainDefPtr def,
                      libxl_ctx *ctx,
                      libxl_domain_config *d_config)
{
    libxl_domain_build_info *b_info = &d_config->b_info;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;
    size_t i;
    size_t nusbdevice = 0;

    libxl_domain_build_info_init(b_info);

    if (hvm)
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_HVM);
    else
        libxl_domain_build_info_init_type(b_info, LIBXL_DOMAIN_TYPE_PV);

    b_info->max_vcpus = virDomainDefGetVcpusMax(def);
    if (libxl_cpu_bitmap_alloc(ctx, &b_info->avail_vcpus, b_info->max_vcpus))
        return -1;
    libxl_bitmap_set_none(&b_info->avail_vcpus);
    for (i = 0; i < virDomainDefGetVcpus(def); i++)
        libxl_bitmap_set((&b_info->avail_vcpus), i);

    for (i = 0; i < def->clock.ntimers; i++) {
        switch ((virDomainTimerNameType) def->clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_TSC:
            switch (def->clock.timers[i]->mode) {
            case VIR_DOMAIN_TIMER_MODE_NATIVE:
                b_info->tsc_mode = LIBXL_TSC_MODE_NATIVE;
                break;
            case VIR_DOMAIN_TIMER_MODE_PARAVIRT:
                b_info->tsc_mode = LIBXL_TSC_MODE_NATIVE_PARAVIRT;
                break;
            case VIR_DOMAIN_TIMER_MODE_EMULATE:
                b_info->tsc_mode = LIBXL_TSC_MODE_ALWAYS_EMULATE;
                break;
            default:
                b_info->tsc_mode = LIBXL_TSC_MODE_DEFAULT;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            if (!hvm) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported timer type (name) '%s'"),
                               virDomainTimerNameTypeToString(def->clock.timers[i]->name));
                return -1;
            }
            if (def->clock.timers[i]->present == 1)
                libxl_defbool_set(&b_info->u.hvm.hpet, 1);
            break;

        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_PIT:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%s'"),
                           virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            return -1;

        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        }
    }

    b_info->sched_params.weight = 1000;
    b_info->max_memkb = virDomainDefGetMemoryInitial(def);
    b_info->target_memkb = def->mem.cur_balloon;
    if (hvm) {
        char bootorder[VIR_DOMAIN_BOOT_LAST + 1];

        libxl_defbool_set(&b_info->u.hvm.pae,
                          def->features[VIR_DOMAIN_FEATURE_PAE] ==
                          VIR_TRISTATE_SWITCH_ON);
        libxl_defbool_set(&b_info->u.hvm.apic,
                          def->features[VIR_DOMAIN_FEATURE_APIC] ==
                          VIR_TRISTATE_SWITCH_ON);
        libxl_defbool_set(&b_info->u.hvm.acpi,
                          def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                          VIR_TRISTATE_SWITCH_ON);

        if (def->nsounds > 0) {
            /*
             * Use first sound device.  man xl.cfg(5) describes soundhw as
             * a single device.  From the man page: soundhw=DEVICE
             */
            virDomainSoundDefPtr snd = def->sounds[0];

            if (VIR_STRDUP(b_info->u.hvm.soundhw,
                           virDomainSoundModelTypeToString(snd->model)) < 0)
                return -1;
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
        } else {
            bootorder[def->os.nBootDevs] = '\0';
        }
        if (VIR_STRDUP(b_info->u.hvm.boot, bootorder) < 0)
            return -1;

#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
        if (VIR_STRDUP(b_info->cmdline, def->os.cmdline) < 0)
            return -1;
        if (VIR_STRDUP(b_info->kernel, def->os.kernel) < 0)
            return -1;
        if (VIR_STRDUP(b_info->ramdisk, def->os.initrd) < 0)
            return -1;
#endif

        /*
         * Currently libxl only allows specifying the type of BIOS.
         * If the type is PFLASH, we assume OVMF and set libxl_bios_type
         * to LIBXL_BIOS_TYPE_OVMF. The path to the OVMF firmware is
         * configured when building Xen using '--with-system-ovmf='. If
         * not specified, LIBXL_FIRMWARE_DIR/ovmf.bin is used. In the
         * future, Xen will support a user-specified firmware path. See
         * http://lists.xenproject.org/archives/html/xen-devel/2016-03/msg01628.html
         */
        if (def->os.loader &&
            def->os.loader->type == VIR_DOMAIN_LOADER_TYPE_PFLASH)
            b_info->u.hvm.bios = LIBXL_BIOS_TYPE_OVMF;

        if (def->emulator) {
            if (!virFileExists(def->emulator)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("emulator '%s' not found"),
                               def->emulator);
                return -1;
            }

            if (!virFileIsExecutable(def->emulator)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("emulator '%s' is not executable"),
                               def->emulator);
                return -1;
            }

            VIR_FREE(b_info->device_model);
            if (VIR_STRDUP(b_info->device_model, def->emulator) < 0)
                return -1;

            b_info->device_model_version = libxlDomainGetEmulatorType(def);
        }

        if (def->nserials) {
            if (def->nserials == 1) {
                if (libxlMakeChrdevStr(def->serials[0], &b_info->u.hvm.serial) <
                    0)
                    return -1;
            } else {
#ifdef LIBXL_HAVE_BUILDINFO_SERIAL_LIST
                if (VIR_ALLOC_N(b_info->u.hvm.serial_list, def->nserials + 1) <
                    0)
                    return -1;
                for (i = 0; i < def->nserials; i++) {
                    if (libxlMakeChrdevStr(def->serials[i],
                                           &b_info->u.hvm.serial_list[i]) < 0)
                    {
                        libxl_string_list_dispose(&b_info->u.hvm.serial_list);
                        return -1;
                    }
                }
                b_info->u.hvm.serial_list[i] = NULL;
#else
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s",
                               _("Only one serial device is supported by libxl"));
                return -1;
#endif
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

#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
            if (VIR_EXPAND_N(b_info->u.hvm.usbdevice_list, nusbdevice, 1) < 0)
                return -1;
#else
            nusbdevice++;
            if (nusbdevice > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("libxenlight supports only one input device"));
                return -1;
            }
#endif

#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
            usbdevice = &b_info->u.hvm.usbdevice_list[nusbdevice - 1];
#else
            usbdevice = &b_info->u.hvm.usbdevice;
#endif
            switch (def->inputs[i]->type) {
                case VIR_DOMAIN_INPUT_TYPE_MOUSE:
                    VIR_FREE(*usbdevice);
                    if (VIR_STRDUP(*usbdevice, "mouse") < 0)
                        return -1;
                    break;
                case VIR_DOMAIN_INPUT_TYPE_TABLET:
                    VIR_FREE(*usbdevice);
                    if (VIR_STRDUP(*usbdevice, "tablet") < 0)
                        return -1;
                    break;
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("Unknown input device type"));
                    return -1;
            }
        }

#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
        /* NULL-terminate usbdevice_list */
        if (nusbdevice > 0 &&
            VIR_EXPAND_N(b_info->u.hvm.usbdevice_list, nusbdevice, 1) < 0) {
            VIR_DISPOSE_N(b_info->u.hvm.usbdevice_list, nusbdevice);
            return -1;
        }
#endif

        /* Allow libxl to calculate shadow memory requirements */
        b_info->shadow_memkb =
            libxl_get_required_shadow_memory(b_info->max_memkb,
                                             b_info->max_vcpus);
    } else {
        /*
         * For compatibility with the legacy xen toolstack, default to pygrub
         * if bootloader is not specified AND direct kernel boot is not specified.
         */
        if (def->os.bootloader) {
            if (VIR_STRDUP(b_info->u.pv.bootloader, def->os.bootloader) < 0)
                return -1;
        } else if (def->os.kernel == NULL) {
            if (VIR_STRDUP(b_info->u.pv.bootloader, LIBXL_BOOTLOADER_PATH) < 0)
                return -1;
        }
        if (def->os.bootloaderArgs) {
            if (!(b_info->u.pv.bootloader_args =
                  virStringSplit(def->os.bootloaderArgs, " \t\n", 0)))
                return -1;
        }
        if (VIR_STRDUP(b_info->u.pv.cmdline, def->os.cmdline) < 0)
            return -1;
        if (def->os.kernel) {
            /* libxl_init_build_info() sets VIR_STRDUP(kernel.path, "hvmloader") */
            VIR_FREE(b_info->u.pv.kernel);
            if (VIR_STRDUP(b_info->u.pv.kernel, def->os.kernel) < 0)
                return -1;
        }
        if (VIR_STRDUP(b_info->u.pv.ramdisk, def->os.initrd) < 0)
            return -1;
    }

    return 0;
}

static int
libxlDiskSetDiscard(libxl_device_disk *x_disk, int discard)
{
    if (!x_disk->readwrite)
        return 0;
#if defined(LIBXL_HAVE_LIBXL_DEVICE_DISK_DISCARD_ENABLE)
    switch ((virDomainDiskDiscard)discard) {
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
    return 0;
#else
    if (discard == VIR_DOMAIN_DISK_DISCARD_DEFAULT)
        return 0;
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("This version of libxenlight does not support "
                     "disk 'discard' option passing"));
    return -1;
#endif
}

static char *
libxlMakeNetworkDiskSrcStr(virStorageSourcePtr src,
                           const char *username,
                           const char *secret)
{
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
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
    case VIR_STORAGE_NET_PROTOCOL_LAST:
    case VIR_STORAGE_NET_PROTOCOL_NONE:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Unsupported network block protocol '%s'"),
                       virStorageNetProtocolTypeToString(src->protocol));
        goto cleanup;

    case VIR_STORAGE_NET_PROTOCOL_RBD:
        if (strchr(src->path, ':')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("':' not allowed in RBD source volume name '%s'"),
                           src->path);
            goto cleanup;
        }

        virBufferStrcat(&buf, "rbd:", src->path, NULL);

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
                    virBufferAsprintf(&buf, "\\:%s", src->hosts[i].port);
            }
        }

        if (src->configFile)
            virBufferEscape(&buf, '\\', ":", ":conf=%s", src->configFile);

        if (virBufferCheckError(&buf) < 0)
            goto cleanup;

        ret = virBufferContentAndReset(&buf);
        break;
    }

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}

static int
libxlMakeNetworkDiskSrc(virStorageSourcePtr src, char **srcstr)
{
    virConnectPtr conn = NULL;
    uint8_t *secret = NULL;
    char *base64secret = NULL;
    size_t secretlen = 0;
    char *username = NULL;
    int ret = -1;

    *srcstr = NULL;
    if (src->auth && src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
        username = src->auth->username;
        if (!(conn = virConnectOpen("xen:///system")))
            goto cleanup;

        if (virSecretGetSecretString(conn, &src->auth->seclookupdef,
                                     VIR_SECRET_USAGE_TYPE_CEPH,
                                     &secret, &secretlen) < 0)
            goto cleanup;

        /* RBD expects an encoded secret */
        if (!(base64secret = virStringEncodeBase64(secret, secretlen)))
            goto cleanup;
    }

    if (!(*srcstr = libxlMakeNetworkDiskSrcStr(src, username, base64secret)))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_DISPOSE_N(secret, secretlen);
    VIR_DISPOSE_STRING(base64secret);
    virObjectUnref(conn);
    return ret;
}

int
libxlMakeDisk(virDomainDiskDefPtr l_disk, libxl_device_disk *x_disk)
{
    const char *driver = virDomainDiskGetDriver(l_disk);
    int format = virDomainDiskGetFormat(l_disk);
    int actual_type = virStorageSourceGetActualType(l_disk->src);

    libxl_device_disk_init(x_disk);

    if (actual_type == VIR_STORAGE_TYPE_NETWORK) {
        if (STRNEQ_NULLABLE(driver, "qemu")) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("only the 'qemu' driver can be used with network disks"));
            return -1;
        }
        if (libxlMakeNetworkDiskSrc(l_disk->src, &x_disk->pdev_path) < 0)
            return -1;
    } else {
        if (VIR_STRDUP(x_disk->pdev_path, virDomainDiskGetSource(l_disk)) < 0)
        return -1;
    }

    if (VIR_STRDUP(x_disk->vdev, l_disk->dst) < 0)
        return -1;

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
            case VIR_STORAGE_FILE_NONE:
                /* No subtype specified, default to raw/tap */
            case VIR_STORAGE_FILE_RAW:
                x_disk->format = LIBXL_DISK_FORMAT_RAW;
                x_disk->backend = LIBXL_DISK_BACKEND_TAP;
                break;
#ifdef LIBXL_HAVE_QED
            case VIR_STORAGE_FILE_QED:
                x_disk->format = LIBXL_DISK_FORMAT_QED;
                x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
                break;
#endif
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
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
#ifdef LIBXL_HAVE_QED
            case VIR_STORAGE_FILE_QED:
                x_disk->format = LIBXL_DISK_FORMAT_QED;
                break;
#endif
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
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
        } else if (STREQ(driver, "file")) {
            if (format != VIR_STORAGE_FILE_NONE &&
                format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_QDISK;
        } else if (STREQ(driver, "phy")) {
            if (format != VIR_STORAGE_FILE_NONE &&
                format != VIR_STORAGE_FILE_RAW) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("libxenlight does not support disk format %s "
                                 "with disk driver %s"),
                               virStorageFileFormatTypeToString(format),
                               driver);
                return -1;
            }
            x_disk->format = LIBXL_DISK_FORMAT_RAW;
            x_disk->backend = LIBXL_DISK_BACKEND_PHY;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxenlight does not support disk driver %s"),
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
    if (libxlDiskSetDiscard(x_disk, l_disk->discard) < 0)
        return -1;
    /* An empty CDROM must have the empty format, otherwise libxl fails. */
    if (x_disk->is_cdrom && !x_disk->pdev_path)
        x_disk->format = LIBXL_DISK_FORMAT_EMPTY;
    if (l_disk->transient) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxenlight does not support transient disks"));
        return -1;
    }

    if (l_disk->domain_name) {
#ifdef LIBXL_HAVE_DEVICE_BACKEND_DOMNAME
        if (VIR_STRDUP(x_disk->backend_domname, l_disk->domain_name) < 0)
            return -1;
#else
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                _("this version of libxenlight does not "
                  "support backend domain name"));
        return -1;
#endif
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
libxlMakeNic(virDomainDefPtr def,
             virDomainNetDefPtr l_nic,
             libxl_device_nic *x_nic,
             bool attach)
{
    virDomainNetType actual_type = virDomainNetGetActualType(l_nic);
    virNetworkPtr network = NULL;
    virConnectPtr conn = NULL;
    virNetDevBandwidthPtr actual_bw;
    int ret = -1;

    /* TODO: Where is mtu stored?
     *
     * x_nics[i].mtu = 1492;
     */

    if (l_nic->script && !(actual_type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
                           actual_type == VIR_DOMAIN_NET_TYPE_ETHERNET)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("specifying a script is only supported with "
                         "interface types bridge and ethernet"));
        return -1;
    }

    libxl_device_nic_init(x_nic);

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
    if (l_nic->model) {
        if (def->os.type == VIR_DOMAIN_OSTYPE_XEN &&
            STRNEQ(l_nic->model, "netfront")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only model 'netfront' is supported for "
                             "Xen PV domains"));
            return -1;
        }
        if (VIR_STRDUP(x_nic->model, l_nic->model) < 0)
            goto cleanup;
        if (STREQ(l_nic->model, "netfront"))
            x_nic->nictype = LIBXL_NIC_TYPE_VIF;
        else
            x_nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
    } else {
        if (def->os.type == VIR_DOMAIN_OSTYPE_HVM && !attach)
            x_nic->nictype = LIBXL_NIC_TYPE_VIF_IOEMU;
        else
            x_nic->nictype = LIBXL_NIC_TYPE_VIF;
    }

    if (VIR_STRDUP(x_nic->ifname, l_nic->ifname) < 0)
        goto cleanup;

    switch (actual_type) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            if (VIR_STRDUP(x_nic->bridge,
                           virDomainNetGetActualBridgeName(l_nic)) < 0)
                goto cleanup;
            /* fallthrough */
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (VIR_STRDUP(x_nic->script, l_nic->script) < 0)
                goto cleanup;
            if (l_nic->guestIP.nips > 0) {
                x_nic->ip = virSocketAddrFormat(&l_nic->guestIP.ips[0]->address);
                if (!x_nic->ip)
                    goto cleanup;
            }
            break;
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        {
            if (!(conn = virConnectOpen("xen:///system")))
                goto cleanup;

            if (!(network =
                  virNetworkLookupByName(conn, l_nic->data.network.name))) {
                goto cleanup;
            }

            if (l_nic->guestIP.nips > 0) {
                x_nic->ip = virSocketAddrFormat(&l_nic->guestIP.ips[0]->address);
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
        case VIR_DOMAIN_NET_TYPE_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("unsupported interface type %s"),
                    virDomainNetTypeToString(l_nic->type));
            goto cleanup;
    }

    if (l_nic->domain_name) {
#ifdef LIBXL_HAVE_DEVICE_BACKEND_DOMNAME
        if (VIR_STRDUP(x_nic->backend_domname, l_nic->domain_name) < 0)
            goto cleanup;
#else
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                _("this version of libxenlight does not "
                  "support backend domain name"));
        goto cleanup;
#endif
    }

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
libxlMakeNicList(virDomainDefPtr def,  libxl_domain_config *d_config)
{
    virDomainNetDefPtr *l_nics = def->nets;
    size_t nnics = def->nnets;
    libxl_device_nic *x_nics;
    size_t i, nvnics = 0;

    if (VIR_ALLOC_N(x_nics, nnics) < 0)
        return -1;

    for (i = 0; i < nnics; i++) {
        if (virDomainNetGetActualType(l_nics[i]) == VIR_DOMAIN_NET_TYPE_HOSTDEV)
            continue;

        if (libxlMakeNic(def, l_nics[i], &x_nics[nvnics], false))
            goto error;
        /*
         * The devid (at least right now) will not get initialized by
         * libxl in the setup case but is required for starting the
         * device-model.
         */
        if (x_nics[nvnics].devid < 0)
            x_nics[nvnics].devid = nvnics;

        nvnics++;
    }

    VIR_SHRINK_N(x_nics, nnics, nnics - nvnics);
    d_config->nics = x_nics;
    d_config->num_nics = nvnics;

    return 0;

 error:
    for (i = 0; i < nnics; i++)
        libxl_device_nic_dispose(&x_nics[i]);
    VIR_FREE(x_nics);
    return -1;
}

int
libxlMakeVfb(virPortAllocatorPtr graphicsports,
             virDomainGraphicsDefPtr l_vfb,
             libxl_device_vfb *x_vfb)
{
    unsigned short port;
    virDomainGraphicsListenDefPtr glisten = NULL;

    libxl_device_vfb_init(x_vfb);

    switch (l_vfb->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            libxl_defbool_set(&x_vfb->sdl.enable, 1);
            libxl_defbool_set(&x_vfb->vnc.enable, 0);
            libxl_defbool_set(&x_vfb->sdl.opengl, 0);
            if (VIR_STRDUP(x_vfb->sdl.display, l_vfb->data.sdl.display) < 0)
                return -1;
            if (VIR_STRDUP(x_vfb->sdl.xauthority, l_vfb->data.sdl.xauth) < 0)
                return -1;
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

            if ((glisten = virDomainGraphicsGetListen(l_vfb, 0)) &&
                glisten->address) {
                /* libxl_device_vfb_init() does VIR_STRDUP("127.0.0.1") */
                VIR_FREE(x_vfb->vnc.listen);
                if (VIR_STRDUP(x_vfb->vnc.listen, glisten->address) < 0)
                    return -1;
            }
            if (VIR_STRDUP(x_vfb->vnc.passwd, l_vfb->data.vnc.auth.passwd) < 0)
                return -1;
            if (VIR_STRDUP(x_vfb->keymap, l_vfb->data.vnc.keymap) < 0)
                return -1;
            break;

        case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
        case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
            break;
    }

    return 0;
}

static int
libxlMakeVfbList(virPortAllocatorPtr graphicsports,
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
libxlMakeBuildInfoVfb(virPortAllocatorPtr graphicsports,
                      virDomainDefPtr def,
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
        virDomainGraphicsDefPtr l_vfb = def->graphics[i];
        unsigned short port;
        virDomainGraphicsListenDefPtr glisten = NULL;

        if (l_vfb->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
            continue;

        libxl_defbool_set(&b_info->u.hvm.spice.enable, true);

        if (l_vfb->data.spice.autoport) {
            if (virPortAllocatorAcquire(graphicsports, &port) < 0)
                return -1;
            l_vfb->data.spice.port = port;
        }
        b_info->u.hvm.spice.port = l_vfb->data.spice.port;

        if ((glisten = virDomainGraphicsGetListen(l_vfb, 0)) &&
            glisten->address &&
            VIR_STRDUP(b_info->u.hvm.spice.host, glisten->address) < 0)
            return -1;

        if (VIR_STRDUP(b_info->u.hvm.keymap, l_vfb->data.spice.keymap) < 0)
            return -1;

        if (l_vfb->data.spice.auth.passwd) {
            if (VIR_STRDUP(b_info->u.hvm.spice.passwd,
                           l_vfb->data.spice.auth.passwd) < 0)
                return -1;
            libxl_defbool_set(&b_info->u.hvm.spice.disable_ticketing, false);
        } else {
            libxl_defbool_set(&b_info->u.hvm.spice.disable_ticketing, true);
        }

        switch (l_vfb->data.spice.mousemode) {
            /* client mouse mode is default in xl.cfg */
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_DEFAULT:
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT:
            libxl_defbool_set(&b_info->u.hvm.spice.agent_mouse, true);
            break;
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER:
            libxl_defbool_set(&b_info->u.hvm.spice.agent_mouse, false);
            break;
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_LAST:
            break;
        }

#ifdef LIBXL_HAVE_SPICE_VDAGENT
        if (l_vfb->data.spice.copypaste == VIR_TRISTATE_BOOL_YES) {
            libxl_defbool_set(&b_info->u.hvm.spice.vdagent, true);
            libxl_defbool_set(&b_info->u.hvm.spice.clipboard_sharing, true);
        } else {
            libxl_defbool_set(&b_info->u.hvm.spice.vdagent, false);
            libxl_defbool_set(&b_info->u.hvm.spice.clipboard_sharing, false);
        }
#endif

        return 0;
    }

    x_vfb = d_config->vfbs[0];

    if (libxl_defbool_val(x_vfb.vnc.enable)) {
        libxl_defbool_set(&b_info->u.hvm.vnc.enable, true);
        if (VIR_STRDUP(b_info->u.hvm.vnc.listen, x_vfb.vnc.listen) < 0)
            return -1;
        if (VIR_STRDUP(b_info->u.hvm.vnc.passwd, x_vfb.vnc.passwd) < 0)
            return -1;
        b_info->u.hvm.vnc.display = x_vfb.vnc.display;
        libxl_defbool_set(&b_info->u.hvm.vnc.findunused,
                          libxl_defbool_val(x_vfb.vnc.findunused));
    } else if (libxl_defbool_val(x_vfb.sdl.enable)) {
        libxl_defbool_set(&b_info->u.hvm.sdl.enable, true);
        libxl_defbool_set(&b_info->u.hvm.sdl.opengl,
                          libxl_defbool_val(x_vfb.sdl.opengl));
        if (VIR_STRDUP(b_info->u.hvm.sdl.display, x_vfb.sdl.display) < 0)
            return -1;
        if (VIR_STRDUP(b_info->u.hvm.sdl.xauthority, x_vfb.sdl.xauthority) < 0)
            return -1;
    }

    if (VIR_STRDUP(b_info->u.hvm.keymap, x_vfb.keymap) < 0)
        return -1;

    return 0;
}

/*
 * Get domain0 autoballoon configuration.  Honor user-specified
 * setting in libxl.conf first.  If not specified, autoballooning
 * is disabled when domain0's memory is set with 'dom0_mem'.
 * Otherwise autoballooning is enabled.
 */
static int
libxlGetAutoballoonConf(libxlDriverConfigPtr cfg,
                        virConfPtr conf)
{
    regex_t regex;
    int res;

    res = virConfGetValueBool(conf, "autoballoon", &cfg->autoballoon);
    if (res < 0)
        return -1;
    else if (res == 1)
        return 0;

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
    cfg->autoballoon = res == REG_NOMATCH;
    return 0;
}

libxlDriverConfigPtr
libxlDriverConfigNew(void)
{
    libxlDriverConfigPtr cfg;
    char ebuf[1024];
    unsigned int free_mem;

    if (libxlConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(libxlDriverConfigClass)))
        return NULL;

    if (VIR_STRDUP(cfg->configBaseDir, LIBXL_CONFIG_BASE_DIR) < 0)
        goto error;
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
    if (VIR_STRDUP(cfg->autoDumpDir, LIBXL_DUMP_DIR) < 0)
        goto error;
    if (VIR_STRDUP(cfg->channelDir, LIBXL_CHANNEL_DIR) < 0)
        goto error;

    if (virFileMakePath(cfg->logDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create log dir '%s': %s"),
                       cfg->logDir,
                       virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }

    cfg->logger = libxlLoggerNew(cfg->logDir, virLogGetDefaultPriority());
    if (!cfg->logger) {
        VIR_ERROR(_("cannot create logger for libxenlight, disabling driver"));
        goto error;
    }

    if (libxl_ctx_alloc(&cfg->ctx, LIBXL_VERSION, 0, (xentoollog_logger *)cfg->logger)) {
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

#ifdef DEFAULT_LOADER_NVRAM
    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0)
        goto error;

#else
    if (VIR_ALLOC_N(cfg->firmwares, 1) < 0)
        goto error;
    cfg->nfirmwares = 1;
    if (VIR_ALLOC(cfg->firmwares[0]) < 0)
        goto error;
    if (VIR_STRDUP(cfg->firmwares[0]->name,
                   LIBXL_FIRMWARE_DIR "/ovmf.bin") < 0)
        goto error;
#endif

    /* Always add hvmloader to firmwares */
    if (VIR_REALLOC_N(cfg->firmwares, cfg->nfirmwares + 1) < 0)
        goto error;
    cfg->nfirmwares++;
    if (VIR_ALLOC(cfg->firmwares[cfg->nfirmwares - 1]) < 0)
        goto error;
    if (VIR_STRDUP(cfg->firmwares[cfg->nfirmwares - 1]->name,
                   LIBXL_FIRMWARE_DIR "/hvmloader") < 0)
        goto error;

    return cfg;

 error:
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

int libxlDriverConfigLoadFile(libxlDriverConfigPtr cfg,
                              const char *filename)
{
    virConfPtr conf = NULL;
    int ret = -1;

    /* defaults for keepalive messages */
    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;

    /* Check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read libxl config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        goto cleanup;

    /* setup autoballoon */
    if (libxlGetAutoballoonConf(cfg, conf) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "lock_manager", &cfg->lockManagerName) < 0)
        goto cleanup;

    if (virConfGetValueInt(conf, "keepalive_interval", &cfg->keepAliveInterval) < 0)
        goto cleanup;

    if (virConfGetValueUInt(conf, "keepalive_count", &cfg->keepAliveCount) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virConfFree(conf);
    return ret;

}

#ifdef LIBXL_HAVE_DEVICE_CHANNEL
static int
libxlPrepareChannel(virDomainChrDefPtr channel,
                    const char *channelDir,
                    const char *domainName)
{
    if (channel->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN &&
        channel->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        !channel->source->data.nix.path) {
        if (virAsprintf(&channel->source->data.nix.path,
                        "%s/%s-%s", channelDir, domainName,
                        channel->target.name ? channel->target.name
                        : "unknown.sock") < 0)
            return -1;

        channel->source->data.nix.listen = true;
    }

    return 0;
}

static int
libxlMakeChannel(virDomainChrDefPtr l_channel,
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
        if (VIR_STRDUP(x_channel->u.socket.path,
                       l_channel->source->data.nix.path) < 0)
            return -1;
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

    if (VIR_STRDUP(x_channel->name, l_channel->target.name) < 0)
        return -1;

    return 0;
}

static int
libxlMakeChannelList(const char *channelDir,
                     virDomainDefPtr def,
                     libxl_domain_config *d_config)
{
    virDomainChrDefPtr *l_channels = def->channels;
    size_t nchannels = def->nchannels;
    libxl_device_channel *x_channels;
    size_t i, nvchannels = 0;

    if (VIR_ALLOC_N(x_channels, nchannels) < 0)
        return -1;

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
#endif

#ifdef LIBXL_HAVE_PVUSB
int
libxlMakeUSBController(virDomainControllerDefPtr controller,
                       libxl_device_usbctrl *usbctrl)
{
    usbctrl->devid = controller->idx;

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
        return -1;

    if (controller->model == -1) {
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
libxlMakeUSBControllerList(virDomainDefPtr def, libxl_domain_config *d_config)
{
    virDomainControllerDefPtr *l_controllers = def->controllers;
    size_t ncontrollers = def->ncontrollers;
    size_t nusbctrls = 0;
    libxl_device_usbctrl *x_usbctrls;
    size_t i;

    if (ncontrollers == 0)
        return 0;

    if (VIR_ALLOC_N(x_usbctrls, ncontrollers) < 0)
        return -1;

    for (i = 0; i < ncontrollers; i++) {
        if (l_controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_USB)
            continue;

        libxl_device_usbctrl_init(&x_usbctrls[nusbctrls]);

        if (libxlMakeUSBController(l_controllers[i],
                                   &x_usbctrls[nusbctrls]) < 0)
            goto error;

        nusbctrls++;
    }

    VIR_SHRINK_N(x_usbctrls, ncontrollers, ncontrollers - nusbctrls);
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
libxlMakeUSB(virDomainHostdevDefPtr hostdev, libxl_device_usbdev *usbdev)
{
    virDomainHostdevSubsysUSBPtr usbsrc = &hostdev->source.subsys.u.usb;
    virUSBDevicePtr usb = NULL;
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
                           _("failed to find USB device busnum:devnum "
                             "for %x:%x"),
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
libxlMakeUSBList(virDomainDefPtr def, libxl_domain_config *d_config)
{
    virDomainHostdevDefPtr *l_hostdevs = def->hostdevs;
    size_t nhostdevs = def->nhostdevs;
    size_t nusbdevs = 0;
    libxl_device_usbdev *x_usbdevs;
    size_t i, j;

    if (nhostdevs == 0)
        return 0;

    if (VIR_ALLOC_N(x_usbdevs, nhostdevs) < 0)
        return -1;

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
#endif

int
libxlMakePCI(virDomainHostdevDefPtr hostdev, libxl_device_pci *pcidev)
{
    virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return -1;
    if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
        return -1;

    pcidev->domain = pcisrc->addr.domain;
    pcidev->bus = pcisrc->addr.bus;
    pcidev->dev = pcisrc->addr.slot;
    pcidev->func = pcisrc->addr.function;

    return 0;
}

static int
libxlMakePCIList(virDomainDefPtr def, libxl_domain_config *d_config)
{
    virDomainHostdevDefPtr *l_hostdevs = def->hostdevs;
    size_t nhostdevs = def->nhostdevs;
    size_t npcidevs = 0;
    libxl_device_pci *x_pcidevs;
    size_t i, j;

    if (nhostdevs == 0)
        return 0;

    if (VIR_ALLOC_N(x_pcidevs, nhostdevs) < 0)
        return -1;

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
libxlMakeVideo(virDomainDefPtr def, libxl_domain_config *d_config)

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

#ifdef LIBXL_HAVE_QXL
        case VIR_DOMAIN_VIDEO_TYPE_QXL:
            b_info->u.hvm.vga.kind = LIBXL_VGA_INTERFACE_TYPE_QXL;
            if (def->videos[0]->vram < 128 * 1024) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("videoram must be at least 128MB for QXL"));
                return -1;
            }
            break;
#endif

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type %s is not supported by libxl"),
                           virDomainVideoTypeToString(def->videos[0]->type));
            return -1;
        }
        /* vram validated for each video type, now set it */
        b_info->video_memkb = def->videos[0]->vram;
    } else {
        libxl_defbool_set(&b_info->u.hvm.nographic, 1);
    }

    return 0;
}

int
libxlDriverNodeGetInfo(libxlDriverPrivatePtr driver, virNodeInfoPtr info)
{
    libxl_physinfo phy_info;
    virArch hostarch = virArchFromHost();
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    int ret = -1;

    libxl_physinfo_init(&phy_info);
    if (libxl_get_physinfo(cfg->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        goto cleanup;
    }

    if (virStrcpyStatic(info->model, virArchToString(hostarch)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("machine type %s too big for destination"),
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
libxlBuildDomainConfig(virPortAllocatorPtr graphicsports,
                       virDomainDefPtr def,
                       const char *channelDir LIBXL_ATTR_UNUSED,
                       libxl_ctx *ctx,
                       libxl_domain_config *d_config)
{
    libxl_domain_config_init(d_config);

    if (libxlMakeDomCreateInfo(ctx, def, &d_config->c_info) < 0)
        return -1;

    if (libxlMakeDomBuildInfo(def, ctx, d_config) < 0)
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

#ifdef LIBXL_HAVE_PVUSB
    if (libxlMakeUSBControllerList(def, d_config) < 0)
        return -1;

    if (libxlMakeUSBList(def, d_config) < 0)
        return -1;
#endif

#ifdef LIBXL_HAVE_DEVICE_CHANNEL
    if (libxlMakeChannelList(channelDir, def, d_config) < 0)
        return -1;
#endif

    /*
     * Now that any potential VFBs are defined, update the build info with
     * the data of the primary display. Some day libxl might implicitely do
     * so but as it does not right now, better be explicit.
     */
    if (libxlMakeVideo(def, d_config) < 0)
        return -1;

    d_config->on_reboot = libxlActionFromVirLifecycle(def->onReboot);
    d_config->on_poweroff = libxlActionFromVirLifecycle(def->onPoweroff);
    d_config->on_crash = libxlActionFromVirLifecycleCrash(def->onCrash);

    return 0;
}

virDomainXMLOptionPtr
libxlCreateXMLConf(void)
{
    return virDomainXMLOptionNew(&libxlDomainDefParserConfig,
                                 &libxlDomainXMLPrivateDataCallbacks,
                                 NULL);
}
