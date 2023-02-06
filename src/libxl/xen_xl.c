/*
 * xen_xl.c: Xen XL parsing functions
 *
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2014 David Kiarie Kahurani
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

#include "virconf.h"
#include "virerror.h"
#include "virlog.h"
#include "domain_conf.h"
#include "domain_postparse.h"
#include "viralloc.h"
#include "virstring.h"
#include "storage_source_backingstore.h"
#include "xen_xl.h"
#include "libxl_capabilities.h"
#include "libxl_conf.h"
#include "cpu/cpu.h"

#define VIR_FROM_THIS VIR_FROM_XENXL

VIR_LOG_INIT("xen.xen_xl");

/*
 * Xen provides a libxl utility library, with several useful functions,
 * specifically xlu_disk_parse for parsing xl disk config strings.
 * Although the libxlutil library is installed, until recently the
 * corresponding header file wasn't.  Use the header file if detected during
 * configure, otherwise provide extern declarations for any functions used.
 */
#ifdef WITH_LIBXLUTIL_H
# include <libxlutil.h>
#else
typedef struct XLU_Config XLU_Config;

extern XLU_Config *xlu_cfg_init(FILE *report,
                                const char *report_filename);

extern void xlu_cfg_destroy(XLU_Config*);

extern int xlu_disk_parse(XLU_Config *cfg,
                          int nspecs,
                          const char *const *specs,
                          libxl_device_disk *disk);
#endif

static int xenParseCmdline(virConf *conf, char **r_cmdline)
{
    char *cmdline = NULL;
    g_autofree char *root = NULL;
    g_autofree char *extra = NULL;
    g_autofree char *buf = NULL;

    if (xenConfigGetString(conf, "cmdline", &buf, NULL) < 0)
        return -1;

    if (xenConfigGetString(conf, "root", &root, NULL) < 0)
        return -1;

    if (xenConfigGetString(conf, "extra", &extra, NULL) < 0)
        return -1;

    if (buf) {
        cmdline = g_strdup(buf);
        if (root || extra)
            VIR_WARN("ignoring root= and extra= in favour of cmdline=");
    } else {
        if (root && extra) {
            cmdline = g_strdup_printf("root=%s %s", root, extra);
        } else if (root) {
            cmdline = g_strdup_printf("root=%s", root);
        } else if (extra) {
            cmdline = g_strdup(extra);
        }
    }

    *r_cmdline = cmdline;
    return 0;
}

static int
xenParseXLOS(virConf *conf, virDomainDef *def, virCaps *caps)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        g_autofree char *bios = NULL;
        g_autofree char *bios_path = NULL;
        g_autofree char *boot = NULL;
        int val = 0;

        if (xenConfigGetString(conf, "bios", &bios, NULL) < 0)
            return -1;
        if (xenConfigGetString(conf, "bios_path_override", &bios_path, NULL) < 0)
            return -1;

        if (bios && STREQ(bios, "ovmf")) {
            def->os.loader = virDomainLoaderDefNew();
            def->os.loader->format = VIR_STORAGE_FILE_RAW;
            def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
            def->os.loader->readonly = VIR_TRISTATE_BOOL_YES;
            if (bios_path)
                def->os.loader->path = g_strdup(bios_path);
            else
                def->os.loader->path = g_strdup(LIBXL_FIRMWARE_DIR "/ovmf.bin");
        } else {
            for (i = 0; i < caps->nguests; i++) {
                if (caps->guests[i]->ostype == VIR_DOMAIN_OSTYPE_HVM &&
                    caps->guests[i]->arch.id == def->os.arch) {
                    def->os.loader = virDomainLoaderDefNew();
                    def->os.loader->format = VIR_STORAGE_FILE_RAW;
                    def->os.loader->path = g_strdup(caps->guests[i]->arch.defaultInfo.loader);
                }
            }
        }

        if (xenConfigCopyStringOpt(conf, "acpi_firmware", &def->os.slic_table) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            return -1;

        if (xenParseCmdline(conf, &def->os.cmdline) < 0)
            return -1;

        if (xenConfigGetString(conf, "boot", &boot, "c") < 0)
            return -1;

        for (i = 0; i < VIR_DOMAIN_BOOT_LAST && boot[i]; i++) {
            switch (boot[i]) {
            case 'a':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_FLOPPY;
                break;
            case 'd':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_CDROM;
                break;
            case 'n':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_NET;
                break;
            case 'c':
            default:
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_DISK;
                break;
            }
            def->os.nBootDevs++;
        }

        if (xenConfigGetBool(conf, "nestedhvm", &val, -1) < 0)
            return -1;

        if (val != -1) {
            const char *vtfeature = "vmx";

            if (caps && caps->host.cpu && ARCH_IS_X86(def->os.arch)) {
                if (virCPUCheckFeature(caps->host.arch, caps->host.cpu, "vmx"))
                    vtfeature = "vmx";
                else if (virCPUCheckFeature(caps->host.arch, caps->host.cpu, "svm"))
                    vtfeature = "svm";
            }

            if (!def->cpu) {
                virCPUDef *cpu = virCPUDefNew();
                cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
                cpu->type = VIR_CPU_TYPE_GUEST;
                cpu->nfeatures = 0;
                cpu->nfeatures_max = 0;
                def->cpu = cpu;
            }

            if (val == 0) {
                if (virCPUDefAddFeature(def->cpu,
                                        vtfeature,
                                        VIR_CPU_FEATURE_DISABLE) < 0)
                    return -1;
            }
        }
    } else {
        if (xenConfigCopyStringOpt(conf, "bootloader", &def->os.bootloader) < 0)
            return -1;
        if (xenConfigCopyStringOpt(conf, "bootargs", &def->os.bootloaderArgs) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            return -1;

        if (xenParseCmdline(conf, &def->os.cmdline) < 0)
            return -1;
    }

    return 0;
}

/*
 * Translate CPU feature name from libvirt to libxl (from_libxl=false) or from
 * libxl to libvirt (from_libxl=true).
 */
const char *
xenTranslateCPUFeature(const char *feature_name, bool from_libxl)
{
    static const char *translation_table[][2] = {
        /* libvirt name, libxl name */
        { "cx16", "cmpxchg16" },
        { "cid", "cntxid" },
        { "ds_cpl", "dscpl" },
        { "pclmuldq", "pclmulqdq" },
        { "pni", "sse3" },
        { "ht", "htt" },
        { "pn", "psn" },
        { "clflush", "clfsh" },
        { "sep", "sysenter" },
        { "cx8", "cmpxchg8" },
        { "nodeid_msr", "nodeid" },
        { "cr8legacy", "altmovcr8" },
        { "lahf_lm", "lahfsahf" },
        { "cmp_legacy", "cmplegacy" },
        { "fxsr_opt", "ffxsr" },
        { "pdpe1gb", "page1gb" },
        { "spec-ctrl", "ibrsb" },
    };
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(translation_table); i++)
        if (STREQ(translation_table[i][from_libxl], feature_name))
            return translation_table[i][!from_libxl];
    return feature_name;
}

static int
xenParseXLCPUID(virConf *conf, virDomainDef *def)
{
    g_autofree char *cpuid_str = NULL;
    g_auto(GStrv) cpuid_pairs = NULL;
    size_t i;
    int policy;

    if (xenConfigGetString(conf, "cpuid", &cpuid_str, NULL) < 0)
        return -1;

    if (!cpuid_str)
        return 0;

    if (!def->cpu) {
        def->cpu = virCPUDefNew();
        def->cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
        def->cpu->type = VIR_CPU_TYPE_GUEST;
        def->cpu->nfeatures = 0;
        def->cpu->nfeatures_max = 0;
    }

    cpuid_pairs = g_strsplit(cpuid_str, ",", 0);
    if (!cpuid_pairs)
        return -1;

    if (!cpuid_pairs[0])
        return 0;

    if (STRNEQ(cpuid_pairs[0], "host")) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("cpuid starting with %1$s is not supported, only libxl format is"),
                       cpuid_pairs[0]);
        return -1;
    }

    for (i = 1; cpuid_pairs[i]; i++) {
        g_auto(GStrv) name_and_value = g_strsplit(cpuid_pairs[i], "=", 2);
        if (!name_and_value)
            return -1;
        if (!name_and_value[0] || !name_and_value[1]) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Invalid libxl cpuid key=value element: %1$s"),
                           cpuid_pairs[i]);
            return -1;
        }
        if (STREQ(name_and_value[1], "1")) {
            policy = VIR_CPU_FEATURE_FORCE;
        } else if (STREQ(name_and_value[1], "0")) {
            policy = VIR_CPU_FEATURE_DISABLE;
        } else if (STREQ(name_and_value[1], "x")) {
            policy = VIR_CPU_FEATURE_OPTIONAL;
        } else if (STREQ(name_and_value[1], "k")) {
            policy = VIR_CPU_FEATURE_OPTIONAL;
        } else if (STREQ(name_and_value[1], "s")) {
            policy = VIR_CPU_FEATURE_OPTIONAL;
        } else {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Invalid libxl cpuid value: %1$s"),
                           cpuid_pairs[i]);
            return -1;
        }

        if (virCPUDefAddFeature(def->cpu,
                                xenTranslateCPUFeature(name_and_value[0], true),
                                policy) < 0)
            return -1;
    }

    return 0;
}


static int
xenParseXLSpice(virConf *conf, virDomainDef *def)
{
    virDomainGraphicsDef *graphics = NULL;
    unsigned long port;
    int val;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        g_autofree char *listenAddr = NULL;

        if (xenConfigGetBool(conf, "spice", &val, 0) < 0)
            return -1;

        if (val) {
            graphics = g_new0(virDomainGraphicsDef, 1);
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SPICE;
            if (xenConfigCopyStringOpt(conf, "spicehost", &listenAddr) < 0)
                goto cleanup;
            if (virDomainGraphicsListenAppendAddress(graphics, listenAddr) < 0)
                goto cleanup;

            if (xenConfigGetULong(conf, "spicetls_port", &port, 0) < 0)
                goto cleanup;
            graphics->data.spice.tlsPort = (int)port;

            if (xenConfigGetULong(conf, "spiceport", &port, 0) < 0)
                goto cleanup;

            graphics->data.spice.port = (int)port;

            if (!graphics->data.spice.tlsPort && !graphics->data.spice.port)
                graphics->data.spice.autoport = 1;

            if (xenConfigGetBool(conf, "spicedisable_ticketing", &val, 0) < 0)
                goto cleanup;
            if (!val) {
                if (xenConfigCopyString(conf, "spicepasswd",
                                        &graphics->data.spice.auth.passwd) < 0)
                    goto cleanup;
            }

            if (xenConfigGetBool(conf, "spiceagent_mouse",
                                 &val, 0) < 0)
                goto cleanup;
            if (val) {
                graphics->data.spice.mousemode = VIR_DOMAIN_MOUSE_MODE_CLIENT;
            } else {
                graphics->data.spice.mousemode = VIR_DOMAIN_MOUSE_MODE_SERVER;
            }

            if (xenConfigGetBool(conf, "spice_clipboard_sharing", &val, 0) < 0)
                goto cleanup;
            if (val)
                graphics->data.spice.copypaste = VIR_TRISTATE_BOOL_YES;
            else
                graphics->data.spice.copypaste = VIR_TRISTATE_BOOL_NO;

            def->graphics = g_new0(virDomainGraphicsDef *, 1);
            def->graphics[0] = graphics;
            def->ngraphics = 1;
        }
    }

    return 0;

 cleanup:
    virDomainGraphicsDefFree(graphics);
    return -1;
}

static int
xenParseXLVnuma(virConf *conf,
                virDomainDef *def)
{
    size_t vcpus = 0;
    size_t nr_nodes = 0;
    size_t vnodeCnt = 0;
    g_autoptr(virCPUDef) cpu = NULL;
    virConfValue *list;
    virConfValue *vnode;
    virDomainNuma *numa;

    numa = def->numa;
    if (numa == NULL)
        return -1;

    list = virConfGetValue(conf, "vnuma");
    if (!list || list->type != VIR_CONF_LIST)
        return 0;

    vnode = list->list;
    while (vnode && vnode->type == VIR_CONF_LIST) {
        vnode = vnode->next;
        nr_nodes++;
    }

    if (!virDomainNumaSetNodeCount(numa, nr_nodes))
        return -1;

    cpu = virCPUDefNew();

    list = list->list;
    while (list) {
        int pnode = -1;
        virBitmap *cpumask = NULL;
        unsigned long long kbsize = 0;

        /* Is there a sublist (vnode)? */
        if (list->type == VIR_CONF_LIST) {
            vnode = list->list;

            while (vnode && vnode->type == VIR_CONF_STRING) {
                const char *data;
                const char *str = vnode->str;

                if (!str ||
                   !(data = strrchr(str, '='))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("vnuma vnode invalid format '%1$s'"),
                                   str);
                    return -1;
                }
                data++;

                if (*data) {
                    if (STRPREFIX(str, "pnode")) {
                        unsigned int cellid;

                        if ((virStrToLong_ui(data, NULL, 10, &cellid) < 0) ||
                            (cellid >= nr_nodes)) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                           _("vnuma vnode %1$zu contains invalid pnode value '%2$s'"),
                                           vnodeCnt, data);
                            return -1;
                        }
                        pnode = cellid;
                    } else if (STRPREFIX(str, "size")) {
                        if (virStrToLong_ull(data, NULL, 10, &kbsize) < 0)
                            return -1;

                        virDomainNumaSetNodeMemorySize(numa, vnodeCnt, (kbsize * 1024));

                    } else if (STRPREFIX(str, "vcpus")) {
                        if (virBitmapParse(data, &cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
                            return -1;

                        virDomainNumaSetNodeCpumask(numa, vnodeCnt, cpumask);
                        vcpus += virBitmapCountBits(cpumask);

                    } else if (STRPREFIX(str, "vdistances")) {
                        g_auto(GStrv) token = NULL;
                        size_t i, ndistances;
                        unsigned int value;

                        if (!(token = g_strsplit(data, ",", 0)))
                            return -1;

                        ndistances = g_strv_length(token);

                        if (ndistances != nr_nodes) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       _("vnuma pnode %1$d configured '%2$s' (count %3$zu) doesn't fit the number of specified vnodes %4$zu"),
                                       pnode, str, ndistances, nr_nodes);
                            return -1;
                        }

                        if (virDomainNumaSetNodeDistanceCount(numa, vnodeCnt, ndistances) != ndistances)
                            return -1;

                        for (i = 0; i < ndistances; i++) {
                            if ((virStrToLong_ui(token[i], NULL, 10, &value) < 0) ||
                                (virDomainNumaSetNodeDistance(numa, vnodeCnt, i, value) != value))
                                return -1;
                        }

                    } else {
                        virReportError(VIR_ERR_CONF_SYNTAX,
                                       _("Invalid vnuma configuration for vnode %1$zu"),
                                       vnodeCnt);
                        return -1;
                    }
                }
                vnode = vnode->next;
            }
        }

        if ((pnode < 0) ||
            (cpumask == NULL) ||
            (kbsize == 0)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Incomplete vnuma configuration for vnode %1$zu"),
                           vnodeCnt);
            return -1;
        }

        list = list->next;
        vnodeCnt++;
    }

    if (def->maxvcpus == 0)
        def->maxvcpus = vcpus;

    if (def->maxvcpus < vcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vnuma configuration contains %1$zu vcpus, which is greater than %2$zu maxvcpus"),
                       vcpus, def->maxvcpus);
        return -1;
    }

    cpu->type = VIR_CPU_TYPE_GUEST;
    def->cpu = g_steal_pointer(&cpu);

    return 0;
}

static int
xenParseXLXenbusLimits(virConf *conf, virDomainDef *def)
{
    int ctlr_idx;
    virDomainControllerDef *xenbus_ctlr;
    unsigned long limit;

    ctlr_idx = virDomainControllerFindByType(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS);
    if (ctlr_idx == -1)
        xenbus_ctlr = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS, -1, -1);
    else
        xenbus_ctlr = def->controllers[ctlr_idx];

    if (xenbus_ctlr == NULL)
        return -1;

    if (xenConfigGetULong(conf, "max_event_channels", &limit, 0) < 0)
        return -1;
    if (limit > 0)
        xenbus_ctlr->opts.xenbusopts.maxEventChannels = limit;

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    if (xenConfigGetULong(conf, "max_grant_frames", &limit, 0) < 0)
        return -1;
    if (limit > 0)
        xenbus_ctlr->opts.xenbusopts.maxGrantFrames = limit;
#endif

    return 0;
}

static int
xenParseXLDiskSrc(virDomainDiskDef *disk, char *srcstr)
{
    /* A NULL source is valid, e.g. an empty CDROM */
    if (srcstr == NULL)
        return 0;

    if (STRPREFIX(srcstr, "rbd:")) {
        g_autofree char *tmpstr = NULL;

        if (!(tmpstr = virStringReplace(srcstr, "\\\\", "\\")))
            return -1;

        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_NETWORK);
        disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
        return virStorageSourceParseRBDColonString(tmpstr, disk->src);
    }

    virDomainDiskSetSource(disk, srcstr);

    return 0;
}


/*
 * For details on xl disk config syntax, see
 * docs/misc/xl-disk-configuration.txt in the Xen sources.  The important
 * section of text is:
 *
 *   More formally, the string is a series of comma-separated keyword/value
 *   pairs, flags and positional parameters.  Parameters which are not bare
 *   keywords and which do not contain "=" symbols are assigned to the
 *   so-far-unspecified positional parameters, in the order below.  The
 *   positional parameters may also be specified explicitly by name.
 *
 *   Each parameter may be specified at most once, either as a positional
 *   parameter or a named parameter.  Default values apply if the parameter
 *   is not specified, or if it is specified with an empty value (whether
 *   positionally or explicitly).
 *
 *   Whitespace may appear before each parameter and will be ignored.
 *
 * The order of the positional parameters mentioned in the quoted text is:
 *
 *   target,format,vdev,access
 *
 * The following options must be specified by key=value:
 *
 *   devtype=<devtype>
 *   backendtype=<backend-type>
 *
 * The following options are currently not supported:
 *
 *   backend=<domain-name>
 *   script=<script>
 *   direct-io-safe
 *
 */
static int
xenParseXLDisk(virConf *conf, virDomainDef *def)
{
    int ret = -1;
    virConfValue *list = virConfGetValue(conf, "disk");
    XLU_Config *xluconf;
    libxl_device_disk libxldisk;
    virDomainDiskDef *disk = NULL;

    if (!(xluconf = xlu_cfg_init(stderr, "command line")))
        goto cleanup;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            const char *disk_spec = list->str;

            if (list->type != VIR_CONF_STRING || list->str == NULL)
                goto skipdisk;

            libxl_device_disk_init(&libxldisk);

            if (xlu_disk_parse(xluconf, 1, &disk_spec, &libxldisk))
                goto fail;

            if (!(disk = virDomainDiskDefNew(NULL)))
                goto fail;

            if (xenParseXLDiskSrc(disk, libxldisk.pdev_path) < 0)
                goto fail;

            disk->dst = g_strdup(libxldisk.vdev);

            disk->src->readonly = !libxldisk.readwrite;
            disk->removable = libxldisk.removable;

            if (libxldisk.is_cdrom) {
                virDomainDiskSetDriver(disk, "qemu");

                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                if (!disk->src->path || STREQ(disk->src->path, ""))
                    disk->src->format = VIR_STORAGE_FILE_NONE;
                else
                    disk->src->format = VIR_STORAGE_FILE_RAW;
            } else {
                switch (libxldisk.format) {
                case LIBXL_DISK_FORMAT_QCOW:
                    disk->src->format = VIR_STORAGE_FILE_QCOW;
                    break;

                case LIBXL_DISK_FORMAT_QCOW2:
                    disk->src->format = VIR_STORAGE_FILE_QCOW2;
                    break;

                case LIBXL_DISK_FORMAT_VHD:
                    disk->src->format = VIR_STORAGE_FILE_VHD;
                    break;

                case LIBXL_DISK_FORMAT_RAW:
                case LIBXL_DISK_FORMAT_UNKNOWN:
                    disk->src->format = VIR_STORAGE_FILE_RAW;
                    break;

                case LIBXL_DISK_FORMAT_EMPTY:
                    break;

                case LIBXL_DISK_FORMAT_QED:
                    disk->src->format = VIR_STORAGE_FILE_QED;
                    break;

                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk image format not supported: %1$s"),
                                   libxl_disk_format_to_string(libxldisk.format));
                    goto fail;
                }

                switch (libxldisk.backend) {
                case LIBXL_DISK_BACKEND_QDISK:
                case LIBXL_DISK_BACKEND_UNKNOWN:
                    virDomainDiskSetDriver(disk, "qemu");
                    if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_NONE)
                        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                    break;

                case LIBXL_DISK_BACKEND_TAP:
                    virDomainDiskSetDriver(disk, "tap");
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                    break;

                case LIBXL_DISK_BACKEND_PHY:
                    virDomainDiskSetDriver(disk, "phy");
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
                    break;
#ifdef LIBXL_HAVE_DEVICE_DISK_SPECIFICATION
                case LIBXL_DISK_BACKEND_STANDALONE:
#endif
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk backend not supported: %1$s"),
                                   libxl_disk_backend_to_string(libxldisk.backend));
                    goto fail;
                }
            }

            if (STRPREFIX(libxldisk.vdev, "xvd") ||
                def->os.type != VIR_DOMAIN_OSTYPE_HVM)
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(libxldisk.vdev, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

            VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);

            libxl_device_disk_dispose(&libxldisk);

        skipdisk:
            list = list->next;
        }
    }
    ret = 0;

 cleanup:
    virDomainDiskDefFree(disk);
    xlu_cfg_destroy(xluconf);
    return ret;

 fail:
    libxl_device_disk_dispose(&libxldisk);
    goto cleanup;
}

static int
xenParseXLInputDevs(virConf *conf, virDomainDef *def)
{
    const char *str;
    virConfValue *val;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        val = virConfGetValue(conf, "usbdevice");
        /* usbdevice can be defined as either a single string or a list */
        if (val && val->type == VIR_CONF_LIST)
            val = val->list;

        /* otherwise val->next is NULL, so can be handled by the same code */
        while (val) {
            if (val->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("config value %1$s was malformed"),
                               "usbdevice");
                return -1;
            }
            str = val->str;

            if (str &&
                    (STREQ(str, "tablet") ||
                     STREQ(str, "mouse") ||
                     STREQ(str, "keyboard"))) {
                virDomainInputDef *input;
                input = g_new0(virDomainInputDef,
                               1);

                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(str, "mouse"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                else if (STREQ(str, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else if (STREQ(str, "keyboard"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_KBD;
                VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input);
            }
            val = val->next;
        }
    }
    return 0;
}

static int
xenParseXLUSBController(virConf *conf, virDomainDef *def)
{
    virConfValue *list = virConfGetValue(conf, "usbctrl");
    virDomainControllerDef *controller = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char *key;
            int usbctrl_version = 2; /* by default USB 2.0 */
            int usbctrl_ports = 8; /* by default 8 ports */
            int usbctrl_type = -1;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipusbctrl;
            /* usbctrl=['type=pv,version=2,ports=8'] */
            key = list->str;
            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');

                if (!(data = strchr(key, '=')))
                    goto skipusbctrl;
                data++;

                if (STRPREFIX(key, "type=")) {
                    if (!STRPREFIX(data, "qusb"))
                        goto skipusbctrl;
                } else if (STRPREFIX(key, "version=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    g_autofree char *tmp = g_strndup(data, len);

                    if (virStrToLong_i(tmp, NULL, 16, &usbctrl_version) < 0)
                        goto skipusbctrl;
                } else if (STRPREFIX(key, "ports=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    g_autofree char *tmp = g_strndup(data, len);

                    if (virStrToLong_i(tmp, NULL, 16, &usbctrl_ports) < 0)
                        goto skipusbctrl;
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (usbctrl_version == 1)
                usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1;
            else
                usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2;

            if (!(controller = virDomainControllerDefNew(VIR_DOMAIN_CONTROLLER_TYPE_USB)))
                return -1;

            controller->type = VIR_DOMAIN_CONTROLLER_TYPE_USB;
            controller->model = usbctrl_type;
            controller->opts.usbopts.ports = usbctrl_ports;

            VIR_APPEND_ELEMENT(def->controllers, def->ncontrollers, controller);

        skipusbctrl:
            list = list->next;
        }
    }

    return 0;
}

static int
xenParseXLUSB(virConf *conf, virDomainDef *def)
{
    virConfValue *list = virConfGetValue(conf, "usbdev");
    virDomainHostdevDef *hostdev = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char *key;
            int busNum;
            int devNum;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipusb;
            /* usbdev=['hostbus=1,hostaddr=3'] */
            key = list->str;
            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');

                if (!(data = strchr(key, '=')))
                    goto skipusb;
                data++;

                if (STRPREFIX(key, "hostbus=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    g_autofree char *tmp = g_strndup(data, len);

                    if (virStrToLong_i(tmp, NULL, 16, &busNum) < 0)
                        goto skipusb;
                } else if (STRPREFIX(key, "hostaddr=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    g_autofree char *tmp = g_strndup(data, len);

                    if (virStrToLong_i(tmp, NULL, 16, &devNum) < 0)
                        goto skipusb;
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (!(hostdev = virDomainHostdevDefNew()))
               return -1;

            hostdev->managed = false;
            hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
            hostdev->source.subsys.u.usb.bus = busNum;
            hostdev->source.subsys.u.usb.device = devNum;

            VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev);

        skipusb:
            list = list->next;
        }
    }

    return 0;
}

static int
xenParseXLChannel(virConf *conf, virDomainDef *def)
{
    virConfValue *list = virConfGetValue(conf, "channel");
    virDomainChrDef *channel = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            g_autofree char *type = NULL;
            g_autofree char *name = NULL;
            g_autofree char *path = NULL;
            char *key;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipchannel;

            key = list->str;
            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');

                if (!(data = strchr(key, '=')))
                    goto skipchannel;
                data++;

                if (STRPREFIX(key, "connection=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    g_clear_pointer(&type, g_free);
                    type = g_strndup(data, len);
                } else if (!name && STRPREFIX(key, "name=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    name = g_strndup(data, len);
                } else if (!path && STRPREFIX(key, "path=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    path = g_strndup(data, len);
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (!(channel = virDomainChrDefNew(NULL)))
                goto cleanup;

            if (STRPREFIX(type, "socket")) {
                channel->source->type = VIR_DOMAIN_CHR_TYPE_UNIX;
                channel->source->data.nix.listen = 1;
                channel->source->data.nix.path = g_steal_pointer(&path);
            } else if (STRPREFIX(type, "pty")) {
                channel->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
            } else {
                goto cleanup;
            }

            channel->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL;
            channel->targetType = VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN;
            channel->target.name = g_steal_pointer(&name);

            VIR_APPEND_ELEMENT(def->channels, def->nchannels, channel);

        skipchannel:
            list = list->next;
        }
    }

    return 0;

 cleanup:
    virDomainChrDefFree(channel);
    return -1;
}

static int
xenParseXLNamespaceData(virConf *conf, virDomainDef *def)
{
    virConfValue *list = virConfGetValue(conf, "device_model_args");
    virConfValue *next;
    size_t nargs = 0;
    libxlDomainXmlNsDef *nsdata = NULL;
    size_t n = 0;

    if (!list || list->type != VIR_CONF_LIST)
        return 0;

    list = list->list;

    for (next = list; next; next = next->next) {
        if (next->type != VIR_CONF_STRING || !next->str)
            continue;

        nargs++;
    }

    if (nargs == 0)
        return 0;

    nsdata = g_new0(libxlDomainXmlNsDef, 1);
    def->namespaceData = nsdata;
    nsdata->args = g_new0(char *, nargs + 1);
    nsdata->num_args = nargs;

    for (next = list; next; next = next->next) {
        if (next->type != VIR_CONF_STRING || !next->str)
            continue;

        nsdata->args[n++] = g_strdup(next->str);
    }

    return 0;
}

virDomainDef *
xenParseXL(virConf *conf,
           virCaps *caps,
           virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainDef) def = NULL;

    if (!(def = virDomainDefNew(xmlopt)))
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;
    def->ns = *(virDomainXMLOptionGetNamespace(xmlopt));

    if (xenParseConfigCommon(conf, def, caps, XEN_CONFIG_FORMAT_XL,
                             xmlopt) < 0)
        return NULL;

    if (xenParseXLOS(conf, def, caps) < 0)
        return NULL;

    if (xenParseXLVnuma(conf, def) < 0)
        return NULL;

    if (xenParseXLXenbusLimits(conf, def) < 0)
        return NULL;

    if (xenParseXLCPUID(conf, def) < 0)
        return NULL;

    if (xenParseXLDisk(conf, def) < 0)
        return NULL;

    if (xenParseXLSpice(conf, def) < 0)
        return NULL;

    if (xenParseXLInputDevs(conf, def) < 0)
        return NULL;

    if (xenParseXLUSB(conf, def) < 0)
        return NULL;

    if (xenParseXLUSBController(conf, def) < 0)
        return NULL;

    if (xenParseXLChannel(conf, def) < 0)
        return NULL;

    if (xenParseXLNamespaceData(conf, def) < 0)
        return NULL;

    if (virDomainDefPostParse(def, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


static int
xenFormatXLOS(virConf *conf, virDomainDef *def)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];
        if (xenConfigSetString(conf, "builder", "hvm") < 0)
            return -1;

        if (virDomainDefHasOldStyleUEFI(def)) {
            if (xenConfigSetString(conf, "bios", "ovmf") < 0)
                return -1;
            if (def->os.loader->path &&
                (xenConfigSetString(conf, "bios_path_override", def->os.loader->path) < 0))
                return -1;
        }

        if (def->os.slic_table &&
            xenConfigSetString(conf, "acpi_firmware", def->os.slic_table) < 0)
            return -1;

        if (def->os.kernel &&
            xenConfigSetString(conf, "kernel", def->os.kernel) < 0)
            return -1;

        if (def->os.initrd &&
            xenConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            return -1;

        if (def->os.cmdline &&
            xenConfigSetString(conf, "cmdline", def->os.cmdline) < 0)
            return -1;

        for (i = 0; i < def->os.nBootDevs; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            case VIR_DOMAIN_BOOT_DISK:
            default:
                boot[i] = 'c';
                break;
            case VIR_DOMAIN_BOOT_LAST:
                break;
            }
        }

        if (!def->os.nBootDevs) {
            boot[0] = 'c';
            boot[1] = '\0';
        } else {
            boot[def->os.nBootDevs] = '\0';
        }

        if (xenConfigSetString(conf, "boot", boot) < 0)
            return -1;

        if (def->cpu &&
            def->cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH) {
            bool hasHwVirt = true;

            if (def->cpu->nfeatures) {
                for (i = 0; i < def->cpu->nfeatures; i++) {

                    switch (def->cpu->features[i].policy) {
                        case VIR_CPU_FEATURE_DISABLE:
                        case VIR_CPU_FEATURE_FORBID:
                            if (STREQ(def->cpu->features[i].name, "vmx") ||
                                STREQ(def->cpu->features[i].name, "svm"))
                                hasHwVirt = false;
                            break;

                        case VIR_CPU_FEATURE_FORCE:
                        case VIR_CPU_FEATURE_REQUIRE:
                        case VIR_CPU_FEATURE_OPTIONAL:
                        case VIR_CPU_FEATURE_LAST:
                            break;
                    }
                }
            }

            if (xenConfigSetInt(conf, "nestedhvm", hasHwVirt) < 0)
                return -1;
        }

        /* XXX floppy disks */
    } else {
        if (def->os.type == VIR_DOMAIN_OSTYPE_XENPVH) {
            if (xenConfigSetString(conf, "type", "pvh") < 0)
                return -1;
        }

        if (def->os.bootloader &&
             xenConfigSetString(conf, "bootloader", def->os.bootloader) < 0)
            return -1;

         if (def->os.bootloaderArgs &&
             xenConfigSetString(conf, "bootargs", def->os.bootloaderArgs) < 0)
            return -1;

         if (def->os.kernel &&
             xenConfigSetString(conf, "kernel", def->os.kernel) < 0)
            return -1;

         if (def->os.initrd &&
             xenConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            return -1;

         if (def->os.cmdline &&
             xenConfigSetString(conf, "cmdline", def->os.cmdline) < 0)
            return -1;
     } /* !hvm */

    return 0;
}

static int
xenFormatXLCPUID(virConf *conf, virDomainDef *def)
{
    g_auto(GStrv) cpuid_pairs = NULL;
    g_autofree char *cpuid_string = NULL;
    size_t i, j;

    if (!def->cpu)
        return 0;

    if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH) {
        VIR_WARN("ignoring CPU mode '%s', only host-passthrough mode "
                 "is supported", virCPUModeTypeToString(def->cpu->mode));
        return 0;
    }

    /* "host" + all features + NULL */
    cpuid_pairs = g_new0(char *, def->cpu->nfeatures + 2);

    cpuid_pairs[0] = g_strdup("host");

    j = 1;
    for (i = 0; i < def->cpu->nfeatures; i++) {
        const char *feature_name = xenTranslateCPUFeature(
                def->cpu->features[i].name,
                false);
        const char *policy = NULL;

        if (STREQ(feature_name, "vmx") || STREQ(feature_name, "svm"))
            /* ignore vmx/svm in cpuid option, translated into nestedhvm
             * elsewhere */
            continue;

        switch (def->cpu->features[i].policy) {
            case VIR_CPU_FEATURE_FORCE:
            case VIR_CPU_FEATURE_REQUIRE:
                policy = "1";
                break;
            case VIR_CPU_FEATURE_OPTIONAL:
                policy = "x";
                break;
            case VIR_CPU_FEATURE_DISABLE:
            case VIR_CPU_FEATURE_FORBID:
                policy = "0";
                break;
        }
        cpuid_pairs[j++] = g_strdup_printf("%s=%s", feature_name, policy);
    }
    cpuid_pairs[j] = NULL;

    if (j > 1) {
        cpuid_string = g_strjoinv(",", cpuid_pairs);

        if (xenConfigSetString(conf, "cpuid", cpuid_string) < 0)
            return -1;
    }

    return 0;
}

static int
xenFormatXLVnode(virConfValue *list,
                 virBuffer *buf)
{
    virConfValue *numaPnode;
    virConfValue *tmp;

    numaPnode = g_new0(virConfValue, 1);

    /* Place VNODE directive */
    numaPnode->type = VIR_CONF_STRING;
    numaPnode->str = virBufferContentAndReset(buf);

    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = numaPnode;
    else
        list->list = numaPnode;

    return 0;
}

static int
xenFormatXLVnuma(virConfValue *list,
                 virDomainNuma *numa,
                 size_t node,
                 size_t nr_nodes)
{
    int ret = -1;
    size_t i;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virConfValue *numaVnode;
    virConfValue *tmp;
    virBitmap *cpumask = virDomainNumaGetNodeCpumask(numa, node);
    size_t nodeSize = virDomainNumaGetNodeMemorySize(numa, node) / 1024;
    g_autofree char *nodeVcpus = NULL;

    if (!cpumask)
        return -1;

    numaVnode = g_new0(virConfValue, 1);
    numaVnode->type = VIR_CONF_LIST;
    numaVnode->list = NULL;

    nodeVcpus = virBitmapFormat(cpumask);

    /* pnode */
    virBufferAsprintf(&buf, "pnode=%zu", node);
    xenFormatXLVnode(numaVnode, &buf);

    /* size */
    virBufferAsprintf(&buf, "size=%zu", nodeSize);
    xenFormatXLVnode(numaVnode, &buf);

    /* vcpus */
    virBufferAsprintf(&buf, "vcpus=%s", nodeVcpus);
    xenFormatXLVnode(numaVnode, &buf);

    /* distances */
    virBufferAddLit(&buf, "vdistances=");
    for (i = 0; i < nr_nodes; i++) {
        virBufferAsprintf(&buf, "%zu",
            virDomainNumaGetNodeDistance(numa, node, i));
        if ((nr_nodes - i) > 1)
            virBufferAddLit(&buf, ",");
    }
    xenFormatXLVnode(numaVnode, &buf);

    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = numaVnode;
    else
        list->list = numaVnode;
    ret = 0;

    return ret;
}

static int
xenFormatXLDomainVnuma(virConf *conf,
                       virDomainDef *def)
{
    virDomainNuma *numa = def->numa;
    g_autoptr(virConfValue) vnumaVal = NULL;
    size_t i;
    size_t nr_nodes;

    if (numa == NULL)
        return -1;

    vnumaVal = g_new0(virConfValue, 1);

    vnumaVal->type = VIR_CONF_LIST;
    vnumaVal->list = NULL;

    nr_nodes = virDomainNumaGetNodeCount(numa);
    for (i = 0; i < nr_nodes; i++) {
        if (xenFormatXLVnuma(vnumaVal, numa, i, nr_nodes) < 0)
            return -1;
    }

    if (vnumaVal->list != NULL &&
        virConfSetValue(conf, "vnuma", &vnumaVal) < 0)
        return -1;

    return 0;
}

static int
xenFormatXLXenbusLimits(virConf *conf, virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_XENBUS) {
            if (def->controllers[i]->opts.xenbusopts.maxEventChannels > 0) {
                if (xenConfigSetInt(conf, "max_event_channels",
                                    def->controllers[i]->opts.xenbusopts.maxEventChannels) < 0)
                    return -1;
            }

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
            if (def->controllers[i]->opts.xenbusopts.maxGrantFrames > 0) {
                if (xenConfigSetInt(conf, "max_grant_frames",
                                    def->controllers[i]->opts.xenbusopts.maxGrantFrames) < 0)
                    return -1;
            }
#endif
        }
    }

    return 0;
}

static char *
xenFormatXLDiskSrcNet(virStorageSource *src)
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

        virBufferAddLit(&buf, ":auth_supported=none");

        if (src->nhosts > 0) {
            virBufferAddLit(&buf, ":mon_host=");
            for (i = 0; i < src->nhosts; i++) {
                if (i)
                    virBufferAddLit(&buf, "\\\\;");

                /* assume host containing : is ipv6 */
                if (strchr(src->hosts[i].name, ':'))
                    virBufferEscape(&buf, '\\', ":", "[%s]",
                                    src->hosts[i].name);
                else
                    virBufferAsprintf(&buf, "%s", src->hosts[i].name);

                if (src->hosts[i].port)
                    virBufferAsprintf(&buf, "\\\\:%u", src->hosts[i].port);
            }
        }

        return virBufferContentAndReset(&buf);
    }

    return NULL;
}


static int
xenFormatXLDiskSrc(virStorageSource *src, char **srcstr)
{
    virStorageType actualType = virStorageSourceGetActualType(src);

    *srcstr = NULL;

    if (virStorageSourceIsEmpty(src))
        return 0;

    switch (actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_DIR:
        *srcstr = g_strdup(src->path);
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        if (!(*srcstr = xenFormatXLDiskSrcNet(src)))
            return -1;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unsupported storage type for this code path"));
        return -1;
    }

    return 0;
}


static int
xenFormatXLDisk(virConfValue *list, virDomainDiskDef *disk)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virConfValue *val;
    virConfValue *tmp;
    int format = virDomainDiskGetFormat(disk);
    const char *driver = virDomainDiskGetDriver(disk);
    g_autofree char *target = NULL;

    /* format */
    virBufferAddLit(&buf, "format=");
    switch (format) {
        case VIR_STORAGE_FILE_RAW:
            virBufferAddLit(&buf, "raw");
            break;
        case VIR_STORAGE_FILE_VHD:
            virBufferAddLit(&buf, "xvhd");
            break;
        case VIR_STORAGE_FILE_QCOW:
            virBufferAddLit(&buf, "qcow");
            break;
        case VIR_STORAGE_FILE_QCOW2:
            virBufferAddLit(&buf, "qcow2");
            break;
        case VIR_STORAGE_FILE_QED:
            virBufferAddLit(&buf, "qed");
            break;
      /* set default */
        default:
            virBufferAddLit(&buf, "raw");
    }

    /* device */
    virBufferAsprintf(&buf, ",vdev=%s", disk->dst);

    /* access */
    virBufferAddLit(&buf, ",access=");
    if (disk->src->readonly)
        virBufferAddLit(&buf, "ro");
    else if (disk->src->shared)
        virBufferAddLit(&buf, "!");
    else
        virBufferAddLit(&buf, "rw");
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        return -1;
    }

    /* backendtype */
    if (driver) {
        virBufferAddLit(&buf, ",backendtype=");
        if (STREQ(driver, "qemu") || STREQ(driver, "file"))
            virBufferAddLit(&buf, "qdisk");
        else if (STREQ(driver, "tap"))
            virBufferAddLit(&buf, "tap");
        else if (STREQ(driver, "phy"))
            virBufferAddLit(&buf, "phy");
    }

    /* devtype */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, ",devtype=cdrom");

    /*
     * target
     * From $xensrc/docs/misc/xl-disk-configuration.txt:
     * When this parameter is specified by name, ie with the "target="
     * syntax in the configuration file, it consumes the whole rest of the
     * <diskspec> including trailing whitespaces.  Therefore in that case
     * it must come last.
     */
    if (xenFormatXLDiskSrc(disk->src, &target) < 0)
        return -1;

    if (target)
        virBufferAsprintf(&buf, ",target=%s", target);

    val = g_new0(virConfValue, 1);

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;
}


static int
xenFormatXLDomainDisks(virConf *conf, virDomainDef *def)
{
    g_autoptr(virConfValue) diskVal = NULL;
    size_t i;

    diskVal = g_new0(virConfValue, 1);

    diskVal->type = VIR_CONF_LIST;
    diskVal->list = NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            continue;

        if (xenFormatXLDisk(diskVal, def->disks[i]) < 0)
            return -1;
    }

    if (diskVal->list != NULL &&
        virConfSetValue(conf, "disk", &diskVal) < 0)
        return -1;

    return 0;
}


static int
xenFormatXLSpice(virConf *conf, virDomainDef *def)
{
    virDomainGraphicsListenDef *glisten;
    virDomainGraphicsDef *graphics;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM && def->graphics) {
        graphics = def->graphics[0];

        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            /* set others to false but may not be necessary */
            if (xenConfigSetInt(conf, "sdl", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "vnc", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spice", 1) < 0)
                return -1;

            if ((glisten = virDomainGraphicsGetListen(graphics, 0)) &&
                glisten->address &&
                xenConfigSetString(conf, "spicehost", glisten->address) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spiceport",
                                graphics->data.spice.port) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spicetls_port",
                                graphics->data.spice.tlsPort) < 0)
                return -1;

            if (graphics->data.spice.auth.passwd) {
                if (xenConfigSetInt(conf, "spicedisable_ticketing", 0) < 0)
                    return -1;

                if (xenConfigSetString(conf, "spicepasswd",
                                       graphics->data.spice.auth.passwd) < 0)
                    return -1;
            } else {
                if (xenConfigSetInt(conf, "spicedisable_ticketing", 1) < 0)
                    return -1;
            }

            if (graphics->data.spice.mousemode) {
                switch (graphics->data.spice.mousemode) {
                case VIR_DOMAIN_MOUSE_MODE_SERVER:
                    if (xenConfigSetInt(conf, "spiceagent_mouse", 0) < 0)
                        return -1;
                    break;
                case VIR_DOMAIN_MOUSE_MODE_CLIENT:
                    if (xenConfigSetInt(conf, "spiceagent_mouse", 1) < 0)
                        return -1;
                    /*
                     * spicevdagent must be enabled if using client
                     * mode mouse
                     */
                    if (xenConfigSetInt(conf, "spicevdagent", 1) < 0)
                        return -1;
                    break;
                case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
                    break;
                case VIR_DOMAIN_MOUSE_MODE_LAST:
                default:
                    virReportEnumRangeError(virDomainMouseMode,
                                            graphics->data.spice.mousemode);
                    return -1;
                }
            }

            if (graphics->data.spice.copypaste == VIR_TRISTATE_BOOL_YES) {
                if (xenConfigSetInt(conf, "spice_clipboard_sharing", 1) < 0)
                    return -1;
                /*
                 * spicevdagent must be enabled if spice_clipboard_sharing
                 * is enabled
                 */
                if (xenConfigSetInt(conf, "spicevdagent", 1) < 0)
                    return -1;
            }
        }
    }

    return 0;
}

static int
xenFormatXLInputDevs(virConf *conf, virDomainDef *def)
{
    size_t i;
    const char *devtype;
    g_autoptr(virConfValue) usbdevices = NULL;
    virConfValue *lastdev;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        usbdevices = g_new0(virConfValue, 1);
        usbdevices->type = VIR_CONF_LIST;
        usbdevices->list = NULL;
        lastdev = NULL;
        for (i = 0; i < def->ninputs; i++) {
            if (def->inputs[i]->bus == VIR_DOMAIN_INPUT_BUS_USB) {
                if (xenConfigSetInt(conf, "usb", 1) < 0)
                    return -1;

                switch (def->inputs[i]->type) {
                    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
                        devtype = "mouse";
                        break;
                    case VIR_DOMAIN_INPUT_TYPE_TABLET:
                        devtype = "tablet";
                        break;
                    case VIR_DOMAIN_INPUT_TYPE_KBD:
                        devtype = "keyboard";
                        break;
                    default:
                        continue;
                }

                if (lastdev == NULL) {
                    lastdev = g_new0(virConfValue, 1);
                    usbdevices->list = lastdev;
                } else {
                    lastdev->next = g_new0(virConfValue, 1);
                    lastdev = lastdev->next;
                }
                lastdev->type = VIR_CONF_STRING;
                lastdev->str = g_strdup(devtype);
            }
        }
        if (usbdevices->list != NULL) {
            if (usbdevices->list->next == NULL) {
                /* for compatibility with Xen <= 4.2, use old syntax when
                 * only one device present */
                if (xenConfigSetString(conf, "usbdevice", usbdevices->list->str) < 0)
                    return -1;
            } else {
                if (virConfSetValue(conf, "usbdevice", &usbdevices) < 0)
                    return -1;
            }
        }
    }

    return 0;
}

static int
xenFormatXLUSBController(virConf *conf,
                         virDomainDef *def)
{
    g_autoptr(virConfValue) usbctrlVal = NULL;
    int hasUSBCtrl = 0;
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            hasUSBCtrl = 1;
            break;
        }
    }

    if (!hasUSBCtrl)
        return 0;

    usbctrlVal = g_new0(virConfValue, 1);

    usbctrlVal->type = VIR_CONF_LIST;
    usbctrlVal->list = NULL;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            virConfValue *val;
            virConfValue *tmp;
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

            if (def->controllers[i]->model != -1) {
                switch (def->controllers[i]->model) {
                case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1:
                    virBufferAddLit(&buf, "type=qusb,version=1,");
                    break;

                case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2:
                    virBufferAddLit(&buf, "type=qusb,version=2,");
                    break;

                default:
                    return -1;
                }
            }

            if (def->controllers[i]->opts.usbopts.ports != -1)
                virBufferAsprintf(&buf, "ports=%x",
                                  def->controllers[i]->opts.usbopts.ports);

            val = g_new0(virConfValue, 1);
            val->type = VIR_CONF_STRING;
            val->str = virBufferContentAndReset(&buf);
            tmp = usbctrlVal->list;
            while (tmp && tmp->next)
                tmp = tmp->next;
            if (tmp)
                tmp->next = val;
            else
                usbctrlVal->list = val;
        }
    }

    if (usbctrlVal->list != NULL &&
        virConfSetValue(conf, "usbctrl", &usbctrlVal) < 0)
        return -1;

    return 0;
}


static int
xenFormatXLUSB(virConf *conf,
               virDomainDef *def)
{
    g_autoptr(virConfValue) usbVal = NULL;
    int hasUSB = 0;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            hasUSB = 1;
            break;
        }
    }

    if (!hasUSB)
        return 0;

    usbVal = g_new0(virConfValue, 1);

    usbVal->type = VIR_CONF_LIST;
    usbVal->list = NULL;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            virConfValue *val;
            virConfValue *tmp;
            char *buf;

            buf = g_strdup_printf("hostbus=%x,hostaddr=%x",
                                  def->hostdevs[i]->source.subsys.u.usb.bus,
                                  def->hostdevs[i]->source.subsys.u.usb.device);

            val = g_new0(virConfValue, 1);
            val->type = VIR_CONF_STRING;
            val->str = buf;
            tmp = usbVal->list;
            while (tmp && tmp->next)
                tmp = tmp->next;
            if (tmp)
                tmp->next = val;
            else
                usbVal->list = val;
        }
    }

    if (usbVal->list != NULL &&
        virConfSetValue(conf, "usbdev", &usbVal) < 0)
        return -1;

    return 0;
}

static int
xenFormatXLChannel(virConfValue *list, virDomainChrDef *channel)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    int sourceType = channel->source->type;
    virConfValue *val;
    virConfValue *tmp;

    /* connection */
    virBufferAddLit(&buf, "connection=");
    switch (sourceType) {
        case VIR_DOMAIN_CHR_TYPE_PTY:
            virBufferAddLit(&buf, "pty,");
            break;
        case VIR_DOMAIN_CHR_TYPE_UNIX:
            virBufferAddLit(&buf, "socket,");
            /* path */
            if (channel->source->data.nix.path)
                virBufferAsprintf(&buf, "path=%s,",
                                  channel->source->data.nix.path);
            break;
        default:
            return -1;
    }

    /* name */
    virBufferAsprintf(&buf, "name=%s", channel->target.name);

    val = g_new0(virConfValue, 1);
    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;
    return 0;
}

static int
xenFormatXLDomainChannels(virConf *conf, virDomainDef *def)
{
    g_autoptr(virConfValue) channelVal = NULL;
    size_t i;

    channelVal = g_new0(virConfValue, 1);

    channelVal->type = VIR_CONF_LIST;
    channelVal->list = NULL;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDef *chr = def->channels[i];

        if (chr->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN)
            continue;

        if (xenFormatXLChannel(channelVal, def->channels[i]) < 0)
            return -1;
    }

    if (channelVal->list != NULL &&
        virConfSetValue(conf, "channel", &channelVal) < 0)
        return -1;

    return 0;
}

static int
xenFormatXLDomainNamespaceData(virConf *conf, virDomainDef *def)
{
    libxlDomainXmlNsDef *nsdata = def->namespaceData;
    g_autoptr(virConfValue) args = NULL;
    size_t i;

    if (!nsdata)
        return 0;

    if (nsdata->num_args == 0)
        return 0;

    args = g_new0(virConfValue, 1);

    args->type = VIR_CONF_LIST;
    args->list = NULL;

    for (i = 0; i < nsdata->num_args; i++) {
        virConfValue *val;
        virConfValue *tmp;

        val = g_new0(virConfValue, 1);

        val->type = VIR_CONF_STRING;
        val->str = g_strdup(nsdata->args[i]);
        tmp = args->list;
        while (tmp && tmp->next)
            tmp = tmp->next;
        if (tmp)
            tmp->next = val;
        else
            args->list = val;
    }

    if (args->list != NULL &&
        virConfSetValue(conf, "device_model_args", &args) < 0)
        return -1;

    return 0;
}

virConf *
xenFormatXL(virDomainDef *def, virConnectPtr conn)
{
    g_autoptr(virConf) conf = NULL;

    if (!(conf = virConfNew()))
        return NULL;

    if (xenFormatConfigCommon(conf, def, conn, XEN_CONFIG_FORMAT_XL) < 0)
        return NULL;

    if (xenFormatXLOS(conf, def) < 0)
        return NULL;

    if (xenFormatXLCPUID(conf, def) < 0)
        return NULL;

    if (xenFormatXLDomainVnuma(conf, def) < 0)
        return NULL;

    if (xenFormatXLXenbusLimits(conf, def) < 0)
        return NULL;

    if (xenFormatXLDomainDisks(conf, def) < 0)
        return NULL;

    if (xenFormatXLSpice(conf, def) < 0)
        return NULL;

    if (xenFormatXLInputDevs(conf, def) < 0)
        return NULL;

    if (xenFormatXLUSB(conf, def) < 0)
        return NULL;

    if (xenFormatXLUSBController(conf, def) < 0)
        return NULL;

    if (xenFormatXLDomainChannels(conf, def) < 0)
        return NULL;

    if (xenFormatXLDomainNamespaceData(conf, def) < 0)
        return NULL;

    return g_steal_pointer(&conf);
}
