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
#include "viralloc.h"
#include "virstring.h"
#include "virstoragefile.h"
#include "xen_xl.h"
#include "libxl_capabilities.h"
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
#ifdef HAVE_LIBXLUTIL_H
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

static int xenParseCmdline(virConfPtr conf, char **r_cmdline)
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
        if (VIR_STRDUP(cmdline, buf) < 0)
            return -1;
        if (root || extra)
            VIR_WARN("ignoring root= and extra= in favour of cmdline=");
    } else {
        if (root && extra) {
            if (virAsprintf(&cmdline, "root=%s %s", root, extra) < 0)
                return -1;
        } else if (root) {
            if (virAsprintf(&cmdline, "root=%s", root) < 0)
                return -1;
        } else if (extra) {
            if (VIR_STRDUP(cmdline, extra) < 0)
                return -1;
        }
    }

    *r_cmdline = cmdline;
    return 0;
}

static int
xenParseXLOS(virConfPtr conf, virDomainDefPtr def, virCapsPtr caps)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        g_autofree char *bios = NULL;
        g_autofree char *boot = NULL;
        int val = 0;

        if (xenConfigGetString(conf, "bios", &bios, NULL) < 0)
            return -1;

        if (bios && STREQ(bios, "ovmf")) {
            if (VIR_ALLOC(def->os.loader) < 0)
                return -1;

            def->os.loader->type = VIR_DOMAIN_LOADER_TYPE_PFLASH;
            def->os.loader->readonly = VIR_TRISTATE_BOOL_YES;

            if (VIR_STRDUP(def->os.loader->path,
                           LIBXL_FIRMWARE_DIR "/ovmf.bin") < 0)
                return -1;
        } else {
            for (i = 0; i < caps->nguests; i++) {
                if (caps->guests[i]->ostype == VIR_DOMAIN_OSTYPE_HVM &&
                    caps->guests[i]->arch.id == def->os.arch) {
                    if (VIR_ALLOC(def->os.loader) < 0 ||
                        VIR_STRDUP(def->os.loader->path,
                                   caps->guests[i]->arch.defaultInfo.loader) < 0)
                        return -1;
                }
            }
        }

        if (xenConfigCopyStringOpt(conf, "acpi_firmware", &def->os.slic_table) < 0)
            return -1;

#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
        if (xenConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            return -1;

        if (xenParseCmdline(conf, &def->os.cmdline) < 0)
            return -1;
#endif

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
                virCPUDefPtr cpu;
                if (VIR_ALLOC(cpu) < 0)
                    return -1;

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
xenParseXLCPUID(virConfPtr conf, virDomainDefPtr def)
{
    g_autofree char *cpuid_str = NULL;
    char **cpuid_pairs = NULL;
    char **name_and_value = NULL;
    size_t i;
    int ret = -1;
    int policy;

    if (xenConfigGetString(conf, "cpuid", &cpuid_str, NULL) < 0)
        return -1;

    if (!cpuid_str)
        return 0;

    if (!def->cpu) {
        if (VIR_ALLOC(def->cpu) < 0)
            goto cleanup;
        def->cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
        def->cpu->type = VIR_CPU_TYPE_GUEST;
        def->cpu->nfeatures = 0;
        def->cpu->nfeatures_max = 0;
    }

    cpuid_pairs = virStringSplit(cpuid_str, ",", 0);
    if (!cpuid_pairs)
        goto cleanup;

    if (!cpuid_pairs[0]) {
        ret = 0;
        goto cleanup;
    }

    if (STRNEQ(cpuid_pairs[0], "host")) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("cpuid starting with %s is not supported, only libxl format is"),
                       cpuid_pairs[0]);
        goto cleanup;
    }

    for (i = 1; cpuid_pairs[i]; i++) {
        name_and_value = virStringSplit(cpuid_pairs[i], "=", 2);
        if (!name_and_value)
            goto cleanup;
        if (!name_and_value[0] || !name_and_value[1]) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Invalid libxl cpuid key=value element: %s"),
                           cpuid_pairs[i]);
            goto cleanup;
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
                           _("Invalid libxl cpuid value: %s"),
                           cpuid_pairs[i]);
            goto cleanup;
        }

        if (virCPUDefAddFeature(def->cpu,
                                xenTranslateCPUFeature(name_and_value[0], true),
                                policy) < 0)
            goto cleanup;

        virStringListFree(name_and_value);
        name_and_value = NULL;
    }

    ret = 0;

 cleanup:
    virStringListFree(name_and_value);
    virStringListFree(cpuid_pairs);
    return ret;
}


static int
xenParseXLSpice(virConfPtr conf, virDomainDefPtr def)
{
    virDomainGraphicsDefPtr graphics = NULL;
    unsigned long port;
    char *listenAddr = NULL;
    int val;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (xenConfigGetBool(conf, "spice", &val, 0) < 0)
            return -1;

        if (val) {
            if (VIR_ALLOC(graphics) < 0)
                return -1;

            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SPICE;
            if (xenConfigCopyStringOpt(conf, "spicehost", &listenAddr) < 0)
                goto cleanup;
            if (virDomainGraphicsListenAppendAddress(graphics, listenAddr) < 0)
                goto cleanup;
            VIR_FREE(listenAddr);

            if (xenConfigGetULong(conf, "spicetls_port", &port, 0) < 0)
                goto cleanup;
            graphics->data.spice.tlsPort = (int)port;

            if (xenConfigGetULong(conf, "spiceport", &port, 0) < 0)
                goto cleanup;

            graphics->data.spice.port = (int)port;

            if (!graphics->data.spice.tlsPort &&
                !graphics->data.spice.port)
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
                graphics->data.spice.mousemode =
                    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT;
            } else {
                graphics->data.spice.mousemode =
                    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER;
            }

            if (xenConfigGetBool(conf, "spice_clipboard_sharing", &val, 0) < 0)
                goto cleanup;
            if (val)
                graphics->data.spice.copypaste = VIR_TRISTATE_BOOL_YES;
            else
                graphics->data.spice.copypaste = VIR_TRISTATE_BOOL_NO;

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto cleanup;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
        }
    }

    return 0;

 cleanup:
    VIR_FREE(listenAddr);
    virDomainGraphicsDefFree(graphics);
    return -1;
}

#ifdef LIBXL_HAVE_VNUMA
static int
xenParseXLVnuma(virConfPtr conf,
                virDomainDefPtr def)
{
    int ret = -1;
    char *tmp = NULL;
    char **token = NULL;
    size_t vcpus = 0;
    size_t nr_nodes = 0;
    size_t vnodeCnt = 0;
    virCPUDefPtr cpu = NULL;
    virConfValuePtr list;
    virConfValuePtr vnode;
    virDomainNumaPtr numa;

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
        goto cleanup;

    if (VIR_ALLOC(cpu) < 0)
        goto cleanup;

    list = list->list;
    while (list) {
        int pnode = -1;
        virBitmapPtr cpumask = NULL;
        unsigned long long kbsize = 0;

        /* Is there a sublist (vnode)? */
        if (list && list->type == VIR_CONF_LIST) {
            vnode = list->list;

            while (vnode && vnode->type == VIR_CONF_STRING) {
                const char *data;
                const char *str = vnode->str;

                if (!str ||
                   !(data = strrchr(str, '='))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("vnuma vnode invalid format '%s'"),
                                   str);
                    goto cleanup;
                }
                data++;

                if (*data) {
                    char vtoken[64];

                    if (STRPREFIX(str, "pnode")) {
                        unsigned int cellid;

                        if (virStrcpyStatic(vtoken, data) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("vnuma vnode %zu pnode '%s' too long for destination"),
                                           vnodeCnt, data);
                            goto cleanup;
                        }

                        if ((virStrToLong_ui(vtoken, NULL, 10, &cellid) < 0) ||
                            (cellid >= nr_nodes)) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                           _("vnuma vnode %zu contains invalid pnode value '%s'"),
                                           vnodeCnt, data);
                            goto cleanup;
                        }
                        pnode = cellid;
                    } else if (STRPREFIX(str, "size")) {
                        if (virStrcpyStatic(vtoken, data) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("vnuma vnode %zu size '%s' too long for destination"),
                                           vnodeCnt, data);
                            goto cleanup;
                        }

                        if (virStrToLong_ull(vtoken, NULL, 10, &kbsize) < 0)
                            goto cleanup;

                        virDomainNumaSetNodeMemorySize(numa, vnodeCnt, (kbsize * 1024));

                    } else if (STRPREFIX(str, "vcpus")) {
                        if (virStrcpyStatic(vtoken, data) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("vnuma vnode %zu vcpus '%s' too long for destination"),
                                           vnodeCnt, data);
                            goto cleanup;
                        }

                        if ((virBitmapParse(vtoken, &cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0) ||
                            (virDomainNumaSetNodeCpumask(numa, vnodeCnt, cpumask) == NULL))
                            goto cleanup;

                        vcpus += virBitmapCountBits(cpumask);

                    } else if (STRPREFIX(str, "vdistances")) {
                        size_t i, ndistances;
                        unsigned int value;

                        if (virStrcpyStatic(vtoken, data) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("vnuma vnode %zu vdistances '%s' too long for destination"),
                                           vnodeCnt, data);
                            goto cleanup;
                        }

                        VIR_FREE(tmp);
                        if (VIR_STRDUP(tmp, vtoken) < 0)
                            goto cleanup;

                        virStringListFree(token);
                        if (!(token = virStringSplitCount(tmp, ",", 0, &ndistances)))
                            goto cleanup;

                        if (ndistances != nr_nodes) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       _("vnuma pnode %d configured '%s' (count %zu) doesn't fit the number of specified vnodes %zu"),
                                       pnode, str, ndistances, nr_nodes);
                            goto cleanup;
                        }

                        if (virDomainNumaSetNodeDistanceCount(numa, vnodeCnt, ndistances) != ndistances)
                            goto cleanup;

                        for (i = 0; i < ndistances; i++) {
                            if ((virStrToLong_ui(token[i], NULL, 10, &value) < 0) ||
                                (virDomainNumaSetNodeDistance(numa, vnodeCnt, i, value) != value))
                                goto cleanup;
                        }

                    } else {
                        virReportError(VIR_ERR_CONF_SYNTAX,
                                       _("Invalid vnuma configuration for vnode %zu"),
                                       vnodeCnt);
                        goto cleanup;
                    }
                }
                vnode = vnode->next;
            }
        }

        if ((pnode < 0) ||
            (cpumask == NULL) ||
            (kbsize == 0)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Incomplete vnuma configuration for vnode %zu"),
                           vnodeCnt);
            goto cleanup;
        }

        list = list->next;
        vnodeCnt++;
    }

    if (def->maxvcpus == 0)
        def->maxvcpus = vcpus;

    if (def->maxvcpus < vcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vnuma configuration contains %zu vcpus, which is greater than %zu maxvcpus"),
                       vcpus, def->maxvcpus);
        goto cleanup;
    }

    cpu->type = VIR_CPU_TYPE_GUEST;
    def->cpu = cpu;

    ret = 0;

 cleanup:
    if (ret)
        VIR_FREE(cpu);
    virStringListFree(token);
    VIR_FREE(tmp);

    return ret;
}
#endif

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
static int
xenParseXLGntLimits(virConfPtr conf, virDomainDefPtr def)
{
    unsigned long max_gntframes;
    int ctlr_idx;
    virDomainControllerDefPtr xenbus_ctlr;

    if (xenConfigGetULong(conf, "max_grant_frames", &max_gntframes, 0) < 0)
        return -1;

    if (max_gntframes <= 0)
        return 0;

    ctlr_idx = virDomainControllerFindByType(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS);
    if (ctlr_idx == -1)
        xenbus_ctlr = virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_XENBUS, -1, -1);
    else
        xenbus_ctlr = def->controllers[ctlr_idx];

    if (xenbus_ctlr == NULL)
        return -1;

    xenbus_ctlr->opts.xenbusopts.maxGrantFrames = max_gntframes;
    return 0;
}
#endif

static int
xenParseXLDiskSrc(virDomainDiskDefPtr disk, char *srcstr)
{
    char *tmpstr = NULL;
    int ret = -1;

    /* A NULL source is valid, e.g. an empty CDROM */
    if (srcstr == NULL)
        return 0;

    if (STRPREFIX(srcstr, "rbd:")) {
        if (!(tmpstr = virStringReplace(srcstr, "\\\\", "\\")))
            goto cleanup;

        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_NETWORK);
        disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
        ret = virStorageSourceParseRBDColonString(tmpstr, disk->src);
    } else {
        if (virDomainDiskSetSource(disk, srcstr) < 0)
            goto cleanup;

        ret = 0;
    }

 cleanup:
    VIR_FREE(tmpstr);
    return ret;
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
xenParseXLDisk(virConfPtr conf, virDomainDefPtr def)
{
    int ret = -1;
    virConfValuePtr list = virConfGetValue(conf, "disk");
    XLU_Config *xluconf;
    libxl_device_disk *libxldisk;
    virDomainDiskDefPtr disk = NULL;

    if (VIR_ALLOC(libxldisk) < 0)
        return -1;

    if (!(xluconf = xlu_cfg_init(stderr, "command line")))
        goto cleanup;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            const char *disk_spec = list->str;

            if (list->type != VIR_CONF_STRING || list->str == NULL)
                goto skipdisk;

            libxl_device_disk_init(libxldisk);

            if (xlu_disk_parse(xluconf, 1, &disk_spec, libxldisk))
                goto fail;

            if (!(disk = virDomainDiskDefNew(NULL)))
                goto fail;

            if (xenParseXLDiskSrc(disk, libxldisk->pdev_path) < 0)
                goto fail;

            if (VIR_STRDUP(disk->dst, libxldisk->vdev) < 0)
                goto fail;

            disk->src->readonly = !libxldisk->readwrite;
            disk->removable = libxldisk->removable;

            if (libxldisk->is_cdrom) {
                if (virDomainDiskSetDriver(disk, "qemu") < 0)
                    goto fail;

                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                if (!disk->src->path || STREQ(disk->src->path, ""))
                    disk->src->format = VIR_STORAGE_FILE_NONE;
                else
                    disk->src->format = VIR_STORAGE_FILE_RAW;
            } else {
                switch (libxldisk->format) {
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

#ifdef LIBXL_HAVE_QED
                case LIBXL_DISK_FORMAT_QED:
                    disk->src->format = VIR_STORAGE_FILE_QED;
                    break;
#endif

                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk image format not supported: %s"),
                                   libxl_disk_format_to_string(libxldisk->format));
                    goto fail;
                }

                switch (libxldisk->backend) {
                case LIBXL_DISK_BACKEND_QDISK:
                case LIBXL_DISK_BACKEND_UNKNOWN:
                    if (virDomainDiskSetDriver(disk, "qemu") < 0)
                        goto fail;
                    if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_NONE)
                        virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                    break;

                case LIBXL_DISK_BACKEND_TAP:
                    if (virDomainDiskSetDriver(disk, "tap") < 0)
                        goto fail;
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                    break;

                case LIBXL_DISK_BACKEND_PHY:
                    if (virDomainDiskSetDriver(disk, "phy") < 0)
                        goto fail;
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
                    break;
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk backend not supported: %s"),
                                   libxl_disk_backend_to_string(libxldisk->backend));
                    goto fail;
                }
            }

            if (STRPREFIX(libxldisk->vdev, "xvd") ||
                def->os.type != VIR_DOMAIN_OSTYPE_HVM)
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(libxldisk->vdev, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto fail;

            libxl_device_disk_dispose(libxldisk);

        skipdisk:
            list = list->next;
        }
    }
    ret = 0;

 cleanup:
    virDomainDiskDefFree(disk);
    xlu_cfg_destroy(xluconf);
    VIR_FREE(libxldisk);
    return ret;

 fail:
    libxl_device_disk_dispose(libxldisk);
    goto cleanup;
}

static int
xenParseXLInputDevs(virConfPtr conf, virDomainDefPtr def)
{
    const char *str;
    virConfValuePtr val;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        val = virConfGetValue(conf, "usbdevice");
        /* usbdevice can be defined as either a single string or a list */
        if (val && val->type == VIR_CONF_LIST) {
#ifdef LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
            val = val->list;
#else
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("multiple USB devices not supported"));
            return -1;
#endif
        }
        /* otherwise val->next is NULL, so can be handled by the same code */
        while (val) {
            if (val->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("config value %s was malformed"),
                               "usbdevice");
                return -1;
            }
            str = val->str;

            if (str &&
                    (STREQ(str, "tablet") ||
                     STREQ(str, "mouse") ||
                     STREQ(str, "keyboard"))) {
                virDomainInputDefPtr input;
                if (VIR_ALLOC(input) < 0)
                    return -1;

                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(str, "mouse"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                else if (STREQ(str, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else if (STREQ(str, "keyboard"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_KBD;
                if (VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input) < 0) {
                    virDomainInputDefFree(input);
                    return -1;
                }
            }
            val = val->next;
        }
    }
    return 0;
}

static int
xenParseXLUSBController(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr list = virConfGetValue(conf, "usbctrl");
    virDomainControllerDefPtr controller = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char type[8];
            char version[4];
            char ports[4];
            char *key;
            int usbctrl_version = 2; /* by default USB 2.0 */
            int usbctrl_ports = 8; /* by default 8 ports */
            int usbctrl_type = -1;

            type[0] = version[0] = ports[0] = '\0';

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
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    if (virStrncpy(type, data, len, sizeof(type)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("type %s invalid"),
                                       data);
                        goto skipusbctrl;
                    }
                } else if (STRPREFIX(key, "version=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    if (virStrncpy(version, data, len, sizeof(version)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("version %s invalid"),
                                       data);
                        goto skipusbctrl;
                    }
                    if (virStrToLong_i(version, NULL, 16, &usbctrl_version) < 0)
                        goto skipusbctrl;
                } else if (STRPREFIX(key, "ports=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    if (virStrncpy(ports, data, len, sizeof(ports)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("version %s invalid"),
                                       data);
                        goto skipusbctrl;
                    }
                    if (virStrToLong_i(ports, NULL, 16, &usbctrl_ports) < 0)
                        goto skipusbctrl;
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (type[0] == '\0') {
                if (usbctrl_version == 1)
                    usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1;
                else
                    usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2;
            } else {
                if (STREQLEN(type, "qusb", 4)) {
                    if (usbctrl_version == 1)
                        usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1;
                    else
                        usbctrl_type = VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2;
                } else {
                    goto skipusbctrl;
                }
            }

            if (!(controller = virDomainControllerDefNew(VIR_DOMAIN_CONTROLLER_TYPE_USB)))
                return -1;

            controller->type = VIR_DOMAIN_CONTROLLER_TYPE_USB;
            controller->model = usbctrl_type;
            controller->opts.usbopts.ports = usbctrl_ports;

            if (VIR_APPEND_ELEMENT(def->controllers, def->ncontrollers, controller) < 0) {
                virDomainControllerDefFree(controller);
                return -1;
            }

        skipusbctrl:
            list = list->next;
        }
    }

    return 0;
}

static int
xenParseXLUSB(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr list = virConfGetValue(conf, "usbdev");
    virDomainHostdevDefPtr hostdev = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char bus[3];
            char device[3];
            char *key;
            int busNum;
            int devNum;

            bus[0] = device[0] = '\0';

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
                    if (virStrncpy(bus, data, len, sizeof(bus)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("bus %s too big for destination"),
                                       data);
                        goto skipusb;
                    }
                } else if (STRPREFIX(key, "hostaddr=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    if (virStrncpy(device, data, len, sizeof(device)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("device %s too big for destination"),
                                       data);
                        goto skipusb;
                    }
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (virStrToLong_i(bus, NULL, 16, &busNum) < 0)
                goto skipusb;
            if (virStrToLong_i(device, NULL, 16, &devNum) < 0)
                goto skipusb;
            if (!(hostdev = virDomainHostdevDefNew()))
               return -1;

            hostdev->managed = false;
            hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
            hostdev->source.subsys.u.usb.bus = busNum;
            hostdev->source.subsys.u.usb.device = devNum;

            if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
                virDomainHostdevDefFree(hostdev);
                return -1;
            }

        skipusb:
            list = list->next;
        }
    }

    return 0;
}

static int
xenParseXLChannel(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr list = virConfGetValue(conf, "channel");
    virDomainChrDefPtr channel = NULL;
    char *name = NULL;
    char *path = NULL;

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char type[10];
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
                    if (virStrncpy(type, data, len, sizeof(type)) < 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("connection %s too big"), data);
                        goto skipchannel;
                    }
                } else if (STRPREFIX(key, "name=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    VIR_FREE(name);
                    if (VIR_STRNDUP(name, data, len) < 0)
                        goto cleanup;
                } else if (STRPREFIX(key, "path=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    VIR_FREE(path);
                    if (VIR_STRNDUP(path, data, len) < 0)
                        goto cleanup;
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
                channel->source->data.nix.path = path;
                path = NULL;
            } else if (STRPREFIX(type, "pty")) {
                channel->source->type = VIR_DOMAIN_CHR_TYPE_PTY;
                VIR_FREE(path);
            } else {
                goto cleanup;
            }

            channel->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL;
            channel->targetType = VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN;
            channel->target.name = name;
            name = NULL;

            if (VIR_APPEND_ELEMENT(def->channels, def->nchannels, channel) < 0)
                goto cleanup;

        skipchannel:
            list = list->next;
        }
    }

    return 0;

 cleanup:
    virDomainChrDefFree(channel);
    VIR_FREE(path);
    VIR_FREE(name);
    return -1;
}

virDomainDefPtr
xenParseXL(virConfPtr conf,
           virCapsPtr caps,
           virDomainXMLOptionPtr xmlopt)
{
    virDomainDefPtr def = NULL;

    if (!(def = virDomainDefNew()))
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenParseConfigCommon(conf, def, caps, XEN_CONFIG_FORMAT_XL,
                             xmlopt) < 0)
        goto cleanup;

    if (xenParseXLOS(conf, def, caps) < 0)
        goto cleanup;

#ifdef LIBXL_HAVE_VNUMA
    if (xenParseXLVnuma(conf, def) < 0)
        goto cleanup;
#endif

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    if (xenParseXLGntLimits(conf, def) < 0)
        goto cleanup;
#endif

    if (xenParseXLCPUID(conf, def) < 0)
        goto cleanup;

    if (xenParseXLDisk(conf, def) < 0)
        goto cleanup;

    if (xenParseXLSpice(conf, def) < 0)
        goto cleanup;

    if (xenParseXLInputDevs(conf, def) < 0)
        goto cleanup;

    if (xenParseXLUSB(conf, def) < 0)
        goto cleanup;

    if (xenParseXLUSBController(conf, def) < 0)
        goto cleanup;

    if (xenParseXLChannel(conf, def) < 0)
        goto cleanup;

    if (virDomainDefPostParse(def, caps, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        goto cleanup;

    return def;

 cleanup:
    virDomainDefFree(def);
    return NULL;
}


static int
xenFormatXLOS(virConfPtr conf, virDomainDefPtr def)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];
        if (xenConfigSetString(conf, "builder", "hvm") < 0)
            return -1;

        if (def->os.loader &&
            def->os.loader->type == VIR_DOMAIN_LOADER_TYPE_PFLASH) {
            if (xenConfigSetString(conf, "bios", "ovmf") < 0)
                return -1;
        }

        if (def->os.slic_table &&
            xenConfigSetString(conf, "acpi_firmware", def->os.slic_table) < 0)
            return -1;

#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
        if (def->os.kernel &&
            xenConfigSetString(conf, "kernel", def->os.kernel) < 0)
            return -1;

        if (def->os.initrd &&
            xenConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            return -1;

        if (def->os.cmdline &&
            xenConfigSetString(conf, "cmdline", def->os.cmdline) < 0)
            return -1;
#endif

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
xenFormatXLCPUID(virConfPtr conf, virDomainDefPtr def)
{
    char **cpuid_pairs = NULL;
    char *cpuid_string = NULL;
    size_t i, j;
    int ret = -1;

    if (!def->cpu)
        return 0;

    if (def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH) {
        VIR_WARN("ignoring CPU mode '%s', only host-passthrough mode "
                 "is supported", virCPUModeTypeToString(def->cpu->mode));
        return 0;
    }

    /* "host" + all features + NULL */
    if (VIR_ALLOC_N(cpuid_pairs, def->cpu->nfeatures + 2) < 0)
        return -1;

    if (VIR_STRDUP(cpuid_pairs[0], "host") < 0)
        goto cleanup;

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
        if (virAsprintf(&cpuid_pairs[j++], "%s=%s",
                        feature_name,
                        policy) < 0)
            goto cleanup;
    }
    cpuid_pairs[j] = NULL;

    if (j > 1) {
        cpuid_string = virStringListJoin((const char **)cpuid_pairs, ",");
        if (!cpuid_string)
            goto cleanup;

        if (xenConfigSetString(conf, "cpuid", cpuid_string) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virStringListFree(cpuid_pairs);
    VIR_FREE(cpuid_string);
    return ret;
}

#ifdef LIBXL_HAVE_VNUMA
static int
xenFormatXLVnode(virConfValuePtr list,
                 virBufferPtr buf)
{
    int ret = -1;
    virConfValuePtr numaPnode, tmp;

    if (virBufferCheckError(buf) < 0)
        goto cleanup;

    if (VIR_ALLOC(numaPnode) < 0)
        goto cleanup;

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
    ret = 0;

 cleanup:
    virBufferFreeAndReset(buf);
    return ret;
}

static int
xenFormatXLVnuma(virConfValuePtr list,
                 virDomainNumaPtr numa,
                 size_t node,
                 size_t nr_nodes)
{
    int ret = -1;
    size_t i;

    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr numaVnode, tmp;

    size_t nodeSize = virDomainNumaGetNodeMemorySize(numa, node) / 1024;
    char *nodeVcpus = virBitmapFormat(virDomainNumaGetNodeCpumask(numa, node));

    if (VIR_ALLOC(numaVnode) < 0)
        goto cleanup;

    numaVnode->type = VIR_CONF_LIST;
    numaVnode->list = NULL;

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

 cleanup:
    VIR_FREE(nodeVcpus);
    return ret;
}

static int
xenFormatXLDomainVnuma(virConfPtr conf,
                       virDomainDefPtr def)
{
    virDomainNumaPtr numa = def->numa;
    virConfValuePtr vnumaVal;
    size_t i;
    size_t nr_nodes;

    if (numa == NULL)
        return -1;

    if (VIR_ALLOC(vnumaVal) < 0)
        return -1;

    vnumaVal->type = VIR_CONF_LIST;
    vnumaVal->list = NULL;

    nr_nodes = virDomainNumaGetNodeCount(numa);
    for (i = 0; i < nr_nodes; i++) {
        if (xenFormatXLVnuma(vnumaVal, numa, i, nr_nodes) < 0)
            goto cleanup;
    }

    if (vnumaVal->list != NULL) {
        int ret = virConfSetValue(conf, "vnuma", vnumaVal);
            vnumaVal = NULL;
            if (ret < 0)
                return -1;
    }
    VIR_FREE(vnumaVal);

    return 0;

 cleanup:
    virConfFreeValue(vnumaVal);
    return -1;
}
#endif

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
static int
xenFormatXLGntLimits(virConfPtr conf, virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_XENBUS &&
            def->controllers[i]->opts.xenbusopts.maxGrantFrames > 0) {
            if (xenConfigSetInt(conf, "max_grant_frames",
                                def->controllers[i]->opts.xenbusopts.maxGrantFrames) < 0)
                return -1;
        }
    }
    return 0;
}
#endif

static char *
xenFormatXLDiskSrcNet(virStorageSourcePtr src)
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
    case VIR_STORAGE_NET_PROTOCOL_VXHS:
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
xenFormatXLDiskSrc(virStorageSourcePtr src, char **srcstr)
{
    int actualType = virStorageSourceGetActualType(src);

    *srcstr = NULL;

    if (virStorageSourceIsEmpty(src))
        return 0;

    switch ((virStorageType)actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_DIR:
        if (VIR_STRDUP(*srcstr, src->path) < 0)
            return -1;
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        if (!(*srcstr = xenFormatXLDiskSrcNet(src)))
            return -1;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        break;
    }

    return 0;
}


static int
xenFormatXLDisk(virConfValuePtr list, virDomainDiskDefPtr disk)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    int format = virDomainDiskGetFormat(disk);
    const char *driver = virDomainDiskGetDriver(disk);
    char *target = NULL;
    int ret = -1;

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
        goto cleanup;
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
        goto cleanup;

    if (target)
        virBufferAsprintf(&buf, ",target=%s", target);

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    if (VIR_ALLOC(val) < 0)
        goto cleanup;

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;
    ret = 0;

 cleanup:
    VIR_FREE(target);
    virBufferFreeAndReset(&buf);
    return ret;
}


static int
xenFormatXLDomainDisks(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr diskVal;
    size_t i;

    if (VIR_ALLOC(diskVal) < 0)
        return -1;

    diskVal->type = VIR_CONF_LIST;
    diskVal->list = NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            continue;

        if (xenFormatXLDisk(diskVal, def->disks[i]) < 0)
            goto cleanup;
    }

    if (diskVal->list != NULL) {
        int ret = virConfSetValue(conf, "disk", diskVal);
        diskVal = NULL;
        if (ret < 0)
            return -1;
    }
    VIR_FREE(diskVal);

    return 0;

 cleanup:
    virConfFreeValue(diskVal);
    return -1;
}


static int
xenFormatXLSpice(virConfPtr conf, virDomainDefPtr def)
{
    virDomainGraphicsListenDefPtr glisten;
    virDomainGraphicsDefPtr graphics;

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
                case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER:
                    if (xenConfigSetInt(conf, "spiceagent_mouse", 0) < 0)
                        return -1;
                    break;
                case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT:
                    if (xenConfigSetInt(conf, "spiceagent_mouse", 1) < 0)
                        return -1;
                    /*
                     * spicevdagent must be enabled if using client
                     * mode mouse
                     */
                    if (xenConfigSetInt(conf, "spicevdagent", 1) < 0)
                        return -1;
                    break;
                case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_DEFAULT:
                    break;
                case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_LAST:
                default:
                    virReportEnumRangeError(virDomainGraphicsSpiceMouseMode,
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
xenFormatXLInputDevs(virConfPtr conf, virDomainDefPtr def)
{
    size_t i;
    const char *devtype;
    virConfValuePtr usbdevices = NULL, lastdev;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (VIR_ALLOC(usbdevices) < 0)
            goto error;

        usbdevices->type = VIR_CONF_LIST;
        usbdevices->list = NULL;
        lastdev = NULL;
        for (i = 0; i < def->ninputs; i++) {
            if (def->inputs[i]->bus == VIR_DOMAIN_INPUT_BUS_USB) {
                if (xenConfigSetInt(conf, "usb", 1) < 0)
                    goto error;

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
                    if (VIR_ALLOC(lastdev) < 0)
                        goto error;
                    usbdevices->list = lastdev;
                } else {
                    if (VIR_ALLOC(lastdev->next) < 0)
                        goto error;
                    lastdev = lastdev->next;
                }
                lastdev->type = VIR_CONF_STRING;
                if (VIR_STRDUP(lastdev->str, devtype) < 0)
                    goto error;
            }
        }
        if (usbdevices->list != NULL) {
            if (usbdevices->list->next == NULL) {
                /* for compatibility with Xen <= 4.2, use old syntax when
                 * only one device present */
                if (xenConfigSetString(conf, "usbdevice", usbdevices->list->str) < 0)
                    goto error;
                virConfFreeValue(usbdevices);
            } else {
                virConfSetValue(conf, "usbdevice", usbdevices);
            }
        } else {
            VIR_FREE(usbdevices);
        }
    }

    return 0;
 error:
    virConfFreeValue(usbdevices);
    return -1;
}

static int
xenFormatXLUSBController(virConfPtr conf,
                         virDomainDefPtr def)
{
    virConfValuePtr usbctrlVal = NULL;
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

    if (VIR_ALLOC(usbctrlVal) < 0)
        return -1;

    usbctrlVal->type = VIR_CONF_LIST;
    usbctrlVal->list = NULL;

    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            virConfValuePtr val, tmp;
            virBuffer buf = VIR_BUFFER_INITIALIZER;

            if (def->controllers[i]->model != -1) {
                switch (def->controllers[i]->model) {
                case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1:
                    virBufferAddLit(&buf, "type=qusb,version=1,");
                    break;

                case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2:
                    virBufferAddLit(&buf, "type=qusb,version=2,");
                    break;

                default:
                    goto error;
                }
            }

            if (def->controllers[i]->opts.usbopts.ports != -1)
                virBufferAsprintf(&buf, "ports=%x",
                                  def->controllers[i]->opts.usbopts.ports);

            if (VIR_ALLOC(val) < 0) {
                virBufferFreeAndReset(&buf);
                goto error;
            }
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

    if (usbctrlVal->list != NULL) {
        int ret = virConfSetValue(conf, "usbctrl", usbctrlVal);
        usbctrlVal = NULL;
        if (ret < 0)
            return -1;
    }
    VIR_FREE(usbctrlVal);

    return 0;

 error:
    virConfFreeValue(usbctrlVal);
    return -1;
}


static int
xenFormatXLUSB(virConfPtr conf,
               virDomainDefPtr def)
{
    virConfValuePtr usbVal = NULL;
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

    if (VIR_ALLOC(usbVal) < 0)
        return -1;

    usbVal->type = VIR_CONF_LIST;
    usbVal->list = NULL;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            virConfValuePtr val, tmp;
            char *buf;

            if (virAsprintf(&buf, "hostbus=%x,hostaddr=%x",
                            def->hostdevs[i]->source.subsys.u.usb.bus,
                            def->hostdevs[i]->source.subsys.u.usb.device) < 0)
                goto error;

            if (VIR_ALLOC(val) < 0) {
                VIR_FREE(buf);
                goto error;
            }
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

    if (usbVal->list != NULL) {
        int ret = virConfSetValue(conf, "usbdev", usbVal);
        usbVal = NULL;
        if (ret < 0)
            return -1;
    }
    VIR_FREE(usbVal);

    return 0;

 error:
    virConfFreeValue(usbVal);
    return -1;
}

static int
xenFormatXLChannel(virConfValuePtr list, virDomainChrDefPtr channel)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int sourceType = channel->source->type;
    virConfValuePtr val, tmp;

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
            goto cleanup;
    }

    /* name */
    virBufferAsprintf(&buf, "name=%s", channel->target.name);

    if (VIR_ALLOC(val) < 0)
        goto cleanup;

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

 cleanup:
    virBufferFreeAndReset(&buf);
    return -1;
}

static int
xenFormatXLDomainChannels(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr channelVal = NULL;
    size_t i;

    if (VIR_ALLOC(channelVal) < 0)
        goto cleanup;

    channelVal->type = VIR_CONF_LIST;
    channelVal->list = NULL;

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr chr = def->channels[i];

        if (chr->targetType != VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN)
            continue;

        if (xenFormatXLChannel(channelVal, def->channels[i]) < 0)
            goto cleanup;
    }

    if (channelVal->list != NULL) {
        int ret = virConfSetValue(conf, "channel", channelVal);
        channelVal = NULL;
        if (ret < 0)
            goto cleanup;
    }

    VIR_FREE(channelVal);
    return 0;

 cleanup:
    virConfFreeValue(channelVal);
    return -1;
}

virConfPtr
xenFormatXL(virDomainDefPtr def, virConnectPtr conn)
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

#ifdef LIBXL_HAVE_VNUMA
    if (xenFormatXLDomainVnuma(conf, def) < 0)
        return NULL;
#endif

#ifdef LIBXL_HAVE_BUILDINFO_GRANT_LIMITS
    if (xenFormatXLGntLimits(conf, def) < 0)
        return NULL;
#endif

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

    VIR_RETURN_PTR(conf);
}
