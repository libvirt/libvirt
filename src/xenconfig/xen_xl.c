/*
 * xen_xl.c: Xen XL parsing functions
 *
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Kiarie Kahurani <davidkiarie4@gmail.com>
 * Author: Jim Fehlig <jfehlig@suse.com>
 */

#include <config.h>

#include <libxl.h>

#include "virconf.h"
#include "virerror.h"
#include "domain_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "virstoragefile.h"
#include "xen_xl.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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

static int
xenParseXLOS(virConfPtr conf, virDomainDefPtr def, virCapsPtr caps)
{
    size_t i;
    const char *extra, *root;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        const char *boot;

        for (i = 0; i < caps->nguests; i++) {
            if (caps->guests[i]->ostype == VIR_DOMAIN_OSTYPE_HVM &&
                caps->guests[i]->arch.id == def->os.arch) {
                if (VIR_ALLOC(def->os.loader) < 0 ||
                    VIR_STRDUP(def->os.loader->path,
                               caps->guests[i]->arch.defaultInfo.loader) < 0)
                    return -1;
            }
        }

#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
        if (xenConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            return -1;

        if (xenConfigGetString(conf, "extra", &extra, NULL) < 0)
            return -1;

        if (xenConfigGetString(conf, "root", &root, NULL) < 0)
            return -1;

        if (root) {
            if (virAsprintf(&def->os.cmdline, "root=%s %s", root, extra) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(def->os.cmdline, extra) < 0)
                return -1;
        }
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
    } else {
        if (xenConfigCopyStringOpt(conf, "bootloader", &def->os.bootloader) < 0)
            return -1;
        if (xenConfigCopyStringOpt(conf, "bootargs", &def->os.bootloaderArgs) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            return -1;

        if (xenConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            return -1;

        if (xenConfigGetString(conf, "extra", &extra, NULL) < 0)
            return -1;

        if (xenConfigGetString(conf, "root", &root, NULL) < 0)
            return -1;

        if (root) {
            if (virAsprintf(&def->os.cmdline, "root=%s %s", root, extra) < 0)
                return -1;
        } else {
            if (VIR_STRDUP(def->os.cmdline, extra) < 0)
                return -1;
        }
    }

    return 0;
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
            if (listenAddr &&
                virDomainGraphicsListenSetAddress(graphics, 0, listenAddr,
                                                  -1, true) < 0) {
                goto cleanup;
            }
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
    virDomainGraphicsDefFree(graphics);
    return -1;
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

            if (VIR_STRDUP(disk->dst, libxldisk->vdev) < 0)
                goto fail;

            if (virDomainDiskSetSource(disk, libxldisk->pdev_path) < 0)
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
                }

                switch (libxldisk->backend) {
                case LIBXL_DISK_BACKEND_QDISK:
                case LIBXL_DISK_BACKEND_UNKNOWN:
                    if (virDomainDiskSetDriver(disk, "qemu") < 0)
                        goto fail;
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

    if (xenParseConfigCommon(conf, def, caps) < 0)
        goto cleanup;

    if (xenParseXLOS(conf, def, caps) < 0)
        goto cleanup;

    if (xenParseXLDisk(conf, def) < 0)
        goto cleanup;

    if (xenParseXLSpice(conf, def) < 0)
        goto cleanup;

    if (xenParseXLInputDevs(conf, def) < 0)
        goto cleanup;

    if (virDomainDefPostParse(def, caps, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt) < 0)
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

#ifdef LIBXL_HAVE_BUILDINFO_KERNEL
        if (def->os.kernel &&
            xenConfigSetString(conf, "kernel", def->os.kernel) < 0)
            return -1;

        if (def->os.initrd &&
            xenConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            return -1;

        if (def->os.cmdline &&
            xenConfigSetString(conf, "extra", def->os.cmdline) < 0)
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

        /* XXX floppy disks */
    } else {
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
             xenConfigSetString(conf, "extra", def->os.cmdline) < 0)
            return -1;
     } /* !hvm */

    return 0;
}


static int
xenFormatXLDisk(virConfValuePtr list, virDomainDiskDefPtr disk)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    const char *src = virDomainDiskGetSource(disk);
    int format = virDomainDiskGetFormat(disk);
    const char *driver = virDomainDiskGetDriver(disk);

    /* target */
    virBufferAsprintf(&buf, "%s,", src);
    /* format */
    switch (format) {
        case VIR_STORAGE_FILE_RAW:
            virBufferAddLit(&buf, "raw,");
            break;
        case VIR_STORAGE_FILE_VHD:
            virBufferAddLit(&buf, "xvhd,");
            break;
        case VIR_STORAGE_FILE_QCOW:
            virBufferAddLit(&buf, "qcow,");
            break;
        case VIR_STORAGE_FILE_QCOW2:
            virBufferAddLit(&buf, "qcow2,");
            break;
      /* set default */
        default:
            virBufferAddLit(&buf, "raw,");
    }

    /* device */
    virBufferAdd(&buf, disk->dst, -1);

    virBufferAddLit(&buf, ",");

    if (disk->src->readonly)
        virBufferAddLit(&buf, "r,");
    else if (disk->src->shared)
        virBufferAddLit(&buf, "!,");
    else
        virBufferAddLit(&buf, "w,");
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        goto cleanup;
    }

    if (STREQ_NULLABLE(driver, "qemu"))
        virBufferAddLit(&buf, "backendtype=qdisk");
    else if (STREQ_NULLABLE(driver, "tap"))
        virBufferAddLit(&buf, "backendtype=tap");
    else if (STREQ_NULLABLE(driver, "phy"))
        virBufferAddLit(&buf, "backendtype=phy");

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, ",devtype=cdrom");

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
    return 0;

 cleanup:
    virBufferFreeAndReset(&buf);
    return -1;
}


static int
xenFormatXLDomainDisks(virConfPtr conf, virDomainDefPtr def)
{
    int ret = -1;
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

    if (diskVal->list != NULL)
        if (virConfSetValue(conf, "disk", diskVal) == 0)
            diskVal = NULL;

    ret = 0;

 cleanup:
    virConfFreeValue(diskVal);
    return ret;
}


static int
xenFormatXLSpice(virConfPtr conf, virDomainDefPtr def)
{
    const char *listenAddr = NULL;
    virDomainGraphicsDefPtr graphics;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        graphics = def->graphics[0];

        if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            /* set others to false but may not be necessary */
            if (xenConfigSetInt(conf, "sdl", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "vnc", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spice", 1) < 0)
                return -1;

            listenAddr = virDomainGraphicsListenGetAddress(graphics, 0);
            if (listenAddr &&
                xenConfigSetString(conf, "spicehost", listenAddr) < 0)
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
                default:
                    break;
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


virConfPtr
xenFormatXL(virDomainDefPtr def, virConnectPtr conn)
{
    virConfPtr conf = NULL;

    if (!(conf = virConfNew()))
        goto cleanup;

    if (xenFormatConfigCommon(conf, def, conn) < 0)
        goto cleanup;

    if (xenFormatXLOS(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLDomainDisks(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLSpice(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLInputDevs(conf, def) < 0)
        goto cleanup;

    return conf;

 cleanup:
    if (conf)
        virConfFree(conf);
    return NULL;
}
