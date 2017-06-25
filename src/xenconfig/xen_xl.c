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
    const char *root, *extra, *buf;

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
        const char *bios;
        const char *boot;
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

        if (val == 1) {
            virCPUDefPtr cpu;

            if (VIR_ALLOC(cpu) < 0)
                return -1;

            cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
            cpu->type = VIR_CPU_TYPE_GUEST;
            def->cpu = cpu;
        } else if (val == 0) {
            const char *vtfeature = NULL;

            if (caps && caps->host.cpu && ARCH_IS_X86(def->os.arch)) {
                if (virCPUCheckFeature(caps->host.arch, caps->host.cpu, "vmx"))
                    vtfeature = "vmx";
                else if (virCPUCheckFeature(caps->host.arch, caps->host.cpu, "svm"))
                    vtfeature = "svm";
            }

            if (vtfeature) {
                virCPUDefPtr cpu;

                if (VIR_ALLOC(cpu) < 0)
                    return -1;

                if (VIR_ALLOC(cpu->features) < 0) {
                    VIR_FREE(cpu);
                    return -1;
                }

                if (VIR_STRDUP(cpu->features->name, vtfeature) < 0) {
                    VIR_FREE(cpu->features);
                    VIR_FREE(cpu);
                    return -1;
                }
                cpu->features->policy = VIR_CPU_FEATURE_DISABLE;
                cpu->nfeatures = cpu->nfeatures_max = 1;
                cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
                cpu->type = VIR_CPU_TYPE_GUEST;
                def->cpu = cpu;
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
                    int len = nextkey ? (nextkey - data) : sizeof(type) - 1;
                    if (virStrncpy(type, data, len, sizeof(type)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("type %s invalid"),
                                       data);
                        goto skipusbctrl;
                    }
                } else if (STRPREFIX(key, "version=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(version) - 1;
                    if (virStrncpy(version, data, len, sizeof(version)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("version %s invalid"),
                                       data);
                        goto skipusbctrl;
                    }
                    if (virStrToLong_i(version, NULL, 16, &usbctrl_version) < 0)
                        goto skipusbctrl;
                } else if (STRPREFIX(key, "ports=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(ports) - 1;
                    if (virStrncpy(ports, data, len, sizeof(ports)) == NULL) {
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
                    int len = nextkey ? (nextkey - data) : sizeof(bus) - 1;
                    if (virStrncpy(bus, data, len, sizeof(bus)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("bus %s too big for destination"),
                                       data);
                        goto skipusb;
                    }
                } else if (STRPREFIX(key, "hostaddr=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(device) - 1;
                    if (virStrncpy(device, data, len, sizeof(device)) == NULL) {
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
            if (!(hostdev = virDomainHostdevDefNew(NULL)))
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
                    int len = nextkey ? (nextkey - data) : sizeof(type) - 1;
                    if (virStrncpy(type, data, len, sizeof(type)) == NULL) {
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
                    virBufferAsprintf(&buf, "\\\\:%s", src->hosts[i].port);
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

    switch ((virStorageType) actualType) {
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
    virConfPtr conf = NULL;

    if (!(conf = virConfNew()))
        goto cleanup;

    if (xenFormatConfigCommon(conf, def, conn, XEN_CONFIG_FORMAT_XL) < 0)
        goto cleanup;

    if (xenFormatXLOS(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLDomainDisks(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLSpice(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLInputDevs(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLUSB(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLUSBController(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLDomainChannels(conf, def) < 0)
        goto cleanup;

    return conf;

 cleanup:
    if (conf)
        virConfFree(conf);
    return NULL;
}
