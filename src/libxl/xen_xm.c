/*
 * xen_xm.c: Xen XM parsing functions
 *
 * Copyright (C) 2006-2007, 2009-2014 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "xenxs_private.h"
#include "xen_xm.h"
#include "domain_conf.h"
#include "domain_postparse.h"
#include "xen_common.h"

#define VIR_FROM_THIS VIR_FROM_XENXM

static int
xenParseXMOS(virConf *conf, virDomainDef *def)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        g_autofree char *boot = NULL;

        def->os.loader = virDomainLoaderDefNew();
        def->os.loader->format = VIR_STORAGE_FILE_RAW;

        if (xenConfigCopyString(conf, "kernel", &def->os.loader->path) < 0)
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
    } else {
        g_autofree char *extra = NULL;
        g_autofree char *root = NULL;

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

        if (root && extra) {
            def->os.cmdline = g_strdup_printf("root=%s %s", root, extra);
        } else if (root) {
            def->os.cmdline = g_strdup_printf("root=%s", root);
        } else if (extra) {
            def->os.cmdline = g_strdup(extra);
        }
    }

    return 0;
}


static virDomainDiskDef *
xenParseXMDisk(char *entry, int hvm)
{
    virDomainDiskDef *disk = NULL;
    char *head;
    char *offset;
    char *tmp;
    const char *src;

    if (!(disk = virDomainDiskDefNew(NULL)))
        return NULL;

    head = entry;
    /*
     * Disks have 3 components, SOURCE,DEST-DEVICE,MODE
     * eg, phy:/dev/HostVG/XenGuest1,xvda,w
     * The SOURCE is usually prefixed with a driver type,
     * and optionally driver sub-type
     * The DEST-DEVICE is optionally post-fixed with disk type
     */

    /* Extract the source file path */
    if (!(offset = strchr(head, ',')))
        goto error;

    if (offset == head) {
        /* No source file given, eg CDROM with no media */
        virDomainDiskSetSource(disk, NULL);
    } else {
        tmp = g_strndup(head, offset - head);

        virDomainDiskSetSource(disk, tmp);
        VIR_FREE(tmp);
    }

    head = offset + 1;
    /* Remove legacy ioemu: junk */
    if (STRPREFIX(head, "ioemu:"))
        head = head + 6;

    /* Extract the dest device name */
    if (!(offset = strchr(head, ',')))
        goto error;

    disk->dst = g_strndup(head, offset - head);

    head = offset + 1;
    /* Extract source driver type */
    src = virDomainDiskGetSource(disk);
    if (src) {
        size_t len;
        /* The main type  phy:, file:, tap: ... */
        if ((tmp = strchr(src, ':')) != NULL) {
            len = tmp - src;
            tmp = g_strndup(src, len);

            virDomainDiskSetDriver(disk, tmp);
            VIR_FREE(tmp);

            /* Strip the prefix we found off the source file name */
            virDomainDiskSetSource(disk, src + len + 1);

            src = virDomainDiskGetSource(disk);
        }

        /* And the sub-type for tap:XXX: type */
        if (STREQ_NULLABLE(virDomainDiskGetDriver(disk), "tap") ||
            STREQ_NULLABLE(virDomainDiskGetDriver(disk), "tap2")) {
            char *driverType;

            if (!(tmp = strchr(src, ':')))
                goto error;
            len = tmp - src;

            driverType = g_strndup(src, len);

            if (STREQ(driverType, "aio"))
                virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
            else
                virDomainDiskSetFormat(disk,
                                       virStorageFileFormatTypeFromString(driverType));
            VIR_FREE(driverType);
            if (virDomainDiskGetFormat(disk) <= 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown driver type %1$s"),
                               src);
                goto error;
            }

            /* Strip the prefix we found off the source file name */
            virDomainDiskSetSource(disk, src + len + 1);
            src = virDomainDiskGetSource(disk);
        }
    }

    /* No source, or driver name, so fix to phy: */
    if (!virDomainDiskGetDriver(disk))
        virDomainDiskSetDriver(disk, "phy");

    /* phy: type indicates a block device */
    virDomainDiskSetType(disk,
                         STREQ(virDomainDiskGetDriver(disk), "phy") ?
                         VIR_STORAGE_TYPE_BLOCK :
                         VIR_STORAGE_TYPE_FILE);

    /* Check for a :cdrom/:disk postfix */
    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    if ((tmp = strchr(disk->dst, ':')) != NULL) {
        if (STREQ(tmp, ":cdrom"))
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
        tmp[0] = '\0';
    }

    if (STRPREFIX(disk->dst, "xvd") || !hvm)
        disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
    else if (STRPREFIX(disk->dst, "sd"))
        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
    else
        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

    if (STREQ(head, "r") || STREQ(head, "ro"))
        disk->src->readonly = true;
    else if (STREQ(head, "w!") || STREQ(head, "!"))
        disk->src->shared = true;

    return disk;

 error:
    virDomainDiskDefFree(disk);
    return NULL;
}


static int
xenParseXMDiskList(virConf *conf, virDomainDef *def)
{
    g_auto(GStrv) disks = NULL;
    GStrv entries;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;
    int rc;

    rc = virConfGetValueStringList(conf, "disk", false, &disks);
    if (rc <= 0)
        return rc;

    for (entries = disks; *entries; entries++) {
        virDomainDiskDef *disk;
        char *entry = *entries;

        if (!(disk = xenParseXMDisk(entry, hvm)))
            continue;

        /* Maintain list in sorted order according to target device name */
        VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk);
    }

    return 0;
}


static int
xenFormatXMDisk(virConfValue *list,
                virDomainDiskDef *disk)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virConfValue *val;
    virConfValue *tmp;
    const char *src = virDomainDiskGetSource(disk);
    int format = virDomainDiskGetFormat(disk);
    const char *driver = virDomainDiskGetDriver(disk);

    if (src) {
        if (format) {
            const char *type;

            if (format == VIR_STORAGE_FILE_RAW)
                type = "aio";
            else
                type = virStorageFileFormatTypeToString(format);

            if (driver) {
                virBufferAsprintf(&buf, "%s:", driver);
                if (STREQ(driver, "tap") || STREQ(driver, "tap2"))
                    virBufferAsprintf(&buf, "%s:", type);
            }
        } else {
            switch (virDomainDiskGetType(disk)) {
            case VIR_STORAGE_TYPE_FILE:
                virBufferAddLit(&buf, "file:");
                break;
            case VIR_STORAGE_TYPE_BLOCK:
                virBufferAddLit(&buf, "phy:");
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported disk type %1$s"),
                               virStorageTypeToString(virDomainDiskGetType(disk)));
                return -1;
            }
        }
        virBufferAdd(&buf, src, -1);
    }
    virBufferAddLit(&buf, ",");

    virBufferAdd(&buf, disk->dst, -1);
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, ":cdrom");

    if (disk->src->readonly)
        virBufferAddLit(&buf, ",r");
    else if (disk->src->shared)
        virBufferAddLit(&buf, ",!");
    else
        virBufferAddLit(&buf, ",w");
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        return -1;
    }

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
xenFormatXMDisks(virConf *conf, virDomainDef *def)
{
    g_autoptr(virConfValue) diskVal = NULL;
    size_t i = 0;

    diskVal = g_new0(virConfValue, 1);

    diskVal->type = VIR_CONF_LIST;
    diskVal->list = NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            continue;

        if (xenFormatXMDisk(diskVal, def->disks[i]) < 0)
            return -1;
    }

    if (diskVal->list != NULL &&
        virConfSetValue(conf, "disk", &diskVal) < 0)
        return -1;

    return 0;
}


static int
xenParseXMInputDevs(virConf *conf, virDomainDef *def)
{
    g_autofree char *str = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (xenConfigGetString(conf, "usbdevice", &str, NULL) < 0)
            return -1;
        if (str &&
                (STREQ(str, "tablet") ||
                 STREQ(str, "mouse") ||
                 STREQ(str, "keyboard"))) {
            virDomainInputDef *input;
            input = g_new0(virDomainInputDef, 1);

            input->bus = VIR_DOMAIN_INPUT_BUS_USB;
            if (STREQ(str, "mouse"))
                input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
            else if (STREQ(str, "tablet"))
                input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
            else if (STREQ(str, "keyboard"))
                input->type = VIR_DOMAIN_INPUT_TYPE_KBD;
            VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input);
        }
    }
    return 0;
}

/*
 * Convert an XM config record into a virDomainDef object.
 */
virDomainDef *
xenParseXM(virConf *conf,
           virCaps *caps,
           virDomainXMLOption *xmlopt)
{
    g_autoptr(virDomainDef) def = NULL;

    if (!(def = virDomainDefNew(xmlopt)))
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenParseConfigCommon(conf, def, caps, XEN_CONFIG_FORMAT_XM,
                             xmlopt) < 0)
        return NULL;

    if (xenParseXMOS(conf, def) < 0)
         return NULL;

    if (xenParseXMDiskList(conf, def) < 0)
         return NULL;

    if (xenParseXMInputDevs(conf, def) < 0)
         return NULL;

    if (virDomainDefPostParse(def, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        return NULL;

    return g_steal_pointer(&def);
}

static int
xenFormatXMOS(virConf *conf, virDomainDef *def)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];
        if (xenConfigSetString(conf, "builder", "hvm") < 0)
            return -1;

        if (def->os.loader && def->os.loader->path &&
            xenConfigSetString(conf, "kernel", def->os.loader->path) < 0)
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
xenFormatXMInputDevs(virConf *conf, virDomainDef *def)
{
    size_t i;
    const char *devtype;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
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
                if (xenConfigSetString(conf, "usbdevice", devtype) < 0)
                    return -1;
                break;
            }
        }
    }
    return 0;
}


/* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
   either 32, or 64 on a platform where long is big enough.  */
G_STATIC_ASSERT(MAX_VIRT_CPUS <= sizeof(1UL) * CHAR_BIT);

/*
 * Convert a virDomainDef object into an XM config record.
 */
virConf *
xenFormatXM(virConnectPtr conn,
            virDomainDef *def)
{
    g_autoptr(virConf) conf = NULL;

    if (!(conf = virConfNew()))
        return NULL;

    if (xenFormatConfigCommon(conf, def, conn, XEN_CONFIG_FORMAT_XM) < 0)
        return NULL;

    if (xenFormatXMOS(conf, def) < 0)
        return NULL;

    if (xenFormatXMDisks(conf, def) < 0)
        return NULL;

    if (xenFormatXMInputDevs(conf, def) < 0)
        return NULL;

    return g_steal_pointer(&conf);
}
