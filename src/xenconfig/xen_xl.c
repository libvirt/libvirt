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
xenParseXLSpice(virConfPtr conf, virDomainDefPtr def)
{
    virDomainGraphicsDefPtr graphics = NULL;
    unsigned long port;
    char *listenAddr = NULL;
    int val;

    if (STREQ(def->os.type, "hvm")) {
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
            if (val) {
                if (xenConfigCopyStringOpt(conf, "spicepasswd",
                                           &graphics->data.spice.auth.passwd) < 0)
                    goto cleanup;
            }

            if (xenConfigGetBool(conf, "spiceagent_mouse",
                                 &graphics->data.spice.mousemode, 0) < 0)
                goto cleanup;
            if (xenConfigGetBool(conf, "spicedvagent", &val, 0) < 0)
                goto cleanup;
            if (val) {
                if (xenConfigGetBool(conf, "spice_clipboard_sharing",
                                     &graphics->data.spice.copypaste,
                                     0) < 0)
                    goto cleanup;
            }

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

            if (!(disk = virDomainDiskDefNew()))
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

            if (STRPREFIX(libxldisk->vdev, "xvd") || !STREQ(def->os.type, "hvm"))
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


virDomainDefPtr
xenParseXL(virConfPtr conf, virCapsPtr caps, int xendConfigVersion)
{
    virDomainDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenParseConfigCommon(conf, def, caps, xendConfigVersion) < 0)
        goto cleanup;

    if (xenParseXLDisk(conf, def) < 0)
        goto cleanup;

    if (xenParseXLSpice(conf, def) < 0)
        goto cleanup;

    return def;

 cleanup:
    virDomainDefFree(def);
    return NULL;
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

    if (STREQ(def->os.type, "hvm")) {
        if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
            /* set others to false but may not be necessary */
            if (xenConfigSetInt(conf, "sdl", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "vnc", 0) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spice", 1) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spiceport",
                                def->graphics[0]->data.spice.port) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spicetls_port",
                                def->graphics[0]->data.spice.tlsPort) < 0)
                return -1;

            if (def->graphics[0]->data.spice.auth.passwd) {
                if (xenConfigSetInt(conf, "spicedisable_ticketing", 1) < 0)
                    return -1;

                if (def->graphics[0]->data.spice.auth.passwd &&
                    xenConfigSetString(conf, "spicepasswd",
                                def->graphics[0]->data.spice.auth.passwd) < 0)
                    return -1;
            }

            listenAddr = virDomainGraphicsListenGetAddress(def->graphics[0], 0);
            if (listenAddr &&
                xenConfigSetString(conf, "spicehost", listenAddr) < 0)
                return -1;

            if (xenConfigSetInt(conf, "spiceagent_mouse",
                                def->graphics[0]->data.spice.mousemode) < 0)
                return -1;

            if (def->graphics[0]->data.spice.copypaste) {
                if (xenConfigSetInt(conf, "spicedvagent", 1) < 0)
                    return -1;
                if (xenConfigSetInt(conf, "spice_clipboard_sharing",
                                def->graphics[0]->data.spice.copypaste) < 0)
                return -1;
            }
        }
    }

    return 0;
}


virConfPtr
xenFormatXL(virDomainDefPtr def, virConnectPtr conn, int xendConfigVersion)
{
    virConfPtr conf = NULL;

    if (!(conf = virConfNew()))
        goto cleanup;

    if (xenFormatConfigCommon(conf, def, conn, xendConfigVersion) < 0)
        goto cleanup;

    if (xenFormatXLDomainDisks(conf, def) < 0)
        goto cleanup;

    if (xenFormatXLSpice(conf, def) < 0)
        goto cleanup;

    return conf;

 cleanup:
    if (conf)
        virConfFree(conf);
    return NULL;
}
