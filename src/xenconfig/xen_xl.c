/*
 * xen_xl.c: Xen XL parsing functions
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
 */

#include <config.h>

#include "virconf.h"
#include "virerror.h"
#include "domain_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "xen_xl.h"
#include "xen_xl_disk.h"
#include "xen_xl_disk_i.h"

#define VIR_FROM_THIS VIR_FROM_NONE


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


void
xenXLDiskParserError(xenXLDiskParserContext *dpc,
                     const char *erroneous,
                     const char *message)
{
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("disk config %s not supported: %s"),
                   erroneous, message);

    if (!dpc->err)
        dpc->err = EINVAL;
}


static int
xenXLDiskParserPrep(xenXLDiskParserContext *dpc,
                    const char *spec,
                    virDomainDiskDefPtr disk)
{
    int err;

    dpc->spec = spec;
    dpc->disk = disk;
    dpc->access_set = 0;

    err = xl_disk_lex_init_extra(dpc, &dpc->scanner);
    if (err)
        goto fail;

    dpc->buf = xl_disk__scan_bytes(spec, strlen(spec), dpc->scanner);
    if (!dpc->buf) {
        err = ENOMEM;
        goto fail;
    }

    return 0;

 fail:
    virReportSystemError(errno, "%s",
                         _("failed to initialize disk configuration parser"));
    return err;
}


static void
xenXLDiskParserCleanup(xenXLDiskParserContext *dpc)
{
    if (dpc->buf) {
        xl_disk__delete_buffer(dpc->buf, dpc->scanner);
        dpc->buf = NULL;
    }

    if (dpc->scanner) {
        xl_disk_lex_destroy(dpc->scanner);
        dpc->scanner = NULL;
    }
}


/*
 * positional parameters
 *     (If the <diskspec> strings are not separated by "="
 *     the  string is split following ',' and assigned to
 *     the following options in the following order)
 *     target,format,vdev,access
 * ================================================================
 *
 * The parameters below cannot be specified as positional parameters:
 *
 * other parameters
 *    devtype = <devtype>
 *    backendtype = <backend-type>
 * parameters not taken care of
 *    backend = <domain-name>
 *    script = <script>
 *    direct-io-safe
 *
 * ================================================================
 * The parser does not take any deprecated parameters
 *
 * For more information refer to /xen/docs/misc/xl-disk-configuration.txt
 */
static int
xenParseXLDisk(virConfPtr conf, virDomainDefPtr def)
{
    virConfValuePtr list = virConfGetValue(conf, "disk");
    xenXLDiskParserContext dpc;
    virDomainDiskDefPtr disk;

    memset(&dpc, 0, sizeof(dpc));

    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char *disk_spec = list->str;
            const char *driver;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipdisk;

            if (!(disk = virDomainDiskDefNew()))
                    return -1;

            disk->src->readonly = 0;
            disk->src->format = VIR_STORAGE_FILE_LAST;

            if (xenXLDiskParserPrep(&dpc, disk_spec, disk))
                goto fail;

            xl_disk_lex(dpc.scanner);

            if (dpc.err)
                goto fail;

            if (disk->src->format == VIR_STORAGE_FILE_LAST)
                disk->src->format = VIR_STORAGE_FILE_RAW;

            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                disk->removable = true;
                disk->src->readonly = true;
                if (virDomainDiskSetDriver(disk, "qemu") < 0)
                    goto fail;

                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                if (!disk->src->path || STREQ(disk->src->path, ""))
                    disk->src->format = VIR_STORAGE_FILE_NONE;
            }

            if (STRPREFIX(disk->dst, "xvd") || !STREQ(def->os.type, "hvm"))
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(disk->dst, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

            driver = virDomainDiskGetDriver(disk);
            if (!driver) {
                switch (disk->src->format) {
                case VIR_STORAGE_FILE_QCOW:
                case VIR_STORAGE_FILE_QCOW2:
                case VIR_STORAGE_FILE_VHD:
                    driver = "qemu";
                    if (virDomainDiskSetDriver(disk, "qemu") < 0)
                        goto fail;
                    break;
                default:
                    driver = "phy";
                    if (virDomainDiskSetDriver(disk, "phy") < 0)
                        goto fail;
                }
            }

            if (STREQ(driver, "phy"))
                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
            else
                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);

            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto fail;

        skipdisk:
            list = list->next;
            xenXLDiskParserCleanup(&dpc);
        }
    }
    return 0;

 fail:
    xenXLDiskParserCleanup(&dpc);
    virDomainDiskDefFree(disk);
    return -1;
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

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, "devtype=cdrom");

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
    virConfValuePtr diskVal = NULL;
    size_t i = 0;

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
            goto cleanup;
    }

    return 0;

 cleanup:
    virConfFreeValue(diskVal);
    return 0;
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

            if (xenConfigSetInt(conf, "spicemouse_mouse",
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
