/*
 * virsh-volume.c: Commands to manage storage volume
 *
 * Copyright (C) 2005, 2007-2016 Red Hat, Inc.
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
#include "virsh-volume.h"
#include "virsh-util.h"

#include <fcntl.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virutil.h"
#include "virfile.h"
#include "virsh-pool.h"
#include "virxml.h"
#include "virstring.h"
#include "vsh-table.h"

#define VIRSH_COMMON_OPT_POOL_FULL \
    VIRSH_COMMON_OPT_POOL(N_("pool name or uuid"), \
                          VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)

#define VIRSH_COMMON_OPT_POOL_NAME \
    VIRSH_COMMON_OPT_POOL(N_("pool name"), \
                          VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE)

#define VIRSH_COMMON_OPT_POOL_OPTIONAL \
    {.name = "pool", \
     .type = VSH_OT_STRING, \
     .help = N_("pool name or uuid"), \
     .completer = virshStoragePoolNameCompleter, \
     .completer_flags = VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE, \
    }

#define VIRSH_COMMON_OPT_VOLUME_VOL \
    {.name = "vol", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = N_("vol name, key or path"), \
     .completer = virshStorageVolNameCompleter, \
    }

virStorageVolPtr
virshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                     const char *optname,
                     const char *pooloptname,
                     const char **name, unsigned int flags)
{
    virStorageVolPtr vol = NULL;
    virStoragePoolPtr pool = NULL;
    const char *n = NULL, *p = NULL;
    virshControlPtr priv = ctl->privData;

    virCheckFlags(VIRSH_BYUUID | VIRSH_BYNAME, NULL);

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    if (pooloptname != NULL &&
        vshCommandOptStringReq(ctl, cmd, pooloptname, &p) < 0)
        return NULL;

    if (p) {
        if (!(pool = virshCommandOptPoolBy(ctl, cmd, pooloptname, name, flags)))
            return NULL;

        if (virStoragePoolIsActive(pool) != 1) {
            vshError(ctl, _("pool '%s' is not active"), p);
            virStoragePoolFree(pool);
            return NULL;
        }
    }

    vshDebug(ctl, VSH_ERR_DEBUG, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by name */
    if (pool && (flags & VIRSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol name\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    /* try it by key */
    if (!vol && (flags & VIRSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(priv->conn, n);
    }
    /* try it by path */
    if (!vol && (flags & VIRSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol path\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByPath(priv->conn, n);
    }

    if (!vol) {
        if (pool || !pooloptname)
            vshError(ctl, _("failed to get vol '%s'"), n);
        else
            vshError(ctl, _("failed to get vol '%s', specifying --%s "
                            "might help"), n, pooloptname);
    } else {
        vshResetLibvirtError();
    }

    /* If the pool was specified, then make sure that the returned
     * volume is from the given pool */
    if (pool && vol) {
        virStoragePoolPtr volpool = NULL;

        if ((volpool = virStoragePoolLookupByVolume(vol))) {
            if (STRNEQ(virStoragePoolGetName(volpool),
                       virStoragePoolGetName(pool))) {
                vshResetLibvirtError();
                vshError(ctl,
                         _("Requested volume '%s' is not in pool '%s'"),
                         n, virStoragePoolGetName(pool));
                virStorageVolFree(vol);
                vol = NULL;
            }
            virStoragePoolFree(volpool);
        }
    }

    if (pool)
        virStoragePoolFree(pool);

    return vol;
}

/*
 * "vol-create-as" command
 */
static const vshCmdInfo info_vol_create_as[] = {
    {.name = "help",
     .data = N_("create a volume from a set of args")
    },
    {.name = "desc",
     .data = N_("Create a vol.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_create_as[] = {
    VIRSH_COMMON_OPT_POOL_NAME,
    {.name = "name",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("name of the volume")
    },
    {.name = "capacity",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("size of the vol, as scaled integer (default bytes)")
    },
    {.name = "allocation",
     .type = VSH_OT_STRING,
     .help = N_("initial allocation size, as scaled integer (default bytes)")
    },
    {.name = "format",
     .type = VSH_OT_STRING,
     .help = N_("file format type raw,bochs,qcow,qcow2,qed,vmdk")
    },
    {.name = "backing-vol",
     .type = VSH_OT_STRING,
     .help = N_("the backing volume if taking a snapshot")
    },
    {.name = "backing-vol-format",
     .type = VSH_OT_STRING,
     .help = N_("format of backing volume if taking a snapshot")
    },
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
    },
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document, but don't define/create")
    },
    {.name = NULL}
};

static int
virshVolSize(const char *data, unsigned long long *val)
{
    char *end;
    if (virStrToLong_ullp(data, &end, 10, val) < 0)
        return -1;
    return virScaleInteger(val, end, 1, ULLONG_MAX);
}

static bool
cmdVolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol = NULL;
    char *xml = NULL;
    bool printXML = vshCommandOptBool(cmd, "print-xml");
    const char *name, *capacityStr = NULL, *allocationStr = NULL, *format = NULL;
    const char *snapshotStrVol = NULL, *snapshotStrFormat = NULL;
    unsigned long long capacity, allocation = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned long flags = 0;
    virshControlPtr priv = ctl->privData;
    bool ret = false;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        goto cleanup;

    if (virshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %s"), capacityStr);
        goto cleanup;
    }

    if (vshCommandOptStringQuiet(ctl, cmd, "allocation", &allocationStr) > 0 &&
        virshVolSize(allocationStr, &allocation) < 0) {
        vshError(ctl, _("Malformed size %s"), allocationStr);
        goto cleanup;
    }

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "backing-vol", &snapshotStrVol) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "backing-vol-format",
                               &snapshotStrFormat) < 0)
        goto cleanup;

    virBufferAddLit(&buf, "<volume>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<name>%s</name>\n", name);
    virBufferAsprintf(&buf, "<capacity>%llu</capacity>\n", capacity);
    if (allocationStr)
        virBufferAsprintf(&buf, "<allocation>%llu</allocation>\n", allocation);

    if (format) {
        virBufferAddLit(&buf, "<target>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<format type='%s'/>\n", format);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</target>\n");
    }

    /* Convert the snapshot parameters into backingStore XML */
    if (snapshotStrVol) {
        /* Lookup snapshot backing volume.  Try the backing-vol
         *  parameter as a name */
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "%s: Look up backing store volume '%s' as name\n",
                 cmd->def->name, snapshotStrVol);
        virStorageVolPtr snapVol = virStorageVolLookupByName(pool, snapshotStrVol);
        if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as name\n",
                         cmd->def->name, snapshotStrVol);

        if (snapVol == NULL) {
            /* Snapshot backing volume not found by name.  Try the
             *  backing-vol parameter as a key */
            vshDebug(ctl, VSH_ERR_DEBUG,
                     "%s: Look up backing store volume '%s' as key\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByKey(priv->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as key\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            /* Snapshot backing volume not found by key.  Try the
             *  backing-vol parameter as a path */
            vshDebug(ctl, VSH_ERR_DEBUG,
                     "%s: Look up backing store volume '%s' as path\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByPath(priv->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as path\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            vshError(ctl, _("failed to get vol '%s'"), snapshotStrVol);
            goto cleanup;
        }

        char *snapshotStrVolPath;
        if ((snapshotStrVolPath = virStorageVolGetPath(snapVol)) == NULL) {
            virStorageVolFree(snapVol);
            goto cleanup;
        }

        /* Create XML for the backing store */
        virBufferAddLit(&buf, "<backingStore>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<path>%s</path>\n", snapshotStrVolPath);
        if (snapshotStrFormat)
            virBufferAsprintf(&buf, "<format type='%s'/>\n",
                              snapshotStrFormat);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</backingStore>\n");

        /* Cleanup snapshot allocations */
        VIR_FREE(snapshotStrVolPath);
        virStorageVolFree(snapVol);
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }
    xml = virBufferContentAndReset(&buf);

    if (printXML) {
        vshPrint(ctl, "%s", xml);
    } else {
        if (!(vol = virStorageVolCreateXML(pool, xml, flags))) {
            vshError(ctl, _("Failed to create vol %s"), name);
            goto cleanup;
        }
        vshPrintExtra(ctl, _("Vol %s created\n"), name);
    }

    ret = true;

 cleanup:
    virBufferFreeAndReset(&buf);
    if (vol)
        virStorageVolFree(vol);
    virStoragePoolFree(pool);
    VIR_FREE(xml);
    return ret;
}

/*
 * "vol-create" command
 */
static const vshCmdInfo info_vol_create[] = {
    {.name = "help",
     .data = N_("create a vol from an XML file")
    },
    {.name = "desc",
     .data = N_("Create a vol.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_create[] = {
    VIRSH_COMMON_OPT_POOL_NAME,
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML vol description")),
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
    },
    {.name = NULL}
};

static bool
cmdVolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    const char *from = NULL;
    bool ret = false;
    unsigned int flags = 0;
    char *buffer = NULL;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        goto cleanup;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    if ((vol = virStorageVolCreateXML(pool, buffer, flags))) {
        vshPrintExtra(ctl, _("Vol %s created from %s\n"),
                      virStorageVolGetName(vol), from);
        virStorageVolFree(vol);
        ret = true;
    } else {
        vshError(ctl, _("Failed to create vol from %s"), from);
    }

 cleanup:
    VIR_FREE(buffer);
    virStoragePoolFree(pool);
    return ret;
}

/*
 * "vol-create-from" command
 */
static const vshCmdInfo info_vol_create_from[] = {
    {.name = "help",
     .data = N_("create a vol, using another volume as input")
    },
    {.name = "desc",
     .data = N_("Create a vol from an existing volume.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_create_from[] = {
    VIRSH_COMMON_OPT_POOL_FULL,
    VIRSH_COMMON_OPT_FILE(N_("file containing an XML vol description")),
    VIRSH_COMMON_OPT_VOLUME_VOL,
    {.name = "inputpool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid of the input volume's pool")
    },
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
    },
    {.name = "reflink",
     .type = VSH_OT_BOOL,
     .help = N_("use btrfs COW lightweight copy")
    },
    {.name = NULL}
};

static bool
cmdVolCreateFrom(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr newvol = NULL, inputvol = NULL;
    const char *from = NULL;
    bool ret = false;
    char *buffer = NULL;
    unsigned int flags = 0;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptBool(cmd, "reflink"))
        flags |= VIR_STORAGE_VOL_CREATE_REFLINK;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        goto cleanup;

    if (!(inputvol = virshCommandOptVol(ctl, cmd, "vol", "inputpool", NULL)))
        goto cleanup;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(pool, buffer, inputvol, flags);

    if (newvol != NULL) {
        vshPrintExtra(ctl, _("Vol %s created from input vol %s\n"),
                      virStorageVolGetName(newvol), virStorageVolGetName(inputvol));
    } else {
        vshError(ctl, _("Failed to create vol from %s"), from);
        goto cleanup;
    }

    ret = true;
 cleanup:
    VIR_FREE(buffer);
    if (pool)
        virStoragePoolFree(pool);
    if (inputvol)
        virStorageVolFree(inputvol);
    if (newvol)
        virStorageVolFree(newvol);
    return ret;
}

static xmlChar *
virshMakeCloneXML(const char *origxml, const char *newname)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlChar *newxml = NULL;
    int size;

    doc = virXMLParseStringCtxt(origxml, _("(volume_definition)"), &ctxt);
    if (!doc)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "/volume/name", ctxt);
    if (obj == NULL || obj->nodesetval == NULL ||
        obj->nodesetval->nodeTab == NULL)
        goto cleanup;

    xmlNodeSetContent(obj->nodesetval->nodeTab[0], (const xmlChar *)newname);
    xmlDocDumpMemory(doc, &newxml, &size);

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return newxml;
}

/*
 * "vol-clone" command
 */
static const vshCmdInfo info_vol_clone[] = {
    {.name = "help",
     .data = N_("clone a volume.")
    },
    {.name = "desc",
     .data = N_("Clone an existing volume within the parent pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_clone[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    {.name = "newname",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("clone name")
    },
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
    },
    {.name = "reflink",
     .type = VSH_OT_BOOL,
     .help = N_("use btrfs COW lightweight copy")
    },
    {.name = NULL}
};

static bool
cmdVolClone(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr origpool = NULL;
    virStorageVolPtr origvol = NULL, newvol = NULL;
    const char *name = NULL;
    char *origxml = NULL;
    xmlChar *newxml = NULL;
    bool ret = false;
    unsigned int flags = 0;

    if (!(origvol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptBool(cmd, "reflink"))
        flags |= VIR_STORAGE_VOL_CREATE_REFLINK;

    origpool = virStoragePoolLookupByVolume(origvol);
    if (!origpool) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        goto cleanup;
    }

    if (vshCommandOptStringReq(ctl, cmd, "newname", &name) < 0)
        goto cleanup;

    origxml = virStorageVolGetXMLDesc(origvol, 0);
    if (!origxml)
        goto cleanup;

    newxml = virshMakeCloneXML(origxml, name);
    if (!newxml) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(origpool, (char *) newxml, origvol, flags);

    if (newvol != NULL) {
        vshPrintExtra(ctl, _("Vol %s cloned from %s\n"),
                      virStorageVolGetName(newvol), virStorageVolGetName(origvol));
    } else {
        vshError(ctl, _("Failed to clone vol from %s"),
                 virStorageVolGetName(origvol));
        goto cleanup;
    }

    ret = true;

 cleanup:
    VIR_FREE(origxml);
    xmlFree(newxml);
    if (origvol)
        virStorageVolFree(origvol);
    if (newvol)
        virStorageVolFree(newvol);
    if (origpool)
        virStoragePoolFree(origpool);
    return ret;
}

/*
 * "vol-upload" command
 */
static const vshCmdInfo info_vol_upload[] = {
    {.name = "help",
     .data = N_("upload file contents to a volume")
    },
    {.name = "desc",
     .data = N_("Upload file contents to a volume")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_upload[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_FILE(N_("file")),
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "offset",
     .type = VSH_OT_INT,
     .help = N_("volume offset to upload to")
    },
    {.name = "length",
     .type = VSH_OT_INT,
     .help = N_("amount of data to upload")
    },
    {.name = "sparse",
     .type = VSH_OT_BOOL,
     .help = N_("preserve sparseness of volume")
    },
    {.name = NULL}
};

static bool
cmdVolUpload(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    virStorageVolPtr vol = NULL;
    bool ret = false;
    int fd = -1;
    virStreamPtr st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;
    virshControlPtr priv = ctl->privData;
    unsigned int flags = 0;
    virshStreamCallbackData cbData;

    if (vshCommandOptULongLong(ctl, cmd, "offset", &offset) < 0)
        return false;

    if (vshCommandOptULongLongWrap(ctl, cmd, "length", &length) < 0)
        return false;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        goto cleanup;

    if ((fd = open(file, O_RDONLY)) < 0) {
        vshError(ctl, _("cannot read %s"), file);
        goto cleanup;
    }

    cbData.ctl = ctl;
    cbData.fd = fd;

    if (vshCommandOptBool(cmd, "sparse"))
        flags |= VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM;

    if (!(st = virStreamNew(priv->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        goto cleanup;
    }

    if (virStorageVolUpload(vol, st, offset, length, flags) < 0) {
        vshError(ctl, _("cannot upload to volume %s"), name);
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM) {
        if (virStreamSparseSendAll(st, virshStreamSource,
                                   virshStreamInData,
                                   virshStreamSourceSkip, &cbData) < 0) {
            vshError(ctl, _("cannot send data to volume %s"), name);
            goto cleanup;
        }
    } else {
        if (virStreamSendAll(st, virshStreamSource, &cbData) < 0) {
            vshError(ctl, _("cannot send data to volume %s"), name);
            goto cleanup;
        }
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        virStreamAbort(st);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %s"), name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    if (vol)
        virStorageVolFree(vol);
    if (st)
        virStreamFree(st);
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/*
 * "vol-download" command
 */
static const vshCmdInfo info_vol_download[] = {
    {.name = "help",
     .data = N_("download volume contents to a file")
    },
    {.name = "desc",
     .data = N_("Download volume contents to a file")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_download[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_FILE(N_("file")),
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "offset",
     .type = VSH_OT_INT,
     .help = N_("volume offset to download from")
    },
    {.name = "length",
     .type = VSH_OT_INT,
     .help = N_("amount of data to download")
    },
    {.name = "sparse",
     .type = VSH_OT_BOOL,
     .help = N_("preserve sparseness of volume")
    },
    {.name = NULL}
};

static bool
cmdVolDownload(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    virStorageVolPtr vol = NULL;
    bool ret = false;
    int fd = -1;
    virStreamPtr st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;
    bool created = false;
    virshControlPtr priv = ctl->privData;
    unsigned int flags = 0;

    if (vshCommandOptULongLong(ctl, cmd, "offset", &offset) < 0)
        return false;

    if (vshCommandOptULongLongWrap(ctl, cmd, "length", &length) < 0)
        return false;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "sparse"))
        flags |= VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM;

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    if (!(st = virStreamNew(priv->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        goto cleanup;
    }

    if (virStorageVolDownload(vol, st, offset, length, flags) < 0) {
        vshError(ctl, _("cannot download from volume %s"), name);
        goto cleanup;
    }

    if (virStreamSparseRecvAll(st, virshStreamSink, virshStreamSkip, &fd) < 0) {
        vshError(ctl, _("cannot receive data from volume %s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        virStreamAbort(st);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %s"), name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (!ret && created)
        unlink(file);
    if (vol)
        virStorageVolFree(vol);
    if (st)
        virStreamFree(st);
    return ret;
}

/*
 * "vol-delete" command
 */
static const vshCmdInfo info_vol_delete[] = {
    {.name = "help",
     .data = N_("delete a vol")
    },
    {.name = "desc",
     .data = N_("Delete a given vol.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_delete[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "delete-snapshots",
     .type = VSH_OT_BOOL,
     .help = N_("delete snapshots associated with volume (must be "
                "supported by storage driver)")
    },
    {.name = NULL}
};

static bool
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    const char *name;
    bool delete_snapshots = vshCommandOptBool(cmd, "delete-snapshots");
    unsigned int flags = 0;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (delete_snapshots)
        flags |= VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS;

    if (virStorageVolDelete(vol, flags) == 0) {
        vshPrintExtra(ctl, _("Vol %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete vol %s"), name);
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}

/*
 * "vol-wipe" command
 */
static const vshCmdInfo info_vol_wipe[] = {
    {.name = "help",
     .data = N_("wipe a vol")
    },
    {.name = "desc",
     .data = N_("Ensure data previously on a volume is not accessible to future reads")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_wipe[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "algorithm",
     .type = VSH_OT_STRING,
     .help = N_("perform selected wiping algorithm")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virStorageVolWipeAlgorithm);
VIR_ENUM_IMPL(virStorageVolWipeAlgorithm, VIR_STORAGE_VOL_WIPE_ALG_LAST,
              "zero", "nnsa", "dod", "bsi", "gutmann", "schneier",
              "pfitzner7", "pfitzner33", "random", "trim");

static bool
cmdVolWipe(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = false;
    const char *name;
    const char *algorithm_str = NULL;
    int algorithm = VIR_STORAGE_VOL_WIPE_ALG_ZERO;
    int funcRet;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "algorithm", &algorithm_str) < 0)
        goto out;

    if (algorithm_str &&
        (algorithm = virStorageVolWipeAlgorithmTypeFromString(algorithm_str)) < 0) {
        vshError(ctl, _("Unsupported algorithm '%s'"), algorithm_str);
        goto out;
    }

    if ((funcRet = virStorageVolWipePattern(vol, algorithm, 0)) < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT &&
            algorithm == VIR_STORAGE_VOL_WIPE_ALG_ZERO)
            funcRet = virStorageVolWipe(vol, 0);
    }

    if (funcRet < 0) {
        vshError(ctl, _("Failed to wipe vol %s"), name);
        goto out;
    }

    vshPrintExtra(ctl, _("Vol %s wiped\n"), name);
    ret = true;
 out:
    virStorageVolFree(vol);
    return ret;
}


VIR_ENUM_DECL(virshStorageVol);
VIR_ENUM_IMPL(virshStorageVol,
              VIR_STORAGE_VOL_LAST,
              N_("file"),
              N_("block"),
              N_("dir"),
              N_("network"),
              N_("netdir"),
              N_("ploop"));

static const char *
virshVolumeTypeToString(int type)
{
    const char *str = virshStorageVolTypeToString(type);
    return str ? _(str) : _("unknown");
}


/*
 * "vol-info" command
 */
static const vshCmdInfo info_vol_info[] = {
    {.name = "help",
     .data = N_("storage vol information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the storage vol.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_info[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "bytes",
     .type = VSH_OT_BOOL,
     .help = N_("sizes are represented in bytes rather than pretty units")
    },
    {.name = "physical",
     .type = VSH_OT_BOOL,
     .help = N_("return the physical size of the volume in allocation field")
    },
    {.name = NULL}
};

static bool
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    bool bytes = vshCommandOptBool(cmd, "bytes");
    bool physical = vshCommandOptBool(cmd, "physical");
    bool ret = true;
    int rc;
    unsigned int flags = 0;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStorageVolGetName(vol));

    if (physical)
        flags |= VIR_STORAGE_VOL_GET_PHYSICAL;

    if (flags)
        rc = virStorageVolGetInfoFlags(vol, &info, flags);
    else
        rc = virStorageVolGetInfo(vol, &info);

    if (rc == 0) {
        double val;
        const char *unit;

        vshPrint(ctl, "%-15s %s\n", _("Type:"),
                 virshVolumeTypeToString(info.type));

        if (bytes) {
            vshPrint(ctl, "%-15s %llu %s\n", _("Capacity:"),
                     info.capacity, _("bytes"));
        } else {
            val = vshPrettyCapacity(info.capacity, &unit);
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);
        }

        if (bytes) {
            if (physical)
                vshPrint(ctl, "%-15s %llu %s\n", _("Physical:"),
                         info.allocation, _("bytes"));
            else
                vshPrint(ctl, "%-15s %llu %s\n", _("Allocation:"),
                         info.allocation, _("bytes"));
         } else {
            val = vshPrettyCapacity(info.allocation, &unit);
            if (physical)
                vshPrint(ctl, "%-15s %2.2lf %s\n", _("Physical:"), val, unit);
            else
                vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);
         }
    } else {
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}

/*
 * "vol-resize" command
 */
static const vshCmdInfo info_vol_resize[] = {
    {.name = "help",
     .data = N_("resize a vol")
    },
    {.name = "desc",
     .data = N_("Resizes a storage volume. This is safe only for storage "
                "volumes not in use by an active guest.\n"
                "See blockresize for live resizing.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_resize[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    {.name = "capacity",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new capacity for the vol, as scaled integer (default bytes)")
    },
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "allocate",
     .type = VSH_OT_BOOL,
     .help = N_("allocate the new capacity, rather than leaving it sparse")
    },
    {.name = "delta",
     .type = VSH_OT_BOOL,
     .help = N_("use capacity as a delta to current size, rather than the new size")
    },
    {.name = "shrink",
     .type = VSH_OT_BOOL,
     .help = N_("allow the resize to shrink the volume")
    },
    {.name = NULL}
};

static bool
cmdVolResize(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    const char *capacityStr = NULL;
    unsigned long long capacity = 0;
    unsigned int flags = 0;
    bool ret = false;
    bool delta = vshCommandOptBool(cmd, "delta");

    if (vshCommandOptBool(cmd, "allocate"))
        flags |= VIR_STORAGE_VOL_RESIZE_ALLOCATE;
    if (vshCommandOptBool(cmd, "shrink"))
        flags |= VIR_STORAGE_VOL_RESIZE_SHRINK;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        goto cleanup;
    virSkipSpaces(&capacityStr);
    if (*capacityStr == '-') {
        /* The API always requires a positive value; but we allow a
         * negative value for convenience.  */
        if (vshCommandOptBool(cmd, "shrink")) {
            capacityStr++;
            delta = true;
        } else {
            vshError(ctl, "%s",
                     _("negative size requires --shrink"));
            goto cleanup;
        }
    }

    if (delta)
        flags |= VIR_STORAGE_VOL_RESIZE_DELTA;

    if (virshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %s"), capacityStr);
        goto cleanup;
    }

    if (virStorageVolResize(vol, capacity, flags) == 0) {
        vshPrintExtra(ctl,
                      delta ? _("Size of volume '%s' successfully changed by %s\n")
                      : _("Size of volume '%s' successfully changed to %s\n"),
                      virStorageVolGetName(vol), capacityStr);
        ret = true;
    } else {
        vshError(ctl,
                 delta ? _("Failed to change size of volume '%s' by %s")
                 : _("Failed to change size of volume '%s' to %s"),
                 virStorageVolGetName(vol), capacityStr);
        ret = false;
    }

 cleanup:
    virStorageVolFree(vol);
    return ret;
}

/*
 * "vol-dumpxml" command
 */
static const vshCmdInfo info_vol_dumpxml[] = {
    {.name = "help",
     .data = N_("vol information in XML")
    },
    {.name = "desc",
     .data = N_("Output the vol information as an XML dump to stdout.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_dumpxml[] = {
    VIRSH_COMMON_OPT_VOLUME_VOL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = NULL}
};

static bool
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    char *dump;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    dump = virStorageVolGetXMLDesc(vol, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}

static int
virshStorageVolSorter(const void *a, const void *b)
{
    virStorageVolPtr *va = (virStorageVolPtr *) a;
    virStorageVolPtr *vb = (virStorageVolPtr *) b;

    if (*va && !*vb)
        return -1;

    if (!*va)
        return *vb != NULL;

    return vshStrcasecmp(virStorageVolGetName(*va),
                      virStorageVolGetName(*vb));
}

struct virshStorageVolList {
    virStorageVolPtr *vols;
    size_t nvols;
};
typedef struct virshStorageVolList *virshStorageVolListPtr;

static void
virshStorageVolListFree(virshStorageVolListPtr list)
{
    size_t i;

    if (list && list->vols) {
        for (i = 0; i < list->nvols; i++) {
            if (list->vols[i])
                virStorageVolFree(list->vols[i]);
        }
        VIR_FREE(list->vols);
    }
    VIR_FREE(list);
}

static virshStorageVolListPtr
virshStorageVolListCollect(vshControl *ctl,
                           virStoragePoolPtr pool,
                           unsigned int flags)
{
    virshStorageVolListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
    char **names = NULL;
    virStorageVolPtr vol = NULL;
    bool success = false;
    size_t deleted = 0;
    int nvols = 0;
    int ret = -1;

    /* try the list with flags support (0.10.2 and later) */
    if ((ret = virStoragePoolListAllVolumes(pool,
                                            &list->vols,
                                            flags)) >= 0) {
        list->nvols = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT)
        goto fallback;

    /* there was an error during the call */
    vshError(ctl, "%s", _("Failed to list volumes"));
    goto cleanup;

 fallback:
    /* fall back to old method (0.10.1 and older) */
    vshResetLibvirtError();

    /* Determine the number of volumes in the pool */
    if ((nvols = virStoragePoolNumOfVolumes(pool)) < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        goto cleanup;
    }

    if (nvols == 0)
        return list;

    /* Retrieve the list of volume names in the pool */
    names = vshCalloc(ctl, nvols, sizeof(*names));
    if ((nvols = virStoragePoolListVolumes(pool, names, nvols)) < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        goto cleanup;
    }

    list->vols = vshMalloc(ctl, sizeof(virStorageVolPtr) * (nvols));
    list->nvols = 0;

    /* get the vols */
    for (i = 0; i < nvols; i++) {
        if (!(vol = virStorageVolLookupByName(pool, names[i])))
            continue;
        list->vols[list->nvols++] = vol;
    }

    /* truncate the list for not found vols */
    deleted = nvols - list->nvols;

 finished:
    /* sort the list */
    if (list->vols && list->nvols)
        qsort(list->vols, list->nvols, sizeof(*list->vols), virshStorageVolSorter);

    if (deleted)
        VIR_SHRINK_N(list->vols, list->nvols, deleted);

    success = true;

 cleanup:
    if (nvols > 0)
        for (i = 0; i < nvols; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        virshStorageVolListFree(list);
        list = NULL;
    }

    return list;
}

/*
 * "vol-list" command
 */
static const vshCmdInfo info_vol_list[] = {
    {.name = "help",
     .data = N_("list vols")
    },
    {.name = "desc",
     .data = N_("Returns list of vols by pool.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_list[] = {
    VIRSH_COMMON_OPT_POOL_FULL,
    {.name = "details",
     .type = VSH_OT_BOOL,
     .help = N_("display extended details for volumes")
    },
    {.name = NULL}
};

static bool
cmdVolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStorageVolInfo volumeInfo;
    virStoragePoolPtr pool;
    const char *unit;
    double val;
    bool details = vshCommandOptBool(cmd, "details");
    size_t i;
    bool ret = false;
    struct volInfoText {
        char *allocation;
        char *capacity;
        char *path;
        char *type;
    };
    struct volInfoText *volInfoTexts = NULL;
    virshStorageVolListPtr list = NULL;
    vshTablePtr table = NULL;

    /* Look up the pool information given to us by the user */
    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (!(list = virshStorageVolListCollect(ctl, pool, 0)))
        goto cleanup;

    if (list->nvols > 0)
        volInfoTexts = vshCalloc(ctl, list->nvols, sizeof(*volInfoTexts));

    /* Collect the rest of the volume information for display */
    for (i = 0; i < list->nvols; i++) {
        /* Retrieve volume info */
        virStorageVolPtr vol = list->vols[i];

        /* Retrieve the volume path */
        if ((volInfoTexts[i].path = virStorageVolGetPath(vol)) == NULL) {
            /* Something went wrong retrieving a volume path, cope with it */
            volInfoTexts[i].path = vshStrdup(ctl, _("unknown"));
        }

        /* If requested, retrieve volume type and sizing information */
        if (details) {
            if (virStorageVolGetInfo(vol, &volumeInfo) != 0) {
                /* Something went wrong retrieving volume info, cope with it */
                volInfoTexts[i].allocation = vshStrdup(ctl, _("unknown"));
                volInfoTexts[i].capacity = vshStrdup(ctl, _("unknown"));
                volInfoTexts[i].type = vshStrdup(ctl, _("unknown"));
            } else {
                /* Convert the returned volume info into output strings */

                /* Volume type */
                volInfoTexts[i].type = vshStrdup(ctl,
                                                 virshVolumeTypeToString(volumeInfo.type));

                val = vshPrettyCapacity(volumeInfo.capacity, &unit);
                if (virAsprintf(&volInfoTexts[i].capacity,
                                "%.2lf %s", val, unit) < 0)
                    goto cleanup;

                val = vshPrettyCapacity(volumeInfo.allocation, &unit);
                if (virAsprintf(&volInfoTexts[i].allocation,
                                "%.2lf %s", val, unit) < 0)
                    goto cleanup;
            }
        }
    }

    /* If the --details option wasn't selected, we output the volume
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        /* The old output format */
        table = vshTableNew(_("Name"), _("Path"), NULL);
        if (!table)
            goto cleanup;

        for (i = 0; i < list->nvols; i++) {
            if (vshTableRowAppend(table,
                                  virStorageVolGetName(list->vols[i]),
                                  volInfoTexts[i].path,
                                  NULL) < 0)
                goto cleanup;
        }

        vshTablePrintToStdout(table, ctl);

        /* Cleanup and return */
        ret = true;
        goto cleanup;
    }

    /* We only get here if the --details option was selected. */

    /* Insert the header into table */
    table = vshTableNew(_("Name"), _("Path"), _("Type"), _("Capacity"), _("Allocation"), NULL);
    if (!table)
        goto cleanup;

    /* Insert the volume info rows into table */
    for (i = 0; i < list->nvols; i++) {
        if (vshTableRowAppend(table,
                              virStorageVolGetName(list->vols[i]),
                              volInfoTexts[i].path,
                              volInfoTexts[i].type,
                              volInfoTexts[i].capacity,
                              volInfoTexts[i].allocation,
                              NULL) < 0)
            goto cleanup;
    }

    vshTablePrintToStdout(table, ctl);

    /* Cleanup and return */
    ret = true;

 cleanup:
    vshTableFree(table);

    /* Safely free the memory allocated in this function */
    if (list && list->nvols) {
        for (i = 0; i < list->nvols; i++) {
            /* Cleanup the memory for one volume info structure per loop */
            VIR_FREE(volInfoTexts[i].path);
            VIR_FREE(volInfoTexts[i].type);
            VIR_FREE(volInfoTexts[i].capacity);
            VIR_FREE(volInfoTexts[i].allocation);
        }
    }

    /* Cleanup remaining memory */
    VIR_FREE(volInfoTexts);
    virStoragePoolFree(pool);
    virshStorageVolListFree(list);

    /* Return the desired value */
    return ret;
}

/*
 * "vol-name" command
 */
static const vshCmdInfo info_vol_name[] = {
    {.name = "help",
     .data = N_("returns the volume name for a given volume key or path")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_name[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("volume key or path")
    },
    {.name = NULL}
};

static bool
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!(vol = virshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                     VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetName(vol));
    virStorageVolFree(vol);
    return true;
}

/*
 * "vol-pool" command
 */
static const vshCmdInfo info_vol_pool[] = {
    {.name = "help",
     .data = N_("returns the storage pool for a given volume key or path")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_pool[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("volume key or path")
    },
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("return the pool uuid rather than pool name")
    },
    {.name = NULL}
};

static bool
cmdVolPool(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char uuid[VIR_UUID_STRING_BUFLEN];

    /* Use the supplied string to locate the volume */
    if (!(vol = virshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                     VIRSH_BYUUID))) {
        return false;
    }

    /* Look up the parent storage pool for the volume */
    pool = virStoragePoolLookupByVolume(vol);
    if (pool == NULL) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        virStorageVolFree(vol);
        return false;
    }

    /* Return the requested details of the parent storage pool */
    if (vshCommandOptBool(cmd, "uuid")) {
        /* Retrieve and return pool UUID string */
        if (virStoragePoolGetUUIDString(pool, &uuid[0]) == 0)
            vshPrint(ctl, "%s\n", uuid);
    } else {
        /* Return the storage pool name */
        vshPrint(ctl, "%s\n", virStoragePoolGetName(pool));
    }

    /* Cleanup */
    virStorageVolFree(vol);
    virStoragePoolFree(pool);
    return true;
}

/*
 * "vol-key" command
 */
static const vshCmdInfo info_vol_key[] = {
    {.name = "help",
     .data = N_("returns the volume key for a given volume name or path")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_key[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("volume name or path")
    },
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = NULL}
};

static bool
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetKey(vol));
    virStorageVolFree(vol);
    return true;
}

/*
 * "vol-path" command
 */
static const vshCmdInfo info_vol_path[] = {
    {.name = "help",
     .data = N_("returns the volume path for a given volume name or key")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_path[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("volume name or key")
    },
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = NULL}
};

static bool
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char * StorageVolPath;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if ((StorageVolPath = virStorageVolGetPath(vol)) == NULL) {
        virStorageVolFree(vol);
        return false;
    }

    vshPrint(ctl, "%s\n", StorageVolPath);
    VIR_FREE(StorageVolPath);
    virStorageVolFree(vol);
    return true;
}

const vshCmdDef storageVolCmds[] = {
    {.name = "vol-clone",
     .handler = cmdVolClone,
     .opts = opts_vol_clone,
     .info = info_vol_clone,
     .flags = 0
    },
    {.name = "vol-create-as",
     .handler = cmdVolCreateAs,
     .opts = opts_vol_create_as,
     .info = info_vol_create_as,
     .flags = 0
    },
    {.name = "vol-create",
     .handler = cmdVolCreate,
     .opts = opts_vol_create,
     .info = info_vol_create,
     .flags = 0
    },
    {.name = "vol-create-from",
     .handler = cmdVolCreateFrom,
     .opts = opts_vol_create_from,
     .info = info_vol_create_from,
     .flags = 0
    },
    {.name = "vol-delete",
     .handler = cmdVolDelete,
     .opts = opts_vol_delete,
     .info = info_vol_delete,
     .flags = 0
    },
    {.name = "vol-download",
     .handler = cmdVolDownload,
     .opts = opts_vol_download,
     .info = info_vol_download,
     .flags = 0
    },
    {.name = "vol-dumpxml",
     .handler = cmdVolDumpXML,
     .opts = opts_vol_dumpxml,
     .info = info_vol_dumpxml,
     .flags = 0
    },
    {.name = "vol-info",
     .handler = cmdVolInfo,
     .opts = opts_vol_info,
     .info = info_vol_info,
     .flags = 0
    },
    {.name = "vol-key",
     .handler = cmdVolKey,
     .opts = opts_vol_key,
     .info = info_vol_key,
     .flags = 0
    },
    {.name = "vol-list",
     .handler = cmdVolList,
     .opts = opts_vol_list,
     .info = info_vol_list,
     .flags = 0
    },
    {.name = "vol-name",
     .handler = cmdVolName,
     .opts = opts_vol_name,
     .info = info_vol_name,
     .flags = 0
    },
    {.name = "vol-path",
     .handler = cmdVolPath,
     .opts = opts_vol_path,
     .info = info_vol_path,
     .flags = 0
    },
    {.name = "vol-pool",
     .handler = cmdVolPool,
     .opts = opts_vol_pool,
     .info = info_vol_pool,
     .flags = 0
    },
    {.name = "vol-resize",
     .handler = cmdVolResize,
     .opts = opts_vol_resize,
     .info = info_vol_resize,
     .flags = 0
    },
    {.name = "vol-upload",
     .handler = cmdVolUpload,
     .opts = opts_vol_upload,
     .info = info_vol_upload,
     .flags = 0
    },
    {.name = "vol-wipe",
     .handler = cmdVolWipe,
     .opts = opts_vol_wipe,
     .info = info_vol_wipe,
     .flags = 0
    },
    {.name = NULL}
};
