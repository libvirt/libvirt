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
#include <libxml/xpath.h>

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virutil.h"
#include "virfile.h"
#include "virsh-pool.h"
#include "virxml.h"
#include "virstring.h"
#include "vsh-table.h"
#include "virenum.h"

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

#define VIRSH_COMMON_OPT_VOL_NAME(_helpstr) \
    {.name = "vol", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = _helpstr, \
     .completer = virshStorageVolNameCompleter, \
    }

#define VIRSH_COMMON_OPT_VOL_KEY(_helpstr) \
    {.name = "vol", \
     .type = VSH_OT_DATA, \
     .flags = VSH_OFLAG_REQ, \
     .help = _helpstr, \
     .completer = virshStorageVolKeyCompleter, \
    }

#define VIRSH_COMMON_OPT_VOL_FULL \
    VIRSH_COMMON_OPT_VOL_NAME(N_("vol name, key or path"))

#define VIRSH_COMMON_OPT_VOL_BY_KEY \
    VIRSH_COMMON_OPT_VOL_KEY(N_("volume key or path"))

virStorageVolPtr
virshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                     const char *optname,
                     const char *pooloptname,
                     const char **name, unsigned int flags)
{
    virStorageVolPtr vol = NULL;
    g_autoptr(virshStoragePool) pool = NULL;
    const char *n = NULL, *p = NULL;
    virshControl *priv = ctl->privData;

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
            vshError(ctl, _("pool '%1$s' is not active"), p);
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
            vshError(ctl, _("failed to get vol '%1$s'"), n);
        else
            vshError(ctl, _("failed to get vol '%1$s', specifying --%2$s might help"),
                     n, pooloptname);
    } else {
        vshResetLibvirtError();
    }

    /* If the pool was specified, then make sure that the returned
     * volume is from the given pool */
    if (pool && vol) {
        g_autoptr(virshStoragePool) volpool = NULL;

        if ((volpool = virStoragePoolLookupByVolume(vol))) {
            if (STRNEQ(virStoragePoolGetName(volpool),
                       virStoragePoolGetName(pool))) {
                vshResetLibvirtError();
                vshError(ctl,
                         _("Requested volume '%1$s' is not in pool '%2$s'"),
                         n, virStoragePoolGetName(pool));
                g_clear_pointer(&vol, virshStorageVolFree);
            }
        }
    }

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
     .completer = virshCompleteEmpty,
     .help = N_("name of the volume")
    },
    {.name = "capacity",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
     .help = N_("size of the vol, as scaled integer (default bytes)")
    },
    {.name = "allocation",
     .type = VSH_OT_STRING,
     .completer = virshCompleteEmpty,
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
    g_autoptr(virshStoragePool) pool = NULL;
    g_autoptr(virshStorageVol) vol = NULL;
    g_autofree char *xml = NULL;
    bool printXML = vshCommandOptBool(cmd, "print-xml");
    const char *name, *capacityStr = NULL, *allocationStr = NULL, *format = NULL;
    const char *snapshotStrVol = NULL, *snapshotStrFormat = NULL;
    unsigned long long capacity, allocation = 0;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    virshControl *priv = ctl->privData;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        return false;

    if (virshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %1$s"), capacityStr);
        return false;
    }

    if (vshCommandOptStringQuiet(ctl, cmd, "allocation", &allocationStr) > 0 &&
        virshVolSize(allocationStr, &allocation) < 0) {
        vshError(ctl, _("Malformed size %1$s"), allocationStr);
        return false;
    }

    if (vshCommandOptStringReq(ctl, cmd, "format", &format) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "backing-vol", &snapshotStrVol) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "backing-vol-format",
                               &snapshotStrFormat) < 0)
        return false;

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
        g_autoptr(virshStorageVol) snapVol = NULL;
        g_autofree char *snapshotStrVolPath = NULL;
        /* Lookup snapshot backing volume.  Try the backing-vol
         *  parameter as a name */
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "%s: Look up backing store volume '%s' as name\n",
                 cmd->def->name, snapshotStrVol);
        snapVol = virStorageVolLookupByName(pool, snapshotStrVol);
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
            vshError(ctl, _("failed to get vol '%1$s'"), snapshotStrVol);
            return false;
        }

        if ((snapshotStrVolPath = virStorageVolGetPath(snapVol)) == NULL) {
            return false;
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
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    xml = virBufferContentAndReset(&buf);

    if (printXML) {
        vshPrint(ctl, "%s", xml);
    } else {
        if (!(vol = virStorageVolCreateXML(pool, xml, flags))) {
            vshError(ctl, _("Failed to create vol %1$s"), name);
            return false;
        }
        vshPrintExtra(ctl, _("Vol %1$s created\n"), name);
    }

    return true;
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
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdVolCreate(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStoragePool) pool = NULL;
    g_autoptr(virshStorageVol) vol = NULL;
    const char *from = NULL;
    unsigned int flags = 0;
    g_autofree char *buffer = NULL;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_STORAGE_VOL_CREATE_VALIDATE;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshSaveLibvirtError();
        return false;
    }

    if (!(vol = virStorageVolCreateXML(pool, buffer, flags))) {
        vshError(ctl, _("Failed to create vol from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Vol %1$s created from %2$s\n"),
                  virStorageVolGetName(vol), from);
    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
    {.name = "inputpool",
     .type = VSH_OT_STRING,
     .completer = virshStoragePoolNameCompleter,
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
    {.name = "validate",
     .type = VSH_OT_BOOL,
     .help = N_("validate the XML against the schema")
    },
    {.name = NULL}
};

static bool
cmdVolCreateFrom(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStoragePool) pool = NULL;
    g_autoptr(virshStorageVol) newvol = NULL;
    g_autoptr(virshStorageVol) inputvol = NULL;
    const char *from = NULL;
    g_autofree char *buffer = NULL;
    unsigned int flags = 0;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptBool(cmd, "reflink"))
        flags |= VIR_STORAGE_VOL_CREATE_REFLINK;

    if (vshCommandOptBool(cmd, "validate"))
        flags |= VIR_STORAGE_VOL_CREATE_VALIDATE;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        return false;

    if (!(inputvol = virshCommandOptVol(ctl, cmd, "vol", "inputpool", NULL)))
        return false;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        return false;
    }

    newvol = virStorageVolCreateXMLFrom(pool, buffer, inputvol, flags);

    if (!newvol) {
        vshError(ctl, _("Failed to create vol from %1$s"), from);
        return false;
    }

    vshPrintExtra(ctl, _("Vol %1$s created from input vol %2$s\n"),
                  virStorageVolGetName(newvol), virStorageVolGetName(inputvol));
    return true;
}

static char *
virshMakeCloneXML(const char *origxml, const char *newname)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    xmlNodePtr node;

    if (!(doc = virXMLParseStringCtxt(origxml, _("(volume_definition)"), &ctxt)))
        return NULL;

    if (!(node = virXPathNode("/volume/name", ctxt)))
        return NULL;

    xmlNodeSetContent(node, (const xmlChar *)newname);

    return virXMLNodeToString(doc, doc->children);
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
    VIRSH_COMMON_OPT_VOL_FULL,
    {.name = "newname",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
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
    {.name = "print-xml",
     .type = VSH_OT_BOOL,
     .help = N_("print XML document rather than clone the volume")
    },
    {.name = NULL}
};

static bool
cmdVolClone(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStoragePool) origpool = NULL;
    g_autoptr(virshStorageVol) origvol = NULL;
    g_autoptr(virshStorageVol) newvol = NULL;
    const char *name = NULL;
    g_autofree char *origxml = NULL;
    g_autofree char *newxml = NULL;
    unsigned int flags = 0;

    if (!(origvol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptBool(cmd, "reflink"))
        flags |= VIR_STORAGE_VOL_CREATE_REFLINK;

    origpool = virStoragePoolLookupByVolume(origvol);
    if (!origpool) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        return false;
    }

    if (vshCommandOptStringReq(ctl, cmd, "newname", &name) < 0)
        return false;

    if (!(origxml = virStorageVolGetXMLDesc(origvol, 0)))
        return false;

    if (!(newxml = virshMakeCloneXML(origxml, name))) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s", newxml);
        return true;
    }

    if (!(newvol = virStorageVolCreateXMLFrom(origpool, newxml, origvol, flags))) {
        vshError(ctl, _("Failed to clone vol from %1$s"),
                 virStorageVolGetName(origvol));
        return false;
    }

    vshPrintExtra(ctl, _("Vol %1$s cloned from %2$s\n"),
                  virStorageVolGetName(newvol), virStorageVolGetName(origvol));
    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
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
    g_autoptr(virshStorageVol) vol = NULL;
    VIR_AUTOCLOSE fd = -1;
    g_autoptr(virshStream) st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;
    virshControl *priv = ctl->privData;
    unsigned int flags = 0;
    virshStreamCallbackData cbData;
    struct stat sb;

    if (vshCommandOptULongLong(ctl, cmd, "offset", &offset) < 0)
        return false;

    if (vshCommandOptULongLongWrap(ctl, cmd, "length", &length) < 0)
        return false;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        return false;

    if ((fd = open(file, O_RDONLY)) < 0) {
        vshError(ctl, _("cannot read %1$s"), file);
        return false;
    }

    if (fstat(fd, &sb) < 0) {
        vshError(ctl, _("unable to stat %1$s"), file);
        return false;
    }

    cbData.ctl = ctl;
    cbData.fd = fd;
    cbData.isBlock = !!S_ISBLK(sb.st_mode);

    if (vshCommandOptBool(cmd, "sparse"))
        flags |= VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM;

    if (!(st = virStreamNew(priv->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        return false;
    }

    if (virStorageVolUpload(vol, st, offset, length, flags) < 0) {
        vshError(ctl, _("cannot upload to volume %1$s"), name);
        return false;
    }

    if (flags & VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM) {
        if (virStreamSparseSendAll(st, virshStreamSource,
                                   virshStreamInData,
                                   virshStreamSourceSkip, &cbData) < 0) {
            vshError(ctl, _("cannot send data to volume %1$s"), name);
            return false;
        }
    } else {
        if (virStreamSendAll(st, virshStreamSource, &cbData) < 0) {
            vshError(ctl, _("cannot send data to volume %1$s"), name);
            return false;
        }
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %1$s"), file);
        virStreamAbort(st);
        return false;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %1$s"), name);
        return false;
    }

    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
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
    g_autoptr(virshStorageVol) vol = NULL;
    bool ret = false;
    VIR_AUTOCLOSE fd = -1;
    g_autoptr(virshStream) st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;
    bool created = false;
    virshControl *priv = ctl->privData;
    virshStreamCallbackData cbData;
    unsigned int flags = 0;
    struct stat sb;

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
            vshError(ctl, _("cannot create %1$s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    if (fstat(fd, &sb) < 0) {
        vshError(ctl, _("unable to stat %1$s"), file);
        goto cleanup;
    }

    cbData.ctl = ctl;
    cbData.fd = fd;
    cbData.isBlock = !!S_ISBLK(sb.st_mode);

    if (!(st = virStreamNew(priv->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        goto cleanup;
    }

    if (virStorageVolDownload(vol, st, offset, length, flags) < 0) {
        vshError(ctl, _("cannot download from volume %1$s"), name);
        goto cleanup;
    }

    if (virStreamSparseRecvAll(st, virshStreamSink, virshStreamSkip, &cbData) < 0) {
        vshError(ctl, _("cannot receive data from volume %1$s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %1$s"), file);
        virStreamAbort(st);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %1$s"), name);
        goto cleanup;
    }

    ret = true;

 cleanup:
    if (!ret && created)
        unlink(file);
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
    VIRSH_COMMON_OPT_VOL_FULL,
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
    g_autoptr(virshStorageVol) vol = NULL;
    bool ret = true;
    const char *name;
    bool delete_snapshots = vshCommandOptBool(cmd, "delete-snapshots");
    unsigned int flags = 0;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (delete_snapshots)
        flags |= VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS;

    if (virStorageVolDelete(vol, flags) == 0) {
        vshPrintExtra(ctl, _("Vol %1$s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete vol %1$s"), name);
        ret = false;
    }

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
    VIRSH_COMMON_OPT_VOL_FULL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "algorithm",
     .type = VSH_OT_STRING,
     .completer = virshStorageVolWipeAlgorithmCompleter,
     .help = N_("perform selected wiping algorithm")
    },
    {.name = NULL}
};

VIR_ENUM_IMPL(virshStorageVolWipeAlgorithm,
              VIR_STORAGE_VOL_WIPE_ALG_LAST,
              "zero", "nnsa", "dod", "bsi", "gutmann", "schneier",
              "pfitzner7", "pfitzner33", "random", "trim");

static bool
cmdVolWipe(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStorageVol) vol = NULL;
    const char *name;
    const char *algorithm_str = NULL;
    int algorithm = VIR_STORAGE_VOL_WIPE_ALG_ZERO;
    int funcRet;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "algorithm", &algorithm_str) < 0)
        return false;

    if (algorithm_str &&
        (algorithm = virshStorageVolWipeAlgorithmTypeFromString(algorithm_str)) < 0) {
        vshError(ctl, _("Unsupported algorithm '%1$s'"), algorithm_str);
        return false;
    }

    if ((funcRet = virStorageVolWipePattern(vol, algorithm, 0)) < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT &&
            algorithm == VIR_STORAGE_VOL_WIPE_ALG_ZERO)
            funcRet = virStorageVolWipe(vol, 0);
    }

    if (funcRet < 0) {
        vshError(ctl, _("Failed to wipe vol %1$s"), name);
        return false;
    }

    vshPrintExtra(ctl, _("Vol %1$s wiped\n"), name);
    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
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
    g_autoptr(virshStorageVol) vol = NULL;
    bool bytes = vshCommandOptBool(cmd, "bytes");
    bool physical = vshCommandOptBool(cmd, "physical");
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

    if (rc < 0) {
        return false;
    }

    vshPrint(ctl, "%-15s %s\n", _("Type:"),
             virshVolumeTypeToString(info.type));

    if (bytes) {
        vshPrint(ctl, "%-15s %llu %s\n", _("Capacity:"), info.capacity, _("bytes"));

        if (physical)
            vshPrint(ctl, "%-15s %llu %s\n", _("Physical:"), info.allocation, _("bytes"));
        else
            vshPrint(ctl, "%-15s %llu %s\n", _("Allocation:"), info.allocation, _("bytes"));
    } else {
        const char *unit;
        double val = vshPrettyCapacity(info.capacity, &unit);

        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);
        val = vshPrettyCapacity(info.allocation, &unit);

        if (physical)
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Physical:"), val, unit);
        else
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);
    }

    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
    {.name = "capacity",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .completer = virshCompleteEmpty,
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
    g_autoptr(virshStorageVol) vol = NULL;
    const char *capacityStr = NULL;
    unsigned long long capacity = 0;
    unsigned int flags = 0;
    bool delta = vshCommandOptBool(cmd, "delta");

    if (vshCommandOptBool(cmd, "allocate"))
        flags |= VIR_STORAGE_VOL_RESIZE_ALLOCATE;
    if (vshCommandOptBool(cmd, "shrink"))
        flags |= VIR_STORAGE_VOL_RESIZE_SHRINK;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        return false;
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
            return false;
        }
    }

    if (delta)
        flags |= VIR_STORAGE_VOL_RESIZE_DELTA;

    if (virshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %1$s"), capacityStr);
        return false;
    }

    if (virStorageVolResize(vol, capacity, flags) < 0) {
        vshError(ctl,
                 delta ? _("Failed to change size of volume '%1$s' by %2$s")
                 : _("Failed to change size of volume '%1$s' to %2$s"),
                 virStorageVolGetName(vol), capacityStr);
        return false;
    }

    vshPrintExtra(ctl,
                  delta ? _("Size of volume '%1$s' successfully changed by %2$s\n")
                  : _("Size of volume '%1$s' successfully changed to %2$s\n"),
                  virStorageVolGetName(vol), capacityStr);
    return true;
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
    VIRSH_COMMON_OPT_VOL_FULL,
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = "xpath",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_REQ_OPT,
     .completer = virshCompleteEmpty,
     .help = N_("xpath expression to filter the XML document")
    },
    {.name = "wrap",
     .type = VSH_OT_BOOL,
     .help = N_("wrap xpath results in an common root element"),
    },
    {.name = NULL}
};

static bool
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStorageVol) vol = NULL;
    bool wrap = vshCommandOptBool(cmd, "wrap");
    const char *xpath = NULL;
    g_autofree char *xml = NULL;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptStringQuiet(ctl, cmd, "xpath", &xpath) < 0)
        return false;

    if (!(xml = virStorageVolGetXMLDesc(vol, 0)))
        return false;

    return virshDumpXML(ctl, xml, "volume", xpath, wrap);
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

static void
virshStorageVolListFree(struct virshStorageVolList *list)
{
    size_t i;

    if (list && list->vols) {
        for (i = 0; i < list->nvols; i++) {
            virshStorageVolFree(list->vols[i]);
        }
        g_free(list->vols);
    }
    g_free(list);
}

static struct virshStorageVolList *
virshStorageVolListCollect(vshControl *ctl,
                           virStoragePoolPtr pool,
                           unsigned int flags)
{
    struct virshStorageVolList *list = g_new0(struct virshStorageVolList, 1);
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
    names = g_new0(char *, nvols);
    if ((nvols = virStoragePoolListVolumes(pool, names, nvols)) < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        goto cleanup;
    }

    list->vols = g_new0(virStorageVolPtr, nvols);
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
        g_clear_pointer(&list, virshStorageVolListFree);
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
cmdVolList(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    virStorageVolInfo volumeInfo;
    g_autoptr(virshStoragePool) pool = NULL;
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
    struct virshStorageVolList *list = NULL;
    g_autoptr(vshTable) table = NULL;

    /* Look up the pool information given to us by the user */
    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (!(list = virshStorageVolListCollect(ctl, pool, 0)))
        goto cleanup;

    if (list->nvols > 0)
        volInfoTexts = g_new0(struct volInfoText, list->nvols);

    /* Collect the rest of the volume information for display */
    for (i = 0; i < list->nvols; i++) {
        /* Retrieve volume info */
        virStorageVolPtr vol = list->vols[i];

        /* Retrieve the volume path */
        if ((volInfoTexts[i].path = virStorageVolGetPath(vol)) == NULL) {
            /* Something went wrong retrieving a volume path, cope with it */
            volInfoTexts[i].path = g_strdup(_("unknown"));
        }

        /* If requested, retrieve volume type and sizing information */
        if (details) {
            if (virStorageVolGetInfo(vol, &volumeInfo) != 0) {
                /* Something went wrong retrieving volume info, cope with it */
                volInfoTexts[i].allocation = g_strdup(_("unknown"));
                volInfoTexts[i].capacity = g_strdup(_("unknown"));
                volInfoTexts[i].type = g_strdup(_("unknown"));
            } else {
                /* Convert the returned volume info into output strings */

                /* Volume type */
                volInfoTexts[i].type = g_strdup(virshVolumeTypeToString(volumeInfo.type));

                val = vshPrettyCapacity(volumeInfo.capacity, &unit);
                volInfoTexts[i].capacity = g_strdup_printf("%.2lf %s", val, unit);

                val = vshPrettyCapacity(volumeInfo.allocation, &unit);
                volInfoTexts[i].allocation = g_strdup_printf("%.2lf %s", val,
                                                             unit);
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
    VIRSH_COMMON_OPT_VOL_BY_KEY,
    {.name = NULL}
};

static bool
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStorageVol) vol = NULL;

    if (!(vol = virshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                     VIRSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetName(vol));
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
    VIRSH_COMMON_OPT_VOL_BY_KEY,
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("return the pool uuid rather than pool name")
    },
    {.name = NULL}
};

static bool
cmdVolPool(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStoragePool) pool = NULL;
    g_autoptr(virshStorageVol) vol = NULL;
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
    VIRSH_COMMON_OPT_VOL_NAME(N_("volume name or path")),
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = NULL}
};

static bool
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStorageVol) vol = NULL;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetKey(vol));
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
    VIRSH_COMMON_OPT_VOL_NAME(N_("volume name or key")),
    VIRSH_COMMON_OPT_POOL_OPTIONAL,
    {.name = NULL}
};

static bool
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshStorageVol) vol = NULL;
    g_autofree char *StorageVolPath = NULL;

    if (!(vol = virshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if ((StorageVolPath = virStorageVolGetPath(vol)) == NULL) {
        return false;
    }

    vshPrint(ctl, "%s\n", StorageVolPath);
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
