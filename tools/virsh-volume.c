/*
 * virsh-volume.c: Commands to manage storage volume
 *
 * Copyright (C) 2005, 2007-2014 Red Hat, Inc.
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
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>
#include "virsh-volume.h"

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

virStorageVolPtr
vshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                   const char *optname,
                   const char *pooloptname,
                   const char **name, unsigned int flags)
{
    virStorageVolPtr vol = NULL;
    virStoragePoolPtr pool = NULL;
    const char *n = NULL, *p = NULL;
    virCheckFlags(VSH_BYUUID | VSH_BYNAME, NULL);

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    if (pooloptname != NULL &&
        vshCommandOptStringReq(ctl, cmd, pooloptname, &p) < 0)
        return NULL;

    if (p) {
        if (!(pool = vshCommandOptPoolBy(ctl, cmd, pooloptname, name, flags)))
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
    if (pool && (flags & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol name\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    /* try it by key */
    if (!vol && (flags & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(ctl->conn, n);
    }
    /* try it by path */
    if (!vol && (flags & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol path\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByPath(ctl->conn, n);
    }

    if (!vol) {
        if (pool || !pooloptname)
            vshError(ctl, _("failed to get vol '%s'"), n);
        else
            vshError(ctl, _("failed to get vol '%s', specifying --%s "
                            "might help"), n, pooloptname);
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
    {.name = "pool",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("pool name")
    },
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
    {.name = NULL}
};

static int
vshVolSize(const char *data, unsigned long long *val)
{
    char *end;
    if (virStrToLong_ull(data, &end, 10, val) < 0)
        return -1;
    return virScaleInteger(val, end, 1, ULLONG_MAX);
}

static bool
cmdVolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char *xml;
    const char *name, *capacityStr = NULL, *allocationStr = NULL, *format = NULL;
    const char *snapshotStrVol = NULL, *snapshotStrFormat = NULL;
    unsigned long long capacity, allocation = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned long flags = 0;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        goto cleanup;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        goto cleanup;

    if (vshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %s"), capacityStr);
        goto cleanup;
    }

    if (vshCommandOptString(cmd, "allocation", &allocationStr) > 0 &&
        vshVolSize(allocationStr, &allocation) < 0) {
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
            snapVol = virStorageVolLookupByKey(ctl->conn, snapshotStrVol);
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
            snapVol = virStorageVolLookupByPath(ctl->conn, snapshotStrVol);
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
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }
    xml = virBufferContentAndReset(&buf);
    vol = virStorageVolCreateXML(pool, xml, flags);
    VIR_FREE(xml);
    virStoragePoolFree(pool);

    if (vol != NULL) {
        vshPrint(ctl, _("Vol %s created\n"), name);
        virStorageVolFree(vol);
        return true;
    } else {
        vshError(ctl, _("Failed to create vol %s"), name);
        return false;
    }

 cleanup:
    virBufferFreeAndReset(&buf);
    virStoragePoolFree(pool);
    return false;
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
    {.name = "pool",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("pool name")
    },
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML vol description")
    },
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
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        goto cleanup;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshSaveLibvirtError();
        goto cleanup;
    }

    if ((vol = virStorageVolCreateXML(pool, buffer, flags))) {
        vshPrint(ctl, _("Vol %s created from %s\n"),
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
    {.name = "pool",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("pool name or uuid")
    },
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file containing an XML vol description")
    },
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("input vol name or key")
    },
    {.name = "inputpool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid of the input volume's pool")
    },
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
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

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

    if (vshCommandOptStringReq(ctl, cmd, "file", &from) < 0)
        goto cleanup;

    if (!(inputvol = vshCommandOptVol(ctl, cmd, "vol", "inputpool", NULL)))
        goto cleanup;

    if (virFileReadAll(from, VSH_MAX_XML_FILE, &buffer) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(pool, buffer, inputvol, flags);

    if (newvol != NULL) {
        vshPrint(ctl, _("Vol %s created from input vol %s\n"),
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
vshMakeCloneXML(const char *origxml, const char *newname)
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
     .data = N_("Clone an existing volume.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_clone[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("orig vol name or key")
    },
    {.name = "newname",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("clone name")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = "prealloc-metadata",
     .type = VSH_OT_BOOL,
     .help = N_("preallocate metadata (for qcow2 instead of full allocation)")
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

    if (!(origvol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "prealloc-metadata"))
        flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;

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

    newxml = vshMakeCloneXML(origxml, name);
    if (!newxml) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(origpool, (char *) newxml, origvol, flags);

    if (newvol != NULL) {
        vshPrint(ctl, _("Vol %s cloned from %s\n"),
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = "offset",
     .type = VSH_OT_INT,
     .help = N_("volume offset to upload to")
    },
    {.name = "length",
     .type = VSH_OT_INT,
     .help = N_("amount of data to upload")
    },
    {.name = NULL}
};

static int
cmdVolUploadSource(virStreamPtr st ATTRIBUTE_UNUSED,
                   char *bytes, size_t nbytes, void *opaque)
{
    int *fd = opaque;

    return saferead(*fd, bytes, nbytes);
}

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

    if (vshCommandOptULongLong(cmd, "offset", &offset) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (vshCommandOptULongLong(cmd, "length", &length) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        goto cleanup;

    if ((fd = open(file, O_RDONLY)) < 0) {
        vshError(ctl, _("cannot read %s"), file);
        goto cleanup;
    }

    if (!(st = virStreamNew(ctl->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        goto cleanup;
    }

    if (virStorageVolUpload(vol, st, offset, length, 0) < 0) {
        vshError(ctl, _("cannot upload to volume %s"), name);
        goto cleanup;
    }

    if (virStreamSendAll(st, cmdVolUploadSource, &fd) < 0) {
        vshError(ctl, _("cannot send data to volume %s"), name);
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "file",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("file")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = "offset",
     .type = VSH_OT_INT,
     .help = N_("volume offset to download from")
    },
    {.name = "length",
     .type = VSH_OT_INT,
     .help = N_("amount of data to download")
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

    if (vshCommandOptULongLong(cmd, "offset", &offset) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (vshCommandOptULongLong(cmd, "length", &length) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "file", &file) < 0)
        goto cleanup;

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    if (!(st = virStreamNew(ctl->conn, 0))) {
        vshError(ctl, _("cannot create a new stream"));
        goto cleanup;
    }

    if (virStorageVolDownload(vol, st, offset, length, 0) < 0) {
        vshError(ctl, _("cannot download from volume %s"), name);
        goto cleanup;
    }

    if (virStreamRecvAll(st, vshStreamSink, &fd) < 0) {
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = NULL}
};

static bool
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    const char *name;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (virStorageVolDelete(vol, 0) == 0) {
        vshPrint(ctl, _("Vol %s deleted\n"), name);
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = "algorithm",
     .type = VSH_OT_STRING,
     .help = N_("perform selected wiping algorithm")
    },
    {.name = NULL}
};

VIR_ENUM_DECL(virStorageVolWipeAlgorithm)
VIR_ENUM_IMPL(virStorageVolWipeAlgorithm, VIR_STORAGE_VOL_WIPE_ALG_LAST,
              "zero", "nnsa", "dod", "bsi", "gutmann", "schneier",
              "pfitzner7", "pfitzner33", "random");

static bool
cmdVolWipe(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = false;
    const char *name;
    const char *algorithm_str = NULL;
    int algorithm = VIR_STORAGE_VOL_WIPE_ALG_ZERO;
    int funcRet;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

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

    vshPrint(ctl, _("Vol %s wiped\n"), name);
    ret = true;
 out:
    virStorageVolFree(vol);
    return ret;
}


VIR_ENUM_DECL(vshStorageVol)
VIR_ENUM_IMPL(vshStorageVol,
              VIR_STORAGE_VOL_LAST,
              N_("file"),
              N_("block"),
              N_("dir"),
              N_("network"),
              N_("netdir"))

static const char *
vshVolumeTypeToString(int type)
{
    const char *str = vshStorageVolTypeToString(type);
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = NULL}
};

static bool
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    bool ret = true;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStorageVolGetName(vol));

    if (virStorageVolGetInfo(vol, &info) == 0) {
        double val;
        const char *unit;

        vshPrint(ctl, "%-15s %s\n", _("Type:"),
                 vshVolumeTypeToString(info.type));

        val = vshPrettyCapacity(info.capacity, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

        val = vshPrettyCapacity(info.allocation, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);
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
     .data = N_("Resizes a storage volume.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_vol_resize[] = {
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "capacity",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("new capacity for the vol, as scaled integer (default bytes)")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
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
    bool delta = false;

    if (vshCommandOptBool(cmd, "allocate"))
        flags |= VIR_STORAGE_VOL_RESIZE_ALLOCATE;
    if (vshCommandOptBool(cmd, "delta")) {
        delta = true;
        flags |= VIR_STORAGE_VOL_RESIZE_DELTA;
    }
    if (vshCommandOptBool(cmd, "shrink"))
        flags |= VIR_STORAGE_VOL_RESIZE_SHRINK;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "capacity", &capacityStr) < 0)
        goto cleanup;
    virSkipSpaces(&capacityStr);
    if (*capacityStr == '-') {
        /* The API always requires a positive value; but we allow a
         * negative value for convenience.  */
        if (delta && vshCommandOptBool(cmd, "shrink")){
            capacityStr++;
        } else {
            vshError(ctl, "%s",
                     _("negative size requires --delta and --shrink"));
            goto cleanup;
        }
    }
    if (vshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %s"), capacityStr);
        goto cleanup;
    }

    if (virStorageVolResize(vol, capacity, flags) == 0) {
        vshPrint(ctl,
                 delta ? _("Size of volume '%s' successfully changed by %s\n")
                 : _("Size of volume '%s' successfully changed to %s\n"),
                 virStorageVolGetName(vol), capacityStr);
        ret = true;
    } else {
        vshError(ctl,
                 delta ? _("Failed to change size of volume '%s' by %s\n")
                 : _("Failed to change size of volume '%s' to %s\n"),
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
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("vol name, key or path")
    },
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = NULL}
};

static bool
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    char *dump;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
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
vshStorageVolSorter(const void *a, const void *b)
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

struct vshStorageVolList {
    virStorageVolPtr *vols;
    size_t nvols;
};
typedef struct vshStorageVolList *vshStorageVolListPtr;

static void
vshStorageVolListFree(vshStorageVolListPtr list)
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

static vshStorageVolListPtr
vshStorageVolListCollect(vshControl *ctl,
                         virStoragePoolPtr pool,
                         unsigned int flags)
{
    vshStorageVolListPtr list = vshMalloc(ctl, sizeof(*list));
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

    if (nvols == 0) {
        success = true;
        return list;
    }

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
        qsort(list->vols, list->nvols, sizeof(*list->vols), vshStorageVolSorter);

    if (deleted)
        VIR_SHRINK_N(list->vols, list->nvols, deleted);

    success = true;

 cleanup:
    if (nvols > 0)
        for (i = 0; i < nvols; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);

    if (!success) {
        vshStorageVolListFree(list);
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
    {.name = "pool",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("pool name or uuid")
    },
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
    char *outputStr = NULL;
    const char *unit;
    double val;
    bool details = vshCommandOptBool(cmd, "details");
    size_t i;
    bool ret = false;
    int stringLength = 0;
    size_t allocStrLength = 0, capStrLength = 0;
    size_t nameStrLength = 0, pathStrLength = 0;
    size_t typeStrLength = 0;
    struct volInfoText {
        char *allocation;
        char *capacity;
        char *path;
        char *type;
    };
    struct volInfoText *volInfoTexts = NULL;
    vshStorageVolListPtr list = NULL;

    /* Look up the pool information given to us by the user */
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    if (!(list = vshStorageVolListCollect(ctl, pool, 0)))
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
                                                 vshVolumeTypeToString(volumeInfo.type));

                val = vshPrettyCapacity(volumeInfo.capacity, &unit);
                if (virAsprintf(&volInfoTexts[i].capacity,
                                "%.2lf %s", val, unit) < 0)
                    goto cleanup;

                val = vshPrettyCapacity(volumeInfo.allocation, &unit);
                if (virAsprintf(&volInfoTexts[i].allocation,
                                "%.2lf %s", val, unit) < 0)
                    goto cleanup;
            }

            /* Remember the largest length for each output string.
             * This lets us displaying header and volume information rows
             * using a single, properly sized, printf style output string.
             */

            /* Keep the length of name string if longest so far */
            stringLength = strlen(virStorageVolGetName(list->vols[i]));
            if (stringLength > nameStrLength)
                nameStrLength = stringLength;

            /* Keep the length of path string if longest so far */
            stringLength = strlen(volInfoTexts[i].path);
            if (stringLength > pathStrLength)
                pathStrLength = stringLength;

            /* Keep the length of type string if longest so far */
            stringLength = strlen(volInfoTexts[i].type);
            if (stringLength > typeStrLength)
                typeStrLength = stringLength;

            /* Keep the length of capacity string if longest so far */
            stringLength = strlen(volInfoTexts[i].capacity);
            if (stringLength > capStrLength)
                capStrLength = stringLength;

            /* Keep the length of allocation string if longest so far */
            stringLength = strlen(volInfoTexts[i].allocation);
            if (stringLength > allocStrLength)
                allocStrLength = stringLength;
        }
    }

    /* If the --details option wasn't selected, we output the volume
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        /* The old output format */
        vshPrintExtra(ctl, " %-20s %-40s\n", _("Name"), _("Path"));
        vshPrintExtra(ctl, "---------------------------------------"
                           "---------------------------------------\n");
        for (i = 0; i < list->nvols; i++) {
            vshPrint(ctl, " %-20s %-40s\n", virStorageVolGetName(list->vols[i]),
                     volInfoTexts[i].path);
        }

        /* Cleanup and return */
        ret = true;
        goto cleanup;
    }

    /* We only get here if the --details option was selected. */

    /* Use the length of name header string if it's longest */
    stringLength = strlen(_("Name"));
    if (stringLength > nameStrLength)
        nameStrLength = stringLength;

    /* Use the length of path header string if it's longest */
    stringLength = strlen(_("Path"));
    if (stringLength > pathStrLength)
        pathStrLength = stringLength;

    /* Use the length of type header string if it's longest */
    stringLength = strlen(_("Type"));
    if (stringLength > typeStrLength)
        typeStrLength = stringLength;

    /* Use the length of capacity header string if it's longest */
    stringLength = strlen(_("Capacity"));
    if (stringLength > capStrLength)
        capStrLength = stringLength;

    /* Use the length of allocation header string if it's longest */
    stringLength = strlen(_("Allocation"));
    if (stringLength > allocStrLength)
        allocStrLength = stringLength;

    /* Display the string lengths for debugging */
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest name string = %zu chars\n", nameStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest path string = %zu chars\n", pathStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest type string = %zu chars\n", typeStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest capacity string = %zu chars\n", capStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest allocation string = %zu chars\n", allocStrLength);

    if (virAsprintf(&outputStr,
                    " %%-%lus  %%-%lus  %%-%lus  %%%lus  %%%lus\n",
                    (unsigned long) nameStrLength,
                    (unsigned long) pathStrLength,
                    (unsigned long) typeStrLength,
                    (unsigned long) capStrLength,
                    (unsigned long) allocStrLength) < 0)
        goto cleanup;

    /* Display the header */
    vshPrint(ctl, outputStr, _("Name"), _("Path"), _("Type"),
             ("Capacity"), _("Allocation"));
    for (i = nameStrLength + pathStrLength + typeStrLength
                           + capStrLength + allocStrLength
                           + 10; i > 0; i--)
        vshPrintExtra(ctl, "-");
    vshPrintExtra(ctl, "\n");

    /* Display the volume info rows */
    for (i = 0; i < list->nvols; i++) {
        vshPrint(ctl, outputStr,
                 virStorageVolGetName(list->vols[i]),
                 volInfoTexts[i].path,
                 volInfoTexts[i].type,
                 volInfoTexts[i].capacity,
                 volInfoTexts[i].allocation);
    }

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
    VIR_FREE(outputStr);
    VIR_FREE(volInfoTexts);
    virStoragePoolFree(pool);
    vshStorageVolListFree(list);

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

    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                   VSH_BYUUID)))
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
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("return the pool uuid rather than pool name")
    },
    {.name = "vol",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("volume key or path")
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
    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                   VSH_BYUUID))) {
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
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = NULL}
};

static bool
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
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
    {.name = "pool",
     .type = VSH_OT_STRING,
     .help = N_("pool name or uuid")
    },
    {.name = NULL}
};

static bool
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char * StorageVolPath;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL))) {
        return false;
    }

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
