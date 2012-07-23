/*
 * virsh-volume.c: Commands to manage storage volume
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

/* default is lookup by Name and UUID */
#define vshCommandOptVol(_ctl, _cmd, _optname, _pooloptname, _name)   \
    vshCommandOptVolBy(_ctl, _cmd, _optname, _pooloptname, _name,     \
                           VSH_BYUUID|VSH_BYNAME)

static virStorageVolPtr
vshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                   const char *optname,
                   const char *pooloptname,
                   const char **name, int flag)
{
    virStorageVolPtr vol = NULL;
    virStoragePoolPtr pool = NULL;
    const char *n = NULL, *p = NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    if (pooloptname != NULL && vshCommandOptString(cmd, pooloptname, &p) < 0) {
        vshError(ctl, "%s", _("missing option"));
        return NULL;
    }

    if (p)
        pool = vshCommandOptPoolBy(ctl, cmd, pooloptname, name, flag);

    vshDebug(ctl, VSH_ERR_DEBUG, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by name */
    if (pool && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol name\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    /* try it by key */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(ctl->conn, n);
    }
    /* try it by path */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol path\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByPath(ctl->conn, n);
    }

    if (!vol) {
        if (pool)
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
    {"help", N_("create a volume from a set of args")},
    {"desc", N_("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_as[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the volume")},
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("size of the vol, as scaled integer (default bytes)")},
    {"allocation", VSH_OT_STRING, 0,
     N_("initial allocation size, as scaled integer (default bytes)")},
    {"format", VSH_OT_STRING, 0,
     N_("file format type raw,bochs,qcow,qcow2,qed,vmdk")},
    {"backing-vol", VSH_OT_STRING, 0,
     N_("the backing volume if taking a snapshot")},
    {"backing-vol-format", VSH_OT_STRING, 0,
     N_("format of backing volume if taking a snapshot")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                     VSH_BYNAME)))
        return false;

    if (vshCommandOptString(cmd, "name", &name) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "capacity", &capacityStr) <= 0)
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

    if (vshCommandOptString(cmd, "format", &format) < 0 ||
        vshCommandOptString(cmd, "backing-vol", &snapshotStrVol) < 0 ||
        vshCommandOptString(cmd, "backing-vol-format",
                            &snapshotStrFormat) < 0) {
        vshError(ctl, "%s", _("missing argument"));
        goto cleanup;
    }


    virBufferAddLit(&buf, "<volume>\n");
    virBufferAsprintf(&buf, "  <name>%s</name>\n", name);
    virBufferAsprintf(&buf, "  <capacity>%llu</capacity>\n", capacity);
    if (allocationStr)
        virBufferAsprintf(&buf, "  <allocation>%llu</allocation>\n", allocation);

    if (format) {
        virBufferAddLit(&buf, "  <target>\n");
        virBufferAsprintf(&buf, "    <format type='%s'/>\n",format);
        virBufferAddLit(&buf, "  </target>\n");
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
        virBufferAddLit(&buf, "  <backingStore>\n");
        virBufferAsprintf(&buf, "    <path>%s</path>\n",snapshotStrVolPath);
        if (snapshotStrFormat)
            virBufferAsprintf(&buf, "    <format type='%s'/>\n",snapshotStrFormat);
        virBufferAddLit(&buf, "  </backingStore>\n");

        /* Cleanup snapshot allocations */
        VIR_FREE(snapshotStrVolPath);
        virStorageVolFree(snapVol);
    }

    virBufferAddLit(&buf, "</volume>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }
    xml = virBufferContentAndReset(&buf);
    vol = virStorageVolCreateXML(pool, xml, 0);
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
    {"help", N_("create a vol from an XML file")},
    {"desc", N_("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML vol description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYNAME)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virStoragePoolFree(pool);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virStoragePoolFree(pool);
        return false;
    }

    vol = virStorageVolCreateXML(pool, buffer, 0);
    VIR_FREE(buffer);
    virStoragePoolFree(pool);

    if (vol != NULL) {
        vshPrint(ctl, _("Vol %s created from %s\n"),
                 virStorageVolGetName(vol), from);
        virStorageVolFree(vol);
    } else {
        vshError(ctl, _("Failed to create vol from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "vol-create-from" command
 */
static const vshCmdInfo info_vol_create_from[] = {
    {"help", N_("create a vol, using another volume as input")},
    {"desc", N_("Create a vol from an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_from[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML vol description")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("input vol name or key")},
    {"inputpool", VSH_OT_STRING, 0, N_("pool name or uuid of the input volume's pool")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolCreateFrom(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr newvol = NULL, inputvol = NULL;
    const char *from = NULL;
    bool ret = false;
    char *buffer = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        goto cleanup;
    }

    if (!(inputvol = vshCommandOptVol(ctl, cmd, "vol", "inputpool", NULL)))
        goto cleanup;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(pool, buffer, inputvol, 0);

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
makeCloneXML(const char *origxml, const char *newname)
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
    {"help", N_("clone a volume.")},
    {"desc", N_("Clone an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_clone[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("orig vol name or key")},
    {"newname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("clone name")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(origvol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        goto cleanup;

    origpool = virStoragePoolLookupByVolume(origvol);
    if (!origpool) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        goto cleanup;
    }

    if (vshCommandOptString(cmd, "newname", &name) <= 0)
        goto cleanup;

    origxml = virStorageVolGetXMLDesc(origvol, 0);
    if (!origxml)
        goto cleanup;

    newxml = makeCloneXML(origxml, name);
    if (!newxml) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(origpool, (char *) newxml, origvol, 0);

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
    {"help", N_("upload a file into a volume")},
    {"desc", N_("Upload a file into a volume")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_upload[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"offset", VSH_OT_INT, 0, N_("volume offset to upload to") },
    {"length", VSH_OT_INT, 0, N_("amount of data to upload") },
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

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

    if (vshCommandOptString(cmd, "file", &file) < 0) {
        vshError(ctl, _("file must not be empty"));
        goto cleanup;
    }

    if ((fd = open(file, O_RDONLY)) < 0) {
        vshError(ctl, _("cannot read %s"), file);
        goto cleanup;
    }

    st = virStreamNew(ctl->conn, 0);
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
    {"help", N_("Download a volume to a file")},
    {"desc", N_("Download a volume to a file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_download[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"offset", VSH_OT_INT, 0, N_("volume offset to download from") },
    {"length", VSH_OT_INT, 0, N_("amount of data to download") },
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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

    if (vshCommandOptString(cmd, "file", &file) < 0) {
        vshError(ctl, _("file must not be empty"));
        goto cleanup;
    }

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    st = virStreamNew(ctl->conn, 0);
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
    {"help", N_("delete a vol")},
    {"desc", N_("Delete a given vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_delete[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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
    {"help", N_("wipe a vol")},
    {"desc", N_("Ensure data previously on a volume is not accessible to future reads")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_wipe[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"algorithm", VSH_OT_STRING, 0, N_("perform selected wiping algorithm")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (vshCommandOptString(cmd, "algorithm", &algorithm_str) < 0) {
        vshError(ctl, "%s", _("missing argument"));
        goto out;
    }

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

/*
 * "vol-info" command
 */
static const vshCmdInfo info_vol_info[] = {
    {"help", N_("storage vol information")},
    {"desc", N_("Returns basic information about the storage vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_info[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStorageVolGetName(vol));

    if (virStorageVolGetInfo(vol, &info) == 0) {
        double val;
        const char *unit;
        switch(info.type) {
        case VIR_STORAGE_VOL_FILE:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("file"));
            break;

        case VIR_STORAGE_VOL_BLOCK:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("block"));
            break;

        case VIR_STORAGE_VOL_DIR:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("dir"));
            break;

        case VIR_STORAGE_VOL_NETWORK:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("network"));
            break;

        default:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("unknown"));
        }

        val = prettyCapacity(info.capacity, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

        val = prettyCapacity(info.allocation, &unit);
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
    {"help", N_("resize a vol")},
    {"desc", N_("Resizes a storage volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_resize[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("new capacity for the vol, as scaled integer (default bytes)")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"allocate", VSH_OT_BOOL, 0,
     N_("allocate the new capacity, rather than leaving it sparse")},
    {"delta", VSH_OT_BOOL, 0,
     N_("use capacity as a delta to current size, rather than the new size")},
    {"shrink", VSH_OT_BOOL, 0, N_("allow the resize to shrink the volume")},
    {NULL, 0, 0, NULL}
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

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptString(cmd, "capacity", &capacityStr) <= 0)
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
    {"help", N_("vol information in XML")},
    {"desc", N_("Output the vol information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_dumpxml[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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

/*
 * "vol-list" command
 */
static const vshCmdInfo info_vol_list[] = {
    {"help", N_("list vols")},
    {"desc", N_("Returns list of vols by pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_list[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {"details", VSH_OT_BOOL, 0, N_("display extended details for volumes")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStorageVolInfo volumeInfo;
    virStoragePoolPtr pool;
    char **activeNames = NULL;
    char *outputStr = NULL;
    const char *unit;
    double val;
    bool details = vshCommandOptBool(cmd, "details");
    int numVolumes = 0, i;
    int ret;
    bool functionReturn;
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

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    /* Look up the pool information given to us by the user */
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    /* Determine the number of volumes in the pool */
    numVolumes = virStoragePoolNumOfVolumes(pool);

    if (numVolumes < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        virStoragePoolFree(pool);
        return false;
    }

    /* Retrieve the list of volume names in the pool */
    if (numVolumes > 0) {
        activeNames = vshCalloc(ctl, numVolumes, sizeof(*activeNames));
        if ((numVolumes = virStoragePoolListVolumes(pool, activeNames,
                                                    numVolumes)) < 0) {
            vshError(ctl, "%s", _("Failed to list active vols"));
            VIR_FREE(activeNames);
            virStoragePoolFree(pool);
            return false;
        }

        /* Sort the volume names */
        qsort(&activeNames[0], numVolumes, sizeof(*activeNames), vshNameSorter);

        /* Set aside memory for volume information pointers */
        volInfoTexts = vshCalloc(ctl, numVolumes, sizeof(*volInfoTexts));
    }

    /* Collect the rest of the volume information for display */
    for (i = 0; i < numVolumes; i++) {
        /* Retrieve volume info */
        virStorageVolPtr vol = virStorageVolLookupByName(pool,
                                                         activeNames[i]);

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
                switch (volumeInfo.type) {
                        case VIR_STORAGE_VOL_FILE:
                            volInfoTexts[i].type = vshStrdup(ctl, _("file"));
                            break;
                        case VIR_STORAGE_VOL_BLOCK:
                            volInfoTexts[i].type = vshStrdup(ctl, _("block"));
                            break;
                        case VIR_STORAGE_VOL_DIR:
                            volInfoTexts[i].type = vshStrdup(ctl, _("dir"));
                            break;
                        default:
                            volInfoTexts[i].type = vshStrdup(ctl, _("unknown"));
                }

                /* Create the capacity output string */
                val = prettyCapacity(volumeInfo.capacity, &unit);
                ret = virAsprintf(&volInfoTexts[i].capacity,
                                  "%.2lf %s", val, unit);
                if (ret < 0) {
                    /* An error occurred creating the string, return */
                    goto asprintf_failure;
                }

                /* Create the allocation output string */
                val = prettyCapacity(volumeInfo.allocation, &unit);
                ret = virAsprintf(&volInfoTexts[i].allocation,
                                  "%.2lf %s", val, unit);
                if (ret < 0) {
                    /* An error occurred creating the string, return */
                    goto asprintf_failure;
                }
            }

            /* Remember the largest length for each output string.
             * This lets us displaying header and volume information rows
             * using a single, properly sized, printf style output string.
             */

            /* Keep the length of name string if longest so far */
            stringLength = strlen(activeNames[i]);
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

        /* Cleanup memory allocation */
        virStorageVolFree(vol);
    }

    /* If the --details option wasn't selected, we output the volume
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        /* The old output format */
        vshPrintExtra(ctl, "%-20s %-40s\n", _("Name"), _("Path"));
        vshPrintExtra(ctl, "-----------------------------------------\n");
        for (i = 0; i < numVolumes; i++) {
            vshPrint(ctl, "%-20s %-40s\n", activeNames[i],
                     volInfoTexts[i].path);
        }

        /* Cleanup and return */
        functionReturn = true;
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

    /* Create the output template */
    ret = virAsprintf(&outputStr,
                      "%%-%lus  %%-%lus  %%-%lus  %%%lus  %%%lus\n",
                      (unsigned long) nameStrLength,
                      (unsigned long) pathStrLength,
                      (unsigned long) typeStrLength,
                      (unsigned long) capStrLength,
                      (unsigned long) allocStrLength);
    if (ret < 0) {
        /* An error occurred creating the string, return */
        goto asprintf_failure;
    }

    /* Display the header */
    vshPrint(ctl, outputStr, _("Name"), _("Path"), _("Type"),
             ("Capacity"), _("Allocation"));
    for (i = nameStrLength + pathStrLength + typeStrLength
                           + capStrLength + allocStrLength
                           + 8; i > 0; i--)
        vshPrintExtra(ctl, "-");
    vshPrintExtra(ctl, "\n");

    /* Display the volume info rows */
    for (i = 0; i < numVolumes; i++) {
        vshPrint(ctl, outputStr,
                 activeNames[i],
                 volInfoTexts[i].path,
                 volInfoTexts[i].type,
                 volInfoTexts[i].capacity,
                 volInfoTexts[i].allocation);
    }

    /* Cleanup and return */
    functionReturn = true;
    goto cleanup;

asprintf_failure:

    /* Display an appropriate error message then cleanup and return */
    switch (errno) {
    case ENOMEM:
        /* Couldn't allocate memory */
        vshError(ctl, "%s", _("Out of memory"));
        break;
    default:
        /* Some other error */
        vshError(ctl, _("virAsprintf failed (errno %d)"), errno);
    }
    functionReturn = false;

cleanup:

    /* Safely free the memory allocated in this function */
    for (i = 0; i < numVolumes; i++) {
        /* Cleanup the memory for one volume info structure per loop */
        VIR_FREE(volInfoTexts[i].path);
        VIR_FREE(volInfoTexts[i].type);
        VIR_FREE(volInfoTexts[i].capacity);
        VIR_FREE(volInfoTexts[i].allocation);
        VIR_FREE(activeNames[i]);
    }

    /* Cleanup remaining memory */
    VIR_FREE(outputStr);
    VIR_FREE(volInfoTexts);
    VIR_FREE(activeNames);
    virStoragePoolFree(pool);

    /* Return the desired value */
    return functionReturn;
}

/*
 * "vol-name" command
 */
static const vshCmdInfo info_vol_name[] = {
    {"help", N_("returns the volume name for a given volume key or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_name[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume key or path")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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
    {"help", N_("returns the storage pool for a given volume key or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_pool[] = {
    {"uuid", VSH_OT_BOOL, 0, N_("return the pool uuid rather than pool name")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume key or path")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolPool(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char uuid[VIR_UUID_STRING_BUFLEN];

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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
    {"help", N_("returns the volume key for a given volume name or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_key[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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
    {"help", N_("returns the volume path for a given volume name or key")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_path[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or key")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char * StorageVolPath;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

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

static const vshCmdDef storageVolCmds[] = {
    {"vol-clone", cmdVolClone, opts_vol_clone, info_vol_clone, 0},
    {"vol-create-as", cmdVolCreateAs, opts_vol_create_as,
     info_vol_create_as, 0},
    {"vol-create", cmdVolCreate, opts_vol_create, info_vol_create, 0},
    {"vol-create-from", cmdVolCreateFrom, opts_vol_create_from,
     info_vol_create_from, 0},
    {"vol-delete", cmdVolDelete, opts_vol_delete, info_vol_delete, 0},
    {"vol-download", cmdVolDownload, opts_vol_download, info_vol_download, 0},
    {"vol-dumpxml", cmdVolDumpXML, opts_vol_dumpxml, info_vol_dumpxml, 0},
    {"vol-info", cmdVolInfo, opts_vol_info, info_vol_info, 0},
    {"vol-key", cmdVolKey, opts_vol_key, info_vol_key, 0},
    {"vol-list", cmdVolList, opts_vol_list, info_vol_list, 0},
    {"vol-name", cmdVolName, opts_vol_name, info_vol_name, 0},
    {"vol-path", cmdVolPath, opts_vol_path, info_vol_path, 0},
    {"vol-pool", cmdVolPool, opts_vol_pool, info_vol_pool, 0},
    {"vol-resize", cmdVolResize, opts_vol_resize, info_vol_resize, 0},
    {"vol-upload", cmdVolUpload, opts_vol_upload, info_vol_upload, 0},
    {"vol-wipe", cmdVolWipe, opts_vol_wipe, info_vol_wipe, 0},
    {NULL, NULL, NULL, NULL, 0}
};
