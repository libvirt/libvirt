/*
 * backup_conf.c: domain backup XML processing
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

#include "configmake.h"
#include "internal.h"
#include "virbuffer.h"
#include "domain_conf.h"
#include "virlog.h"
#include "viralloc.h"
#include "backup_conf.h"
#include "storage_source_conf.h"
#include "virerror.h"
#include "virxml.h"
#include "virhash.h"
#include "virenum.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.backup_conf");

VIR_ENUM_DECL(virDomainBackup);
VIR_ENUM_IMPL(virDomainBackup,
              VIR_DOMAIN_BACKUP_TYPE_LAST,
              "default",
              "push",
              "pull");

/* following values appear in the status XML */
VIR_ENUM_DECL(virDomainBackupDiskState);
VIR_ENUM_IMPL(virDomainBackupDiskState,
              VIR_DOMAIN_BACKUP_DISK_STATE_LAST,
              "",
              "running",
              "complete",
              "failed",
              "cancelling",
              "cancelled");

VIR_ENUM_DECL(virDomainBackupDiskBackupMode);
VIR_ENUM_IMPL(virDomainBackupDiskBackupMode,
              VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_LAST,
              "",
              "full",
              "incremental");

void
virDomainBackupDefFree(virDomainBackupDef *def)
{
    size_t i;

    if (!def)
        return;

    g_free(def->incremental);
    g_free(def->errmsg);
    virStorageNetHostDefFree(1, def->server);

    for (i = 0; i < def->ndisks; i++) {
        virDomainBackupDiskDef *disk = def->disks + i;

        g_free(disk->name);
        g_free(disk->incremental);
        g_free(disk->exportname);
        g_free(disk->exportbitmap);
        virObjectUnref(disk->store);
    }

    g_free(def->disks);

    g_free(def->tlsAlias);
    g_free(def->tlsSecretAlias);

    g_free(def);
}


static int
virDomainBackupDiskDefParseXML(xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               virDomainBackupDiskDef *def,
                               bool push,
                               unsigned int flags,
                               virDomainXMLOption *xmlopt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *type = NULL;
    g_autofree char *format = NULL;
    g_autofree char *idx = NULL;
    xmlNodePtr srcNode;
    unsigned int storageSourceParseFlags = 0;
    bool internal = flags & VIR_DOMAIN_BACKUP_PARSE_INTERNAL;

    if (internal)
        storageSourceParseFlags = VIR_DOMAIN_DEF_PARSE_STATUS;

    ctxt->node = node;

    if (!(def->name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing name from disk backup element"));
        return -1;
    }

    if (virXMLPropTristateBool(node, "backup", VIR_XML_PROP_NONE,
                               &def->backup) < 0)
        return -1;

    if (def->backup == VIR_TRISTATE_BOOL_ABSENT)
        def->backup = VIR_TRISTATE_BOOL_YES;

    /* don't parse anything else if backup is disabled */
    if (def->backup == VIR_TRISTATE_BOOL_NO)
        return 0;

    if (!push) {
        def->exportname = virXMLPropString(node, "exportname");
        def->exportbitmap = virXMLPropString(node, "exportbitmap");
    }

    if (virXMLPropEnum(node, "backupmode",
                       virDomainBackupDiskBackupModeTypeFromString,
                       VIR_XML_PROP_NONE, &def->backupmode) < 0)
        return -1;

    def->incremental = virXMLPropString(node, "incremental");

    if (internal) {
        if (virXMLPropEnum(node, "state",
                           virDomainBackupDiskStateTypeFromString,
                           VIR_XML_PROP_REQUIRED, &def->state) < 0)
            return -1;
    }

    type = virXMLPropString(node, "type");
    format = virXPathString("string(./driver/@type)", ctxt);
    if (internal)
        idx = virXMLPropString(node, "index");

    if (!(def->store = virDomainStorageSourceParseBase(type, format, idx)))
          return -1;

    if (def->store->type != VIR_STORAGE_TYPE_FILE &&
        def->store->type != VIR_STORAGE_TYPE_BLOCK) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported disk backup type '%1$s'"), type);
        return -1;
    }

    if (push)
        srcNode = virXPathNode("./target", ctxt);
    else
        srcNode = virXPathNode("./scratch", ctxt);

    if (srcNode &&
        virDomainStorageSourceParse(srcNode, ctxt, def->store,
                                    storageSourceParseFlags, xmlopt) < 0)
        return -1;

    return 0;
}


static void
virDomainBackupDefParsePrivate(virDomainBackupDef *def,
                               xmlXPathContextPtr ctxt,
                               unsigned int flags)
{
    if (!(flags & VIR_DOMAIN_BACKUP_PARSE_INTERNAL))
        return;

    def->tlsSecretAlias = virXPathString("string(./privateData/objects/secret[@type='tlskey']/@alias)", ctxt);
    def->tlsAlias = virXPathString("string(./privateData/objects/TLSx509/@alias)", ctxt);
}


virDomainBackupDef *
virDomainBackupDefParseXML(xmlXPathContextPtr ctxt,
                           virDomainXMLOption *xmlopt,
                           unsigned int flags)
{
    g_autoptr(virDomainBackupDef) def = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    xmlNodePtr node = NULL;
    g_autofree char *mode = NULL;
    bool push;
    size_t i;
    int n;

    def = g_new0(virDomainBackupDef, 1);

    def->type = VIR_DOMAIN_BACKUP_TYPE_PUSH;

    if ((mode = virXMLPropString(ctxt->node, "mode"))) {
        if ((def->type = virDomainBackupTypeFromString(mode)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown backup mode '%1$s'"), mode);
            return NULL;
        }
    }

    push = def->type == VIR_DOMAIN_BACKUP_TYPE_PUSH;

    def->incremental = virXPathString("string(./incremental)", ctxt);

    if ((node = virXPathNode("./server", ctxt))) {
        if (def->type != VIR_DOMAIN_BACKUP_TYPE_PULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("use of <server> requires pull mode backup"));
            return NULL;
        }

        def->server = g_new0(virStorageNetHostDef, 1);

        if (virDomainStorageNetworkParseHost(node, def->server) < 0)
            return NULL;

        if (def->server->transport == VIR_STORAGE_NET_HOST_TRANS_RDMA) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("transport rdma is not supported for <server>"));
            return NULL;
        }

        if (def->server->transport == VIR_STORAGE_NET_HOST_TRANS_UNIX &&
            !g_path_is_absolute(def->server->socket)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("backup socket path '%1$s' must be absolute"),
                           def->server->socket);
            return NULL;
        }

        if (virXMLPropTristateBool(node, "tls", VIR_XML_PROP_NONE,
                                   &def->tls) < 0)
            return NULL;
    }

    if ((n = virXPathNodeSet("./disks/*", ctxt, &nodes)) < 0)
        return NULL;

    def->disks = g_new0(virDomainBackupDiskDef, n);

    def->ndisks = n;
    for (i = 0; i < def->ndisks; i++) {
        if (virDomainBackupDiskDefParseXML(nodes[i], ctxt,
                                           &def->disks[i], push,
                                           flags, xmlopt) < 0)
            return NULL;
    }

    virDomainBackupDefParsePrivate(def, ctxt, flags);

    return g_steal_pointer(&def);
}


virDomainBackupDef *
virDomainBackupDefParseString(const char *xmlStr,
                              virDomainXMLOption *xmlopt,
                              unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);
    bool validate = !(flags & VIR_DOMAIN_BACKUP_PARSE_INTERNAL);

    xml = virXMLParse(NULL, xmlStr, _("(domain_backup)"),
                      "domainbackup", &ctxt, "domainbackup.rng", validate);

    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virDomainBackupDefParseXML(ctxt, xmlopt, flags);
}


static int
virDomainBackupDiskDefFormat(virBuffer *buf,
                             virDomainBackupDiskDef *disk,
                             bool push,
                             bool internal,
                             virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    const char *sourcename = "scratch";
    unsigned int storageSourceFormatFlags = 0;

    if (push)
        sourcename = "target";

    if (internal)
        storageSourceFormatFlags |= VIR_DOMAIN_DEF_FORMAT_STATUS;

    virBufferEscapeString(&attrBuf, " name='%s'", disk->name);
    virBufferAsprintf(&attrBuf, " backup='%s'", virTristateBoolTypeToString(disk->backup));
    if (internal && disk->state != VIR_DOMAIN_BACKUP_DISK_STATE_NONE)
        virBufferAsprintf(&attrBuf, " state='%s'", virDomainBackupDiskStateTypeToString(disk->state));

    if (disk->backup == VIR_TRISTATE_BOOL_YES) {
        virBufferAsprintf(&attrBuf, " type='%s'", virStorageTypeToString(disk->store->type));

        if (disk->backupmode != VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_DEFAULT) {
            virBufferAsprintf(&attrBuf, " backupmode='%s'",
                              virDomainBackupDiskBackupModeTypeToString(disk->backupmode));
        }

        virBufferEscapeString(&attrBuf, " incremental='%s'", disk->incremental);

        virBufferEscapeString(&attrBuf, " exportname='%s'", disk->exportname);
        virBufferEscapeString(&attrBuf, " exportbitmap='%s'", disk->exportbitmap);

        if (disk->store->id != 0)
            virBufferAsprintf(&attrBuf, " index='%u'", disk->store->id);

        if (disk->store->format > 0)
            virBufferEscapeString(&childBuf, "<driver type='%s'/>\n",
                                  virStorageFileFormatTypeToString(disk->store->format));

        if (virDomainDiskSourceFormat(&childBuf, disk->store, sourcename,
                                      0, false, storageSourceFormatFlags,
                                      false, false, xmlopt) < 0)
            return -1;
    }

    virXMLFormatElement(buf, "disk", &attrBuf, &childBuf);
    return 0;
}


static void
virDomainBackupDefFormatPrivate(virBuffer *buf,
                                virDomainBackupDef *def,
                                bool internal)
{
    g_auto(virBuffer) privChildBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) objectsChildBuf = VIR_BUFFER_INIT_CHILD(&privChildBuf);

    if (!internal)
        return;

    virBufferEscapeString(&objectsChildBuf, "<secret type='tlskey' alias='%s'/>\n",
                          def->tlsSecretAlias);
    virBufferEscapeString(&objectsChildBuf, "<TLSx509 alias='%s'/>\n", def->tlsAlias);

    virXMLFormatElement(&privChildBuf, "objects", NULL, &objectsChildBuf);
    virXMLFormatElement(buf, "privateData", NULL, &privChildBuf);
}


int
virDomainBackupDefFormat(virBuffer *buf,
                         virDomainBackupDef *def,
                         bool internal,
                         virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    g_auto(virBuffer) serverAttrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) disksChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);
    size_t i;

    virBufferAsprintf(&attrBuf, " mode='%s'", virDomainBackupTypeToString(def->type));

    virBufferEscapeString(&childBuf, "<incremental>%s</incremental>\n", def->incremental);

    if (def->server) {
        virBufferAsprintf(&serverAttrBuf, " transport='%s'",
                          virStorageNetHostTransportTypeToString(def->server->transport));
        if (def->tls != VIR_TRISTATE_BOOL_ABSENT)
            virBufferAsprintf(&serverAttrBuf, " tls='%s'", virTristateBoolTypeToString(def->tls));
        virBufferEscapeString(&serverAttrBuf, " name='%s'", def->server->name);
        if (def->server->port)
            virBufferAsprintf(&serverAttrBuf, " port='%u'", def->server->port);
        virBufferEscapeString(&serverAttrBuf, " socket='%s'", def->server->socket);
    }

    virXMLFormatElement(&childBuf, "server", &serverAttrBuf, NULL);

    for (i = 0; i < def->ndisks; i++) {
        if (virDomainBackupDiskDefFormat(&disksChildBuf, &def->disks[i],
                                         def->type == VIR_DOMAIN_BACKUP_TYPE_PUSH,
                                         internal, xmlopt) < 0)
            return -1;
    }

    virXMLFormatElement(&childBuf, "disks", NULL, &disksChildBuf);

    virDomainBackupDefFormatPrivate(&childBuf, def, internal);

    virXMLFormatElement(buf, "domainbackup", &attrBuf, &childBuf);

    return 0;
}


static int
virDomainBackupDefAssignStore(virDomainBackupDiskDef *disk,
                              virStorageSource *src,
                              const char *suffix)
{
    if (virStorageSourceIsEmpty(src)) {
        if (disk->store) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' has no media"), disk->name);
            return -1;
        }
    }

    if (!disk->store ||
        virStorageSourceIsEmpty(disk->store)) {
        if (virStorageSourceGetActualType(src) != VIR_STORAGE_TYPE_FILE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("refusing to generate file name for disk '%1$s'"),
                           disk->name);
            return -1;
        }

        if (!disk->store)
            disk->store = virStorageSourceNew();

        disk->store->type = VIR_STORAGE_TYPE_FILE;
        disk->store->path = g_strdup_printf("%s.%s", src->path, suffix);
    }

    return 0;
}


int
virDomainBackupAlignDisks(virDomainBackupDef *def,
                          virDomainDef *dom,
                          const char *suffix)
{
    g_autoptr(GHashTable) disks = virHashNew(NULL);
    size_t i;
    int ndisks;
    bool backup_all = false;

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!dom->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain must have at least one disk to perform backup"));
        return -1;
    }

    /* Double check requested disks.  */
    for (i = 0; i < def->ndisks; i++) {
        virDomainBackupDiskDef *backupdisk = &def->disks[i];
        virDomainDiskDef *domdisk;

        if (!(domdisk = virDomainDiskByTarget(dom, backupdisk->name))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%1$s'"), backupdisk->name);
            return -1;
        }

        if (virHashAddEntry(disks, backupdisk->name, NULL) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' specified twice"),
                           backupdisk->name);
            return -1;
        }

        if (backupdisk->backupmode == VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_INCREMENTAL &&
            !backupdisk->incremental &&
            !def->incremental) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("'incremental' backup mode of disk '%1$s' requires setting 'incremental' field for disk or backup"),
                           backupdisk->name);
            return -1;
        }


        if (backupdisk->backup == VIR_TRISTATE_BOOL_YES &&
            virDomainBackupDefAssignStore(backupdisk, domdisk->src, suffix) < 0)
            return -1;
    }

    if (def->ndisks == 0)
        backup_all = true;

    ndisks = def->ndisks;
    VIR_EXPAND_N(def->disks, def->ndisks, dom->ndisks - def->ndisks);

    for (i = 0; i < dom->ndisks; i++) {
        virDomainBackupDiskDef *backupdisk = NULL;
        virDomainDiskDef *domdisk =  dom->disks[i];

        if (virHashHasEntry(disks, domdisk->dst))
            continue;

        backupdisk = &def->disks[ndisks++];
        backupdisk->name = g_strdup(domdisk->dst);

        if (backup_all &&
            !virStorageSourceIsEmpty(domdisk->src) &&
            !domdisk->src->readonly) {
            backupdisk->backup = VIR_TRISTATE_BOOL_YES;

            if (virDomainBackupDefAssignStore(backupdisk, domdisk->src, suffix) < 0)
                return -1;
        } else {
            backupdisk->backup = VIR_TRISTATE_BOOL_NO;
        }
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainBackupDiskDef *backupdisk = &def->disks[i];

        if (backupdisk->backupmode == VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_DEFAULT) {
            if (def->incremental || backupdisk->incremental) {
                backupdisk->backupmode = VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_INCREMENTAL;
            } else {
                backupdisk->backupmode = VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_FULL;
            }
        }

        if (!backupdisk->incremental &&
            backupdisk->backupmode == VIR_DOMAIN_BACKUP_DISK_BACKUP_MODE_INCREMENTAL)
            backupdisk->incremental = g_strdup(def->incremental);
    }

    return 0;
}
