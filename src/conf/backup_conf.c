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
#include "datatypes.h"
#include "domain_conf.h"
#include "virlog.h"
#include "viralloc.h"
#include "backup_conf.h"
#include "virstoragefile.h"
#include "virfile.h"
#include "virerror.h"
#include "virxml.h"
#include "virstring.h"
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

void
virDomainBackupDefFree(virDomainBackupDefPtr def)
{
    size_t i;

    if (!def)
        return;

    g_free(def->incremental);
    virStorageNetHostDefFree(1, def->server);

    for (i = 0; i < def->ndisks; i++) {
        virDomainBackupDiskDefPtr disk = def->disks + i;

        g_free(disk->name);
        g_free(disk->exportname);
        g_free(disk->exportbitmap);
        virObjectUnref(disk->store);
    }

    g_free(def->disks);
    g_free(def);
}


static int
virDomainBackupDiskDefParseXML(xmlNodePtr node,
                               xmlXPathContextPtr ctxt,
                               virDomainBackupDiskDefPtr def,
                               bool push,
                               unsigned int flags,
                               virDomainXMLOptionPtr xmlopt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt);
    g_autofree char *type = NULL;
    g_autofree char *driver = NULL;
    g_autofree char *backup = NULL;
    g_autofree char *state = NULL;
    int tmp;
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

    def->backup = VIR_TRISTATE_BOOL_YES;

    if ((backup = virXMLPropString(node, "backup"))) {
        if ((tmp = virTristateBoolTypeFromString(backup)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid disk 'backup' state '%s'"), backup);
            return -1;
        }

        def->backup = tmp;
    }

    /* don't parse anything else if backup is disabled */
    if (def->backup == VIR_TRISTATE_BOOL_NO)
        return 0;

    if (!push) {
        def->exportname = virXMLPropString(node, "exportname");
        def->exportbitmap = virXMLPropString(node, "exportbitmap");
    }

    if (internal) {
        if (!(state = virXMLPropString(node, "state")) ||
            (tmp = virDomainBackupDiskStateTypeFromString(state)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("disk '%s' backup state wrong or missing'"), def->name);
            return -1;
        }

        def->state = tmp;
    }

    if (!(def->store = virStorageSourceNew()))
        return -1;

    if ((type = virXMLPropString(node, "type"))) {
        if ((def->store->type = virStorageTypeFromString(type)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown disk backup type '%s'"), type);
            return -1;
        }

        if (def->store->type != VIR_STORAGE_TYPE_FILE &&
            def->store->type != VIR_STORAGE_TYPE_BLOCK) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unsupported disk backup type '%s'"), type);
            return -1;
        }
    } else {
        def->store->type = VIR_STORAGE_TYPE_FILE;
    }

    if (push)
        srcNode = virXPathNode("./target", ctxt);
    else
        srcNode = virXPathNode("./scratch", ctxt);

    if (srcNode &&
        virDomainStorageSourceParse(srcNode, ctxt, def->store,
                                    storageSourceParseFlags, xmlopt) < 0)
        return -1;

    if ((driver = virXPathString("string(./driver/@type)", ctxt))) {
        def->store->format = virStorageFileFormatTypeFromString(driver);
        if (def->store->format <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk backup driver '%s'"), driver);
            return -1;
        } else if (!push && def->store->format != VIR_STORAGE_FILE_QCOW2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("pull mode requires qcow2 driver, not '%s'"),
                           driver);
            return -1;
        }
    }

    return 0;
}


static virDomainBackupDefPtr
virDomainBackupDefParse(xmlXPathContextPtr ctxt,
                        virDomainXMLOptionPtr xmlopt,
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
                           _("unknown backup mode '%s'"), mode);
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
            def->server->socket[0] != '/') {
            virReportError(VIR_ERR_XML_ERROR,
                           _("backup socket path '%s' must be absolute"),
                           def->server->socket);
            return NULL;
        }
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

    return g_steal_pointer(&def);
}


virDomainBackupDefPtr
virDomainBackupDefParseString(const char *xmlStr,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags)
{
    virDomainBackupDefPtr ret = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(NULL, xmlStr, _("(domain_backup)")))) {
        xmlKeepBlanksDefault(keepBlanksDefault);
        ret = virDomainBackupDefParseNode(xml, xmlDocGetRootElement(xml),
                                          xmlopt, flags);
    }
    xmlKeepBlanksDefault(keepBlanksDefault);

    return ret;
}


virDomainBackupDefPtr
virDomainBackupDefParseNode(xmlDocPtr xml,
                            xmlNodePtr root,
                            virDomainXMLOptionPtr xmlopt,
                            unsigned int flags)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree char *schema = NULL;

    if (!virXMLNodeNameEqual(root, "domainbackup")) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("domainbackup"));
        return NULL;
    }

    if (!(flags & VIR_DOMAIN_BACKUP_PARSE_INTERNAL)) {
        if (!(schema = virFileFindResource("domainbackup.rng",
                                           abs_top_srcdir "/docs/schemas",
                                           PKGDATADIR "/schemas")))
            return NULL;

        if (virXMLValidateAgainstSchema(schema, xml) < 0)
            return NULL;
    }

    if (!(ctxt = virXMLXPathContextNew(xml)))
        return NULL;

    ctxt->node = root;
    return virDomainBackupDefParse(ctxt, xmlopt, flags);
}


static int
virDomainBackupDiskDefFormat(virBufferPtr buf,
                             virDomainBackupDiskDefPtr disk,
                             bool push,
                             bool internal)
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
    if (internal)
        virBufferAsprintf(&attrBuf, " state='%s'", virDomainBackupDiskStateTypeToString(disk->state));

    if (disk->backup == VIR_TRISTATE_BOOL_YES) {
        virBufferAsprintf(&attrBuf, " type='%s'", virStorageTypeToString(disk->store->type));

        virBufferEscapeString(&attrBuf, " exportname='%s'", disk->exportname);
        virBufferEscapeString(&attrBuf, " exportbitmap='%s'", disk->exportbitmap);

        if (disk->store->format > 0)
            virBufferEscapeString(&childBuf, "<driver type='%s'/>\n",
                                  virStorageFileFormatTypeToString(disk->store->format));

        if (virDomainDiskSourceFormat(&childBuf, disk->store, sourcename,
                                      0, false, storageSourceFormatFlags, true, NULL) < 0)
            return -1;
    }

    virXMLFormatElement(buf, "disk", &attrBuf, &childBuf);
    return 0;
}


int
virDomainBackupDefFormat(virBufferPtr buf,
                         virDomainBackupDefPtr def,
                         bool internal)
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
        virBufferEscapeString(&serverAttrBuf, " name='%s'", def->server->name);
        if (def->server->port)
            virBufferAsprintf(&serverAttrBuf, " port='%u'", def->server->port);
        virBufferEscapeString(&serverAttrBuf, " socket='%s'", def->server->socket);
    }

    virXMLFormatElement(&childBuf, "server", &serverAttrBuf, NULL);

    for (i = 0; i < def->ndisks; i++) {
        if (virDomainBackupDiskDefFormat(&disksChildBuf, &def->disks[i],
                                         def->type == VIR_DOMAIN_BACKUP_TYPE_PUSH,
                                         internal) < 0)
            return -1;
    }

    virXMLFormatElement(&childBuf, "disks", NULL, &disksChildBuf);
    virXMLFormatElement(buf, "domainbackup", &attrBuf, &childBuf);

    return 0;
}


static int
virDomainBackupDefAssignStore(virDomainBackupDiskDefPtr disk,
                              virStorageSourcePtr src,
                              const char *suffix)
{
    if (virStorageSourceIsEmpty(src)) {
        if (disk->store) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' has no media"), disk->name);
            return -1;
        }
    } else if (src->readonly) {
        if (disk->store) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("backup of readonly disk '%s' makes no sense"),
                           disk->name);
            return -1;
        }
    } else if (!disk->store) {
        if (virStorageSourceGetActualType(src) == VIR_STORAGE_TYPE_FILE) {
            if (!(disk->store = virStorageSourceNew()))
                return -1;

            disk->store->type = VIR_STORAGE_TYPE_FILE;
            disk->store->path = g_strdup_printf("%s.%s", src->path, suffix);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("refusing to generate file name for disk '%s'"),
                           disk->name);
            return -1;
        }
    }

    return 0;
}


int
virDomainBackupAlignDisks(virDomainBackupDefPtr def,
                          virDomainDefPtr dom,
                          const char *suffix)
{
    g_autoptr(virHashTable) disks = virHashNew(NULL);
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
        virDomainBackupDiskDefPtr backupdisk = &def->disks[i];
        virDomainDiskDefPtr domdisk;

        if (!(domdisk = virDomainDiskByTarget(dom, backupdisk->name))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%s'"), backupdisk->name);
            return -1;
        }

        if (virHashAddEntry(disks, backupdisk->name, NULL) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' specified twice"),
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
    if (VIR_EXPAND_N(def->disks, def->ndisks, dom->ndisks - def->ndisks) < 0)
        return -1;

    for (i = 0; i < dom->ndisks; i++) {
        virDomainBackupDiskDefPtr backupdisk = NULL;
        virDomainDiskDefPtr domdisk =  dom->disks[i];

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

    return 0;
}
