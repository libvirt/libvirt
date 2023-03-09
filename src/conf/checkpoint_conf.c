/*
 * checkpoint_conf.c: domain checkpoint XML processing
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
#include "checkpoint_conf.h"
#include "storage_source_conf.h"
#include "viruuid.h"
#include "virerror.h"
#include "virxml.h"
#include "virdomaincheckpointobjlist.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_CHECKPOINT

VIR_LOG_INIT("conf.checkpoint_conf");

static virClass *virDomainCheckpointDefClass;
static void virDomainCheckpointDefDispose(void *obj);

static int
virDomainCheckpointOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainCheckpointDef, virClassForDomainMomentDef()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainCheckpoint);

VIR_ENUM_IMPL(virDomainCheckpoint,
              VIR_DOMAIN_CHECKPOINT_TYPE_LAST,
              "default", "no", "bitmap");


/* Checkpoint Def functions */
static void
virDomainCheckpointDiskDefClear(virDomainCheckpointDiskDef *disk)
{
    VIR_FREE(disk->name);
    VIR_FREE(disk->bitmap);
}

/* Allocate a new virDomainCheckpointDef; free with virObjectUnref() */
virDomainCheckpointDef *
virDomainCheckpointDefNew(void)
{
    if (virDomainCheckpointInitialize() < 0)
        return NULL;

    return virObjectNew(virDomainCheckpointDefClass);
}

static void
virDomainCheckpointDefDispose(void *obj)
{
    virDomainCheckpointDef *def = obj;
    size_t i;

    for (i = 0; i < def->ndisks; i++)
        virDomainCheckpointDiskDefClear(&def->disks[i]);
    g_free(def->disks);
}

static int
virDomainCheckpointDiskDefParseXML(xmlNodePtr node,
                                   xmlXPathContextPtr ctxt,
                                   virDomainCheckpointDiskDef *def)
{
    g_autofree char *checkpoint = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    /* Schema guarantees this is non-NULL: */
    def->name = virXMLPropString(node, "name");

    checkpoint = virXMLPropString(node, "checkpoint");
    if (checkpoint)
        /* Schema guarantees this is in range: */
        def->type = virDomainCheckpointTypeFromString(checkpoint);
    else
        def->type = VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP;

    def->bitmap = virXMLPropString(node, "bitmap");

    return 0;
}

/* flags is bitwise-or of virDomainCheckpointParseFlags.
 */
static virDomainCheckpointDef *
virDomainCheckpointDefParse(xmlXPathContextPtr ctxt,
                            virDomainXMLOption *xmlopt,
                            void *parseOpaque,
                            unsigned int flags)
{
    virDomainCheckpointDef *ret = NULL;
    size_t i;
    int n;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autoptr(virDomainCheckpointDef) def = NULL;

    if (!(def = virDomainCheckpointDefNew()))
        return NULL;

    def->parent.name = virXPathString("string(./name)", ctxt);

    if (def->parent.name == NULL) {
        if (flags & VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("a redefined checkpoint must have a name"));
            return NULL;
        }
    }

    def->parent.description = virXPathString("string(./description)", ctxt);

    if (flags & VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE) {
        xmlNodePtr domainNode;

        if (virXPathLongLong("string(./creationTime)", ctxt,
                             &def->parent.creationTime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing creationTime from existing checkpoint"));
            return NULL;
        }

        def->parent.parent_name = virXPathString("string(./parent/name)", ctxt);

        if ((domainNode = virXPathNode("./domain", ctxt))) {
            VIR_XPATH_NODE_AUTORESTORE(ctxt)
            unsigned int domainParseFlags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;

            ctxt->node = domainNode;

            def->parent.dom = virDomainDefParseNode(ctxt, xmlopt, parseOpaque,
                                                    domainParseFlags);
            if (!def->parent.dom)
                return NULL;
        }
    } else if (virDomainXMLOptionRunMomentPostParse(xmlopt, &def->parent) < 0) {
        return NULL;
    }

    if ((n = virXPathNodeSet("./disks/*", ctxt, &nodes)) < 0)
        return NULL;
    if (n)
        def->disks = g_new0(virDomainCheckpointDiskDef, n);
    def->ndisks = n;
    for (i = 0; i < def->ndisks; i++) {
        if (virDomainCheckpointDiskDefParseXML(nodes[i], ctxt,
                                               &def->disks[i]) < 0)
            return NULL;
    }

    ret = g_steal_pointer(&def);
    return ret;
}


virDomainCheckpointDef *
virDomainCheckpointDefParseString(const char *xmlStr,
                                  virDomainXMLOption *xmlopt,
                                  void *parseOpaque,
                                  unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    xml = virXMLParse(NULL, xmlStr, _("(domain_checkpoint)"),
                      "domaincheckpoint", &ctxt, "domaincheckpoint.rng", true);

    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virDomainCheckpointDefParse(ctxt, xmlopt, parseOpaque, flags);
}


/**
 * virDomainCheckpointDefAssignBitmapNames:
 * @def: checkpoint def object
 *
 * Generate default bitmap names for checkpoint targets. Returns 0 on
 * success, -1 on error.
 */
static int
virDomainCheckpointDefAssignBitmapNames(virDomainCheckpointDef *def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDef *disk = &def->disks[i];

        if (disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP ||
            disk->bitmap)
            continue;

        disk->bitmap = g_strdup(def->parent.name);
    }

    return 0;
}


/* Align def->disks to def->domain.  Sort the list of def->disks,
 * filling in any missing disks with appropriate default.  Convert
 * paths to disk targets for uniformity.  Issue an error and return -1
 * if any def->disks[n]->name appears more than once or does not map
 * to dom->disks. */
int
virDomainCheckpointAlignDisks(virDomainCheckpointDef *chkdef)
{
    virDomainDef *domdef = chkdef->parent.dom;
    g_autoptr(GHashTable) map = virHashNew(NULL);
    g_autofree virDomainCheckpointDiskDef *olddisks = NULL;
    size_t oldndisks;
    size_t i;
    int checkpoint_default = VIR_DOMAIN_CHECKPOINT_TYPE_NONE;

    if (!domdef) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing domain in checkpoint"));
        return -1;
    }

    if (chkdef->ndisks > domdef->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disk checkpoint requests for domain"));
        return -1;
    }

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!domdef->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain must have at least one disk to perform checkpoints"));
        return -1;
    }

    /* If <disks> omitted, do bitmap on all writeable disks;
     * otherwise, do nothing for omitted disks */
    if (!chkdef->ndisks)
        checkpoint_default = VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP;

    olddisks = g_steal_pointer(&chkdef->disks);
    oldndisks = chkdef->ndisks;
    chkdef->disks = g_new0(virDomainCheckpointDiskDef, domdef->ndisks);
    chkdef->ndisks = domdef->ndisks;

    /* Double check requested disks.  */
    for (i = 0; i < oldndisks; i++) {
        virDomainCheckpointDiskDef *chkdisk = &olddisks[i];
        virDomainDiskDef *domdisk = virDomainDiskByName(domdef, chkdisk->name, false);

        if (!domdisk) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%1$s'"), chkdisk->name);
            return -1;
        }

        if (virHashHasEntry(map, domdisk->dst)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' specified twice"),
                           chkdisk->name);
            return -1;
        }

        if (virHashAddEntry(map, domdisk->dst, chkdisk) < 0)
            return -1;

        if ((virStorageSourceIsEmpty(domdisk->src) ||
             domdisk->src->readonly) &&
            chkdisk->type != VIR_DOMAIN_CHECKPOINT_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' is empty or readonly"),
                           chkdisk->name);
            return -1;
        }

        if (STRNEQ(chkdisk->name, domdisk->dst)) {
            VIR_FREE(chkdisk->name);
            chkdisk->name = g_strdup(domdisk->dst);
        }
    }

    for (i = 0; i < domdef->ndisks; i++) {
        virDomainDiskDef *domdisk = domdef->disks[i];
        virDomainCheckpointDiskDef *chkdisk = chkdef->disks + i;
        virDomainCheckpointDiskDef *existing;

        /* copy existing disks */
        if ((existing = virHashLookup(map, domdisk->dst))) {
            memcpy(chkdisk, existing, sizeof(*chkdisk));
            continue;
        }

        /* Provide defaults for all remaining disks. */
        chkdisk->name = g_strdup(domdisk->dst);

        /* Don't checkpoint empty or readonly drives */
        if (virStorageSourceIsEmpty(domdisk->src) ||
            domdisk->src->readonly)
            chkdisk->type = VIR_DOMAIN_CHECKPOINT_TYPE_NONE;
        else
            chkdisk->type = checkpoint_default;
    }

    /* Generate default bitmap names for checkpoint */
    if (virDomainCheckpointDefAssignBitmapNames(chkdef) < 0)
        return -1;

    return 0;
}


/* Converts public VIR_DOMAIN_CHECKPOINT_XML_* into
 * VIR_DOMAIN_CHECKPOINT_FORMAT_* flags, and silently ignores any other
 * flags.  */
unsigned int virDomainCheckpointFormatConvertXMLFlags(unsigned int flags)
{
    unsigned int formatFlags = 0;

    if (flags & VIR_DOMAIN_CHECKPOINT_XML_SECURE)
        formatFlags |= VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE;
    if (flags & VIR_DOMAIN_CHECKPOINT_XML_NO_DOMAIN)
        formatFlags |= VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN;
    if (flags & VIR_DOMAIN_CHECKPOINT_XML_SIZE)
        formatFlags |= VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE;

    return formatFlags;
}


static int
virDomainCheckpointDiskDefFormat(virBuffer *buf,
                                 virDomainCheckpointDiskDef *disk,
                                 unsigned int flags)
{
    if (!disk->name)
        return 0;

    virBufferEscapeString(buf, "<disk name='%s'", disk->name);
    if (disk->type)
        virBufferAsprintf(buf, " checkpoint='%s'",
                          virDomainCheckpointTypeToString(disk->type));
    if (disk->bitmap) {
        virBufferEscapeString(buf, " bitmap='%s'", disk->bitmap);
        if (flags & VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE && disk->sizeValid)
            virBufferAsprintf(buf, " size='%llu'", disk->size);
    }
    virBufferAddLit(buf, "/>\n");
    return 0;
}


static int
virDomainCheckpointDefFormatInternal(virBuffer *buf,
                                     virDomainCheckpointDef *def,
                                     virDomainXMLOption *xmlopt,
                                     unsigned int flags)
{
    size_t i;
    unsigned int domainflags = VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    if (flags & VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE)
        domainflags |= VIR_DOMAIN_DEF_FORMAT_SECURE;

    virBufferAddLit(buf, "<domaincheckpoint>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<name>%s</name>\n", def->parent.name);
    virBufferEscapeString(buf, "<description>%s</description>\n",
                          def->parent.description);

    if (def->parent.parent_name) {
        virBufferAddLit(buf, "<parent>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<name>%s</name>\n",
                              def->parent.parent_name);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</parent>\n");
    }

    if (def->parent.creationTime)
        virBufferAsprintf(buf, "<creationTime>%lld</creationTime>\n",
                          def->parent.creationTime);

    if (def->ndisks) {
        virBufferAddLit(buf, "<disks>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < def->ndisks; i++) {
            if (virDomainCheckpointDiskDefFormat(buf, &def->disks[i],
                                                 flags) < 0)
                return -1;
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</disks>\n");
    }

    if (def->parent.dom && !(flags & VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN)) {
        if (virDomainDefFormatInternal(def->parent.dom, xmlopt, buf, domainflags) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</domaincheckpoint>\n");

    return 0;
}


char *
virDomainCheckpointDefFormat(virDomainCheckpointDef *def,
                             virDomainXMLOption *xmlopt,
                             unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE |
                  VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN |
                  VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE, NULL);
    if (virDomainCheckpointDefFormatInternal(&buf, def, xmlopt,
                                             flags) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virDomainCheckpointRedefinePrep(virDomainObj *vm,
                                virDomainCheckpointDef *def,
                                bool *update_current)
{
    virDomainMomentObj *parent = NULL;

    if (virDomainCheckpointCheckCycles(vm->checkpoints, def, vm->def->name) < 0)
        return -1;

    if (def->parent.dom) {
        if (memcmp(def->parent.dom->uuid, vm->def->uuid, VIR_UUID_BUFLEN)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_INVALID_ARG,
                           _("definition for checkpoint %1$s must use uuid %2$s"),
                           def->parent.name, uuidstr);
            return -1;
        }

        if (virDomainCheckpointAlignDisks(def) < 0)
            return -1;
    } else {
        if (virDomainCheckpointDefAssignBitmapNames(def) < 0)
            return -1;
    }

    if (def->parent.parent_name &&
         (parent = virDomainCheckpointFindByName(vm->checkpoints,
                                                 def->parent.parent_name))) {
        if (parent == virDomainCheckpointGetCurrent(vm->checkpoints))
            *update_current = true;
    }

    /* set the first redefined checkpoint as current */
    if (virDomainCheckpointGetCurrent(vm->checkpoints) == NULL)
        *update_current = true;

    return 0;
}


virDomainMomentObj *
virDomainCheckpointRedefineCommit(virDomainObj *vm,
                                  virDomainCheckpointDef **defptr)
{
    virDomainCheckpointDef *def = *defptr;
    virDomainMomentObj *other = NULL;
    virDomainCheckpointDef *otherdef = NULL;
    virDomainMomentObj *chk = NULL;

    other = virDomainCheckpointFindByName(vm->checkpoints, def->parent.name);
    if (other) {
        otherdef = virDomainCheckpointObjGetDef(other);
        /* Drop and rebuild the parent relationship, but keep all
         * child relations by reusing chk.  */
        virDomainMomentDropParent(other);
        virObjectUnref(otherdef);
        other->def = &(*defptr)->parent;
        *defptr = NULL;
        chk = other;
    } else {
        chk = virDomainCheckpointAssignDef(vm->checkpoints, def);
        *defptr = NULL;
    }

    return chk;
}
