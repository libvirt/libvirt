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
#include "virbitmap.h"
#include "virbuffer.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virlog.h"
#include "viralloc.h"
#include "checkpoint_conf.h"
#include "virstoragefile.h"
#include "viruuid.h"
#include "virfile.h"
#include "virerror.h"
#include "virxml.h"
#include "virstring.h"
#include "virdomaincheckpointobjlist.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_CHECKPOINT

VIR_LOG_INIT("conf.checkpoint_conf");

static virClassPtr virDomainCheckpointDefClass;
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
virDomainCheckpointDiskDefClear(virDomainCheckpointDiskDefPtr disk)
{
    VIR_FREE(disk->name);
    VIR_FREE(disk->bitmap);
}

/* Allocate a new virDomainCheckpointDef; free with virObjectUnref() */
virDomainCheckpointDefPtr
virDomainCheckpointDefNew(void)
{
    virDomainCheckpointDefPtr def;

    if (virDomainCheckpointInitialize() < 0)
        return NULL;

    def = virObjectNew(virDomainCheckpointDefClass);
    return def;
}

static void
virDomainCheckpointDefDispose(void *obj)
{
    virDomainCheckpointDefPtr def = obj;
    size_t i;

    for (i = 0; i < def->ndisks; i++)
        virDomainCheckpointDiskDefClear(&def->disks[i]);
    VIR_FREE(def->disks);
}

static int
virDomainCheckpointDiskDefParseXML(xmlNodePtr node,
                                   xmlXPathContextPtr ctxt,
                                   virDomainCheckpointDiskDefPtr def)
{
    g_autofree char *checkpoint = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt);

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

/* flags is bitwise-or of virDomainCheckpointParseFlags.  If flags
 * does not include VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE, then caps
 * is ignored.
 */
static virDomainCheckpointDefPtr
virDomainCheckpointDefParse(xmlXPathContextPtr ctxt,
                            virCapsPtr caps,
                            virDomainXMLOptionPtr xmlopt,
                            void *parseOpaque,
                            unsigned int flags)
{
    virDomainCheckpointDefPtr ret = NULL;
    size_t i;
    int n;
    char *tmp;
    g_autofree xmlNodePtr *nodes = NULL;
    VIR_AUTOUNREF(virDomainCheckpointDefPtr) def = NULL;

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
        if (virXPathLongLong("string(./creationTime)", ctxt,
                             &def->parent.creationTime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing creationTime from existing checkpoint"));
            return NULL;
        }

        def->parent.parent_name = virXPathString("string(./parent/name)", ctxt);

        if ((tmp = virXPathString("string(./domain/@type)", ctxt))) {
            int domainflags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                              VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
            xmlNodePtr domainNode = virXPathNode("./domain", ctxt);

            VIR_FREE(tmp);
            if (!domainNode) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing domain in checkpoint"));
                return NULL;
            }
            def->parent.dom = virDomainDefParseNode(ctxt->node->doc, domainNode,
                                                    caps, xmlopt, parseOpaque,
                                                    domainflags);
            if (!def->parent.dom)
                return NULL;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing domain in checkpoint redefine"));
            return NULL;
        }
    } else if (virDomainXMLOptionRunMomentPostParse(xmlopt, &def->parent) < 0) {
        return NULL;
    }

    if ((n = virXPathNodeSet("./disks/*", ctxt, &nodes)) < 0)
        return NULL;
    if (n && VIR_ALLOC_N(def->disks, n) < 0)
        return NULL;
    def->ndisks = n;
    for (i = 0; i < def->ndisks; i++) {
        if (virDomainCheckpointDiskDefParseXML(nodes[i], ctxt,
                                               &def->disks[i]) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, def);
    return ret;
}

static virDomainCheckpointDefPtr
virDomainCheckpointDefParseNode(xmlDocPtr xml,
                                xmlNodePtr root,
                                virCapsPtr caps,
                                virDomainXMLOptionPtr xmlopt,
                                void *parseOpaque,
                                unsigned int flags)
{
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    g_autofree char *schema = NULL;

    if (!virXMLNodeNameEqual(root, "domaincheckpoint")) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("domaincheckpoint"));
        return NULL;
    }

    /* This is a new enough API to make schema validation unconditional */
    schema = virFileFindResource("domaincheckpoint.rng",
                                 abs_top_srcdir "/docs/schemas",
                                 PKGDATADIR "/schemas");
    if (!schema)
        return NULL;
    if (virXMLValidateAgainstSchema(schema, xml) < 0)
        return NULL;

    if (!(ctxt = virXMLXPathContextNew(xml)))
        return NULL;

    ctxt->node = root;
    return virDomainCheckpointDefParse(ctxt, caps, xmlopt, parseOpaque, flags);
}

virDomainCheckpointDefPtr
virDomainCheckpointDefParseString(const char *xmlStr,
                                  virCapsPtr caps,
                                  virDomainXMLOptionPtr xmlopt,
                                  void *parseOpaque,
                                  unsigned int flags)
{
    virDomainCheckpointDefPtr ret = NULL;
    xmlDocPtr xml;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(NULL, xmlStr, _("(domain_checkpoint)")))) {
        xmlKeepBlanksDefault(keepBlanksDefault);
        ret = virDomainCheckpointDefParseNode(xml, xmlDocGetRootElement(xml),
                                              caps, xmlopt, parseOpaque, flags);
        xmlFreeDoc(xml);
    }
    xmlKeepBlanksDefault(keepBlanksDefault);

    return ret;
}


/**
 * virDomainCheckpointDefAssignBitmapNames:
 * @def: checkpoint def object
 *
 * Generate default bitmap names for checkpoint targets. Returns 0 on
 * success, -1 on error.
 */
static int
virDomainCheckpointDefAssignBitmapNames(virDomainCheckpointDefPtr def)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDefPtr disk = &def->disks[i];

        if (disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP ||
            disk->bitmap)
            continue;

        if (VIR_STRDUP(disk->bitmap, def->parent.name) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainCheckpointCompareDiskIndex(const void *a, const void *b)
{
    const virDomainCheckpointDiskDef *diska = a;
    const virDomainCheckpointDiskDef *diskb = b;

    /* Integer overflow shouldn't be a problem here.  */
    return diska->idx - diskb->idx;
}

/* Align def->disks to def->domain.  Sort the list of def->disks,
 * filling in any missing disks with appropriate default.  Convert
 * paths to disk targets for uniformity.  Issue an error and return -1
 * if any def->disks[n]->name appears more than once or does not map
 * to dom->disks. */
int
virDomainCheckpointAlignDisks(virDomainCheckpointDefPtr def)
{
    int ret = -1;
    virBitmapPtr map = NULL;
    size_t i;
    int ndisks;
    int checkpoint_default = VIR_DOMAIN_CHECKPOINT_TYPE_NONE;

    if (!def->parent.dom) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing domain in checkpoint"));
        goto cleanup;
    }

    if (def->ndisks > def->parent.dom->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disk checkpoint requests for domain"));
        goto cleanup;
    }

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!def->parent.dom->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("domain must have at least one disk to perform "
                         "checkpoints"));
        goto cleanup;
    }

    /* If <disks> omitted, do bitmap on all writeable disks;
     * otherwise, do nothing for omitted disks */
    if (!def->ndisks)
        checkpoint_default = VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP;

    if (!(map = virBitmapNew(def->parent.dom->ndisks)))
        goto cleanup;

    /* Double check requested disks.  */
    for (i = 0; i < def->ndisks; i++) {
        virDomainCheckpointDiskDefPtr disk = &def->disks[i];
        int idx = virDomainDiskIndexByName(def->parent.dom, disk->name, false);

        if (idx < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%s'"), disk->name);
            goto cleanup;
        }

        if (virBitmapIsBitSet(map, idx)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' specified twice"),
                           disk->name);
            goto cleanup;
        }
        if ((virStorageSourceIsEmpty(def->parent.dom->disks[idx]->src) ||
             def->parent.dom->disks[idx]->src->readonly) &&
            disk->type != VIR_DOMAIN_CHECKPOINT_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' is empty or readonly"),
                           disk->name);
            goto cleanup;
        }
        ignore_value(virBitmapSetBit(map, idx));
        disk->idx = idx;

        if (STRNEQ(disk->name, def->parent.dom->disks[idx]->dst)) {
            VIR_FREE(disk->name);
            if (VIR_STRDUP(disk->name, def->parent.dom->disks[idx]->dst) < 0)
                goto cleanup;
        }
    }

    /* Provide defaults for all remaining disks.  */
    ndisks = def->ndisks;
    if (VIR_EXPAND_N(def->disks, def->ndisks,
                     def->parent.dom->ndisks - def->ndisks) < 0)
        goto cleanup;

    for (i = 0; i < def->parent.dom->ndisks; i++) {
        virDomainCheckpointDiskDefPtr disk;

        if (virBitmapIsBitSet(map, i))
            continue;
        disk = &def->disks[ndisks++];
        if (VIR_STRDUP(disk->name, def->parent.dom->disks[i]->dst) < 0)
            goto cleanup;
        disk->idx = i;

        /* Don't checkpoint empty or readonly drives */
        if (virStorageSourceIsEmpty(def->parent.dom->disks[i]->src) ||
            def->parent.dom->disks[i]->src->readonly)
            disk->type = VIR_DOMAIN_CHECKPOINT_TYPE_NONE;
        else
            disk->type = checkpoint_default;
    }

    qsort(&def->disks[0], def->ndisks, sizeof(def->disks[0]),
          virDomainCheckpointCompareDiskIndex);

    /* Generate default bitmap names for checkpoint */
    if (virDomainCheckpointDefAssignBitmapNames(def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBitmapFree(map);
    return ret;
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
virDomainCheckpointDiskDefFormat(virBufferPtr buf,
                                 virDomainCheckpointDiskDefPtr disk,
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
        if (flags & VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE)
            virBufferAsprintf(buf, " size='%llu'", disk->size);
    }
    virBufferAddLit(buf, "/>\n");
    return 0;
}


static int
virDomainCheckpointDefFormatInternal(virBufferPtr buf,
                                     virDomainCheckpointDefPtr def,
                                     virCapsPtr caps,
                                     virDomainXMLOptionPtr xmlopt,
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
                goto error;
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</disks>\n");
    }

    if (!(flags & VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN) &&
        virDomainDefFormatInternal(def->parent.dom, caps, domainflags, buf,
                                   xmlopt) < 0)
        goto error;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</domaincheckpoint>\n");

    if (virBufferCheckError(buf) < 0)
        goto error;

    return 0;

 error:
    virBufferFreeAndReset(buf);
    return -1;
}

char *
virDomainCheckpointDefFormat(virDomainCheckpointDefPtr def,
                             virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt,
                             unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE |
                  VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN |
                  VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE, NULL);
    if (virDomainCheckpointDefFormatInternal(&buf, def, caps, xmlopt,
                                             flags) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virDomainCheckpointRedefinePrep(virDomainObjPtr vm,
                                virDomainCheckpointDefPtr *defptr,
                                virDomainMomentObjPtr *chk,
                                virDomainXMLOptionPtr xmlopt,
                                bool *update_current)
{
    virDomainCheckpointDefPtr def = *defptr;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainMomentObjPtr other = NULL;
    virDomainCheckpointDefPtr otherdef = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);

    if (virDomainCheckpointCheckCycles(vm->checkpoints, def, vm->def->name) < 0)
        return -1;

    if (!def->parent.dom ||
        memcmp(def->parent.dom->uuid, vm->def->uuid, VIR_UUID_BUFLEN)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("definition for checkpoint %s must use uuid %s"),
                       def->parent.name, uuidstr);
        return -1;
    }
    if (virDomainCheckpointAlignDisks(def) < 0)
        return -1;

    if (def->parent.parent_name)
        other = virDomainCheckpointFindByName(vm->checkpoints,
                                              def->parent.parent_name);
    if (other == virDomainCheckpointGetCurrent(vm->checkpoints)) {
        *update_current = true;
        virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
    }

    other = virDomainCheckpointFindByName(vm->checkpoints, def->parent.name);
    if (other) {
        otherdef = virDomainCheckpointObjGetDef(other);
        if (!virDomainDefCheckABIStability(otherdef->parent.dom,
                                           def->parent.dom, xmlopt))
            return -1;

        if (other == virDomainCheckpointGetCurrent(vm->checkpoints)) {
            *update_current = true;
            virDomainCheckpointSetCurrent(vm->checkpoints, NULL);
        }

        /* Drop and rebuild the parent relationship, but keep all
         * child relations by reusing chk.  */
        virDomainMomentDropParent(other);
        virObjectUnref(otherdef);
        other->def = &(*defptr)->parent;
        *defptr = NULL;
        *chk = other;
    }

    return 0;
}
