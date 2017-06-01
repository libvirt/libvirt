/*
 * snapshot_conf.c: domain snapshot XML processing
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 *
 * Author: Eric Blake <eblake@redhat.com>
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "count-one-bits.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "virlog.h"
#include "viralloc.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vport_profile_conf.h"
#include "nwfilter_conf.h"
#include "secret_conf.h"
#include "snapshot_conf.h"
#include "virstoragefile.h"
#include "viruuid.h"
#include "virfile.h"
#include "virerror.h"
#include "virxml.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.snapshot_conf");

VIR_ENUM_IMPL(virDomainSnapshotLocation, VIR_DOMAIN_SNAPSHOT_LOCATION_LAST,
              "default",
              "no",
              "internal",
              "external")

/* virDomainSnapshotState is really virDomainState plus one extra state */
VIR_ENUM_IMPL(virDomainSnapshotState, VIR_DOMAIN_SNAPSHOT_STATE_LAST,
              "nostate",
              "running",
              "blocked",
              "paused",
              "shutdown",
              "shutoff",
              "crashed",
              "pmsuspended",
              "disk-snapshot")

struct _virDomainSnapshotObjList {
    /* name string -> virDomainSnapshotObj  mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objs;

    virDomainSnapshotObj metaroot; /* Special parent of all root snapshots */
};

/* Snapshot Def functions */
static void
virDomainSnapshotDiskDefClear(virDomainSnapshotDiskDefPtr disk)
{
    VIR_FREE(disk->name);
    virStorageSourceFree(disk->src);
    disk->src = NULL;
}

void virDomainSnapshotDefFree(virDomainSnapshotDefPtr def)
{
    size_t i;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->description);
    VIR_FREE(def->parent);
    VIR_FREE(def->file);
    for (i = 0; i < def->ndisks; i++)
        virDomainSnapshotDiskDefClear(&def->disks[i]);
    VIR_FREE(def->disks);
    virDomainDefFree(def->dom);
    virObjectUnref(def->cookie);
    VIR_FREE(def);
}

static int
virDomainSnapshotDiskDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainSnapshotDiskDefPtr def)
{
    int ret = -1;
    char *snapshot = NULL;
    char *type = NULL;
    char *driver = NULL;
    xmlNodePtr cur;
    xmlNodePtr saved = ctxt->node;

    ctxt->node = node;

    if (VIR_ALLOC(def->src) < 0)
        goto cleanup;

    def->name = virXMLPropString(node, "name");
    if (!def->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing name from disk snapshot element"));
        goto cleanup;
    }

    snapshot = virXMLPropString(node, "snapshot");
    if (snapshot) {
        def->snapshot = virDomainSnapshotLocationTypeFromString(snapshot);
        if (def->snapshot <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk snapshot setting '%s'"),
                           snapshot);
            goto cleanup;
        }
    }

    if ((type = virXMLPropString(node, "type"))) {
        if ((def->src->type = virStorageTypeFromString(type)) <= 0 ||
            def->src->type == VIR_STORAGE_TYPE_VOLUME ||
            def->src->type == VIR_STORAGE_TYPE_DIR) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown disk snapshot type '%s'"), type);
            goto cleanup;
        }
    } else {
        def->src->type = VIR_STORAGE_TYPE_FILE;
    }

    if ((cur = virXPathNode("./source", ctxt)) &&
        virDomainDiskSourceParse(cur, ctxt, def->src) < 0)
        goto cleanup;

    if ((driver = virXPathString("string(./driver/@type)", ctxt))) {
        def->src->format = virStorageFileFormatTypeFromString(driver);
        if (def->src->format < VIR_STORAGE_FILE_BACKING) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           def->src->format <= 0
                           ? _("unknown disk snapshot driver '%s'")
                           : _("disk format '%s' lacks backing file "
                               "support"),
                           driver);
            goto cleanup;
        }
    }

    /* validate that the passed path is absolute */
    if (virStorageSourceIsRelative(def->src)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("disk snapshot image path '%s' must be absolute"),
                       def->src->path);
        goto cleanup;
    }

    if (!def->snapshot && (def->src->path || def->src->format))
        def->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;

    ret = 0;
 cleanup:
    ctxt->node = saved;

    VIR_FREE(driver);
    VIR_FREE(snapshot);
    VIR_FREE(type);
    if (ret < 0)
        virDomainSnapshotDiskDefClear(def);
    return ret;
}

/* flags is bitwise-or of virDomainSnapshotParseFlags.
 * If flags does not include VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE, then
 * caps are ignored.
 */
static virDomainSnapshotDefPtr
virDomainSnapshotDefParse(xmlXPathContextPtr ctxt,
                          virCapsPtr caps,
                          virDomainXMLOptionPtr xmlopt,
                          unsigned int flags)
{
    virDomainSnapshotDefPtr def = NULL;
    virDomainSnapshotDefPtr ret = NULL;
    xmlNodePtr *nodes = NULL;
    size_t i;
    int n;
    char *creation = NULL, *state = NULL;
    struct timeval tv;
    int active;
    char *tmp;
    char *memorySnapshot = NULL;
    char *memoryFile = NULL;
    bool offline = !!(flags & VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE);
    virSaveCookieCallbacksPtr saveCookie = virDomainXMLOptionGetSaveCookie(xmlopt);

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    gettimeofday(&tv, NULL);

    def->name = virXPathString("string(./name)", ctxt);
    if (def->name == NULL) {
        if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("a redefined snapshot must have a name"));
            goto cleanup;
        }
        if (virAsprintf(&def->name, "%lld", (long long)tv.tv_sec) < 0)
            goto cleanup;
    }

    def->description = virXPathString("string(./description)", ctxt);

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        if (virXPathLongLong("string(./creationTime)", ctxt,
                             &def->creationTime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing creationTime from existing snapshot"));
            goto cleanup;
        }

        def->parent = virXPathString("string(./parent/name)", ctxt);

        state = virXPathString("string(./state)", ctxt);
        if (state == NULL) {
            /* there was no state in an existing snapshot; this
             * should never happen
             */
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing state from existing snapshot"));
            goto cleanup;
        }
        def->state = virDomainSnapshotStateTypeFromString(state);
        if (def->state < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid state '%s' in domain snapshot XML"),
                           state);
            goto cleanup;
        }
        offline = (def->state == VIR_DOMAIN_SHUTOFF ||
                   def->state == VIR_DOMAIN_DISK_SNAPSHOT);

        /* Older snapshots were created with just <domain>/<uuid>, and
         * lack domain/@type.  In that case, leave dom NULL, and
         * clients will have to decide between best effort
         * initialization or outright failure.  */
        if ((tmp = virXPathString("string(./domain/@type)", ctxt))) {
            int domainflags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                              VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
            if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL)
                domainflags |= VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS;
            xmlNodePtr domainNode = virXPathNode("./domain", ctxt);

            VIR_FREE(tmp);
            if (!domainNode) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing domain in snapshot"));
                goto cleanup;
            }
            def->dom = virDomainDefParseNode(ctxt->node->doc, domainNode,
                                             caps, xmlopt, NULL, domainflags);
            if (!def->dom)
                goto cleanup;
        } else {
            VIR_WARN("parsing older snapshot that lacks domain");
        }
    } else {
        def->creationTime = tv.tv_sec;
    }

    memorySnapshot = virXPathString("string(./memory/@snapshot)", ctxt);
    memoryFile = virXPathString("string(./memory/@file)", ctxt);
    if (memorySnapshot) {
        def->memory = virDomainSnapshotLocationTypeFromString(memorySnapshot);
        if (def->memory <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown memory snapshot setting '%s'"),
                           memorySnapshot);
            goto cleanup;
        }
        if (memoryFile &&
            def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("memory filename '%s' requires external snapshot"),
                           memoryFile);
            goto cleanup;
        }
        if (!memoryFile &&
            def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("external memory snapshots require a filename"));
            goto cleanup;
        }
    } else if (memoryFile) {
        def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
    } else if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        def->memory = (offline ?
                       VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                       VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL);
    }
    if (offline && def->memory &&
        def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("memory state cannot be saved with offline or "
                         "disk-only snapshot"));
        goto cleanup;
    }
    def->file = memoryFile;
    memoryFile = NULL;

    /* verify that memory path is absolute */
    if (def->file && def->file[0] != '/') {
        virReportError(VIR_ERR_XML_ERROR,
                       _("memory snapshot file path (%s) must be absolute"),
                       def->file);
        goto cleanup;
    }

    if ((n = virXPathNodeSet("./disks/*", ctxt, &nodes)) < 0)
        goto cleanup;
    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_DISKS) {
        if (n && VIR_ALLOC_N(def->disks, n) < 0)
            goto cleanup;
        def->ndisks = n;
        for (i = 0; i < def->ndisks; i++) {
            if (virDomainSnapshotDiskDefParseXML(nodes[i], ctxt,
                                                 &def->disks[i]) < 0)
                goto cleanup;
        }
        VIR_FREE(nodes);
    } else if (n) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("unable to handle disk requests in snapshot"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL) {
        if (virXPathInt("string(./active)", ctxt, &active) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find 'active' element"));
            goto cleanup;
        }
        def->current = active != 0;
    }

    if (!offline && virSaveCookieParse(ctxt, &def->cookie, saveCookie) < 0)
        goto cleanup;

    ret = def;

 cleanup:
    VIR_FREE(creation);
    VIR_FREE(state);
    VIR_FREE(nodes);
    VIR_FREE(memorySnapshot);
    VIR_FREE(memoryFile);
    if (ret == NULL)
        virDomainSnapshotDefFree(def);

    return ret;
}

virDomainSnapshotDefPtr
virDomainSnapshotDefParseNode(xmlDocPtr xml,
                              xmlNodePtr root,
                              virCapsPtr caps,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags)
{
    xmlXPathContextPtr ctxt = NULL;
    virDomainSnapshotDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "domainsnapshot")) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("domainsnapshot"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virDomainSnapshotDefParse(ctxt, caps, xmlopt, flags);
 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

virDomainSnapshotDefPtr
virDomainSnapshotDefParseString(const char *xmlStr,
                                virCapsPtr caps,
                                virDomainXMLOptionPtr xmlopt,
                                unsigned int flags)
{
    virDomainSnapshotDefPtr ret = NULL;
    xmlDocPtr xml;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(NULL, xmlStr, _("(domain_snapshot)")))) {
        xmlKeepBlanksDefault(keepBlanksDefault);
        ret = virDomainSnapshotDefParseNode(xml, xmlDocGetRootElement(xml),
                                            caps, xmlopt, flags);
        xmlFreeDoc(xml);
    }
    xmlKeepBlanksDefault(keepBlanksDefault);

    return ret;
}


/**
 * virDomainSnapshotDefAssignExternalNames:
 * @def: snapshot def object
 *
 * Generate default external file names for snapshot targets. Returns 0 on
 * success, -1 on error.
 */
static int
virDomainSnapshotDefAssignExternalNames(virDomainSnapshotDefPtr def)
{
    const char *origpath;
    char *tmppath;
    char *tmp;
    struct stat sb;
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDefPtr disk = &def->disks[i];

        if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL ||
            disk->src->path)
            continue;

        if (disk->src->type != VIR_STORAGE_TYPE_FILE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot generate external snapshot name "
                             "for disk '%s' on a '%s' device"),
                           disk->name, virStorageTypeToString(disk->src->type));
            return -1;
        }

        if (!(origpath = virDomainDiskGetSource(def->dom->disks[i]))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot generate external snapshot name "
                             "for disk '%s' without source"),
                           disk->name);
            return -1;
        }

        if (stat(origpath, &sb) < 0 || !S_ISREG(sb.st_mode)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("source for disk '%s' is not a regular "
                             "file; refusing to generate external "
                             "snapshot name"),
                           disk->name);
            return -1;
        }

        if (VIR_STRDUP(tmppath, origpath) < 0)
            return -1;

        /* drop suffix of the file name */
        if ((tmp = strrchr(tmppath, '.')) && !strchr(tmp, '/'))
            *tmp = '\0';

        if (virAsprintf(&disk->src->path, "%s.%s", tmppath, def->name) < 0) {
            VIR_FREE(tmppath);
            return -1;
        }

        VIR_FREE(tmppath);

        /* verify that we didn't generate a duplicate name */
        for (j = 0; j < i; j++) {
            if (STREQ_NULLABLE(disk->src->path, def->disks[j].src->path)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("cannot generate external snapshot name for "
                                 "disk '%s': collision with disk '%s'"),
                               disk->name, def->disks[j].name);
                return -1;
            }
        }
    }

    return 0;
}


static int
virDomainSnapshotCompareDiskIndex(const void *a, const void *b)
{
    const virDomainSnapshotDiskDef *diska = a;
    const virDomainSnapshotDiskDef *diskb = b;

    /* Integer overflow shouldn't be a problem here.  */
    return diska->idx - diskb->idx;
}

/* Align def->disks to def->domain.  Sort the list of def->disks,
 * filling in any missing disks or snapshot state defaults given by
 * the domain, with a fallback to a passed in default.  Convert paths
 * to disk targets for uniformity.  Issue an error and return -1 if
 * any def->disks[n]->name appears more than once or does not map to
 * dom->disks.  If require_match, also ensure that there is no
 * conflicting requests for both internal and external snapshots.  */
int
virDomainSnapshotAlignDisks(virDomainSnapshotDefPtr def,
                            int default_snapshot,
                            bool require_match)
{
    int ret = -1;
    virBitmapPtr map = NULL;
    size_t i;
    int ndisks;

    if (!def->dom) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing domain in snapshot"));
        goto cleanup;
    }

    if (def->ndisks > def->dom->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disk snapshot requests for domain"));
        goto cleanup;
    }

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!def->dom->ndisks) {
        ret = 0;
        goto cleanup;
    }

    if (!(map = virBitmapNew(def->dom->ndisks)))
        goto cleanup;

    /* Double check requested disks.  */
    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDefPtr disk = &def->disks[i];
        int idx = virDomainDiskIndexByName(def->dom, disk->name, false);
        int disk_snapshot;

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
        ignore_value(virBitmapSetBit(map, idx));
        disk->idx = idx;

        disk_snapshot = def->dom->disks[idx]->snapshot;
        if (!disk->snapshot) {
            if (disk_snapshot &&
                (!require_match ||
                 disk_snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE))
                disk->snapshot = disk_snapshot;
            else
                disk->snapshot = default_snapshot;
        } else if (require_match &&
                   disk->snapshot != default_snapshot &&
                   !(disk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE &&
                     disk_snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)) {
            const char *tmp;

            tmp = virDomainSnapshotLocationTypeToString(default_snapshot);
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' must use snapshot mode '%s'"),
                           disk->name, tmp);
            goto cleanup;
        }
        if (disk->src->path &&
            disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("file '%s' for disk '%s' requires "
                             "use of external snapshot mode"),
                           disk->src->path, disk->name);
            goto cleanup;
        }
        if (STRNEQ(disk->name, def->dom->disks[idx]->dst)) {
            VIR_FREE(disk->name);
            if (VIR_STRDUP(disk->name, def->dom->disks[idx]->dst) < 0)
                goto cleanup;
        }
    }

    /* Provide defaults for all remaining disks.  */
    ndisks = def->ndisks;
    if (VIR_EXPAND_N(def->disks, def->ndisks,
                     def->dom->ndisks - def->ndisks) < 0)
        goto cleanup;

    for (i = 0; i < def->dom->ndisks; i++) {
        virDomainSnapshotDiskDefPtr disk;

        if (virBitmapIsBitSet(map, i))
            continue;
        disk = &def->disks[ndisks++];
        if (VIR_ALLOC(disk->src) < 0)
            goto cleanup;
        if (VIR_STRDUP(disk->name, def->dom->disks[i]->dst) < 0)
            goto cleanup;
        disk->idx = i;

        /* Don't snapshot empty drives */
        if (virStorageSourceIsEmpty(def->dom->disks[i]->src))
            disk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
        else
            disk->snapshot = def->dom->disks[i]->snapshot;

        disk->src->type = VIR_STORAGE_TYPE_FILE;
        if (!disk->snapshot)
            disk->snapshot = default_snapshot;
    }

    qsort(&def->disks[0], def->ndisks, sizeof(def->disks[0]),
          virDomainSnapshotCompareDiskIndex);

    /* Generate default external file names for external snapshot locations */
    if (virDomainSnapshotDefAssignExternalNames(def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBitmapFree(map);
    return ret;
}

static void
virDomainSnapshotDiskDefFormat(virBufferPtr buf,
                               virDomainSnapshotDiskDefPtr disk)
{
    int type = disk->src->type;

    if (!disk->name)
        return;

    virBufferEscapeString(buf, "<disk name='%s'", disk->name);
    if (disk->snapshot > 0)
        virBufferAsprintf(buf, " snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(disk->snapshot));

    if (!disk->src->path && disk->src->format == 0) {
        virBufferAddLit(buf, "/>\n");
        return;
    }

    virBufferAsprintf(buf, " type='%s'>\n", virStorageTypeToString(type));
    virBufferAdjustIndent(buf, 2);

    if (disk->src->format > 0)
        virBufferEscapeString(buf, "<driver type='%s'/>\n",
                              virStorageFileFormatTypeToString(disk->src->format));
    virDomainDiskSourceFormat(buf, disk->src, 0, 0);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</disk>\n");
}


char *
virDomainSnapshotDefFormat(const char *domain_uuid,
                           virDomainSnapshotDefPtr def,
                           virCapsPtr caps,
                           virDomainXMLOptionPtr xmlopt,
                           unsigned int flags,
                           int internal)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virCheckFlags(VIR_DOMAIN_DEF_FORMAT_SECURE |
                  VIR_DOMAIN_DEF_FORMAT_UPDATE_CPU, NULL);

    flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    virBufferAddLit(&buf, "<domainsnapshot>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);
    if (def->description)
        virBufferEscapeString(&buf, "<description>%s</description>\n",
                              def->description);
    virBufferAsprintf(&buf, "<state>%s</state>\n",
                      virDomainSnapshotStateTypeToString(def->state));

    if (def->parent) {
        virBufferAddLit(&buf, "<parent>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferEscapeString(&buf, "<name>%s</name>\n", def->parent);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</parent>\n");
    }

    virBufferAsprintf(&buf, "<creationTime>%lld</creationTime>\n",
                      def->creationTime);

    if (def->memory) {
        virBufferAsprintf(&buf, "<memory snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(def->memory));
        virBufferEscapeString(&buf, " file='%s'", def->file);
        virBufferAddLit(&buf, "/>\n");
    }

    if (def->ndisks) {
        virBufferAddLit(&buf, "<disks>\n");
        virBufferAdjustIndent(&buf, 2);
        for (i = 0; i < def->ndisks; i++)
            virDomainSnapshotDiskDefFormat(&buf, &def->disks[i]);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</disks>\n");
    }

    if (def->dom) {
        if (virDomainDefFormatInternal(def->dom, caps, flags, &buf) < 0)
            goto error;
    } else if (domain_uuid) {
        virBufferAddLit(&buf, "<domain>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", domain_uuid);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</domain>\n");
    }

    if (virSaveCookieFormatBuf(&buf, def->cookie,
                               virDomainXMLOptionGetSaveCookie(xmlopt)) < 0)
        goto error;

    if (internal)
        virBufferAsprintf(&buf, "<active>%d</active>\n", def->current);

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</domainsnapshot>\n");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

/* Snapshot Obj functions */
static virDomainSnapshotObjPtr virDomainSnapshotObjNew(void)
{
    virDomainSnapshotObjPtr snapshot;

    if (VIR_ALLOC(snapshot) < 0)
        return NULL;

    VIR_DEBUG("obj=%p", snapshot);

    return snapshot;
}

static void virDomainSnapshotObjFree(virDomainSnapshotObjPtr snapshot)
{
    if (!snapshot)
        return;

    VIR_DEBUG("obj=%p", snapshot);

    virDomainSnapshotDefFree(snapshot->def);
    VIR_FREE(snapshot);
}

virDomainSnapshotObjPtr virDomainSnapshotAssignDef(virDomainSnapshotObjListPtr snapshots,
                                                   virDomainSnapshotDefPtr def)
{
    virDomainSnapshotObjPtr snap;

    if (virHashLookup(snapshots->objs, def->name) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain snapshot %s already exists"),
                       def->name);
        return NULL;
    }

    if (!(snap = virDomainSnapshotObjNew()))
        return NULL;
    snap->def = def;

    if (virHashAddEntry(snapshots->objs, snap->def->name, snap) < 0) {
        VIR_FREE(snap);
        return NULL;
    }

    return snap;
}

/* Snapshot Obj List functions */
static void
virDomainSnapshotObjListDataFree(void *payload,
                                 const void *name ATTRIBUTE_UNUSED)
{
    virDomainSnapshotObjPtr obj = payload;

    virDomainSnapshotObjFree(obj);
}

virDomainSnapshotObjListPtr
virDomainSnapshotObjListNew(void)
{
    virDomainSnapshotObjListPtr snapshots;
    if (VIR_ALLOC(snapshots) < 0)
        return NULL;
    snapshots->objs = virHashCreate(50, virDomainSnapshotObjListDataFree);
    if (!snapshots->objs) {
        VIR_FREE(snapshots);
        return NULL;
    }
    return snapshots;
}

void
virDomainSnapshotObjListFree(virDomainSnapshotObjListPtr snapshots)
{
    if (!snapshots)
        return;
    virHashFree(snapshots->objs);
    VIR_FREE(snapshots);
}

struct virDomainSnapshotNameData {
    char **const names;
    int maxnames;
    unsigned int flags;
    int count;
    bool error;
};

static int virDomainSnapshotObjListCopyNames(void *payload,
                                             const void *name ATTRIBUTE_UNUSED,
                                             void *opaque)
{
    virDomainSnapshotObjPtr obj = payload;
    struct virDomainSnapshotNameData *data = opaque;

    if (data->error)
        return 0;
    /* Caller already sanitized flags.  Filtering on DESCENDANTS was
     * done by choice of iteration in the caller.  */
    if ((data->flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES) && obj->nchildren)
        return 0;
    if ((data->flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES) && !obj->nchildren)
        return 0;

    if (data->flags & VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS) {
        if (!(data->flags & VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE) &&
            obj->def->state == VIR_DOMAIN_SHUTOFF)
            return 0;
        if (!(data->flags & VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY) &&
            obj->def->state == VIR_DOMAIN_DISK_SNAPSHOT)
            return 0;
        if (!(data->flags & VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE) &&
            obj->def->state != VIR_DOMAIN_SHUTOFF &&
            obj->def->state != VIR_DOMAIN_DISK_SNAPSHOT)
            return 0;
    }

    if ((data->flags & VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL) &&
        virDomainSnapshotIsExternal(obj))
        return 0;
    if ((data->flags & VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL) &&
        !virDomainSnapshotIsExternal(obj))
        return 0;

    if (data->names && data->count < data->maxnames &&
        VIR_STRDUP(data->names[data->count], obj->def->name) < 0) {
        data->error = true;
        return 0;
    }
    data->count++;
    return 0;
}

int
virDomainSnapshotObjListGetNames(virDomainSnapshotObjListPtr snapshots,
                                 virDomainSnapshotObjPtr from,
                                 char **const names, int maxnames,
                                 unsigned int flags)
{
    struct virDomainSnapshotNameData data = { names, maxnames, flags, 0,
                                              false };
    size_t i;

    if (!from) {
        /* LIST_ROOTS and LIST_DESCENDANTS have the same bit value,
         * but opposite semantics.  Toggle here to get the correct
         * traversal on the metaroot.  */
        flags ^= VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
        from = &snapshots->metaroot;
    }

    /* We handle LIST_ROOT/LIST_DESCENDANTS directly, mask that bit
     * out to determine when we must use the filter callback.  */
    data.flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;

    /* If this common code is being used, we assume that all snapshots
     * have metadata, and thus can handle METADATA up front as an
     * all-or-none filter.  XXX This might not always be true, if we
     * add the ability to track qcow2 internal snapshots without the
     * use of metadata.  */
    if ((data.flags & VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA) ==
        VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA)
        return 0;
    data.flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA;

    /* For ease of coding the visitor, it is easier to zero each group
     * where all of the bits are set.  */
    if ((data.flags & VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES)
        data.flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES;
    if ((data.flags & VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS)
        data.flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS;
    if ((data.flags & VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)
        data.flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION;

    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS) {
        if (from->def)
            virDomainSnapshotForEachDescendant(from,
                                               virDomainSnapshotObjListCopyNames,
                                               &data);
        else if (names || data.flags)
            virHashForEach(snapshots->objs, virDomainSnapshotObjListCopyNames,
                           &data);
        else
            data.count = virHashSize(snapshots->objs);
    } else if (names || data.flags) {
        virDomainSnapshotForEachChild(from,
                                      virDomainSnapshotObjListCopyNames, &data);
    } else {
        data.count = from->nchildren;
    }

    if (data.error) {
        for (i = 0; i < data.count; i++)
            VIR_FREE(names[i]);
        return -1;
    }

    return data.count;
}

int
virDomainSnapshotObjListNum(virDomainSnapshotObjListPtr snapshots,
                            virDomainSnapshotObjPtr from,
                            unsigned int flags)
{
    return virDomainSnapshotObjListGetNames(snapshots, from, NULL, 0, flags);
}

virDomainSnapshotObjPtr
virDomainSnapshotFindByName(virDomainSnapshotObjListPtr snapshots,
                            const char *name)
{
    return name ? virHashLookup(snapshots->objs, name) : &snapshots->metaroot;
}

void virDomainSnapshotObjListRemove(virDomainSnapshotObjListPtr snapshots,
                                    virDomainSnapshotObjPtr snapshot)
{
    virHashRemoveEntry(snapshots->objs, snapshot->def->name);
}

int
virDomainSnapshotForEach(virDomainSnapshotObjListPtr snapshots,
                         virHashIterator iter,
                         void *data)
{
    return virHashForEach(snapshots->objs, iter, data);
}

/* Run iter(data) on all direct children of snapshot, while ignoring all
 * other entries in snapshots.  Return the number of children
 * visited.  No particular ordering is guaranteed.  */
int
virDomainSnapshotForEachChild(virDomainSnapshotObjPtr snapshot,
                              virHashIterator iter,
                              void *data)
{
    virDomainSnapshotObjPtr child = snapshot->first_child;

    while (child) {
        virDomainSnapshotObjPtr next = child->sibling;
        (iter)(child, child->def->name, data);
        child = next;
    }

    return snapshot->nchildren;
}

struct snapshot_act_on_descendant {
    int number;
    virHashIterator iter;
    void *data;
};

static int
virDomainSnapshotActOnDescendant(void *payload,
                                 const void *name,
                                 void *data)
{
    virDomainSnapshotObjPtr obj = payload;
    struct snapshot_act_on_descendant *curr = data;

    curr->number += 1 + virDomainSnapshotForEachDescendant(obj,
                                                           curr->iter,
                                                           curr->data);
    (curr->iter)(payload, name, curr->data);
    return 0;
}

/* Run iter(data) on all descendants of snapshot, while ignoring all
 * other entries in snapshots.  Return the number of descendants
 * visited.  No particular ordering is guaranteed.  */
int
virDomainSnapshotForEachDescendant(virDomainSnapshotObjPtr snapshot,
                                   virHashIterator iter,
                                   void *data)
{
    struct snapshot_act_on_descendant act;

    act.number = 0;
    act.iter = iter;
    act.data = data;
    virDomainSnapshotForEachChild(snapshot,
                                  virDomainSnapshotActOnDescendant, &act);

    return act.number;
}

/* Struct and callback function used as a hash table callback; each call
 * inspects the pre-existing snapshot->def->parent field, and adjusts
 * the snapshot->parent field as well as the parent's child fields to
 * wire up the hierarchical relations for the given snapshot.  The error
 * indicator gets set if a parent is missing or a requested parent would
 * cause a circular parent chain.  */
struct snapshot_set_relation {
    virDomainSnapshotObjListPtr snapshots;
    int err;
};
static int
virDomainSnapshotSetRelations(void *payload,
                              const void *name ATTRIBUTE_UNUSED,
                              void *data)
{
    virDomainSnapshotObjPtr obj = payload;
    struct snapshot_set_relation *curr = data;
    virDomainSnapshotObjPtr tmp;

    obj->parent = virDomainSnapshotFindByName(curr->snapshots,
                                              obj->def->parent);
    if (!obj->parent) {
        curr->err = -1;
        obj->parent = &curr->snapshots->metaroot;
        VIR_WARN("snapshot %s lacks parent", obj->def->name);
    } else {
        tmp = obj->parent;
        while (tmp && tmp->def) {
            if (tmp == obj) {
                curr->err = -1;
                obj->parent = &curr->snapshots->metaroot;
                VIR_WARN("snapshot %s in circular chain", obj->def->name);
                break;
            }
            tmp = tmp->parent;
        }
    }
    obj->parent->nchildren++;
    obj->sibling = obj->parent->first_child;
    obj->parent->first_child = obj;
    return 0;
}

/* Populate parent link and child count of all snapshots, with all
 * relations starting as 0/NULL.  Return 0 on success, -1 if a parent
 * is missing or if a circular relationship was requested.  */
int
virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots)
{
    struct snapshot_set_relation act = { snapshots, 0 };

    virHashForEach(snapshots->objs, virDomainSnapshotSetRelations, &act);
    return act.err;
}

/* Prepare to reparent or delete snapshot, by removing it from its
 * current listed parent.  Note that when bulk removing all children
 * of a parent, it is faster to just 0 the count rather than calling
 * this function on each child.  */
void
virDomainSnapshotDropParent(virDomainSnapshotObjPtr snapshot)
{
    virDomainSnapshotObjPtr prev = NULL;
    virDomainSnapshotObjPtr curr = NULL;

    snapshot->parent->nchildren--;
    curr = snapshot->parent->first_child;
    while (curr != snapshot) {
        if (!curr) {
            VIR_WARN("inconsistent snapshot relations");
            return;
        }
        prev = curr;
        curr = curr->sibling;
    }
    if (prev)
        prev->sibling = snapshot->sibling;
    else
        snapshot->parent->first_child = snapshot->sibling;
    snapshot->parent = NULL;
    snapshot->sibling = NULL;
}

int
virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                       virDomainSnapshotObjPtr from,
                       virDomainPtr dom,
                       virDomainSnapshotPtr **snaps,
                       unsigned int flags)
{
    int count = virDomainSnapshotObjListNum(snapshots, from, flags);
    virDomainSnapshotPtr *list = NULL;
    char **names;
    int ret = -1;
    size_t i;

    if (!snaps || count < 0)
        return count;
    if (VIR_ALLOC_N(names, count) < 0 ||
        VIR_ALLOC_N(list, count + 1) < 0)
        goto cleanup;

    if (virDomainSnapshotObjListGetNames(snapshots, from, names, count,
                                         flags) < 0)
        goto cleanup;
    for (i = 0; i < count; i++)
        if ((list[i] = virGetDomainSnapshot(dom, names[i])) == NULL)
            goto cleanup;

    ret = count;
    *snaps = list;

 cleanup:
    for (i = 0; i < count; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);
    if (ret < 0 && list) {
        for (i = 0; i < count; i++)
            virObjectUnref(list[i]);
        VIR_FREE(list);
    }
    return ret;
}


bool
virDomainSnapshotDefIsExternal(virDomainSnapshotDefPtr def)
{
    size_t i;

    if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
        return true;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i].snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL)
            return true;
    }

    return false;
}

bool
virDomainSnapshotIsExternal(virDomainSnapshotObjPtr snap)
{
    return virDomainSnapshotDefIsExternal(snap->def);
}

int
virDomainSnapshotRedefinePrep(virDomainPtr domain,
                              virDomainObjPtr vm,
                              virDomainSnapshotDefPtr *defptr,
                              virDomainSnapshotObjPtr *snap,
                              virDomainXMLOptionPtr xmlopt,
                              bool *update_current,
                              unsigned int flags)
{
    virDomainSnapshotDefPtr def = *defptr;
    int ret = -1;
    int align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    bool align_match = true;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainSnapshotObjPtr other;

    virUUIDFormat(domain->uuid, uuidstr);

    /* Prevent circular chains */
    if (def->parent) {
        if (STREQ(def->name, def->parent)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot set snapshot %s as its own parent"),
                           def->name);
            goto cleanup;
        }
        other = virDomainSnapshotFindByName(vm->snapshots, def->parent);
        if (!other) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("parent %s for snapshot %s not found"),
                           def->parent, def->name);
            goto cleanup;
        }
        while (other->def->parent) {
            if (STREQ(other->def->parent, def->name)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("parent %s would create cycle to %s"),
                               other->def->name, def->name);
                goto cleanup;
            }
            other = virDomainSnapshotFindByName(vm->snapshots,
                                                other->def->parent);
            if (!other) {
                VIR_WARN("snapshots are inconsistent for %s",
                         vm->def->name);
                break;
            }
        }
    }

    /* Check that any replacement is compatible */
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) &&
        def->state != VIR_DOMAIN_DISK_SNAPSHOT) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk-only flag for snapshot %s requires "
                         "disk-snapshot state"),
                       def->name);
        goto cleanup;

    }

    if (def->dom &&
        memcmp(def->dom->uuid, domain->uuid, VIR_UUID_BUFLEN)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("definition for snapshot %s must use uuid %s"),
                       def->name, uuidstr);
        goto cleanup;
    }

    other = virDomainSnapshotFindByName(vm->snapshots, def->name);
    if (other) {
        if ((other->def->state == VIR_DOMAIN_RUNNING ||
             other->def->state == VIR_DOMAIN_PAUSED) !=
            (def->state == VIR_DOMAIN_RUNNING ||
             def->state == VIR_DOMAIN_PAUSED)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between online and offline "
                             "snapshot state in snapshot %s"),
                           def->name);
            goto cleanup;
        }

        if ((other->def->state == VIR_DOMAIN_DISK_SNAPSHOT) !=
            (def->state == VIR_DOMAIN_DISK_SNAPSHOT)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between disk snapshot and "
                             "system checkpoint in snapshot %s"),
                           def->name);
            goto cleanup;
        }

        if (other->def->dom) {
            if (def->dom) {
                if (!virDomainDefCheckABIStability(other->def->dom,
                                                   def->dom, xmlopt))
                    goto cleanup;
            } else {
                /* Transfer the domain def */
                def->dom = other->def->dom;
                other->def->dom = NULL;
            }
        }

        if (def->dom) {
            if (def->state == VIR_DOMAIN_DISK_SNAPSHOT ||
                virDomainSnapshotDefIsExternal(def)) {
                align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
                align_match = false;
            }

            if (virDomainSnapshotAlignDisks(def, align_location,
                                            align_match) < 0) {
                /* revert stealing of the snapshot domain definition */
                if (def->dom && !other->def->dom) {
                    other->def->dom = def->dom;
                    def->dom = NULL;
                }
                goto cleanup;
            }
        }

        if (other == vm->current_snapshot) {
            *update_current = true;
            vm->current_snapshot = NULL;
        }

        /* Drop and rebuild the parent relationship, but keep all
         * child relations by reusing snap.  */
        virDomainSnapshotDropParent(other);
        virDomainSnapshotDefFree(other->def);
        other->def = def;
        *defptr = NULL;
        *snap = other;
    } else {
        if (def->dom) {
            if (def->state == VIR_DOMAIN_DISK_SNAPSHOT ||
                def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
                align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
                align_match = false;
            }
            if (virDomainSnapshotAlignDisks(def, align_location,
                                            align_match) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}
