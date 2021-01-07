/*
 * snapshot_conf.c: domain snapshot XML processing
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

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "configmake.h"
#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
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
#include "virdomainsnapshotobjlist.h"

#define LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW
#include "snapshot_conf_priv.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.snapshot_conf");

static virClassPtr virDomainSnapshotDefClass;
static void virDomainSnapshotDefDispose(void *obj);

static int
virDomainSnapshotOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainSnapshotDef, virClassForDomainMomentDef()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainSnapshot);

VIR_ENUM_IMPL(virDomainSnapshotLocation,
              VIR_DOMAIN_SNAPSHOT_LOCATION_LAST,
              "default",
              "no",
              "internal",
              "external",
);

/* virDomainSnapshotState is really virDomainState plus one extra state */
VIR_ENUM_IMPL(virDomainSnapshotState,
              VIR_DOMAIN_SNAPSHOT_LAST,
              "nostate",
              "running",
              "blocked",
              "paused",
              "shutdown",
              "shutoff",
              "crashed",
              "pmsuspended",
              "disk-snapshot",
);

/* Snapshot Def functions */
static void
virDomainSnapshotDiskDefClear(virDomainSnapshotDiskDefPtr disk)
{
    VIR_FREE(disk->name);
    virObjectUnref(disk->src);
    disk->src = NULL;
}

void
virDomainSnapshotDiskDefFree(virDomainSnapshotDiskDefPtr disk)
{
    if (!disk)
        return;

    virDomainSnapshotDiskDefClear(disk);
    VIR_FREE(disk);
}


/* Allocate a new virDomainSnapshotDef; free with virObjectUnref() */
virDomainSnapshotDefPtr
virDomainSnapshotDefNew(void)
{
    if (virDomainSnapshotInitialize() < 0)
        return NULL;

    return virObjectNew(virDomainSnapshotDefClass);
}

static void
virDomainSnapshotDefDispose(void *obj)
{
    virDomainSnapshotDefPtr def = obj;
    size_t i;

    VIR_FREE(def->file);
    for (i = 0; i < def->ndisks; i++)
        virDomainSnapshotDiskDefClear(&def->disks[i]);
    VIR_FREE(def->disks);
    virObjectUnref(def->cookie);
}

int
virDomainSnapshotDiskDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainSnapshotDiskDefPtr def,
                                 unsigned int flags,
                                 virDomainXMLOptionPtr xmlopt)
{
    int ret = -1;
    char *snapshot = NULL;
    char *type = NULL;
    char *driver = NULL;
    xmlNodePtr cur;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    def->src = virStorageSourceNew();
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
        virDomainStorageSourceParse(cur, ctxt, def->src, flags, xmlopt) < 0)
        goto cleanup;

    if ((driver = virXPathString("string(./driver/@type)", ctxt)) &&
        (def->src->format = virStorageFileFormatTypeFromString(driver)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk snapshot driver '%s'"), driver);
            goto cleanup;
    }

    if (virParseScaledValue("./driver/metadata_cache/max_size", NULL,
                            ctxt,
                            &def->src->metadataCacheMaxSize,
                            1, ULLONG_MAX, false) < 0)
        goto cleanup;

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

    VIR_FREE(driver);
    VIR_FREE(snapshot);
    VIR_FREE(type);
    if (ret < 0)
        virDomainSnapshotDiskDefClear(def);
    return ret;
}

/* flags is bitwise-or of virDomainSnapshotParseFlags.
 * If flags does not include
 * VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL, then current is ignored.
 */
static virDomainSnapshotDefPtr
virDomainSnapshotDefParse(xmlXPathContextPtr ctxt,
                          virDomainXMLOptionPtr xmlopt,
                          void *parseOpaque,
                          bool *current,
                          unsigned int flags)
{
    virDomainSnapshotDefPtr def = NULL;
    virDomainSnapshotDefPtr ret = NULL;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr inactiveDomNode = NULL;
    size_t i;
    int n;
    char *state = NULL;
    int active;
    char *tmp;
    char *memorySnapshot = NULL;
    char *memoryFile = NULL;
    bool offline = !!(flags & VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE);
    virSaveCookieCallbacksPtr saveCookie = virDomainXMLOptionGetSaveCookie(xmlopt);
    int domainflags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;

    if (!(def = virDomainSnapshotDefNew()))
        return NULL;

    def->parent.name = virXPathString("string(./name)", ctxt);
    if (def->parent.name == NULL) {
        if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("a redefined snapshot must have a name"));
            goto cleanup;
        }
    }

    def->parent.description = virXPathString("string(./description)", ctxt);

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        if (virXPathLongLong("string(./creationTime)", ctxt,
                             &def->parent.creationTime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing creationTime from existing snapshot"));
            goto cleanup;
        }

        def->parent.parent_name = virXPathString("string(./parent/name)", ctxt);

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
        if (def->state <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid state '%s' in domain snapshot XML"),
                           state);
            goto cleanup;
        }
        offline = (def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF ||
                   def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT);

        /* Older snapshots were created with just <domain>/<uuid>, and
         * lack domain/@type.  In that case, leave dom NULL, and
         * clients will have to decide between best effort
         * initialization or outright failure.  */
        if ((tmp = virXPathString("string(./domain/@type)", ctxt))) {
            xmlNodePtr domainNode = virXPathNode("./domain", ctxt);

            VIR_FREE(tmp);
            if (!domainNode) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing domain in snapshot"));
                goto cleanup;
            }
            def->parent.dom = virDomainDefParseNode(ctxt->node->doc, domainNode,
                                                    xmlopt, parseOpaque,
                                                    domainflags);
            if (!def->parent.dom)
                goto cleanup;
        } else {
            VIR_WARN("parsing older snapshot that lacks domain");
        }

        /* /inactiveDomain entry saves the config XML present in a running
         * VM. In case of absent, leave parent.inactiveDom NULL and use
         * parent.dom for config and live XML. */
        if ((inactiveDomNode = virXPathNode("./inactiveDomain", ctxt))) {
            def->parent.inactiveDom = virDomainDefParseNode(ctxt->node->doc, inactiveDomNode,
                                                            xmlopt, NULL, domainflags);
            if (!def->parent.inactiveDom)
                goto cleanup;
        }
    } else if (virDomainXMLOptionRunMomentPostParse(xmlopt, &def->parent) < 0) {
        goto cleanup;
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
    def->file = g_steal_pointer(&memoryFile);

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
        if (n)
            def->disks = g_new0(virDomainSnapshotDiskDef, n);
        def->ndisks = n;
        for (i = 0; i < def->ndisks; i++) {
            if (virDomainSnapshotDiskDefParseXML(nodes[i], ctxt, &def->disks[i],
                                                 flags, xmlopt) < 0)
                goto cleanup;
        }
        VIR_FREE(nodes);
    } else if (n) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("unable to handle disk requests in snapshot"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL) {
        if (!current) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("internal parse requested with NULL current"));
            goto cleanup;
        }
        if (virXPathInt("string(./active)", ctxt, &active) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find 'active' element"));
            goto cleanup;
        }
        *current = active != 0;
    }

    if (!offline && virSaveCookieParse(ctxt, &def->cookie, saveCookie) < 0)
        goto cleanup;

    ret = g_steal_pointer(&def);

 cleanup:
    VIR_FREE(state);
    VIR_FREE(nodes);
    VIR_FREE(memorySnapshot);
    VIR_FREE(memoryFile);
    virObjectUnref(def);

    return ret;
}

virDomainSnapshotDefPtr
virDomainSnapshotDefParseNode(xmlDocPtr xml,
                              xmlNodePtr root,
                              virDomainXMLOptionPtr xmlopt,
                              void *parseOpaque,
                              bool *current,
                              unsigned int flags)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (!virXMLNodeNameEqual(root, "domainsnapshot")) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("domainsnapshot"));
        return NULL;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_VALIDATE) {
        g_autofree char *schema = NULL;

        schema = virFileFindResource("domainsnapshot.rng",
                                     abs_top_srcdir "/docs/schemas",
                                     PKGDATADIR "/schemas");
        if (!schema)
            return NULL;
        if (virXMLValidateAgainstSchema(schema, xml) < 0)
            return NULL;
    }

    if (!(ctxt = virXMLXPathContextNew(xml)))
        return NULL;

    ctxt->node = root;
    return virDomainSnapshotDefParse(ctxt, xmlopt, parseOpaque, current, flags);
}

virDomainSnapshotDefPtr
virDomainSnapshotDefParseString(const char *xmlStr,
                                virDomainXMLOptionPtr xmlopt,
                                void *parseOpaque,
                                bool *current,
                                unsigned int flags)
{
    virDomainSnapshotDefPtr ret = NULL;
    xmlDocPtr xml;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(NULL, xmlStr, _("(domain_snapshot)")))) {
        xmlKeepBlanksDefault(keepBlanksDefault);
        ret = virDomainSnapshotDefParseNode(xml, xmlDocGetRootElement(xml),
                                            xmlopt, parseOpaque,
                                            current, flags);
        xmlFreeDoc(xml);
    }
    xmlKeepBlanksDefault(keepBlanksDefault);

    return ret;
}


/* Perform sanity checking on a redefined snapshot definition. If
 * @other is non-NULL, this may include swapping def->parent.dom from other
 * into def. */
int
virDomainSnapshotRedefineValidate(virDomainSnapshotDefPtr def,
                                  const unsigned char *domain_uuid,
                                  virDomainMomentObjPtr other,
                                  virDomainXMLOptionPtr xmlopt,
                                  unsigned int flags)
{
    int align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    bool align_match = true;
    bool external = def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT ||
        virDomainSnapshotDefIsExternal(def);

    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) && !external) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk-only flag for snapshot %s requires "
                         "disk-snapshot state"),
                       def->parent.name);
        return -1;
    }
    if (def->parent.dom && memcmp(def->parent.dom->uuid, domain_uuid,
                                  VIR_UUID_BUFLEN)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(domain_uuid, uuidstr);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("definition for snapshot %s must use uuid %s"),
                       def->parent.name, uuidstr);
        return -1;
    }

    if (other) {
        virDomainSnapshotDefPtr otherdef = virDomainSnapshotObjGetDef(other);

        if ((otherdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
             otherdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED) !=
            (def->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
             def->state == VIR_DOMAIN_SNAPSHOT_PAUSED)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between online and offline "
                             "snapshot state in snapshot %s"),
                           def->parent.name);
            return -1;
        }

        if ((otherdef->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT) !=
            (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between disk only and "
                             "full system in snapshot %s"),
                           def->parent.name);
            return -1;
        }

        if (otherdef->parent.dom) {
            if (def->parent.dom) {
                if (!virDomainDefCheckABIStability(otherdef->parent.dom,
                                                   def->parent.dom, xmlopt))
                    return -1;
            } else {
                /* Transfer the domain def */
                def->parent.dom = g_steal_pointer(&otherdef->parent.dom);
            }
        }
    }

    if (def->parent.dom) {
        if (external) {
            align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
            align_match = false;
        }
        if (virDomainSnapshotAlignDisks(def, align_location,
                                        align_match) < 0)
            return -1;
    }


    return 0;
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

        if (!(origpath = virDomainDiskGetSource(def->parent.dom->disks[i]))) {
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

        tmppath = g_strdup(origpath);

        /* drop suffix of the file name */
        if ((tmp = strrchr(tmppath, '.')) && !strchr(tmp, '/'))
            *tmp = '\0';

        disk->src->path = g_strdup_printf("%s.%s", tmppath, def->parent.name);

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


/* Align def->disks to def->parent.dom.  Sort the list of def->disks,
 * filling in any missing disks or snapshot state defaults given by
 * the domain, with a fallback to a passed in default.  Convert paths
 * to disk targets for uniformity.  Issue an error and return -1 if
 * any def->disks[n]->name appears more than once or does not map to
 * dom->disks.  If require_match, also ensure that there is no
 * conflicting requests for both internal and external snapshots.  */
int
virDomainSnapshotAlignDisks(virDomainSnapshotDefPtr snapdef,
                            int default_snapshot,
                            bool require_match)
{
    virDomainDefPtr domdef = snapdef->parent.dom;
    g_autoptr(GHashTable) map = virHashNew(NULL);
    g_autofree virDomainSnapshotDiskDefPtr olddisks = NULL;
    size_t i;

    if (!domdef) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing domain in snapshot"));
        return -1;
    }

    if (snapdef->ndisks > domdef->ndisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("too many disk snapshot requests for domain"));
        return -1;
    }

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!domdef->ndisks)
        return 0;

    /* Double check requested disks.  */
    for (i = 0; i < snapdef->ndisks; i++) {
        virDomainSnapshotDiskDefPtr snapdisk = &snapdef->disks[i];
        virDomainDiskDefPtr domdisk = virDomainDiskByName(domdef, snapdisk->name, false);

        if (!domdisk) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%s'"), snapdisk->name);
            return -1;
        }

        if (virHashHasEntry(map, domdisk->dst)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' specified twice"),
                           snapdisk->name);
            return -1;
        }

        if (virHashAddEntry(map, domdisk->dst, snapdisk) < 0)
            return -1;

        if (snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) {
            if (domdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
                (!require_match ||
                 domdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)) {
                snapdisk->snapshot = domdisk->snapshot;
            } else {
                snapdisk->snapshot = default_snapshot;
            }
        } else if (require_match &&
                   snapdisk->snapshot != default_snapshot &&
                   !(snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE &&
                     domdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NONE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' must use snapshot mode '%s'"),
                           snapdisk->name,
                           virDomainSnapshotLocationTypeToString(default_snapshot));
            return -1;
        }

        if (snapdisk->src->path &&
            snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("file '%s' for disk '%s' requires "
                             "use of external snapshot mode"),
                           snapdisk->src->path, snapdisk->name);
            return -1;
        }
        if (STRNEQ(snapdisk->name, domdisk->dst)) {
            VIR_FREE(snapdisk->name);
            snapdisk->name = g_strdup(domdisk->dst);
        }
    }

    olddisks = g_steal_pointer(&snapdef->disks);
    snapdef->disks = g_new0(virDomainSnapshotDiskDef, domdef->ndisks);
    snapdef->ndisks = domdef->ndisks;

    for (i = 0; i < domdef->ndisks; i++) {
        virDomainDiskDefPtr domdisk = domdef->disks[i];
        virDomainSnapshotDiskDefPtr snapdisk = snapdef->disks + i;
        virDomainSnapshotDiskDefPtr existing;

        /* copy existing disks */
        if ((existing = virHashLookup(map, domdisk->dst))) {
            memcpy(snapdisk, existing, sizeof(*snapdisk));
            continue;
        }

        /* Provide defaults for all remaining disks. */
        snapdisk->src = virStorageSourceNew();
        snapdisk->name = g_strdup(domdef->disks[i]->dst);

        /* Don't snapshot empty drives */
        if (virStorageSourceIsEmpty(domdef->disks[i]->src))
            snapdisk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
        else
            snapdisk->snapshot = domdef->disks[i]->snapshot;

        snapdisk->src->type = VIR_STORAGE_TYPE_FILE;
        if (!snapdisk->snapshot)
            snapdisk->snapshot = default_snapshot;
    }

    /* Generate default external file names for external snapshot locations */
    if (virDomainSnapshotDefAssignExternalNames(snapdef) < 0)
        return -1;

    return 0;
}


/* Converts public VIR_DOMAIN_SNAPSHOT_XML_* into
 * VIR_DOMAIN_SNAPSHOT_FORMAT_* flags, and silently ignores any other
 * flags. */
unsigned int
virDomainSnapshotFormatConvertXMLFlags(unsigned int flags)
{
    unsigned int formatFlags = 0;

    if (flags & VIR_DOMAIN_SNAPSHOT_XML_SECURE)
        formatFlags |= VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE;

    return formatFlags;
}


static int
virDomainSnapshotDiskDefFormat(virBufferPtr buf,
                               virDomainSnapshotDiskDefPtr disk,
                               virDomainXMLOptionPtr xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!disk->name)
        return 0;

    virBufferEscapeString(&attrBuf, " name='%s'", disk->name);
    if (disk->snapshot > 0)
        virBufferAsprintf(&attrBuf, " snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(disk->snapshot));

    if (disk->src->path || disk->src->format != 0) {
        g_auto(virBuffer) driverAttrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) driverChildBuf = VIR_BUFFER_INIT_CHILD(&childBuf);

        virBufferAsprintf(&attrBuf, " type='%s'", virStorageTypeToString(disk->src->type));

        if (disk->src->format > 0)
            virBufferEscapeString(&driverAttrBuf, " type='%s'",
                                  virStorageFileFormatTypeToString(disk->src->format));

        if (disk->src->metadataCacheMaxSize > 0) {
            g_auto(virBuffer) metadataCacheChildBuf = VIR_BUFFER_INIT_CHILD(&driverChildBuf);

            virBufferAsprintf(&metadataCacheChildBuf,
                              "<max_size unit='bytes'>%llu</max_size>\n",
                              disk->src->metadataCacheMaxSize);

            virXMLFormatElement(&driverChildBuf, "metadata_cache", NULL, &metadataCacheChildBuf);
        }

        virXMLFormatElement(&childBuf, "driver", &driverAttrBuf, &driverChildBuf);

        if (virDomainDiskSourceFormat(&childBuf, disk->src, "source", 0, false, 0,
                                      false, false, xmlopt) < 0)
        return -1;
    }

    virXMLFormatElement(buf, "disk", &attrBuf, &childBuf);
    return 0;
}


/* Append XML describing def into buf. Return 0 on success, or -1 on
 * failure with buf cleared. */
static int
virDomainSnapshotDefFormatInternal(virBufferPtr buf,
                                   const char *uuidstr,
                                   virDomainSnapshotDefPtr def,
                                   virDomainXMLOptionPtr xmlopt,
                                   unsigned int flags)
{
    size_t i;
    int domainflags = VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    if (flags & VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE)
        domainflags |= VIR_DOMAIN_DEF_FORMAT_SECURE;

    virBufferAddLit(buf, "<domainsnapshot>\n");
    virBufferAdjustIndent(buf, 2);

    virBufferEscapeString(buf, "<name>%s</name>\n", def->parent.name);
    if (def->parent.description)
        virBufferEscapeString(buf, "<description>%s</description>\n",
                              def->parent.description);
    if (def->state)
        virBufferAsprintf(buf, "<state>%s</state>\n",
                          virDomainSnapshotStateTypeToString(def->state));

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

    if (def->memory) {
        virBufferAsprintf(buf, "<memory snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(def->memory));
        virBufferEscapeString(buf, " file='%s'", def->file);
        virBufferAddLit(buf, "/>\n");
    }

    if (def->ndisks) {
        virBufferAddLit(buf, "<disks>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < def->ndisks; i++) {
            if (virDomainSnapshotDiskDefFormat(buf, &def->disks[i], xmlopt) < 0)
                return -1;
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</disks>\n");
    }

    if (def->parent.dom) {
        if (virDomainDefFormatInternal(def->parent.dom, xmlopt,
                                       buf, domainflags) < 0)
            return -1;
    } else if (uuidstr) {
        virBufferAddLit(buf, "<domain>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</domain>\n");
    }

    if (def->parent.inactiveDom) {
        if (virDomainDefFormatInternalSetRootName(def->parent.inactiveDom, xmlopt,
                                                  buf, "inactiveDomain",
                                                  domainflags) < 0)
            return -1;
    }

    if (virSaveCookieFormatBuf(buf, def->cookie,
                               virDomainXMLOptionGetSaveCookie(xmlopt)) < 0)
        return -1;

    if (flags & VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL)
        virBufferAsprintf(buf, "<active>%d</active>\n",
                          !!(flags & VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT));

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</domainsnapshot>\n");

    return 0;
}


char *
virDomainSnapshotDefFormat(const char *uuidstr,
                           virDomainSnapshotDefPtr def,
                           virDomainXMLOptionPtr xmlopt,
                           unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE |
                  VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL |
                  VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT, NULL);
    if (virDomainSnapshotDefFormatInternal(&buf, uuidstr, def,
                                           xmlopt, flags) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
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
virDomainSnapshotIsExternal(virDomainMomentObjPtr snap)
{
    virDomainSnapshotDefPtr def = virDomainSnapshotObjGetDef(snap);

    return virDomainSnapshotDefIsExternal(def);
}

int
virDomainSnapshotRedefinePrep(virDomainObjPtr vm,
                              virDomainSnapshotDefPtr *defptr,
                              virDomainMomentObjPtr *snap,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags)
{
    virDomainSnapshotDefPtr def = *defptr;
    virDomainMomentObjPtr other;
    virDomainSnapshotDefPtr otherdef = NULL;
    bool check_if_stolen;

    if (virDomainSnapshotCheckCycles(vm->snapshots, def, vm->def->name) < 0)
        return -1;

    other = virDomainSnapshotFindByName(vm->snapshots, def->parent.name);
    if (other)
        otherdef = virDomainSnapshotObjGetDef(other);
    check_if_stolen = other && otherdef->parent.dom;
    if (virDomainSnapshotRedefineValidate(def, vm->def->uuid, other, xmlopt,
                                          flags) < 0) {
        /* revert any stealing of the snapshot domain definition */
        if (check_if_stolen && def->parent.dom && !otherdef->parent.dom)
            otherdef->parent.dom = g_steal_pointer(&def->parent.dom);
        return -1;
    }
    if (other) {
        /* Drop and rebuild the parent relationship, but keep all
         * child relations by reusing snap. */
        virDomainMomentDropParent(other);
        virObjectUnref(otherdef);
        other->def = &(*defptr)->parent;
        *defptr = NULL;
        *snap = other;
    }

    return 0;
}
