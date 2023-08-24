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
#include "virbuffer.h"
#include "domain_conf.h"
#include "virlog.h"
#include "viralloc.h"
#include "snapshot_conf.h"
#include "storage_source_conf.h"
#include "viruuid.h"
#include "virerror.h"
#include "virxml.h"
#include "virdomainsnapshotobjlist.h"

#define LIBVIRT_SNAPSHOT_CONF_PRIV_H_ALLOW
#include "snapshot_conf_priv.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.snapshot_conf");

static virClass *virDomainSnapshotDefClass;
static void virDomainSnapshotDefDispose(void *obj);

static int
virDomainSnapshotOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainSnapshotDef, virClassForDomainMomentDef()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainSnapshot);

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
void
virDomainSnapshotDiskDefClear(virDomainSnapshotDiskDef *disk)
{
    VIR_FREE(disk->name);
    g_clear_pointer(&disk->src, virObjectUnref);
}

void
virDomainSnapshotDiskDefFree(virDomainSnapshotDiskDef *disk)
{
    if (!disk)
        return;

    virDomainSnapshotDiskDefClear(disk);
    g_free(disk);
}


/* Allocate a new virDomainSnapshotDef; free with virObjectUnref() */
virDomainSnapshotDef *
virDomainSnapshotDefNew(void)
{
    if (virDomainSnapshotInitialize() < 0)
        return NULL;

    return virObjectNew(virDomainSnapshotDefClass);
}

static void
virDomainSnapshotDefDispose(void *obj)
{
    virDomainSnapshotDef *def = obj;
    size_t i;

    g_free(def->memorysnapshotfile);
    for (i = 0; i < def->ndisks; i++)
        virDomainSnapshotDiskDefClear(&def->disks[i]);
    g_free(def->disks);
    for (i = 0; i < def->nrevertdisks; i++)
        virDomainSnapshotDiskDefClear(&def->revertdisks[i]);
    g_free(def->revertdisks);
    virObjectUnref(def->cookie);
}

int
virDomainSnapshotDiskDefParseXML(xmlNodePtr node,
                                 xmlXPathContextPtr ctxt,
                                 virDomainSnapshotDiskDef *def,
                                 unsigned int flags,
                                 virDomainXMLOption *xmlopt)
{
    g_autofree char *driver = NULL;
    g_autofree char *name = NULL;
    g_autoptr(virStorageSource) src = virStorageSourceNew();
    xmlNodePtr cur;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing name from disk snapshot element"));
        return -1;
    }

    if (virXMLPropEnumDefault(node, "snapshot",
                              virDomainSnapshotLocationTypeFromString,
                              VIR_XML_PROP_NONZERO,
                              &def->snapshot,
                              VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) < 0)
        return -1;

    if (virXMLPropEnumDefault(node, "type",
                              virStorageTypeFromString,
                              VIR_XML_PROP_NONZERO,
                              &src->type,
                              VIR_STORAGE_TYPE_FILE) < 0)
        return -1;

    if (src->type == VIR_STORAGE_TYPE_VOLUME ||
        src->type == VIR_STORAGE_TYPE_DIR) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unsupported disk snapshot type '%1$s'"),
                       virStorageTypeToString(src->type));
        return -1;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        def->snapshotDeleteInProgress = !!virXPathNode("./snapshotDeleteInProgress",
                                                       ctxt);
    }

    if ((cur = virXPathNode("./source", ctxt)) &&
        virDomainStorageSourceParse(cur, ctxt, src, flags, xmlopt) < 0)
        return -1;

    if ((driver = virXPathString("string(./driver/@type)", ctxt)) &&
        (src->format = virStorageFileFormatTypeFromString(driver)) <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown disk snapshot driver '%1$s'"), driver);
            return -1;
    }

    if (virParseScaledValue("./driver/metadata_cache/max_size", NULL,
                            ctxt,
                            &src->metadataCacheMaxSize,
                            1, ULLONG_MAX, false) < 0)
        return -1;

    /* validate that the passed path is absolute */
    if (virStorageSourceIsRelative(src)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("disk snapshot image path '%1$s' must be absolute"),
                       src->path);
        return -1;
    }

    if (def->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
        (src->path || src->format))
        def->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;

    def->name = g_steal_pointer(&name);
    def->src = g_steal_pointer(&src);

    return 0;
}

/* flags is bitwise-or of virDomainSnapshotParseFlags.
 * If flags does not include
 * VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL, then current is ignored.
 */
virDomainSnapshotDef *
virDomainSnapshotDefParse(xmlXPathContextPtr ctxt,
                          virDomainXMLOption *xmlopt,
                          void *parseOpaque,
                          bool *current,
                          unsigned int flags)
{
    g_autoptr(virDomainSnapshotDef) def = NULL;
    g_autofree xmlNodePtr *diskNodes = NULL;
    size_t i;
    int n;
    xmlNodePtr memoryNode = NULL;
    bool offline = !!(flags & VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE);
    virSaveCookieCallbacks *saveCookie = virDomainXMLOptionGetSaveCookie(xmlopt);
    int domainflags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;

    if (!(def = virDomainSnapshotDefNew()))
        return NULL;

    def->parent.name = virXPathString("string(./name)", ctxt);
    if (def->parent.name == NULL) {
        if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("a redefined snapshot must have a name"));
            return NULL;
        }
    }

    def->parent.description = virXPathString("string(./description)", ctxt);

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        g_autofree char *state = NULL;
        g_autofree char *domtype = NULL;
        xmlNodePtr inactiveDomNode = NULL;

        if (virXPathLongLong("string(./creationTime)", ctxt,
                             &def->parent.creationTime) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing creationTime from existing snapshot"));
            return NULL;
        }

        def->parent.parent_name = virXPathString("string(./parent/name)", ctxt);

        state = virXPathString("string(./state)", ctxt);
        if (state == NULL) {
            /* there was no state in an existing snapshot; this
             * should never happen
             */
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing state from existing snapshot"));
            return NULL;
        }
        def->state = virDomainSnapshotStateTypeFromString(state);
        if (def->state <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid state '%1$s' in domain snapshot XML"),
                           state);
            return NULL;
        }
        offline = (def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF ||
                   def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT);

        /* Older snapshots were created with just <domain>/<uuid>, and
         * lack domain/@type.  In that case, leave dom NULL, and
         * clients will have to decide between best effort
         * initialization or outright failure.  */
        if ((domtype = virXPathString("string(./domain/@type)", ctxt))) {
            VIR_XPATH_NODE_AUTORESTORE(ctxt)

            if (!(ctxt->node = virXPathNode("./domain", ctxt))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing domain in snapshot"));
                return NULL;
            }

            def->parent.dom = virDomainDefParseNode(ctxt, xmlopt, parseOpaque,
                                                    domainflags);
            if (!def->parent.dom)
                return NULL;
        } else {
            VIR_WARN("parsing older snapshot that lacks domain");
        }

        /* /inactiveDomain entry saves the config XML present in a running
         * VM. In case of absent, leave parent.inactiveDom NULL and use
         * parent.dom for config and live XML. */
        if ((inactiveDomNode = virXPathNode("./inactiveDomain", ctxt))) {
            VIR_XPATH_NODE_AUTORESTORE(ctxt)

            ctxt->node = inactiveDomNode;

            def->parent.inactiveDom = virDomainDefParseNode(ctxt, xmlopt, NULL,
                                                            domainflags);
            if (!def->parent.inactiveDom)
                return NULL;
        }
    } else if (virDomainXMLOptionRunMomentPostParse(xmlopt, &def->parent) < 0) {
        return NULL;
    }

    if ((memoryNode = virXPathNode("./memory", ctxt))) {
        def->memorysnapshotfile = virXMLPropString(memoryNode, "file");

        if (virXMLPropEnumDefault(memoryNode, "snapshot",
                                  virDomainSnapshotLocationTypeFromString,
                                  VIR_XML_PROP_NONZERO,
                                  &def->memory,
                                  VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) < 0)
            return NULL;

        if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_MANUAL) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'manual' memory snapshot mode not supported"));
            return NULL;
        }
    }

    if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) {
        if (def->memorysnapshotfile) {
            def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
        } else if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
            if (offline) {
                def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;
            } else {
                def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
            }
        }
    }

    if (def->memorysnapshotfile &&
        def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("memory filename '%1$s' requires external snapshot"),
                       def->memorysnapshotfile);
        return NULL;
    }

    if (!def->memorysnapshotfile &&
        def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("external memory snapshots require a filename"));
        return NULL;
    }

    if (offline &&
        def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
        def->memory != VIR_DOMAIN_SNAPSHOT_LOCATION_NO) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("memory state cannot be saved with offline or disk-only snapshot"));
        return NULL;
    }

    /* verify that memory path is absolute */
    if (def->memorysnapshotfile && !g_path_is_absolute(def->memorysnapshotfile)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("memory snapshot file path (%1$s) must be absolute"),
                       def->memorysnapshotfile);
        return NULL;
    }

    if ((n = virXPathNodeSet("./disks/*", ctxt, &diskNodes)) < 0)
        return NULL;
    if (n)
        def->disks = g_new0(virDomainSnapshotDiskDef, n);
    def->ndisks = n;
    for (i = 0; i < def->ndisks; i++) {
        if (virDomainSnapshotDiskDefParseXML(diskNodes[i], ctxt, &def->disks[i],
                                             flags, xmlopt) < 0)
            return NULL;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) {
        g_autofree xmlNodePtr *revertDiskNodes = NULL;

        if ((n = virXPathNodeSet("./revertDisks/*", ctxt, &revertDiskNodes)) < 0)
            return NULL;
        if (n)
            def->revertdisks = g_new0(virDomainSnapshotDiskDef, n);
        def->nrevertdisks = n;
        for (i = 0; i < def->nrevertdisks; i++) {
            if (virDomainSnapshotDiskDefParseXML(revertDiskNodes[i], ctxt,
                                                 &def->revertdisks[i],
                                                 flags, xmlopt) < 0)
                return NULL;
        }
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL) {
        int active;

        if (!current) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("internal parse requested with NULL current"));
            return NULL;
        }
        if (virXPathInt("string(./active)", ctxt, &active) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find 'active' element"));
            return NULL;
        }
        *current = active != 0;
    }

    if (!offline && virSaveCookieParse(ctxt, &def->cookie, saveCookie) < 0)
        return NULL;

    return g_steal_pointer(&def);
}


virDomainSnapshotDef *
virDomainSnapshotDefParseString(const char *xmlStr,
                                virDomainXMLOption *xmlopt,
                                void *parseOpaque,
                                bool *current,
                                unsigned int flags)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);
    bool validate = flags & VIR_DOMAIN_SNAPSHOT_PARSE_VALIDATE;

    xml = virXMLParse(NULL, xmlStr, _("(domain_snapshot)"),
                      "domainsnapshot", &ctxt, "domainsnapshot.rng", validate);

    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virDomainSnapshotDefParse(ctxt, xmlopt, parseOpaque, current, flags);
}


/* Perform sanity checking on a redefined snapshot definition. */
static int
virDomainSnapshotRedefineValidate(virDomainSnapshotDef *def,
                                  const unsigned char *domain_uuid,
                                  virDomainMomentObj *other,
                                  virDomainXMLOption *xmlopt,
                                  unsigned int flags)
{
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) &&
        def->state != VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("disk-only flag for snapshot %1$s requires disk-snapshot state"),
                       def->parent.name);
        return -1;
    }
    if (def->parent.dom && memcmp(def->parent.dom->uuid, domain_uuid,
                                  VIR_UUID_BUFLEN)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(domain_uuid, uuidstr);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("definition for snapshot %1$s must use uuid %2$s"),
                       def->parent.name, uuidstr);
        return -1;
    }

    if (other) {
        virDomainSnapshotDef *otherdef = virDomainSnapshotObjGetDef(other);

        if ((otherdef->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
             otherdef->state == VIR_DOMAIN_SNAPSHOT_PAUSED) !=
            (def->state == VIR_DOMAIN_SNAPSHOT_RUNNING ||
             def->state == VIR_DOMAIN_SNAPSHOT_PAUSED)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between online and offline snapshot state in snapshot %1$s"),
                           def->parent.name);
            return -1;
        }

        if ((otherdef->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT) !=
            (def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot change between disk only and full system in snapshot %1$s"),
                           def->parent.name);
            return -1;
        }

        if (otherdef->parent.dom) {
            if (def->parent.dom) {
                if (!virDomainDefCheckABIStability(otherdef->parent.dom,
                                                   def->parent.dom, xmlopt))
                    return -1;
            }
        }
    }

    return 0;
}


/**
 * virDomainSnapshotDefAssignExternalNames:
 * @def: snapshot def object
 * @domdef: domain def object
 *
 * Generate default external file names for snapshot targets. Returns 0 on
 * success, -1 on error.
 */
static int
virDomainSnapshotDefAssignExternalNames(virDomainSnapshotDef *def,
                                        virDomainDef *domdef)
{
    const char *origpath;
    char *tmppath;
    char *tmp;
    struct stat sb;
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        virDomainSnapshotDiskDef *disk = &def->disks[i];

        if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL ||
            disk->src->path)
            continue;

        if (disk->src->type != VIR_STORAGE_TYPE_FILE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot generate external snapshot name for disk '%1$s' on a '%2$s' device"),
                           disk->name, virStorageTypeToString(disk->src->type));
            return -1;
        }

        if (!(origpath = virDomainDiskGetSource(domdef->disks[i]))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot generate external snapshot name for disk '%1$s' without source"),
                           disk->name);
            return -1;
        }

        if (stat(origpath, &sb) < 0 || !S_ISREG(sb.st_mode)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("source for disk '%1$s' is not a regular file; refusing to generate external snapshot name"),
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
                               _("cannot generate external snapshot name for disk '%1$s': collision with disk '%2$s'"),
                               disk->name, def->disks[j].name);
                return -1;
            }
        }
    }

    return 0;
}


/**
 * virDomainSnapshotAlignDisks:
 * @snapdef: Snapshot definition to align
 * @existingDomainDef: definition of the domain belonging to a redefined snapshot
 * @default_snapshot: snapshot location to assign to disks which don't have any
 * @uniform_internal_snapshot: Require that for an internal snapshot all disks
 *                             take part in the internal snapshot
 * @force_default_location: Always use @default_snapshot even if domain def
 *                          has different default value
 *
 * Align snapdef->disks to domain definition, filling in any missing disks or
 * snapshot state defaults given by the domain, with a fallback to
 * @default_snapshot. Ensure that there are no duplicate snapshot disk
 * definitions in @snapdef and there are no disks described in @snapdef but
 * missing from the domain definition.
 *
 * By default the domain definition from @snapdef->parent.dom is used, but when
 * redefining an existing snapshot the domain definition may be omitted in
 * @snapdef. In such case callers must pass in the definition from the snapsot
 * being redefined as @existingDomainDef. In all other cases callers pass NULL.
 *
 * When @uniform_internal_snapshot is true and @default_snapshot is
 * VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL, all disks in @snapdef must take part
 * in the internal snapshot. This is for hypervisors where granularity of an
 * internal snapshot can't be controlled.
 *
 * When @force_default_location is true we will always use @default_snapshot
 * even if domain definition has different default set. This is required to
 * create new snapshot definition when reverting external snapshots.
 *
 * Convert paths to disk targets for uniformity.
 *
 * On error -1 is returned and a libvirt error is reported.
 */
int
virDomainSnapshotAlignDisks(virDomainSnapshotDef *snapdef,
                            virDomainDef *existingDomainDef,
                            virDomainSnapshotLocation default_snapshot,
                            bool uniform_internal_snapshot,
                            bool force_default_location)
{
    virDomainDef *domdef = snapdef->parent.dom;
    g_autoptr(GHashTable) map = virHashNew(NULL);
    g_autofree virDomainSnapshotDiskDef *olddisks = NULL;
    bool require_match = false;
    size_t oldndisks;
    size_t i;

    if (!domdef)
        domdef = existingDomainDef;

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

    if (uniform_internal_snapshot &&
        default_snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL)
        require_match = true;

    /* Unlikely to have a guest without disks but technically possible.  */
    if (!domdef->ndisks)
        return 0;

    olddisks = g_steal_pointer(&snapdef->disks);
    oldndisks = snapdef->ndisks;
    snapdef->disks = g_new0(virDomainSnapshotDiskDef, domdef->ndisks);
    snapdef->ndisks = domdef->ndisks;

    /* Double check requested disks.  */
    for (i = 0; i < oldndisks; i++) {
        virDomainSnapshotDiskDef *snapdisk = &olddisks[i];
        virDomainDiskDef *domdisk = virDomainDiskByName(domdef, snapdisk->name, false);

        if (!domdisk) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no disk named '%1$s'"), snapdisk->name);
            return -1;
        }

        if (virHashHasEntry(map, domdisk->dst)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' specified twice"),
                           snapdisk->name);
            return -1;
        }

        if (virHashAddEntry(map, domdisk->dst, snapdisk) < 0)
            return -1;

        if (snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT) {
            if (domdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT &&
                (!require_match ||
                 domdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NO)) {
                snapdisk->snapshot = domdisk->snapshot;
            } else {
                snapdisk->snapshot = default_snapshot;
            }
        } else if (require_match &&
                   snapdisk->snapshot != default_snapshot &&
                   !(snapdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NO &&
                     domdisk->snapshot == VIR_DOMAIN_SNAPSHOT_LOCATION_NO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%1$s' must use snapshot mode '%2$s'"),
                           snapdisk->name,
                           virDomainSnapshotLocationTypeToString(default_snapshot));
            return -1;
        }

        if (snapdisk->src->path &&
            snapdisk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("file '%1$s' for disk '%2$s' requires use of external snapshot mode"),
                           snapdisk->src->path, snapdisk->name);
            return -1;
        }
        if (STRNEQ(snapdisk->name, domdisk->dst)) {
            VIR_FREE(snapdisk->name);
            snapdisk->name = g_strdup(domdisk->dst);
        }
    }

    for (i = 0; i < domdef->ndisks; i++) {
        virDomainDiskDef *domdisk = domdef->disks[i];
        virDomainSnapshotDiskDef *snapdisk = snapdef->disks + i;
        virDomainSnapshotDiskDef *existing;

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
            snapdisk->snapshot = VIR_DOMAIN_SNAPSHOT_LOCATION_NO;
        else if (!force_default_location)
            snapdisk->snapshot = domdef->disks[i]->snapshot;

        snapdisk->src->type = VIR_STORAGE_TYPE_FILE;
        if (!snapdisk->snapshot)
            snapdisk->snapshot = default_snapshot;
    }

    /* Generate default external file names for external snapshot locations */
    if (virDomainSnapshotDefAssignExternalNames(snapdef, domdef) < 0)
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
virDomainSnapshotDiskDefFormat(virBuffer *buf,
                               virDomainSnapshotDiskDef *disk,
                               virDomainXMLOption *xmlopt)
{
    g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

    if (!disk->name)
        return 0;

    virBufferEscapeString(&attrBuf, " name='%s'", disk->name);
    if (disk->snapshot > 0)
        virBufferAsprintf(&attrBuf, " snapshot='%s'",
                          virDomainSnapshotLocationTypeToString(disk->snapshot));

    if (disk->snapshotDeleteInProgress)
        virBufferAddLit(&childBuf, "<snapshotDeleteInProgress/>\n");

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
virDomainSnapshotDefFormatInternal(virBuffer *buf,
                                   const char *uuidstr,
                                   virDomainSnapshotDef *def,
                                   virDomainXMLOption *xmlopt,
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
        virBufferEscapeString(buf, " file='%s'", def->memorysnapshotfile);
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

    if (def->nrevertdisks > 0) {
        g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

        for (i = 0; i < def->nrevertdisks; i++) {
            if (virDomainSnapshotDiskDefFormat(&childBuf, &def->revertdisks[i], xmlopt) < 0)
                return -1;
        }

        virXMLFormatElement(buf, "revertDisks", NULL, &childBuf);
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
                           virDomainSnapshotDef *def,
                           virDomainXMLOption *xmlopt,
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
virDomainSnapshotDefIsExternal(virDomainSnapshotDef *def)
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
virDomainSnapshotIsExternal(virDomainMomentObj *snap)
{
    virDomainSnapshotDef *def = virDomainSnapshotObjGetDef(snap);

    return virDomainSnapshotDefIsExternal(def);
}

int
virDomainSnapshotRedefinePrep(virDomainObj *vm,
                              virDomainSnapshotDef *snapdef,
                              virDomainMomentObj **snap,
                              virDomainXMLOption *xmlopt,
                              unsigned int flags)
{
    virDomainMomentObj *other;
    virDomainSnapshotDef *otherSnapDef = NULL;
    virDomainDef *otherDomDef = NULL;
    virDomainSnapshotLocation align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;

    if (virDomainSnapshotCheckCycles(vm->snapshots, snapdef, vm->def->name) < 0)
        return -1;

    if ((other = virDomainSnapshotFindByName(vm->snapshots, snapdef->parent.name))) {
        otherSnapDef = virDomainSnapshotObjGetDef(other);
        otherDomDef = otherSnapDef->parent.dom;
    }

    *snap = other;

    if (virDomainSnapshotRedefineValidate(snapdef, vm->def->uuid, other, xmlopt, flags) < 0)
        return -1;

    if (snapdef->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT ||
        virDomainSnapshotDefIsExternal(snapdef))
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;

    if (virDomainSnapshotAlignDisks(snapdef, otherDomDef, align_location,
                                    true, false) < 0) {
        return -1;
    }

    return 0;
}
