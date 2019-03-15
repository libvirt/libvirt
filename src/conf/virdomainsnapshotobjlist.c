/*
 * virdomainsnapshotobjlist.c: handle a tree of snapshot objects
 *                  (derived from snapshot_conf.c)
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

#include "internal.h"
#include "virdomainsnapshotobjlist.h"
#include "snapshot_conf.h"
#include "virlog.h"
#include "virerror.h"
#include "datatypes.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.virdomainsnapshotobjlist");

struct _virDomainSnapshotObjList {
    /* name string -> virDomainSnapshotObj  mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objs;

    virDomainSnapshotObj metaroot; /* Special parent of all root snapshots */
};


/* Parse a <snapshots> XML entry into snapshots, which must start empty.
 * Any <domain> sub-elements of a <domainsnapshot> must match domain_uuid.
 */
int
virDomainSnapshotObjListParse(const char *xmlStr,
                              const unsigned char *domain_uuid,
                              virDomainSnapshotObjListPtr snapshots,
                              virDomainSnapshotObjPtr *current_snap,
                              virCapsPtr caps,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags)
{
    int ret = -1;
    xmlDocPtr xml;
    xmlNodePtr root;
    xmlXPathContextPtr ctxt = NULL;
    int n;
    size_t i;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);
    VIR_AUTOFREE(xmlNodePtr *) nodes = NULL;
    VIR_AUTOFREE(char *) current = NULL;

    if (!(flags & VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE) ||
        (flags & VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("incorrect flags for bulk parse"));
        return -1;
    }
    if (snapshots->metaroot.nchildren || *current_snap) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("bulk define of snapshots only possible with "
                         "no existing snapshot"));
        return -1;
    }

    if (!(xml = virXMLParse(NULL, xmlStr, _("(domain_snapshot)"))))
        return -1;

    root = xmlDocGetRootElement(xml);
    if (!virXMLNodeNameEqual(root, "snapshots")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <snapshots>"), root->name);
        goto cleanup;
    }
    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    ctxt->node = root;
    current = virXMLPropString(root, "current");

    if ((n = virXPathNodeSet("./domainsnapshot", ctxt, &nodes)) < 0)
        goto cleanup;
    if (!n) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("expected at least one <domainsnapshot> child"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        virDomainSnapshotDefPtr def;
        virDomainSnapshotObjPtr snap;

        def = virDomainSnapshotDefParseNode(xml, nodes[i], caps, xmlopt, flags);
        if (!def)
            goto cleanup;
        if (!(snap = virDomainSnapshotAssignDef(snapshots, def))) {
            virDomainSnapshotDefFree(def);
            goto cleanup;
        }
        if (virDomainSnapshotRedefineValidate(def, domain_uuid, NULL, NULL,
                                              flags) < 0)
            goto cleanup;
    }

    if (virDomainSnapshotUpdateRelations(snapshots) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("<snapshots> contains inconsistent parent-child "
                         "relationships"));
        goto cleanup;
    }

    if (current) {
        if (!(*current_snap = virDomainSnapshotFindByName(snapshots,
                                                          current))) {
            virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                           _("no snapshot matching current='%s'"), current);
            goto cleanup;
        }
        (*current_snap)->def->current = true;
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        /* There were no snapshots before this call; so on error, just
         * blindly delete anything created before the failure. */
        virHashRemoveAll(snapshots->objs);
        snapshots->metaroot.nchildren = 0;
        snapshots->metaroot.first_child = NULL;
    }
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlKeepBlanksDefault(keepBlanksDefault);
    return ret;
}


/* Struct and callback function used as a hash table callback; each call
 * appends another snapshot XML to buf, with the caller clearing the
 * buffer if any callback fails. */
struct virDomainSnapshotFormatData {
    virBufferPtr buf;
    const char *uuidstr;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    unsigned int flags;
};

static int
virDomainSnapshotFormatOne(void *payload,
                           const void *name ATTRIBUTE_UNUSED,
                           void *opaque)
{
    virDomainSnapshotObjPtr snap = payload;
    struct virDomainSnapshotFormatData *data = opaque;
    return virDomainSnapshotDefFormatInternal(data->buf, data->uuidstr,
                                              snap->def, data->caps,
                                              data->xmlopt, data->flags);
}


/* Format the XML for all snapshots in the list into buf. On error,
 * clear the buffer and return -1. */
int
virDomainSnapshotObjListFormat(virBufferPtr buf,
                               const char *uuidstr,
                               virDomainSnapshotObjListPtr snapshots,
                               virDomainSnapshotObjPtr current_snapshot,
                               virCapsPtr caps,
                               virDomainXMLOptionPtr xmlopt,
                               unsigned int flags)
{
    struct virDomainSnapshotFormatData data = {
        .buf = buf,
        .uuidstr = uuidstr,
        .caps = caps,
        .xmlopt = xmlopt,
        .flags = flags,
    };

    virBufferAddLit(buf, "<snapshots");
    if (current_snapshot)
        virBufferEscapeString(buf, " current='%s'",
                              current_snapshot->def->name);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    if (virDomainSnapshotForEach(snapshots, virDomainSnapshotFormatOne,
                                 &data) < 0) {
        virBufferFreeAndReset(buf);
        return -1;
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</snapshots>\n");
    return 0;
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
            obj->def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF)
            return 0;
        if (!(data->flags & VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY) &&
            obj->def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)
            return 0;
        if (!(data->flags & VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE) &&
            obj->def->state != VIR_DOMAIN_SNAPSHOT_SHUTOFF &&
            obj->def->state != VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)
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

    /* We handle LIST_ROOT/LIST_DESCENDANTS and LIST_TOPOLOGICAL directly,
     * mask those bits out to determine when we must use the filter callback. */
    data.flags &= ~(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                    VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL);

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
        /* We could just always do a topological visit; but it is
         * possible to optimize for less stack usage and time when a
         * simpler full hashtable visit or counter will do. */
        if (from->def || (names &&
                          (flags & VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL)))
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
 * assigned defs having relations starting as 0/NULL. Return 0 on
 * success, -1 if a parent is missing or if a circular relationship
 * was requested. */
int
virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots)
{
    struct snapshot_set_relation act = { snapshots, 0 };

    snapshots->metaroot.nchildren = 0;
    snapshots->metaroot.first_child = NULL;
    virHashForEach(snapshots->objs, virDomainSnapshotSetRelations, &act);
    return act.err;
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
