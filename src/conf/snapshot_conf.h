/*
 * snapshot_conf.h: domain snapshot XML processing
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

#ifndef __SNAPSHOT_CONF_H
# define __SNAPSHOT_CONF_H

# include "internal.h"
# include "domain_conf.h"

/* Items related to snapshot state */

typedef enum {
    VIR_DOMAIN_SNAPSHOT_LOCATION_DEFAULT = 0,
    VIR_DOMAIN_SNAPSHOT_LOCATION_NONE,
    VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL,
    VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL,

    VIR_DOMAIN_SNAPSHOT_LOCATION_LAST
} virDomainSnapshotLocation;

typedef enum {
    /* Inherit the VIR_DOMAIN_* states from virDomainState.  */
    VIR_DOMAIN_DISK_SNAPSHOT = VIR_DOMAIN_LAST,
    VIR_DOMAIN_SNAPSHOT_STATE_LAST
} virDomainSnapshotState;

/* Stores disk-snapshot information */
typedef struct _virDomainSnapshotDiskDef virDomainSnapshotDiskDef;
typedef virDomainSnapshotDiskDef *virDomainSnapshotDiskDefPtr;
struct _virDomainSnapshotDiskDef {
    char *name;     /* name matching the <target dev='...' of the domain */
    int idx;        /* index within snapshot->dom->disks that matches name */
    int snapshot;   /* virDomainSnapshotLocation */

    /* details of wrapper external file. src is always non-NULL.
     * XXX optimize this to allow NULL for internal snapshots? */
    virStorageSourcePtr src;
};

/* Stores the complete snapshot metadata */
typedef struct _virDomainSnapshotDef virDomainSnapshotDef;
typedef virDomainSnapshotDef *virDomainSnapshotDefPtr;
struct _virDomainSnapshotDef {
    /* Public XML.  */
    char *name;
    char *description;
    char *parent;
    long long creationTime; /* in seconds */
    int state; /* virDomainSnapshotState */

    int memory; /* virDomainMemorySnapshot */
    char *file; /* memory state file when snapshot is external */

    size_t ndisks; /* should not exceed dom->ndisks */
    virDomainSnapshotDiskDef *disks;

    virDomainDefPtr dom;

    /* Internal use.  */
    bool current; /* At most one snapshot in the list should have this set */
};

struct _virDomainSnapshotObj {
    virDomainSnapshotDefPtr def; /* non-NULL except for metaroot */

    virDomainSnapshotObjPtr parent; /* non-NULL except for metaroot, before
                                       virDomainSnapshotUpdateRelations, or
                                       after virDomainSnapshotDropParent */
    virDomainSnapshotObjPtr sibling; /* NULL if last child of parent */
    size_t nchildren;
    virDomainSnapshotObjPtr first_child; /* NULL if no children */
};

virDomainSnapshotObjListPtr virDomainSnapshotObjListNew(void);
void virDomainSnapshotObjListFree(virDomainSnapshotObjListPtr snapshots);

typedef enum {
    VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_PARSE_DISKS    = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL = 1 << 2,
    VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE  = 1 << 3,
} virDomainSnapshotParseFlags;

virDomainSnapshotDefPtr virDomainSnapshotDefParseString(const char *xmlStr,
                                                        virCapsPtr caps,
                                                        virDomainXMLOptionPtr xmlopt,
                                                        unsigned int flags);
virDomainSnapshotDefPtr virDomainSnapshotDefParseNode(xmlDocPtr xml,
                                                      xmlNodePtr root,
                                                      virCapsPtr caps,
                                                      virDomainXMLOptionPtr xmlopt,
                                                      unsigned int flags);
void virDomainSnapshotDefFree(virDomainSnapshotDefPtr def);
char *virDomainSnapshotDefFormat(const char *domain_uuid,
                                 virDomainSnapshotDefPtr def,
                                 virCapsPtr caps,
                                 virDomainXMLOptionPtr xmlopt,
                                 unsigned int flags,
                                 int internal);
int virDomainSnapshotAlignDisks(virDomainSnapshotDefPtr snapshot,
                                int default_snapshot,
                                bool require_match);
virDomainSnapshotObjPtr virDomainSnapshotAssignDef(virDomainSnapshotObjListPtr snapshots,
                                                   virDomainSnapshotDefPtr def);

int virDomainSnapshotObjListGetNames(virDomainSnapshotObjListPtr snapshots,
                                     virDomainSnapshotObjPtr from,
                                     char **const names, int maxnames,
                                     unsigned int flags);
int virDomainSnapshotObjListNum(virDomainSnapshotObjListPtr snapshots,
                                virDomainSnapshotObjPtr from,
                                unsigned int flags);
virDomainSnapshotObjPtr virDomainSnapshotFindByName(virDomainSnapshotObjListPtr snapshots,
                                                    const char *name);
void virDomainSnapshotObjListRemove(virDomainSnapshotObjListPtr snapshots,
                                    virDomainSnapshotObjPtr snapshot);
int virDomainSnapshotForEach(virDomainSnapshotObjListPtr snapshots,
                             virHashIterator iter,
                             void *data);
int virDomainSnapshotForEachChild(virDomainSnapshotObjPtr snapshot,
                                  virHashIterator iter,
                                  void *data);
int virDomainSnapshotForEachDescendant(virDomainSnapshotObjPtr snapshot,
                                       virHashIterator iter,
                                       void *data);
int virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots);
void virDomainSnapshotDropParent(virDomainSnapshotObjPtr snapshot);

# define VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA           \
               (VIR_DOMAIN_SNAPSHOT_LIST_METADATA     | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES             \
               (VIR_DOMAIN_SNAPSHOT_LIST_LEAVES       | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS             \
               (VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE     | \
                VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE       | \
                VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION           \
               (VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL     | \
                VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_ALL                \
               (VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA  | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)

int virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                           virDomainSnapshotObjPtr from,
                           virDomainPtr dom,
                           virDomainSnapshotPtr **snaps,
                           unsigned int flags);

bool virDomainSnapshotDefIsExternal(virDomainSnapshotDefPtr def);
bool virDomainSnapshotIsExternal(virDomainSnapshotObjPtr snap);

int virDomainSnapshotRedefinePrep(virDomainPtr domain,
                                  virDomainObjPtr vm,
                                  virDomainSnapshotDefPtr *def,
                                  virDomainSnapshotObjPtr *snap,
                                  virDomainXMLOptionPtr xmlopt,
                                  bool *update_current,
                                  unsigned int flags);

VIR_ENUM_DECL(virDomainSnapshotLocation)
VIR_ENUM_DECL(virDomainSnapshotState)

#endif /* __SNAPSHOT_CONF_H */
