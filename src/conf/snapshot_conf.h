/*
 * snapshot_conf.h: domain snapshot XML processing
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

#ifndef LIBVIRT_SNAPSHOT_CONF_H
# define LIBVIRT_SNAPSHOT_CONF_H

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

/**
 * This enum has to map all known domain states from the public enum
 * virDomainState, before adding one additional state possible only
 * for snapshots.
 */
typedef enum {
    /* Mapped to public enum */
    VIR_DOMAIN_SNAPSHOT_NOSTATE = VIR_DOMAIN_NOSTATE,
    VIR_DOMAIN_SNAPSHOT_RUNNING = VIR_DOMAIN_RUNNING,
    VIR_DOMAIN_SNAPSHOT_BLOCKED = VIR_DOMAIN_BLOCKED,
    VIR_DOMAIN_SNAPSHOT_PAUSED = VIR_DOMAIN_PAUSED,
    VIR_DOMAIN_SNAPSHOT_SHUTDOWN = VIR_DOMAIN_SHUTDOWN,
    VIR_DOMAIN_SNAPSHOT_SHUTOFF = VIR_DOMAIN_SHUTOFF,
    VIR_DOMAIN_SNAPSHOT_CRASHED = VIR_DOMAIN_CRASHED,
    VIR_DOMAIN_SNAPSHOT_PMSUSPENDED = VIR_DOMAIN_PMSUSPENDED,
    /* Additional enum values local to snapshots */
    VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT,
    VIR_DOMAIN_SNAPSHOT_LAST
} virDomainSnapshotState;
verify((int)VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT == VIR_DOMAIN_LAST);

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

    virObjectPtr cookie;
};

typedef enum {
    VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_PARSE_DISKS    = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL = 1 << 2,
    VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE  = 1 << 3,
} virDomainSnapshotParseFlags;

typedef enum {
    VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE   = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT  = 1 << 2,
} virDomainSnapshotFormatFlags;

unsigned int virDomainSnapshotFormatConvertXMLFlags(unsigned int flags);

virDomainSnapshotDefPtr virDomainSnapshotDefParseString(const char *xmlStr,
                                                        virCapsPtr caps,
                                                        virDomainXMLOptionPtr xmlopt,
                                                        bool *current,
                                                        unsigned int flags);
virDomainSnapshotDefPtr virDomainSnapshotDefParseNode(xmlDocPtr xml,
                                                      xmlNodePtr root,
                                                      virCapsPtr caps,
                                                      virDomainXMLOptionPtr xmlopt,
                                                      bool *current,
                                                      unsigned int flags);
void virDomainSnapshotDefFree(virDomainSnapshotDefPtr def);
char *virDomainSnapshotDefFormat(const char *uuidstr,
                                 virDomainSnapshotDefPtr def,
                                 virCapsPtr caps,
                                 virDomainXMLOptionPtr xmlopt,
                                 unsigned int flags);
int virDomainSnapshotDefFormatInternal(virBufferPtr buf,
                                       const char *uuidstr,
                                       virDomainSnapshotDefPtr def,
                                       virCapsPtr caps,
                                       virDomainXMLOptionPtr xmlopt,
                                       unsigned int flags);

int virDomainSnapshotAlignDisks(virDomainSnapshotDefPtr snapshot,
                                int default_snapshot,
                                bool require_match);

# define VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA \
               (VIR_DOMAIN_SNAPSHOT_LIST_METADATA     | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES \
               (VIR_DOMAIN_SNAPSHOT_LIST_LEAVES       | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS \
               (VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE     | \
                VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE       | \
                VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION \
               (VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL     | \
                VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL)

# define VIR_DOMAIN_SNAPSHOT_FILTERS_ALL \
               (VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA  | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)

bool virDomainSnapshotDefIsExternal(virDomainSnapshotDefPtr def);
bool virDomainSnapshotIsExternal(virDomainSnapshotObjPtr snap);

int virDomainSnapshotRedefinePrep(virDomainPtr domain,
                                  virDomainObjPtr vm,
                                  virDomainSnapshotDefPtr *def,
                                  virDomainSnapshotObjPtr *snap,
                                  virDomainXMLOptionPtr xmlopt,
                                  bool *update_current,
                                  unsigned int flags);

int virDomainSnapshotRedefineValidate(virDomainSnapshotDefPtr def,
                                      const unsigned char *domain_uuid,
                                      virDomainSnapshotObjPtr other,
                                      virDomainXMLOptionPtr xmlopt,
                                      unsigned int flags);

VIR_ENUM_DECL(virDomainSnapshotLocation);
VIR_ENUM_DECL(virDomainSnapshotState);

#endif /* LIBVIRT_SNAPSHOT_CONF_H */
