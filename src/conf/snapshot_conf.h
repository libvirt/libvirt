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

#pragma once

#include "internal.h"
#include "domain_conf.h"
#include "moment_conf.h"
#include "virenum.h"

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
G_STATIC_ASSERT((int)VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT == VIR_DOMAIN_LAST);

/* Stores disk-snapshot information */
typedef struct _virDomainSnapshotDiskDef virDomainSnapshotDiskDef;
struct _virDomainSnapshotDiskDef {
    char *name;     /* name matching the <target dev='...' of the domain */
    int snapshot;   /* virDomainSnapshotLocation */

    /* details of wrapper external file. src is always non-NULL.
     * XXX optimize this to allow NULL for internal snapshots? */
    virStorageSource *src;
};

void
virDomainSnapshotDiskDefFree(virDomainSnapshotDiskDef *disk);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainSnapshotDiskDef, virDomainSnapshotDiskDefFree);

/* Stores the complete snapshot metadata */
struct _virDomainSnapshotDef {
    virDomainMomentDef parent;

    /* Additional public XML.  */
    int state; /* virDomainSnapshotState */

    int memory; /* virDomainMemorySnapshot */
    char *memorysnapshotfile; /* memory state file when snapshot is external */

    size_t ndisks; /* should not exceed dom->ndisks */
    virDomainSnapshotDiskDef *disks;

    virObject *cookie;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainSnapshotDef, virObjectUnref);


typedef enum {
    VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_PARSE_DISKS    = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL = 1 << 2,
    VIR_DOMAIN_SNAPSHOT_PARSE_OFFLINE  = 1 << 3,
    VIR_DOMAIN_SNAPSHOT_PARSE_VALIDATE = 1 << 4,
} virDomainSnapshotParseFlags;

typedef enum {
    VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE   = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT  = 1 << 2,
} virDomainSnapshotFormatFlags;

unsigned int virDomainSnapshotFormatConvertXMLFlags(unsigned int flags);

virDomainSnapshotDef *virDomainSnapshotDefParseString(const char *xmlStr,
                                                      virDomainXMLOption *xmlopt,
                                                      void *parseOpaque,
                                                      bool *current,
                                                      unsigned int flags);
virDomainSnapshotDef *virDomainSnapshotDefParseNode(xmlDocPtr xml,
                                                    xmlNodePtr root,
                                                    virDomainXMLOption *xmlopt,
                                                    void *parseOpaque,
                                                    bool *current,
                                                    unsigned int flags);
virDomainSnapshotDef *virDomainSnapshotDefNew(void);
char *virDomainSnapshotDefFormat(const char *uuidstr,
                                 virDomainSnapshotDef *def,
                                 virDomainXMLOption *xmlopt,
                                 unsigned int flags);
int virDomainSnapshotAlignDisks(virDomainSnapshotDef *snapshot,
                                virDomainDef *existingDomainDef,
                                virDomainSnapshotLocation default_snapshot,
                                bool uniform_internal_snapshot);

bool virDomainSnapshotDefIsExternal(virDomainSnapshotDef *def);
bool virDomainSnapshotIsExternal(virDomainMomentObj *snap);

int virDomainSnapshotRedefinePrep(virDomainObj *vm,
                                  virDomainSnapshotDef *snapdef,
                                  virDomainMomentObj **snap,
                                  virDomainXMLOption *xmlopt,
                                  unsigned int flags);

VIR_ENUM_DECL(virDomainSnapshotLocation);
VIR_ENUM_DECL(virDomainSnapshotState);
