/*
 * backup_conf.h: domain backup XML processing
 *                 (based on domain_conf.h)
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
#include "virconftypes.h"

/* Items related to incremental backup state */

typedef enum {
    VIR_DOMAIN_BACKUP_TYPE_DEFAULT = 0,
    VIR_DOMAIN_BACKUP_TYPE_PUSH,
    VIR_DOMAIN_BACKUP_TYPE_PULL,

    VIR_DOMAIN_BACKUP_TYPE_LAST
} virDomainBackupType;

typedef enum {
    VIR_DOMAIN_BACKUP_DISK_STATE_NONE = 0,
    VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING,
    VIR_DOMAIN_BACKUP_DISK_STATE_COMPLETE,
    VIR_DOMAIN_BACKUP_DISK_STATE_FAILED,
    VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLING,
    VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLED,
    VIR_DOMAIN_BACKUP_DISK_STATE_LAST
} virDomainBackupDiskState;

/* Stores disk-backup information */
typedef struct _virDomainBackupDiskDef virDomainBackupDiskDef;
typedef virDomainBackupDiskDef *virDomainBackupDiskDefPtr;
struct _virDomainBackupDiskDef {
    char *name;     /* name matching the <target dev='...' of the domain */
    virTristateBool backup; /* whether backup is requested */
    char *exportname; /* name of the NBD export for pull mode backup */
    char *exportbitmap; /* name of the bitmap exposed in NBD for pull mode backup */

    /* details of target for push-mode, or of the scratch file for pull-mode */
    virStorageSourcePtr store;

    /* internal data */
    virDomainBackupDiskState state;
};

/* Stores the complete backup metadata */
typedef struct _virDomainBackupDef virDomainBackupDef;
typedef virDomainBackupDef *virDomainBackupDefPtr;
struct _virDomainBackupDef {
    /* Public XML.  */
    int type; /* virDomainBackupType */
    char *incremental;
    virStorageNetHostDefPtr server; /* only when type == PULL */

    size_t ndisks; /* should not exceed dom->ndisks */
    virDomainBackupDiskDef *disks;

    /* internal data */
    /* statistic totals for completed disks */
    unsigned long long push_transferred;
    unsigned long long push_total;
    unsigned long long pull_tmp_used;
    unsigned long long pull_tmp_total;
};

typedef enum {
    VIR_DOMAIN_BACKUP_PARSE_INTERNAL = 1 << 0,
} virDomainBackupParseFlags;

virDomainBackupDefPtr
virDomainBackupDefParseString(const char *xmlStr,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags);

virDomainBackupDefPtr
virDomainBackupDefParseNode(xmlDocPtr xml,
                            xmlNodePtr root,
                            virDomainXMLOptionPtr xmlopt,
                            unsigned int flags);
void
virDomainBackupDefFree(virDomainBackupDefPtr def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainBackupDef, virDomainBackupDefFree);

int
virDomainBackupDefFormat(virBufferPtr buf,
                         virDomainBackupDefPtr def,
                         bool internal);
int
virDomainBackupAlignDisks(virDomainBackupDefPtr backup,
                          virDomainDefPtr dom,
                          const char *suffix);
