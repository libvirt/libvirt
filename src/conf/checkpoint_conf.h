/*
 * checkpoint_conf.h: domain checkpoint XML processing
 *                 (based on snapshot_conf.h)
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
#include "virobject.h"

/* Items related to checkpoint state */

typedef enum {
    VIR_DOMAIN_CHECKPOINT_TYPE_DEFAULT = 0,
    VIR_DOMAIN_CHECKPOINT_TYPE_NONE,
    VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP,

    VIR_DOMAIN_CHECKPOINT_TYPE_LAST
} virDomainCheckpointType;

/* Stores disk-checkpoint information */
typedef struct _virDomainCheckpointDiskDef virDomainCheckpointDiskDef;
typedef virDomainCheckpointDiskDef *virDomainCheckpointDiskDefPtr;
struct _virDomainCheckpointDiskDef {
    char *name;     /* name matching the <target dev='...' of the domain */
    int idx;        /* index within checkpoint->dom->disks that matches name */
    int type;       /* virDomainCheckpointType */
    char *bitmap;   /* bitmap name, if type is bitmap */
    unsigned long long size; /* current checkpoint size in bytes */
};

/* Stores the complete checkpoint metadata */
struct _virDomainCheckpointDef {
    virDomainMomentDef parent;

    /* Additional Public XML.  */
    size_t ndisks; /* should not exceed dom->ndisks */
    virDomainCheckpointDiskDef *disks;
};


typedef enum {
    VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE = 1 << 0,
} virDomainCheckpointParseFlags;

typedef enum {
    VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE    = 1 << 0,
    VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN = 1 << 1,
    VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE      = 1 << 2,
} virDomainCheckpointFormatFlags;

unsigned int
virDomainCheckpointFormatConvertXMLFlags(unsigned int flags);

virDomainCheckpointDefPtr
virDomainCheckpointDefParseString(const char *xmlStr,
                                  virCapsPtr caps,
                                  virDomainXMLOptionPtr xmlopt,
                                  void *parseOpaque,
                                  unsigned int flags);

virDomainCheckpointDefPtr
virDomainCheckpointDefNew(void);

char *
virDomainCheckpointDefFormat(virDomainCheckpointDefPtr def,
                             virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt,
                             unsigned int flags);

int
virDomainCheckpointAlignDisks(virDomainCheckpointDefPtr checkpoint);

int virDomainCheckpointRedefinePrep(virDomainObjPtr vm,
                                    virDomainCheckpointDefPtr *def,
                                    virDomainMomentObjPtr *checkpoint,
                                    virDomainXMLOptionPtr xmlopt,
                                    bool *update_current);

VIR_ENUM_DECL(virDomainCheckpoint);
