/*
 * qemu_migration_params.h: QEMU migration parameters handling
 *
 * Copyright (C) 2006-2018 Red Hat, Inc.
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
 */

#pragma once

#include "internal.h"

#include "virbuffer.h"
#include "virxml.h"
#include "qemu_monitor.h"
#include "qemu_conf.h"
#include "virenum.h"

typedef enum {
    QEMU_MIGRATION_CAP_XBZRLE,
    QEMU_MIGRATION_CAP_AUTO_CONVERGE,
    QEMU_MIGRATION_CAP_RDMA_PIN_ALL,
    QEMU_MIGRATION_CAP_EVENTS,
    QEMU_MIGRATION_CAP_POSTCOPY,
    QEMU_MIGRATION_CAP_COMPRESS,
    QEMU_MIGRATION_CAP_PAUSE_BEFORE_SWITCHOVER,
    QEMU_MIGRATION_CAP_LATE_BLOCK_ACTIVATE,
    QEMU_MIGRATION_CAP_MULTIFD,

    QEMU_MIGRATION_CAP_LAST
} qemuMigrationCapability;
VIR_ENUM_DECL(qemuMigrationCapability);

typedef enum {
    QEMU_MIGRATION_PARAM_COMPRESS_LEVEL,
    QEMU_MIGRATION_PARAM_COMPRESS_THREADS,
    QEMU_MIGRATION_PARAM_DECOMPRESS_THREADS,
    QEMU_MIGRATION_PARAM_THROTTLE_INITIAL,
    QEMU_MIGRATION_PARAM_THROTTLE_INCREMENT,
    QEMU_MIGRATION_PARAM_TLS_CREDS,
    QEMU_MIGRATION_PARAM_TLS_HOSTNAME,
    QEMU_MIGRATION_PARAM_MAX_BANDWIDTH,
    QEMU_MIGRATION_PARAM_DOWNTIME_LIMIT,
    QEMU_MIGRATION_PARAM_BLOCK_INCREMENTAL,
    QEMU_MIGRATION_PARAM_XBZRLE_CACHE_SIZE,
    QEMU_MIGRATION_PARAM_MAX_POSTCOPY_BANDWIDTH,
    QEMU_MIGRATION_PARAM_MULTIFD_CHANNELS,

    QEMU_MIGRATION_PARAM_LAST
} qemuMigrationParam;

typedef struct _qemuMigrationParams qemuMigrationParams;
typedef qemuMigrationParams *qemuMigrationParamsPtr;

typedef enum {
    QEMU_MIGRATION_SOURCE = (1 << 0),
    QEMU_MIGRATION_DESTINATION = (1 << 1),
} qemuMigrationParty;


virBitmapPtr
qemuMigrationParamsGetAlwaysOnCaps(qemuMigrationParty party);

qemuMigrationParamsPtr
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned long flags,
                             qemuMigrationParty party);

int
qemuMigrationParamsDump(qemuMigrationParamsPtr migParams,
                        virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        unsigned long *flags);

qemuMigrationParamsPtr
qemuMigrationParamsNew(void);

void
qemuMigrationParamsFree(qemuMigrationParamsPtr migParams);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMigrationParams, qemuMigrationParamsFree);

int
qemuMigrationParamsApply(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsEnableTLS(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             bool tlsListen,
                             int asyncJob,
                             char **tlsAlias,
                             const char *hostname,
                             qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsDisableTLS(virDomainObjPtr vm,
                              qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsFetch(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr *migParams);

int
qemuMigrationParamsSetULL(qemuMigrationParamsPtr migParams,
                          qemuMigrationParam param,
                          unsigned long long value);

int
qemuMigrationParamsGetULL(qemuMigrationParamsPtr migParams,
                          qemuMigrationParam param,
                          unsigned long long *value);

int
qemuMigrationParamsCheck(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr migParams,
                         virBitmapPtr remoteCaps);

void
qemuMigrationParamsReset(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr origParams,
                         unsigned long apiFlags);

void
qemuMigrationParamsFormat(virBufferPtr buf,
                          qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsParse(xmlXPathContextPtr ctxt,
                         qemuMigrationParamsPtr *migParams);

int
qemuMigrationCapsCheck(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob);

bool
qemuMigrationCapsGet(virDomainObjPtr vm,
                     qemuMigrationCapability cap);
