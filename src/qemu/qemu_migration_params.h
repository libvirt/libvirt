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
    QEMU_MIGRATION_CAP_BLOCK_DIRTY_BITMAPS,
    QEMU_MIGRATION_CAP_RETURN_PATH,
    QEMU_MIGRATION_CAP_ZERO_COPY_SEND,

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
    QEMU_MIGRATION_PARAM_MULTIFD_COMPRESSION,
    QEMU_MIGRATION_PARAM_MULTIFD_ZLIB_LEVEL,
    QEMU_MIGRATION_PARAM_MULTIFD_ZSTD_LEVEL,

    QEMU_MIGRATION_PARAM_LAST
} qemuMigrationParam;

typedef struct _qemuMigrationParams qemuMigrationParams;

typedef enum {
    QEMU_MIGRATION_SOURCE = (1 << 0),
    QEMU_MIGRATION_DESTINATION = (1 << 1),
} qemuMigrationParty;


virBitmap *
qemuMigrationParamsGetAlwaysOnCaps(qemuMigrationParty party);

qemuMigrationParams *
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags,
                             qemuMigrationParty party);

int
qemuMigrationParamsDump(qemuMigrationParams *migParams,
                        virTypedParameterPtr *params,
                        int *nparams,
                        int *maxparams,
                        unsigned int *flags);

qemuMigrationParams *
qemuMigrationParamsNew(void);

void
qemuMigrationParamsFree(qemuMigrationParams *migParams);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMigrationParams, qemuMigrationParamsFree);

int
qemuMigrationParamsApply(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *migParams,
                         unsigned int apiFlags);

int
qemuMigrationParamsEnableTLS(virQEMUDriver *driver,
                             virDomainObj *vm,
                             bool tlsListen,
                             int asyncJob,
                             char **tlsAlias,
                             const char *hostname,
                             qemuMigrationParams *migParams);

int
qemuMigrationParamsDisableTLS(virDomainObj *vm,
                              qemuMigrationParams *migParams);

bool
qemuMigrationParamsTLSHostnameIsSet(qemuMigrationParams *migParams);

int
qemuMigrationParamsFetch(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams **migParams);

int
qemuMigrationParamsSetULL(qemuMigrationParams *migParams,
                          qemuMigrationParam param,
                          unsigned long long value);

int
qemuMigrationParamsGetULL(qemuMigrationParams *migParams,
                          qemuMigrationParam param,
                          unsigned long long *value);

void
qemuMigrationParamsSetBlockDirtyBitmapMapping(qemuMigrationParams *migParams,
                                              virJSONValue **params);

int
qemuMigrationParamsCheck(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *migParams,
                         virBitmap *remoteCaps);

void
qemuMigrationParamsReset(virDomainObj *vm,
                         int asyncJob,
                         qemuMigrationParams *origParams,
                         unsigned int apiFlags);

void
qemuMigrationParamsFormat(virBuffer *buf,
                          qemuMigrationParams *migParams);

int
qemuMigrationParamsParse(xmlXPathContextPtr ctxt,
                         qemuMigrationParams **migParams);

int
qemuMigrationCapsCheck(virDomainObj *vm,
                       int asyncJob,
                       bool reconnect);

bool
qemuMigrationCapsGet(virDomainObj *vm,
                     qemuMigrationCapability cap);

const char *
qemuMigrationParamsGetTLSHostname(qemuMigrationParams *migParams);
