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

#ifndef __QEMU_MIGRATION_PARAMS_H__
# define __QEMU_MIGRATION_PARAMS_H__

# include "internal.h"

# include "qemu_monitor.h"
# include "qemu_conf.h"


typedef struct _qemuMigrationCompression qemuMigrationCompression;
typedef qemuMigrationCompression *qemuMigrationCompressionPtr;
struct _qemuMigrationCompression {
    unsigned long long methods;

    bool level_set;
    int level;

    bool threads_set;
    int threads;

    bool dthreads_set;
    int dthreads;

    bool xbzrle_cache_set;
    unsigned long long xbzrle_cache;
};


typedef struct _qemuMigrationParams qemuMigrationParams;
typedef qemuMigrationParams *qemuMigrationParamsPtr;
struct _qemuMigrationParams {
    qemuMonitorMigrationParams params;
};


qemuMigrationParamsPtr
qemuMigrationParamsNew(void);

qemuMigrationParamsPtr
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned long flags);

void
qemuMigrationParamsFree(qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsSet(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob,
                       qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsEnableTLS(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             bool tlsListen,
                             int asyncJob,
                             char **tlsAlias,
                             char **secAlias,
                             const char *hostname,
                             qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsDisableTLS(virDomainObjPtr vm,
                              qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsSetCompression(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  int asyncJob,
                                  qemuMigrationCompressionPtr compression,
                                  qemuMigrationParamsPtr migParams);

int
qemuMigrationParamsCheck(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob);

void
qemuMigrationParamsReset(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob,
                         qemuMigrationParamsPtr origParams);

int
qemuMigrationCapsCheck(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob);

bool
qemuMigrationCapsGet(virDomainObjPtr vm,
                     qemuMonitorMigrationCaps cap);

#endif /* __QEMU_MIGRATION_PARAMS_H__ */
