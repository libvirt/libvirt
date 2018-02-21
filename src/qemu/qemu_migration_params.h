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


qemuMonitorMigrationParamsPtr
qemuMigrationParamsFromFlags(virTypedParameterPtr params,
                             int nparams,
                             unsigned long flags);

void
qemuMigrationParamsClear(qemuMonitorMigrationParamsPtr migParams);

void
qemuMigrationParamsFree(qemuMonitorMigrationParamsPtr *migParams);

int
qemuMigrationParamsSet(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       int asyncJob,
                       qemuMonitorMigrationParamsPtr migParams);

int
qemuMigrationParamsCheckSetupTLS(virQEMUDriverPtr driver,
                                 virQEMUDriverConfigPtr cfg,
                                 virDomainObjPtr vm,
                                 int asyncJob);

int
qemuMigrationParamsAddTLSObjects(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virQEMUDriverConfigPtr cfg,
                                 bool tlsListen,
                                 int asyncJob,
                                 char **tlsAlias,
                                 char **secAlias,
                                 qemuMonitorMigrationParamsPtr migParams);

int
qemuMigrationParamsSetEmptyTLS(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               int asyncJob,
                               qemuMonitorMigrationParamsPtr migParams);

int
qemuMigrationParamsSetCompression(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  int asyncJob,
                                  qemuMigrationCompressionPtr compression,
                                  qemuMonitorMigrationParamsPtr migParams);

void
qemuMigrationParamsReset(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         int asyncJob);

#endif /* __QEMU_MIGRATION_PARAMS_H__ */
