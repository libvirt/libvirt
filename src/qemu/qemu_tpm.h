/*
 * qemu_tpm.h: QEMU TPM support
 *
 * Copyright (C) 2018 IBM Corporation
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

#include "vircommand.h"

int qemuExtTPMInitPaths(virQEMUDriver *driver,
                        virDomainDef *def,
                        virDomainTPMDef *tpm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

int qemuExtTPMPrepareHost(virQEMUDriver *driver,
                          virDomainDef *def,
                          virDomainTPMDef *tpm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuExtTPMCleanupHost(virDomainTPMDef *tpm,
                           virDomainUndefineFlagsValues flags,
                           bool outgoingMigration)
    ATTRIBUTE_NONNULL(1);

int qemuExtTPMStart(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virDomainTPMDef *def,
                    bool incomingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuExtTPMStop(virQEMUDriver *driver,
                    virDomainObj *vm,
                    bool outgoingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuExtTPMSetupCgroup(virQEMUDriver *driver,
                          virDomainDef *def,
                          virCgroup *cgroup)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;

bool qemuTPMHasSharedStorage(virDomainDef *def)
    ATTRIBUTE_NONNULL(1)
    G_GNUC_WARN_UNUSED_RESULT;

bool qemuTPMCanMigrateSharedStorage(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);
