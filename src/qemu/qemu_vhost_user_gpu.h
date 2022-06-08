/*
 * qemu_vhost_user_gpu.h: QEMU vhost-user GPU support
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "qemu_domain.h"
#include "qemu_security.h"

int qemuExtVhostUserGPUPrepareDomain(virQEMUDriver *driver,
                                     virDomainVideoDef *video)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

int qemuExtVhostUserGPUStart(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainVideoDef *video)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuExtVhostUserGPUStop(virQEMUDriver *driver,
                             virDomainObj *def,
                             virDomainVideoDef *video)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuExtVhostUserGPUSetupCgroup(virQEMUDriver *driver,
                               virDomainDef *def,
                               virDomainVideoDef *video,
                               virCgroup *cgroup)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;
