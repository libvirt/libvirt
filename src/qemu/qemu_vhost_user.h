/*
 * qemu_vhost_user.h: QEMU vhost-user
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

#include "qemu_conf.h"

typedef struct _qemuVhostUser qemuVhostUser;

void
qemuVhostUserFree(qemuVhostUser *fw);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuVhostUser, qemuVhostUserFree);

qemuVhostUser *
qemuVhostUserParse(const char *path);

char *
qemuVhostUserFormat(qemuVhostUser *fw);

int
qemuVhostUserFetchConfigs(char ***configs,
                         bool privileged);

int
qemuVhostUserFillDomainGPU(virQEMUDriver *driver,
                           virDomainVideoDef *video);

int
qemuVhostUserFillDomainFS(virQEMUDriver *driver,
                          virDomainFSDef *fs);

int
qemuVhostUserFillFSCapabilities(virBitmap **caps,
                                const char *binary);
typedef enum {
    QEMU_VHOST_USER_FS_FEATURE_MIGRATE_PRECOPY = 0,
    QEMU_VHOST_USER_FS_FEATURE_SEPARATE_OPTIONS,
    QEMU_VHOST_USER_FS_FEATURE_LAST
} qemuVhostUserFSFeature;

VIR_ENUM_DECL(qemuVhostUserFSFeature);
