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

#include "domain_conf.h"
#include "qemu_conf.h"
#include "virautoclean.h"
#include "virarch.h"

typedef struct _qemuVhostUser qemuVhostUser;
typedef qemuVhostUser *qemuVhostUserPtr;

void
qemuVhostUserFree(qemuVhostUserPtr fw);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuVhostUser, qemuVhostUserFree);

qemuVhostUserPtr
qemuVhostUserParse(const char *path);

char *
qemuVhostUserFormat(qemuVhostUserPtr fw);

int
qemuVhostUserFetchConfigs(char ***configs,
                         bool privileged);

int
qemuVhostUserFillDomainGPU(virQEMUDriverPtr driver,
                           virDomainVideoDefPtr video);
