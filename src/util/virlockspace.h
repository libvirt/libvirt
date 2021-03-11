/*
 * virlockspace.h: simple file based lockspaces
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "internal.h"
#include "virjson.h"

typedef struct _virLockSpace virLockSpace;

virLockSpace *virLockSpaceNew(const char *directory);
virLockSpace *virLockSpaceNewPostExecRestart(virJSONValue *object);

virJSONValue *virLockSpacePreExecRestart(virLockSpace *lockspace);

void virLockSpaceFree(virLockSpace *lockspace);

const char *virLockSpaceGetDirectory(virLockSpace *lockspace);

int virLockSpaceCreateResource(virLockSpace *lockspace,
                               const char *resname);
int virLockSpaceDeleteResource(virLockSpace *lockspace,
                               const char *resname);

typedef enum {
    VIR_LOCK_SPACE_ACQUIRE_SHARED     = (1 << 0),
    VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE = (1 << 1),
} virLockSpaceAcquireFlags;

int virLockSpaceAcquireResource(virLockSpace *lockspace,
                                const char *resname,
                                pid_t owner,
                                unsigned int flags);

int virLockSpaceReleaseResource(virLockSpace *lockspace,
                                const char *resname,
                                pid_t owner);

int virLockSpaceReleaseResourcesForOwner(virLockSpace *lockspace,
                                         pid_t owner);
