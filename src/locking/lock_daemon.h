/*
 * lock_daemon.h: lock management daemon
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 */

#pragma once

#include "virlockspace.h"
#include "virthread.h"

typedef struct _virLockDaemon virLockDaemon;
typedef virLockDaemon *virLockDaemonPtr;

typedef struct _virLockDaemonClient virLockDaemonClient;
typedef virLockDaemonClient *virLockDaemonClientPtr;

struct _virLockDaemonClient {
    virMutex lock;
    bool restricted;

    pid_t ownerPid;
    char *ownerName;
    unsigned char ownerUUID[VIR_UUID_BUFLEN];
    unsigned int ownerId;

    pid_t clientPid;
};

extern virLockDaemonPtr lockDaemon;

int virLockDaemonAddLockSpace(virLockDaemonPtr lockd,
                              const char *path,
                              virLockSpacePtr lockspace);

virLockSpacePtr virLockDaemonFindLockSpace(virLockDaemonPtr lockd,
                                           const char *path);
