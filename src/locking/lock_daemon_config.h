/*
 * lock_daemon_config.h: virtlockd config file handling
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "internal.h"

typedef struct _virLockDaemonConfig virLockDaemonConfig;
struct _virLockDaemonConfig {
    unsigned int log_level;
    char *log_filters;
    char *log_outputs;
    unsigned int max_clients;
    unsigned int admin_max_clients;
};


int virLockDaemonConfigFilePath(bool privileged, char **configfile);
virLockDaemonConfig *virLockDaemonConfigNew(bool privileged);
void virLockDaemonConfigFree(virLockDaemonConfig *data);
int virLockDaemonConfigLoadFile(virLockDaemonConfig *data,
                                const char *filename,
                                bool allow_missing);
