/*
 * log_daemon_config.h: virtlogd config file handling
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

typedef struct _virLogDaemonConfig virLogDaemonConfig;
struct _virLogDaemonConfig {
    unsigned int log_level;
    char *log_filters;
    char *log_outputs;
    unsigned int max_clients;
    unsigned int admin_max_clients;

    size_t max_backups;
    size_t max_size;

    char *log_root;
    size_t max_age_days;
};


int virLogDaemonConfigFilePath(bool privileged, char **configfile);
virLogDaemonConfig *virLogDaemonConfigNew(bool privileged);
void virLogDaemonConfigFree(virLogDaemonConfig *data);
int virLogDaemonConfigLoadFile(virLogDaemonConfig *data,
                               const char *filename,
                               bool allow_missing);
