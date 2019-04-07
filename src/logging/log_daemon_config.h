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

#ifndef LIBVIRT_LOG_DAEMON_CONFIG_H
# define LIBVIRT_LOG_DAEMON_CONFIG_H

# include "internal.h"

typedef struct _virLogDaemonConfig virLogDaemonConfig;
typedef virLogDaemonConfig *virLogDaemonConfigPtr;

struct _virLogDaemonConfig {
    unsigned int log_level;
    char *log_filters;
    char *log_outputs;
    unsigned int max_clients;
    unsigned int admin_max_clients;

    size_t max_backups;
    size_t max_size;
};


int virLogDaemonConfigFilePath(bool privileged, char **configfile);
virLogDaemonConfigPtr virLogDaemonConfigNew(bool privileged);
void virLogDaemonConfigFree(virLogDaemonConfigPtr data);
int virLogDaemonConfigLoadFile(virLogDaemonConfigPtr data,
                               const char *filename,
                               bool allow_missing);

#endif /* LIBVIRT_LOG_DAEMON_CONFIG_H */
