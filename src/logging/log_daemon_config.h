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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_LOG_DAEMON_CONFIG_H__
# define __VIR_LOG_DAEMON_CONFIG_H__

# include "internal.h"

typedef struct _virLogDaemonConfig virLogDaemonConfig;
typedef virLogDaemonConfig *virLogDaemonConfigPtr;

struct _virLogDaemonConfig {
    int log_level;
    char *log_filters;
    char *log_outputs;
    int max_clients;
};


int virLogDaemonConfigFilePath(bool privileged, char **configfile);
virLogDaemonConfigPtr virLogDaemonConfigNew(bool privileged);
void virLogDaemonConfigFree(virLogDaemonConfigPtr data);
int virLogDaemonConfigLoadFile(virLogDaemonConfigPtr data,
                               const char *filename,
                               bool allow_missing);
int virLogDaemonConfigLoadData(virLogDaemonConfigPtr data,
                               const char *filename,
                               const char *filedata);

#endif /* __LIBVIRTD_CONFIG_H__ */
