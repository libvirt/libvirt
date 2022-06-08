/*
 * lock_daemon_config.c: virtlockd config file handling
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

#include <config.h>

#include "lock_daemon_config.h"
#include "virconf.h"
#include "virlog.h"
#include "configmake.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("locking.lock_daemon_config");

int
virLockDaemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        *configfile = g_strdup(SYSCONFDIR "/libvirt/virtlockd.conf");
    } else {
        g_autofree char *configdir = NULL;

        configdir = virGetUserConfigDirectory();

        *configfile = g_strdup_printf("%s/virtlockd.conf", configdir);
    }

    return 0;
}


virLockDaemonConfig *
virLockDaemonConfigNew(bool privileged G_GNUC_UNUSED)
{
    virLockDaemonConfig *data;

    data = g_new0(virLockDaemonConfig, 1);

    data->max_clients = 1024;
    data->admin_max_clients = 5000;

    return data;
}

void
virLockDaemonConfigFree(virLockDaemonConfig *data)
{
    if (!data)
        return;

    g_free(data->log_filters);
    g_free(data->log_outputs);

    g_free(data);
}

static int
virLockDaemonConfigLoadOptions(virLockDaemonConfig *data,
                               virConf *conf)
{
    if (virConfGetValueUInt(conf, "log_level", &data->log_level) < 0)
        return -1;
    if (virConfGetValueString(conf, "log_filters", &data->log_filters) < 0)
        return -1;
    if (virConfGetValueString(conf, "log_outputs", &data->log_outputs) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_clients", &data->max_clients) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "admin_max_clients", &data->admin_max_clients) < 0)
        return -1;

    return 0;
}


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
int
virLockDaemonConfigLoadFile(virLockDaemonConfig *data,
                            const char *filename,
                            bool allow_missing)
{
    g_autoptr(virConf) conf = NULL;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    return virLockDaemonConfigLoadOptions(data, conf);
}
