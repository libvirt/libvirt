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
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetdaemon.h"
#include "configmake.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("locking.lock_daemon_config");

int
virLockDaemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        if (VIR_STRDUP(*configfile, SYSCONFDIR "/libvirt/virtlockd.conf") < 0)
            goto error;
    } else {
        char *configdir = NULL;

        if (!(configdir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(configfile, "%s/virtlockd.conf", configdir) < 0) {
            VIR_FREE(configdir);
            goto error;
        }
        VIR_FREE(configdir);
    }

    return 0;

 error:
    return -1;
}


virLockDaemonConfigPtr
virLockDaemonConfigNew(bool privileged G_GNUC_UNUSED)
{
    virLockDaemonConfigPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->max_clients = 1024;
    data->admin_max_clients = 5000;

    return data;
}

void
virLockDaemonConfigFree(virLockDaemonConfigPtr data)
{
    if (!data)
        return;

    VIR_FREE(data->log_filters);
    VIR_FREE(data->log_outputs);

    VIR_FREE(data);
}

static int
virLockDaemonConfigLoadOptions(virLockDaemonConfigPtr data,
                               virConfPtr conf)
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
virLockDaemonConfigLoadFile(virLockDaemonConfigPtr data,
                            const char *filename,
                            bool allow_missing)
{
    VIR_AUTOPTR(virConf) conf = NULL;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    return virLockDaemonConfigLoadOptions(data, conf);
}
