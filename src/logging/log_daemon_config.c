/*
 * log_daemon_config.c: virtlogd config file handling
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

#include <config.h>

#include "log_daemon_config.h"
#include "virconf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetserver.h"
#include "configmake.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("logging.log_daemon_config");


int
virLogDaemonConfigFilePath(bool privileged, char **configfile)
{
    if (privileged) {
        if (VIR_STRDUP(*configfile, SYSCONFDIR "/libvirt/virtlogd.conf") < 0)
            goto error;
    } else {
        char *configdir = NULL;

        if (!(configdir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(configfile, "%s/virtlogd.conf", configdir) < 0) {
            VIR_FREE(configdir);
            goto error;
        }
        VIR_FREE(configdir);
    }

    return 0;

 error:
    return -1;
}


virLogDaemonConfigPtr
virLogDaemonConfigNew(bool privileged ATTRIBUTE_UNUSED)
{
    virLogDaemonConfigPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->max_clients = 1024;
    data->admin_max_clients = 5000;
    data->max_size = 1024 * 1024 * 2;
    data->max_backups = 3;

    return data;
}

void
virLogDaemonConfigFree(virLogDaemonConfigPtr data)
{
    if (!data)
        return;

    VIR_FREE(data->log_filters);
    VIR_FREE(data->log_outputs);

    VIR_FREE(data);
}

static int
virLogDaemonConfigLoadOptions(virLogDaemonConfigPtr data,
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
    if (virConfGetValueSizeT(conf, "max_size", &data->max_size) < 0)
        return -1;
    if (virConfGetValueSizeT(conf, "max_backups", &data->max_backups) < 0)
        return -1;

    return 0;
}


/* Read the config file if it exists.
 */
int
virLogDaemonConfigLoadFile(virLogDaemonConfigPtr data,
                           const char *filename,
                           bool allow_missing)
{
    virConfPtr conf;
    int ret;

    if (allow_missing &&
        access(filename, R_OK) == -1 &&
        errno == ENOENT)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    ret = virLogDaemonConfigLoadOptions(data, conf);
    virConfFree(conf);
    return ret;
}
