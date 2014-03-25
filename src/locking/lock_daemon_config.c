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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "lock_daemon_config.h"
#include "virconf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetserver.h"
#include "configmake.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("locking.lock_daemon_config");


/* A helper function used by each of the following macros.  */
static int
checkType(virConfValuePtr p, const char *filename,
          const char *key, virConfType required_type)
{
    if (p->type != required_type) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("remoteReadConfigFile: %s: %s: invalid type:"
                         " got %s; expected %s"), filename, key,
                       virConfTypeName(p->type),
                       virConfTypeName(required_type));
        return -1;
    }
    return 0;
}

/* If there is no config data for the key, #var_name, then do nothing.
   If there is valid data of type VIR_CONF_STRING, and VIR_STRDUP succeeds,
   store the result in var_name.  Otherwise, (i.e. invalid type, or VIR_STRDUP
   failure), give a diagnostic and "goto" the cleanup-and-fail label.  */
#define GET_CONF_STR(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue(conf, #var_name);           \
        if (p) {                                                        \
            if (checkType(p, filename, #var_name, VIR_CONF_STRING) < 0) \
                goto error;                                             \
            VIR_FREE(data->var_name);                                   \
            if (VIR_STRDUP(data->var_name, p->str) < 0)                 \
                goto error;                                             \
        }                                                               \
    } while (0)

/* Like GET_CONF_STR, but for integral values.  */
#define GET_CONF_INT(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue(conf, #var_name);           \
        if (p) {                                                        \
            if (checkType(p, filename, #var_name, VIR_CONF_LONG) < 0)   \
                goto error;                                             \
            data->var_name = p->l;                                      \
        }                                                               \
    } while (0)

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
virLockDaemonConfigNew(bool privileged ATTRIBUTE_UNUSED)
{
    virLockDaemonConfigPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->max_clients = 1024;

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
                               const char *filename,
                               virConfPtr conf)
{
    GET_CONF_INT(conf, filename, log_level);
    GET_CONF_STR(conf, filename, log_filters);
    GET_CONF_STR(conf, filename, log_outputs);
    GET_CONF_INT(conf, filename, max_clients);

    return 0;

 error:
    return -1;
}


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
int
virLockDaemonConfigLoadFile(virLockDaemonConfigPtr data,
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

    ret = virLockDaemonConfigLoadOptions(data, filename, conf);
    virConfFree(conf);
    return ret;
}

int virLockDaemonConfigLoadData(virLockDaemonConfigPtr data,
                                const char *filename,
                                const char *filedata)
{
    virConfPtr conf;
    int ret;

    conf = virConfReadMem(filedata, strlen(filedata), 0);
    if (!conf)
        return -1;

    ret = virLockDaemonConfigLoadOptions(data, filename, conf);
    virConfFree(conf);
    return ret;
}
