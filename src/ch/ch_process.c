/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_process.c: Process controller for Cloud-Hypervisor driver
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

#include <unistd.h>
#include <fcntl.h>

#include "ch_domain.h"
#include "ch_monitor.h"
#include "ch_process.h"
#include "viralloc.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_process");

#define START_SOCKET_POSTFIX ": starting up socket\n"
#define START_VM_POSTFIX ": starting up vm\n"



static virCHMonitor *
virCHProcessConnectMonitor(virCHDriver *driver,
                           virDomainObj *vm)
{
    virCHMonitor *monitor = NULL;
    virCHDriverConfig *cfg = virCHDriverGetConfig(driver);

    monitor = virCHMonitorNew(vm, cfg->stateDir);

    virObjectUnref(cfg);
    return monitor;
}

static void
virCHProcessUpdateConsoleDevice(virDomainObj *vm,
                                virJSONValue *config,
                                const char *device)
{
    const char *path;
    virDomainChrDef *chr = NULL;
    virJSONValue *dev, *file;

    if (!config)
        return;

    dev = virJSONValueObjectGet(config, device);
    if (!dev) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing '%s' in 'config' from cloud-hypervisor"),
                       device);
        return;
    }

    file = virJSONValueObjectGet(dev, "file");
    if (!file) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing 'file' in '%s' from cloud-hypervisor"),
                       device);
        return;
    }

    path = virJSONValueGetString(file);
    if (!path) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse contents of 'file' field in '%s' from cloud-hypervisor"),
                       device);
        return;
    }

    if (STREQ(device, "console")) {
        chr = vm->def->consoles[0];
    } else if (STREQ(device, "serial")) {
        chr = vm->def->serials[0];
    }

    if (chr && chr->source)
        chr->source->data.file.path = g_strdup(path);
}

static void
virCHProcessUpdateConsole(virDomainObj *vm,
                          virJSONValue *info)
{
    virJSONValue *config;

    config = virJSONValueObjectGet(info, "config");
    if (!config) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing 'config' in info query result from cloud-hypervisor"));
        return;
    }

    if (vm->def->nconsoles > 0)
        virCHProcessUpdateConsoleDevice(vm, config, "console");
    if (vm->def->nserials > 0)
        virCHProcessUpdateConsoleDevice(vm, config, "serial");
}

static int
virCHProcessUpdateInfo(virDomainObj *vm)
{
    virJSONValue *info;
    virCHDomainObjPrivate *priv = vm->privateData;
    if (virCHMonitorGetInfo(priv->monitor, &info) < 0)
        return -1;

    virCHProcessUpdateConsole(vm, info);

    virJSONValueFree(info);

    return 0;
}

/**
 * virCHProcessStart:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @reason: reason for switching vm to running state
 *
 * Starts Cloud-Hypervisor listen on a local socket
 *
 * Returns 0 on success or -1 in case of error
 */
int virCHProcessStart(virCHDriver *driver,
                      virDomainObj *vm,
                      virDomainRunningReason reason)
{
    int ret = -1;
    virCHDomainObjPrivate *priv = vm->privateData;

    if (!priv->monitor) {
        /* And we can get the first monitor connection now too */
        if (!(priv->monitor = virCHProcessConnectMonitor(driver, vm))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to create connection to CH socket"));
            goto cleanup;
        }

        if (virCHMonitorCreateVM(priv->monitor) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to create guest VM"));
            goto cleanup;
        }
    }

    if (virCHMonitorBootVM(priv->monitor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to boot guest VM"));
        goto cleanup;
    }

    vm->pid = priv->monitor->pid;
    vm->def->id = vm->pid;

    virCHProcessUpdateInfo(vm);

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    return 0;

 cleanup:
    if (ret)
        virCHProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);

    return ret;
}

int virCHProcessStop(virCHDriver *driver G_GNUC_UNUSED,
                     virDomainObj *vm,
                     virDomainShutoffReason reason)
{
    virCHDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);

    if (priv->monitor) {
        virCHMonitorClose(priv->monitor);
        priv->monitor = NULL;
    }

    vm->pid = -1;
    vm->def->id = -1;

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    return 0;
}
