/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * bridge_driver__conf.c: network.conf config file inspection
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
 */

/* includes */
#include <config.h>
#include "configmake.h"
#include "datatypes.h"
#include "virlog.h"
#include "virerror.h"
#include "virutil.h"
#include "bridge_driver_conf.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("network.bridge_driver");


static virClass *virNetworkDriverConfigClass;
static void virNetworkDriverConfigDispose(void *obj);

static int
virNetworkConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetworkDriverConfig, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virNetworkConfig);


dnsmasqCaps *
networkGetDnsmasqCaps(virNetworkDriverState *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->dnsmasqCaps);
}


static int
virNetworkLoadDriverConfig(virNetworkDriverConfig *cfg G_GNUC_UNUSED,
                           const char *filename)
{
    g_autoptr(virConf) conf = NULL;

    /* if file doesn't exist or is unreadable, ignore the "error" */
    if (access(filename, R_OK) == -1)
        return 0;

    conf = virConfReadFile(filename, 0);
    if (!conf)
        return -1;

    /* use virConfGetValue*(conf, ...) functions to read any settings into cfg */

    return 0;
}


virNetworkDriverConfig *
virNetworkDriverConfigNew(bool privileged)
{
    g_autoptr(virNetworkDriverConfig) cfg = NULL;
    g_autofree char *configdir = NULL;
    g_autofree char *configfile = NULL;

    if (virNetworkConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virNetworkDriverConfigClass)))
        return NULL;

    /* configuration/state paths are one of
     * ~/.config/libvirt/... (session/unprivileged)
     * /etc/libvirt/... && /var/(run|lib)/libvirt/... (system/privileged).
     */
    if (privileged) {
        configdir = g_strdup(SYSCONFDIR "/libvirt");
        cfg->networkConfigDir = g_strdup(SYSCONFDIR "/libvirt/qemu/networks");
        cfg->networkAutostartDir = g_strdup(SYSCONFDIR "/libvirt/qemu/networks/autostart");
        cfg->stateDir = g_strdup(RUNSTATEDIR "/libvirt/network");
        cfg->pidDir = g_strdup(RUNSTATEDIR "/libvirt/network");
        cfg->dnsmasqStateDir = g_strdup(LOCALSTATEDIR "/lib/libvirt/dnsmasq");
    } else {
        g_autofree char *rundir = virGetUserRuntimeDirectory();

        configdir = virGetUserConfigDirectory();
        cfg->networkConfigDir = g_strdup_printf("%s/qemu/networks", configdir);
        cfg->networkAutostartDir = g_strdup_printf("%s/qemu/networks/autostart", configdir);
        cfg->stateDir = g_strdup_printf("%s/network/lib", rundir);
        cfg->pidDir = g_strdup_printf("%s/network/run", rundir);
        cfg->dnsmasqStateDir = g_strdup_printf("%s/dnsmasq/lib", rundir);
    }

    configfile = g_strconcat(configdir, "/network.conf", NULL);

    if (virNetworkLoadDriverConfig(cfg, configfile) < 0)
        return NULL;

    if (g_mkdir_with_parents(cfg->stateDir, 0777) < 0) {
        virReportSystemError(errno, _("cannot create directory %1$s"), cfg->stateDir);
        return NULL;
    }

    return g_steal_pointer(&cfg);
}


virNetworkDriverConfig *
virNetworkDriverGetConfig(virNetworkDriverState *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->config);
}


static void
virNetworkDriverConfigDispose(void *obj)
{
    virNetworkDriverConfig *cfg = obj;

    g_free(cfg->networkConfigDir);
    g_free(cfg->networkAutostartDir);
    g_free(cfg->stateDir);
    g_free(cfg->pidDir);
    g_free(cfg->dnsmasqStateDir);
}



int
networkDnsmasqCapsRefresh(virNetworkDriverState *driver)
{
    dnsmasqCaps *caps;

    if (!(caps = dnsmasqCapsNewFromBinary()))
        return -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        virObjectUnref(driver->dnsmasqCaps);
        driver->dnsmasqCaps = caps;
    }

    return 0;
}
