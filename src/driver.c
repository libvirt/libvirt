/*
 * driver.c: Helpers for loading drivers
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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


#include <config.h>

#include <unistd.h>

#include "driver.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virmodule.h"
#include "virstring.h"
#include "virthread.h"
#include "configmake.h"

VIR_LOG_INIT("driver");

#define VIR_FROM_THIS VIR_FROM_NONE

/* XXX re-implement this for other OS, or use libtools helper lib ? */
#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"



int
virDriverLoadModule(const char *name,
                    const char *regfunc,
                    bool required)
{
    char *modfile = NULL;
    int ret;

    VIR_DEBUG("Module load %s", name);

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_driver_",
                                            ".so",
                                            abs_top_builddir "/src/.libs",
                                            DEFAULT_DRIVER_DIR,
                                            "LIBVIRT_DRIVER_DIR")))
        return -1;

    ret = virModuleLoad(modfile, regfunc, required);

    VIR_FREE(modfile);

    return ret;
}


/* XXX unload modules, but we can't until we can unregister libvirt drivers */

/**
 * virDriverShouldAutostart:
 * @dir: driver's run state directory (usually /var/run/libvirt/$driver)
 * @autostart: whether driver should initiate autostart
 *
 * Automatic starting of libvirt's objects (e.g. domains, networks, storage
 * pools, etc.) doesn't play nice with using '--timeout' on daemon's command
 * line because the objects are attempted to autostart on every start of
 * corresponding driver/daemon. To resolve this problem, a file is created in
 * driver's private directory (which doesn't survive host's reboot) and thus
 * autostart is attempted only once.
 */
int
virDriverShouldAutostart(const char *dir,
                         bool *autostart)
{
    g_autofree char *path = NULL;

    *autostart = false;

    if (virAsprintf(&path, "%s/autostarted", dir) < 0)
        return -1;

    if (virFileExists(path)) {
        VIR_DEBUG("Autostart file %s exists, skipping autostart", path);
        return 0;
    }

    VIR_DEBUG("Autostart file %s does not exist, do autostart", path);
    *autostart = true;

    if (virFileTouch(path, 0600) < 0)
        return -1;

    return 0;
}


virThreadLocal connectInterface;
virThreadLocal connectNetwork;
virThreadLocal connectNWFilter;
virThreadLocal connectNodeDev;
virThreadLocal connectSecret;
virThreadLocal connectStorage;

static int
virConnectCacheOnceInit(void)
{
    if (virThreadLocalInit(&connectInterface, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNetwork, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNWFilter, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectNodeDev, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectSecret, NULL) < 0)
        return -1;
    if (virThreadLocalInit(&connectStorage, NULL) < 0)
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virConnectCache);

static virConnectPtr
virGetConnectGeneric(virThreadLocalPtr threadPtr, const char *name)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(threadPtr);

    if (conn) {
        VIR_DEBUG("Return cached %s connection %p", name, conn);
        virObjectRef(conn);
    } else {
        g_autofree char *uri = NULL;
        const char *uriPath = geteuid() == 0 ? "/system" : "/session";

        if (virAsprintf(&uri, "%s://%s", name, uriPath) < 0)
            return NULL;

        conn = virConnectOpen(uri);
        VIR_DEBUG("Opened new %s connection %p", name, conn);
    }
    return conn;
}


virConnectPtr virGetConnectInterface(void)
{
    return virGetConnectGeneric(&connectInterface, "interface");
}

virConnectPtr virGetConnectNetwork(void)
{
    return virGetConnectGeneric(&connectNetwork, "network");
}

virConnectPtr virGetConnectNWFilter(void)
{
    return virGetConnectGeneric(&connectNWFilter, "nwfilter");
}

virConnectPtr virGetConnectNodeDev(void)
{
    return virGetConnectGeneric(&connectNodeDev, "nodedev");
}

virConnectPtr virGetConnectSecret(void)
{
    return virGetConnectGeneric(&connectSecret, "secret");
}

virConnectPtr virGetConnectStorage(void)
{
    return virGetConnectGeneric(&connectStorage, "storage");
}


int
virSetConnectInterface(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override interface connection with %p", conn);
    return virThreadLocalSet(&connectInterface, conn);
}


int
virSetConnectNetwork(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override network connection with %p", conn);
    return virThreadLocalSet(&connectNetwork, conn);
}


int
virSetConnectNWFilter(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override nwfilter connection with %p", conn);
    return virThreadLocalSet(&connectNWFilter, conn);
}


int
virSetConnectNodeDev(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override nodedev connection with %p", conn);
    return virThreadLocalSet(&connectNodeDev, conn);
}


int
virSetConnectSecret(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override secret connection with %p", conn);
    return virThreadLocalSet(&connectSecret, conn);
}


int
virSetConnectStorage(virConnectPtr conn)
{
    if (virConnectCacheInitialize() < 0)
        return -1;

    VIR_DEBUG("Override storage connection with %p", conn);
    return virThreadLocalSet(&connectStorage, conn);
}

bool
virConnectValidateURIPath(const char *uriPath,
                          const char *entityName,
                          bool privileged)
{
    if (privileged) {
        /* TODO: qemu and vbox drivers allow '/session'
         * connections as root. This is not ideal, but changing
         * these drivers to refuse privileged '/session'
         * connections, like everyone else is already doing, can
         * break existing applications. Until we decide what to do,
         * for now we can handle them as exception in this validate
         * function.
         */
        bool compatSessionRoot = (STREQ(entityName, "qemu") ||
                                  STREQ(entityName, "vbox")) &&
                                  STREQ(uriPath, "/session");

        if (STRNEQ(uriPath, "/system") && !compatSessionRoot) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected %s URI path '%s', try "
                             "%s:///system"),
                           entityName, uriPath, entityName);
            return false;
        }
    } else {
        if (STRNEQ(uriPath, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected %s URI path '%s', try "
                             "%s:///session"),
                           entityName, uriPath, entityName);
            return false;
        }
    }

    return true;
}
