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
    VIR_AUTOFREE(char *) path = NULL;

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

virConnectPtr virGetConnectInterface(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectInterface);
    if (conn) {
        VIR_DEBUG("Return cached interface connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "interface:///system" : "interface:///session");
        VIR_DEBUG("Opened new interface connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNetwork(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNetwork);
    if (conn) {
        VIR_DEBUG("Return cached network connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "network:///system" : "network:///session");
        VIR_DEBUG("Opened new network connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNWFilter(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNWFilter);
    if (conn) {
        VIR_DEBUG("Return cached nwfilter connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "nwfilter:///system" : "nwfilter:///session");
        VIR_DEBUG("Opened new nwfilter connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectNodeDev(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectNodeDev);
    if (conn) {
        VIR_DEBUG("Return cached nodedev connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "nodedev:///system" : "nodedev:///session");
        VIR_DEBUG("Opened new nodedev connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectSecret(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectSecret);
    if (conn) {
        VIR_DEBUG("Return cached secret connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "secret:///system" : "secret:///session");
        VIR_DEBUG("Opened new secret connection %p", conn);
    }
    return conn;
}

virConnectPtr virGetConnectStorage(void)
{
    virConnectPtr conn;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(&connectStorage);
    if (conn) {
        VIR_DEBUG("Return cached storage connection %p", conn);
        virObjectRef(conn);
    } else {
        conn = virConnectOpen(geteuid() == 0 ? "storage:///system" : "storage:///session");
        VIR_DEBUG("Opened new storage connection %p", conn);
    }
    return conn;
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
