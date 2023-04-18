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
#include "virobject.h"
#include "virstring.h"
#include "virthread.h"
#include "virutil.h"
#include "viridentity.h"
#include "datatypes.h"
#include "configmake.h"
#include "virtypedparam.h"

VIR_LOG_INIT("driver");

#define VIR_FROM_THIS VIR_FROM_NONE

/* XXX re-implement this for other OS, or use libtools helper lib ? */
#define DEFAULT_DRIVER_DIR LIBDIR "/libvirt/connection-driver"



int
virDriverLoadModule(const char *name,
                    const char *regfunc,
                    bool required)
{
    g_autofree char *modfile = NULL;

    VIR_DEBUG("Module load %s", name);

    if (!(modfile = virFileFindResourceFull(name,
                                            "libvirt_driver_",
                                            VIR_FILE_MODULE_EXT,
                                            abs_top_builddir "/src",
                                            DEFAULT_DRIVER_DIR,
                                            "LIBVIRT_DRIVER_DIR")))
        return -1;

    return virModuleLoad(modfile, regfunc, required);
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

    path = g_strdup_printf("%s/autostarted", dir);

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
    if (virThreadLocalInit(&connectInterface, NULL) < 0 ||
        virThreadLocalInit(&connectNetwork, NULL) < 0 ||
        virThreadLocalInit(&connectNWFilter, NULL) < 0 ||
        virThreadLocalInit(&connectNodeDev, NULL) < 0 ||
        virThreadLocalInit(&connectSecret, NULL) < 0 ||
        virThreadLocalInit(&connectStorage, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize thread local variable"));
        return -1;
    }

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virConnectCache);

static virConnectPtr
virGetConnectGeneric(virThreadLocal *threadPtr, const char *name)
{
    virConnectPtr conn;
    virErrorPtr orig_err;

    if (virConnectCacheInitialize() < 0)
        return NULL;

    conn = virThreadLocalGet(threadPtr);

    if (conn) {
        VIR_DEBUG("Return cached %s connection %p", name, conn);
        virObjectRef(conn);
    } else {
        g_autofree char *uri = NULL;
        const char *uriPath = geteuid() == 0 ? "/system" : "/session";

        uri = g_strdup_printf("%s://%s", name, uriPath);

        conn = virConnectOpen(uri);
        VIR_DEBUG("Opened new %s connection %p", name, conn);
        if (!conn)
            return NULL;

        if (conn->driver->connectSetIdentity != NULL) {
            g_autoptr(virIdentity) ident = NULL;

            VIR_DEBUG("Attempting to delegate current identity");
            ident = virIdentityGetCurrent();
            if (ident) {
                g_autoptr(virTypedParamList) tmp = virIdentityGetParameters(ident);
                virTypedParameterPtr par;
                size_t npar;

                if (virTypedParamListFetch(tmp, &par, &npar) < 0)
                    goto error;

                if (virConnectSetIdentity(conn, par, npar, 0) < 0)
                    goto error;
            }
        }
    }
    return conn;

 error:
    virErrorPreserveLast(&orig_err);
    virConnectClose(conn);
    virErrorRestore(&orig_err);
    return NULL;
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
                           _("unexpected %1$s URI path '%2$s', try %3$s:///system"),
                           entityName, uriPath, entityName);
            return false;
        }
    } else {
        if (STRNEQ(uriPath, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected %1$s URI path '%2$s', try %3$s:///session"),
                           entityName, uriPath, entityName);
            return false;
        }
    }

    return true;
}


/**
 * virDriverFeatureIsGlobal:
 * @feat: a VIR_DRV_FEATURE
 * @supported: If a feature is globally handled
 *
 * Certain driver feature flags are really not for individual drivers to decide
 * whether they implement them or not, but are rather global based on e.g.
 * whether the RPC protocol supports it.
 *
 * This function returns 'true' and fills @supported if a feature is a global
 * feature and the individual driver implementations don't decide whether
 * they support it or not.
 */
bool
virDriverFeatureIsGlobal(virDrvFeature feat,
                         int *supported)

{
    switch (feat) {
    /* This is a special case where the generated remote driver dispatcher
     * function intercepts this specific flag and returns '1'. Thus any local
     * implementation must return 0, so that the return value properly reflects
     * whether we are going through the remote driver */
    case VIR_DRV_FEATURE_REMOTE:
    /* keepalive is handled at RPC level, driver implementations must always
     * return 0, to signal that direct/embedded use doesn't use keepalive */
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    /* Support for close callbacks and remote event filtering are both features
     * of the RPC protocol and thus normal drivers must not signal support
     * for them. */
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
        *supported = 0;
        return true;

    /* Limitation of string support in typed parameters was an RPC limitation.
     * At this point everything supports them and thus also drivers need to
     * always advertise this feature */
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    /* Feature flag exposes that the accidental switching of order of arguments
     * in the public API trampoline virNetworkUpdate is known. Updated clients
     * thus use the correct ordering with an updated server. All drivers must
     * signal support for this feature. */
    case VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER:
    /* The remote driver intercepts and always reports the feature since it was
     * introduced. This means that all driver implementations should advertise
     * it too as it works natively without RPC. Always enabling this will also
     * prevent regressions when a driver is used in embedded mode */
    case VIR_DRV_FEATURE_FD_PASSING:
        *supported = 1;
        return true;

    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
    case VIR_DRV_FEATURE_MIGRATION_V1:
    default:
        return false;
    }
}
