/*
 * nwfilter_driver.c: core driver for network filter APIs
 *                    (based on storage_driver.c)
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
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
 *         Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "virdbus.h"
#include "logging.h"

#include "internal.h"

#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "domain_conf.h"
#include "domain_nwfilter.h"
#include "nwfilter_conf.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"
#include "configmake.h"

#include "nwfilter_ipaddrmap.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

#define DBUS_RULE_FWD_NAMEOWNERCHANGED \
    "type='signal'" \
    ",interface='"DBUS_INTERFACE_DBUS"'" \
    ",member='NameOwnerChanged'" \
    ",arg0='org.fedoraproject.FirewallD1'"

#define DBUS_RULE_FWD_RELOADED \
    "type='signal'" \
    ",interface='org.fedoraproject.FirewallD1'" \
    ",member='Reloaded'"


static virNWFilterDriverStatePtr driverState;

static int nwfilterDriverShutdown(void);

static int nwfilterDriverReload(void);

static void nwfilterDriverLock(virNWFilterDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}
static void nwfilterDriverUnlock(virNWFilterDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

#if HAVE_FIREWALLD

static DBusHandlerResult
nwfilterFirewalldDBusFilter(DBusConnection *connection ATTRIBUTE_UNUSED,
                            DBusMessage *message,
                            void *user_data ATTRIBUTE_UNUSED)
{
    if (dbus_message_is_signal(message, DBUS_INTERFACE_DBUS,
                               "NameOwnerChanged") ||
        dbus_message_is_signal(message, "org.fedoraproject.FirewallD1",
                               "Reloaded")) {
        VIR_DEBUG("Reload in nwfilter_driver because of firewalld.");
        nwfilterDriverReload();
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
nwfilterDriverRemoveDBusMatches(void)
{
    DBusConnection *sysbus;

    sysbus = virDBusGetSystemBus();
    if (sysbus) {
        dbus_bus_remove_match(sysbus,
                              DBUS_RULE_FWD_NAMEOWNERCHANGED,
                              NULL);
        dbus_bus_remove_match(sysbus,
                              DBUS_RULE_FWD_RELOADED,
                              NULL);
        dbus_connection_remove_filter(sysbus, nwfilterFirewalldDBusFilter, NULL);
    }
}

/**
 * virNWFilterDriverInstallDBusMatches
 *
 * Startup DBus matches for monitoring the state of firewalld
 */
static int
nwfilterDriverInstallDBusMatches(DBusConnection *sysbus)
{
    int ret = 0;

    if (!sysbus) {
        ret = -1;
    } else {
        /* add matches for
         * NameOwnerChanged on org.freedesktop.DBus for firewalld start/stop
         * Reloaded on org.fedoraproject.FirewallD1 for firewalld reload
         */
        dbus_bus_add_match(sysbus,
                           DBUS_RULE_FWD_NAMEOWNERCHANGED,
                           NULL);
        dbus_bus_add_match(sysbus,
                           DBUS_RULE_FWD_RELOADED,
                           NULL);
        if (!dbus_connection_add_filter(sysbus, nwfilterFirewalldDBusFilter,
                                        NULL, NULL)) {
            VIR_WARN(("Adding a filter to the DBus connection failed"));
            nwfilterDriverRemoveDBusMatches();
            ret =  -1;
        }
    }

    return ret;
}

#else /* HAVE_FIREWALLD */

static void
nwfilterDriverRemoveDBusMatches(void)
{
}

static int
nwfilterDriverInstallDBusMatches(DBusConnection *sysbus ATTRIBUTE_UNUSED)
{
    return 0;
}

#endif /* HAVE_FIREWALLD */

/**
 * virNWFilterStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
nwfilterDriverStartup(int privileged)
{
    char *base = NULL;
    DBusConnection *sysbus = NULL;

#if HAVE_DBUS
    sysbus = virDBusGetSystemBus();
#endif /* HAVE_DBUS */

    if (VIR_ALLOC(driverState) < 0)
        goto alloc_err_exit;

    if (virMutexInit(&driverState->lock) < 0)
        goto err_free_driverstate;

    driverState->watchingFirewallD = (sysbus != NULL);

    if (!privileged)
        return 0;

    if (virNWFilterIPAddrMapInit() < 0)
        goto err_free_driverstate;
    if (virNWFilterLearnInit() < 0)
        goto err_exit_ipaddrmapshutdown;
    if (virNWFilterDHCPSnoopInit() < 0)
        goto err_exit_learnshutdown;

    virNWFilterTechDriversInit(privileged);

    if (virNWFilterConfLayerInit(virNWFilterDomainFWUpdateCB) < 0)
        goto err_techdrivers_shutdown;

    nwfilterDriverLock(driverState);

    /*
     * startup the DBus late so we don't get a reload signal while
     * initializing
     */
    if (nwfilterDriverInstallDBusMatches(sysbus) < 0) {
        VIR_ERROR(_("DBus matches could not be installed. Disabling nwfilter "
                  "driver"));
        /*
         * unfortunately this is fatal since virNWFilterTechDriversInit
         * may have caused the ebiptables driver to use the firewall tool
         * but now that the watches don't work, we just disable the nwfilter
         * driver
         */
        goto error;
    }

    if (privileged) {
        if ((base = strdup (SYSCONFDIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        base = virGetUserConfigDirectory();
        if (!base)
            goto error;
    }

    if (virAsprintf(&driverState->configDir,
                    "%s/nwfilter", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if (virNWFilterLoadAllConfigs(NULL,
                                  &driverState->nwfilters,
                                  driverState->configDir) < 0)
        goto error;

    nwfilterDriverUnlock(driverState);

    return 0;

out_of_memory:
    virReportOOMError();

error:
    VIR_FREE(base);
    nwfilterDriverUnlock(driverState);
    nwfilterDriverShutdown();

alloc_err_exit:
    return -1;

    nwfilterDriverUnlock(driverState);

err_techdrivers_shutdown:
    virNWFilterTechDriversShutdown();
    virNWFilterDHCPSnoopShutdown();
err_exit_learnshutdown:
    virNWFilterLearnShutdown();
err_exit_ipaddrmapshutdown:
    virNWFilterIPAddrMapShutdown();

err_free_driverstate:
    VIR_FREE(driverState);

    return -1;
}

/**
 * virNWFilterReload:
 *
 * Function to restart the nwfilter driver, it will recheck the configuration
 * files and update its state
 */
static int
nwfilterDriverReload(void) {
    virConnectPtr conn;

    if (!driverState) {
        return -1;
    }

    conn = virConnectOpen("qemu:///system");

    if (conn) {
        virNWFilterDHCPSnoopEnd(NULL);
        /* shut down all threads -- they will be restarted if necessary */
        virNWFilterLearnThreadsTerminate(true);

        nwfilterDriverLock(driverState);
        virNWFilterCallbackDriversLock();

        virNWFilterLoadAllConfigs(conn,
                                  &driverState->nwfilters,
                                  driverState->configDir);

        virNWFilterCallbackDriversUnlock();
        nwfilterDriverUnlock(driverState);

        virNWFilterInstFiltersOnAllVMs(conn);

        virConnectClose(conn);
    }

    return 0;
}

/**
 * virNWFilterActive:
 *
 * Checks if the nwfilter driver is active, i.e. has an active nwfilter
 *
 * Returns 1 if active, 0 otherwise
 */
static int
nwfilterDriverActive(void) {
    int ret;

    if (!driverState)
        return 0;

    nwfilterDriverLock(driverState);
    ret = driverState->nwfilters.count ? 1 : 0;
    ret |= driverState->watchingFirewallD;
    nwfilterDriverUnlock(driverState);

    return ret;
}

/**
 * virNWFilterIsWatchingFirewallD:
 *
 * Checks if the nwfilter has the DBus watches for FirewallD installed.
 *
 * Returns true if it is watching firewalld, false otherwise
 */
bool
virNWFilterDriverIsWatchingFirewallD(void)
{
    bool ret;

    if (!driverState)
        return false;

    nwfilterDriverLock(driverState);
    ret = driverState->watchingFirewallD;
    nwfilterDriverUnlock(driverState);

    return ret;
}

/**
 * virNWFilterShutdown:
 *
 * Shutdown the nwfilter driver, it will stop all active nwfilters
 */
static int
nwfilterDriverShutdown(void) {
    if (!driverState)
        return -1;

    virNWFilterConfLayerShutdown();
    virNWFilterTechDriversShutdown();
    virNWFilterDHCPSnoopShutdown();
    virNWFilterLearnShutdown();
    virNWFilterIPAddrMapShutdown();

    nwfilterDriverLock(driverState);

    nwfilterDriverRemoveDBusMatches();

    /* free inactive nwfilters */
    virNWFilterObjListFree(&driverState->nwfilters);

    VIR_FREE(driverState->configDir);
    nwfilterDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);
    VIR_FREE(driverState);

    return 0;
}


static virNWFilterPtr
nwfilterLookupByUUID(virConnectPtr conn,
                     const unsigned char *uuid) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, uuid);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static virNWFilterPtr
nwfilterLookupByName(virConnectPtr conn,
                     const char *name) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByName(&driver->nwfilters, name);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("no nwfilter with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static virDrvOpenStatus
nwfilterOpen(virConnectPtr conn,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!driverState)
        return VIR_DRV_OPEN_DECLINED;

    conn->nwfilterPrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}


static int
nwfilterClose(virConnectPtr conn) {
    conn->nwfilterPrivateData = NULL;
    return 0;
}


static int
nwfilterNumNWFilters(virConnectPtr conn) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    return driver->nwfilters.count;
}


static int
nwfilterListNWFilters(virConnectPtr conn,
                      char **const names,
                      int nnames) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    int got = 0, i;

    nwfilterDriverLock(driver);
    for (i = 0 ; i < driver->nwfilters.count && got < nnames ; i++) {
        virNWFilterObjLock(driver->nwfilters.objs[i]);
        if (!(names[got] = strdup(driver->nwfilters.objs[i]->def->name))) {
             virNWFilterObjUnlock(driver->nwfilters.objs[i]);
             virReportOOMError();
             goto cleanup;
        }
        got++;
        virNWFilterObjUnlock(driver->nwfilters.objs[i]);
    }
    nwfilterDriverUnlock(driver);
    return got;

 cleanup:
    nwfilterDriverUnlock(driver);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}


static int
nwfilterListAllNWFilters(virConnectPtr conn,
                         virNWFilterPtr **filters,
                         unsigned int flags) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterPtr *tmp_filters = NULL;
    int nfilters = 0;
    virNWFilterPtr filter = NULL;
    virNWFilterObjPtr obj = NULL;
    int i;
    int ret = -1;

    virCheckFlags(0, -1);

    nwfilterDriverLock(driver);

    if (!filters) {
        ret = driver->nwfilters.count;
        goto cleanup;
    }

    if (VIR_ALLOC_N(tmp_filters, driver->nwfilters.count + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0 ; i < driver->nwfilters.count; i++) {
        obj = driver->nwfilters.objs[i];
        virNWFilterObjLock(obj);
        if (!(filter = virGetNWFilter(conn, obj->def->name,
                                      obj->def->uuid))) {
            virNWFilterObjUnlock(obj);
            goto cleanup;
        }
        virNWFilterObjUnlock(obj);
        tmp_filters[nfilters++] = filter;
    }

    *filters = tmp_filters;
    tmp_filters = NULL;
    ret = nfilters;

 cleanup:
    nwfilterDriverUnlock(driver);
    if (tmp_filters) {
        for (i = 0; i < nfilters; i ++) {
            if (tmp_filters[i])
                virNWFilterFree(tmp_filters[i]);
        }
    }
    VIR_FREE(tmp_filters);

    return ret;
}

static virNWFilterPtr
nwfilterDefine(virConnectPtr conn,
               const char *xml)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterDefPtr def;
    virNWFilterObjPtr nwfilter = NULL;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    virNWFilterCallbackDriversLock();

    if (!(def = virNWFilterDefParseString(conn, xml)))
        goto cleanup;

    if (!(nwfilter = virNWFilterObjAssignDef(conn, &driver->nwfilters, def)))
        goto cleanup;

    if (virNWFilterObjSaveDef(driver, nwfilter, def) < 0) {
        virNWFilterObjRemove(&driver->nwfilters, nwfilter);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    virNWFilterDefFree(def);
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);

    virNWFilterCallbackDriversUnlock();
    nwfilterDriverUnlock(driver);
    return ret;
}


static int
nwfilterUndefine(virNWFilterPtr obj) {
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    int ret = -1;

    nwfilterDriverLock(driver);
    virNWFilterCallbackDriversLock();

    virNWFilterLockFilterUpdates();

    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, obj->uuid);
    if (!nwfilter) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    if (virNWFilterTestUnassignDef(obj->conn, nwfilter) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s",
                       _("nwfilter is in use"));
        goto cleanup;
    }

    if (virNWFilterObjDeleteDef(nwfilter) < 0)
        goto cleanup;

    VIR_FREE(nwfilter->configFile);

    virNWFilterObjRemove(&driver->nwfilters, nwfilter);
    nwfilter = NULL;
    ret = 0;

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);

    virNWFilterUnlockFilterUpdates();

    virNWFilterCallbackDriversUnlock();
    nwfilterDriverUnlock(driver);
    return ret;
}


static char *
nwfilterGetXMLDesc(virNWFilterPtr obj,
                   unsigned int flags)
{
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, obj->uuid);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    ret = virNWFilterDefFormat(nwfilter->def);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static int
nwfilterInstantiateFilter(virConnectPtr conn,
                          const unsigned char *vmuuid,
                          virDomainNetDefPtr net)
{
    return virNWFilterInstantiateFilter(conn, vmuuid, net);
}


static void
nwfilterTeardownFilter(virDomainNetDefPtr net) {
    if ((net->ifname) && (net->filter))
        virNWFilterTeardownFilter(net);
}


static virNWFilterDriver nwfilterDriver = {
    .name = "nwfilter",
    .open = nwfilterOpen, /* 0.8.0 */
    .close = nwfilterClose, /* 0.8.0 */
    .numOfNWFilters = nwfilterNumNWFilters, /* 0.8.0 */
    .listNWFilters = nwfilterListNWFilters, /* 0.8.0 */
    .listAllNWFilters = nwfilterListAllNWFilters, /* 0.10.2 */
    .nwfilterLookupByName = nwfilterLookupByName, /* 0.8.0 */
    .nwfilterLookupByUUID = nwfilterLookupByUUID, /* 0.8.0 */
    .defineXML = nwfilterDefine, /* 0.8.0 */
    .undefine = nwfilterUndefine, /* 0.8.0 */
    .getXMLDesc = nwfilterGetXMLDesc, /* 0.8.0 */
};


static virStateDriver stateDriver = {
    .name = "NWFilter",
    .initialize = nwfilterDriverStartup,
    .cleanup = nwfilterDriverShutdown,
    .reload = nwfilterDriverReload,
    .active = nwfilterDriverActive,
};


static virDomainConfNWFilterDriver domainNWFilterDriver = {
    .instantiateFilter = nwfilterInstantiateFilter,
    .teardownFilter = nwfilterTeardownFilter,
};


int nwfilterRegister(void) {
    virRegisterNWFilterDriver(&nwfilterDriver);
    virRegisterStateDriver(&stateDriver);
    virDomainConfNWFilterRegister(&domainNWFilterDriver);
    return 0;
}
