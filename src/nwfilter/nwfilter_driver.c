/*
 * nwfilter_driver.c: core driver for network filter APIs
 *                    (based on storage_driver.c)
 *
 * Copyright (C) 2006-2011, 2014 Red Hat, Inc.
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
#include "virlog.h"

#include "internal.h"

#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "domain_nwfilter.h"
#include "nwfilter_conf.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"
#include "configmake.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#include "nwfilter_ipaddrmap.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_driver");

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

static int nwfilterStateCleanup(void);

static int nwfilterStateReload(void);

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
        nwfilterStateReload();
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
 * nwfilterStateInitialize:
 *
 * Initialization function for the QEmu daemon
 */
static int
nwfilterStateInitialize(bool privileged,
                        virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                        void *opaque ATTRIBUTE_UNUSED)
{
    char *base = NULL;
    DBusConnection *sysbus = NULL;

    if (!privileged)
        return 0;

    if (virDBusHasSystemBus() &&
        !(sysbus = virDBusGetSystemBus()))
        return -1;

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (virMutexInit(&driverState->lock) < 0)
        goto err_free_driverstate;

    /* remember that we are going to use firewalld */
    driverState->watchingFirewallD = (sysbus != NULL);
    driverState->privileged = privileged;

    nwfilterDriverLock(driverState);

    if (virNWFilterIPAddrMapInit() < 0)
        goto err_free_driverstate;
    if (virNWFilterLearnInit() < 0)
        goto err_exit_ipaddrmapshutdown;
    if (virNWFilterDHCPSnoopInit() < 0)
        goto err_exit_learnshutdown;

    if (virNWFilterTechDriversInit(privileged) < 0)
        goto err_dhcpsnoop_shutdown;

    if (virNWFilterConfLayerInit(virNWFilterDomainFWUpdateCB,
                                 driverState) < 0)
        goto err_techdrivers_shutdown;

    /*
     * startup the DBus late so we don't get a reload signal while
     * initializing
     */
    if (sysbus &&
        nwfilterDriverInstallDBusMatches(sysbus) < 0) {
        VIR_ERROR(_("DBus matches could not be installed. Disabling nwfilter "
                  "driver"));
        /*
         * unfortunately this is fatal since virNWFilterTechDriversInit
         * may have caused the ebiptables driver to use the firewall tool
         * but now that the watches don't work, we just disable the nwfilter
         * driver
         *
         * This may only happen if the system bus is available.
         */
        goto error;
    }

    if (VIR_STRDUP(base, SYSCONFDIR "/libvirt") < 0)
        goto error;

    if (virAsprintf(&driverState->configDir,
                    "%s/nwfilter", base) == -1)
        goto error;

    VIR_FREE(base);

    if (virNWFilterLoadAllConfigs(&driverState->nwfilters,
                                  driverState->configDir) < 0)
        goto error;

    nwfilterDriverUnlock(driverState);

    return 0;

 error:
    VIR_FREE(base);
    nwfilterDriverUnlock(driverState);
    nwfilterStateCleanup();

    return -1;

 err_techdrivers_shutdown:
    virNWFilterTechDriversShutdown();
 err_dhcpsnoop_shutdown:
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
 * nwfilterStateReload:
 *
 * Function to restart the nwfilter driver, it will recheck the configuration
 * files and update its state
 */
static int
nwfilterStateReload(void)
{
    if (!driverState)
        return -1;

    if (!driverState->privileged)
        return 0;

    virNWFilterDHCPSnoopEnd(NULL);
    /* shut down all threads -- they will be restarted if necessary */
    virNWFilterLearnThreadsTerminate(true);

    nwfilterDriverLock(driverState);
    virNWFilterWriteLockFilterUpdates();
    virNWFilterCallbackDriversLock();

    virNWFilterLoadAllConfigs(&driverState->nwfilters,
                              driverState->configDir);

    virNWFilterCallbackDriversUnlock();
    virNWFilterUnlockFilterUpdates();
    nwfilterDriverUnlock(driverState);

    virNWFilterInstFiltersOnAllVMs();

    return 0;
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
    if (!driverState)
        return false;

    return driverState->watchingFirewallD;
}

/**
 * nwfilterStateCleanup:
 *
 * Shutdown the nwfilter driver, it will stop all active nwfilters
 */
static int
nwfilterStateCleanup(void)
{
    if (!driverState)
        return -1;

    if (driverState->privileged) {
        virNWFilterConfLayerShutdown();
        virNWFilterDHCPSnoopShutdown();
        virNWFilterLearnShutdown();
        virNWFilterIPAddrMapShutdown();
        virNWFilterTechDriversShutdown();

        nwfilterDriverLock(driverState);

        nwfilterDriverRemoveDBusMatches();

        /* free inactive nwfilters */
        virNWFilterObjListFree(&driverState->nwfilters);

        VIR_FREE(driverState->configDir);
        nwfilterDriverUnlock(driverState);
    }

    virMutexDestroy(&driverState->lock);
    VIR_FREE(driverState);

    return 0;
}


static virNWFilterPtr
nwfilterLookupByUUID(virConnectPtr conn,
                     const unsigned char *uuid)
{
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

    if (virNWFilterLookupByUUIDEnsureACL(conn, nwfilter->def) < 0)
        goto cleanup;

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

 cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static virNWFilterPtr
nwfilterLookupByName(virConnectPtr conn,
                     const char *name)
{
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

    if (virNWFilterLookupByNameEnsureACL(conn, nwfilter->def) < 0)
        goto cleanup;

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
nwfilterClose(virConnectPtr conn)
{
    conn->nwfilterPrivateData = NULL;
    return 0;
}


static int
nwfilterConnectNumOfNWFilters(virConnectPtr conn)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    size_t i;
    int n;

    if (virConnectNumOfNWFiltersEnsureACL(conn) < 0)
        return -1;

    n = 0;
    for (i = 0; i < driver->nwfilters.count; i++) {
        virNWFilterObjPtr obj = driver->nwfilters.objs[i];
        virNWFilterObjLock(obj);
        if (virConnectNumOfNWFiltersCheckACL(conn, obj->def))
            n++;
        virNWFilterObjUnlock(obj);
    }

    return n;
}


static int
nwfilterConnectListNWFilters(virConnectPtr conn,
                             char **const names,
                             int nnames)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    int got = 0;
    size_t i;

    if (virConnectListNWFiltersEnsureACL(conn) < 0)
        return -1;

    nwfilterDriverLock(driver);
    for (i = 0; i < driver->nwfilters.count && got < nnames; i++) {
        virNWFilterObjPtr obj = driver->nwfilters.objs[i];
        virNWFilterObjLock(obj);
        if (virConnectListNWFiltersCheckACL(conn, obj->def)) {
            if (VIR_STRDUP(names[got], obj->def->name) < 0) {
                virNWFilterObjUnlock(obj);
                goto cleanup;
            }
            got++;
        }
        virNWFilterObjUnlock(obj);
    }
    nwfilterDriverUnlock(driver);
    return got;

 cleanup:
    nwfilterDriverUnlock(driver);
    for (i = 0; i < got; i++)
        VIR_FREE(names[i]);
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}


static int
nwfilterConnectListAllNWFilters(virConnectPtr conn,
                                virNWFilterPtr **filters,
                                unsigned int flags)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterPtr *tmp_filters = NULL;
    int nfilters = 0;
    virNWFilterPtr filter = NULL;
    virNWFilterObjPtr obj = NULL;
    size_t i;
    int ret = -1;

    virCheckFlags(0, -1);

    if (virConnectListAllNWFiltersEnsureACL(conn) < 0)
        return -1;

    nwfilterDriverLock(driver);

    if (!filters) {
        ret = driver->nwfilters.count;
        goto cleanup;
    }

    if (VIR_ALLOC_N(tmp_filters, driver->nwfilters.count + 1) < 0)
        goto cleanup;

    for (i = 0; i < driver->nwfilters.count; i++) {
        obj = driver->nwfilters.objs[i];
        virNWFilterObjLock(obj);
        if (virConnectListAllNWFiltersCheckACL(conn, obj->def)) {
            if (!(filter = virGetNWFilter(conn, obj->def->name,
                                          obj->def->uuid))) {
                virNWFilterObjUnlock(obj);
                goto cleanup;
            }
            tmp_filters[nfilters++] = filter;
        }
        virNWFilterObjUnlock(obj);
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
nwfilterDefineXML(virConnectPtr conn,
                  const char *xml)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterDefPtr def;
    virNWFilterObjPtr nwfilter = NULL;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    virNWFilterWriteLockFilterUpdates();
    virNWFilterCallbackDriversLock();

    if (!(def = virNWFilterDefParseString(xml)))
        goto cleanup;

    if (virNWFilterDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(nwfilter = virNWFilterObjAssignDef(&driver->nwfilters, def)))
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
    virNWFilterUnlockFilterUpdates();
    nwfilterDriverUnlock(driver);
    return ret;
}


static int
nwfilterUndefine(virNWFilterPtr obj)
{
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    int ret = -1;

    nwfilterDriverLock(driver);
    virNWFilterWriteLockFilterUpdates();
    virNWFilterCallbackDriversLock();

    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, obj->uuid);
    if (!nwfilter) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    if (virNWFilterUndefineEnsureACL(obj->conn, nwfilter->def) < 0)
        goto cleanup;

    if (virNWFilterTestUnassignDef(nwfilter) < 0) {
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

    virNWFilterCallbackDriversUnlock();
    virNWFilterUnlockFilterUpdates();
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

    if (virNWFilterGetXMLDescEnsureACL(obj->conn, nwfilter->def) < 0)
        goto cleanup;

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
    return virNWFilterInstantiateFilter(conn->nwfilterPrivateData, vmuuid, net);
}


static void
nwfilterTeardownFilter(virDomainNetDefPtr net)
{
    if ((net->ifname) && (net->filter))
        virNWFilterTeardownFilter(net);
}


static virNWFilterDriver nwfilterDriver = {
    .name = "nwfilter",
    .nwfilterOpen = nwfilterOpen, /* 0.8.0 */
    .nwfilterClose = nwfilterClose, /* 0.8.0 */
    .connectNumOfNWFilters = nwfilterConnectNumOfNWFilters, /* 0.8.0 */
    .connectListNWFilters = nwfilterConnectListNWFilters, /* 0.8.0 */
    .connectListAllNWFilters = nwfilterConnectListAllNWFilters, /* 0.10.2 */
    .nwfilterLookupByName = nwfilterLookupByName, /* 0.8.0 */
    .nwfilterLookupByUUID = nwfilterLookupByUUID, /* 0.8.0 */
    .nwfilterDefineXML = nwfilterDefineXML, /* 0.8.0 */
    .nwfilterUndefine = nwfilterUndefine, /* 0.8.0 */
    .nwfilterGetXMLDesc = nwfilterGetXMLDesc, /* 0.8.0 */
};


static virStateDriver stateDriver = {
    .name = "NWFilter",
    .stateInitialize = nwfilterStateInitialize,
    .stateCleanup = nwfilterStateCleanup,
    .stateReload = nwfilterStateReload,
};


static virDomainConfNWFilterDriver domainNWFilterDriver = {
    .instantiateFilter = nwfilterInstantiateFilter,
    .teardownFilter = nwfilterTeardownFilter,
};


int nwfilterRegister(void)
{
    if (virRegisterNWFilterDriver(&nwfilterDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    virDomainConfNWFilterRegister(&domainNWFilterDriver);
    return 0;
}
