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
 */

#include <config.h>

#include "virgdbus.h"
#include "virlog.h"

#include "internal.h"

#include "virerror.h"
#include "datatypes.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"
#include "configmake.h"
#include "virpidfile.h"
#include "viraccessapicheck.h"

#include "nwfilter_ipaddrmap.h"
#include "nwfilter_dhcpsnoop.h"
#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_driver");


static virNWFilterDriverState *driver;

static int nwfilterStateReload(void);

static virMutex driverMutex = VIR_MUTEX_INITIALIZER;

#ifdef WITH_FIREWALLD

static void nwfilterStateReloadThread(void *opaque G_GNUC_UNUSED)
{
    VIR_INFO("Reloading configuration on firewalld reload/restart");

    nwfilterStateReload();
}

static void
nwfilterFirewalldDBusSignalCallback(GDBusConnection *connection G_GNUC_UNUSED,
                                    const char *senderName G_GNUC_UNUSED,
                                    const char *objectPath G_GNUC_UNUSED,
                                    const char *interfaceName G_GNUC_UNUSED,
                                    const char *signalName G_GNUC_UNUSED,
                                    GVariant *parameters G_GNUC_UNUSED,
                                    gpointer user_data G_GNUC_UNUSED)
{
    virThread thr;

    if (virThreadCreateFull(&thr, false, nwfilterStateReloadThread,
                            "firewall-reload", false, NULL) < 0) {
        /*
         * Not much we can do on error here except log it.
         */
        VIR_ERROR(_("Failed to create thread to handle firewall reload/restart"));
    }
}

static unsigned int restartID;
static unsigned int reloadID;

static void
nwfilterDriverRemoveDBusMatches(void)
{
    GDBusConnection *sysbus = virGDBusGetSystemBus();

    if (!sysbus)
        return;

    if (restartID != 0) {
        g_dbus_connection_signal_unsubscribe(sysbus, restartID);
        restartID = 0;
    }

    if (reloadID != 0) {
        g_dbus_connection_signal_unsubscribe(sysbus, reloadID);
        reloadID = 0;
    }
}

/**
 * virNWFilterDriverInstallDBusMatches
 *
 * Startup DBus matches for monitoring the state of firewalld
 */
static void
nwfilterDriverInstallDBusMatches(GDBusConnection *sysbus)
{
    restartID = g_dbus_connection_signal_subscribe(sysbus,
                                                   NULL,
                                                   "org.freedesktop.DBus",
                                                   "NameOwnerChanged",
                                                   NULL,
                                                   "org.fedoraproject.FirewallD1",
                                                   G_DBUS_SIGNAL_FLAGS_NONE,
                                                   nwfilterFirewalldDBusSignalCallback,
                                                   NULL,
                                                   NULL);
    reloadID = g_dbus_connection_signal_subscribe(sysbus,
                                                  NULL,
                                                  "org.fedoraproject.FirewallD1",
                                                  "Reloaded",
                                                  NULL,
                                                  NULL,
                                                  G_DBUS_SIGNAL_FLAGS_NONE,
                                                  nwfilterFirewalldDBusSignalCallback,
                                                  NULL,
                                                  NULL);
}

#else /* WITH_FIREWALLD */

static void
nwfilterDriverRemoveDBusMatches(void)
{
}

static void
nwfilterDriverInstallDBusMatches(GDBusConnection *sysbus G_GNUC_UNUSED)
{
}

#endif /* WITH_FIREWALLD */

static int
virNWFilterTriggerRebuildImpl(void *opaque)
{
    virNWFilterDriverState *nwdriver = opaque;

    return virNWFilterBuildAll(nwdriver, true);
}


static int
nwfilterStateCleanupLocked(void)
{
    if (!driver)
        return -1;

    if (driver->privileged) {
        virNWFilterConfLayerShutdown();
        virNWFilterDHCPSnoopShutdown();
        virNWFilterLearnShutdown();
        virNWFilterIPAddrMapShutdown();
        virNWFilterTechDriversShutdown();
        nwfilterDriverRemoveDBusMatches();

        if (driver->lockFD != -1)
            virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

        g_free(driver->stateDir);
        g_free(driver->configDir);
        g_free(driver->bindingDir);
    }

    virObjectUnref(driver->bindings);

    /* free inactive nwfilters */
    virNWFilterObjListFree(driver->nwfilters);

    if (driver->updateLockInitialized)
        virMutexDestroy(&driver->updateLock);
    g_clear_pointer(&driver, g_free);

    return 0;
}

/**
 * nwfilterStateCleanup:
 *
 * Shutdown the nwfilter driver, it will stop all active nwfilters
 */
static int
nwfilterStateCleanup(void)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driverMutex);
    return nwfilterStateCleanupLocked();
}


/**
 * nwfilterStateInitialize:
 *
 * Initialization function for the QEMU daemon
 */
static int
nwfilterStateInitialize(bool privileged,
                        const char *root,
                        bool monolithic G_GNUC_UNUSED,
                        virStateInhibitCallback callback G_GNUC_UNUSED,
                        void *opaque G_GNUC_UNUSED)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driverMutex);
    GDBusConnection *sysbus = NULL;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (virGDBusHasSystemBus() && !(sysbus = virGDBusGetSystemBus()))
        return VIR_DRV_STATE_INIT_ERROR;

    driver = g_new0(virNWFilterDriverState, 1);

    driver->lockFD = -1;
    if (virMutexInitRecursive(&driver->updateLock) < 0)
        goto error;

    driver->updateLockInitialized = true;
    driver->privileged = privileged;

    if (!(driver->nwfilters = virNWFilterObjListNew()))
        goto error;

    if (!(driver->bindings = virNWFilterBindingObjListNew()))
        goto error;

    if (!privileged)
        return VIR_DRV_STATE_INIT_SKIPPED;

    driver->stateDir = g_strdup(RUNSTATEDIR "/libvirt/nwfilter");

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto error;
    }

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto error;

    if (virNWFilterIPAddrMapInit() < 0)
        goto error;

    if (virNWFilterLearnInit() < 0)
        goto error;

    if (virNWFilterDHCPSnoopInit() < 0)
        goto error;

    if (virNWFilterTechDriversInit(privileged) < 0)
        goto error;

    if (virNWFilterConfLayerInit(virNWFilterTriggerRebuildImpl, driver) < 0)
        goto error;

    /*
     * startup the DBus late so we don't get a reload signal while
     * initializing
     */
    if (sysbus)
        nwfilterDriverInstallDBusMatches(sysbus);

    driver->configDir = g_strdup(SYSCONFDIR "/libvirt/nwfilter");

    if (g_mkdir_with_parents(driver->configDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             driver->configDir);
        goto error;
    }

    driver->bindingDir = g_strdup(RUNSTATEDIR "/libvirt/nwfilter-binding");

    if (g_mkdir_with_parents(driver->bindingDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create config directory '%1$s'"),
                             driver->bindingDir);
        goto error;
    }

    if (virNWFilterObjListLoadAllConfigs(driver->nwfilters, driver->configDir) < 0)
        goto error;

    if (virNWFilterBindingObjListLoadAllConfigs(driver->bindings, driver->bindingDir) < 0)
        goto error;

    if (virNWFilterBuildAll(driver, false) < 0)
        goto error;

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    nwfilterStateCleanupLocked();
    return VIR_DRV_STATE_INIT_ERROR;
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
    if (!driver)
        return -1;

    if (!driver->privileged)
        return 0;

    virNWFilterDHCPSnoopEnd(NULL);
    /* shut down all threads -- they will be restarted if necessary */
    virNWFilterLearnThreadsTerminate(true);

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        VIR_WITH_MUTEX_LOCK_GUARD(&driver->updateLock) {
            virNWFilterObjListLoadAllConfigs(driver->nwfilters, driver->configDir);
        }


        virNWFilterBuildAll(driver, false);
    }

    return 0;
}


static virDrvOpenStatus
nwfilterConnectOpen(virConnectPtr conn,
                    virConnectAuthPtr auth G_GNUC_UNUSED,
                    virConf *conf G_GNUC_UNUSED,
                    unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nwfilter state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected nwfilter URI path '%1$s', try nwfilter:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int nwfilterConnectClose(virConnectPtr conn G_GNUC_UNUSED)
{
    return 0;
}


static int nwfilterConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int nwfilterConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int nwfilterConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static virNWFilterObj *
nwfilterObjFromNWFilter(const unsigned char *uuid)
{
    virNWFilterObj *obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(obj = virNWFilterObjListFindByUUID(driver->nwfilters, uuid))) {
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("no nwfilter with matching uuid '%1$s'"), uuidstr);
    }
    return obj;
}


static virNWFilterPtr
nwfilterLookupByUUID(virConnectPtr conn,
                     const unsigned char *uuid)
{
    virNWFilterObj *obj = NULL;
    virNWFilterDef *def;
    virNWFilterPtr nwfilter = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        obj = nwfilterObjFromNWFilter(uuid);
    }

    if (!obj)
        return NULL;
    def = virNWFilterObjGetDef(obj);

    if (virNWFilterLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    nwfilter = virGetNWFilter(conn, def->name, def->uuid);

 cleanup:
    virNWFilterObjUnlock(obj);
    return nwfilter;
}


static virNWFilterPtr
nwfilterLookupByName(virConnectPtr conn,
                     const char *name)
{
    virNWFilterObj *obj = NULL;
    virNWFilterDef *def;
    virNWFilterPtr nwfilter = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        obj = virNWFilterObjListFindByName(driver->nwfilters, name);
    }

    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("no nwfilter with matching name '%1$s'"), name);
        return NULL;
    }
    def = virNWFilterObjGetDef(obj);

    if (virNWFilterLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    nwfilter = virGetNWFilter(conn, def->name, def->uuid);

 cleanup:
    virNWFilterObjUnlock(obj);
    return nwfilter;
}


static int
nwfilterConnectNumOfNWFilters(virConnectPtr conn)
{
    int ret = -1;
    if (virConnectNumOfNWFiltersEnsureACL(conn) < 0)
        return -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        ret = virNWFilterObjListNumOfNWFilters(driver->nwfilters, conn,
                                               virConnectNumOfNWFiltersCheckACL);
    }

    return ret;
}


static int
nwfilterConnectListNWFilters(virConnectPtr conn,
                             char **const names,
                             int maxnames)
{
    int nnames = -1;

    if (virConnectListNWFiltersEnsureACL(conn) < 0)
        return -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        nnames = virNWFilterObjListGetNames(driver->nwfilters, conn,
                                            virConnectListNWFiltersCheckACL,
                                            names, maxnames);
    }

    return nnames;
}


static int
nwfilterConnectListAllNWFilters(virConnectPtr conn,
                                virNWFilterPtr **nwfilters,
                                unsigned int flags)
{
    int ret = -1;

    virCheckFlags(0, -1);

    if (virConnectListAllNWFiltersEnsureACL(conn) < 0)
        return -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        ret = virNWFilterObjListExport(conn, driver->nwfilters, nwfilters,
                                       virConnectListAllNWFiltersCheckACL);
    }

    return ret;
}


static virNWFilterPtr
nwfilterDefineXMLFlags(virConnectPtr conn,
                       const char *xml,
                       unsigned int flags)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driverMutex);
    virNWFilterDef *def;
    virNWFilterObj *obj = NULL;
    virNWFilterDef *objdef;
    virNWFilterPtr nwfilter = NULL;

    virCheckFlags(VIR_NWFILTER_DEFINE_VALIDATE, NULL);


    if (!driver->privileged) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Can't define NWFilters in session mode"));
        return NULL;
    }

    if (!(def = virNWFilterDefParse(xml, NULL, flags)))
        goto cleanup;

    if (virNWFilterDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->updateLock) {
        if (!(obj = virNWFilterObjListAssignDef(driver->nwfilters, def)))
            goto cleanup;
    }
    def = NULL;
    objdef = virNWFilterObjGetDef(obj);

    if (virNWFilterSaveConfig(driver->configDir, objdef) < 0) {
        virNWFilterObjListRemove(driver->nwfilters, obj);
        goto cleanup;
    }

    nwfilter = virGetNWFilter(conn, objdef->name, objdef->uuid);

 cleanup:
    virNWFilterDefFree(def);
    if (obj)
        virNWFilterObjUnlock(obj);
    return nwfilter;
}


static virNWFilterPtr
nwfilterDefineXML(virConnectPtr conn,
                  const char *xml)
{
    return nwfilterDefineXMLFlags(conn, xml, 0);
}


static int
nwfilterUndefine(virNWFilterPtr nwfilter)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driverMutex);
    virNWFilterObj *obj;
    virNWFilterDef *def;
    int ret = -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->updateLock) {
        if (!(obj = nwfilterObjFromNWFilter(nwfilter->uuid)))
            goto cleanup;
        def = virNWFilterObjGetDef(obj);

        if (virNWFilterUndefineEnsureACL(nwfilter->conn, def) < 0)
            goto cleanup;

        if (virNWFilterObjTestUnassignDef(obj) < 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s",
                           _("nwfilter is in use"));
            goto cleanup;
        }

        if (virNWFilterDeleteDef(driver->configDir, def) < 0)
            goto cleanup;

        virNWFilterObjListRemove(driver->nwfilters, obj);
        obj = NULL;
    }
    ret = 0;

 cleanup:
    if (obj)
        virNWFilterObjUnlock(obj);

    return ret;
}


static char *
nwfilterGetXMLDesc(virNWFilterPtr nwfilter,
                   unsigned int flags)
{
    virNWFilterObj *obj = NULL;
    virNWFilterDef *def;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    VIR_WITH_MUTEX_LOCK_GUARD(&driverMutex) {
        obj = nwfilterObjFromNWFilter(nwfilter->uuid);
    }

    if (!obj)
        return NULL;
    def = virNWFilterObjGetDef(obj);

    if (virNWFilterGetXMLDescEnsureACL(nwfilter->conn, def) < 0)
        goto cleanup;

    ret = virNWFilterDefFormat(def);

 cleanup:
    virNWFilterObjUnlock(obj);
    return ret;
}


static virNWFilterBindingPtr
nwfilterBindingLookupByPortDev(virConnectPtr conn,
                               const char *portdev)
{
    virNWFilterBindingPtr ret = NULL;
    virNWFilterBindingObj *obj;
    virNWFilterBindingDef *def;

    obj = virNWFilterBindingObjListFindByPortDev(driver->bindings,
                                                 portdev);
    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER_BINDING,
                       _("no nwfilter binding for port dev '%1$s'"), portdev);
        goto cleanup;
    }

    def = virNWFilterBindingObjGetDef(obj);
    if (virNWFilterBindingLookupByPortDevEnsureACL(conn, def) < 0)
        goto cleanup;

    ret = virGetNWFilterBinding(conn, def->portdevname, def->filter);

 cleanup:
    virNWFilterBindingObjEndAPI(&obj);
    return ret;
}


static int
nwfilterConnectListAllNWFilterBindings(virConnectPtr conn,
                                       virNWFilterBindingPtr **bindings,
                                       unsigned int flags)
{
    virCheckFlags(0, -1);

    if (virConnectListAllNWFilterBindingsEnsureACL(conn) < 0)
        return -1;

    return virNWFilterBindingObjListExport(driver->bindings, conn, bindings,
                                           virConnectListAllNWFilterBindingsCheckACL);
}


static char *
nwfilterBindingGetXMLDesc(virNWFilterBindingPtr binding,
                          unsigned int flags)
{
    virNWFilterBindingObj *obj;
    virNWFilterBindingDef *def;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    obj = virNWFilterBindingObjListFindByPortDev(driver->bindings,
                                                 binding->portdev);
    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER_BINDING,
                       _("no nwfilter binding for port dev '%1$s'"), binding->portdev);
        goto cleanup;
    }

    def = virNWFilterBindingObjGetDef(obj);
    if (virNWFilterBindingGetXMLDescEnsureACL(binding->conn, def) < 0)
        goto cleanup;

    ret = virNWFilterBindingDefFormat(def);

 cleanup:
    virNWFilterBindingObjEndAPI(&obj);
    return ret;
}


static virNWFilterBindingPtr
nwfilterBindingCreateXML(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags)
{
    virNWFilterBindingDef *def;
    virNWFilterBindingObj *obj = NULL;
    virNWFilterBindingPtr ret = NULL;

    virCheckFlags(VIR_NWFILTER_BINDING_CREATE_VALIDATE, NULL);

    if (!driver->privileged) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Can't define NWFilter bindings in session mode"));
        return NULL;
    }

    def = virNWFilterBindingDefParse(xml, NULL, flags);
    if (!def)
        return NULL;

    if (virNWFilterBindingCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    obj = virNWFilterBindingObjListAdd(driver->bindings,
                                       def);
    if (!obj)
        goto cleanup;

    if (!(ret = virGetNWFilterBinding(conn, def->portdevname, def->filter)))
        goto cleanup;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->updateLock) {
        if (virNWFilterInstantiateFilter(driver, def) < 0) {
            virNWFilterBindingObjListRemove(driver->bindings, obj);
            g_clear_pointer(&ret, virObjectUnref);
            goto cleanup;
        }
    }

    virNWFilterBindingObjSave(obj, driver->bindingDir);

 cleanup:
    if (!obj)
        virNWFilterBindingDefFree(def);
    virNWFilterBindingObjEndAPI(&obj);

    return ret;
}


/*
 * Note that this is primarily intended for usage by the hypervisor
 * drivers. it is exposed to the admin, however, and nothing stops
 * an admin from deleting filter bindings created by the hypervisor
 * drivers. IOW, it is the admin's responsibility not to shoot
 * themself in the foot
 */
static int
nwfilterBindingDelete(virNWFilterBindingPtr binding)
{
    virNWFilterBindingObj *obj;
    virNWFilterBindingDef *def;
    int ret = -1;

    obj = virNWFilterBindingObjListFindByPortDev(driver->bindings, binding->portdev);
    if (!obj) {
        virReportError(VIR_ERR_NO_NWFILTER_BINDING,
                       _("no nwfilter binding for port dev '%1$s'"), binding->portdev);
        return -1;
    }

    def = virNWFilterBindingObjGetDef(obj);
    if (virNWFilterBindingDeleteEnsureACL(binding->conn, def) < 0)
        goto cleanup;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->updateLock) {
        virNWFilterTeardownFilter(def);
    }
    virNWFilterBindingObjDelete(obj, driver->bindingDir);
    virNWFilterBindingObjListRemove(driver->bindings, obj);

    ret = 0;

 cleanup:
    virNWFilterBindingObjEndAPI(&obj);
    return ret;
}


static virNWFilterDriver nwfilterDriver = {
    .name = "nwfilter",
    .connectNumOfNWFilters = nwfilterConnectNumOfNWFilters, /* 0.8.0 */
    .connectListNWFilters = nwfilterConnectListNWFilters, /* 0.8.0 */
    .connectListAllNWFilters = nwfilterConnectListAllNWFilters, /* 0.10.2 */
    .nwfilterLookupByName = nwfilterLookupByName, /* 0.8.0 */
    .nwfilterLookupByUUID = nwfilterLookupByUUID, /* 0.8.0 */
    .nwfilterDefineXML = nwfilterDefineXML, /* 0.8.0 */
    .nwfilterDefineXMLFlags = nwfilterDefineXMLFlags, /* 7.7.0 */
    .nwfilterUndefine = nwfilterUndefine, /* 0.8.0 */
    .nwfilterGetXMLDesc = nwfilterGetXMLDesc, /* 0.8.0 */
    .nwfilterBindingLookupByPortDev = nwfilterBindingLookupByPortDev, /* 4.5.0 */
    .connectListAllNWFilterBindings = nwfilterConnectListAllNWFilterBindings, /* 4.5.0 */
    .nwfilterBindingGetXMLDesc = nwfilterBindingGetXMLDesc, /* 4.5.0 */
    .nwfilterBindingCreateXML = nwfilterBindingCreateXML, /* 4.5.0 */
    .nwfilterBindingDelete = nwfilterBindingDelete, /* 4.5.0 */
};


static virHypervisorDriver nwfilterHypervisorDriver = {
    .name = "nwfilter",
    .connectOpen = nwfilterConnectOpen, /* 4.1.0 */
    .connectClose = nwfilterConnectClose, /* 4.1.0 */
    .connectIsEncrypted = nwfilterConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = nwfilterConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = nwfilterConnectIsAlive, /* 4.1.0 */
};


static virConnectDriver nwfilterConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "nwfilter", NULL },
    .hypervisorDriver = &nwfilterHypervisorDriver,
    .nwfilterDriver = &nwfilterDriver,
};


static virStateDriver stateDriver = {
    .name = "NWFilter",
    .stateInitialize = nwfilterStateInitialize,
    .stateCleanup = nwfilterStateCleanup,
    .stateReload = nwfilterStateReload,
};

int nwfilterRegister(void)
{
    if (virRegisterConnectDriver(&nwfilterConnectDriver, false) < 0)
        return -1;
    if (virSetSharedNWFilterDriver(&nwfilterDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    return 0;
}
