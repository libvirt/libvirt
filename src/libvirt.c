/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005-2006, 2008-2014 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <gio/gnetworking.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#ifdef WITH_CURL
# include <curl/curl.h>
#endif

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "driver.h"

#include "viruuid.h"
#include "viralloc.h"
#include "configmake.h"
#include "virconf.h"
#include "rpc/virnettlscontext.h"
#include "vircommand.h"
#include "virevent.h"
#include "virfile.h"
#include "virrandom.h"
#include "viruri.h"
#include "virthread.h"
#include "virstring.h"
#include "virutil.h"
#include "virtypedparam.h"

#ifdef WITH_TEST
# include "test/test_driver.h"
#endif
#ifdef WITH_REMOTE
# include "remote/remote_driver.h"
#endif
#ifdef WITH_OPENVZ
# include "openvz/openvz_driver.h"
#endif
#ifdef WITH_VMWARE
# include "vmware/vmware_driver.h"
#endif
#ifdef WITH_ESX
# include "esx/esx_driver.h"
#endif
#ifdef WITH_HYPERV
# include "hyperv/hyperv_driver.h"
#endif
#ifdef WITH_BHYVE
# include "bhyve/bhyve_driver.h"
#endif
#include "access/viraccessmanager.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("libvirt");

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to guarantee coherent pointer state ?
 */

#define MAX_DRIVERS 21

static virConnectDriver *virConnectDriverTab[MAX_DRIVERS];
static int virConnectDriverTabCount;
static virStateDriver *virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount;

static virNetworkDriver *virSharedNetworkDriver;
static virInterfaceDriver *virSharedInterfaceDriver;
static virStorageDriver *virSharedStorageDriver;
static virNodeDeviceDriver *virSharedNodeDeviceDriver;
static virSecretDriver *virSharedSecretDriver;
static virNWFilterDriver *virSharedNWFilterDriver;


static int
virConnectAuthCallbackDefault(virConnectCredentialPtr cred,
                              unsigned int ncred,
                              void *cbdata G_GNUC_UNUSED)
{
    size_t i;

    for (i = 0; i < ncred; i++) {
        char buf[1024];
        char *bufptr = NULL;
        size_t len;

        switch (cred[i].type) {
        case VIR_CRED_EXTERNAL: {
            if (STRNEQ(cred[i].challenge, "PolicyKit"))
                return -1;

            /*
             * Ignore & carry on. Although we can't auth
             * directly, the user may have authenticated
             * themselves already outside context of libvirt
             */
            break;
        }

        case VIR_CRED_USERNAME:
        case VIR_CRED_AUTHNAME:
        case VIR_CRED_ECHOPROMPT:
        case VIR_CRED_REALM:
            if (printf("%s: ", cred[i].prompt) < 0)
                return -1;
            if (fflush(stdout) != 0)
                return -1;

            if (!fgets(buf, sizeof(buf), stdin)) {
                if (feof(stdin)) { /* Treat EOF as "" */
                    break;
                }
                return -1;
            }

            len = strlen(buf);
            if (len != 0 && buf[len-1] == '\n')
                buf[len-1] = '\0';

            if (strlen(buf) > 0)
                bufptr = g_strdup(buf);
            break;

        case VIR_CRED_PASSPHRASE:
        case VIR_CRED_NOECHOPROMPT:
            if (printf("%s: ", cred[i].prompt) < 0)
                return -1;
            if (fflush(stdout) != 0)
                return -1;

            bufptr = virGetPassword();
            if (STREQ(bufptr, ""))
                VIR_FREE(bufptr);
            break;

        default:
            return -1;
        }

        if (cred[i].type != VIR_CRED_EXTERNAL) {
            cred[i].result = bufptr ? bufptr : g_strdup(cred[i].defresult ? cred[i].defresult : "");
            cred[i].resultlen = strlen(cred[i].result);
        }
    }

    return 0;
}


/* Don't typically want VIR_CRED_USERNAME. It enables you to authenticate
 * as one user, and act as another. It just results in annoying
 * prompts for the username twice & is very rarely what you want
 */
static int virConnectCredTypeDefault[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_ECHOPROMPT,
    VIR_CRED_REALM,
    VIR_CRED_PASSPHRASE,
    VIR_CRED_NOECHOPROMPT,
    VIR_CRED_EXTERNAL,
};

static virConnectAuth virConnectAuthDefault = {
    virConnectCredTypeDefault,
    G_N_ELEMENTS(virConnectCredTypeDefault),
    virConnectAuthCallbackDefault,
    NULL,
};

/* Explanation in the header file */
virConnectAuthPtr virConnectAuthPtrDefault = &virConnectAuthDefault;

static bool virGlobalError;
static virOnceControl virGlobalOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
virGlobalInit(void)
{
    /* It would be nice if we could trace the use of this call, to
     * help diagnose in log files if a user calls something other than
     * virConnectOpen first.  But we can't rely on VIR_DEBUG working
     * until after initialization is complete, and since this is
     * one-shot, we never get here again.  */
    if (virErrorInitialize() < 0)
        goto error;

    /* Make glib initialize its own global state. See more:
     *
     *   https://gitlab.gnome.org/GNOME/glib/-/issues/3034
     *
     * TODO: Remove ASAP.
     */
    g_ascii_strtoull("0", NULL, 0);

    virFileActivateDirOverrideForLib();

    if (getuid() != geteuid() ||
        getgid() != getegid()) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libvirt.so is not safe to use from setuid/setgid programs"));
        goto error;
    }

    /* Do this upfront rather than every time a child is spawned. */
    if (virCloseRangeInit() < 0)
        goto error;

    if (virLogSetFromEnv() < 0)
        goto error;

    virNetTLSInit();

#if WITH_CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    VIR_DEBUG("register drivers");

    g_networking_init();

#ifdef WITH_LIBINTL_H
    if (!bindtextdomain(PACKAGE, LOCALEDIR))
        goto error;
#endif /* WITH_LIBINTL_H */

    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virConnectOpen.
     */
#ifdef WITH_TEST
    if (testRegister() == -1)
        goto error;
#endif
#ifdef WITH_OPENVZ
    if (openvzRegister() == -1)
        goto error;
#endif
#ifdef WITH_VMWARE
    if (vmwareRegister() == -1)
        goto error;
#endif
#ifdef WITH_ESX
    if (esxRegister() == -1)
        goto error;
#endif
#ifdef WITH_HYPERV
    if (hypervRegister() == -1)
        goto error;
#endif
#ifdef WITH_REMOTE
    if (remoteRegister() == -1)
        goto error;
#endif

    return;

 error:
    virGlobalError = true;
}


/**
 * virInitialize:
 *
 * Initialize the library.
 *
 * This method is invoked automatically by any of the virConnectOpen() API
 * calls, and by virGetVersion(). Since release 1.0.0, there is no need to
 * call this method even in a multithreaded application, since
 * initialization is performed in a thread safe manner; but applications
 * using an older version of the library should manually call this before
 * setting up competing threads that attempt virConnectOpen in parallel.
 *
 * The only other time it would be necessary to call virInitialize is if the
 * application did not invoke virConnectOpen as its first API call, such
 * as when calling virEventRegisterImpl() before setting up connections,
 * or when using virSetErrorFunc() to alter error reporting of the first
 * connection attempt.
 *
 * Returns 0 in case of success, -1 in case of error
 *
 * Since: 0.1.0
 */
int
virInitialize(void)
{
    if (virOnce(&virGlobalOnce, virGlobalInit) < 0 ||
        virGlobalError) {
        virDispatchError(NULL);
        return -1;
    }

    return 0;
}


#ifdef WIN32
BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID ignore);

BOOL WINAPI
DllMain(HINSTANCE instance G_GNUC_UNUSED,
        DWORD reason,
        LPVOID ignore G_GNUC_UNUSED)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        virInitialize();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        /* Nothing todo in libvirt yet */
        break;

    case DLL_PROCESS_DETACH:
        /* Don't bother releasing per-thread data
           since (hopefully) windows cleans up
           everything on process exit */
        break;
    }

    return TRUE;
}
#endif


/**
 * virSetSharedNetworkDriver:
 * @driver: pointer to a network driver block
 *
 * Register a network virtualization driver
 *
 * Returns 0 on success, or -1 in case of error.
 */
int
virSetSharedNetworkDriver(virNetworkDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedNetworkDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A network driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as network driver", driver->name);

    virSharedNetworkDriver = driver;
    return 0;
}


/**
 * virSetSharedInterfaceDriver:
 * @driver: pointer to an interface driver block
 *
 * Register an interface virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virSetSharedInterfaceDriver(virInterfaceDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedInterfaceDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A interface driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as interface driver", driver->name);

    virSharedInterfaceDriver = driver;
    return 0;
}


/**
 * virSetSharedStorageDriver:
 * @driver: pointer to a storage driver block
 *
 * Register a storage virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virSetSharedStorageDriver(virStorageDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedStorageDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A storage driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as storage driver", driver->name);

    virSharedStorageDriver = driver;
    return 0;
}


/**
 * virSetSharedNodeDeviceDriver:
 * @driver: pointer to a device monitor block
 *
 * Register a device monitor
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virSetSharedNodeDeviceDriver(virNodeDeviceDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedNodeDeviceDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A node device driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as device driver", driver->name);

    virSharedNodeDeviceDriver = driver;
    return 0;
}


/**
 * virSetSharedSecretDriver:
 * @driver: pointer to a secret driver block
 *
 * Register a secret driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virSetSharedSecretDriver(virSecretDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedSecretDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A secret driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as secret driver", driver->name);

    virSharedSecretDriver = driver;
    return 0;
}


/**
 * virSetSharedNWFilterDriver:
 * @driver: pointer to a network filter driver block
 *
 * Register a network filter virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virSetSharedNWFilterDriver(virNWFilterDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virSharedNWFilterDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("A network filter driver is already registered"));
        return -1;
    }

    VIR_DEBUG("registering %s as network filter driver", driver->name);

    virSharedNWFilterDriver = driver;
    return 0;
}


/**
 * virRegisterConnectDriver:
 * @driver: pointer to a driver block
 * @setSharedDrivers: populate shared drivers
 *
 * Register a virtualization driver, optionally filling in
 * any empty pointers for shared secondary drivers
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterConnectDriver(virConnectDriver *driver,
                         bool setSharedDrivers)
{
    VIR_DEBUG("driver=%p name=%s", driver,
              driver ? NULLSTR(driver->hypervisorDriver->name) : "(null)");

    virCheckNonNullArgReturn(driver, -1);
    if (virConnectDriverTabCount >= MAX_DRIVERS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register %1$s"),
                       driver->hypervisorDriver->name);
        return -1;
    }

    VIR_DEBUG("registering %s as driver %d",
           driver->hypervisorDriver->name, virConnectDriverTabCount);

    if (setSharedDrivers) {
        if (driver->interfaceDriver == NULL)
            driver->interfaceDriver = virSharedInterfaceDriver;
        if (driver->networkDriver == NULL)
            driver->networkDriver = virSharedNetworkDriver;
        if (driver->nodeDeviceDriver == NULL)
            driver->nodeDeviceDriver = virSharedNodeDeviceDriver;
        if (driver->nwfilterDriver == NULL)
            driver->nwfilterDriver = virSharedNWFilterDriver;
        if (driver->secretDriver == NULL)
            driver->secretDriver = virSharedSecretDriver;
        if (driver->storageDriver == NULL)
            driver->storageDriver = virSharedStorageDriver;
    }

    virConnectDriverTab[virConnectDriverTabCount] = driver;
    return virConnectDriverTabCount++;
}


/**
 * virHasDriverForURIScheme:
 * @scheme: the URI scheme
 *
 * Determine if there is a driver registered that explicitly
 * handles URIs with the scheme @scheme.
 *
 * Returns: true if a driver is registered
 */
bool
virHasDriverForURIScheme(const char *scheme)
{
    size_t i;
    size_t j;

    for (i = 0; i < virConnectDriverTabCount; i++) {
        if (!virConnectDriverTab[i]->uriSchemes)
            continue;
        for (j = 0; virConnectDriverTab[i]->uriSchemes[j]; j++) {
            if (STREQ(virConnectDriverTab[i]->uriSchemes[j], scheme))
                return true;
        }
    }

    return false;
}

/**
 * virRegisterStateDriver:
 * @driver: pointer to a driver block
 *
 * Register a virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterStateDriver(virStateDriver *driver)
{
    virCheckNonNullArgReturn(driver, -1);

    if (virStateDriverTabCount >= MAX_DRIVERS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register %1$s"),
                       driver->name);
        return -1;
    }

    virStateDriverTab[virStateDriverTabCount] = driver;
    return virStateDriverTabCount++;
}


/**
 * virStateInitialize:
 * @privileged: set to true if running with root privilege, false otherwise
 * @mandatory: set to true if all drivers must report success, not skipped
 * @root: directory to use for embedded mode
 * @monolithic: set to true if running in monolithic mode (daemon is libvirtd)
 * @callback: callback to invoke to inhibit shutdown of the daemon
 * @opaque: data to pass to @callback
 *
 * Initialize all virtualization drivers.
 *
 * Passing a non-NULL @root instructs the driver to run in embedded mode.
 * Instead of using the compile time $prefix as the basis for directory
 * paths, @root should be used instead. In addition any '/libvirt'
 * component of the paths should be stripped.
 *
 * eg consider a build with prefix=/usr/local. A driver might use the
 * locations
 *
 *    /usr/local/etc/libvirt/$DRIVER/
 *    /usr/local/var/lib/libvirt/$DRIVER/
 *    /usr/local/run/libvirt/$DRIVER/
 *
 * When run with @root, the locations should instead be
 *
 *    @root/etc/$DRIVER/
 *    @root/var/lib/$DRIVER/
 *    @root/run/$DRIVER/
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateInitialize(bool privileged,
                   bool mandatory,
                   const char *root,
                   bool monolithic,
                   virStateInhibitCallback callback,
                   void *opaque)
{
    size_t i;

    if (virInitialize() < 0)
        return -1;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateInitialize &&
            !virStateDriverTab[i]->initialized) {
            virDrvStateInitResult ret;
            VIR_DEBUG("Running global init for %s state driver",
                      virStateDriverTab[i]->name);
            virStateDriverTab[i]->initialized = true;
            ret = virStateDriverTab[i]->stateInitialize(privileged,
                                                        root,
                                                        monolithic,
                                                        callback,
                                                        opaque);
            VIR_DEBUG("State init result %d (mandatory=%d)", ret, mandatory);
            if (ret == VIR_DRV_STATE_INIT_ERROR) {
                VIR_ERROR(_("Initialization of %1$s state driver failed: %2$s"),
                          virStateDriverTab[i]->name,
                          virGetLastErrorMessage());
                return -1;
            }
            if (ret == VIR_DRV_STATE_INIT_SKIPPED && mandatory) {
                VIR_ERROR(_("Initialization of mandatory %1$s state driver skipped"),
                          virStateDriverTab[i]->name);
                return -1;
            }
        }
    }
    return 0;
}


/**
 * virStateShutdownPrepare:
 *
 * Run each virtualization driver's shutdown prepare method.
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateShutdownPrepare(void)
{
    size_t i;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateShutdownPrepare &&
            virStateDriverTab[i]->stateShutdownPrepare() < 0)
            return -1;
    }
    return 0;
}


/**
 * virStateShutdownWait:
 *
 * Run each virtualization driver's shutdown wait method.
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateShutdownWait(void)
{
    size_t i;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateShutdownWait &&
            virStateDriverTab[i]->stateShutdownWait() < 0)
            return -1;
    }
    return 0;
}


/**
 * virStateCleanup:
 *
 * Run each virtualization driver's cleanup method.
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateCleanup(void)
{
    int r;
    int ret = 0;

    for (r = virStateDriverTabCount - 1; r >= 0; r--) {
        if (virStateDriverTab[r]->stateCleanup &&
            virStateDriverTab[r]->stateCleanup() < 0)
            ret = -1;
    }
    return ret;
}


/**
 * virStateReload:
 *
 * Run each virtualization driver's reload method.
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateReload(void)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateReload &&
            virStateDriverTab[i]->stateReload() < 0)
            ret = -1;
    }
    return ret;
}


/**
 * virStateStop:
 *
 * Run each virtualization driver's "stop" method.
 *
 * Returns 0 if successful, -1 on failure
 */
int
virStateStop(void)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateStop &&
            virStateDriverTab[i]->stateStop())
            ret = 1;
    }
    return ret;
}


/**
 * virGetVersion:
 * @libVer: return value for the library version (OUT)
 * @type: ignored; pass NULL
 * @typeVer: pass NULL; for historical purposes duplicates @libVer if
 * non-NULL
 *
 * Provides version information. @libVer is the version of the
 * library and will always be set unless an error occurs, in which case
 * an error code will be returned. @typeVer exists for historical
 * compatibility; if it is not NULL it will duplicate @libVer (it was
 * originally intended to return hypervisor information based on @type,
 * but due to the design of remote clients this is not reliable). To
 * get the version of the running hypervisor use the virConnectGetVersion()
 * function instead. To get the libvirt library version used by a
 * connection use the virConnectGetLibVersion() instead.
 *
 * This function includes a call to virInitialize() when necessary.
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer and
 *       @typeVer have the format major * 1,000,000 + minor * 1,000 + release.
 *
 * Since: 0.0.3
 */
int
virGetVersion(unsigned long *libVer, const char *type G_GNUC_UNUSED,
              unsigned long *typeVer)
{
    if (virInitialize() < 0)
        goto error;
    VIR_DEBUG("libVir=%p, type=%s, typeVer=%p", libVer, type, typeVer);

    virResetLastError();
    if (libVer == NULL)
        goto error;
    *libVer = LIBVIR_VERSION_NUMBER;

    if (typeVer != NULL)
        *typeVer = LIBVIR_VERSION_NUMBER;

    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}


static int
virConnectGetDefaultURI(virConf *conf,
                        char **name)
{
    const char *defname = getenv("LIBVIRT_DEFAULT_URI");
    if (defname && *defname) {
        VIR_DEBUG("Using LIBVIRT_DEFAULT_URI '%s'", defname);
        *name = g_strdup(defname);
    } else {
        if (virConfGetValueString(conf, "uri_default", name) < 0)
            return -1;

        if (*name)
            VIR_DEBUG("Using config file uri '%s'", *name);
    }

    return 0;
}


/*
 * Check to see if an invalid URI like qemu://system (missing /) was passed,
 * offer the suggested fix.
 */
static int
virConnectCheckURIMissingSlash(const char *uristr, virURI *uri)
{
    if (!uri->path || !uri->server)
        return 0;

    /* To avoid false positives, only check drivers that mandate
       a path component in the URI, like /system or /session */
    if (STRNEQ(uri->scheme, "qemu") &&
        STRNEQ(uri->scheme, "vbox") &&
        STRNEQ(uri->scheme, "vz"))
        return 0;

    if (STREQ(uri->server, "session") ||
        STREQ(uri->server, "system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid URI %1$s (maybe you want %2$s:///%3$s)"),
                       uristr, uri->scheme, uri->server);
        return -1;
    }

    return 0;
}


static virConnectPtr
virConnectOpenInternal(const char *name,
                       virConnectAuthPtr auth,
                       unsigned int flags)
{
    size_t i;
    int res;
    g_autoptr(virConnect) ret = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autofree char *uristr = NULL;
    bool embed = false;

    ret = virGetConnect();
    if (ret == NULL)
        return NULL;

    if (virConfLoadConfig(&conf, "libvirt.conf") < 0)
        return NULL;

    if (name && name[0] == '\0')
        name = NULL;

    /* Convert xen -> xen:///system for back compat */
    if (name && STRCASEEQ(name, "xen"))
        name = "xen:///system";

    /* Convert xen:// -> xen:///system because xmlParseURI cannot parse the
     * former.  This allows URIs such as xen://localhost to work.
     */
    if (name && STREQ(name, "xen://"))
        name = "xen:///system";

    /*
     * If no URI is passed, then check for an environment string if not
     * available probe the compiled in drivers to find a default hypervisor
     * if detectable.
     */
    if (name) {
        uristr = g_strdup(name);
    } else {
        if (virConnectGetDefaultURI(conf, &uristr) < 0)
            return NULL;

        if (uristr == NULL) {
            VIR_DEBUG("Trying to probe for default URI");
            for (i = 0; i < virConnectDriverTabCount && uristr == NULL; i++) {
                if (virConnectDriverTab[i]->hypervisorDriver->connectURIProbe) {
                    if (virConnectDriverTab[i]->hypervisorDriver->connectURIProbe(&uristr) < 0)
                        return NULL;
                    VIR_DEBUG("%s driver URI probe returned '%s'",
                              virConnectDriverTab[i]->hypervisorDriver->name,
                              NULLSTR(uristr));
                }
            }
        }
    }

    if (uristr) {
        char *alias = NULL;

        if (!(flags & VIR_CONNECT_NO_ALIASES) &&
            virURIResolveAlias(conf, uristr, &alias) < 0)
            return NULL;

        if (alias) {
            g_free(uristr);
            uristr = g_steal_pointer(&alias);
        }

        if (!(ret->uri = virURIParse(uristr)))
            return NULL;

        /* Avoid need for drivers to worry about NULLs, as
         * no one needs to distinguish "" vs NULL */
        if (ret->uri->path == NULL)
            ret->uri->path = g_strdup("");

        VIR_DEBUG("Split \"%s\" to URI components:\n"
                  "  scheme %s\n"
                  "  server %s\n"
                  "  user %s\n"
                  "  port %d\n"
                  "  path %s",
                  uristr,
                  NULLSTR(ret->uri->scheme), NULLSTR(ret->uri->server),
                  NULLSTR(ret->uri->user), ret->uri->port,
                  ret->uri->path);

        if (ret->uri->scheme == NULL) {
            virReportError(VIR_ERR_NO_CONNECT,
                           _("URI '%1$s' does not include a driver name"),
                           name);
            return NULL;
        }

        if (virConnectCheckURIMissingSlash(uristr,
                                           ret->uri) < 0) {
            return NULL;
        }

        if (STREQ(ret->uri->path, "/embed")) {
            const char *root = NULL;
            g_autofree char *regMethod = NULL;
            VIR_DEBUG("URI path requests %s driver embedded mode",
                      ret->uri->scheme);
            if (strspn(ret->uri->scheme, "abcdefghijklmnopqrstuvwxyz")  !=
                strlen(ret->uri->scheme)) {
                virReportError(VIR_ERR_NO_CONNECT,
                               _("URI scheme '%1$s' for embedded driver is not valid"),
                               ret->uri->scheme);
                return NULL;
            }

            root = virURIGetParam(ret->uri, "root");
            if (!root)
                return NULL;

            if (!g_path_is_absolute(root)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("root path must be absolute"));
                return NULL;
            }

            if (virEventRequireImpl() < 0)
                return NULL;

            regMethod = g_strdup_printf("%sRegister", ret->uri->scheme);

            if (virDriverLoadModule(ret->uri->scheme, regMethod, false) < 0)
                return NULL;

            if (virAccessManagerGetDefault() == NULL) {
                virAccessManager *acl;

                virResetLastError();

                if (!(acl = virAccessManagerNew("none")))
                    return NULL;
                virAccessManagerSetDefault(acl);
            }

            if (virStateInitialize(geteuid() == 0, true, root, false, NULL, NULL) < 0)
                return NULL;

            embed = true;
        }
    } else {
        VIR_DEBUG("no name, allowing driver auto-select");
    }

    /* Cleansing flags */
    ret->flags = flags & VIR_CONNECT_RO;

    for (i = 0; i < virConnectDriverTabCount; i++) {
        /* We're going to probe the remote driver next. So we have already
         * probed all other client-side-only driver before, but none of them
         * accepted the URI.
         * If the scheme corresponds to a known but disabled client-side-only
         * driver then report a useful error, instead of a cryptic one about
         * not being able to connect to libvirtd or not being able to find
         * certificates. */
        if (STREQ(virConnectDriverTab[i]->hypervisorDriver->name, "remote") &&
            ret->uri != NULL &&
            (
#ifndef WITH_ESX
             STRCASEEQ(ret->uri->scheme, "vpx") ||
             STRCASEEQ(ret->uri->scheme, "esx") ||
             STRCASEEQ(ret->uri->scheme, "gsx") ||
#endif
#ifndef WITH_HYPERV
             STRCASEEQ(ret->uri->scheme, "hyperv") ||
#endif
#ifndef WITH_VZ
             STRCASEEQ(ret->uri->scheme, "parallels") ||
#endif
             false)) {
            virReportErrorHelper(VIR_FROM_NONE, VIR_ERR_CONFIG_UNSUPPORTED,
                                 __FILE__, __FUNCTION__, __LINE__,
                                 _("libvirt was built without the '%1$s' driver"),
                                 ret->uri->scheme);
            return NULL;
        }

        VIR_DEBUG("trying driver %zu (%s) ...",
                  i, virConnectDriverTab[i]->hypervisorDriver->name);

        if (virConnectDriverTab[i]->localOnly && ret->uri && ret->uri->server) {
            VIR_DEBUG("Server present, skipping local only driver");
            continue;
        }

        /* Filter drivers based on declared URI schemes */
        if (virConnectDriverTab[i]->uriSchemes) {
            bool matchScheme = false;
            size_t s;
            if (!ret->uri) {
                VIR_DEBUG("No URI, skipping driver with URI whitelist");
                continue;
            }
            if (embed && !virConnectDriverTab[i]->embeddable) {
                VIR_DEBUG("Ignoring non-embeddable driver %s",
                          virConnectDriverTab[i]->hypervisorDriver->name);
                continue;
            }

            VIR_DEBUG("Checking for supported URI schemes");
            for (s = 0; virConnectDriverTab[i]->uriSchemes[s] != NULL; s++) {
                if (STREQ(ret->uri->scheme, virConnectDriverTab[i]->uriSchemes[s])) {
                    VIR_DEBUG("Matched URI scheme '%s'", ret->uri->scheme);
                    matchScheme = true;
                    break;
                }
            }
            if (!matchScheme) {
                VIR_DEBUG("No matching URI scheme");
                continue;
            }
        } else {
            if (embed) {
                VIR_DEBUG("Skipping wildcard for embedded URI");
                continue;
            } else {
                VIR_DEBUG("Matching any URI scheme for '%s'", ret->uri ? ret->uri->scheme : "");
            }
        }

        if (embed && !virConnectDriverTab[i]->embeddable) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Driver %1$s cannot be used in embedded mode"),
                           virConnectDriverTab[i]->hypervisorDriver->name);
            return NULL;
        }
        /* before starting the new connection, check if the driver only works
         * with a server, and so return an error if the server is missing */
        if (virConnectDriverTab[i]->remoteOnly && ret->uri && !ret->uri->server) {
            virReportError(VIR_ERR_INVALID_ARG, "%s", _("URI is missing the server part"));
            return NULL;
        }

        ret->driver = virConnectDriverTab[i]->hypervisorDriver;
        ret->interfaceDriver = virConnectDriverTab[i]->interfaceDriver;
        ret->networkDriver = virConnectDriverTab[i]->networkDriver;
        ret->nodeDeviceDriver = virConnectDriverTab[i]->nodeDeviceDriver;
        ret->nwfilterDriver = virConnectDriverTab[i]->nwfilterDriver;
        ret->secretDriver = virConnectDriverTab[i]->secretDriver;
        ret->storageDriver = virConnectDriverTab[i]->storageDriver;

        res = virConnectDriverTab[i]->hypervisorDriver->connectOpen(ret, auth, conf, flags);
        VIR_DEBUG("driver %zu %s returned %s",
                  i, virConnectDriverTab[i]->hypervisorDriver->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            break;
        } else {
            ret->driver = NULL;
            ret->interfaceDriver = NULL;
            ret->networkDriver = NULL;
            ret->nodeDeviceDriver = NULL;
            ret->nwfilterDriver = NULL;
            ret->secretDriver = NULL;
            ret->storageDriver = NULL;

            if (res == VIR_DRV_OPEN_ERROR)
                return NULL;
        }
    }

    if (!ret->driver) {
        /* If we reach here, then all drivers declined the connection. */
        virReportError(VIR_ERR_NO_CONNECT, "%s", NULLSTR(name));
        return NULL;
    }

    return g_steal_pointer(&ret);
}


/**
 * virConnectOpen:
 * @name: (optional) URI of the hypervisor
 *
 * This function should be called first to get a connection to the
 * Hypervisor and xen store
 *
 * If @name is NULL, if the LIBVIRT_DEFAULT_URI environment variable is set,
 * then it will be used. Otherwise if the client configuration file
 * has the "uri_default" parameter set, then it will be used. Finally
 * probing will be done to determine a suitable default driver to activate.
 * This involves trying each hypervisor in turn until one successfully opens.
 *
 * If connecting to an unprivileged hypervisor driver which requires
 * the libvirtd daemon to be active, it will automatically be launched
 * if not already running. This can be prevented by setting the
 * environment variable LIBVIRT_AUTOSTART=0
 *
 * URIs are documented at https://libvirt.org/uri.html
 *
 * virConnectClose should be used to release the resources after the connection
 * is no longer needed.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * Since: 0.0.3
 */
virConnectPtr
virConnectOpen(const char *name)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        return NULL;

    VIR_DEBUG("name=%s", NULLSTR(name));
    virResetLastError();
    ret = virConnectOpenInternal(name, NULL, 0);
    if (!ret)
        virDispatchError(NULL);

    return ret;
}


/**
 * virConnectOpenReadOnly:
 * @name: (optional) URI of the hypervisor
 *
 * This function should be called first to get a restricted connection to the
 * library functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * See virConnectOpen for notes about environment variables which can
 * have an effect on opening drivers and freeing the connection resources
 *
 * URIs are documented at https://libvirt.org/uri.html
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * Since: 0.0.3
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        return NULL;

    VIR_DEBUG("name=%s", NULLSTR(name));
    virResetLastError();
    ret = virConnectOpenInternal(name, NULL, VIR_CONNECT_RO);
    if (!ret)
        virDispatchError(NULL);
    return ret;
}


/**
 * virConnectOpenAuth:
 * @name: (optional) URI of the hypervisor
 * @auth: Authenticate callback parameters
 * @flags: bitwise-OR of virConnectFlags
 *
 * This function should be called first to get a connection to the
 * Hypervisor. If necessary, authentication will be performed fetching
 * credentials via the callback
 *
 * See virConnectOpen for notes about environment variables which can
 * have an effect on opening drivers and freeing the connection resources
 *
 * URIs are documented at https://libvirt.org/uri.html
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * Since: 0.4.0
 */
virConnectPtr
virConnectOpenAuth(const char *name,
                   virConnectAuthPtr auth,
                   unsigned int flags)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        return NULL;

    VIR_DEBUG("name=%s, auth=%p, flags=0x%x", NULLSTR(name), auth, flags);
    virResetLastError();
    ret = virConnectOpenInternal(name, auth, flags);
    if (!ret)
        virDispatchError(NULL);
    return ret;
}



/**
 * virConnectClose:
 * @conn: pointer to the hypervisor connection
 *
 * This function closes the connection to the Hypervisor. This should
 * not be called if further interaction with the Hypervisor are needed
 * especially if there is running domain which need further monitoring by
 * the application.
 *
 * Connections are reference counted; the count is explicitly
 * increased by the initial open (virConnectOpen, virConnectOpenAuth,
 * and the like) as well as virConnectRef; it is also temporarily
 * increased by other API that depend on the connection remaining
 * alive.  The open and every virConnectRef call should have a
 * matching virConnectClose, and all other references will be released
 * after the corresponding operation completes.
 *
 * Returns a positive number if at least 1 reference remains on
 * success. The returned value should not be assumed to be the total
 * reference count. A return of 0 implies no references remain and
 * the connection is closed and memory has been freed. A return of -1
 * implies a failure.
 *
 * It is possible for the last virConnectClose to return a positive
 * value if some other object still has a temporary reference to the
 * connection, but the application should not try to further use a
 * connection after the virConnectClose that matches the initial open.
 *
 * Since: 0.0.3
 */
int
virConnectClose(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    virConnectWatchDispose();
    virObjectUnref(conn);
    if (virConnectWasDisposed())
        return 0;
    return 1;
}


/* Helper function called to validate incoming client array on any
 * interface that sets typed parameters in the hypervisor.  */
int
virTypedParameterValidateSet(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int nparams)
{
    int string_okay;
    size_t i;

    string_okay = VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                           VIR_DRV_FEATURE_TYPED_PARAM_STRING);
    if (string_okay < 0)
        return -1;
    for (i = 0; i < nparams; i++) {
        if (strnlen(params[i].field, VIR_TYPED_PARAM_FIELD_LENGTH) ==
            VIR_TYPED_PARAM_FIELD_LENGTH) {
            virReportInvalidArg(params,
                                _("string parameter name '%2$.*1$s' too long"),
                                VIR_TYPED_PARAM_FIELD_LENGTH,
                                params[i].field);
            return -1;
        }
        if (params[i].type == VIR_TYPED_PARAM_STRING) {
            if (string_okay) {
                if (!params[i].value.s) {
                    virReportInvalidArg(params,
                                        _("NULL string parameter '%1$s'"),
                                        params[i].field);
                    return -1;
                }
            } else {
                virReportInvalidArg(params,
                                    _("string parameter '%1$s' unsupported"),
                                    params[i].field);
                return -1;
            }
        }
    }
    return 0;
}
