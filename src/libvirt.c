/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005,2006,2008,2009 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <time.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include "getpass.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "libvirt_internal.h"
#include "driver.h"

#include "uuid.h"
#include "util.h"
#include "memory.h"

#ifndef WITH_DRIVER_MODULES
#ifdef WITH_TEST
#include "test.h"
#endif
#ifdef WITH_XEN
#include "xen_unified.h"
#endif
#ifdef WITH_REMOTE
#include "remote_internal.h"
#endif
#ifdef WITH_OPENVZ
#include "openvz_driver.h"
#endif
#ifdef WITH_VBOX
#include "vbox/vbox_driver.h"
#endif
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to guarantee coherent pointer state ?
 */

#define MAX_DRIVERS 10

static virDriverPtr virDriverTab[MAX_DRIVERS];
static int virDriverTabCount = 0;
static virNetworkDriverPtr virNetworkDriverTab[MAX_DRIVERS];
static int virNetworkDriverTabCount = 0;
static virInterfaceDriverPtr virInterfaceDriverTab[MAX_DRIVERS];
static int virInterfaceDriverTabCount = 0;
static virStorageDriverPtr virStorageDriverTab[MAX_DRIVERS];
static int virStorageDriverTabCount = 0;
static virDeviceMonitorPtr virDeviceMonitorTab[MAX_DRIVERS];
static int virDeviceMonitorTabCount = 0;
#ifdef WITH_LIBVIRTD
static virStateDriverPtr virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount = 0;
#endif
static int initialized = 0;

#if defined(POLKIT_AUTH)
static int virConnectAuthGainPolkit(const char *privilege) {
    const char *const args[] = {
        POLKIT_AUTH, "--obtain", privilege, NULL
    };
    int childpid, status, ret;

    /* Root has all rights */
    if (getuid() == 0)
        return 0;

    if ((childpid = fork()) < 0)
        return -1;

    if (!childpid) {
        execvp(args[0], (char **)args);
        _exit(-1);
    }

    while ((ret = waitpid(childpid, &status, 0) == -1) && errno == EINTR);
    if (ret == -1) {
        return -1;
    }

    if (!WIFEXITED(status) ||
        (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 1)) {
        return -1;
    }

    return 0;
}
#endif

static int virConnectAuthCallbackDefault(virConnectCredentialPtr cred,
                                         unsigned int ncred,
                                         void *cbdata ATTRIBUTE_UNUSED) {
    int i;

    for (i = 0 ; i < ncred ; i++) {
        char buf[1024];
        char *bufptr = buf;
        size_t len;

        switch (cred[i].type) {
        case VIR_CRED_EXTERNAL: {
            if (STRNEQ(cred[i].challenge, "PolicyKit"))
                return -1;

#if defined(POLKIT_AUTH)
            if (virConnectAuthGainPolkit(cred[i].prompt) < 0)
                return -1;
#else
            /*
             * Ignore & carry on. Although we can't auth
             * directly, the user may have authenticated
             * themselves already outside context of libvirt
             */
#endif
            break;
        }

        case VIR_CRED_USERNAME:
        case VIR_CRED_AUTHNAME:
        case VIR_CRED_ECHOPROMPT:
        case VIR_CRED_REALM:
            if (printf("%s:", cred[i].prompt) < 0)
                return -1;
            if (fflush(stdout) != 0)
                return -1;

            if (!fgets(buf, sizeof(buf), stdin)) {
                if (feof(stdin)) { /* Treat EOF as "" */
                    buf[0] = '\0';
                    break;
                }
                return -1;
            }
            len = strlen(buf);
            if (len != 0 && buf[len-1] == '\n')
                buf[len-1] = '\0';
            break;

        case VIR_CRED_PASSPHRASE:
        case VIR_CRED_NOECHOPROMPT:
            if (printf("%s:", cred[i].prompt) < 0)
                return -1;
            if (fflush(stdout) != 0)
                return -1;

            bufptr = getpass("");
            if (!bufptr)
                return -1;
            break;

        default:
            return -1;
        }

        if (cred[i].type != VIR_CRED_EXTERNAL) {
            if (STREQ(bufptr, "") && cred[i].defresult)
                cred[i].result = strdup(cred[i].defresult);
            else
                cred[i].result = strdup(bufptr);
            if (!cred[i].result)
                return -1;
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
    sizeof(virConnectCredTypeDefault)/sizeof(int),
    virConnectAuthCallbackDefault,
    NULL,
};

/*
 * virConnectAuthPtrDefault
 *
 * A default implementation of the authentication callbacks. This
 * implementation is suitable for command line based tools. It will
 * prompt for username, passwords, realm and one time keys as needed.
 * It will print on STDOUT, and read from STDIN. If this is not
 * suitable for the application's needs an alternative implementation
 * should be provided.
 */
virConnectAuthPtr virConnectAuthPtrDefault = &virConnectAuthDefault;

#if HAVE_WINSOCK2_H
static int
winsock_init (void)
{
    WORD winsock_version, err;
    WSADATA winsock_data;

    /* http://msdn2.microsoft.com/en-us/library/ms742213.aspx */
    winsock_version = MAKEWORD (2, 2);
    err = WSAStartup (winsock_version, &winsock_data);
    return err == 0 ? 0 : -1;
}
#endif

/**
 * virInitialize:
 *
 * Initialize the library. It's better to call this routine at startup
 * in multithreaded applications to avoid potential race when initializing
 * the library.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInitialize(void)
{
    char *debugEnv;
    if (initialized)
        return(0);

    initialized = 1;

    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0 ||
        virRandomInitialize(time(NULL) ^ getpid()))
        return -1;

    debugEnv = getenv("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv && *debugEnv != '0') {
        if (STREQ(debugEnv, "2") || STREQ(debugEnv, "info"))
            virLogSetDefaultPriority(VIR_LOG_INFO);
        else if (STREQ(debugEnv, "3") || STREQ(debugEnv, "warning"))
            virLogSetDefaultPriority(VIR_LOG_WARN);
        else if (STREQ(debugEnv, "4") || STREQ(debugEnv, "error"))
            virLogSetDefaultPriority(VIR_LOG_ERROR);
        else
            virLogSetDefaultPriority(VIR_LOG_DEBUG);
    }
    debugEnv = getenv("LIBVIRT_LOG_FILTERS");
    if (debugEnv)
        virLogParseFilters(debugEnv);
    debugEnv = getenv("LIBVIRT_LOG_OUTPUTS");
    if (debugEnv)
        virLogParseOutputs(debugEnv);

    DEBUG0("register drivers");

#if HAVE_WINSOCK2_H
    if (winsock_init () == -1) return -1;
#endif

    if (!bindtextdomain(GETTEXT_PACKAGE, LOCALEBASEDIR))
        return (-1);

    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virConnectOpen.
     */
#ifdef WITH_DRIVER_MODULES
    /* We don't care if any of these fail, because the whole point
     * is to allow users to only install modules they want to use.
     * If they try to use a open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
    virDriverLoadModule("test");
    virDriverLoadModule("xen");
    virDriverLoadModule("openvz");
    virDriverLoadModule("vbox");
    virDriverLoadModule("remote");
#else
#ifdef WITH_TEST
    if (testRegister() == -1) return -1;
#endif
#ifdef WITH_XEN
    if (xenRegister () == -1) return -1;
#endif
#ifdef WITH_OPENVZ
    if (openvzRegister() == -1) return -1;
#endif
#ifdef WITH_VBOX
    if (vboxRegister() == -1) return -1;
#endif
#ifdef WITH_REMOTE
    if (remoteRegister () == -1) return -1;
#endif
#endif

    return(0);
}

#ifdef WIN32
BOOL WINAPI
DllMain (HINSTANCE instance, DWORD reason, LPVOID ignore);

BOOL WINAPI
DllMain (HINSTANCE instance ATTRIBUTE_UNUSED,
         DWORD reason,
         LPVOID ignore ATTRIBUTE_UNUSED)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        virInitialize();
        break;

    case DLL_THREAD_ATTACH:
        /* Nothing todo in libvirt yet */
        break;

    case DLL_THREAD_DETACH:
        /* Release per-thread local data */
        virThreadOnExit();
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
 * virLibConnError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibConnError(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    virRaiseError(conn, NULL, NULL, VIR_FROM_NONE, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibConnWarning:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibConnWarning(virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    virRaiseError(conn, NULL, NULL, VIR_FROM_NONE, error, VIR_ERR_WARNING,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibDomainError:
 * @domain: the domain if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibDomainError(virDomainPtr domain, virErrorNumber error,
                  const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_DOMAIN) {
        conn = domain->conn;
    }
    virRaiseError(conn, domain, NULL, VIR_FROM_DOM, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibNetworkError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibNetworkError(virNetworkPtr network, virErrorNumber error,
                   const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_NETWORK) {
        conn = network->conn;
    }
    virRaiseError(conn, NULL, network, VIR_FROM_NET, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibInterfaceError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibInterfaceError(virInterfacePtr iface, virErrorNumber error,
                   const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_INTERFACE) {
        conn = iface->conn;
    }
    virRaiseError(conn, NULL, NULL, VIR_FROM_INTERFACE, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibStoragePoolError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibStoragePoolError(virStoragePoolPtr pool, virErrorNumber error,
                       const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_STORAGE_POOL)
        conn = pool->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_STORAGE, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibStorageVolError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibStorageVolError(virStorageVolPtr vol, virErrorNumber error,
                      const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_STORAGE_VOL)
        conn = vol->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_STORAGE, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibNodeDeviceError:
 * @dev: the device if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the node device level
 */
static void
virLibNodeDeviceError(virNodeDevicePtr dev, virErrorNumber error,
                      const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_NODE_DEVICE)
        conn = dev->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_NODEDEV, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virRegisterNetworkDriver:
 * @driver: pointer to a network driver block
 *
 * Register a network virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterNetworkDriver(virNetworkDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virNetworkDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    DEBUG ("registering %s as network driver %d",
           driver->name, virNetworkDriverTabCount);

    virNetworkDriverTab[virNetworkDriverTabCount] = driver;
    return virNetworkDriverTabCount++;
}

/**
 * virRegisterInterfaceDriver:
 * @driver: pointer to a interface driver block
 *
 * Register a interface virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterInterfaceDriver(virInterfaceDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virInterfaceDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    DEBUG ("registering %s as interface driver %d",
           driver->name, virInterfaceDriverTabCount);

    virInterfaceDriverTab[virInterfaceDriverTabCount] = driver;
    return virInterfaceDriverTabCount++;
}

/**
 * virRegisterStorageDriver:
 * @driver: pointer to a storage driver block
 *
 * Register a storage virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterStorageDriver(virStorageDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virStorageDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    DEBUG ("registering %s as storage driver %d",
           driver->name, virStorageDriverTabCount);

    virStorageDriverTab[virStorageDriverTabCount] = driver;
    return virStorageDriverTabCount++;
}

/**
 * virRegisterDeviceMonitor:
 * @driver: pointer to a device monitor block
 *
 * Register a device monitor
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterDeviceMonitor(virDeviceMonitorPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virDeviceMonitorTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    DEBUG ("registering %s as device driver %d",
           driver->name, virDeviceMonitorTabCount);

    virDeviceMonitorTab[virDeviceMonitorTabCount] = driver;
    return virDeviceMonitorTabCount++;
}

/**
 * virRegisterDriver:
 * @driver: pointer to a driver block
 *
 * Register a virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterDriver(virDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (driver->no < 0) {
        virLibConnError
            (NULL, VIR_ERR_INVALID_ARG,
             "virRegisterDriver: tried to register an internal Xen driver");
        return -1;
    }

    DEBUG ("registering %s as driver %d",
           driver->name, virDriverTabCount);

    virDriverTab[virDriverTabCount] = driver;
    return virDriverTabCount++;
}

#ifdef WITH_LIBVIRTD
/**
 * virRegisterStateDriver:
 * @driver: pointer to a driver block
 *
 * Register a virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterStateDriver(virStateDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virStateDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    virStateDriverTab[virStateDriverTabCount] = driver;
    return virStateDriverTabCount++;
}

/**
 * virStateInitialize:
 * @privileged: set to 1 if running with root priviledge, 0 otherwise
 *
 * Initialize all virtualization drivers.
 *
 * Return 0 if all succeed, -1 upon any failure.
 */
int virStateInitialize(int privileged) {
    int i, ret = 0;

    if (virInitialize() < 0)
        return -1;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->initialize &&
            virStateDriverTab[i]->initialize(privileged) < 0)
            ret = -1;
    }
    return ret;
}

/**
 * virStateCleanup:
 *
 * Run each virtualization driver's cleanup method.
 *
 * Return 0 if all succeed, -1 upon any failure.
 */
int virStateCleanup(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->cleanup &&
            virStateDriverTab[i]->cleanup() < 0)
            ret = -1;
    }
    return ret;
}

/**
 * virStateReload:
 *
 * Run each virtualization driver's reload method.
 *
 * Return 0 if all succeed, -1 upon any failure.
 */
int virStateReload(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->reload &&
            virStateDriverTab[i]->reload() < 0)
            ret = -1;
    }
    return ret;
}

/**
 * virStateActive:
 *
 * Run each virtualization driver's "active" method.
 *
 * Return 0 if none are active, 1 if at least one is.
 */
int virStateActive(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->active &&
            virStateDriverTab[i]->active())
            ret = 1;
    }
    return ret;
}

#endif



/**
 * virGetVersion:
 * @libVer: return value for the library version (OUT)
 * @type: the type of connection/driver looked at
 * @typeVer: return value for the version of the hypervisor (OUT)
 *
 * Provides two information back, @libVer is the version of the library
 * while @typeVer will be the version of the hypervisor type @type against
 * which the library was compiled. If @type is NULL, "Xen" is assumed, if
 * @type is unknown or not available, an error code will be returned and
 * @typeVer will be 0.
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer and
 *       @typeVer have the format major * 1,000,000 + minor * 1,000 + release.
 */
int
virGetVersion(unsigned long *libVer, const char *type,
              unsigned long *typeVer)
{
    DEBUG("libVir=%p, type=%s, typeVer=%p", libVer, type, typeVer);

    if (!initialized)
        if (virInitialize() < 0)
            return -1;

    if (libVer == NULL)
        return (-1);
    *libVer = LIBVIR_VERSION_NUMBER;

    if (typeVer != NULL) {
        if (type == NULL)
            type = "Xen";

/* FIXME: Add _proper_ type version handling for loadable driver modules... */
#ifdef WITH_DRIVER_MODULES
        *typeVer = LIBVIR_VERSION_NUMBER;
#else
        *typeVer = 0;

#if WITH_XEN
        if (STRCASEEQ(type, "Xen"))
            *typeVer = xenUnifiedVersion();
#endif
#if WITH_TEST
        if (STRCASEEQ(type, "Test"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_QEMU
        if (STRCASEEQ(type, "QEMU"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_LXC
        if (STRCASEEQ(type, "LXC"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_OPENVZ
        if (STRCASEEQ(type, "OpenVZ"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_VBOX
        if (STRCASEEQ(type, "VBox"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_UML
        if (STRCASEEQ(type, "UML"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_ONE
        if (STRCASEEQ(type, "ONE"))
            *typeVer = LIBVIR_VERSION_NUMBER;
#endif
#if WITH_REMOTE
        if (STRCASEEQ(type, "Remote"))
            *typeVer = remoteVersion();
#endif
        if (*typeVer == 0) {
            virLibConnError(NULL, VIR_ERR_NO_SUPPORT, type);
            return (-1);
        }
#endif /* WITH_DRIVER_MODULES */
    }
    return (0);
}

static virConnectPtr
do_open (const char *name,
         virConnectAuthPtr auth,
         int flags)
{
    int i, res;
    virConnectPtr ret;

    virResetLastError();

    ret = virGetConnect();
    if (ret == NULL)
        return NULL;

    /*
     *  If no URI is passed, then check for an environment string if not
     *  available probe the compiled in drivers to find a default hypervisor
     *  if detectable.
     */
    if (!name || name[0] == '\0') {
        char *defname = getenv("LIBVIRT_DEFAULT_URI");
        if (defname && *defname) {
            DEBUG("Using LIBVIRT_DEFAULT_URI %s", defname);
            name = defname;
        } else {
            name = NULL;
        }
    }

    if (name) {
        /* Convert xen -> xen:/// for back compat */
        if (STRCASEEQ(name, "xen"))
            name = "xen:///";

        /* Convert xen:// -> xen:/// because xmlParseURI cannot parse the
         * former.  This allows URIs such as xen://localhost to work.
         */
        if (STREQ (name, "xen://"))
            name = "xen:///";

        ret->uri = xmlParseURI (name);
        if (!ret->uri) {
            virLibConnError (ret, VIR_ERR_INVALID_ARG,
                             _("could not parse connection URI"));
            goto failed;
        }

        DEBUG("name \"%s\" to URI components:\n"
              "  scheme %s\n"
              "  opaque %s\n"
              "  authority %s\n"
              "  server %s\n"
              "  user %s\n"
              "  port %d\n"
              "  path %s\n",
              name,
              NULLSTR(ret->uri->scheme), NULLSTR(ret->uri->opaque),
              NULLSTR(ret->uri->authority), NULLSTR(ret->uri->server),
              NULLSTR(ret->uri->user), ret->uri->port,
              NULLSTR(ret->uri->path));
    } else {
        DEBUG0("no name, allowing driver auto-select");
    }

    /* Cleansing flags */
    ret->flags = flags & VIR_CONNECT_RO;

    for (i = 0; i < virDriverTabCount; i++) {
        DEBUG("trying driver %d (%s) ...",
              i, virDriverTab[i]->name);
        res = virDriverTab[i]->open (ret, auth, flags);
        DEBUG("driver %d %s returned %s",
              i, virDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) goto failed;
        else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->driver = virDriverTab[i];
            break;
        }
    }

    if (!ret->driver) {
        /* If we reach here, then all drivers declined the connection. */
        virLibConnError (NULL, VIR_ERR_NO_CONNECT, name);
        goto failed;
    }

    for (i = 0; i < virNetworkDriverTabCount; i++) {
        res = virNetworkDriverTab[i]->open (ret, auth, flags);
        DEBUG("network driver %d %s returned %s",
              i, virNetworkDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virNetworkDriverTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_NETWORK,
                                   "Is the daemon running ?");
            }
            break;
        } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->networkDriver = virNetworkDriverTab[i];
            break;
        }
    }

#if 0
    /* TODO: reactivate once we have an interface driver */

    for (i = 0; i < virInterfaceDriverTabCount; i++) {
        res = virInterfaceDriverTab[i]->open (ret, auth, flags);
        DEBUG("interface driver %d %s returned %s",
              i, virInterfaceDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virInterfaceDriverTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_INTERFACE,
                                   "Is the daemon running ?");
            }
            break;
        } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->interfaceDriver = virInterfaceDriverTab[i];
            break;
        }
    }
#endif

    /* Secondary driver for storage. Optional */
    for (i = 0; i < virStorageDriverTabCount; i++) {
        res = virStorageDriverTab[i]->open (ret, auth, flags);
        DEBUG("storage driver %d %s returned %s",
              i, virStorageDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (0 && STREQ(virStorageDriverTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_STORAGE,
                                   "Is the daemon running ?");
            }
            break;
         } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->storageDriver = virStorageDriverTab[i];
            break;
        }
    }

    /* Node driver (optional) */
    for (i = 0; i < virDeviceMonitorTabCount; i++) {
        res = virDeviceMonitorTab[i]->open (ret, auth, flags);
        DEBUG("node driver %d %s returned %s",
              i, virDeviceMonitorTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virDeviceMonitorTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_NODE,
                                   "Is the libvirtd daemon running ?");
            } else {
                char *msg;
                if (virAsprintf(&msg, "Is the %s daemon running?",
                                virDeviceMonitorTab[i]->name) > 0) {
                    virLibConnWarning (NULL, VIR_WAR_NO_NODE, msg);
                    VIR_FREE(msg);
                }
            }
            break;
        } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->deviceMonitor = virDeviceMonitorTab[i];
            break;
        }
    }

    return ret;

failed:
    if (ret->driver) ret->driver->close (ret);

    /* Ensure a global error is set in case driver forgot */
    virSetGlobalError();

    virUnrefConnect(ret);

    return NULL;
}

/**
 * virConnectOpen:
 * @name: URI of the hypervisor
 *
 * This function should be called first to get a connection to the
 * Hypervisor and xen store
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpen (const char *name)
{
    if (!initialized)
        if (virInitialize() < 0)
            return NULL;

    DEBUG("name=%s", name);
    return do_open (name, NULL, 0);
}

/**
 * virConnectOpenReadOnly:
 * @name: URI of the hypervisor
 *
 * This function should be called first to get a restricted connection to the
 * library functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    if (!initialized)
        if (virInitialize() < 0)
            return NULL;

    DEBUG("name=%s", name);
    return do_open (name, NULL, VIR_CONNECT_RO);
}

/**
 * virConnectOpenAuth:
 * @name: URI of the hypervisor
 * @auth: Authenticate callback parameters
 * @flags: Open flags
 *
 * This function should be called first to get a connection to the
 * Hypervisor. If necessary, authentication will be performed fetching
 * credentials via the callback
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpenAuth(const char *name,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (!initialized)
        if (virInitialize() < 0)
            return NULL;

    DEBUG("name=%s, auth=%p, flags=%d", NULLSTR(name), auth, flags);
    return do_open (name, auth, flags);
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
 * Returns 0 in case of success or -1 in case of error.
 */
int
virConnectClose(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver)
        conn->networkDriver->close (conn);
    if (conn->interfaceDriver)
        conn->interfaceDriver->close (conn);
    if (conn->storageDriver)
        conn->storageDriver->close (conn);
    if (conn->deviceMonitor)
        conn->deviceMonitor->close (conn);
    conn->driver->close (conn);

    if (virUnrefConnect(conn) < 0)
        return (-1);
    return (0);
}

/**
 * virConnectRef:
 * @conn: the connection to hold a reference on
 *
 * Increment the reference count on the connection. For each
 * additional call to this method, there shall be a corresponding
 * call to virConnectClose to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a connection would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virConnectRef(virConnectPtr conn)
{
    if ((!VIR_IS_CONNECT(conn))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&conn->lock);
    DEBUG("conn=%p refs=%d", conn, conn->refs);
    conn->refs++;
    virMutexUnlock(&conn->lock);
    return 0;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of driver features in the remote case.
 */
int
virDrvSupportsFeature (virConnectPtr conn, int feature)
{
    int ret;
    DEBUG("conn=%p, feature=%d", conn, feature);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    ret = VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn, feature);
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return ret;
}

/**
 * virConnectGetType:
 * @conn: pointer to the hypervisor connection
 *
 * Get the name of the Hypervisor software used.
 *
 * Returns NULL in case of error, a static zero terminated string otherwise.
 *
 * See also:
 * http://www.redhat.com/archives/libvir-list/2007-February/msg00096.html
 */
const char *
virConnectGetType(virConnectPtr conn)
{
    const char *ret;
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->type) {
        ret = conn->driver->type (conn);
        if (ret) return ret;
    }
    return conn->driver->name;
}

/**
 * virConnectGetVersion:
 * @conn: pointer to the hypervisor connection
 * @hvVer: return value for the version of the running hypervisor (OUT)
 *
 * Get the version level of the Hypervisor running. This may work only with
 * hypervisor call, i.e. with privileged access to the hypervisor, not
 * with a Read-Only connection.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
int
virConnectGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    DEBUG("conn=%p, hvVer=%p", conn, hvVer);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (hvVer == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->version) {
        int ret = conn->driver->version (conn, hvVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectGetHostname:
 * @conn: pointer to a hypervisor connection
 *
 * This returns the system hostname on which the hypervisor is
 * running (the result of the gethostname(2) system call).  If
 * we are connected to a remote system, then this returns the
 * hostname of the remote system.
 *
 * Returns the hostname which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virConnectGetHostname (virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getHostname) {
        char *ret = conn->driver->getHostname (conn);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virConnectGetURI:
 * @conn: pointer to a hypervisor connection
 *
 * This returns the URI (name) of the hypervisor connection.
 * Normally this is the same as or similar to the string passed
 * to the virConnectOpen/virConnectOpenReadOnly call, but
 * the driver may make the URI canonical.  If name == NULL
 * was passed to virConnectOpen, then the driver will return
 * a non-NULL URI which can be used to connect to the same
 * hypervisor later.
 *
 * Returns the URI string which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virConnectGetURI (virConnectPtr conn)
{
    char *name;
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    name = (char *)xmlSaveUri(conn->uri);
    if (!name) {
        virReportOOMError (conn);
        goto error;
    }
    return name;

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virConnectGetMaxVcpus:
 * @conn: pointer to the hypervisor connection
 * @type: value of the 'type' attribute in the <domain> element
 *
 * Provides the maximum number of virtual CPUs supported for a guest VM of a
 * specific type. The 'type' parameter here corresponds to the 'type'
 * attribute in the <domain> element of the XML.
 *
 * Returns the maximum of virtual CPU or -1 in case of error.
 */
int
virConnectGetMaxVcpus(virConnectPtr conn,
                      const char *type)
{
    DEBUG("conn=%p, type=%s", conn, type);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (conn->driver->getMaxVcpus) {
        int ret = conn->driver->getMaxVcpus (conn, type);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListDomains:
 * @conn: pointer to the hypervisor connection
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    DEBUG("conn=%p, ids=%p, maxids=%d", conn, ids, maxids);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if ((ids == NULL) || (maxids < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->listDomains) {
        int ret = conn->driver->listDomains (conn, ids, maxids);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectNumOfDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDomains(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }

    if (conn->driver->numOfDomains) {
        int ret = conn->driver->numOfDomains (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virDomainGetConnect:
 * @dom: pointer to a domain
 *
 * Provides the connection pointer associated with a domain.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the domain object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virDomainGetConnect (virDomainPtr dom)
{
    DEBUG("dom=%p", dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    return dom->conn;
}

/**
 * virDomainCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: callers should always pass 0
 *
 * Launch a new guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateXML(virConnectPtr conn, const char *xmlDesc,
                   unsigned int flags)
{
    DEBUG("conn=%p, xmlDesc=%s, flags=%d", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreateXML) {
        virDomainPtr ret;
        ret = conn->driver->domainCreateXML (conn, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: callers should always pass 0
 *
 * Deprecated after 0.4.6.
 * Renamed to virDomainCreateXML() providing identical functionality.
 * This existing name will left indefinitely for API compatability.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags)
{
    return(virDomainCreateXML(conn, xmlDesc, flags));
}

/**
 * virDomainLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 * Note that this won't work for inactive domains which have an ID of -1,
 * in that case a lookup based on the Name or UUId need to be done instead.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByID(virConnectPtr conn, int id)
{
    DEBUG("conn=%p, id=%d", conn, id);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainLookupByID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByID (conn, id);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    DEBUG("conn=%p, uuid=%s", conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainLookupByUUID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByUUID (conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    int raw[VIR_UUID_BUFLEN], i;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int ret;

    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    /* XXX: sexpr_uuid() also supports 'xxxx-xxxx-xxxx-xxxx' format.
     *      We needn't it here. Right?
     */
    ret = sscanf(uuidstr,
                 "%02x%02x%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x%02x%02x%02x%02x",
                 raw + 0, raw + 1, raw + 2, raw + 3,
                 raw + 4, raw + 5, raw + 6, raw + 7,
                 raw + 8, raw + 9, raw + 10, raw + 11,
                 raw + 12, raw + 13, raw + 14, raw + 15);

    if (ret!=VIR_UUID_BUFLEN) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    for (i = 0; i < VIR_UUID_BUFLEN; i++)
        uuid[i] = raw[i] & 0xFF;

    return virDomainLookupByUUID(conn, &uuid[0]);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its name.
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByName(virConnectPtr conn, const char *name)
{
    DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainLookupByName) {
        virDomainPtr dom;
        dom = conn->driver->domainLookupByName (conn, name);
        if (!dom)
            goto error;
        return dom;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainDestroy:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor. This
 * does not free the associated virDomainPtr object.
 * This function may require privileged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain)
{
    virConnectPtr conn;

    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainDestroy) {
        int ret;
        ret = conn->driver->domainDestroy (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virDomainFree:
 * @domain: a domain object
 *
 * Free the domain object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainFree(virDomainPtr domain)
{
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (virUnrefDomain(domain) < 0)
        return -1;
    return(0);
}

/**
 * virDomainRef:
 * @domain: the domain to hold a reference on
 *
 * Increment the reference count on the domain. For each
 * additional call to this method, there shall be a corresponding
 * call to virDomainFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a domain would increment
 * the reference count.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRef(virDomainPtr domain)
{
    if ((!VIR_IS_CONNECTED_DOMAIN(domain))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&domain->conn->lock);
    DEBUG("domain=%p refs=%d", domain, domain->refs);
    domain->refs++;
    virMutexUnlock(&domain->conn->lock);
    return 0;
}


/**
 * virDomainSuspend:
 * @domain: a domain object
 *
 * Suspends an active domain, the process is frozen without further access
 * to CPU resources and I/O but the memory used by the domain at the
 * hypervisor level will stay allocated. Use virDomainResume() to reactivate
 * the domain.
 * This function may requires privileged access.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainSuspend) {
        int ret;
        ret = conn->driver->domainSuspend (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume an suspended domain, the process is restarted from the state where
 * it was frozen by calling virSuspendDomain().
 * This function may requires privileged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainResume) {
        int ret;
        ret = conn->driver->domainResume (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainSave:
 * @domain: a domain object
 * @to: path for the output file
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this may be a problem).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSave(virDomainPtr domain, const char *to)
{
    char filepath[4096];
    virConnectPtr conn;
    DEBUG("domain=%p, to=%s", domain, to);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;
    if (to == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /*
     * We must absolutize the file path as the save is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (to[0] != '/') {
        unsigned int len, t;

        t = strlen(to);
        if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL)
            return (-1);
        len = strlen(filepath);
        /* that should be covered by getcwd() semantic, but be 100% sure */
        if (len > sizeof(filepath) - (t + 3))
            return (-1);
        filepath[len] = '/';
        strcpy(&filepath[len + 1], to);
        to = &filepath[0];

    }

    if (conn->driver->domainSave) {
        int ret;
        ret = conn->driver->domainSave (domain, to);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainRestore:
 * @conn: pointer to the hypervisor connection
 * @from: path to the
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestore(virConnectPtr conn, const char *from)
{
    char filepath[4096];
    DEBUG("conn=%p, from=%s", conn, from);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (from == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /*
     * We must absolutize the file path as the restore is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (from[0] != '/') {
        unsigned int len, t;

        t = strlen(from);
        if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL) {
            virLibConnError(conn, VIR_ERR_SYSTEM_ERROR,
                            _("cannot get working directory"));
            goto error;
        }
        len = strlen(filepath);
        /* that should be covered by getcwd() semantic, but be 100% sure */
        if (len > sizeof(filepath) - (t + 3)) {
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            _("path too long"));
            goto error;
        }
        filepath[len] = '/';
        strcpy(&filepath[len + 1], from);
        from = &filepath[0];
    }

    if (conn->driver->domainRestore) {
        int ret;
        ret = conn->driver->domainRestore (conn, from);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virDomainCoreDump:
 * @domain: a domain object
 * @to: path for the core file
 * @flags: extra flags, currently unused
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainCoreDump(virDomainPtr domain, const char *to, int flags)
{
    char filepath[4096];
    virConnectPtr conn;
    DEBUG("domain=%p, to=%s, flags=%d", domain, to, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;
    if (to == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /*
     * We must absolutize the file path as the save is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (to[0] != '/') {
        unsigned int len, t;

        t = strlen(to);
        if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL) {
            virLibDomainError(domain, VIR_ERR_SYSTEM_ERROR,
                              _("cannot get current directory"));
            goto error;
        }
        len = strlen(filepath);
        /* that should be covered by getcwd() semantic, but be 100% sure */
        if (len > sizeof(filepath) - (t + 3)) {
            virLibDomainError(domain, VIR_ERR_INTERNAL_ERROR,
                              _("path too long"));
            goto error;
        }
        filepath[len] = '/';
        strcpy(&filepath[len + 1], to);
        to = &filepath[0];

    }

    if (conn->driver->domainCoreDump) {
        int ret;
        ret = conn->driver->domainCoreDump (domain, to, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainShutdown:
 * @domain: a domain object
 *
 * Shutdown a domain, the domain object is still usable there after but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request.
 *
 * TODO: should we add an option for reboot, knowing it may not be doable
 *       in the general case ?
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdown(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainShutdown) {
        int ret;
        ret = conn->driver->domainShutdown (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainReboot:
 * @domain: a domain object
 * @flags: extra flags for the reboot operation, not used yet
 *
 * Reboot a domain, the domain object is still usable there after but
 * the domain OS is being stopped for a restart.
 * Note that the guest OS may ignore the request.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainReboot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, flags=%u", domain, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainReboot) {
        int ret;
        ret = conn->driver->domainReboot (domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetName:
 * @domain: a domain object
 *
 * Get the public name for that domain
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the domain object.
 */
const char *
virDomainGetName(virDomainPtr domain)
{
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    return (domain->name);
}

/**
 * virDomainGetUUID:
 * @domain: a domain object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a domain
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetUUID(virDomainPtr domain, unsigned char *uuid)
{
    DEBUG("domain=%p, uuid=%p", domain, uuid);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        /* Copy to connection error object for back compatability */
        virSetConnError(domain->conn);
        return (-1);
    }

    memcpy(uuid, &domain->uuid[0], VIR_UUID_BUFLEN);

    return (0);
}

/**
 * virDomainGetUUIDString:
 * @domain: a domain object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a domain as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetUUIDString(virDomainPtr domain, char *buf)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("domain=%p, buf=%p", domain, buf);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virDomainGetUUID(domain, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return (0);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetID:
 * @domain: a domain object
 *
 * Get the hypervisor ID number for the domain
 *
 * Returns the domain ID number or (unsigned int) -1 in case of error
 */
unsigned int
virDomainGetID(virDomainPtr domain)
{
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return ((unsigned int) -1);
    }
    return (domain->id);
}

/**
 * virDomainGetOSType:
 * @domain: a domain object
 *
 * Get the type of domain operation system.
 *
 * Returns the new string or NULL in case of error, the string must be
 *         freed by the caller.
 */
char *
virDomainGetOSType(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    conn = domain->conn;

    if (conn->driver->domainGetOSType) {
        char *ret;
        ret = conn->driver->domainGetOSType (domain);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return NULL;
}

/**
 * virDomainGetMaxMemory:
 * @domain: a domain object or NULL
 *
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
virDomainGetMaxMemory(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxMemory) {
        unsigned long ret;
        ret = conn->driver->domainGetMaxMemory (domain);
        if (ret == 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return 0;
}

/**
 * virDomainSetMaxMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kilobytes
 *
 * Dynamically change the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function requires privileged access to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;
    DEBUG("domain=%p, memory=%lu", domain, memory);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (memory < 4096) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainSetMaxMemory) {
        int ret;
        ret = conn->driver->domainSetMaxMemory (domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainSetMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kilobytes
 *
 * Dynamically change the target amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may requires privileged access to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;
    DEBUG("domain=%p, memory=%lu", domain, memory);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (memory < 4096) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainSetMemory) {
        int ret;
        ret = conn->driver->domainSetMemory (domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 *
 * Extract information about a domain. Note that if the connection
 * used to get the domain is limited only a partial set of the information
 * can be extracted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virConnectPtr conn;
    DEBUG("domain=%p, info=%p", domain, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memset(info, 0, sizeof(virDomainInfo));

    conn = domain->conn;

    if (conn->driver->domainGetInfo) {
        int ret;
        ret = conn->driver->domainGetInfo (domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetXMLDesc:
 * @domain: a domain object
 * @flags: an OR'ed set of virDomainXMLFlags
 *
 * Provide an XML description of the domain. The description may be reused
 * later to relaunch the domain with virDomainCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainGetXMLDesc(virDomainPtr domain, int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, flags=%d", domain, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    conn = domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED,
                        _("virDomainGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainDumpXML) {
        char *ret;
        ret = conn->driver->domainDumpXML (domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return NULL;
}

/**
 * virConnectDomainXMLFromNative:
 * @conn: a connection object
 * @nativeFormat: configuration format importing from
 * @nativeConfig: the configuration data to import
 * @flags: currently unused, pass 0
 *
 * Reads native configuration data  describing a domain, and
 * generates libvirt domain XML. The format of the native
 * data is hypervisor dependant.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *virConnectDomainXMLFromNative(virConnectPtr conn,
                                    const char *nativeFormat,
                                    const char *nativeConfig,
                                    unsigned int flags)
{
    DEBUG("conn=%p, format=%s config=%s flags=%u", conn, nativeFormat, nativeConfig, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }

    if (nativeFormat == NULL || nativeConfig == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainXMLFromNative) {
        char *ret;
        ret = conn->driver->domainXMLFromNative (conn,
                                                 nativeFormat,
                                                 nativeConfig,
                                                 flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virConnectDomainXMLToNative:
 * @conn: a connection object
 * @nativeFormat: configuration format exporting to
 * @domainXml: the domain configuration to export
 * @flags: currently unused, pass 0
 *
 * Reads a domain XML configuration document, and generates
 * generates a native configuration file describing the domain.
 * The format of the native data is hypervisor dependant.
 *
 * Returns a 0 terminated UTF-8 encoded native config datafile, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *virConnectDomainXMLToNative(virConnectPtr conn,
                                  const char *nativeFormat,
                                  const char *domainXml,
                                  unsigned int flags)
{
    DEBUG("conn=%p, format=%s xml=%s flags=%u", conn, nativeFormat, domainXml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }

    if (nativeFormat == NULL || domainXml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainXMLToNative) {
        char *ret;
        ret = conn->driver->domainXMLToNative(conn,
                                              nativeFormat,
                                              domainXml,
                                              flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virDomainMigrate:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @flags: flags
 * @dname: (optional) rename domain to this at destination
 * @uri: (optional) dest hostname/URI as seen from the source host
 * @bandwidth: (optional) specify migration bandwidth limit in Mbps
 *
 * Migrate the domain object from its current host to the destination
 * host given by dconn (a connection to the destination host).
 *
 * Flags may be one of more of the following:
 *   VIR_MIGRATE_LIVE   Attempt a live migration.
 *
 * If a hypervisor supports renaming domains during migration,
 * then you may set the dname parameter to the new name (otherwise
 * it keeps the same name).  If this is not supported by the
 * hypervisor, dname must be NULL or else you will get an error.
 *
 * Since typically the two hypervisors connect directly to each
 * other in order to perform the migration, you may need to specify
 * a path from the source to the destination.  This is the purpose
 * of the uri parameter.  If uri is NULL, then libvirt will try to
 * find the best method.  Uri may specify the hostname or IP address
 * of the destination host as seen from the source.  Or uri may be
 * a URI giving transport, hostname, user, port, etc. in the usual
 * form.  Refer to driver documentation for the particular URIs
 * supported.
 *
 * The maximum bandwidth (in Mbps) that will be used to do migration
 * can be specified with the bandwidth parameter.  If set to 0,
 * libvirt will choose a suitable default.  Some hypervisors do
 * not support this feature and will return an error if bandwidth
 * is not 0.
 *
 * To see which features are supported by the current hypervisor,
 * see virConnectGetCapabilities, /capabilities/host/migration_features.
 *
 * There are many limitations on migration imposed by the underlying
 * technology - for example it may not be possible to migrate between
 * different processors even with the same architecture, or between
 * different types of hypervisor.
 *
 * Returns the new domain object if the migration was successful,
 *   or NULL in case of error.  Note that the new domain object
 *   exists in the scope of the destination connection (dconn).
 */
virDomainPtr
virDomainMigrate (virDomainPtr domain,
                  virConnectPtr dconn,
                  unsigned long flags,
                  const char *dname,
                  const char *uri,
                  unsigned long bandwidth)
{
    virConnectPtr conn;
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret, version = 0;
    DEBUG("domain=%p, dconn=%p, flags=%lu, dname=%s, uri=%s, bandwidth=%lu",
          domain, dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    conn = domain->conn;        /* Source connection. */
    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (dconn->flags & VIR_CONNECT_RO) {
        /* NB, delibrately report error against source object, not dest here */
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Check that migration is supported by both drivers. */
    if (VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn,
                                  VIR_DRV_FEATURE_MIGRATION_V1) &&
        VIR_DRV_SUPPORTS_FEATURE (dconn->driver, dconn,
                                  VIR_DRV_FEATURE_MIGRATION_V1))
        version = 1;
    else if (VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn,
                                       VIR_DRV_FEATURE_MIGRATION_V2) &&
             VIR_DRV_SUPPORTS_FEATURE (dconn->driver, dconn,
                                       VIR_DRV_FEATURE_MIGRATION_V2))
        version = 2;
    else {
        virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        goto error;
    }

    /* Prepare the migration.
     *
     * The destination host may return a cookie, or leave cookie as
     * NULL.
     *
     * The destination host MUST set uri_out if uri_in is NULL.
     *
     * If uri_in is non-NULL, then the destination host may modify
     * the URI by setting uri_out.  If it does not wish to modify
     * the URI, it should leave uri_out as NULL.
     */
    if (version == 1) {
        ret = dconn->driver->domainMigratePrepare
            (dconn, &cookie, &cookielen, uri, &uri_out, flags, dname,
             bandwidth);
        if (ret == -1) goto done;
        if (uri == NULL && uri_out == NULL) {
            virLibConnError (conn, VIR_ERR_INTERNAL_ERROR,
                             _("domainMigratePrepare did not set uri"));
            goto done;
        }
        if (uri_out) uri = uri_out; /* Did domainMigratePrepare change URI? */

        assert (uri != NULL);
    }
    else /* if (version == 2) */ {
        /* In version 2 of the protocol, the prepare step is slightly
         * different.  We fetch the domain XML of the source domain
         * and pass it to Prepare2.
         */
        if (!conn->driver->domainDumpXML) {
            virLibConnError (conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
            goto error;
        }
        dom_xml = conn->driver->domainDumpXML (domain,
                                               VIR_DOMAIN_XML_SECURE);

        if (!dom_xml)
            goto error;

        ret = dconn->driver->domainMigratePrepare2
            (dconn, &cookie, &cookielen, uri, &uri_out, flags, dname,
             bandwidth, dom_xml);
        free (dom_xml);
        if (ret == -1) goto done;
        if (uri == NULL && uri_out == NULL) {
            virLibConnError (conn, VIR_ERR_INTERNAL_ERROR,
                             _("domainMigratePrepare2 did not set uri"));
            goto done;
        }
        if (uri_out) uri = uri_out; /* Did domainMigratePrepare2 change URI? */

        assert (uri != NULL);
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    ret = conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth);

    if (version == 1) {
        if (ret == -1) goto done;
        /* Get the destination domain and return it or error.
         * 'domain' no longer actually exists at this point
         * (or so we hope), but we still use the object in memory
         * in order to get the name.
         */
        dname = dname ? dname : domain->name;
        if (dconn->driver->domainMigrateFinish)
            ddomain = dconn->driver->domainMigrateFinish
                (dconn, dname, cookie, cookielen, uri, flags);
        else
            ddomain = virDomainLookupByName (dconn, dname);
    } else /* if (version == 2) */ {
        /* In version 2 of the migration protocol, we pass the
         * status code from the sender to the destination host,
         * so it can do any cleanup if the migration failed.
         */
        dname = dname ? dname : domain->name;
        ddomain = dconn->driver->domainMigrateFinish2
            (dconn, dname, cookie, cookielen, uri, flags, ret);
    }

 done:
    free (uri_out);
    free (cookie);
    return ddomain;

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return NULL;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare (virConnectPtr dconn,
                           char **cookie,
                           int *cookielen,
                           const char *uri_in,
                           char **uri_out,
                           unsigned long flags,
                           const char *dname,
                           unsigned long bandwidth)
{
    VIR_DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p, "
              "flags=%lu, dname=%s, bandwidth=%lu", dconn, cookie, cookielen,
              NULLSTR(uri_in), uri_out, flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(dconn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare) {
        int ret;
        ret = dconn->driver->domainMigratePrepare (dconn, cookie, cookielen,
                                                   uri_in, uri_out,
                                                   flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dconn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform (virDomainPtr domain,
                           const char *cookie,
                           int cookielen,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long bandwidth)
{
    virConnectPtr conn;
    VIR_DEBUG("domain=%p, cookie=%p, cookielen=%d, uri=%s, flags=%lu, "
              "dname=%s, bandwidth=%lu", domain, cookie, cookielen, uri, flags,
              NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (domain)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePerform) {
        int ret;
        ret = conn->driver->domainMigratePerform (domain, cookie, cookielen,
                                                  uri,
                                                  flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError (domain, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish (virConnectPtr dconn,
                          const char *dname,
                          const char *cookie,
                          int cookielen,
                          const char *uri,
                          unsigned long flags)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lu", dconn, NULLSTR(dname), cookie, cookielen,
              uri, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(dconn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish (dconn, dname,
                                                  cookie, cookielen,
                                                  uri, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare2 (virConnectPtr dconn,
                          char **cookie,
                          int *cookielen,
                          const char *uri_in,
                          char **uri_out,
                          unsigned long flags,
                          const char *dname,
                          unsigned long bandwidth,
                          const char *dom_xml)
{
    VIR_DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p,"
              "flags=%lu, dname=%s, bandwidth=%lu, dom_xml=%s", dconn,
              cookie, cookielen, uri_in, uri_out, flags, NULLSTR(dname),
              bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(dconn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare2) {
        int ret;
        ret = dconn->driver->domainMigratePrepare2 (dconn, cookie, cookielen,
                                                    uri_in, uri_out,
                                                    flags, dname, bandwidth,
                                                    dom_xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dconn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish2 (virConnectPtr dconn,
                         const char *dname,
                         const char *cookie,
                         int cookielen,
                         const char *uri,
                         unsigned long flags,
                         int retcode)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lu, retcode=%d", dconn, NULLSTR(dname), cookie,
              cookielen, uri, flags, retcode);

    virResetLastError();

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(dconn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish2) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish2 (dconn, dname,
                                                   cookie, cookielen,
                                                   uri, flags,
                                                   retcode);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dconn);
    return NULL;
}


/**
 * virNodeGetInfo:
 * @conn: pointer to the hypervisor connection
 * @info: pointer to a virNodeInfo structure allocated by the user
 *
 * Extract hardware information about the node.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    DEBUG("conn=%p, info=%p", conn, info);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->nodeGetInfo) {
        int ret;
        ret = conn->driver->nodeGetInfo (conn, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectGetCapabilities:
 * @conn: pointer to the hypervisor connection
 *
 * Provides capabilities of the hypervisor / driver.
 *
 * Returns NULL in case of error, or an XML string
 * defining the capabilities.
 * The client must free the returned string after use.
 */
char *
virConnectGetCapabilities (virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getCapabilities) {
        char *ret;
        ret = conn->driver->getCapabilities (conn);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNodeGetFreeMemory:
 * @conn: pointer to the hypervisor connection
 *
 * provides the free memory available on the Node
 * Note: most libvirt APIs provide memory sizes in kilobytes, but in this
 * function the returned value is in bytes. Divide by 1024 as necessary.
 *
 * Returns the available free memory in bytes or 0 in case of error
 */
unsigned long long
virNodeGetFreeMemory(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return 0;
    }

    if (conn->driver->getFreeMemory) {
        unsigned long long ret;
        ret = conn->driver->getFreeMemory (conn);
        if (ret == 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return 0;
}

/**
 * virDomainGetSchedulerType:
 * @domain: pointer to domain object
 * @nparams: number of scheduler parameters(return value)
 *
 * Get the scheduler type.
 *
 * Returns NULL in case of error. The caller must free the returned string.
 */
char *
virDomainGetSchedulerType(virDomainPtr domain, int *nparams)
{
    virConnectPtr conn;
    char *schedtype;
    DEBUG("domain=%p, nparams=%p", domain, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerType){
        schedtype = conn->driver->domainGetSchedulerType (domain, nparams);
        if (!schedtype)
            goto error;
        return schedtype;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return NULL;
}


/**
 * virDomainGetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter object
 *          (return value)
 * @nparams: pointer to number of scheduler parameter
 *          (this value should be same than the returned value
 *           nparams of virDomainGetSchedulerType)
 *
 * Get the scheduler parameters, the @params array will be filled with the
 * values.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int *nparams)
{
    virConnectPtr conn;
    DEBUG("domain=%p, params=%p, nparams=%p", domain, params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainGetSchedulerParameters (domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainSetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter
 *          (this value should be same or less than the returned value
 *           nparams of virDomainGetSchedulerType)
 *
 * Change the scheduler parameters
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetSchedulerParameters(virDomainPtr domain,
                                virSchedParameterPtr params, int nparams)
{
    virConnectPtr conn;
    DEBUG("domain=%p, params=%p, nparams=%d", domain, params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainSetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainSetSchedulerParameters (domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}


/**
 * virDomainBlockStats:
 * @dom: pointer to the domain object
 * @path: path to the block device
 * @stats: block device stats (returned)
 * @size: size of stats structure
 *
 * This function returns block device (disk) stats for block
 * devices attached to the domain.
 *
 * The path parameter is the name of the block device.  Get this
 * by calling virDomainGetXMLDesc and finding the <target dev='...'>
 * attribute within //domain/devices/disk.  (For example, "xvda").
 *
 * Domains may have more than one block device.  To get stats for
 * each you should make multiple calls to this function.
 *
 * Individual fields within the stats structure may be returned
 * as -1, which indicates that the hypervisor does not support
 * that particular statistic.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockStats (virDomainPtr dom, const char *path,
                     virDomainBlockStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    struct _virDomainBlockStats stats2 = { -1, -1, -1, -1, -1 };
    DEBUG("domain=%p, path=%s, stats=%p, size=%zi", dom, path, stats, size);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    if (!stats || size > sizeof stats2) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    conn = dom->conn;

    if (conn->driver->domainBlockStats) {
        if (conn->driver->domainBlockStats (dom, path, &stats2) == -1)
            goto error;

        memcpy (stats, &stats2, size);
        return 0;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dom->conn);
    return -1;
}

/**
 * virDomainInterfaceStats:
 * @dom: pointer to the domain object
 * @path: path to the interface
 * @stats: network interface stats (returned)
 * @size: size of stats structure
 *
 * This function returns network interface stats for interfaces
 * attached to the domain.
 *
 * The path parameter is the name of the network interface.
 *
 * Domains may have more than network interface.  To get stats for
 * each you should make multiple calls to this function.
 *
 * Individual fields within the stats structure may be returned
 * as -1, which indicates that the hypervisor does not support
 * that particular statistic.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainInterfaceStats (virDomainPtr dom, const char *path,
                         virDomainInterfaceStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    struct _virDomainInterfaceStats stats2 = { -1, -1, -1, -1,
                                               -1, -1, -1, -1 };
    DEBUG("domain=%p, path=%s, stats=%p, size=%zi", dom, path, stats, size);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    if (!stats || size > sizeof stats2) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    conn = dom->conn;

    if (conn->driver->domainInterfaceStats) {
        if (conn->driver->domainInterfaceStats (dom, path, &stats2) == -1)
            goto error;

        memcpy (stats, &stats2, size);
        return 0;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dom->conn);
    return -1;
}

/**
 * virDomainBlockPeek:
 * @dom: pointer to the domain object
 * @path: path to the block device
 * @offset: offset within block device
 * @size: size to read
 * @buffer: return buffer (must be at least size bytes)
 * @flags: unused, always pass 0
 *
 * This function allows you to read the contents of a domain's
 * disk device.
 *
 * Typical uses for this are to determine if the domain has
 * written a Master Boot Record (indicating that the domain
 * has completed installation), or to try to work out the state
 * of the domain's filesystems.
 *
 * (Note that in the local case you might try to open the
 * block device or file directly, but that won't work in the
 * remote case, nor if you don't have sufficient permission.
 * Hence the need for this call).
 *
 * 'path' must be a device or file corresponding to the domain.
 * In other words it must be the precise string returned in
 * a <disk><source dev='...'/></disk> from
 * virDomainGetXMLDesc.
 *
 * 'offset' and 'size' represent an area which must lie entirely
 * within the device or file.  'size' may be 0 to test if the
 * call would succeed.
 *
 * 'buffer' is the return buffer and must be at least 'size' bytes.
 *
 * NB. The remote driver imposes a 64K byte limit on 'size'.
 * For your program to be able to work reliably over a remote
 * connection you should split large requests to <= 65536 bytes.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockPeek (virDomainPtr dom,
                    const char *path,
                    unsigned long long offset /* really 64 bits */,
                    size_t size,
                    void *buffer,
                    unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, path=%s, offset=%lld, size=%zi, buffer=%p",
          dom, path, offset, size, buffer);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(dom, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (!path) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("path is NULL"));
        goto error;
    }

    if (flags != 0) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("flags must be zero"));
        goto error;
    }

    /* Allow size == 0 as an access test. */
    if (size > 0 && !buffer) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("buffer is NULL"));
        goto error;
    }

    if (conn->driver->domainBlockPeek) {
        int ret;
        ret =conn->driver->domainBlockPeek (dom, path, offset, size,
                                            buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dom->conn);
    return -1;
}

/**
 * virDomainMemoryPeek:
 * @dom: pointer to the domain object
 * @start: start of memory to peek
 * @size: size of memory to peek
 * @buffer: return buffer (must be at least size bytes)
 * @flags: flags, see below
 *
 * This function allows you to read the contents of a domain's
 * memory.
 *
 * The memory which is read is controlled by the 'start', 'size'
 * and 'flags' parameters.
 *
 * If 'flags' is VIR_MEMORY_VIRTUAL then the 'start' and 'size'
 * parameters are interpreted as virtual memory addresses for
 * whichever task happens to be running on the domain at the
 * moment.  Although this sounds haphazard it is in fact what
 * you want in order to read Linux kernel state, because it
 * ensures that pointers in the kernel image can be interpreted
 * coherently.
 *
 * 'buffer' is the return buffer and must be at least 'size' bytes.
 * 'size' may be 0 to test if the call would succeed.
 *
 * NB. The remote driver imposes a 64K byte limit on 'size'.
 * For your program to be able to work reliably over a remote
 * connection you should split large requests to <= 65536 bytes.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainMemoryPeek (virDomainPtr dom,
                     unsigned long long start /* really 64 bits */,
                     size_t size,
                     void *buffer,
                     unsigned int flags)
{
    virConnectPtr conn;
    DEBUG ("domain=%p, start=%lld, size=%zi, buffer=%p, flags=%d",
           dom, start, size, buffer, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(dom, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Flags must be VIR_MEMORY_VIRTUAL at the moment.
     *
     * Note on access to physical memory: A VIR_MEMORY_PHYSICAL flag is
     * a possibility.  However it isn't really useful unless the caller
     * can also access registers, particularly CR3 on x86 in order to
     * get the Page Table Directory.  Since registers are different on
     * every architecture, that would imply another call to get the
     * machine registers.
     *
     * The QEMU driver handles only VIR_MEMORY_VIRTUAL, mapping it
     * to the qemu 'memsave' command which does the virtual to physical
     * mapping inside qemu.
     *
     * At time of writing there is no Xen driver.  However the Xen
     * hypervisor only lets you map physical pages from other domains,
     * and so the Xen driver would have to do the virtual to physical
     * mapping by chasing 2, 3 or 4-level page tables from the PTD.
     * There is example code in libxc (xc_translate_foreign_address)
     * which does this, although we cannot copy this code directly
     * because of incompatible licensing.
     */
    if (flags != VIR_MEMORY_VIRTUAL) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("flags parameter must be VIR_MEMORY_VIRTUAL"));
        goto error;
    }

    /* Allow size == 0 as an access test. */
    if (size > 0 && !buffer) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("buffer is NULL but size is non-zero"));
        goto error;
    }

    if (conn->driver->domainMemoryPeek) {
        int ret;
        ret = conn->driver->domainMemoryPeek (dom, start, size,
                                              buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dom->conn);
    return -1;
}


/************************************************************************
 *									*
 *		Handling of defined but not running domains		*
 *									*
 ************************************************************************/

/**
 * virDomainDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the domain, preferably in UTF-8
 *
 * Define a domain, but does not start it.
 * This definition is persistent, until explicitly undefined with
 * virDomainUndefine(). A previous definition for this domain would be
 * overriden if it already exists.
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXML(virConnectPtr conn, const char *xml) {
    DEBUG("conn=%p, xml=%s", conn, xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainDefineXML) {
        virDomainPtr ret;
        ret = conn->driver->domainDefineXML (conn, xml);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virDomainUndefine:
 * @domain: pointer to a defined domain
 *
 * Undefine a domain but does not stop it if it is running
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefine(virDomainPtr domain) {
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainUndefine) {
        int ret;
        ret = conn->driver->domainUndefine (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virConnectNumOfDefinedDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of defined but inactive domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDefinedDomains(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->numOfDefinedDomains) {
        int ret;
        ret = conn->driver->numOfDefinedDomains (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListDefinedDomains:
 * @conn: pointer to the hypervisor connection
 * @names: pointer to an array to store the names
 * @maxnames: size of the array
 *
 * list the defined but inactive domains, stores the pointers to the names
 * in @names
 *
 * Returns the number of names provided in the array or -1 in case of error
 */
int
virConnectListDefinedDomains(virConnectPtr conn, char **const names,
                             int maxnames) {
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->listDefinedDomains) {
        int ret;
        ret = conn->driver->listDefinedDomains (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virDomainCreate:
 * @domain: pointer to a defined domain
 *
 * launch a defined domain. If the call succeed the domain moves from the
 * defined to the running domains pools.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreate(virDomainPtr domain) {
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreate) {
        int ret;
        ret = conn->driver->domainCreate (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetAutostart:
 * @domain: a domain object
 * @autostart: the value returned
 *
 * Provides a boolean value indicating whether the domain
 * configured to be automatically started when the host
 * machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainGetAutostart(virDomainPtr domain,
                      int *autostart)
{
    virConnectPtr conn;
    DEBUG("domain=%p, autostart=%p", domain, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetAutostart) {
        int ret;
        ret = conn->driver->domainGetAutostart (domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainSetAutostart:
 * @domain: a domain object
 * @autostart: whether the domain should be automatically started 0 or 1
 *
 * Configure the domain to be automatically started
 * when the host machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virDomainSetAutostart(virDomainPtr domain,
                      int autostart)
{
    virConnectPtr conn;
    DEBUG("domain=%p, autostart=%d", domain, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSetAutostart) {
        int ret;
        ret = conn->driver->domainSetAutostart (domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainSetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @nvcpus: the new number of virtual CPUs for this domain
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it or if growing the number is arbitrary limited.
 * This function requires privileged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    virConnectPtr conn;
    DEBUG("domain=%p, nvcpus=%u", domain, nvcpus);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (nvcpus < 1) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainSetVcpus) {
        int ret;
        ret = conn->driver->domainSetVcpus (domain, nvcpus);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainPinVcpu:
 * @domain: pointer to domain object, or NULL for Domain0
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 * 	Each bit set to 1 means that corresponding CPU is usable.
 * 	Bytes are stored in little-endian order: CPU0-7, 8-15...
 * 	In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *	If maplen < size, missing bytes are set to zero.
 *	If maplen > size, failure code is returned.
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * This function requires privileged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                 unsigned char *cpumap, int maplen)
{
    virConnectPtr conn;
    DEBUG("domain=%p, vcpu=%u, cpumap=%p, maplen=%d", domain, vcpu, cpumap, maplen);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((vcpu > 32000) || (cpumap == NULL) || (maplen < 1)) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
       goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainPinVcpu) {
        int ret;
        ret = conn->driver->domainPinVcpu (domain, vcpu, cpumap, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to an bit map of real CPUs for all vcpus of this
 *      domain (in 8-bit bytes) (OUT)
 *	If cpumaps is NULL, then no cpumap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in
 *      virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer isn't NULL.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
virDomainGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
                  unsigned char *cpumaps, int maplen)
{
    virConnectPtr conn;
    DEBUG("domain=%p, info=%p, maxinfo=%d, cpumaps=%p, maplen=%d", domain, info, maxinfo, cpumaps, maplen);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if ((info == NULL) || (maxinfo < 1)) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if (cpumaps != NULL && maplen < 1) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetVcpus) {
        int ret;
        ret = conn->driver->domainGetVcpus (domain, info, maxinfo,
                                            cpumaps, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetMaxVcpus:
 * @domain: pointer to domain object
 *
 * Provides the maximum number of virtual CPUs supported for
 * the guest VM. If the guest is inactive, this is basically
 * the same as virConnectGetMaxVcpus. If the guest is running
 * this will reflect the maximum number of virtual CPUs the
 * guest was booted with.
 *
 * Returns the maximum of virtual CPU or -1 in case of error.
 */
int
virDomainGetMaxVcpus(virDomainPtr domain)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxVcpus) {
        int ret;
        ret = conn->driver->domainGetMaxVcpus (domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainGetSecurityLabel:
 * @domain: a domain object
 * @seclabel: pointer to a virSecurityLabel structure
 *
 * Extract security label of an active domain. The 'label' field
 * in the @seclabel argument will be initialized to the empty
 * string if the domain is not running under a security model.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virDomainGetSecurityLabel(virDomainPtr domain, virSecurityLabelPtr seclabel)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }

    if (seclabel == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    conn = domain->conn;

    if (conn->driver->domainGetSecurityLabel)
        return conn->driver->domainGetSecurityLabel(domain, seclabel);

    virLibConnWarning(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/**
 * virNodeGetSecurityModel:
 * @conn: a connection object
 * @secmodel: pointer to a virSecurityModel structure
 *
 * Extract the security model of a hypervisor. The 'model' field
 * in the @secmodel argument may be initialized to the empty
 * string if the driver has not activated a security model.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virNodeGetSecurityModel(virConnectPtr conn, virSecurityModelPtr secmodel)
{
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (secmodel == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    if (conn->driver->nodeGetSecurityModel)
        return conn->driver->nodeGetSecurityModel(conn, secmodel);

    virLibConnWarning(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/**
 * virDomainAttachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * Create a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainAttachDevice(virDomainPtr domain, const char *xml)
{
    virConnectPtr conn;
    DEBUG("domain=%p, xml=%s", domain, xml);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainAttachDevice) {
        int ret;
        ret = conn->driver->domainAttachDevice (domain, xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virDomainDetachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * Destroy a virtual device attachment to backend.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDetachDevice(virDomainPtr domain, const char *xml)
{
    virConnectPtr conn;
    DEBUG("domain=%p, xml=%s", domain, xml);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainDetachDevice) {
        int ret;
        ret = conn->driver->domainDetachDevice (domain, xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(domain->conn);
    return -1;
}

/**
 * virNodeGetCellsFreeMemory:
 * @conn: pointer to the hypervisor connection
 * @freeMems: pointer to the array of unsigned long long
 * @startCell: index of first cell to return freeMems info on.
 * @maxCells: Maximum number of cells for which freeMems information can
 *            be returned.
 *
 * This call returns the amount of free memory in one or more NUMA cells.
 * The @freeMems array must be allocated by the caller and will be filled
 * with the amount of free memory in kilobytes for each cell requested,
 * starting with startCell (in freeMems[0]), up to either
 * (startCell + maxCells), or the number of additional cells in the node,
 * whichever is smaller.
 *
 * Returns the number of entries filled in freeMems, or -1 in case of error.
 */

int
virNodeGetCellsFreeMemory(virConnectPtr conn, unsigned long long *freeMems,
                          int startCell, int maxCells)
{
    DEBUG("conn=%p, freeMems=%p, startCell=%d, maxCells=%d",
          conn, freeMems, startCell, maxCells);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((freeMems == NULL) || (maxCells <= 0) || (startCell < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->nodeGetCellsFreeMemory) {
        int ret;
        ret = conn->driver->nodeGetCellsFreeMemory (conn, freeMems, startCell, maxCells);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virNetworkGetConnect:
 * @net: pointer to a network
 *
 * Provides the connection pointer associated with a network.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the network object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virNetworkGetConnect (virNetworkPtr net)
{
    DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK (net)) {
        virLibNetworkError (NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return NULL;
    }
    return net->conn;
}

/**
 * virConnectNumOfNetworks:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active networks.
 *
 * Returns the number of network found or -1 in case of error
 */
int
virConnectNumOfNetworks(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->numOfNetworks) {
        int ret;
        ret = conn->networkDriver->numOfNetworks (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListNetworks:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of active networks
 * @maxnames: size of @names
 *
 * Collect the list of active networks, and store their names in @names
 *
 * Returns the number of networks found or -1 in case of error
 */
int
virConnectListNetworks(virConnectPtr conn, char **const names, int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->listNetworks) {
        int ret;
        ret = conn->networkDriver->listNetworks (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectNumOfDefinedNetworks:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of inactive networks.
 *
 * Returns the number of networks found or -1 in case of error
 */
int
virConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->numOfDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->numOfDefinedNetworks (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListDefinedNetworks:
 * @conn: pointer to the hypervisor connection
 * @names: pointer to an array to store the names
 * @maxnames: size of the array
 *
 * list the inactive networks, stores the pointers to the names in @names
 *
 * Returns the number of names provided in the array or -1 in case of error
 */
int
virConnectListDefinedNetworks(virConnectPtr conn, char **const names,
                              int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->listDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->listDefinedNetworks (conn,
                                                        names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virNetworkLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the network
 *
 * Try to lookup a network on the given hypervisor based on its name.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByName(virConnectPtr conn, const char *name)
{
    DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto  error;
    }

    if (conn->networkDriver && conn->networkDriver->networkLookupByName) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByName (conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNetworkLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    DEBUG("conn=%p, uuid=%s", conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkLookupByUUID){
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByUUID (conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNetworkLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * Returns a new network object or NULL in case of failure.  If the
 * network cannot be found, then VIR_ERR_NO_NETWORK error is raised.
 */
virNetworkPtr
virNetworkLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    int raw[VIR_UUID_BUFLEN], i;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int ret;
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /* XXX: sexpr_uuid() also supports 'xxxx-xxxx-xxxx-xxxx' format.
     *      We needn't it here. Right?
     */
    ret = sscanf(uuidstr,
                 "%02x%02x%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x-"
                 "%02x%02x%02x%02x%02x%02x",
                 raw + 0, raw + 1, raw + 2, raw + 3,
                 raw + 4, raw + 5, raw + 6, raw + 7,
                 raw + 8, raw + 9, raw + 10, raw + 11,
                 raw + 12, raw + 13, raw + 14, raw + 15);

    if (ret!=VIR_UUID_BUFLEN) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    for (i = 0; i < VIR_UUID_BUFLEN; i++)
        uuid[i] = raw[i] & 0xFF;

    return virNetworkLookupByUUID(conn, &uuid[0]);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNetworkCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the network
 *
 * Create and start a new virtual network, based on an XML description
 * similar to the one returned by virNetworkGetXMLDesc()
 *
 * Returns a new network object or NULL in case of failure
 */
virNetworkPtr
virNetworkCreateXML(virConnectPtr conn, const char *xmlDesc)
{
    DEBUG("conn=%p, xmlDesc=%s", conn, xmlDesc);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkCreateXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkCreateXML (conn, xmlDesc);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNetworkDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the network, preferably in UTF-8
 *
 * Define a network, but does not create it
 *
 * Returns NULL in case of error, a pointer to the network otherwise
 */
virNetworkPtr
virNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    DEBUG("conn=%p, xml=%s", conn, xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkDefineXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkDefineXML (conn, xml);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virNetworkUndefine:
 * @network: pointer to a defined network
 *
 * Undefine a network but does not stop it if it is running
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkUndefine(virNetworkPtr network) {
    virConnectPtr conn;
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkUndefine) {
        int ret;
        ret = conn->networkDriver->networkUndefine (network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkCreate:
 * @network: pointer to a defined network
 *
 * Create and start a defined network. If the call succeed the network
 * moves from the defined to the running networks pools.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkCreate(virNetworkPtr network)
{
    virConnectPtr conn;
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkCreate) {
        int ret;
        ret = conn->networkDriver->networkCreate (network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkDestroy:
 * @network: a network object
 *
 * Destroy the network object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor. This
 * does not free the associated virNetworkPtr object.
 * This function may require privileged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNetworkDestroy(virNetworkPtr network)
{
    virConnectPtr conn;
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }

    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkDestroy) {
        int ret;
        ret = conn->networkDriver->networkDestroy (network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkFree:
 * @network: a network object
 *
 * Free the network object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNetworkFree(virNetworkPtr network)
{
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (virUnrefNetwork(network) < 0)
        return (-1);
    return(0);
}

/**
 * virNetworkRef:
 * @network: the network to hold a reference on
 *
 * Increment the reference count on the network. For each
 * additional call to this method, there shall be a corresponding
 * call to virNetworkFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a network would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNetworkRef(virNetworkPtr network)
{
    if ((!VIR_IS_CONNECTED_NETWORK(network))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&network->conn->lock);
    DEBUG("network=%p refs=%d", network, network->refs);
    network->refs++;
    virMutexUnlock(&network->conn->lock);
    return 0;
}

/**
 * virNetworkGetName:
 * @network: a network object
 *
 * Get the public name for that network
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the network object.
 */
const char *
virNetworkGetName(virNetworkPtr network)
{
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }
    return (network->name);
}

/**
 * virNetworkGetUUID:
 * @network: a network object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a network
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetUUID(virNetworkPtr network, unsigned char *uuid)
{
    DEBUG("network=%p, uuid=%p", network, uuid);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memcpy(uuid, &network->uuid[0], VIR_UUID_BUFLEN);

    return (0);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkGetUUIDString:
 * @network: a network object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a network as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetUUIDString(virNetworkPtr network, char *buf)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("network=%p, buf=%p", network, buf);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virNetworkGetUUID(network, &uuid[0]))
        return (-1);

    virUUIDFormat(uuid, buf);
    return (0);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkGetXMLDesc:
 * @network: a network object
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * Provide an XML description of the network. The description may be reused
 * later to relaunch the network with virNetworkCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetXMLDesc(virNetworkPtr network, int flags)
{
    virConnectPtr conn;
    DEBUG("network=%p, flags=%d", network, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkDumpXML) {
        char *ret;
        ret = conn->networkDriver->networkDumpXML (network, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return NULL;
}

/**
 * virNetworkGetBridgeName:
 * @network: a network object
 *
 * Provides a bridge interface name to which a domain may connect
 * a network interface in order to join the network.
 *
 * Returns a 0 terminated interface name, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetBridgeName(virNetworkPtr network)
{
    virConnectPtr conn;
    DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetBridgeName) {
        char *ret;
        ret = conn->networkDriver->networkGetBridgeName (network);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return NULL;
}

/**
 * virNetworkGetAutostart:
 * @network: a network object
 * @autostart: the value returned
 *
 * Provides a boolean value indicating whether the network
 * configured to be automatically started when the host
 * machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkGetAutostart(virNetworkPtr network,
                       int *autostart)
{
    virConnectPtr conn;
    DEBUG("network=%p, autostart=%p", network, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetAutostart) {
        int ret;
        ret = conn->networkDriver->networkGetAutostart (network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virNetworkSetAutostart:
 * @network: a network object
 * @autostart: whether the network should be automatically started 0 or 1
 *
 * Configure the network to be automatically started
 * when the host machine boots.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNetworkSetAutostart(virNetworkPtr network,
                       int autostart)
{
    virConnectPtr conn;
    DEBUG("network=%p, autostart=%d", network, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }

    if (network->conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkSetAutostart) {
        int ret;
        ret = conn->networkDriver->networkSetAutostart (network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(network->conn);
    return -1;
}

/**
 * virInterfaceGetConnect:
 * @iface: pointer to a interface
 *
 * Provides the connection pointer associated with an interface.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the interface object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virInterfaceGetConnect (virInterfacePtr iface)
{
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE (iface)) {
        virLibInterfaceError (NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return NULL;
    }
    return iface->conn;
}

/**
 * virConnectNumOfInterfaces:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of interfaces on the physical host.
 *
 * Returns the number of interface found or -1 in case of error
 */
int
virConnectNumOfInterfaces(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->interfaceDriver && conn->interfaceDriver->numOfInterfaces) {
        int ret;
        ret = conn->interfaceDriver->numOfInterfaces (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListInterfaces:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of interfaces
 * @maxnames: size of @names
 *
 * Collect the list of physical host interfaces, and store their names in @names
 *
 * Returns the number of interfaces found or -1 in case of error
 */
int
virConnectListInterfaces(virConnectPtr conn, char **const names, int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->listInterfaces) {
        int ret;
        ret = conn->interfaceDriver->listInterfaces (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virInterfaceLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the interface
 *
 * Try to lookup an interface on the given hypervisor based on its name.
 *
 * Returns a new interface object or NULL in case of failure.  If the
 * interface cannot be found, then VIR_ERR_NO_INTERFACE error is raised.
 */
virInterfacePtr
virInterfaceLookupByName(virConnectPtr conn, const char *name)
{
    DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto  error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByName) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByName (conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virInterfaceLookupByMACString:
 * @conn: pointer to the hypervisor connection
 * @macstr: the MAC for the interface (null-terminated ASCII format)
 *
 * Try to lookup an interface on the given hypervisor based on its MAC.
 *
 * Returns a new interface object or NULL in case of failure.  If the
 * interface cannot be found, then VIR_ERR_NO_INTERFACE error is raised.
 */
virInterfacePtr
virInterfaceLookupByMACString(virConnectPtr conn, const char *macstr)
{
    DEBUG("conn=%p, macstr=%s", conn, macstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (macstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto  error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByMACString) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByMACString (conn, macstr);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virInterfaceGetName:
 * @iface: a interface object
 *
 * Get the public name for that interface
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the interface object.
 */
const char *
virInterfaceGetName(virInterfacePtr iface)
{
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (NULL);
    }
    return (iface->name);
}

/**
 * virInterfaceGetMACString:
 * @iface: a interface object
 *
 * Get the MAC for a interface as string. For more information about
 * MAC see RFC4122.
 *
 * Returns a pointer to the MAC address (in null-terminated ASCII
 * format) or NULL, the string need not be deallocated its lifetime
 * will be the same as the interface object.
 */
const char *
virInterfaceGetMACString(virInterfacePtr iface)
{
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (NULL);
    }
    return (iface->mac);
}

/**
 * virInterfaceGetXMLDesc:
 * @iface: a interface object
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * Provide an XML description of the interface. The description may be reused
 * later to recreate the interface with virInterfaceCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virInterfaceGetXMLDesc(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("iface=%p, flags=%d", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibInterfaceError(iface, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = iface->conn;

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceGetXMLDesc) {
        char *ret;
        ret = conn->interfaceDriver->interfaceGetXMLDesc (iface, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(iface->conn);
    return NULL;
}

/**
 * virInterfaceDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the interface, preferably in UTF-8
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * Define an interface (or modify existing interface configuration)
 *
 * Returns NULL in case of error, a pointer to the interface otherwise
 */
virInterfacePtr
virInterfaceDefineXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    DEBUG("conn=%p, xml=%s, flags=%d", conn, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDefineXML) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceDefineXML (conn, xml, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virInterfaceUndefine:
 * @iface: pointer to a defined interface
 *
 * Undefine an interface, ie remove it from the config.
 * This does not free the associated virInterfacePtr object.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceUndefine(virInterfacePtr iface) {
    virConnectPtr conn;
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (-1);
    }
    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(iface, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceUndefine) {
        int ret;
        ret = conn->interfaceDriver->interfaceUndefine (iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(iface->conn);
    return -1;
}

/**
 * virInterfaceCreate:
 * @iface: pointer to a defined interface
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * Activate an interface (ie call "ifup")
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceCreate(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("iface=%p, flags=%d", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (-1);
    }
    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(iface, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceCreate) {
        int ret;
        ret = conn->interfaceDriver->interfaceCreate (iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(iface->conn);
    return -1;
}

/**
 * virInterfaceDestroy:
 * @iface: an interface object
 * @flags: and OR'ed set of extraction flags, not used yet
 *
 * deactivate an interface (ie call "ifdown")
 * This does not remove the interface from the config, and
 * does not free the associated virInterfacePtr object.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceDestroy(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("iface=%p, flags=%d", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (-1);
    }

    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(iface, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDestroy) {
        int ret;
        ret = conn->interfaceDriver->interfaceDestroy (iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(iface->conn);
    return -1;
}

/**
 * virInterfaceRef:
 * @iface: the interface to hold a reference on
 *
 * Increment the reference count on the interface. For each
 * additional call to this method, there shall be a corresponding
 * call to virInterfaceFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a interface would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virInterfaceRef(virInterfacePtr iface)
{
    if ((!VIR_IS_CONNECTED_INTERFACE(iface))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&iface->conn->lock);
    DEBUG("iface=%p refs=%d", iface, iface->refs);
    iface->refs++;
    virMutexUnlock(&iface->conn->lock);
    return 0;
}

/**
 * virInterfaceFree:
 * @iface: a interface object
 *
 * Free the interface object. The interface itself is unaltered.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceFree(virInterfacePtr iface)
{
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(NULL, VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        return (-1);
    }
    if (virUnrefInterface(iface) < 0)
        return (-1);
    return(0);
}


/**
 * virStoragePoolGetConnect:
 * @pool: pointer to a pool
 *
 * Provides the connection pointer associated with a storage pool.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the pool object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virStoragePoolGetConnect (virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL (pool)) {
        virLibStoragePoolError (NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return NULL;
    }
    return pool->conn;
}

/**
 * virConnectNumOfStoragePools:
 * @conn: pointer to hypervisor connection
 *
 * Provides the number of active storage pools
 *
 * Returns the number of pools found, or -1 on error
 */
int
virConnectNumOfStoragePools	(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->numOfPools) {
        int ret;
        ret = conn->storageDriver->numOfPools (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectListStoragePools:
 * @conn: pointer to hypervisor connection
 * @names: array of char * to fill with pool names (allocated by caller)
 * @maxnames: size of the names array
 *
 * Provides the list of names of active storage pools
 * upto maxnames. If there are more than maxnames, the
 * remaining names will be silently ignored.
 *
 * Returns 0 on success, -1 on error
 */
int
virConnectListStoragePools	(virConnectPtr conn,
                             char **const names,
                             int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->listPools) {
        int ret;
        ret = conn->storageDriver->listPools (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}


/**
 * virConnectNumOfDefinedStoragePools:
 * @conn: pointer to hypervisor connection
 *
 * Provides the number of inactive storage pools
 *
 * Returns the number of pools found, or -1 on error
 */
int
virConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->numOfDefinedPools) {
        int ret;
        ret = conn->storageDriver->numOfDefinedPools (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}


/**
 * virConnectListDefinedStoragePools:
 * @conn: pointer to hypervisor connection
 * @names: array of char * to fill with pool names (allocated by caller)
 * @maxnames: size of the names array
 *
 * Provides the list of names of inactive storage pools
 * upto maxnames. If there are more than maxnames, the
 * remaining names will be silently ignored.
 *
 * Returns 0 on success, -1 on error
 */
int
virConnectListDefinedStoragePools(virConnectPtr conn,
                                  char **const names,
                                  int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->listDefinedPools) {
        int ret;
        ret = conn->storageDriver->listDefinedPools (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}


/**
 * virConnectFindStoragePoolSources:
 * @conn: pointer to hypervisor connection
 * @type: type of storage pool sources to discover
 * @srcSpec: XML document specifying discovery source
 * @flags: flags for discovery (unused, pass 0)
 *
 * Talks to a storage backend and attempts to auto-discover the set of
 * available storage pool sources. e.g. For iSCSI this would be a set of
 * iSCSI targets. For NFS this would be a list of exported paths.  The
 * srcSpec (optional for some storage pool types, e.g. local ones) is
 * an instance of the storage pool's source element specifying where
 * to look for the pools.
 *
 * srcSpec is not required for some types (e.g., those querying
 * local storage resources only)
 *
 * Returns an xml document consisting of a SourceList element
 * containing a source document appropriate to the given pool
 * type for each discovered source.
 */
char *
virConnectFindStoragePoolSources(virConnectPtr conn,
                                 const char *type,
                                 const char *srcSpec,
                                 unsigned int flags)
{
    DEBUG("conn=%p, type=%s, src=%s, flags=%u", conn, type ? type : "", srcSpec ? srcSpec : "", flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }
    if (type == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->findPoolSources) {
        char *ret;
        ret = conn->storageDriver->findPoolSources(conn, type, srcSpec, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByName:
 * @conn: pointer to hypervisor connection
 * @name: name of pool to fetch
 *
 * Fetch a storage pool based on its unique name
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 */
virStoragePoolPtr
virStoragePoolLookupByName(virConnectPtr conn,
                           const char *name)
{
    DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolLookupByName) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->poolLookupByName (conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByUUID:
 * @conn: pointer to hypervisor connection
 * @uuid: globally unique id of pool to fetch
 *
 * Fetch a storage pool based on its globally unique id
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 */
virStoragePoolPtr
virStoragePoolLookupByUUID(virConnectPtr conn,
                           const unsigned char *uuid)
{
    DEBUG("conn=%p, uuid=%s", conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolLookupByUUID) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->poolLookupByUUID (conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByUUIDString:
 * @conn: pointer to hypervisor connection
 * @uuidstr: globally unique id of pool to fetch
 *
 * Fetch a storage pool based on its globally unique id
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 */
virStoragePoolPtr
virStoragePoolLookupByUUIDString(virConnectPtr conn,
                                 const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    return virStoragePoolLookupByUUID(conn, uuid);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByVolume:
 * @vol: pointer to storage volume
 *
 * Fetch a storage pool which contains a particular volume
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 */
virStoragePoolPtr
virStoragePoolLookupByVolume(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }

    if (vol->conn->storageDriver && vol->conn->storageDriver->poolLookupByVolume) {
        virStoragePoolPtr ret;
        ret = vol->conn->storageDriver->poolLookupByVolume (vol);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (vol->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(vol->conn);
    return NULL;
}

/**
 * virStoragePoolCreateXML:
 * @conn: pointer to hypervisor connection
 * @xmlDesc: XML description for new pool
 * @flags: future flags, use 0 for now
 *
 * Create a new storage based on its XML description. The
 * pool is not persistent, so its definition will disappear
 * when it is destroyed, or if the host is restarted
 *
 * Returns a virStoragePoolPtr object, or NULL if creation failed
 */
virStoragePoolPtr
virStoragePoolCreateXML(virConnectPtr conn,
                        const char *xmlDesc,
                        unsigned int flags)
{
    DEBUG("conn=%p, xmlDesc=%s", conn, xmlDesc);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolCreateXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->poolCreateXML (conn, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virStoragePoolDefineXML:
 * @conn: pointer to hypervisor connection
 * @xml: XML description for new pool
 * @flags: future flags, use 0 for now
 *
 * Define a new inactive storage pool based on its XML description. The
 * pool is persistent, until explicitly undefined.
 *
 * Returns a virStoragePoolPtr object, or NULL if creation failed
 */
virStoragePoolPtr
virStoragePoolDefineXML(virConnectPtr conn,
                        const char *xml,
                        unsigned int flags)
{
    DEBUG("conn=%p, xml=%s", conn, xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolDefineXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->poolDefineXML (conn, xml, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virStoragePoolBuild:
 * @pool: pointer to storage pool
 * @flags: future flags, use 0 for now
 *
 * Build the underlying storage pool
 *
 * Returns 0 on success, or -1 upon failure
 */
int
virStoragePoolBuild(virStoragePoolPtr pool,
                    unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("pool=%p, flags=%u", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolBuild) {
        int ret;
        ret = conn->storageDriver->poolBuild (pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolUndefine:
 * @pool: pointer to storage pool
 *
 * Undefine an inactive storage pool
 *
 * Returns a virStoragePoolPtr object, or NULL if creation failed
 */
int
virStoragePoolUndefine(virStoragePoolPtr pool)
{
    virConnectPtr conn;
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolUndefine) {
        int ret;
        ret = conn->storageDriver->poolUndefine (pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolCreate:
 * @pool: pointer to storage pool
 * @flags: future flags, use 0 for now
 *
 * Starts an inactive storage pool
 *
 * Returns 0 on success, or -1 if it could not be started
 */
int
virStoragePoolCreate(virStoragePoolPtr pool,
                     unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolCreate) {
        int ret;
        ret = conn->storageDriver->poolCreate (pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolDestroy:
 * @pool: pointer to storage pool
 *
 * Destroy an active storage pool. This will deactivate the
 * pool on the host, but keep any persistent config associated
 * with it. If it has a persistent config it can later be
 * restarted with virStoragePoolCreate(). This does not free
 * the associated virStoragePoolPtr object.
 *
 * Returns 0 on success, or -1 if it could not be destroyed
 */
int
virStoragePoolDestroy(virStoragePoolPtr pool)
{
    virConnectPtr conn;
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolDestroy) {
        int ret;
        ret = conn->storageDriver->poolDestroy (pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}

/**
 * virStoragePoolDelete:
 * @pool: pointer to storage pool
 * @flags: flags for obliteration process
 *
 * Delete the underlying pool resources. This is
 * a non-recoverable operation. The virStoragePoolPtr object
 * itself is not free'd.
 *
 * Returns 0 on success, or -1 if it could not be obliterate
 */
int
virStoragePoolDelete(virStoragePoolPtr pool,
                     unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("pool=%p, flags=%u", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolDelete) {
        int ret;
        ret = conn->storageDriver->poolDelete (pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolFree:
 * @pool: pointer to storage pool
 *
 * Free a storage pool object, releasing all memory associated with
 * it. Does not change the state of the pool on the host.
 *
 * Returns 0 on success, or -1 if it could not be free'd.
 */
int
virStoragePoolFree(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (virUnrefStoragePool(pool) < 0)
        return (-1);
    return(0);

}


/**
 * virStoragePoolRef:
 * @pool: the pool to hold a reference on
 *
 * Increment the reference count on the pool. For each
 * additional call to this method, there shall be a corresponding
 * call to virStoragePoolFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a pool would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virStoragePoolRef(virStoragePoolPtr pool)
{
    if ((!VIR_IS_CONNECTED_STORAGE_POOL(pool))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&pool->conn->lock);
    DEBUG("pool=%p refs=%d", pool, pool->refs);
    pool->refs++;
    virMutexUnlock(&pool->conn->lock);
    return 0;
}

/**
 * virStoragePoolRefresh:
 * @pool: pointer to storage pool
 * @flags: flags to control refresh behaviour (currently unused, use 0)
 *
 * Request that the pool refresh its list of volumes. This may
 * involve communicating with a remote server, and/or initializing
 * new devices at the OS layer
 *
 * Return 0 if the volume list was refreshed, -1 on failure
 */
int
virStoragePoolRefresh(virStoragePoolPtr pool,
                      unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("pool=%p flags=%u", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->poolRefresh) {
        int ret;
        ret = conn->storageDriver->poolRefresh (pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetName:
 * @pool: pointer to storage pool
 *
 * Fetch the locally unique name of the storage pool
 *
 * Return the name of the pool, or NULL on error
 */
const char*
virStoragePoolGetName(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (NULL);
    }
    return (pool->name);
}


/**
 * virStoragePoolGetUUID:
 * @pool: pointer to storage pool
 * @uuid: buffer of VIR_UUID_BUFLEN bytes in size
 *
 * Fetch the globally unique ID of the storage pool
 *
 * Return 0 on success, or -1 on error;
 */
int
virStoragePoolGetUUID(virStoragePoolPtr pool,
                      unsigned char *uuid)
{
    DEBUG("pool=%p, uuid=%p", pool, uuid);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memcpy(uuid, &pool->uuid[0], VIR_UUID_BUFLEN);

    return (0);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}

/**
 * virStoragePoolGetUUIDString:
 * @pool: pointer to storage pool
 * @buf: buffer of VIR_UUID_STRING_BUFLEN bytes in size
 *
 * Fetch the globally unique ID of the storage pool as a string
 *
 * Return 0 on success, or -1 on error;
 */
int
virStoragePoolGetUUIDString(virStoragePoolPtr pool,
                            char *buf)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("pool=%p, buf=%p", pool, buf);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virStoragePoolGetUUID(pool, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return (0);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetInfo:
 * @pool: pointer to storage pool
 * @info: pointer at which to store info
 *
 * Get volatile information about the storage pool
 * such as free space / usage summary
 *
 * returns 0 on success, or -1 on failure.
 */
int
virStoragePoolGetInfo(virStoragePoolPtr pool,
                      virStoragePoolInfoPtr info)
{
    virConnectPtr conn;
    DEBUG("pool=%p, info=%p", pool, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memset(info, 0, sizeof(virStoragePoolInfo));

    conn = pool->conn;

    if (conn->storageDriver->poolGetInfo) {
        int ret;
        ret = conn->storageDriver->poolGetInfo (pool, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetXMLDesc:
 * @pool: pointer to storage pool
 * @flags: flags for XML format options (set of virDomainXMLFlags)
 *
 * Fetch an XML document describing all aspects of the
 * storage pool. This is suitable for later feeding back
 * into the virStoragePoolCreateXML method.
 *
 * returns a XML document, or NULL on error
 */
char *
virStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                         unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("pool=%p, flags=%u", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->poolGetXMLDesc (pool, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return NULL;
}


/**
 * virStoragePoolGetAutostart:
 * @pool: pointer to storage pool
 * @autostart: location in which to store autostart flag
 *
 * Fetches the value of the autostart flag, which determines
 * whether the pool is automatically started at boot time
 *
 * return 0 on success, -1 on failure
 */
int
virStoragePoolGetAutostart(virStoragePoolPtr pool,
                           int *autostart)
{
    virConnectPtr conn;
    DEBUG("pool=%p, autostart=%p", pool, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolGetAutostart) {
        int ret;
        ret = conn->storageDriver->poolGetAutostart (pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolSetAutostart:
 * @pool: pointer to storage pool
 * @autostart: new flag setting
 *
 * Sets the autostart flag
 *
 * returns 0 on success, -1 on failure
 */
int
virStoragePoolSetAutostart(virStoragePoolPtr pool,
                           int autostart)
{
    virConnectPtr conn;
    DEBUG("pool=%p, autostart=%d", pool, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        goto error;
    }

    if (pool->conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolSetAutostart) {
        int ret;
        ret = conn->storageDriver->poolSetAutostart (pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolNumOfVolumes:
 * @pool: pointer to storage pool
 *
 * Fetch the number of storage volumes within a pool
 *
 * Returns the number of storage pools, or -1 on failure
 */
int
virStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->poolNumOfVolumes) {
        int ret;
        ret = pool->conn->storageDriver->poolNumOfVolumes (pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStoragePoolListVolumes:
 * @pool: pointer to storage pool
 * @names: array in which to storage volume names
 * @maxnames: size of names array
 *
 * Fetch list of storage volume names, limiting to
 * at most maxnames.
 *
 * Returns the number of names fetched, or -1 on error
 */
int
virStoragePoolListVolumes(virStoragePoolPtr pool,
                          char **const names,
                          int maxnames)
{
    DEBUG("pool=%p, names=%p, maxnames=%d", pool, names, maxnames);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->poolListVolumes) {
        int ret;
        ret = pool->conn->storageDriver->poolListVolumes (pool, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return -1;
}


/**
 * virStorageVolGetConnect:
 * @vol: pointer to a pool
 *
 * Provides the connection pointer associated with a storage volume.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do
 * not use this function.  Instead, store the connection and
 * the volume object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virStorageVolGetConnect (virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL (vol)) {
        virLibStoragePoolError (NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return NULL;
    }
    return vol->conn;
}


/**
 * virStorageVolLookupByName:
 * @pool: pointer to storage pool
 * @name: name of storage volume
 *
 * Fetch a pointer to a storage volume based on its name
 * within a pool
 *
 * return a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByName(virStoragePoolPtr pool,
                          const char *name)
{
    DEBUG("pool=%p, name=%s", pool, name);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->volLookupByName) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->volLookupByName (pool, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return NULL;
}



/**
 * virStorageVolLookupByKey:
 * @conn: pointer to hypervisor connection
 * @key: globally unique key
 *
 * Fetch a pointer to a storage volume based on its
 * globally unique key
 *
 * return a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByKey(virConnectPtr conn,
                         const char *key)
{
    DEBUG("conn=%p, key=%s", conn, key);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (key == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->volLookupByKey) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->volLookupByKey (conn, key);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}

/**
 * virStorageVolLookupByPath:
 * @conn: pointer to hypervisor connection
 * @path: locally unique path
 *
 * Fetch a pointer to a storage volume based on its
 * locally (host) unique path
 *
 * return a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByPath(virConnectPtr conn,
                          const char *path)
{
    DEBUG("conn=%p, path=%s", conn, path);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (path == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->volLookupByPath) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->volLookupByPath (conn, path);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virStorageVolGetName:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume name. This is unique
 * within the scope of a pool
 *
 * return the volume name, or NULL on error
 */
const char*
virStorageVolGetName(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }
    return (vol->name);
}


/**
 * virStorageVolGetKey:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume key. This is globally
 * unique, so the same volume will have the same
 * key no matter what host it is accessed from
 *
 * return the volume key, or NULL on error
 */
const char*
virStorageVolGetKey(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }
    return (vol->key);
}


/**
 * virStorageVolCreateXML:
 * @pool: pointer to storage pool
 * @xmldesc: description of volume to create
 * @flags: flags for creation (unused, pass 0)
 *
 * Create a storage volume within a pool based
 * on an XML description. Not all pools support
 * creation of volumes
 *
 * return the storage volume, or NULL on error
 */
virStorageVolPtr
virStorageVolCreateXML(virStoragePoolPtr pool,
                       const char *xmldesc,
                       unsigned int flags)
{
    DEBUG("pool=%p, flags=%u", pool, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (NULL);
    }

    if (pool->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(pool->conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->volCreateXML) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->volCreateXML (pool, xmldesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return NULL;
}


/**
 * virStorageVolCreateXMLFrom:
 * @pool: pointer to parent pool for the new volume
 * @xmldesc: description of volume to create
 * @clonevol: storage volume to use as input
 * @flags: flags for creation (unused, pass 0)
 *
 * Create a storage volume in the parent pool, using the
 * 'clonevol' volume as input. Information for the new
 * volume (name, perms)  are passed via a typical volume
 * XML description.
 *
 * return the storage volume, or NULL on error
 */
virStorageVolPtr
virStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                           const char *xmldesc,
                           virStorageVolPtr clonevol,
                           unsigned int flags)
{
    DEBUG("pool=%p, flags=%u, clonevol=%p", pool, flags, clonevol);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (NULL);
    }

    if (!VIR_IS_STORAGE_VOL(clonevol)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }

    if (pool->conn->flags & VIR_CONNECT_RO ||
        clonevol->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(pool->conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver &&
        pool->conn->storageDriver->volCreateXMLFrom) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->volCreateXMLFrom (pool, xmldesc,
                                                           clonevol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(pool->conn);
    return NULL;
}


/**
 * virStorageVolDelete:
 * @vol: pointer to storage volume
 * @flags: future flags, use 0 for now
 *
 * Delete the storage volume from the pool
 *
 * Return 0 on success, or -1 on error
 */
int
virStorageVolDelete(virStorageVolPtr vol,
                    unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("vol=%p, flags=%u", vol, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(vol, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->volDelete) {
        int ret;
        ret = conn->storageDriver->volDelete (vol, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(vol->conn);
    return -1;
}


/**
 * virStorageVolFree:
 * @vol: pointer to storage volume
 *
 * Release the storage volume handle. The underlying
 * storage volume continues to exist.
 *
 * Return 0 on success, or -1 on error
 */
int
virStorageVolFree(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }
    if (virUnrefStorageVol(vol) < 0)
        return (-1);
    return(0);
}


/**
 * virStorageVolRef:
 * @vol: the vol to hold a reference on
 *
 * Increment the reference count on the vol. For each
 * additional call to this method, there shall be a corresponding
 * call to virStorageVolFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a vol would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virStorageVolRef(virStorageVolPtr vol)
{
    if ((!VIR_IS_CONNECTED_STORAGE_VOL(vol))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&vol->conn->lock);
    DEBUG("vol=%p refs=%d", vol, vol->refs);
    vol->refs++;
    virMutexUnlock(&vol->conn->lock);
    return 0;
}

/**
 * virStorageVolGetInfo:
 * @vol: pointer to storage volume
 * @info: pointer at which to store info
 *
 * Fetches volatile information about the storage
 * volume such as its current allocation
 *
 * Return 0 on success, or -1 on failure
 */
int
virStorageVolGetInfo(virStorageVolPtr vol,
                     virStorageVolInfoPtr info)
{
    virConnectPtr conn;
    DEBUG("vol=%p, info=%p", vol, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibStorageVolError(vol, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memset(info, 0, sizeof(virStorageVolInfo));

    conn = vol->conn;

    if (conn->storageDriver->volGetInfo){
        int ret;
        ret = conn->storageDriver->volGetInfo (vol, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(vol->conn);
    return -1;
}


/**
 * virStorageVolGetXMLDesc:
 * @vol: pointer to storage volume
 * @flags: flags for XML generation (unused, pass 0)
 *
 * Fetch an XML document describing all aspects of
 * the storage volume
 *
 * Return the XML document, or NULL on error
 */
char *
virStorageVolGetXMLDesc(virStorageVolPtr vol,
                        unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("vol=%p, flags=%u", vol, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibStorageVolError(vol, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->volGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->volGetXMLDesc (vol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(vol->conn);
    return NULL;
}


/**
 * virStorageVolGetPath:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume path. Depending on the pool
 * configuration this is either persistent across hosts,
 * or dynamically assigned at pool startup. Consult
 * pool documentation for information on getting the
 * persistent naming
 *
 * Returns the storage volume path, or NULL on error
 */
char *
virStorageVolGetPath(virStorageVolPtr vol)
{
    virConnectPtr conn;
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->volGetPath) {
        char *ret;
        ret = conn->storageDriver->volGetPath (vol);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(vol->conn);
    return NULL;
}


/**
 * virNodeNumOfDevices:
 * @conn: pointer to the hypervisor connection
 * @cap: capability name
 * @flags: flags (unused, pass 0)
 *
 * Provides the number of node devices.
 *
 * If the optional 'cap'  argument is non-NULL, then the count
 * will be restricted to devices with the specified capability
 *
 * Returns the number of node devices or -1 in case of error
 */
int
virNodeNumOfDevices(virConnectPtr conn, const char *cap, unsigned int flags)
{
    DEBUG("conn=%p, cap=%s, flags=%d", conn, NULLSTR(cap), flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (flags != 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->deviceMonitor && conn->deviceMonitor->numOfDevices) {
        int ret;
        ret = conn->deviceMonitor->numOfDevices (conn, cap, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}


/**
 * virNodeListDevices:
 * @conn: pointer to the hypervisor connection
 * @cap: capability name
 * @names: array to collect the list of node device names
 * @maxnames: size of @names
 * @flags: flags (unused, pass 0)
 *
 * Collect the list of node devices, and store their names in @names
 *
 * If the optional 'cap'  argument is non-NULL, then the count
 * will be restricted to devices with the specified capability
 *
 * Returns the number of node devices found or -1 in case of error
 */
int
virNodeListDevices(virConnectPtr conn,
                   const char *cap,
                   char **const names, int maxnames,
                   unsigned int flags)
{
    DEBUG("conn=%p, cap=%s, names=%p, maxnames=%d, flags=%d",
          conn, cap, names, maxnames, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if ((flags != 0) || (names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->deviceMonitor && conn->deviceMonitor->listDevices) {
        int ret;
        ret = conn->deviceMonitor->listDevices (conn, cap, names, maxnames, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}


/**
 * virNodeDeviceLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: unique device name
 *
 * Lookup a node device by its name.
 *
 * Returns a virNodeDevicePtr if found, NULL otherwise.
 */
virNodeDevicePtr virNodeDeviceLookupByName(virConnectPtr conn, const char *name)
{
    DEBUG("conn=%p, name=%p", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->deviceMonitor && conn->deviceMonitor->deviceLookupByName) {
        virNodeDevicePtr ret;
        ret = conn->deviceMonitor->deviceLookupByName (conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virNodeDeviceGetXMLDesc:
 * @dev: pointer to the node device
 * @flags: flags for XML generation (unused, pass 0)
 *
 * Fetch an XML document describing all aspects of
 * the device.
 *
 * Return the XML document, or NULL on error
 */
char *virNodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return NULL;
    }

    if (dev->conn->deviceMonitor && dev->conn->deviceMonitor->deviceDumpXML) {
        char *ret;
        ret = dev->conn->deviceMonitor->deviceDumpXML (dev, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return NULL;
}


/**
 * virNodeDeviceGetName:
 * @dev: the device
 *
 * Just return the device name
 *
 * Returns the device name or NULL in case of error
 */
const char *virNodeDeviceGetName(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return NULL;
    }

    return dev->name;
}

/**
 * virNodeDeviceGetParent:
 * @dev: the device
 *
 * Accessor for the parent of the device
 *
 * Returns the name of the device's parent, or NULL if the
 * device has no parent.
 */
const char *virNodeDeviceGetParent(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return NULL;
    }

    if (!dev->parent) {
        if (dev->conn->deviceMonitor && dev->conn->deviceMonitor->deviceGetParent) {
            dev->parent = dev->conn->deviceMonitor->deviceGetParent (dev);
        } else {
            virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            virSetConnError(dev->conn);
            return NULL;
        }
    }
    return dev->parent;
}

/**
 * virNodeDeviceNumOfCaps:
 * @dev: the device
 *
 * Accessor for the number of capabilities supported by the device.
 *
 * Returns the number of capabilities supported by the device.
 */
int virNodeDeviceNumOfCaps(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return -1;
    }

    if (dev->conn->deviceMonitor && dev->conn->deviceMonitor->deviceNumOfCaps) {
        int ret;
        ret = dev->conn->deviceMonitor->deviceNumOfCaps (dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return -1;
}

/**
 * virNodeDeviceListCaps:
 * @dev: the device
 * @names: array to collect the list of capability names
 * @maxnames: size of @names
 *
 * Lists the names of the capabilities supported by the device.
 *
 * Returns the number of capability names listed in @names.
 */
int virNodeDeviceListCaps(virNodeDevicePtr dev,
                          char **const names,
                          int maxnames)
{
    DEBUG("dev=%p, conn=%p, names=%p, maxnames=%d",
          dev, dev ? dev->conn : NULL, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return -1;
    }

    if (dev->conn->deviceMonitor && dev->conn->deviceMonitor->deviceListCaps) {
        int ret;
        ret = dev->conn->deviceMonitor->deviceListCaps (dev, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceFree:
 * @dev: pointer to the node device
 *
 * Drops a reference to the node device, freeing it if
 * this was the last reference.
 *
 * Returns the 0 for success, -1 for error.
 */
int virNodeDeviceFree(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return (-1);
    }
    if (virUnrefNodeDevice(dev) < 0)
        return (-1);
    return(0);
}


/**
 * virNodeDeviceRef:
 * @dev: the dev to hold a reference on
 *
 * Increment the reference count on the dev. For each
 * additional call to this method, there shall be a corresponding
 * call to virNodeDeviceFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a dev would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceRef(virNodeDevicePtr dev)
{
    if ((!VIR_IS_CONNECTED_NODE_DEVICE(dev))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&dev->conn->lock);
    DEBUG("dev=%p refs=%d", dev, dev->refs);
    dev->refs++;
    virMutexUnlock(&dev->conn->lock);
    return 0;
}

/**
 * virNodeDeviceDettach:
 * @dev: pointer to the node device
 *
 * Dettach the node device from the node itself so that it may be
 * assigned to a guest domain.
 *
 * Depending on the hypervisor, this may involve operations such
 * as unbinding any device drivers from the device, binding the
 * device to a dummy device driver and resetting the device.
 *
 * If the device is currently in use by the node, this method may
 * fail.
 *
 * Once the device is not assigned to any guest, it may be re-attached
 * to the node using the virNodeDeviceReattach() method.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceDettach(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return (-1);
    }

    if (dev->conn->driver->nodeDeviceDettach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceDettach (dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return (-1);
}

/**
 * virNodeDeviceReAttach:
 * @dev: pointer to the node device
 *
 * Re-attach a previously dettached node device to the node so that it
 * may be used by the node again.
 *
 * Depending on the hypervisor, this may involve operations such
 * as resetting the device, unbinding it from a dummy device driver
 * and binding it to its appropriate driver.
 *
 * If the device is currently in use by a guest, this method may fail.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceReAttach(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return (-1);
    }

    if (dev->conn->driver->nodeDeviceReAttach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReAttach (dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return (-1);
}

/**
 * virNodeDeviceReset:
 * @dev: pointer to the node device
 *
 * Reset a previously dettached node device to the node before or
 * after assigning it to a guest.
 *
 * The exact reset semantics depends on the hypervisor and device
 * type but, for example, KVM will attempt to reset PCI devices with
 * a Function Level Reset, Secondary Bus Reset or a Power Management
 * D-State reset.
 *
 * If the reset will affect other devices which are currently in use,
 * this function may fail.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceReset(virNodeDevicePtr dev)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return (-1);
    }

    if (dev->conn->driver->nodeDeviceReset) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReset (dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return (-1);
}


/**
 * virNodeDeviceCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the device to be created
 * @flags: callers should always pass 0
 *
 * Create a new device on the VM host machine, for example, virtual
 * HBAs created using vport_create.
 *
 * Returns a node device object if successful, NULL in case of failure
 */
virNodeDevicePtr
virNodeDeviceCreateXML(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%d", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->deviceMonitor &&
        conn->deviceMonitor->deviceCreateXML) {
        virNodeDevicePtr dev = conn->deviceMonitor->deviceCreateXML(conn, xmlDesc, flags);
        if (dev == NULL)
            goto error;
        return dev;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return NULL;
}


/**
 * virNodeDeviceDestroy:
 * @dev: a device object
 *
 * Destroy the device object. The virtual device is removed from the host operating system.
 * This function may require privileged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNodeDeviceDestroy(virNodeDevicePtr dev)
{
    DEBUG("dev=%p", dev);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        return (-1);
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(dev->conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->deviceMonitor &&
        dev->conn->deviceMonitor->deviceDestroy) {
        int retval = dev->conn->deviceMonitor->deviceDestroy(dev);
        if (retval < 0) {
            goto error;
        }

        return 0;
    }

    virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    /* Copy to connection error object for back compatability */
    virSetConnError(dev->conn);
    return -1;
}


/*
 * Domain Event Notification
 */

/**
 * virConnectDomainEventRegister:
 * @conn: pointer to the connection
 * @cb: callback to the function handling domain events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a Domain Event Callback.
 * Registering for a domain callback will enable delivery of the events
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback
 * returns, it shall take a reference to it, by calling virDomainRef.
 * The reference can be released once the object is no longer required
 * by calling virDomainFree.
 *
 * Returns 0 on success, -1 on failure
 */
int
virConnectDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback cb,
                              void *opaque,
                              virFreeCallback freecb)
{
    DEBUG("conn=%p, cb=%p, opaque=%p, freecb=%p", conn, cb, opaque, freecb);
    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (cb == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if ((conn->driver) && (conn->driver->domainEventRegister)) {
        int ret;
        ret = conn->driver->domainEventRegister (conn, cb, opaque, freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}

/**
 * virConnectDomainEventDeregister:
 * @conn: pointer to the connection
 * @cb: callback to the function handling domain events
 *
 * Removes a Domain Event Callback.
 * De-registering for a domain callback will disable
 * delivery of this event type
 *
 * Returns 0 on success, -1 on failure
 */
int
virConnectDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback cb)
{
    DEBUG("conn=%p, cb=%p", conn, cb);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (cb == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if ((conn->driver) && (conn->driver->domainEventDeregister)) {
        int ret;
        ret = conn->driver->domainEventDeregister (conn, cb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    /* Copy to connection error object for back compatability */
    virSetConnError(conn);
    return -1;
}
