/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005-2006, 2008-2010 Red Hat, Inc.
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
# include <sys/wait.h>
#endif
#include <time.h>
#include <gcrypt.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include "getpass.h"

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "driver.h"

#include "uuid.h"
#include "util.h"
#include "memory.h"

#ifndef WITH_DRIVER_MODULES
# ifdef WITH_TEST
#  include "test/test_driver.h"
# endif
# ifdef WITH_XEN
#  include "xen/xen_driver.h"
# endif
# ifdef WITH_REMOTE
#  include "remote/remote_driver.h"
# endif
# ifdef WITH_OPENVZ
#  include "openvz/openvz_driver.h"
# endif
# ifdef WITH_PHYP
#  include "phyp/phyp_driver.h"
# endif
# ifdef WITH_VBOX
#  include "vbox/vbox_driver.h"
# endif
# ifdef WITH_ESX
#  include "esx/esx_driver.h"
# endif
# ifdef WITH_XENAPI
#  include "xenapi/xenapi_driver.h"
# endif
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
static virSecretDriverPtr virSecretDriverTab[MAX_DRIVERS];
static int virSecretDriverTabCount = 0;
static virNWFilterDriverPtr virNWFilterDriverTab[MAX_DRIVERS];
static int virNWFilterDriverTabCount = 0;
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
            if (printf("%s: ", cred[i].prompt) < 0)
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
            if (printf("%s: ", cred[i].prompt) < 0)
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

static int virTLSMutexInit (void **priv)
{                                                                             \
    virMutexPtr lock = NULL;

    if (VIR_ALLOC(lock) < 0)
        return ENOMEM;

    if (virMutexInit(lock) < 0) {
        VIR_FREE(lock);
        return errno;
    }

    *priv = lock;
    return 0;
}

static int virTLSMutexDestroy(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexDestroy(lock);
    VIR_FREE(lock);
    return 0;
}

static int virTLSMutexLock(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexLock(lock);
    return 0;
}

static int virTLSMutexUnlock(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexUnlock(lock);
    return 0;
}

static struct gcry_thread_cbs virTLSThreadImpl = {
    /* GCRY_THREAD_OPTION_VERSION was added in gcrypt 1.4.2 */
#ifdef GCRY_THREAD_OPTION_VERSION
    (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)),
#else
    GCRY_THREAD_OPTION_PTHREAD,
#endif
    NULL,
    virTLSMutexInit,
    virTLSMutexDestroy,
    virTLSMutexLock,
    virTLSMutexUnlock,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};


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
    if (initialized)
        return(0);

    initialized = 1;

    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0 ||
        virRandomInitialize(time(NULL) ^ getpid()))
        return -1;

    gcry_control(GCRYCTL_SET_THREAD_CBS, &virTLSThreadImpl);
    gcry_check_version(NULL);

    virLogSetFromEnv();

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
     * If they try to open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
    virDriverLoadModule("test");
    virDriverLoadModule("xen");
    virDriverLoadModule("openvz");
    virDriverLoadModule("vbox");
    virDriverLoadModule("esx");
    virDriverLoadModule("xenapi");
    virDriverLoadModule("remote");
#else
# ifdef WITH_TEST
    if (testRegister() == -1) return -1;
# endif
# ifdef WITH_XEN
    if (xenRegister () == -1) return -1;
# endif
# ifdef WITH_OPENVZ
    if (openvzRegister() == -1) return -1;
# endif
# ifdef WITH_PHYP
    if (phypRegister() == -1) return -1;
# endif
# ifdef WITH_VBOX
    if (vboxRegister() == -1) return -1;
# endif
# ifdef WITH_ESX
    if (esxRegister() == -1) return -1;
# endif
# ifdef WITH_XENAPI
    if (xenapiRegister() == -1) return -1;
# endif
# ifdef WITH_REMOTE
    if (remoteRegister () == -1) return -1;
# endif
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

#define virLibStreamError(conn, code, ...)                      \
    virReportErrorHelper(conn, VIR_FROM_NONE, code, __FILE__,   \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/**
 * virLibSecretError:
 * @secret: the secret if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the secret level
 */
static void
virLibSecretError(virSecretPtr secret, virErrorNumber error, const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_SECRET)
        conn = secret->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_SECRET, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibNWFilterError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the connection level
 */
static void
virLibNWFilterError(virNWFilterPtr pool, virErrorNumber error,
                    const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_NWFILTER)
        conn = pool->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_NWFILTER, error, VIR_ERR_ERROR,
                  errmsg, info, NULL, 0, 0, errmsg, info);
}

/**
 * virLibDomainSnapshotError:
 * @snapshot: the snapshot if available
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the domain snapshot level
 */
static void
virLibDomainSnapshotError(virDomainSnapshotPtr snapshot, virErrorNumber error, const char *info)
{
    virConnectPtr conn = NULL;
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_DOMAIN_SNAPSHOT)
        conn = snapshot->domain->conn;

    virRaiseError(conn, NULL, NULL, VIR_FROM_DOMAIN_SNAPSHOT, error, VIR_ERR_ERROR,
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
 * @driver: pointer to an interface driver block
 *
 * Register an interface virtualization driver
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
 * virRegisterSecretDriver:
 * @driver: pointer to a secret driver block
 *
 * Register a secret driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterSecretDriver(virSecretDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    if (virSecretDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }

    DEBUG ("registering %s as secret driver %d",
           driver->name, virSecretDriverTabCount);

    virSecretDriverTab[virSecretDriverTabCount] = driver;
    return virSecretDriverTabCount++;
}

/**
 * virRegisterNWFilterDriver:
 * @driver: pointer to a network filter driver block
 *
 * Register a network filter virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterNWFilterDriver(virNWFilterDriverPtr driver)
{
    if (virInitialize() < 0)
      return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    if (virNWFilterDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    DEBUG ("registering %s as network filter driver %d",
           driver->name, virNWFilterDriverTabCount);

    virNWFilterDriverTab[virNWFilterDriverTabCount] = driver;
    return virNWFilterDriverTabCount++;
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
 * Returns 0 if all succeed, -1 upon any failure.
 */
int virStateInitialize(int privileged) {
    int i, ret = 0;

    if (virInitialize() < 0)
        return -1;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->initialize &&
            virStateDriverTab[i]->initialize(privileged) < 0) {
            VIR_ERROR("Initialization of %s state driver failed",
                      virStateDriverTab[i]->name);
            ret = -1;
        }
    }
    return ret;
}

/**
 * virStateCleanup:
 *
 * Run each virtualization driver's cleanup method.
 *
 * Returns 0 if all succeed, -1 upon any failure.
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
 * Returns 0 if all succeed, -1 upon any failure.
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
 * Returns 0 if none are active, 1 if at least one is.
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
            goto error;

    if (libVer == NULL)
        goto error;
    *libVer = LIBVIR_VERSION_NUMBER;

    if (typeVer != NULL) {
        if (type == NULL)
            type = "Xen";

/* FIXME: Add _proper_ type version handling for loadable driver modules... */
#ifdef WITH_DRIVER_MODULES
        *typeVer = LIBVIR_VERSION_NUMBER;
#else
        *typeVer = 0;

# if WITH_XEN
        if (STRCASEEQ(type, "Xen"))
            *typeVer = xenUnifiedVersion();
# endif
# if WITH_TEST
        if (STRCASEEQ(type, "Test"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_QEMU
        if (STRCASEEQ(type, "QEMU"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_LXC
        if (STRCASEEQ(type, "LXC"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_PHYP
        if (STRCASEEQ(type, "phyp"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_OPENVZ
        if (STRCASEEQ(type, "OpenVZ"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_VBOX
        if (STRCASEEQ(type, "VBox"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_UML
        if (STRCASEEQ(type, "UML"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_ONE
        if (STRCASEEQ(type, "ONE"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_ESX
        if (STRCASEEQ(type, "ESX"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_XENAPI
        if (STRCASEEQ(type, "XenAPI"))
            *typeVer = LIBVIR_VERSION_NUMBER;
# endif
# if WITH_REMOTE
        if (STRCASEEQ(type, "Remote"))
            *typeVer = remoteVersion();
# endif
        if (*typeVer == 0) {
            virLibConnError(NULL, VIR_ERR_NO_SUPPORT, type);
            goto error;
        }
#endif /* WITH_DRIVER_MODULES */
    }
    return (0);

error:
    virDispatchError(NULL);
    return -1;
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

    /* Secondary driver for storage. Optional */
    for (i = 0; i < virStorageDriverTabCount; i++) {
        res = virStorageDriverTab[i]->open (ret, auth, flags);
        DEBUG("storage driver %d %s returned %s",
              i, virStorageDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virStorageDriverTab[i]->name, "remote")) {
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

    /* Secret manipulation driver. Optional */
    for (i = 0; i < virSecretDriverTabCount; i++) {
        res = virSecretDriverTab[i]->open (ret, auth, flags);
        DEBUG("secret driver %d %s returned %s",
              i, virSecretDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virSecretDriverTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_SECRET,
                                   "Is the daemon running ?");
            }
            break;
         } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->secretDriver = virSecretDriverTab[i];
            break;
        }
    }

    /* Network filter driver. Optional */
    for (i = 0; i < virNWFilterDriverTabCount; i++) {
        res = virNWFilterDriverTab[i]->open (ret, auth, flags);
        DEBUG("nwfilter driver %d %s returned %s",
              i, virNWFilterDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
        if (res == VIR_DRV_OPEN_ERROR) {
            if (STREQ(virNWFilterDriverTab[i]->name, "remote")) {
                virLibConnWarning (NULL, VIR_WAR_NO_NWFILTER,
                                   _("Is the daemon running ?"));
            }
            break;
         } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->nwfilterDriver = virNWFilterDriverTab[i];
            break;
        }
    }

    return ret;

failed:
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
 * If @name is NULL then probing will be done to determine a suitable
 * default driver to activate. This involves trying each hypervisor
 * in turn until one successfully opens. If the LIBVIRT_DEFAULT_URI
 * environment variable is set, then it will be used in preference
 * to probing for a driver.
 *
 * If connecting to an unprivileged hypervisor driver which requires
 * the libvirtd daemon to be active, it will automatically be launched
 * if not already running. This can be prevented by setting the
 * environment variable LIBVIRT_AUTOSTART=0
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpen (const char *name)
{
    virConnectPtr ret = NULL;
    if (!initialized)
        if (virInitialize() < 0)
            goto error;

    DEBUG("name=%s", name);
    ret = do_open (name, NULL, 0);
    if (!ret)
        goto error;
    return ret;

error:
    virDispatchError(NULL);
    return NULL;
}

/**
 * virConnectOpenReadOnly:
 * @name: URI of the hypervisor
 *
 * This function should be called first to get a restricted connection to the
 * library functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * See virConnectOpen for notes about environment variables which can
 * have an effect on opening drivers
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    virConnectPtr ret = NULL;
    if (!initialized)
        if (virInitialize() < 0)
            goto error;

    DEBUG("name=%s", name);
    ret = do_open (name, NULL, VIR_CONNECT_RO);
    if (!ret)
        goto error;
    return ret;

error:
    virDispatchError(NULL);
    return NULL;
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
 * See virConnectOpen for notes about environment variables which can
 * have an effect on opening drivers
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
    virConnectPtr ret = NULL;
    if (!initialized)
        if (virInitialize() < 0)
            goto error;

    DEBUG("name=%s, auth=%p, flags=%d", NULLSTR(name), auth, flags);
    ret = do_open (name, auth, flags);
    if (!ret)
        goto error;
    return ret;

error:
    virDispatchError(NULL);
    return NULL;
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
    int ret = -1;
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }

    ret = virUnrefConnect(conn);
    if (ret < 0)
        goto error;
    return ret;

error:
    virDispatchError(NULL);
    return ret;
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
        return (-1);
    }

    ret = VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn, feature);

    if (ret < 0)
        virDispatchError(conn);

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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectGetLibVersion:
 * @conn: pointer to the hypervisor connection
 * @libVer: returns the libvirt library version used on the connection (OUT)
 *
 * Provides @libVer, which is the version of libvirt used by the
 *   daemon running on the @conn host
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer have
 *      the format major * 1,000,000 + minor * 1,000 + release.
 */
int
virConnectGetLibVersion(virConnectPtr conn, unsigned long *libVer)
{
    int ret = -1;
    DEBUG("conn=%p, libVir=%p", conn, libVer);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (libVer == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->libvirtVersion) {
        ret = conn->driver->libvirtVersion(conn, libVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    *libVer = LIBVIR_VERSION_NUMBER;
    return 0;

error:
    virDispatchError(conn);
    return ret;
}

/**
 * virConnectGetHostname:
 * @conn: pointer to a hypervisor connection
 *
 * This returns the system hostname on which the hypervisor is
 * running (the result of the gethostname system call).  If
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
        return NULL;
    }

    name = (char *)xmlSaveUri(conn->uri);
    if (!name) {
        virReportOOMError();
        goto error;
    }
    return name;

error:
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->numOfDomains) {
        int ret = conn->driver->numOfDomains (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
 * This existing name will left indefinitely for API compatibility.
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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

    return virDomainLookupByUUID(conn, &uuid[0]);

error:
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefDomain(domain) < 0) {
        virDispatchError(NULL);
        return -1;
    }
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume a suspended domain, the process is restarted from the state where
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (uuid == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
        return (NULL);
    }

    conn = domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED,
                        _("virDomainGetXMLDesc with secure flag"));
        goto error;
    }

    flags &= VIR_DOMAIN_XML_FLAGS_MASK;

    if (conn->driver->domainDumpXML) {
        char *ret;
        ret = conn->driver->domainDumpXML (domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
        return (NULL);
    }

    if (nativeFormat == NULL || nativeConfig == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
        return (NULL);
    }

    if (nativeFormat == NULL || domainXml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
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
    virDispatchError(conn);
    return NULL;
}


static virDomainPtr
virDomainMigrateVersion1 (virDomainPtr domain,
                          virConnectPtr dconn,
                          unsigned long flags,
                          const char *dname,
                          const char *uri,
                          unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    int cookielen = 0, ret;
    virDomainInfo info;

    ret = virDomainGetInfo (domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED) {
        flags |= VIR_MIGRATE_PAUSED;
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
    if (dconn->driver->domainMigratePrepare
        (dconn, &cookie, &cookielen, uri, &uri_out, flags, dname,
         bandwidth) == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virLibConnError (domain->conn, VIR_ERR_INTERNAL_ERROR,
                         _("domainMigratePrepare did not set uri"));
        goto done;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare change URI? */
    assert (uri != NULL);

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    if (domain->conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth) == -1)
        goto done;

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

 done:
    VIR_FREE (uri_out);
    VIR_FREE (cookie);
    return ddomain;
}

static virDomainPtr
virDomainMigrateVersion2 (virDomainPtr domain,
                          virConnectPtr dconn,
                          unsigned long flags,
                          const char *dname,
                          const char *uri,
                          unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret;
    virDomainInfo info;
    virErrorPtr orig_err = NULL;

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

    /* In version 2 of the protocol, the prepare step is slightly
     * different.  We fetch the domain XML of the source domain
     * and pass it to Prepare2.
     */
    if (!domain->conn->driver->domainDumpXML) {
        virLibConnError (domain->conn, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        virDispatchError(domain->conn);
        return NULL;
    }
    dom_xml = domain->conn->driver->domainDumpXML (domain,
                                                   VIR_DOMAIN_XML_SECURE |
                                                   VIR_DOMAIN_XML_UPDATE_CPU);
    if (!dom_xml)
        return NULL;

    ret = virDomainGetInfo (domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED) {
        flags |= VIR_MIGRATE_PAUSED;
    }

    ret = dconn->driver->domainMigratePrepare2
        (dconn, &cookie, &cookielen, uri, &uri_out, flags, dname,
         bandwidth, dom_xml);
    VIR_FREE (dom_xml);
    if (ret == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virLibConnError (domain->conn, VIR_ERR_INTERNAL_ERROR,
                         _("domainMigratePrepare2 did not set uri"));
        virDispatchError(domain->conn);
        goto done;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare2 change URI? */
    assert (uri != NULL);

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    ret = domain->conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : domain->name;
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen, uri, flags, ret);

 done:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE (uri_out);
    VIR_FREE (cookie);
    return ddomain;
}


 /*
  * This is sort of a migration v3
  *
  * In this version, the client does not talk to the destination
  * libvirtd. The source libvirtd will still try to talk to the
  * destination libvirtd though, and will do the prepare/perform/finish
  * steps.
  */
static int
virDomainMigratePeer2Peer (virDomainPtr domain,
                           unsigned long flags,
                           const char *dname,
                           const char *uri,
                           unsigned long bandwidth)
{
    if (!domain->conn->driver->domainMigratePerform) {
        virLibConnError (domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        virDispatchError(domain->conn);
        return -1;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    return domain->conn->driver->domainMigratePerform(domain,
                                                      NULL, /* cookie */
                                                      0,    /* cookielen */
                                                      uri,
                                                      flags,
                                                      dname,
                                                      bandwidth);
}


/*
 * This is a variation on v1 & 2  migration
 *
 * This is for hypervisors which can directly handshake
 * without any libvirtd involvement on destination either
 * from client, or source libvirt.
 *
 * eg, XenD can talk direct to XenD, so libvirtd on dest
 * does not need to be involved at all, or even running
 */
static int
virDomainMigrateDirect (virDomainPtr domain,
                        unsigned long flags,
                        const char *dname,
                        const char *uri,
                        unsigned long bandwidth)
{
    if (!domain->conn->driver->domainMigratePerform) {
        virLibConnError (domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        virDispatchError(domain->conn);
        return -1;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    return domain->conn->driver->domainMigratePerform(domain,
                                                      NULL, /* cookie */
                                                      0,    /* cookielen */
                                                      uri,
                                                      flags,
                                                      dname,
                                                      bandwidth);
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
 *   VIR_MIGRATE_LIVE      Do not pause the VM during migration
 *   VIR_MIGRATE_PEER2PEER Direct connection between source & destination hosts
 *   VIR_MIGRATE_TUNNELLED Tunnel migration data over the libvirt RPC channel
 *   VIR_MIGRATE_PERSIST_DEST If the migration is successful, persist the domain
 *                            on the destination host.
 *   VIR_MIGRATE_UNDEFINE_SOURCE If the migration is successful, undefine the
 *                               domain on the source host.
 *   VIR_MIGRATE_PAUSED    Leave the domain suspended on the remote side.
 *
 * VIR_MIGRATE_TUNNELLED requires that VIR_MIGRATE_PEER2PEER be set.
 * Applications using the VIR_MIGRATE_PEER2PEER flag will probably
 * prefer to invoke virDomainMigrateToURI, avoiding the need to
 * open connection to the destination host themselves.
 *
 * If a hypervisor supports renaming domains during migration,
 * then you may set the dname parameter to the new name (otherwise
 * it keeps the same name).  If this is not supported by the
 * hypervisor, dname must be NULL or else you will get an error.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is set, the uri parameter
 * must be a valid libvirt connection URI, by which the source
 * libvirt driver can connect to the destination libvirt. If
 * omitted, the dconn connection object will be queried for its
 * current URI.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, the URI parameter
 * takes a hypervisor specific format. The hypervisor capabilities
 * XML includes details of the support URI schemes. If omitted
 * the dconn will be asked for a default URI.
 *
 * In either case it is typically only necessary to specify a
 * URI if the destination host has multiple interfaces and a
 * specific interface is required to transmit migration data.
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
    virDomainPtr ddomain = NULL;
    DEBUG("domain=%p, dconn=%p, flags=%lu, dname=%s, uri=%s, bandwidth=%lu",
          domain, dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN (domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Now checkout the destination */
    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(domain->conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }
    if (dconn->flags & VIR_CONNECT_RO) {
        /* NB, deliberately report error against source object, not dest */
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE (domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_P2P)) {
            char *dstURI = NULL;
            if (uri == NULL) {
                dstURI = virConnectGetURI(dconn);
                if (!dstURI)
                    return NULL;
            }

            if (virDomainMigratePeer2Peer(domain, flags, dname, uri ? uri : dstURI, bandwidth) < 0) {
                VIR_FREE(dstURI);
                goto error;
            }
            VIR_FREE(dstURI);

            ddomain = virDomainLookupByName (dconn, dname ? dname : domain->name);
        } else {
            /* This driver does not support peer to peer migration */
            virLibConnError (domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virLibConnError(domain->conn, VIR_ERR_OPERATION_INVALID,
                            _("cannot perform tunnelled migration without using peer2peer flag"));
            goto error;
        }

        /* Check that migration is supported by both drivers. */
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_V1) &&
            VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                     VIR_DRV_FEATURE_MIGRATION_V1))
            ddomain = virDomainMigrateVersion1(domain, dconn, flags, dname, uri, bandwidth);
        else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                          VIR_DRV_FEATURE_MIGRATION_V2) &&
                 VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                          VIR_DRV_FEATURE_MIGRATION_V2))
            ddomain = virDomainMigrateVersion2(domain, dconn, flags, dname, uri, bandwidth);
        else {
            /* This driver does not support any migration method */
            virLibConnError(domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    }

    if (ddomain == NULL)
        goto error;

    return ddomain;

error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainMigrateToURI:
 * @domain: a domain object
 * @duri: mandatory URI for the destination host
 * @flags: flags
 * @dname: (optional) rename domain to this at destination
 * @bandwidth: (optional) specify migration bandwidth limit in Mbps
 *
 * Migrate the domain object from its current host to the destination
 * host given by duri.
 *
 * Flags may be one of more of the following:
 *   VIR_MIGRATE_LIVE      Do not pause the VM during migration
 *   VIR_MIGRATE_PEER2PEER Direct connection between source & destination hosts
 *   VIR_MIGRATE_TUNNELLED Tunnel migration data over the libvirt RPC channel
 *   VIR_MIGRATE_PERSIST_DEST If the migration is successful, persist the domain
 *                            on the destination host.
 *   VIR_MIGRATE_UNDEFINE_SOURCE If the migration is successful, undefine the
 *                               domain on the source host.
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, the duri parameter
 * takes a hypervisor specific format. The uri_transports element of the
 * hypervisor capabilities XML includes details of the supported URI
 * schemes. Not all hypervisors will support this mode of migration, so
 * if the VIR_MIGRATE_PEER2PEER flag is not set, then it may be necessary
 * to use the alternative virDomainMigrate API providing and explicit
 * virConnectPtr for the destination host.
 *
 * If the VIR_MIGRATE_PEER2PEER flag IS set, the duri parameter
 * must be a valid libvirt connection URI, by which the source
 * libvirt driver can connect to the destination libvirt.
 *
 * VIR_MIGRATE_TUNNELLED requires that VIR_MIGRATE_PEER2PEER be set.
 *
 * If a hypervisor supports renaming domains during migration,
 * the dname parameter specifies the new name for the domain.
 * Setting dname to NULL keeps the domain name the same.  If domain
 * renaming is not supported by the hypervisor, dname must be NULL or
 * else an error will be returned.
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
 * Returns 0 if the migration succeeded, -1 upon error.
 */
int
virDomainMigrateToURI (virDomainPtr domain,
                       const char *duri,
                       unsigned long flags,
                       const char *dname,
                       unsigned long bandwidth)
{
    DEBUG("domain=%p, duri=%p, flags=%lu, dname=%s, bandwidth=%lu",
          domain, NULLSTR(duri), flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN (domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (duri == NULL) {
        virLibConnError (domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE (domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_P2P)) {
            if (virDomainMigratePeer2Peer (domain, flags, dname, duri, bandwidth) < 0)
                goto error;
        } else {
            /* No peer to peer migration supported */
            virLibConnError (domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        if (VIR_DRV_SUPPORTS_FEATURE (domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_DIRECT)) {
            if (virDomainMigrateDirect (domain, flags, dname, duri, bandwidth) < 0)
                goto error;
        } else {
            /* Cannot do a migration with only the perform step */
            virLibConnError (domain->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    }

    return 0;

error:
    virDispatchError(domain->conn);
    return -1;
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
        virDispatchError(NULL);
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
    virDispatchError(dconn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dconn);
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
        virDispatchError(NULL);
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
    virDispatchError(dconn);
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
        virDispatchError(NULL);
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
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel(virConnectPtr conn,
                              virStreamPtr st,
                              unsigned long flags,
                              const char *dname,
                              unsigned long bandwidth,
                              const char *dom_xml)

{
    VIR_DEBUG("conn=%p, stream=%p, flags=%lu, dname=%s, "
              "bandwidth=%lu, dom_xml=%s", conn, st, flags,
              NULLSTR(dname), bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn != st->conn) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel) {
        int rv = conn->driver->domainMigratePrepareTunnel(conn, st,
                                                          flags, dname,
                                                          bandwidth, dom_xml);
        if (rv < 0)
            goto error;
        return rv;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
        return -1;
    }
    if (!path || !stats || size > sizeof stats2) {
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
    virDispatchError(dom->conn);
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
 * Domains may have more than one network interface.  To get stats for
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
        virDispatchError(NULL);
        return -1;
    }
    if (!path || !stats || size > sizeof stats2) {
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
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainMemoryStats:
 * @dom: pointer to the domain object
 * @stats: nr_stats-sized array of stat structures (returned)
 * @nr_stats: number of memory statistics requested
 * @flags: unused, always pass 0
 *
 * This function provides memory statistics for the domain.
 *
 * Up to 'nr_stats' elements of 'stats' will be populated with memory statistics
 * from the domain.  Only statistics supported by the domain, the driver, and
 * this version of libvirt will be returned.
 *
 * Memory Statistics:
 *
 * VIR_DOMAIN_MEMORY_STAT_SWAP_IN:
 *     The total amount of data read from swap space (in kb).
 * VIR_DOMAIN_MEMORY_STAT_SWAP_OUT:
 *     The total amount of memory written out to swap space (in kb).
 * VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT:
 *     The number of page faults that required disk IO to service.
 * VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT:
 *     The number of page faults serviced without disk IO.
 * VIR_DOMAIN_MEMORY_STAT_UNUSED:
 *     The amount of memory which is not being used for any purpose (in kb).
 * VIR_DOMAIN_MEMORY_STAT_AVAILABLE:
 *     The total amount of memory available to the domain's OS (in kb).
 *
 * Returns: The number of stats provided or -1 in case of failure.
 */
int virDomainMemoryStats (virDomainPtr dom, virDomainMemoryStatPtr stats,
                          unsigned int nr_stats, unsigned int flags)
{
    virConnectPtr conn;
    unsigned long nr_stats_ret = 0;
    DEBUG("domain=%p, stats=%p, nr_stats=%u", dom, stats, nr_stats);

    if (flags != 0) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("flags must be zero"));
        goto error;
    }

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (!stats || nr_stats == 0)
        return 0;

    if (nr_stats > VIR_DOMAIN_MEMORY_STAT_NR)
        nr_stats = VIR_DOMAIN_MEMORY_STAT_NR;

    conn = dom->conn;
    if (conn->driver->domainMemoryStats) {
        nr_stats_ret = conn->driver->domainMemoryStats (dom, stats, nr_stats);
        if (nr_stats_ret == -1)
            goto error;
        return nr_stats_ret;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dom->conn);
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
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(dom, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Note on access to physical memory: A VIR_MEMORY_PHYSICAL flag is
     * a possibility.  However it isn't really useful unless the caller
     * can also access registers, particularly CR3 on x86 in order to
     * get the Page Table Directory.  Since registers are different on
     * every architecture, that would imply another call to get the
     * machine registers.
     *
     * The QEMU driver handles VIR_MEMORY_VIRTUAL, mapping it
     * to the qemu 'memsave' command which does the virtual to physical
     * mapping inside qemu.
     *
     * The QEMU driver also handles VIR_MEMORY_PHYSICAL, mapping it
     * to the qemu 'pmemsave' command.
     *
     * At time of writing there is no Xen driver.  However the Xen
     * hypervisor only lets you map physical pages from other domains,
     * and so the Xen driver would have to do the virtual to physical
     * mapping by chasing 2, 3 or 4-level page tables from the PTD.
     * There is example code in libxc (xc_translate_foreign_address)
     * which does this, although we cannot copy this code directly
     * because of incompatible licensing.
     */

    if (flags != VIR_MEMORY_VIRTUAL && flags != VIR_MEMORY_PHYSICAL) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                     _("flags parameter must be VIR_MEMORY_VIRTUAL or VIR_MEMORY_PHYSICAL"));
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
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetBlockInfo:
 * @domain: a domain object
 * @path: path to the block device or file
 * @info: pointer to a virDomainBlockInfo structure allocated by the user
 * @flags: currently unused, pass zero
 *
 * Extract information about a domain's block device.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetBlockInfo(virDomainPtr domain, const char *path, virDomainBlockInfoPtr info, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, info=%p flags=%u", domain, info, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memset(info, 0, sizeof(virDomainBlockInfo));

    conn = domain->conn;

    if (conn->driver->domainGetBlockInfo) {
        int ret;
        ret = conn->driver->domainGetBlockInfo (domain, path, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this
 *      domain (in 8-bit bytes) (OUT)
 *	If cpumaps is NULL, then no cpumap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in
 *      virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *	Must be zero when cpumaps is NULL and positive when it is non-NULL.
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
        virDispatchError(NULL);
        return (-1);
    }
    if ((info == NULL) || (maxinfo < 1)) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /* Ensure that domainGetVcpus (aka remoteDomainGetVcpus) does not
       try to memcpy anything into a NULL pointer.  */
    if ((cpumaps == NULL && maplen != 0)
        || (cpumaps && maplen <= 0)) {
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
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
        virDispatchError(NULL);
        return -1;
    }

    if (seclabel == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetSecurityLabel) {
        int ret;
        ret = conn->driver->domainGetSecurityLabel(domain, seclabel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
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
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (secmodel == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->nodeGetSecurityModel) {
        int ret;
        ret = conn->driver->nodeGetSecurityModel(conn, secmodel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainAttachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * Create a virtual device attachment to backend.  This function,
 * having hotplug semantics, is only allowed on an active domain.
 *
 * For compatibility, this method can also be used to change the media
 * in an existing CDROM/Floppy device, however, applications are
 * recommended to use the virDomainUpdateDeviceFlag method instead.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainAttachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Attach a virtual device to a domain, using the flags parameter
 * to control how the device is attached.  VIR_DOMAIN_DEVICE_MODIFY_CURRENT
 * specifies that the device allocation is made based on current domain
 * state.  VIR_DOMAIN_DEVICE_MODIFY_LIVE specifies that the device shall be
 * allocated to the active domain instance only and is not added to the
 * persisted domain configuration.  VIR_DOMAIN_DEVICE_MODIFY_CONFIG
 * specifies that the device shall be allocated to the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports modifying the
 * persisted device allocation.
 *
 * For compatibility, this method can also be used to change the media
 * in an existing CDROM/Floppy device, however, applications are
 * recommended to use the virDomainUpdateDeviceFlag method instead.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainAttachDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, xml=%s, flags=%d", domain, xml, flags);

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

    if (conn->driver->domainAttachDeviceFlags) {
        int ret;
        ret = conn->driver->domainAttachDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainDetachDevice:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 *
 * Destroy a virtual device attachment to backend.  This function,
 * having hot-unplug semantics, is only allowed on an active domain.
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
        virDispatchError(NULL);
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
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainDetachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Detach a virtual device from a domain, using the flags parameter
 * to control how the device is detached.  VIR_DOMAIN_DEVICE_MODIFY_CURRENT
 * specifies that the device allocation is removed based on current domain
 * state.  VIR_DOMAIN_DEVICE_MODIFY_LIVE specifies that the device shall be
 * deallocated from the active domain instance only and is not from the
 * persisted domain configuration.  VIR_DOMAIN_DEVICE_MODIFY_CONFIG
 * specifies that the device shall be deallocated from the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports removing the
 * persisted device allocation.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDetachDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, xml=%s, flags=%d", domain, xml, flags);

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

    if (conn->driver->domainDetachDeviceFlags) {
        int ret;
        ret = conn->driver->domainDetachDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainUpdateDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: an OR'ed set of virDomainDeviceModifyFlags
 *
 * Change a virtual device on a domain, using the flags parameter
 * to control how the device is changed.  VIR_DOMAIN_DEVICE_MODIFY_CURRENT
 * specifies that the device change is made based on current domain
 * state.  VIR_DOMAIN_DEVICE_MODIFY_LIVE specifies that the device shall be
 * changed on the active domain instance only and is not added to the
 * persisted domain configuration. VIR_DOMAIN_DEVICE_MODIFY_CONFIG
 * specifies that the device shall be changed on the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports modifying the
 * persisted device allocation.
 *
 * This method is used for actions such changing CDROM/Floppy device
 * media, altering the graphics configuration such as password,
 * reconfiguring the NIC device backend connectivity, etc.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainUpdateDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, xml=%s, flags=%d", domain, xml, flags);

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

    if (conn->driver->domainUpdateDeviceFlags) {
        int ret;
        ret = conn->driver->domainUpdateDeviceFlags(domain, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
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
 * with the amount of free memory in bytes for each cell requested,
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
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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

    return virNetworkLookupByUUID(conn, &uuid[0]);

error:
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefNetwork(network) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (uuid == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memcpy(uuid, &network->uuid[0], VIR_UUID_BUFLEN);

    return (0);

error:
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (buf == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virNetworkGetUUID(network, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return (0);

error:
    virDispatchError(network->conn);
    return -1;
}

/**
 * virNetworkGetXMLDesc:
 * @network: a network object
 * @flags: an OR'ed set of extraction flags, not used yet
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(network->conn);
    return -1;
}

/**
 * virInterfaceGetConnect:
 * @iface: pointer to an interface
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
        virDispatchError(NULL);
        return NULL;
    }
    return iface->conn;
}

/**
 * virConnectNumOfInterfaces:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active interfaces on the physical host.
 *
 * Returns the number of active interfaces found or -1 in case of error
 */
int
virConnectNumOfInterfaces(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListInterfaces:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of interfaces
 * @maxnames: size of @names
 *
 * Collect the list of active physical host interfaces,
 * and store their names in @names
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectNumOfDefinedInterfaces:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of defined (inactive) interfaces on the physical host.
 *
 * Returns the number of defined interface found or -1 in case of error
 */
int
virConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (conn->interfaceDriver && conn->interfaceDriver->numOfDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->numOfDefinedInterfaces (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListDefinedInterfaces:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of interfaces
 * @maxnames: size of @names
 *
 * Collect the list of defined (inactive) physical host interfaces,
 * and store their names in @names.
 *
 * Returns the number of interfaces found or -1 in case of error
 */
int
virConnectListDefinedInterfaces(virConnectPtr conn,
                                char **const names,
                                int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->listDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->listDefinedInterfaces (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return NULL;
}

/**
 * virInterfaceGetName:
 * @iface: an interface object
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
        virDispatchError(NULL);
        return (NULL);
    }
    return (iface->name);
}

/**
 * virInterfaceGetMACString:
 * @iface: an interface object
 *
 * Get the MAC for an interface as string. For more information about
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
        virDispatchError(NULL);
        return (NULL);
    }
    return (iface->mac);
}

/**
 * virInterfaceGetXMLDesc:
 * @iface: an interface object
 * @flags: an OR'ed set of extraction flags. Current valid bits:
 *
 *      VIR_INTERFACE_XML_INACTIVE - return the static configuration,
 *                                   suitable for use redefining the
 *                                   interface via virInterfaceDefineXML()
 *
 * Provide an XML description of the interface. If
 * VIR_INTERFACE_XML_INACTIVE is set, the description may be reused
 * later to redefine the interface with virInterfaceDefineXML(). If it
 * is not set, the ip address and netmask will be the current live
 * setting of the interface, not the settings from the config files.
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
        virDispatchError(NULL);
        return (NULL);
    }
    if ((flags & ~VIR_INTERFACE_XML_INACTIVE) != 0) {
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
    virDispatchError(iface->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(iface->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(iface->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(iface->conn);
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
 * it. ie, each new thread using an interface would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virInterfaceRef(virInterfacePtr iface)
{
    if ((!VIR_IS_CONNECTED_INTERFACE(iface))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        virDispatchError(NULL);
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
 * @iface: an interface object
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
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefInterface(iface) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
        return NULL;
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(vol->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolUndefine:
 * @pool: pointer to storage pool
 *
 * Undefine an inactive storage pool
 *
 * Returns 0 on success, -1 on failure
 */
int
virStoragePoolUndefine(virStoragePoolPtr pool)
{
    virConnectPtr conn;
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefStoragePool(pool) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
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
        virDispatchError(NULL);
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
 * Returns 0 if the volume list was refreshed, -1 on failure
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetName:
 * @pool: pointer to storage pool
 *
 * Fetch the locally unique name of the storage pool
 *
 * Returns the name of the pool, or NULL on error
 */
const char*
virStoragePoolGetName(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
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
 * Returns 0 on success, or -1 on error;
 */
int
virStoragePoolGetUUID(virStoragePoolPtr pool,
                      unsigned char *uuid)
{
    DEBUG("pool=%p, uuid=%p", pool, uuid);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (uuid == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memcpy(uuid, &pool->uuid[0], VIR_UUID_BUFLEN);

    return (0);

error:
    virDispatchError(pool->conn);
    return -1;
}

/**
 * virStoragePoolGetUUIDString:
 * @pool: pointer to storage pool
 * @buf: buffer of VIR_UUID_STRING_BUFLEN bytes in size
 *
 * Fetch the globally unique ID of the storage pool as a string
 *
 * Returns 0 on success, or -1 on error;
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
 * Returns 0 on success, or -1 on failure.
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
 * Returns a XML document, or NULL on error
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
 * Returns 0 on success, -1 on failure
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolSetAutostart:
 * @pool: pointer to storage pool
 * @autostart: new flag setting
 *
 * Sets the autostart flag
 *
 * Returns 0 on success, -1 on failure
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
        virDispatchError(NULL);
        return -1;
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
        virDispatchError(NULL);
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
 * Returns a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByName(virStoragePoolPtr pool,
                          const char *name)
{
    DEBUG("pool=%p, name=%s", pool, name);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
 * Returns a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByKey(virConnectPtr conn,
                         const char *key)
{
    DEBUG("conn=%p, key=%s", conn, key);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
 * Returns a storage volume, or NULL if not found / error
 */
virStorageVolPtr
virStorageVolLookupByPath(virConnectPtr conn,
                          const char *path)
{
    DEBUG("conn=%p, path=%s", conn, path);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return NULL;
}


/**
 * virStorageVolGetName:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume name. This is unique
 * within the scope of a pool
 *
 * Returns the volume name, or NULL on error
 */
const char*
virStorageVolGetName(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
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
 * Returns the volume key, or NULL on error
 */
const char*
virStorageVolGetKey(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
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
 * Returns the storage volume, or NULL on error
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
        virDispatchError(NULL);
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
    virDispatchError(pool->conn);
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
 * Returns the storage volume, or NULL on error
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
        virDispatchError(NULL);
        return (NULL);
    }

    if (!VIR_IS_STORAGE_VOL(clonevol)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        goto error;
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
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolDelete:
 * @vol: pointer to storage volume
 * @flags: future flags, use 0 for now
 *
 * Delete the storage volume from the pool
 *
 * Returns 0 on success, or -1 on error
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
        virDispatchError(NULL);
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
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolWipe:
 * @vol: pointer to storage volume
 * @flags: future flags, use 0 for now
 *
 * Ensure data previously on a volume is not accessible to future reads
 *
 * Returns 0 on success, or -1 on error
 */
int
virStorageVolWipe(virStorageVolPtr vol,
                  unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, flags=%u", vol, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(vol, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->volWipe) {
        int ret;
        ret = conn->storageDriver->volWipe(vol, flags);
        if (ret < 0) {
            goto error;
        }
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolFree:
 * @vol: pointer to storage volume
 *
 * Release the storage volume handle. The underlying
 * storage volume continues to exist.
 *
 * Returns 0 on success, or -1 on error
 */
int
virStorageVolFree(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefStorageVol(vol) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
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
        virDispatchError(NULL);
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
 * Returns 0 on success, or -1 on failure
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
        virDispatchError(NULL);
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
    virDispatchError(vol->conn);
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
 * Returns the XML document, or NULL on error
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
        virDispatchError(NULL);
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
    virDispatchError(vol->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(vol->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
 * Returns the XML document, or NULL on error
 */
char *virNodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags)
{
    DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(NULL, VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
        return NULL;
    }

    if (!dev->parent) {
        if (dev->conn->deviceMonitor && dev->conn->deviceMonitor->deviceGetParent) {
            dev->parent = dev->conn->deviceMonitor->deviceGetParent (dev);
        } else {
            virLibConnError (dev->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
            virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
        return (-1);
    }
    if (virUnrefNodeDevice(dev) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
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
        virDispatchError(NULL);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
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
        virDispatchError(NULL);
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
    virDispatchError(dev->conn);
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
 * Adds a callback to receive notifications of domain lifecycle events
 * occurring on a connection
 *
 * Use of this method is no longer recommended. Instead applications
 * should try virConnectDomainEventRegisterAny which has a more flexible
 * API contract
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectDomainEventDeregister:
 * @conn: pointer to the connection
 * @cb: callback to the function handling domain events
 *
 * Removes a callback previously registered with the virConnectDomainEventRegister
 * funtion.
 *
 * Use of this method is no longer recommended. Instead applications
 * should try virConnectDomainEventUnregisterAny which has a more flexible
 * API contract
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
        virDispatchError(NULL);
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
    virDispatchError(conn);
    return -1;
}

/**
 * virSecretGetConnect:
 * @secret: A virSecret secret
 *
 * Provides the connection pointer associated with a secret.  The reference
 * counter on the connection is not increased by this call.
 *
 * WARNING: When writing libvirt bindings in other languages, do not use this
 * function.  Instead, store the connection and the secret object together.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virSecretGetConnect (virSecretPtr secret)
{
    DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET (secret)) {
        virLibSecretError (NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return secret->conn;
}

/**
 * virConnectNumOfSecrets:
 * @conn: virConnect connection
 *
 * Fetch number of currently defined secrets.
 *
 * Returns the number currently defined secrets.
 */
int
virConnectNumOfSecrets(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->secretDriver != NULL &&
        conn->secretDriver->numOfSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->numOfSecrets(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListSecrets:
 * @conn: virConnect connection
 * @uuids: Pointer to an array to store the UUIDs
 * @maxuuids: size of the array.
 *
 * List UUIDs of defined secrets, store pointers to names in uuids.
 *
 * Returns the number of UUIDs provided in the array, or -1 on failure.
 */
int
virConnectListSecrets(virConnectPtr conn, char **uuids, int maxuuids)
{
    VIR_DEBUG("conn=%p, uuids=%p, maxuuids=%d", conn, uuids, maxuuids);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (uuids == NULL || maxuuids < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver != NULL && conn->secretDriver->listSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->listSecrets(conn, uuids, maxuuids);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virSecretLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the secret
 *
 * Try to lookup a secret on the given hypervisor based on its UUID.
 * Uses the 16 bytes of raw data to describe the UUID
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    DEBUG("conn=%p, uuid=%s", conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver &&
        conn->secretDriver->lookupByUUID) {
        virSecretPtr ret;
        ret = conn->secretDriver->lookupByUUID (conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virSecretLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the secret
 *
 * Try to lookup a secret on the given hypervisor based on its UUID.
 * Uses the printable string value to describe the UUID
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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

    return virSecretLookupByUUID(conn, &uuid[0]);

error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretLookupByUsage:
 * @conn: pointer to the hypervisor connection
 * @usageType: the type of secret usage
 * @usageID: identifier of the object using the secret
 *
 * Try to lookup a secret on the given hypervisor based on its usage
 * The usageID is unique within the set of secrets sharing the
 * same usageType value.
 *
 * Returns a new secret object or NULL in case of failure.  If the
 * secret cannot be found, then VIR_ERR_NO_SECRET error is raised.
 */
virSecretPtr
virSecretLookupByUsage(virConnectPtr conn,
                       int usageType,
                       const char *usageID)
{
    DEBUG("conn=%p, usageType=%d usageID=%s", conn, usageType, NULLSTR(usageID));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    if (usageID == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver &&
        conn->secretDriver->lookupByUsage) {
        virSecretPtr ret;
        ret = conn->secretDriver->lookupByUsage (conn, usageType, usageID);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretDefineXML:
 * @conn: virConnect connection
 * @xml: XML describing the secret.
 * @flags: flags, use 0 for now
 *
 * If XML specifies a UUID, locates the specified secret and replaces all
 * attributes of the secret specified by UUID by attributes specified in xml
 * (any attributes not specified in xml are discarded).
 *
 * Otherwise, creates a new secret with an automatically chosen UUID, and
 * initializes its attributes from xml.
 *
 * Returns a the secret on success, NULL on failure.
 */
virSecretPtr
virSecretDefineXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=%u", conn, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver != NULL && conn->secretDriver->defineXML != NULL) {
        virSecretPtr ret;

        ret = conn->secretDriver->defineXML(conn, xml, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virSecretGetUUID:
 * @secret: A virSecret secret
 * @uuid: buffer of VIR_UUID_BUFLEN bytes in size
 *
 * Fetches the UUID of the secret.
 *
 * Returns 0 on success with the uuid buffer being filled, or
 * -1 upon failure.
 */
int
virSecretGetUUID(virSecretPtr secret, unsigned char *uuid)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (uuid == NULL) {
        virLibSecretError(secret, VIR_ERR_INVALID_ARG, __FUNCTION__);
        virDispatchError(secret->conn);
        return -1;
    }

    memcpy(uuid, &secret->uuid[0], VIR_UUID_BUFLEN);

    return 0;
}

/**
 * virSecretGetUUIDString:
 * @secret: a secret object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a secret as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virSecretGetUUIDString(virSecretPtr secret, char *buf)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("secret=%p, buf=%p", secret, buf);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (buf == NULL) {
        virLibSecretError(secret, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virSecretGetUUID(secret, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return (0);

error:
    virDispatchError(secret->conn);
    return -1;
}

/**
 * virSecretGetUsageType:
 * @secret: a secret object
 *
 * Get the type of object which uses this secret. The returned
 * value is one of the constants defined in the virSecretUsageType
 * enumeration. More values may be added to this enumeration in
 * the future, so callers should expect to see usage types they
 * do not explicitly know about.
 *
 * Returns a positive integer identifying the type of object,
 * or -1 upon error.
 */
int
virSecretGetUsageType(virSecretPtr secret)
{
    DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    return (secret->usageType);
}

/**
 * virSecretGetUsageID:
 * @secret: a secret object
 *
 * Get the unique identifier of the object with which this
 * secret is to be used. The format of the identifier is
 * dependant on the usage type of the secret. For a secret
 * with a usage type of VIR_SECRET_USAGE_TYPE_VOLUME the
 * identifier will be a fully qualfied path name. The
 * identifiers are intended to be unique within the set of
 * all secrets sharing the same usage type. ie, there shall
 * only ever be one secret for each volume path.
 *
 * Returns a string identifying the object using the secret,
 * or NULL upon error
 */
const char *
virSecretGetUsageID(virSecretPtr secret)
{
    DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    return (secret->usageID);
}


/**
 * virSecretGetXMLDesc:
 * @secret: A virSecret secret
 * @flags: flags, use 0 for now
 *
 * Fetches an XML document describing attributes of the secret.
 *
 * Returns the XML document on success, NULL on failure.  The caller must
 * free() the XML.
 */
char *
virSecretGetXMLDesc(virSecretPtr secret, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, flags=%u", secret, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = secret->conn;
    if (conn->secretDriver != NULL && conn->secretDriver->getXMLDesc != NULL) {
        char *ret;

        ret = conn->secretDriver->getXMLDesc(secret, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virSecretSetValue:
 * @secret: A virSecret secret
 * @value: Value of the secret
 * @value_size: Size of the value
 * @flags: flags, use 0 for now
 *
 * Sets the value of a secret.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virSecretSetValue(virSecretPtr secret, const unsigned char *value,
                  size_t value_size, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, value=%p, value_size=%zu, flags=%u", secret, value,
              value_size, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(secret, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (value == NULL) {
        virLibSecretError(secret, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver != NULL && conn->secretDriver->setValue != NULL) {
        int ret;

        ret = conn->secretDriver->setValue(secret, value, value_size, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virSecretGetValue:
 * @secret: A virSecret connection
 * @value_size: Place for storing size of the secret value
 * @flags: flags, use 0 for now
 *
 * Fetches the value of a secret.
 *
 * Returns the secret value on success, NULL on failure.  The caller must
 * free() the secret value.
 */
unsigned char *
virSecretGetValue(virSecretPtr secret, size_t *value_size, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p, value_size=%p, flags=%u", secret, value_size, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(secret, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    if (value_size == NULL) {
        virLibSecretError(secret, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    flags &= VIR_SECRET_GET_VALUE_FLAGS_MASK;

    if (conn->secretDriver != NULL && conn->secretDriver->getValue != NULL) {
        unsigned char *ret;

        ret = conn->secretDriver->getValue(secret, value_size, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virSecretUndefine:
 * @secret: A virSecret secret
 *
 * Deletes the specified secret.  This does not free the associated
 * virSecretPtr object.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virSecretUndefine(virSecretPtr secret)
{
    virConnectPtr conn;

    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(secret, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver != NULL && conn->secretDriver->undefine != NULL) {
        int ret;

        ret = conn->secretDriver->undefine(secret);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virSecretRef:
 * @secret: the secret to hold a reference on
 *
 * Increment the reference count on the secret. For each additional call to
 * this method, there shall be a corresponding call to virSecretFree to release
 * the reference count, once the caller no longer needs the reference to this
 * object.
 *
 * This method is typically useful for applications where multiple threads are
 * using a connection, and it is required that the connection remain open until
 * all threads have finished using it. ie, each new thread using a secret would
 * increment the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virSecretRef(virSecretPtr secret)
{
    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virMutexLock(&secret->conn->lock);
    DEBUG("secret=%p refs=%d", secret, secret->refs);
    secret->refs++;
    virMutexUnlock(&secret->conn->lock);
    return 0;
}

/**
 * virSecretFree:
 * @secret: pointer to a secret
 *
 * Release the secret handle. The underlying secret continues to exist.
 *
 * Returns 0 on success, or -1 on error
 */
int
virSecretFree(virSecretPtr secret)
{
    DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(NULL, VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (virUnrefSecret(secret) < 0) {
        virDispatchError(NULL);
        return -1;
    }
    return 0;
}


/**
 * virStreamNew:
 * @conn: pointer to the connection
 * @flags: control features of the stream
 *
 * Creates a new stream object which can be used to perform
 * streamed I/O with other public API function.
 *
 * When no longer needed, a stream object must be released
 * with virStreamFree. If a data stream has been used,
 * then the application must call virStreamFinish or
 * virStreamAbort before free'ing to, in order to notify
 * the driver of termination.
 *
 * If a non-blocking data stream is required passed
 * VIR_STREAM_NONBLOCK for flags, otherwise pass 0.
 *
 * Returns the new stream, or NULL upon error
 */
virStreamPtr
virStreamNew(virConnectPtr conn,
             unsigned int flags)
{
    virStreamPtr st;

    DEBUG("conn=%p, flags=%u", conn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }

    st = virGetStream(conn);
    if (st)
        st->flags = flags;

    return st;
}


/**
 * virStreamRef:
 * @stream: pointer to the stream
 *
 * Increment the reference count on the stream. For each
 * additional call to this method, there shall be a corresponding
 * call to virStreamFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virStreamRef(virStreamPtr stream)
{
    if ((!VIR_IS_CONNECTED_STREAM(stream))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        virDispatchError(NULL);
        return(-1);
    }
    virMutexLock(&stream->conn->lock);
    DEBUG("stream=%p refs=%d", stream, stream->refs);
    stream->refs++;
    virMutexUnlock(&stream->conn->lock);
    return 0;
}


/**
 * virStreamSend:
 * @stream: pointer to the stream object
 * @data: buffer to write to stream
 * @nbytes: size of @data buffer
 *
 * Write a series of bytes to the stream. This method may
 * block the calling application for an arbitrary amount
 * of time. Once an application has finished sending data
 * it should call virStreamFinish to wait for successful
 * confirmation from the driver, or detect any error
 *
 * This method may not be used if a stream source has been
 * registered
 *
 * Errors are not guaranteed to be reported synchronously
 * with the call, but may instead be delayed until a
 * subsequent call.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_RDONLY)
 *
 *   virConnectUploadFile(conn, "demo.iso", st);
 *
 *   while (1) {
 *       char buf[1024];
 *       int got = read(fd, buf, 1024);
 *       if (got < 0) {
 *          virStreamAbort(st);
 *          break;
 *       }
 *       if (got == 0) {
 *          virStreamFinish(st);
 *          break;
 *       }
 *       int offset = 0;
 *       while (offset < got) {
 *          int sent = virStreamSend(st, buf+offset, got-offset)
 *          if (sent < 0) {
 *             virStreamAbort(st);
 *             goto done;
 *          }
 *          offset += sent;
 *       }
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ... report an error ....
 * done:
 *   virStreamFree(st);
 *   close(fd);
 *
 * Returns the number of bytes written, which may be less
 * than requested.
 *
 * Returns -1 upon error, at which time the stream will
 * be marked as aborted, and the caller should now release
 * the stream with virStreamFree.
 *
 * Returns -2 if the outgoing transmit buffers are full &
 * the stream is marked as non-blocking.
 */
int virStreamSend(virStreamPtr stream,
                  const char *data,
                  size_t nbytes)
{
    DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamSend) {
        int ret;
        ret = (stream->driver->streamSend)(stream, data, nbytes);
        if (ret == -2)
            return -2;
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamRecv:
 * @stream: pointer to the stream object
 * @data: buffer to write to stream
 * @nbytes: size of @data buffer
 *
 * Write a series of bytes to the stream. This method may
 * block the calling application for an arbitrary amount
 * of time.
 *
 * Errors are not guaranteed to be reported synchronously
 * with the call, but may instead be delayed until a
 * subsequent call.
 *
 * An example using this with a hypothetical file download
 * API looks like
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_WRONLY, 0600)
 *
 *   virConnectDownloadFile(conn, "demo.iso", st);
 *
 *   while (1) {
 *       char buf[1024];
 *       int got = virStreamRecv(st, buf, 1024);
 *       if (got < 0)
 *          break;
 *       if (got == 0) {
 *          virStreamFinish(st);
 *          break;
 *       }
 *       int offset = 0;
 *       while (offset < got) {
 *          int sent = write(fd, buf+offset, got-offset)
 *          if (sent < 0) {
 *             virStreamAbort(st);
 *             goto done;
 *          }
 *          offset += sent;
 *       }
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ... report an error ....
 * done:
 *   virStreamFree(st);
 *   close(fd);
 *
 *
 * Returns the number of bytes read, which may be less
 * than requested.
 *
 * Returns 0 when the end of the stream is reached, at
 * which time the caller should invoke virStreamFinish()
 * to get confirmation of stream completion.
 *
 * Returns -1 upon error, at which time the stream will
 * be marked as aborted, and the caller should now release
 * the stream with virStreamFree.
 *
 * Returns -2 if there is no data pending to be read & the
 * stream is marked as non-blocking.
 */
int virStreamRecv(virStreamPtr stream,
                  char *data,
                  size_t nbytes)
{
    DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamRecv) {
        int ret;
        ret = (stream->driver->streamRecv)(stream, data, nbytes);
        if (ret == -2)
            return -2;
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamSendAll:
 * @stream: pointer to the stream object
 * @handler: source callback for reading data from application
 * @opaque: application defined data
 *
 * Send the entire data stream, reading the data from the
 * requested data source. This is simply a convenient alternative
 * to virStreamSend, for apps that do blocking-I/o.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *   int mysource(virStreamPtr st, char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return read(*fd, buf, nbytes);
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_RDONLY)
 *
 *   virConnectUploadFile(conn, st);
 *   if (virStreamSendAll(st, mysource, &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Returns 0 if all the data was successfully sent. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called,  so the caller need only call
 * virStreamFree()
 */
int virStreamSendAll(virStreamPtr stream,
                     virStreamSourceFunc handler,
                     void *opaque)
{
    char *bytes = NULL;
    int want = 1024*64;
    int ret = -1;
    DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virLibConnError(NULL, VIR_ERR_OPERATION_INVALID,
                        _("data sources cannot be used for non-blocking streams"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(bytes, want) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (;;) {
        int got, offset = 0;
        got = (handler)(stream, bytes, want, opaque);
        if (got < 0) {
            virStreamAbort(stream);
            goto cleanup;
        }
        if (got == 0)
            break;
        while (offset < got) {
            int done;
            done = virStreamSend(stream, bytes + offset, got - offset);
            if (done < 0)
                goto cleanup;
            offset += done;
        }
    }
    ret = 0;

cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}


/**
 * virStreamRecvAll:
 * @stream: pointer to the stream object
 * @handler: sink callback for writing data to application
 * @opaque: application defined data
 *
 * Receive the entire data stream, sending the data to the
 * requested data sink. This is simply a convenient alternative
 * to virStreamRecv, for apps that do blocking-I/o.
 *
 * An example using this with a hypothetical file download
 * API looks like
 *
 *   int mysink(virStreamPtr st, const char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return write(*fd, buf, nbytes);
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_WRONLY)
 *
 *   virConnectUploadFile(conn, st);
 *   if (virStreamRecvAll(st, mysink, &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Returns 0 if all the data was successfully received. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called,  so the caller need only call
 * virStreamFree()
 */
int virStreamRecvAll(virStreamPtr stream,
                     virStreamSinkFunc handler,
                     void *opaque)
{
    char *bytes = NULL;
    int want = 1024*64;
    int ret = -1;
    DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virLibConnError(NULL, VIR_ERR_OPERATION_INVALID,
                        _("data sinks cannot be used for non-blocking streams"));
        goto cleanup;
    }


    if (VIR_ALLOC_N(bytes, want) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (;;) {
        int got, offset = 0;
        got = virStreamRecv(stream, bytes, want);
        if (got < 0)
            goto cleanup;
        if (got == 0)
            break;
        while (offset < got) {
            int done;
            done = (handler)(stream, bytes + offset, got - offset, opaque);
            if (done < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }
            offset += done;
        }
    }
    ret = 0;

cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}


/**
 * virStreamEventAddCallback:
 * @stream: pointer to the stream object
 * @events: set of events to monitor
 * @cb: callback to invoke when an event occurs
 * @opaque: application defined data
 * @ff: callback to free @opaque data
 *
 * Register a callback to be notified when a stream
 * becomes writable, or readable. This is most commonly
 * used in conjunction with non-blocking data streams
 * to integrate into an event loop
 *
 * Returns 0 on success, -1 upon error
 */
int virStreamEventAddCallback(virStreamPtr stream,
                              int events,
                              virStreamEventCallback cb,
                              void *opaque,
                              virFreeCallback ff)
{
    DEBUG("stream=%p, events=%d, cb=%p, opaque=%p, ff=%p", stream, events, cb, opaque, ff);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamAddCallback) {
        int ret;
        ret = (stream->driver->streamAddCallback)(stream, events, cb, opaque, ff);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamEventUpdateCallback:
 * @stream: pointer to the stream object
 * @events: set of events to monitor
 *
 * Changes the set of events to monitor for a stream. This allows
 * for event notification to be changed without having to
 * unregister & register the callback completely. This method
 * is guarenteed to succeed if a callback is already registered
 *
 * Returns 0 on success, -1 if no callback is registered
 */
int virStreamEventUpdateCallback(virStreamPtr stream,
                                 int events)
{
    DEBUG("stream=%p, events=%d", stream, events);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamUpdateCallback) {
        int ret;
        ret = (stream->driver->streamUpdateCallback)(stream, events);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}

/**
 * virStreamEventRemoveCallback:
 * @stream: pointer to the stream object
 *
 * Remove an event callback from the stream
 *
 * Returns 0 on success, -1 on error
 */
int virStreamEventRemoveCallback(virStreamPtr stream)
{
    DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamRemoveCallback) {
        int ret;
        ret = (stream->driver->streamRemoveCallback)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}

/**
 * virStreamFinish:
 * @stream: pointer to the stream object
 *
 * Indicate that there is no further data is to be transmitted
 * on the stream. For output streams this should be called once
 * all data has been written. For input streams this should be
 * called once virStreamRecv returns end-of-file.
 *
 * This method is a synchronization point for all asynchronous
 * errors, so if this returns a success code the application can
 * be sure that all data has been successfully processed.
 *
 * Returns 0 on success, -1 upon error
 */
int virStreamFinish(virStreamPtr stream)
{
    DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamFinish) {
        int ret;
        ret = (stream->driver->streamFinish)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}

/**
 * virStreamAbort:
 * @stream: pointer to the stream object
 *
 * Request that the in progress data transfer be cancelled
 * abnormally before the end of the stream has been reached.
 * For output streams this can be used to inform the driver
 * that the stream is being terminated early. For input
 * streams this can be used to inform the driver that it
 * should stop sending data.
 *
 * Returns 0 on success, -1 upon error
 */
int virStreamAbort(virStreamPtr stream)
{
    DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    if (stream->driver &&
        stream->driver->streamAbort) {
        int ret;
        ret = (stream->driver->streamAbort)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (stream->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}

/**
 * virStreamFree:
 * @stream: pointer to the stream object
 *
 * Decrement the reference count on a stream, releasing
 * the stream object if the reference count has hit zero.
 *
 * There must not be an active data transfer in progress
 * when releasing the stream. If a stream needs to be
 * disposed of prior to end of stream being reached, then
 * the virStreamAbort function should be called first.
 *
 * Returns 0 upon success, or -1 on error
 */
int virStreamFree(virStreamPtr stream)
{
    DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    /* XXX Enforce shutdown before free'ing resources ? */

    if (virUnrefStream(stream) < 0) {
        virDispatchError(NULL);
        return (-1);
    }
    return (0);
}


/**
 * virDomainIsActive:
 * @dom: pointer to the domain object
 *
 * Determine if the domain is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int virDomainIsActive(virDomainPtr dom)
{
    DEBUG("dom=%p", dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (dom->conn->driver->domainIsActive) {
        int ret;
        ret = dom->conn->driver->domainIsActive(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainIsPersistent:
 * @dom: pointer to the domain object
 *
 * Determine if the domain has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 */
int virDomainIsPersistent(virDomainPtr dom)
{
    DEBUG("dom=%p", dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (dom->conn->driver->domainIsPersistent) {
        int ret;
        ret = dom->conn->driver->domainIsPersistent(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virNetworkIsActive:
 * @net: pointer to the network object
 *
 * Determine if the network is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int virNetworkIsActive(virNetworkPtr net)
{
    DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(net)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (net->conn->networkDriver->networkIsActive) {
        int ret;
        ret = net->conn->networkDriver->networkIsActive(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(net->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(net->conn);
    return -1;
}


/**
 * virNetworkIsPersistent:
 * @net: pointer to the network object
 *
 * Determine if the network has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 */
int virNetworkIsPersistent(virNetworkPtr net)
{
    DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(net)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (net->conn->networkDriver->networkIsPersistent) {
        int ret;
        ret = net->conn->networkDriver->networkIsPersistent(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(net->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(net->conn);
    return -1;
}


/**
 * virStoragePoolIsActive:
 * @pool: pointer to the storage pool object
 *
 * Determine if the storage pool is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int virStoragePoolIsActive(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (pool->conn->storageDriver->poolIsActive) {
        int ret;
        ret = pool->conn->storageDriver->poolIsActive(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolIsPersistent:
 * @pool: pointer to the storage pool object
 *
 * Determine if the storage pool has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 */
int virStoragePoolIsPersistent(virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (pool->conn->storageDriver->poolIsPersistent) {
        int ret;
        ret = pool->conn->storageDriver->poolIsPersistent(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(pool->conn);
    return -1;
}



/**
 * virConnectNumOfNWFilters:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of nwfilters.
 *
 * Returns the number of nwfilters found or -1 in case of error
 */
int
virConnectNumOfNWFilters(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->numOfNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->numOfNWFilters (conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectListNWFilters:
 * @conn: pointer to the hypervisor connection
 * @names: array to collect the list of names of network filters
 * @maxnames: size of @names
 *
 * Collect the list of network filters, and store their names in @names
 *
 * Returns the number of network filters found or -1 in case of error
 */
int
virConnectListNWFilters(virConnectPtr conn, char **const names, int maxnames)
{
    DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->listNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->listNWFilters (conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNWFilterLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the network filter
 *
 * Try to lookup a network filter on the given hypervisor based on its name.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * network filter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 */
virNWFilterPtr
virNWFilterLookupByName(virConnectPtr conn, const char *name)
{
    DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto  error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByName) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByName (conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virNWFilterLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the network filter
 *
 * Try to lookup a network filter on the given hypervisor based on its UUID.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * nwfdilter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 */
virNWFilterPtr
virNWFilterLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    DEBUG("conn=%p, uuid=%s", conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByUUID){
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByUUID (conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virNWFilterLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the nwfilter
 *
 * Try to lookup an nwfilter on the given hypervisor based on its UUID.
 *
 * Returns a new nwfilter object or NULL in case of failure.  If the
 * nwfilter cannot be found, then VIR_ERR_NO_NWFILTER error is raised.
 */
virNWFilterPtr
virNWFilterLookupByUUIDString(virConnectPtr conn, const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("conn=%p, uuidstr=%s", conn, uuidstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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

    return virNWFilterLookupByUUID(conn, &uuid[0]);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virNWFilterFree:
 * @nwfilter: a nwfilter object
 *
 * Free the nwfilter object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNWFilterFree(virNWFilterPtr nwfilter)
{
    DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (virUnrefNWFilter(nwfilter) < 0) {
        virDispatchError(NULL);
        return -1;
    }
    return 0;
}

/**
 * virNWFilterGetName:
 * @nwfilter: a nwfilter object
 *
 * Get the public name for the network filter
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the nwfilter object.
 */
const char *
virNWFilterGetName(virNWFilterPtr nwfilter)
{
    DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    return (nwfilter->name);
}

/**
 * virNWFilterGetUUID:
 * @nwfilter: a nwfilter object
 * @uuid: pointer to a VIR_UUID_BUFLEN bytes array
 *
 * Get the UUID for a network filter
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNWFilterGetUUID(virNWFilterPtr nwfilter, unsigned char *uuid)
{
    DEBUG("nwfilter=%p, uuid=%p", nwfilter, uuid);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (uuid == NULL) {
        virLibNWFilterError(nwfilter, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memcpy(uuid, &nwfilter->uuid[0], VIR_UUID_BUFLEN);

    return 0;

error:
    virDispatchError(nwfilter->conn);
    return -1;
}

/**
 * virNWFilterGetUUIDString:
 * @nwfilter: a nwfilter object
 * @buf: pointer to a VIR_UUID_STRING_BUFLEN bytes array
 *
 * Get the UUID for a network filter as string. For more information about
 * UUID see RFC4122.
 *
 * Returns -1 in case of error, 0 in case of success
 */
int
virNWFilterGetUUIDString(virNWFilterPtr nwfilter, char *buf)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    DEBUG("nwfilter=%p, buf=%p", nwfilter, buf);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (buf == NULL) {
        virLibNWFilterError(nwfilter, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (virNWFilterGetUUID(nwfilter, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return 0;

error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the nwfilter
 *
 * Define a new network filter, based on an XML description
 * similar to the one returned by virNWFilterGetXMLDesc()
 *
 * Returns a new nwfilter object or NULL in case of failure
 */
virNWFilterPtr
virNWFilterDefineXML(virConnectPtr conn, const char *xmlDesc)
{
    DEBUG("conn=%p, xmlDesc=%s", conn, xmlDesc);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
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

    if (conn->nwfilterDriver && conn->nwfilterDriver->defineXML) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->defineXML (conn, xmlDesc, 0);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNWFilterUndefine:
 * @nwfilter: a nwfilter object
 *
 * Undefine the nwfilter object. This call will not succeed if
 * a running VM is referencing the filter. This does not free the
 * associated virNWFilterPtr object.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNWFilterUndefine(virNWFilterPtr nwfilter)
{
    virConnectPtr conn;
    DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = nwfilter->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNWFilterError(nwfilter, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->undefine) {
        int ret;
        ret = conn->nwfilterDriver->undefine (nwfilter);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterGetXMLDesc:
 * @nwfilter: a nwfilter object
 * @flags: an OR'ed set of extraction flags, not used yet
 *
 * Provide an XML description of the network filter. The description may be
 * reused later to redefine the network filter with virNWFilterCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNWFilterGetXMLDesc(virNWFilterPtr nwfilter, int flags)
{
    virConnectPtr conn;
    DEBUG("nwfilter=%p, flags=%d", nwfilter, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(NULL, VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }
    if (flags != 0) {
        virLibNWFilterError(nwfilter, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = nwfilter->conn;

    if (conn->nwfilterDriver && conn->nwfilterDriver->getXMLDesc) {
        char *ret;
        ret = conn->nwfilterDriver->getXMLDesc (nwfilter, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(nwfilter->conn);
    return NULL;
}


/**
 * virNWFilterRef:
 * @nwfilter: the nwfilter to hold a reference on
 *
 * Increment the reference count on the nwfilter. For each
 * additional call to this method, there shall be a corresponding
 * call to virNWFilterFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using an nwfilter would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNWFilterRef(virNWFilterPtr nwfilter)
{
    if ((!VIR_IS_CONNECTED_NWFILTER(nwfilter))) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virMutexLock(&nwfilter->conn->lock);
    DEBUG("nwfilter=%p refs=%d", nwfilter, nwfilter->refs);
    nwfilter->refs++;
    virMutexUnlock(&nwfilter->conn->lock);
    return 0;
}


/**
 * virInterfaceIsActive:
 * @iface: pointer to the interface object
 *
 * Determine if the interface is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 */
int virInterfaceIsActive(virInterfacePtr iface)
{
    DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (iface->conn->interfaceDriver->interfaceIsActive) {
        int ret;
        ret = iface->conn->interfaceDriver->interfaceIsActive(iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(iface->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(iface->conn);
    return -1;
}


/**
 * virConnectIsEncrypted:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is encrypted
 *
 * Returns 1 if encrypted, 0 if not encrypted, -1 on error
 */
int virConnectIsEncrypted(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (conn->driver->isEncrypted) {
        int ret;
        ret = conn->driver->isEncrypted(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectIsSecure:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is secure
 *
 * A connection will be classed as secure if it is either
 * encrypted, or running over a channel which is not exposed
 * to eavesdropping (eg a UNIX domain socket, or pipe)
 *
 * Returns 1 if secure, 0 if secure, -1 on error
 */
int virConnectIsSecure(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (conn->driver->isSecure) {
        int ret;
        ret = conn->driver->isSecure(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectCompareCPU:
 * @conn: virConnect connection
 * @xmlDesc: XML describing the CPU to compare with host CPU
 * @flags: currently unused, pass 0
 *
 * Compares the given CPU description with the host CPU
 *
 * Returns comparison result according to enum virCPUCompareResult
 */
int
virConnectCompareCPU(virConnectPtr conn,
                     const char *xmlDesc,
                     unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%u", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return VIR_CPU_COMPARE_ERROR;
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->cpuCompare) {
        int ret;

        ret = conn->driver->cpuCompare(conn, xmlDesc, flags);
        if (ret == VIR_CPU_COMPARE_ERROR)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return VIR_CPU_COMPARE_ERROR;
}


/**
 * virConnectBaselineCPU:
 *
 * @conn: virConnect connection
 * @xmlCPUs: array of XML descriptions of host CPUs
 * @ncpus: number of CPUs in xmlCPUs
 * @flags: fine-tuning flags, currently unused, pass 0.
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * host CPUs.
 *
 * Returns XML description of the computed CPU or NULL on error.
 */
char *
virConnectBaselineCPU(virConnectPtr conn,
                      const char **xmlCPUs,
                      unsigned int ncpus,
                      unsigned int flags)
{
    unsigned int i;

    VIR_DEBUG("conn=%p, xmlCPUs=%p, ncpus=%u, flags=%u",
              conn, xmlCPUs, ncpus, flags);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%u]=%s", i, NULLSTR(xmlCPUs[i]));
    }

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (xmlCPUs == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->cpuBaseline) {
        char *cpu;

        cpu = conn->driver->cpuBaseline(conn, xmlCPUs, ncpus, flags);
        if (!cpu)
            goto error;
        return cpu;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virDomainGetJobInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainJobInfo structure allocated by the user
 *
 * Extract information about progress of a background job on a domain.
 * Will return an error if the domain is not active.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetJobInfo(virDomainPtr domain, virDomainJobInfoPtr info)
{
    virConnectPtr conn;
    DEBUG("domain=%p, info=%p", domain, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    memset(info, 0, sizeof(virDomainJobInfo));

    conn = domain->conn;

    if (conn->driver->domainGetJobInfo) {
        int ret;
        ret = conn->driver->domainGetJobInfo (domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainAbortJob:
 * @domain: a domain object
 *
 * Requests that the current background job be aborted at the
 * soonest opportunity. This will block until the job has
 * either completed, or aborted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainAbortJob(virDomainPtr domain)
{
    virConnectPtr conn;

    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainAbortJob) {
        int ret;
        ret = conn->driver->domainAbortJob(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateSetMaxDowntime:
 * @domain: a domain object
 * @downtime: maximum tolerable downtime for live migration, in milliseconds
 * @flags: fine-tuning flags, currently unused, use 0
 *
 * Sets maximum tolerable time for which the domain is allowed to be paused
 * at the end of live migration. It's supposed to be called while the domain is
 * being live-migrated as a reaction to migration progress.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetMaxDowntime(virDomainPtr domain,
                               unsigned long long downtime,
                               unsigned int flags)
{
    virConnectPtr conn;

    DEBUG("domain=%p, downtime=%llu, flags=%u", domain, downtime, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateSetMaxDowntime) {
        if (conn->driver->domainMigrateSetMaxDowntime(domain, downtime, flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectDomainEventRegisterAny:
 * @conn: pointer to the connection
 * @dom: pointer to the domain
 * @eventID: the event type to receive
 * @cb: callback to the function handling domain events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary domain events
 * occurring on a domain.
 *
 * If dom is NULL, then events will be monitored for any domain. If dom
 * is non-NULL, then only the specific domain will be monitored
 *
 * Most types of event have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus neccessary to use
 * the VIR_DOMAIN_EVENT_CALLBACK() macro to cast the supplied function pointer
 * to match the signature of this method.
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback
 * returns, it shall take a reference to it, by calling virDomainRef.
 * The reference can be released once the object is no longer required
 * by calling virDomainFree.
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virDomainEventUnregisterAny method
 *
 * Returns a callback identifier on success, -1 on failure
 */
int
virConnectDomainEventRegisterAny(virConnectPtr conn,
                                 virDomainPtr dom,
                                 int eventID,
                                 virConnectDomainEventGenericCallback cb,
                                 void *opaque,
                                 virFreeCallback freecb)
{
    DEBUG("conn=%p dom=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p", conn, dom, eventID, cb, opaque, freecb);
    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (dom != NULL &&
        !(VIR_IS_CONNECTED_DOMAIN(dom) && dom->conn == conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(conn);
        return (-1);
    }
    if (eventID < 0 || eventID >= VIR_DOMAIN_EVENT_ID_LAST || cb == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if ((conn->driver) && (conn->driver->domainEventRegisterAny)) {
        int ret;
        ret = conn->driver->domainEventRegisterAny(conn, dom, eventID, cb, opaque, freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectDomainEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * vaule obtained from a previous virDomainEventRegisterAny method.
 *
 * Returns 0 on success, -1 on failure
 */
int
virConnectDomainEventDeregisterAny(virConnectPtr conn,
                                   int callbackID)
{
    DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return (-1);
    }
    if (callbackID < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    if ((conn->driver) && (conn->driver->domainEventDeregisterAny)) {
        int ret;
        ret = conn->driver->domainEventDeregisterAny(conn, callbackID);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainManagedSave:
 * @dom: pointer to the domain
 * @flags: optional flags currently unused
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore.
 * The difference from virDomainSave() is that libvirt is keeping track of
 * the saved state itself, and will reuse it once the domain is being
 * restarted (automatically or via an explicit libvirt call).
 * As a result any running domain is sure to not have a managed saved image.
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int virDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("dom=%p, flags=%u", dom, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(dom, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainManagedSave) {
        int ret;

        ret = conn->driver->domainManagedSave(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainHasManagedSaveImage:
 * @dom: pointer to the domain
 * @flags: optional flags currently unused
 *
 * Check if a domain has a managed save image as created by
 * virDomainManagedSave(). Note that any running domain should not have
 * such an image, as it should have been removed on restart.
 *
 * Returns 0 if no image is present, 1 if an image is present, and
 *         -1 in case of error
 */
int virDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("dom=%p, flags=%u", dom, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;

    if (conn->driver->domainHasManagedSaveImage) {
        int ret;

        ret = conn->driver->domainHasManagedSaveImage(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainManagedSaveRemove:
 * @dom: pointer to the domain
 * @flags: optional flags currently unused
 *
 * Remove any managed save image for this domain.
 *
 * Returns 0 in case of success, and -1 in case of error
 */
int virDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("dom=%p, flags=%u", dom, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(dom, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainManagedSaveRemove) {
        int ret;

        ret = conn->driver->domainManagedSaveRemove(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotCreateXML:
 * @domain: a domain object
 * @xmlDesc: string containing an XML description of the domain
 * @flags: unused flag parameters; callers should pass 0
 *
 * Creates a new snapshot of a domain based on the snapshot xml
 * contained in xmlDesc.
 *
 * Returns an (opaque) virDomainSnapshotPtr on success, NULL on failure.
 */
virDomainSnapshotPtr
virDomainSnapshotCreateXML(virDomainPtr domain,
                           const char *xmlDesc,
                           unsigned int flags)
{
    virConnectPtr conn;

    DEBUG("domain=%p, xmlDesc=%s, flags=%u", domain, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSnapshotCreateXML) {
        virDomainSnapshotPtr ret;
        ret = conn->driver->domainSnapshotCreateXML(domain, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotGetXMLDesc:
 * @snapshot: a domain snapshot object
 * @flags: unused flag parameters; callers should pass 0
 *
 * Provide an XML description of the domain snapshot.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("snapshot=%p, flags=%d", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(NULL, VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }

    conn = snapshot->domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED,
                        _("virDomainSnapshotGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainSnapshotDumpXML) {
        char *ret;
        ret = conn->driver->domainSnapshotDumpXML(snapshot, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotNum:
 * @domain: a domain object
 * @flags: unused flag parameters; callers should pass 0
 *
 * Provides the number of domain snapshots for this domain..
 *
 * Returns the number of domain snapshost found or -1 in case of error.
 */
int
virDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->driver->domainSnapshotNum) {
        int ret = conn->driver->domainSnapshotNum(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotListNames:
 * @domain: a domain object
 * @names: array to collect the list of names of snapshots
 * @nameslen: size of @names
 * @flags: unused flag parameters; callers should pass 0
 *
 * Collect the list of domain snapshots for the given domain, and store
 * their names in @names.  Caller is responsible for freeing each member
 * of the array.
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 */
int
virDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                           unsigned int flags)
{
    virConnectPtr conn;

    DEBUG("domain=%p, names=%p, nameslen=%d, flags=%u",
          domain, names, nameslen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if ((names == NULL) || (nameslen < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSnapshotListNames) {
        int ret = conn->driver->domainSnapshotListNames(domain, names,
                                                        nameslen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotLookupByName:
 * @domain: a domain object
 * @name: name for the domain snapshot
 * @flags: unused flag parameters; callers should pass 0
 *
 * Try to lookup a domain snapshot based on its name.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * domain snapshot cannot be found, then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 */
virDomainSnapshotPtr
virDomainSnapshotLookupByName(virDomainPtr domain,
                              const char *name,
                              unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, name=%s, flags=%u", domain, name, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }

    conn = domain->conn;

    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSnapshotLookupByName) {
        virDomainSnapshotPtr dom;
        dom = conn->driver->domainSnapshotLookupByName(domain, name, flags);
        if (!dom)
            goto error;
        return dom;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainHasCurrentSnapshot:
 * @domain: pointer to the domain object
 * @flags: unused flag parameters; callers should pass 0
 *
 * Determine if the domain has a current snapshot.
 *
 * Returns 1 if such snapshot exists, 0 if it doesn't, -1 on error.
 */
int
virDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, flags=%u", domain, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if (conn->driver->domainHasCurrentSnapshot) {
        int ret = conn->driver->domainHasCurrentSnapshot(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotCurrent:
 * @domain: a domain object
 * @flags: unused flag parameters; callers should pass 0
 *
 * Get the current snapshot for a domain, if any.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * current domain snapshot cannot be found, then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 */
virDomainSnapshotPtr
virDomainSnapshotCurrent(virDomainPtr domain,
                         unsigned int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, flags=%u", domain, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (NULL);
    }

    conn = domain->conn;

    if (conn->driver->domainSnapshotCurrent) {
        virDomainSnapshotPtr snap;
        snap = conn->driver->domainSnapshotCurrent(domain, flags);
        if (!snap)
            goto error;
        return snap;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainRevertToSnapshot:
 * @snapshot: a domain snapshot object
 * @flags: unused flag parameters; callers should pass 0
 *
 * Revert the domain to a given snapshot.
 *
 * Returns 0 if the creation is successful, -1 on error.
 */
int
virDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                          unsigned int flags)
{
    virConnectPtr conn;

    DEBUG("snapshot=%p, flags=%u", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(NULL, VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainRevertToSnapshot) {
        int ret = conn->driver->domainRevertToSnapshot(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotDelete:
 * @snapshot: a domain snapshot object
 * @flags: flag parameters
 *
 * Delete the snapshot.
 *
 * If @flags is 0, then just this snapshot is deleted, and changes from
 * this snapshot are automatically merged into children snapshots.  If
 * flags is VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN, then this snapshot
 * and any children snapshots are deleted.
 *
 * Returns 0 if the snapshot was successfully deleted, -1 on error.
 */
int
virDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                        unsigned int flags)
{
    virConnectPtr conn;

    DEBUG("snapshot=%p, flags=%u", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(NULL, VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotDelete) {
        int ret = conn->driver->domainSnapshotDelete(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotFree:
 * @snapshot: a domain snapshot object
 *
 * Free the domain snapshot object.  The snapshot itself is not modified.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSnapshotFree(virDomainSnapshotPtr snapshot)
{
    DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(NULL, VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (virUnrefDomainSnapshot(snapshot) < 0) {
        virDispatchError(NULL);
        return -1;
    }
    return 0;
}
