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
#include <sys/wait.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include "getpass.h"

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif

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
#if WITH_GNUTLS
# if WITH_GNUTLS_GCRYPT
#  include <gcrypt.h>
# endif
# include "rpc/virnettlscontext.h"
#endif
#include "vircommand.h"
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
#ifdef WITH_PHYP
# include "phyp/phyp_driver.h"
#endif
#ifdef WITH_ESX
# include "esx/esx_driver.h"
#endif
#ifdef WITH_HYPERV
# include "hyperv/hyperv_driver.h"
#endif
#ifdef WITH_XENAPI
# include "xenapi/xenapi_driver.h"
#endif
#ifdef WITH_VZ
# include "vz/vz_driver.h"
#endif
#ifdef WITH_BHYVE
# include "bhyve/bhyve_driver.h"
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("libvirt");

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to guarantee coherent pointer state ?
 */

#define MAX_DRIVERS 21

static virConnectDriverPtr virConnectDriverTab[MAX_DRIVERS];
static int virConnectDriverTabCount;
static virStateDriverPtr virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount;

static virNetworkDriverPtr virSharedNetworkDriver;
static virInterfaceDriverPtr virSharedInterfaceDriver;
static virStorageDriverPtr virSharedStorageDriver;
static virNodeDeviceDriverPtr virSharedNodeDeviceDriver;
static virSecretDriverPtr virSharedSecretDriver;
static virNWFilterDriverPtr virSharedNWFilterDriver;


#if defined(POLKIT_AUTH)
static int
virConnectAuthGainPolkit(const char *privilege)
{
    virCommandPtr cmd;
    int ret = -1;

    if (geteuid() == 0)
        return 0;

    cmd = virCommandNewArgList(POLKIT_AUTH, "--obtain", privilege, NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}
#endif


static int
virConnectAuthCallbackDefault(virConnectCredentialPtr cred,
                              unsigned int ncred,
                              void *cbdata ATTRIBUTE_UNUSED)
{
    size_t i;

    for (i = 0; i < ncred; i++) {
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
            if (VIR_STRDUP(cred[i].result,
                           STREQ(bufptr, "") && cred[i].defresult ?
                           cred[i].defresult : bufptr) < 0)
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
winsock_init(void)
{
    WORD winsock_version, err;
    WSADATA winsock_data;

    /* http://msdn2.microsoft.com/en-us/library/ms742213.aspx */
    winsock_version = MAKEWORD (2, 2);
    err = WSAStartup (winsock_version, &winsock_data);
    return err == 0 ? 0 : -1;
}
#endif


#ifdef WITH_GNUTLS_GCRYPT
static int
virTLSMutexInit(void **priv)
{
    virMutexPtr lock = NULL;

    if (VIR_ALLOC_QUIET(lock) < 0)
        return ENOMEM;

    if (virMutexInit(lock) < 0) {
        VIR_FREE(lock);
        return errno;
    }

    *priv = lock;
    return 0;
}


static int
virTLSMutexDestroy(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexDestroy(lock);
    VIR_FREE(lock);
    return 0;
}


static int
virTLSMutexLock(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexLock(lock);
    return 0;
}


static int
virTLSMutexUnlock(void **priv)
{
    virMutexPtr lock = *priv;
    virMutexUnlock(lock);
    return 0;
}


static struct gcry_thread_cbs virTLSThreadImpl = {
    /* GCRY_THREAD_OPTION_VERSION was added in gcrypt 1.4.2 */
# ifdef GCRY_THREAD_OPTION_VERSION
    (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)),
# else
    GCRY_THREAD_OPTION_PTHREAD,
# endif
    NULL,
    virTLSMutexInit,
    virTLSMutexDestroy,
    virTLSMutexLock,
    virTLSMutexUnlock,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
#endif /* WITH_GNUTLS_GCRYPT */


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
    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0)
        goto error;

#ifndef LIBVIRT_SETUID_RPC_CLIENT
    if (virIsSUID()) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libvirt.so is not safe to use from setuid programs"));
        goto error;
    }
#endif

#ifdef WITH_GNUTLS_GCRYPT
    /*
     * This sequence of API calls it copied exactly from
     * gnutls 2.12.23 source lib/gcrypt/init.c, with
     * exception that GCRYCTL_ENABLE_QUICK_RANDOM, is
     * dropped
     */
    if (gcry_control(GCRYCTL_ANY_INITIALIZATION_P) == 0) {
        gcry_control(GCRYCTL_SET_THREAD_CBS, &virTLSThreadImpl);
        gcry_check_version(NULL);

        gcry_control(GCRYCTL_DISABLE_SECMEM, NULL, 0);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
    }
#endif

    virLogSetFromEnv();

#ifdef WITH_GNUTLS
    virNetTLSInit();
#endif

#if WITH_CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    VIR_DEBUG("register drivers");

#if HAVE_WINSOCK2_H
    if (winsock_init() == -1)
        goto error;
#endif

    if (!bindtextdomain(PACKAGE, LOCALEDIR))
        goto error;

    /*
     * Note we must avoid everything except 'remote' driver
     * for virt-login-shell usage
     */
#ifndef LIBVIRT_SETUID_RPC_CLIENT
    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virConnectOpen.
     */
# ifdef WITH_TEST
    if (testRegister() == -1)
        goto error;
# endif
# ifdef WITH_OPENVZ
    if (openvzRegister() == -1)
        goto error;
# endif
# ifdef WITH_VMWARE
    if (vmwareRegister() == -1)
        goto error;
# endif
# ifdef WITH_PHYP
    if (phypRegister() == -1)
        goto error;
# endif
# ifdef WITH_ESX
    if (esxRegister() == -1)
        goto error;
# endif
# ifdef WITH_HYPERV
    if (hypervRegister() == -1)
        goto error;
# endif
# ifdef WITH_XENAPI
    if (xenapiRegister() == -1)
        goto error;
# endif
# ifdef WITH_VZ
    if (vzRegister() == -1)
        goto error;
# endif
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
 */
int
virInitialize(void)
{
    if (virOnce(&virGlobalOnce, virGlobalInit) < 0)
        return -1;

    if (virGlobalError)
        return -1;
    return 0;
}


#ifdef WIN32
BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID ignore);

BOOL WINAPI
DllMain(HINSTANCE instance ATTRIBUTE_UNUSED,
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
 * virSetSharedNetworkDriver:
 * @driver: pointer to a network driver block
 *
 * Register a network virtualization driver
 *
 * Returns 0 on success, or -1 in case of error.
 */
int
virSetSharedNetworkDriver(virNetworkDriverPtr driver)
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
virSetSharedInterfaceDriver(virInterfaceDriverPtr driver)
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
virSetSharedStorageDriver(virStorageDriverPtr driver)
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
virSetSharedNodeDeviceDriver(virNodeDeviceDriverPtr driver)
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
virSetSharedSecretDriver(virSecretDriverPtr driver)
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
virSetSharedNWFilterDriver(virNWFilterDriverPtr driver)
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
virRegisterConnectDriver(virConnectDriverPtr driver,
                         bool setSharedDrivers)
{
    VIR_DEBUG("driver=%p name=%s", driver,
              driver ? NULLSTR(driver->hypervisorDriver->name) : "(null)");

    virCheckNonNullArgReturn(driver, -1);
    if (virConnectDriverTabCount >= MAX_DRIVERS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register %s"),
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
    virCheckNonNullArgReturn(driver, -1);

    if (virStateDriverTabCount >= MAX_DRIVERS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many drivers, cannot register %s"),
                       driver->name);
        return -1;
    }

    virStateDriverTab[virStateDriverTabCount] = driver;
    return virStateDriverTabCount++;
}


/**
 * virStateInitialize:
 * @privileged: set to true if running with root privilege, false otherwise
 * @callback: callback to invoke to inhibit shutdown of the daemon
 * @opaque: data to pass to @callback
 *
 * Initialize all virtualization drivers. Accomplished in two phases,
 * the first being state and structure initialization followed by any
 * auto start supported by the driver.  This is done to ensure dependencies
 * that some drivers may have on another driver having been initialized
 * will exist, such as the storage driver's need to use the secret driver.
 *
 * Returns 0 if all succeed, -1 upon any failure.
 */
int
virStateInitialize(bool privileged,
                   virStateInhibitCallback callback,
                   void *opaque)
{
    size_t i;

    if (virInitialize() < 0)
        return -1;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateInitialize) {
            VIR_DEBUG("Running global init for %s state driver",
                      virStateDriverTab[i]->name);
            if (virStateDriverTab[i]->stateInitialize(privileged,
                                                      callback,
                                                      opaque) < 0) {
                virErrorPtr err = virGetLastError();
                VIR_ERROR(_("Initialization of %s state driver failed: %s"),
                          virStateDriverTab[i]->name,
                          err && err->message ? err->message : _("Unknown problem"));
                return -1;
            }
        }
    }

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateAutoStart) {
            VIR_DEBUG("Running global auto start for %s state driver",
                      virStateDriverTab[i]->name);
            virStateDriverTab[i]->stateAutoStart();
        }
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
    size_t i;
    int ret = 0;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateCleanup &&
            virStateDriverTab[i]->stateCleanup() < 0)
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
 */
int
virGetVersion(unsigned long *libVer, const char *type ATTRIBUTE_UNUSED,
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


static char *
virConnectGetConfigFilePath(void)
{
    char *path;
    if (geteuid() == 0) {
        if (virAsprintf(&path, "%s/libvirt/libvirt.conf",
                        SYSCONFDIR) < 0)
            return NULL;
    } else {
        char *userdir = virGetUserConfigDirectory();
        if (!userdir)
            return NULL;

        if (virAsprintf(&path, "%s/libvirt.conf",
                        userdir) < 0) {
            VIR_FREE(userdir);
            return NULL;
        }
        VIR_FREE(userdir);
    }

    return path;
}


static int
virConnectGetConfigFile(virConfPtr *conf)
{
    char *filename = NULL;
    int ret = -1;

    *conf = NULL;

    if (!(filename = virConnectGetConfigFilePath()))
        goto cleanup;

    if (!virFileExists(filename)) {
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Loading config file '%s'", filename);
    if (!(*conf = virConfReadFile(filename, 0)))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(filename);
    return ret;
}

#define URI_ALIAS_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


static int
virConnectOpenFindURIAliasMatch(virConfValuePtr value, const char *alias,
                                char **uri)
{
    virConfValuePtr entry;
    size_t alias_len;

    if (value->type != VIR_CONF_LIST) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Expected a list for 'uri_aliases' config parameter"));
        return -1;
    }

    entry = value->list;
    alias_len = strlen(alias);
    while (entry) {
        char *offset;
        size_t safe;

        if (entry->type != VIR_CONF_STRING) {
            virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                           _("Expected a string for 'uri_aliases' config parameter list entry"));
            return -1;
        }

        if (!(offset = strchr(entry->str, '='))) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Malformed 'uri_aliases' config entry '%s', expected 'alias=uri://host/path'"),
                            entry->str);
            return -1;
        }

        safe  = strspn(entry->str, URI_ALIAS_CHARS);
        if (safe < (offset - entry->str)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Malformed 'uri_aliases' config entry '%s', aliases may only contain 'a-Z, 0-9, _, -'"),
                            entry->str);
            return -1;
        }

        if (alias_len == (offset - entry->str) &&
            STREQLEN(entry->str, alias, alias_len)) {
            VIR_DEBUG("Resolved alias '%s' to '%s'",
                      alias, offset+1);
            return VIR_STRDUP(*uri, offset+1);
        }

        entry = entry->next;
    }

    VIR_DEBUG("No alias found for '%s', passing through to drivers",
              alias);
    return 0;
}


static int
virConnectOpenResolveURIAlias(virConfPtr conf,
                              const char *alias, char **uri)
{
    int ret = -1;
    virConfValuePtr value = NULL;

    *uri = NULL;

    if ((value = virConfGetValue(conf, "uri_aliases")))
        ret = virConnectOpenFindURIAliasMatch(value, alias, uri);
    else
        ret = 0;

    return ret;
}


static int
virConnectGetDefaultURI(virConfPtr conf,
                        const char **name)
{
    int ret = -1;
    virConfValuePtr value = NULL;
    const char *defname = virGetEnvBlockSUID("LIBVIRT_DEFAULT_URI");
    if (defname && *defname) {
        VIR_DEBUG("Using LIBVIRT_DEFAULT_URI '%s'", defname);
        *name = defname;
    } else if ((value = virConfGetValue(conf, "uri_default"))) {
        if (value->type != VIR_CONF_STRING) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Expected a string for 'uri_default' config parameter"));
            goto cleanup;
        }
        VIR_DEBUG("Using config file uri '%s'", value->str);
        *name = value->str;
    }

    ret = 0;
 cleanup:
    return ret;
}


static virConnectPtr
do_open(const char *name,
        virConnectAuthPtr auth,
        unsigned int flags)
{
    size_t i;
    int res;
    virConnectPtr ret;
    virConfPtr conf = NULL;

    ret = virGetConnect();
    if (ret == NULL)
        return NULL;

    if (virConnectGetConfigFile(&conf) < 0)
        goto failed;

    if (name && name[0] == '\0')
        name = NULL;

    if (!name && virIsSUID()) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("An explicit URI must be provided when setuid"));
        goto failed;
    }

    /*
     * If no URI is passed, then check for an environment string if not
     * available probe the compiled in drivers to find a default hypervisor
     * if detectable.
     */
    if (!name &&
        virConnectGetDefaultURI(conf, &name) < 0)
        goto failed;

    if (name) {
        char *alias = NULL;
        /* Convert xen -> xen:/// for back compat */
        if (STRCASEEQ(name, "xen"))
            name = "xen:///";

        /* Convert xen:// -> xen:/// because xmlParseURI cannot parse the
         * former.  This allows URIs such as xen://localhost to work.
         */
        if (STREQ(name, "xen://"))
            name = "xen:///";

        if (!(flags & VIR_CONNECT_NO_ALIASES) &&
            virConnectOpenResolveURIAlias(conf, name, &alias) < 0)
            goto failed;

        if (!(ret->uri = virURIParse(alias ? alias : name))) {
            VIR_FREE(alias);
            goto failed;
        }

        VIR_DEBUG("name \"%s\" to URI components:\n"
                  "  scheme %s\n"
                  "  server %s\n"
                  "  user %s\n"
                  "  port %d\n"
                  "  path %s\n",
                  alias ? alias : name,
                  NULLSTR(ret->uri->scheme), NULLSTR(ret->uri->server),
                  NULLSTR(ret->uri->user), ret->uri->port,
                  NULLSTR(ret->uri->path));

        VIR_FREE(alias);
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
            ret->uri != NULL && ret->uri->scheme != NULL &&
            (
#ifndef WITH_PHYP
             STRCASEEQ(ret->uri->scheme, "phyp") ||
#endif
#ifndef WITH_ESX
             STRCASEEQ(ret->uri->scheme, "vpx") ||
             STRCASEEQ(ret->uri->scheme, "esx") ||
             STRCASEEQ(ret->uri->scheme, "gsx") ||
#endif
#ifndef WITH_HYPERV
             STRCASEEQ(ret->uri->scheme, "hyperv") ||
#endif
#ifndef WITH_XENAPI
             STRCASEEQ(ret->uri->scheme, "xenapi") ||
#endif
#ifndef WITH_VZ
             STRCASEEQ(ret->uri->scheme, "parallels") ||
#endif
             false)) {
            virReportErrorHelper(VIR_FROM_NONE, VIR_ERR_CONFIG_UNSUPPORTED,
                                 __FILE__, __FUNCTION__, __LINE__,
                                 _("libvirt was built without the '%s' driver"),
                                 ret->uri->scheme);
            goto failed;
        }

        VIR_DEBUG("trying driver %zu (%s) ...",
                  i, virConnectDriverTab[i]->hypervisorDriver->name);

        ret->driver = virConnectDriverTab[i]->hypervisorDriver;
        ret->interfaceDriver = virConnectDriverTab[i]->interfaceDriver;
        ret->networkDriver = virConnectDriverTab[i]->networkDriver;
        ret->nodeDeviceDriver = virConnectDriverTab[i]->nodeDeviceDriver;
        ret->nwfilterDriver = virConnectDriverTab[i]->nwfilterDriver;
        ret->secretDriver = virConnectDriverTab[i]->secretDriver;
        ret->storageDriver = virConnectDriverTab[i]->storageDriver;

        res = virConnectDriverTab[i]->hypervisorDriver->connectOpen(ret, auth, flags);
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
                goto failed;
        }
    }

    if (!ret->driver) {
        /* If we reach here, then all drivers declined the connection. */
        virReportError(VIR_ERR_NO_CONNECT, "%s", NULLSTR(name));
        goto failed;
    }

    virConfFree(conf);

    return ret;

 failed:
    virConfFree(conf);
    virObjectUnref(ret);

    return NULL;
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
 * URIs are documented at http://libvirt.org/uri.html
 *
 * virConnectClose should be used to release the resources after the connection
 * is no longer needed.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpen(const char *name)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        goto error;

    VIR_DEBUG("name=%s", NULLSTR(name));
    virResetLastError();
    ret = do_open(name, NULL, 0);
    if (!ret)
        goto error;
    return ret;

 error:
    virDispatchError(NULL);
    return NULL;
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
 * URIs are documented at http://libvirt.org/uri.html
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        goto error;

    VIR_DEBUG("name=%s", NULLSTR(name));
    virResetLastError();
    ret = do_open(name, NULL, VIR_CONNECT_RO);
    if (!ret)
        goto error;
    return ret;

 error:
    virDispatchError(NULL);
    return NULL;
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
 * URIs are documented at http://libvirt.org/uri.html
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpenAuth(const char *name,
                   virConnectAuthPtr auth,
                   unsigned int flags)
{
    virConnectPtr ret = NULL;

    if (virInitialize() < 0)
        goto error;

    VIR_DEBUG("name=%s, auth=%p, flags=%x", NULLSTR(name), auth, flags);
    virResetLastError();
    ret = do_open(name, auth, flags);
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
 */
int
virConnectClose(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (!virObjectUnref(conn))
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
    bool string_okay;
    size_t i;

    string_okay = VIR_DRV_SUPPORTS_FEATURE(conn->driver,
                                           conn,
                                           VIR_DRV_FEATURE_TYPED_PARAM_STRING);
    for (i = 0; i < nparams; i++) {
        if (strnlen(params[i].field, VIR_TYPED_PARAM_FIELD_LENGTH) ==
            VIR_TYPED_PARAM_FIELD_LENGTH) {
            virReportInvalidArg(params,
                                _("string parameter name '%.*s' too long"),
                                VIR_TYPED_PARAM_FIELD_LENGTH,
                                params[i].field);
            return -1;
        }
        if (params[i].type == VIR_TYPED_PARAM_STRING) {
            if (string_okay) {
                if (!params[i].value.s) {
                    virReportInvalidArg(params,
                                        _("NULL string parameter '%s'"),
                                        params[i].field);
                    return -1;
                }
            } else {
                virReportInvalidArg(params,
                                    _("string parameter '%s' unsupported"),
                                    params[i].field);
                return -1;
            }
        }
    }
    return 0;
}
