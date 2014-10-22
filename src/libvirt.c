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
#ifdef WITH_PARALLELS
# include "parallels/parallels_driver.h"
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

#define MAX_DRIVERS 20

#define virDriverCheckTabMaxReturn(count, ret)                          \
    do {                                                                \
        if ((count) >= MAX_DRIVERS) {                                   \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           _("Too many drivers, cannot register %s"),   \
                           driver->name);                               \
            return ret;                                                 \
        }                                                               \
    } while (0)

static virHypervisorDriverPtr virHypervisorDriverTab[MAX_DRIVERS];
static int virHypervisorDriverTabCount = 0;
static virNetworkDriverPtr virNetworkDriverTab[MAX_DRIVERS];
static int virNetworkDriverTabCount = 0;
static virInterfaceDriverPtr virInterfaceDriverTab[MAX_DRIVERS];
static int virInterfaceDriverTabCount = 0;
static virStorageDriverPtr virStorageDriverTab[MAX_DRIVERS];
static int virStorageDriverTabCount = 0;
static virNodeDeviceDriverPtr virNodeDeviceDriverTab[MAX_DRIVERS];
static int virNodeDeviceDriverTabCount = 0;
static virSecretDriverPtr virSecretDriverTab[MAX_DRIVERS];
static int virSecretDriverTabCount = 0;
static virNWFilterDriverPtr virNWFilterDriverTab[MAX_DRIVERS];
static int virNWFilterDriverTabCount = 0;
#ifdef WITH_LIBVIRTD
static virStateDriverPtr virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount = 0;
#endif


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


static bool virGlobalError = false;
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
# ifdef WITH_PARALLELS
    if (parallelsRegister() == -1)
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virNetworkDriverTabCount, -1);

    VIR_DEBUG("registering %s as network driver %d",
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virInterfaceDriverTabCount, -1);

    VIR_DEBUG("registering %s as interface driver %d",
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virStorageDriverTabCount, -1);

    VIR_DEBUG("registering %s as storage driver %d",
           driver->name, virStorageDriverTabCount);

    virStorageDriverTab[virStorageDriverTabCount] = driver;
    return virStorageDriverTabCount++;
}


/**
 * virRegisterNodeDeviceDriver:
 * @driver: pointer to a device monitor block
 *
 * Register a device monitor
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterNodeDeviceDriver(virNodeDeviceDriverPtr driver)
{
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virNodeDeviceDriverTabCount, -1);

    VIR_DEBUG("registering %s as device driver %d",
           driver->name, virNodeDeviceDriverTabCount);

    virNodeDeviceDriverTab[virNodeDeviceDriverTabCount] = driver;
    return virNodeDeviceDriverTabCount++;
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virSecretDriverTabCount, -1);

    VIR_DEBUG("registering %s as secret driver %d",
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virNWFilterDriverTabCount, -1);

    VIR_DEBUG("registering %s as network filter driver %d",
           driver->name, virNWFilterDriverTabCount);

    virNWFilterDriverTab[virNWFilterDriverTabCount] = driver;
    return virNWFilterDriverTabCount++;
}


/**
 * virRegisterHypervisorDriver:
 * @driver: pointer to a driver block
 *
 * Register a virtualization driver
 *
 * Returns the driver priority or -1 in case of error.
 */
int
virRegisterHypervisorDriver(virHypervisorDriverPtr driver)
{
    VIR_DEBUG("driver=%p name=%s", driver,
              driver ? NULLSTR(driver->name) : "(null)");

    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virHypervisorDriverTabCount, -1);

    VIR_DEBUG("registering %s as driver %d",
           driver->name, virHypervisorDriverTabCount);

    virHypervisorDriverTab[virHypervisorDriverTabCount] = driver;
    return virHypervisorDriverTabCount++;
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
    virCheckNonNullArgReturn(driver, -1);
    virDriverCheckTabMaxReturn(virStateDriverTabCount, -1);

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
#endif /* WITH_LIBVIRTD */


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

    for (i = 0; i < virHypervisorDriverTabCount; i++) {
        /* We're going to probe the remote driver next. So we have already
         * probed all other client-side-only driver before, but none of them
         * accepted the URI.
         * If the scheme corresponds to a known but disabled client-side-only
         * driver then report a useful error, instead of a cryptic one about
         * not being able to connect to libvirtd or not being able to find
         * certificates. */
        if (virHypervisorDriverTab[i]->no == VIR_DRV_REMOTE &&
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
#ifndef WITH_PARALLELS
             STRCASEEQ(ret->uri->scheme, "parallels") ||
#endif
             false)) {
            virReportErrorHelper(VIR_FROM_NONE, VIR_ERR_CONFIG_UNSUPPORTED,
                                 __FILE__, __FUNCTION__, __LINE__,
                                 _("libvirt was built without the '%s' driver"),
                                 ret->uri->scheme);
            goto failed;
        }

        VIR_DEBUG("trying driver %zu (%s) ...", i, virHypervisorDriverTab[i]->name);
        ret->driver = virHypervisorDriverTab[i];
        res = virHypervisorDriverTab[i]->connectOpen(ret, auth, flags);
        VIR_DEBUG("driver %zu %s returned %s",
                  i, virHypervisorDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            ret->driver = NULL;
            goto failed;
        } else {
            ret->driver = NULL;
        }
    }

    if (!ret->driver) {
        /* If we reach here, then all drivers declined the connection. */
        virReportError(VIR_ERR_NO_CONNECT, "%s", NULLSTR(name));
        goto failed;
    }

    for (i = 0; i < virNetworkDriverTabCount; i++) {
        res = virNetworkDriverTab[i]->networkOpen(ret, auth, flags);
        VIR_DEBUG("network driver %zu %s returned %s",
                  i, virNetworkDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->networkDriver = virNetworkDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
    }

    for (i = 0; i < virInterfaceDriverTabCount; i++) {
        res = virInterfaceDriverTab[i]->interfaceOpen(ret, auth, flags);
        VIR_DEBUG("interface driver %zu %s returned %s",
                  i, virInterfaceDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->interfaceDriver = virInterfaceDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
    }

    /* Secondary driver for storage. Optional */
    for (i = 0; i < virStorageDriverTabCount; i++) {
        res = virStorageDriverTab[i]->storageOpen(ret, auth, flags);
        VIR_DEBUG("storage driver %zu %s returned %s",
                  i, virStorageDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->storageDriver = virStorageDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
    }

    /* Node driver (optional) */
    for (i = 0; i < virNodeDeviceDriverTabCount; i++) {
        res = virNodeDeviceDriverTab[i]->nodeDeviceOpen(ret, auth, flags);
        VIR_DEBUG("node driver %zu %s returned %s",
                  i, virNodeDeviceDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->nodeDeviceDriver = virNodeDeviceDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
    }

    /* Secret manipulation driver. Optional */
    for (i = 0; i < virSecretDriverTabCount; i++) {
        res = virSecretDriverTab[i]->secretOpen(ret, auth, flags);
        VIR_DEBUG("secret driver %zu %s returned %s",
                  i, virSecretDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->secretDriver = virSecretDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
    }

    /* Network filter driver. Optional */
    for (i = 0; i < virNWFilterDriverTabCount; i++) {
        res = virNWFilterDriverTab[i]->nwfilterOpen(ret, auth, flags);
        VIR_DEBUG("nwfilter driver %zu %s returned %s",
                  i, virNWFilterDriverTab[i]->name,
                  res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
                  (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
                  (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));

        if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->nwfilterDriver = virNWFilterDriverTab[i];
            break;
        } else if (res == VIR_DRV_OPEN_ERROR) {
            break;
        }
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
    VIR_DEBUG("conn=%p refs=%d", conn, conn ? conn->object.u.s.refs : 0);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virObjectRef(conn);
    return 0;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of driver features in the remote case.
 */
int
virConnectSupportsFeature(virConnectPtr conn, int feature)
{
    int ret;
    VIR_DEBUG("conn=%p, feature=%d", conn, feature);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (!conn->driver->connectSupportsFeature)
        ret = 0;
    else
        ret = conn->driver->connectSupportsFeature(conn, feature);

    if (ret < 0)
        virDispatchError(conn);

    return ret;
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


/**
 * virConnectGetType:
 * @conn: pointer to the hypervisor connection
 *
 * Get the name of the Hypervisor driver used. This is merely the driver
 * name; for example, both KVM and QEMU guests are serviced by the
 * driver for the qemu:// URI, so a return of "QEMU" does not indicate
 * whether KVM acceleration is present.  For more details about the
 * hypervisor, use virConnectGetCapabilities().
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetType) {
        ret = conn->driver->connectGetType(conn);
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
    VIR_DEBUG("conn=%p, hvVer=%p", conn, hvVer);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(hvVer, error);

    if (conn->driver->connectGetVersion) {
        int ret = conn->driver->connectGetVersion(conn, hvVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
    VIR_DEBUG("conn=%p, libVir=%p", conn, libVer);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(libVer, error);

    if (conn->driver->connectGetLibVersion) {
        ret = conn->driver->connectGetLibVersion(conn, libVer);
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
 * This returns a system hostname on which the hypervisor is
 * running (based on the result of the gethostname system call, but
 * possibly expanded to a fully-qualified domain name via getaddrinfo).
 * If we are connected to a remote system, then this returns the
 * hostname of the remote system.
 *
 * Returns the hostname which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virConnectGetHostname(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetHostname) {
        char *ret = conn->driver->connectGetHostname(conn);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
virConnectGetURI(virConnectPtr conn)
{
    char *name;
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (!(name = virURIFormat(conn->uri)))
        goto error;

    return name;

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectGetSysinfo:
 * @conn: pointer to a hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This returns the XML description of the sysinfo details for the
 * host on which the hypervisor is running, in the same format as the
 * <sysinfo> element of a domain XML.  This information is generally
 * available only for hypervisors running with root privileges.
 *
 * Returns the XML string which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetSysinfo) {
        char *ret = conn->driver->connectGetSysinfo(conn, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
    VIR_DEBUG("conn=%p, type=%s", conn, type);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectGetMaxVcpus) {
        int ret = conn->driver->connectGetMaxVcpus(conn, type);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
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
    VIR_DEBUG("conn=%p, info=%p", conn, info);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(info, error);

    if (conn->driver->nodeGetInfo) {
        int ret;
        ret = conn->driver->nodeGetInfo(conn, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
virConnectGetCapabilities(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->driver->connectGetCapabilities) {
        char *ret;
        ret = conn->driver->connectGetCapabilities(conn);
        if (!ret)
            goto error;
        VIR_DEBUG("conn=%p ret=%s", conn, ret);
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virNodeGetCPUStats:
 * @conn: pointer to the hypervisor connection.
 * @cpuNum: number of node cpu. (VIR_NODE_CPU_STATS_ALL_CPUS means total cpu
 *          statistics)
 * @params: pointer to node cpu time parameter objects
 * @nparams: number of node cpu time parameter (this value should be same or
 *          less than the number of parameters supported)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function provides individual cpu statistics of the node.
 * If you want to get total cpu statistics of the node, you must specify
 * VIR_NODE_CPU_STATS_ALL_CPUS to @cpuNum.
 * The @params array will be filled with the values equal to the number of
 * parameters suggested by @nparams
 *
 * As the value of @nparams is dynamic, call the API setting @nparams to 0 and
 * @params as NULL, the API returns the number of parameters supported by the
 * HV by updating @nparams on SUCCESS. The caller should then allocate @params
 * array, i.e. (sizeof(@virNodeCPUStats) * @nparams) bytes and call
 * the API again.
 *
 * Here is a sample code snippet:
 *
 *   if (virNodeGetCPUStats(conn, cpuNum, NULL, &nparams, 0) == 0 &&
 *       nparams != 0) {
 *       if ((params = malloc(sizeof(virNodeCPUStats) * nparams)) == NULL)
 *           goto error;
 *       memset(params, 0, sizeof(virNodeCPUStats) * nparams);
 *       if (virNodeGetCPUStats(conn, cpuNum, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function doesn't require privileged access to the hypervisor.
 * This function expects the caller to allocate the @params.
 *
 * CPU time Statistics:
 *
 * VIR_NODE_CPU_STATS_KERNEL:
 *     The cumulative CPU time which spends by kernel,
 *     when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_USER:
 *     The cumulative CPU time which spends by user processes,
 *     when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_IDLE:
 *     The cumulative idle CPU time, when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_IOWAIT:
 *     The cumulative I/O wait CPU time, when the node booting up.(nanoseconds)
 * VIR_NODE_CPU_STATS_UTILIZATION:
 *     The CPU utilization. The usage value is in percent and 100%
 *     represents all CPUs on the server.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virNodeGetCPUStats(virConnectPtr conn,
                   int cpuNum,
                   virNodeCPUStatsPtr params,
                   int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cpuNum=%d, params=%p, nparams=%d, flags=%x",
              conn, cpuNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (cpuNum < 0 && cpuNum != VIR_NODE_CPU_STATS_ALL_CPUS) {
        virReportInvalidArg(cpuNum,
                            _("cpuNum in %s only accepts %d as a negative "
                              "value"),
                            __FUNCTION__, VIR_NODE_CPU_STATS_ALL_CPUS);
        goto error;
    }

    if (conn->driver->nodeGetCPUStats) {
        int ret;
        ret = conn->driver->nodeGetCPUStats(conn, cpuNum, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetMemoryStats:
 * @conn: pointer to the hypervisor connection.
 * @cellNum: number of node cell. (VIR_NODE_MEMORY_STATS_ALL_CELLS means total
 *           cell statistics)
 * @params: pointer to node memory stats objects
 * @nparams: number of node memory stats (this value should be same or
 *          less than the number of stats supported)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function provides memory stats of the node.
 * If you want to get total memory statistics of the node, you must specify
 * VIR_NODE_MEMORY_STATS_ALL_CELLS to @cellNum.
 * The @params array will be filled with the values equal to the number of
 * stats suggested by @nparams
 *
 * As the value of @nparams is dynamic, call the API setting @nparams to 0 and
 * @params as NULL, the API returns the number of parameters supported by the
 * HV by updating @nparams on SUCCESS. The caller should then allocate @params
 * array, i.e. (sizeof(@virNodeMemoryStats) * @nparams) bytes and call
 * the API again.
 *
 * Here is the sample code snippet:
 *
 *   if (virNodeGetMemoryStats(conn, cellNum, NULL, &nparams, 0) == 0 &&
 *       nparams != 0) {
 *       if ((params = malloc(sizeof(virNodeMemoryStats) * nparams)) == NULL)
 *           goto error;
 *       memset(params, cellNum, 0, sizeof(virNodeMemoryStats) * nparams);
 *       if (virNodeGetMemoryStats(conn, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function doesn't require privileged access to the hypervisor.
 * This function expects the caller to allocate the @params.
 *
 * Memory Stats:
 *
 * VIR_NODE_MEMORY_STATS_TOTAL:
 *     The total memory usage.(KB)
 * VIR_NODE_MEMORY_STATS_FREE:
 *     The free memory usage.(KB)
 *     On linux, this usage includes buffers and cached.
 * VIR_NODE_MEMORY_STATS_BUFFERS:
 *     The buffers memory usage.(KB)
 * VIR_NODE_MEMORY_STATS_CACHED:
 *     The cached memory usage.(KB)
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virNodeGetMemoryStats(virConnectPtr conn,
                      int cellNum,
                      virNodeMemoryStatsPtr params,
                      int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cellNum=%d, params=%p, nparams=%d, flags=%x",
              conn, cellNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (cellNum < 0 && cellNum != VIR_NODE_MEMORY_STATS_ALL_CELLS) {
        virReportInvalidArg(cpuNum,
                            _("cellNum in %s only accepts %d as a negative "
                              "value"),
                            __FUNCTION__, VIR_NODE_MEMORY_STATS_ALL_CELLS);
        goto error;
    }

    if (conn->driver->nodeGetMemoryStats) {
        int ret;
        ret = conn->driver->nodeGetMemoryStats(conn, cellNum, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetFreeMemory:
 * @conn: pointer to the hypervisor connection
 *
 * provides the free memory available on the Node
 * Note: most libvirt APIs provide memory sizes in kibibytes, but in this
 * function the returned value is in bytes. Divide by 1024 as necessary.
 *
 * Returns the available free memory in bytes or 0 in case of error
 */
unsigned long long
virNodeGetFreeMemory(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, 0);

    if (conn->driver->nodeGetFreeMemory) {
        unsigned long long ret;
        ret = conn->driver->nodeGetFreeMemory(conn);
        if (ret == 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return 0;
}


/**
 * virNodeSuspendForDuration:
 * @conn: pointer to the hypervisor connection
 * @target: the state to which the host must be suspended to,
 *         such as: VIR_NODE_SUSPEND_TARGET_MEM (Suspend-to-RAM)
 *                  VIR_NODE_SUSPEND_TARGET_DISK (Suspend-to-Disk)
 *                  VIR_NODE_SUSPEND_TARGET_HYBRID (Hybrid-Suspend,
 *                  which is a combination of the former modes).
 * @duration: the time duration in seconds for which the host
 *            has to be suspended
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Attempt to suspend the node (host machine) for the given duration of
 * time in the specified state (Suspend-to-RAM, Suspend-to-Disk or
 * Hybrid-Suspend). Schedule the node's Real-Time-Clock interrupt to
 * resume the node after the duration is complete.
 *
 * Returns 0 on success (i.e., the node will be suspended after a short
 * delay), -1 on failure (the operation is not supported, or an attempted
 * suspend is already underway).
 */
int
virNodeSuspendForDuration(virConnectPtr conn,
                          unsigned int target,
                          unsigned long long duration,
                          unsigned int flags)
{
    VIR_DEBUG("conn=%p, target=%d, duration=%lld, flags=%x",
              conn, target, duration, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->nodeSuspendForDuration) {
        int ret;
        ret = conn->driver->nodeSuspendForDuration(conn, target,
                                                   duration, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * virNodeGetMemoryParameters:
 * @conn: pointer to the hypervisor connection
 * @params: pointer to memory parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of memory parameters; input and output
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get all node memory parameters (parameters unsupported by OS will be
 * omitted).  On input, @nparams gives the size of the @params array;
 * on output, @nparams gives how many slots were filled with parameter
 * information, which might be less but will not exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.  See virDomainGetMemoryParameters() for an equivalent usage
 * example.
 *
 * Returns 0 in case of success, and -1 in case of failure.
 */
int
virNodeGetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int *nparams,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, params=%p, nparams=%p, flags=%x",
              conn, params, nparams, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    if (conn->driver->nodeGetMemoryParameters) {
        int ret;
        ret = conn->driver->nodeGetMemoryParameters(conn, params,
                                                    nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/*
 * virNodeSetMemoryParameters:
 * @conn: pointer to the hypervisor connection
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned
 *           value nparams of virDomainGetSchedulerType)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Change all or a subset of the node memory tunables. The function
 * fails if not all of the tunables are supported.
 *
 * Note that it's not recommended to use this function while the
 * outside tuning program is running (such as ksmtuned under Linux),
 * as they could change the tunables in parallel, which could cause
 * conflicts.
 *
 * This function may require privileged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeSetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, params=%p, nparams=%d, flags=%x",
              conn, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(conn, params, nparams) < 0)
        goto error;

    if (conn->driver->nodeSetMemoryParameters) {
        int ret;
        ret = conn->driver->nodeSetMemoryParameters(conn, params,
                                                          nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
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
    VIR_DEBUG("conn=%p secmodel=%p", conn, secmodel);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(secmodel, error);

    if (conn->driver->nodeGetSecurityModel) {
        int ret;
        ret = conn->driver->nodeGetSecurityModel(conn, secmodel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
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
    VIR_DEBUG("conn=%p, freeMems=%p, startCell=%d, maxCells=%d",
          conn, freeMems, startCell, maxCells);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(freeMems, error);
    virCheckPositiveArgGoto(maxCells, error);
    virCheckNonNegativeArgGoto(startCell, error);

    if (conn->driver->nodeGetCellsFreeMemory) {
        int ret;
        ret = conn->driver->nodeGetCellsFreeMemory(conn, freeMems, startCell, maxCells);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
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
int
virConnectIsEncrypted(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsEncrypted) {
        int ret;
        ret = conn->driver->connectIsEncrypted(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
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
 * Returns 1 if secure, 0 if not secure, -1 on error
 */
int
virConnectIsSecure(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsSecure) {
        int ret;
        ret = conn->driver->connectIsSecure(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectCompareCPU:
 * @conn: virConnect connection
 * @xmlDesc: XML describing the CPU to compare with host CPU
 * @flags: bitwise-OR of virConnectCompareCPUFlags
 *
 * Compares the given CPU description with the host CPU
 *
 * Returns comparison result according to enum virCPUCompareResult. If
 * VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE is used and @xmlDesc CPU is
 * incompatible with host CPU, this function will return VIR_CPU_COMPARE_ERROR
 * (instead of VIR_CPU_COMPARE_INCOMPATIBLE) and the error will use the
 * VIR_ERR_CPU_INCOMPATIBLE code with a message providing more details about
 * the incompatibility.
 */
int
virConnectCompareCPU(virConnectPtr conn,
                     const char *xmlDesc,
                     unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, xmlDesc, flags);

    virResetLastError();

    virCheckConnectReturn(conn, VIR_CPU_COMPARE_ERROR);
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->driver->connectCompareCPU) {
        int ret;

        ret = conn->driver->connectCompareCPU(conn, xmlDesc, flags);
        if (ret == VIR_CPU_COMPARE_ERROR)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return VIR_CPU_COMPARE_ERROR;
}


/**
 * virConnectGetCPUModelNames:
 *
 * @conn: virConnect connection
 * @arch: Architecture
 * @models: Pointer to a variable to store the NULL-terminated array of the
 *          CPU models supported for the specified architecture.  Each element
 *          and the array itself must be freed by the caller with free.  Pass
 *          NULL if only the list length is needed.
 * @flags: extra flags; not used yet, so callers should always pass 0.
 *
 * Get the list of supported CPU models for a specific architecture.
 *
 * Returns -1 on error, number of elements in @models on success.
 */
int
virConnectGetCPUModelNames(virConnectPtr conn, const char *arch, char ***models,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, arch=%s, models=%p, flags=%x",
              conn, arch, models, flags);
    virResetLastError();

    if (models)
        *models = NULL;

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArgGoto(arch, error);

    if (conn->driver->connectGetCPUModelNames) {
        int ret;

        ret = conn->driver->connectGetCPUModelNames(conn, arch, models, flags);
        if (ret < 0)
            goto error;

        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectBaselineCPU:
 *
 * @conn: virConnect connection
 * @xmlCPUs: array of XML descriptions of host CPUs
 * @ncpus: number of CPUs in xmlCPUs
 * @flags: bitwise-OR of virConnectBaselineCPUFlags
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * host CPUs.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES then libvirt
 * will explicitly list all CPU features that are part of the host CPU,
 * without this flag features that are part of the CPU model will not be
 * listed.
 *
 * Returns XML description of the computed CPU (caller frees) or NULL on error.
 */
char *
virConnectBaselineCPU(virConnectPtr conn,
                      const char **xmlCPUs,
                      unsigned int ncpus,
                      unsigned int flags)
{
    size_t i;

    VIR_DEBUG("conn=%p, xmlCPUs=%p, ncpus=%u, flags=%x",
              conn, xmlCPUs, ncpus, flags);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%zu]=%s", i, NULLSTR(xmlCPUs[i]));
    }

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlCPUs, error);

    if (conn->driver->connectBaselineCPU) {
        char *cpu;

        cpu = conn->driver->connectBaselineCPU(conn, xmlCPUs, ncpus, flags);
        if (!cpu)
            goto error;
        return cpu;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectSetKeepAlive:
 * @conn: pointer to a hypervisor connection
 * @interval: number of seconds of inactivity before a keepalive message is sent
 * @count: number of messages that can be sent in a row
 *
 * Start sending keepalive messages after @interval seconds of inactivity and
 * consider the connection to be broken when no response is received after
 * @count keepalive messages sent in a row.  In other words, sending count + 1
 * keepalive message results in closing the connection.  When @interval is
 * <= 0, no keepalive messages will be sent.  When @count is 0, the connection
 * will be automatically closed after @interval seconds of inactivity without
 * sending any keepalive messages.
 *
 * Note: The client has to implement and run an event loop with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl() to be able to
 * use keepalive messages.  Failure to do so may result in connections
 * being closed unexpectedly.
 *
 * Note: This API function controls only keepalive messages sent by the client.
 * If the server is configured to use keepalive you still need to run the event
 * loop to respond to them, even if you disable keepalives by this function.
 *
 * Returns -1 on error, 0 on success, 1 when remote party doesn't support
 * keepalive messages.
 */
int
virConnectSetKeepAlive(virConnectPtr conn,
                       int interval,
                       unsigned int count)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, interval=%d, count=%u", conn, interval, count);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->connectSetKeepAlive) {
        ret = conn->driver->connectSetKeepAlive(conn, interval, count);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectIsAlive:
 * @conn: pointer to the connection object
 *
 * Determine if the connection to the hypervisor is still alive
 *
 * A connection will be classed as alive if it is either local, or running
 * over a channel (TCP or UNIX socket) which is not closed.
 *
 * Returns 1 if alive, 0 if dead, -1 on error
 */
int
virConnectIsAlive(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (conn->driver->connectIsAlive) {
        int ret;
        ret = conn->driver->connectIsAlive(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectRegisterCloseCallback:
 * @conn: pointer to connection object
 * @cb: callback to invoke upon close
 * @opaque: user data to pass to @cb
 * @freecb: callback to free @opaque
 *
 * Registers a callback to be invoked when the connection
 * is closed. This callback is invoked when there is any
 * condition that causes the socket connection to the
 * hypervisor to be closed.
 *
 * This function is only applicable to hypervisor drivers
 * which maintain a persistent open connection. Drivers
 * which open a new connection for every operation will
 * not invoke this.
 *
 * The @freecb must not invoke any other libvirt public
 * APIs, since it is not called from a re-entrant safe
 * context.
 *
 * Returns 0 on success, -1 on error
 */
int
virConnectRegisterCloseCallback(virConnectPtr conn,
                                virConnectCloseFunc cb,
                                void *opaque,
                                virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    virObjectRef(conn);

    virMutexLock(&conn->lock);
    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A close callback is already registered"));
        goto error;
    }

    conn->closeCallback->conn = conn;
    conn->closeCallback->callback = cb;
    conn->closeCallback->opaque = opaque;
    conn->closeCallback->freeCallback = freecb;

    virObjectUnlock(conn->closeCallback);
    virMutexUnlock(&conn->lock);

    return 0;

 error:
    virObjectUnlock(conn->closeCallback);
    virMutexUnlock(&conn->lock);
    virDispatchError(conn);
    virObjectUnref(conn);
    return -1;
}


/**
 * virConnectUnregisterCloseCallback:
 * @conn: pointer to connection object
 * @cb: pointer to the current registered callback
 *
 * Unregisters the callback previously set with the
 * virConnectRegisterCloseCallback method. The callback
 * will no longer receive notifications when the connection
 * closes. If a virFreeCallback was provided at time of
 * registration, it will be invoked
 *
 * Returns 0 on success, -1 on error
 */
int
virConnectUnregisterCloseCallback(virConnectPtr conn,
                                  virConnectCloseFunc cb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    virMutexLock(&conn->lock);
    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback != cb) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A different callback was requested"));
        goto error;
    }

    conn->closeCallback->callback = NULL;
    if (conn->closeCallback->freeCallback)
        conn->closeCallback->freeCallback(conn->closeCallback->opaque);
    conn->closeCallback->freeCallback = NULL;

    virObjectUnref(conn);
    virObjectUnlock(conn->closeCallback);
    virMutexUnlock(&conn->lock);

    return 0;

 error:
    virObjectUnlock(conn->closeCallback);
    virMutexUnlock(&conn->lock);
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetCPUMap:
 * @conn: pointer to the hypervisor connection
 * @cpumap: optional pointer to a bit map of real CPUs on the host node
 *      (in 8-bit bytes) (OUT)
 *      In case of success each bit set to 1 means that corresponding
 *      CPU is online.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 *      The bit map is allocated by virNodeGetCPUMap and needs
 *      to be released using free() by the caller.
 * @online: optional number of online CPUs in cpumap (OUT)
 *      Contains the number of online CPUs if the call was successful.
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get CPU map of host node CPUs.
 *
 * Returns number of CPUs present on the host node,
 * or -1 if there was an error.
 */
int
virNodeGetCPUMap(virConnectPtr conn,
                 unsigned char **cpumap,
                 unsigned int *online,
                 unsigned int flags)
{
    VIR_DEBUG("conn=%p, cpumap=%p, online=%p, flags=%x",
              conn, cpumap, online, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->driver->nodeGetCPUMap) {
        int ret = conn->driver->nodeGetCPUMap(conn, cpumap, online, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeGetFreePages:
 * @conn: pointer to the hypervisor connection
 * @npages: number of items in the @pages array
 * @pages: page sizes to query
 * @startCell: index of first cell to return free pages info on.
 * @cellCount: maximum number of cells for which free pages
 *             information can be returned.
 * @counts: returned counts of free pages
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This calls queries the host system on free pages of
 * specified size. For the input, @pages is expected to be
 * filled with pages that caller is interested in (the size
 * unit is kibibytes, so e.g. pass 2048 for 2MB), then @startcell
 * refers to the first NUMA node that info should be collected
 * from, and @cellcount tells how many consecutive nodes should
 * be queried. On the function output, @counts is filled with
 * desired information, where items are grouped by NUMA node.
 * So from @counts[0] till @counts[@npages - 1] you'll find count
 * for the first node (@startcell), then from @counts[@npages]
 * till @count[2 * @npages - 1] you'll find info for the
 * (@startcell + 1) node, and so on. It's callers responsibility
 * to allocate the @counts array.
 *
 * Example how to use this API:
 *
 *   unsigned int pages[] = { 4, 2048, 1048576}
 *   unsigned int npages = ARRAY_CARDINALITY(pages);
 *   int startcell = 0;
 *   unsigned int cellcount = 2;
 *
 *   unsigned long long counts = malloc(sizeof(long long) * npages * cellcount);
 *
 *   virNodeGetFreePages(conn, pages, npages,
 *                       startcell, cellcount, counts, 0);
 *
 *   for (i = 0 ; i < cellcount ; i++) {
 *       fprintf(stdout, "Cell %d\n", startcell + i);
 *       for (j = 0 ; j < npages ; j++) {
 *          fprintf(stdout, "  Page size=%d count=%d bytes=%llu\n",
 *                  pages[j], counts[(i * npages) +  j],
 *                  pages[j] * counts[(i * npages) +  j]);
 *       }
 *   }
 *
 *   This little code snippet will produce something like this:
 * Cell 0
 *    Page size=4096 count=300 bytes=1228800
 *    Page size=2097152 count=0 bytes=0
 *    Page size=1073741824 count=1 bytes=1073741824
 * Cell 1
 *    Page size=4096 count=0 bytes=0
 *    Page size=2097152 count=20 bytes=41943040
 *    Page size=1073741824 count=0 bytes=0
 *
 * Returns: the number of entries filled in @counts or -1 in case of error.
 */
int
virNodeGetFreePages(virConnectPtr conn,
                    unsigned int npages,
                    unsigned int *pages,
                    int startCell,
                    unsigned int cellCount,
                    unsigned long long *counts,
                    unsigned int flags)
{
    VIR_DEBUG("conn=%p, npages=%u, pages=%p, startCell=%u, "
              "cellCount=%u, counts=%p, flags=%x",
              conn, npages, pages, startCell, cellCount, counts, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonZeroArgGoto(npages, error);
    virCheckNonNullArgGoto(pages, error);
    virCheckNonZeroArgGoto(cellCount, error);
    virCheckNonNullArgGoto(counts, error);

    if (conn->driver->nodeGetFreePages) {
        int ret;
        ret = conn->driver->nodeGetFreePages(conn, npages, pages, startCell,
                                             cellCount, counts, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virNodeAllocPages:
 * @conn: pointer to the hypervisor connection
 * @npages: number of items in the @pageSizes and
 *          @pageCounts arrays
 * @pageSizes: which huge page sizes to allocate
 * @pageCounts: how many pages should be allocated
 * @startCell: index of first cell to allocate pages on
 * @cellCount: number of consecutive cells to allocate pages on
 * @flags: extra flags; binary-OR of virNodeAllocPagesFlags
 *
 * Sometimes, when trying to start a new domain, it may be
 * necessary to reserve some huge pages in the system pool which
 * can be then allocated by the domain. This API serves that
 * purpose. On its input, @pageSizes and @pageCounts are arrays
 * of the same cardinality of @npages. The @pageSizes contains
 * page sizes which are to be allocated in the system (the size
 * unit is kibibytes), and @pageCounts then contains the number
 * of pages to reserve.  If @flags is 0
 * (VIR_NODE_ALLOC_PAGES_ADD), each pool corresponding to
 * @pageSizes grows by the number of pages specified in the
 * corresponding @pageCounts.  If @flags contains
 * VIR_NODE_ALLOC_PAGES_SET, each pool mentioned is resized to
 * the given number of pages.  The pages pool can be allocated
 * over several NUMA nodes at once, just point at @startCell and
 * tell how many subsequent NUMA nodes should be taken in. As a
 * special case, if @startCell is equal to negative one, then
 * kernel is instructed to allocate the pages over all NUMA nodes
 * proportionally.
 *
 * Returns: the number of nodes successfully adjusted or -1 in
 * case of an error.
 */
int
virNodeAllocPages(virConnectPtr conn,
                  unsigned int npages,
                  unsigned int *pageSizes,
                  unsigned long long *pageCounts,
                  int startCell,
                  unsigned int cellCount,
                  unsigned int flags)
{
    VIR_DEBUG("conn=%p npages=%u pageSizes=%p pageCounts=%p "
              "startCell=%d cellCount=%u flagx=%x",
              conn, npages, pageSizes, pageCounts, startCell,
              cellCount, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonZeroArgGoto(npages, error);
    virCheckNonNullArgGoto(pageSizes, error);
    virCheckNonNullArgGoto(pageCounts, error);
    virCheckNonZeroArgGoto(cellCount, error);

    if (conn->driver->nodeAllocPages) {
        int ret;
        ret = conn->driver->nodeAllocPages(conn, npages, pageSizes,
                                           pageCounts, startCell,
                                           cellCount, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}
