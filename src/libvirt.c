/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005-2006, 2008-2013 Red Hat, Inc.
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
#include "intprops.h"
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

#define VIR_FROM_THIS VIR_FROM_NONE

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to guarantee coherent pointer state ?
 */

#define MAX_DRIVERS 20

static virDriverPtr virDriverTab[MAX_DRIVERS];
static int virDriverTabCount = 0;
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
static int virConnectAuthGainPolkit(const char *privilege) {
    virCommandPtr cmd;
    int status;
    int ret = -1;

    if (geteuid() == 0)
        return 0;

    cmd = virCommandNewArgList(POLKIT_AUTH, "--obtain", privilege, NULL);
    if (virCommandRun(cmd, &status) < 0 ||
        status > 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}
#endif

static int virConnectAuthCallbackDefault(virConnectCredentialPtr cred,
                                         unsigned int ncred,
                                         void *cbdata ATTRIBUTE_UNUSED) {
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
static int virTLSMutexInit(void **priv)
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

/* Helper macros to implement VIR_DOMAIN_DEBUG using just C99.  This
 * assumes you pass fewer than 15 arguments to VIR_DOMAIN_DEBUG, but
 * can easily be expanded if needed.
 *
 * Note that gcc provides extensions of "define a(b...) b" or
 * "define a(b,...) b,##__VA_ARGS__" as a means of eliding a comma
 * when no var-args are present, but we don't want to require gcc.
 */
#define VIR_ARG15(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, ...) _15
#define VIR_HAS_COMMA(...) VIR_ARG15(__VA_ARGS__, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0)

/* Form the name VIR_DOMAIN_DEBUG_[01], then call that macro,
 * according to how many arguments are present.  Two-phase due to
 * macro expansion rules.  */
#define VIR_DOMAIN_DEBUG_EXPAND(a, b, ...)      \
    VIR_DOMAIN_DEBUG_PASTE(a, b, __VA_ARGS__)
#define VIR_DOMAIN_DEBUG_PASTE(a, b, ...)       \
    a##b(__VA_ARGS__)

/* Internal use only, when VIR_DOMAIN_DEBUG has one argument.  */
#define VIR_DOMAIN_DEBUG_0(dom)                 \
    VIR_DOMAIN_DEBUG_2(dom, "%s", "")

/* Internal use only, when VIR_DOMAIN_DEBUG has three or more arguments.  */
#define VIR_DOMAIN_DEBUG_1(dom, fmt, ...)       \
    VIR_DOMAIN_DEBUG_2(dom, ", " fmt, __VA_ARGS__)

/* Internal use only, with final format.  */
#define VIR_DOMAIN_DEBUG_2(dom, fmt, ...)                               \
    do {                                                                \
        char _uuidstr[VIR_UUID_STRING_BUFLEN];                          \
        const char *_domname = NULL;                                    \
                                                                        \
        if (!VIR_IS_DOMAIN(dom)) {                                      \
            memset(_uuidstr, 0, sizeof(_uuidstr));                      \
        } else {                                                        \
            virUUIDFormat((dom)->uuid, _uuidstr);                       \
            _domname = (dom)->name;                                     \
        }                                                               \
                                                                        \
        VIR_DEBUG("dom=%p, (VM: name=%s, uuid=%s)" fmt,                 \
                  dom, NULLSTR(_domname), _uuidstr, __VA_ARGS__);       \
    } while (0)

/**
 * VIR_DOMAIN_DEBUG:
 * @dom: domain
 * @fmt: optional format for additional information
 * @...: optional arguments corresponding to @fmt.
 */
#define VIR_DOMAIN_DEBUG(...)                           \
    VIR_DOMAIN_DEBUG_EXPAND(VIR_DOMAIN_DEBUG_,          \
                            VIR_HAS_COMMA(__VA_ARGS__), \
                            __VA_ARGS__)

/**
 * VIR_UUID_DEBUG:
 * @conn: connection
 * @uuid: possibly null UUID array
 */
#define VIR_UUID_DEBUG(conn, uuid)                              \
    do {                                                        \
        if (uuid) {                                             \
            char _uuidstr[VIR_UUID_STRING_BUFLEN];              \
            virUUIDFormat(uuid, _uuidstr);                      \
            VIR_DEBUG("conn=%p, uuid=%s", conn, _uuidstr);      \
        } else {                                                \
            VIR_DEBUG("conn=%p, uuid=(null)", conn);            \
        }                                                       \
    } while (0)


static bool virGlobalError = false;
static virOnceControl virGlobalOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
virGlobalInit(void)
{
    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0)
        goto error;

#ifndef IN_VIRT_LOGIN_SHELL
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
 * This method is invoked automatically by any of the virConnectOpen API
 * calls. Since release 1.0.0, there is no need to call this method even
 * in a multithreaded application, since initialization is performed in
 * a thread safe manner.
 *
 * The only time it would be necessary to call virInitialize is if the
 * application did not invoke virConnectOpen as its first API call.
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

#define virLibConnError(code, ...)                                \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibDomainError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_DOM, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibNetworkError(code, ...)                             \
    virReportErrorHelper(VIR_FROM_NETWORK, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibStoragePoolError(code, ...)                         \
    virReportErrorHelper(VIR_FROM_STORAGE, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibStorageVolError(code, ...)                          \
    virReportErrorHelper(VIR_FROM_STORAGE, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibInterfaceError(code, ...)                           \
    virReportErrorHelper(VIR_FROM_INTERFACE, code, __FILE__,      \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibNodeDeviceError(code, ...)                          \
    virReportErrorHelper(VIR_FROM_NODEDEV, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibSecretError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_SECRET, code, __FILE__,         \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibStreamError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_STREAMS, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibNWFilterError(code, ...)                            \
    virReportErrorHelper(VIR_FROM_NWFILTER, code, __FILE__,       \
                         __FUNCTION__, __LINE__, __VA_ARGS__)
#define virLibDomainSnapshotError(code, ...)                       \
    virReportErrorHelper(VIR_FROM_DOMAIN_SNAPSHOT, code, __FILE__, \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


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

    if (virNetworkDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

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

    if (virInterfaceDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

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

    if (virStorageDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

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

    if (virNodeDeviceDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

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

    if (virSecretDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

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

    if (virNWFilterDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

    VIR_DEBUG("registering %s as network filter driver %d",
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
    VIR_DEBUG("driver=%p name=%s", driver, driver ? NULLSTR(driver->name) : "(null)");

    virCheckNonNullArgReturn(driver, -1);

    if (virDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
                        _("Too many drivers, cannot register %s"),
                        driver->name);
        return -1;
    }

    VIR_DEBUG("registering %s as driver %d",
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
    virCheckNonNullArgReturn(driver, -1);

    if (virStateDriverTabCount >= MAX_DRIVERS) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR,
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
int virStateInitialize(bool privileged,
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
int virStateCleanup(void) {
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
int virStateReload(void) {
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
int virStateStop(void) {
    size_t i;
    int ret = 0;

    for (i = 0; i < virStateDriverTabCount; i++) {
        if (virStateDriverTab[i]->stateStop &&
            virStateDriverTab[i]->stateStop())
            ret = 1;
    }
    return ret;
}

#endif



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
 * get the version of the running hypervisor use the virConnectGetVersion
 * function instead. To get the libvirt library version used by a
 * connection use the virConnectGetLibVersion instead.
 *
 * Returns -1 in case of failure, 0 otherwise, and values for @libVer and
 *       @typeVer have the format major * 1,000,000 + minor * 1,000 + release.
 */
int
virGetVersion(unsigned long *libVer, const char *type ATTRIBUTE_UNUSED,
              unsigned long *typeVer)
{
    VIR_DEBUG("libVir=%p, type=%s, typeVer=%p", libVer, type, typeVer);

    if (virInitialize() < 0)
        goto error;

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
virConnectOpenFindURIAliasMatch(virConfValuePtr value, const char *alias, char **uri)
{
    virConfValuePtr entry;
    size_t alias_len;

    if (value->type != VIR_CONF_LIST) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Expected a list for 'uri_aliases' config parameter"));
        return -1;
    }

    entry = value->list;
    alias_len = strlen(alias);
    while (entry) {
        char *offset;
        size_t safe;

        if (entry->type != VIR_CONF_STRING) {
            virLibConnError(VIR_ERR_CONF_SYNTAX, "%s",
                            _("Expected a string for 'uri_aliases' config parameter list entry"));
            return -1;
        }

        if (!(offset = strchr(entry->str, '='))) {
            virLibConnError(VIR_ERR_CONF_SYNTAX,
                            _("Malformed 'uri_aliases' config entry '%s', expected 'alias=uri://host/path'"),
                            entry->str);
            return -1;
        }

        safe  = strspn(entry->str, URI_ALIAS_CHARS);
        if (safe < (offset - entry->str)) {
            virLibConnError(VIR_ERR_CONF_SYNTAX,
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
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
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

    virResetLastError();

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
     *  If no URI is passed, then check for an environment string if not
     *  available probe the compiled in drivers to find a default hypervisor
     *  if detectable.
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

    for (i = 0; i < virDriverTabCount; i++) {
        /* We're going to probe the remote driver next. So we have already
         * probed all other client-side-only driver before, but none of them
         * accepted the URI.
         * If the scheme corresponds to a known but disabled client-side-only
         * driver then report a useful error, instead of a cryptic one about
         * not being able to connect to libvirtd or not being able to find
         * certificates. */
        if (virDriverTab[i]->no == VIR_DRV_REMOTE &&
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

        VIR_DEBUG("trying driver %zu (%s) ...", i, virDriverTab[i]->name);
        ret->driver = virDriverTab[i];
        res = virDriverTab[i]->connectOpen(ret, auth, flags);
        VIR_DEBUG("driver %zu %s returned %s",
                  i, virDriverTab[i]->name,
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
        virLibConnError(VIR_ERR_NO_CONNECT,
                        "%s",
                        NULLSTR(name));
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
 * Returns a pointer to the hypervisor connection or NULL in case of error
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
 * have an effect on opening drivers
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
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
    int ret = -1;
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }

    if (!virObjectUnref(conn))
        return 0;
    return 1;

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
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("conn=%p refs=%d", conn, conn->object.refs);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (!conn->driver->connectSupportsFeature)
        ret = 0;
    else
        ret = conn->driver->connectSupportsFeature(conn, feature);

    if (ret < 0)
        virDispatchError(conn);

    return ret;
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(hvVer, error);

    if (conn->driver->connectGetVersion) {
        int ret = conn->driver->connectGetVersion(conn, hvVer);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (conn->driver->connectGetHostname) {
        char *ret = conn->driver->connectGetHostname(conn);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (conn->driver->connectGetSysinfo) {
        char *ret = conn->driver->connectGetSysinfo(conn, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->connectGetMaxVcpus) {
        int ret = conn->driver->connectGetMaxVcpus(conn, type);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * Collect the list of active domains, and store their IDs in array @ids
 *
 * For inactive domains, see virConnectListDefinedDomains().  For more
 * control over the results, see virConnectListAllDomains().
 *
 * Returns the number of domains found or -1 in case of error.  Note that
 * this command is inherently racy; a domain can be started between a
 * call to virConnectNumOfDomains() and this call; you are only guaranteed
 * that all currently active domains were listed if the return is less
 * than @maxids.
 */
int
virConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    VIR_DEBUG("conn=%p, ids=%p, maxids=%d", conn, ids, maxids);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(ids, error);
    virCheckNonNegativeArgGoto(maxids, error);

    if (conn->driver->connectListDomains) {
        int ret = conn->driver->connectListDomains(conn, ids, maxids);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->connectNumOfDomains) {
        int ret = conn->driver->connectNumOfDomains(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
virDomainGetConnect(virDomainPtr dom)
{
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return dom->conn;
}

/**
 * virDomainCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a new guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may require privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, the guest domain
 * will be started, but its CPUs will remain paused. The CPUs
 * can later be manually started using virDomainResume.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateXML(virConnectPtr conn, const char *xmlDesc,
                   unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlDesc, error);
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreateXML) {
        virDomainPtr ret;
        ret = conn->driver->domainCreateXML(conn, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainCreateXMLWithFiles:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @nfiles: number of file descriptors passed
 * @files: list of file descriptors passed
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a new guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may require privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * @files provides an array of file descriptors which will be
 * made available to the 'init' process of the guest. The file
 * handles exposed to the guest will be renumbered to start
 * from 3 (ie immediately following stderr). This is only
 * supported for guests which use container based virtualization
 * technology.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, the guest domain
 * will be started, but its CPUs will remain paused. The CPUs
 * can later be manually started using virDomainResume.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateXMLWithFiles(virConnectPtr conn, const char *xmlDesc,
                            unsigned int nfiles,
                            int *files,
                            unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, nfiles=%u, files=%p, flags=%x",
              conn, xmlDesc, nfiles, files, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlDesc, error);
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreateXMLWithFiles) {
        virDomainPtr ret;
        ret = conn->driver->domainCreateXMLWithFiles(conn, xmlDesc,
                                                     nfiles, files,
                                                     flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    return virDomainCreateXML(conn, xmlDesc, flags);
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
    VIR_DEBUG("conn=%p, id=%d", conn, id);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNegativeArgGoto(id, error);

    if (conn->driver->domainLookupByID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByID(conn, id);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuid, error);

    if (conn->driver->domainLookupByUUID) {
        virDomainPtr ret;
        ret = conn->driver->domainLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
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
    VIR_DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(name, error);

    if (conn->driver->domainLookupByName) {
        virDomainPtr dom;
        dom = conn->driver->domainLookupByName(conn, name);
        if (!dom)
            goto error;
        return dom;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * This function may require privileged access.
 *
 * virDomainDestroy first requests that a guest terminate
 * (e.g. SIGTERM), then waits for it to comply. After a reasonable
 * timeout, if the guest still exists, virDomainDestroy will
 * forcefully terminate the guest (e.g. SIGKILL) if necessary (which
 * may produce undesirable results, for example unflushed disk cache
 * in the guest). To avoid this possibility, it's recommended to
 * instead call virDomainDestroyFlags, sending the
 * VIR_DOMAIN_DESTROY_GRACEFUL flag.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainDestroy) {
        int ret;
        ret = conn->driver->domainDestroy(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainDestroyFlags:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainDestroyFlagsValues
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 * This does not free the associated virDomainPtr object.
 * This function may require privileged access.
 *
 * Calling this function with no @flags set (equal to zero) is
 * equivalent to calling virDomainDestroy, and after a reasonable
 * timeout will forcefully terminate the guest (e.g. SIGKILL) if
 * necessary (which may produce undesirable results, for example
 * unflushed disk cache in the guest). Including
 * VIR_DOMAIN_DESTROY_GRACEFUL in the flags will prevent the forceful
 * termination of the guest, and virDomainDestroyFlags will instead
 * return an error if the guest doesn't terminate by the end of the
 * timeout; at that time, the management application can decide if
 * calling again without VIR_DOMAIN_DESTROY_GRACEFUL is appropriate.
 *
 * Another alternative which may produce cleaner results for the
 * guest's disks is to use virDomainShutdown() instead, but that
 * depends on guest support (some hypervisor/guest combinations may
 * ignore the shutdown request).
 *
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroyFlags(virDomainPtr domain,
                      unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainDestroyFlags) {
        int ret;
        ret = conn->driver->domainDestroyFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(domain);
    return 0;
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
        virLibConnError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    VIR_DOMAIN_DEBUG(domain, "refs=%d", domain->object.refs);
    virObjectRef(domain);
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
 * This function may require privileged access.
 * Moreover, suspend may not be supported if domain is in some
 * special state like VIR_DOMAIN_PMSUSPENDED.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainSuspend) {
        int ret;
        ret = conn->driver->domainSuspend(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume a suspended domain, the process is restarted from the state where
 * it was frozen by calling virDomainSuspend().
 * This function may require privileged access
 * Moreover, resume may not be supported if domain is in some
 * special state like VIR_DOMAIN_PMSUSPENDED.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainResume) {
        int ret;
        ret = conn->driver->domainResume(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainPMSuspendForDuration:
 * @dom: a domain object
 * @target: a value from virNodeSuspendTarget
 * @duration: duration in seconds to suspend, or 0 for indefinite
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Attempt to have the guest enter the given @target power management
 * suspension level.  If @duration is non-zero, also schedule the guest to
 * resume normal operation after that many seconds, if nothing else has
 * resumed it earlier.  Some hypervisors require that @duration be 0, for
 * an indefinite suspension.
 *
 * Dependent on hypervisor used, this may require a
 * guest agent to be available, e.g. QEMU.
 *
 * Beware that at least for QEMU, the domain's process will be terminated
 * when VIR_NODE_SUSPEND_TARGET_DISK is used and a new process will be
 * launched when libvirt is asked to wake up the domain. As a result of
 * this, any runtime changes, such as device hotplug or memory settings,
 * are lost unless such changes were made with VIR_DOMAIN_AFFECT_CONFIG
 * flag.
 *
 * Returns: 0 on success,
 *          -1 on failure.
 */
int
virDomainPMSuspendForDuration(virDomainPtr dom,
                              unsigned int target,
                              unsigned long long duration,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "target=%u duration=%llu flags=%x",
                     target, duration, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainPMSuspendForDuration) {
        int ret;
        ret = conn->driver->domainPMSuspendForDuration(dom, target,
                                                       duration, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainPMWakeup:
 * @dom: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Inject a wakeup into the guest that previously used
 * virDomainPMSuspendForDuration, rather than waiting for the
 * previously requested duration (if any) to elapse.
 *
 * Returns: 0 on success,
 *          -1 on failure.
 */
int
virDomainPMWakeup(virDomainPtr dom,
                  unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainPMWakeup) {
        int ret;
        ret = conn->driver->domainPMWakeup(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSave:
 * @domain: a domain object
 * @to: path for the output file
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this ends the life of a transient domain).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * See virDomainSaveFlags() for more control.  Also, a save file can
 * be inspected or modified slightly with virDomainSaveImageGetXMLDesc()
 * and virDomainSaveImageDefineXML().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSave(virDomainPtr domain, const char *to)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s", to);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;
    virCheckNonNullArgGoto(to, error);

    if (conn->driver->domainSave) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute output file path"));
            goto error;
        }

        ret = conn->driver->domainSave(domain, absolute_to);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSaveFlags:
 * @domain: a domain object
 * @to: path for the output file
 * @dxml: (optional) XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore (this ends the life of a transient domain).
 * Use virDomainRestore() to restore a domain after saving.
 *
 * If the hypervisor supports it, @dxml can be used to alter
 * host-specific portions of the domain XML that will be used when
 * restoring an image.  For example, it is possible to alter the
 * backing filename that is associated with a disk device, in order to
 * prepare for file renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while creating the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override what state gets saved into the file.  These
 * two flags are mutually exclusive.
 *
 * A save file can be inspected or modified slightly with
 * virDomainSaveImageGetXMLDesc() and virDomainSaveImageDefineXML().
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation; in that case, use virDomainBlockJobAbort()
 * to stop the block copy first.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSaveFlags(virDomainPtr domain, const char *to,
                   const char *dxml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s, dxml=%s, flags=%x",
                     to, NULLSTR(dxml), flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;
    virCheckNonNullArgGoto(to, error);

    if ((flags & VIR_DOMAIN_SAVE_RUNNING) && (flags & VIR_DOMAIN_SAVE_PAUSED)) {
        virReportInvalidArg(flags, "%s",
                            _("running and paused flags are mutually exclusive"));
        goto error;
    }

    if (conn->driver->domainSaveFlags) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute output file path"));
            goto error;
        }

        ret = conn->driver->domainSaveFlags(domain, absolute_to, dxml, flags);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainRestore:
 * @conn: pointer to the hypervisor connection
 * @from: path to the input file
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * See virDomainRestoreFlags() for more control.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestore(virConnectPtr conn, const char *from)
{
    VIR_DEBUG("conn=%p, from=%s", conn, from);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(from, error);

    if (conn->driver->domainRestore) {
        int ret;
        char *absolute_from;

        /* We must absolutize the file path as the restore is done out of process */
        if (virFileAbsPath(from, &absolute_from) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainRestore(conn, absolute_from);

        VIR_FREE(absolute_from);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainRestoreFlags:
 * @conn: pointer to the hypervisor connection
 * @from: path to the input file
 * @dxml: (optional) XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will restore a domain saved to disk by virDomainSave().
 *
 * If the hypervisor supports it, @dxml can be used to alter
 * host-specific portions of the domain XML that will be used when
 * restoring an image.  For example, it is possible to alter the
 * backing filename that is associated with a disk device, in order to
 * prepare for file renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while restoring the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing restores from NFS.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default read from the file.  These two
 * flags are mutually exclusive.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainRestoreFlags(virConnectPtr conn, const char *from, const char *dxml,
    unsigned int flags)
{
    VIR_DEBUG("conn=%p, from=%s, dxml=%s, flags=%x",
              conn, from, NULLSTR(dxml), flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(from, error);

    if ((flags & VIR_DOMAIN_SAVE_RUNNING) && (flags & VIR_DOMAIN_SAVE_PAUSED)) {
        virReportInvalidArg(flags, "%s",
                            _("running and paused flags are mutually exclusive"));
        goto error;
    }

    if (conn->driver->domainRestoreFlags) {
        int ret;
        char *absolute_from;

        /* We must absolutize the file path as the restore is done out of process */
        if (virFileAbsPath(from, &absolute_from) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainRestoreFlags(conn, absolute_from, dxml,
                                               flags);

        VIR_FREE(absolute_from);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSaveImageGetXMLDesc:
 * @conn: pointer to the hypervisor connection
 * @file: path to saved state file
 * @flags: bitwise-OR of subset of virDomainXMLFlags
 *
 * This method will extract the XML describing the domain at the time
 * a saved state file was created.  @file must be a file created
 * previously by virDomainSave() or virDomainSaveFlags().
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_XML_SECURE; this flag is rejected on read-only
 * connections.  For this API, @flags should not contain either
 * VIR_DOMAIN_XML_INACTIVE or VIR_DOMAIN_XML_UPDATE_CPU.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of
 * error.  The caller must free() the returned value.
 */
char *
virDomainSaveImageGetXMLDesc(virConnectPtr conn, const char *file,
                             unsigned int flags)
{
    VIR_DEBUG("conn=%p, file=%s, flags=%x",
              conn, file, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(file, error);

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, "%s",
                        _("virDomainSaveImageGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainSaveImageGetXMLDesc) {
        char *ret;
        char *absolute_file;

        /* We must absolutize the file path as the read is done out of process */
        if (virFileAbsPath(file, &absolute_file) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainSaveImageGetXMLDesc(conn, absolute_file,
                                                      flags);

        VIR_FREE(absolute_file);

        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSaveImageDefineXML:
 * @conn: pointer to the hypervisor connection
 * @file: path to saved state file
 * @dxml: XML config for adjusting guest xml used on restore
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This updates the definition of a domain stored in a saved state
 * file.  @file must be a file created previously by virDomainSave()
 * or virDomainSaveFlags().
 *
 * @dxml can be used to alter host-specific portions of the domain XML
 * that will be used when restoring an image.  For example, it is
 * possible to alter the backing filename that is associated with a
 * disk device, to match renaming done as part of backing up the disk
 * device while the domain is stopped.
 *
 * Normally, the saved state file will remember whether the domain was
 * running or paused, and restore defaults to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default saved into the file; omitting both
 * leaves the file's default unchanged.  These two flags are mutually
 * exclusive.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSaveImageDefineXML(virConnectPtr conn, const char *file,
                            const char *dxml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, file=%s, dxml=%s, flags=%x",
              conn, file, dxml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(file, error);
    virCheckNonNullArgGoto(dxml, error);

    if ((flags & VIR_DOMAIN_SAVE_RUNNING) && (flags & VIR_DOMAIN_SAVE_PAUSED)) {
        virReportInvalidArg(flags, "%s",
                            _("running and paused flags are mutually exclusive"));
        goto error;
    }

    if (conn->driver->domainSaveImageDefineXML) {
        int ret;
        char *absolute_file;

        /* We must absolutize the file path as the read is done out of process */
        if (virFileAbsPath(file, &absolute_file) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute input file path"));
            goto error;
        }

        ret = conn->driver->domainSaveImageDefineXML(conn, absolute_file,
                                                     dxml, flags);

        VIR_FREE(absolute_file);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainCoreDump:
 * @domain: a domain object
 * @to: path for the core file
 * @flags: bitwise-OR of virDomainCoreDumpFlags
 *
 * This method will dump the core of a domain on a given file for analysis.
 * Note that for remote Xen Daemon the file path will be interpreted in
 * the remote host. Hypervisors may require  the user to manually ensure
 * proper permissions on the file named by @to.
 *
 * If @flags includes VIR_DUMP_CRASH, then leave the guest shut off with
 * a crashed state after the dump completes.  If @flags includes
 * VIR_DUMP_LIVE, then make the core dump while continuing to allow
 * the guest to run; otherwise, the guest is suspended during the dump.
 * VIR_DUMP_RESET flag forces reset of the quest after dump.
 * The above three flags are mutually exclusive.
 *
 * Additionally, if @flags includes VIR_DUMP_BYPASS_CACHE, then libvirt
 * will attempt to bypass the file system cache while creating the file,
 * or fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainCoreDump(virDomainPtr domain, const char *to, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "to=%s, flags=%x", to, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;
    virCheckNonNullArgGoto(to, error);

    if ((flags & VIR_DUMP_CRASH) && (flags & VIR_DUMP_LIVE)) {
        virReportInvalidArg(flags, "%s",
                            _("crash and live flags are mutually exclusive"));
        goto error;
    }

    if ((flags & VIR_DUMP_CRASH) && (flags & VIR_DUMP_RESET)) {
        virReportInvalidArg(flags, "%s",
                         _("crash and reset flags are mutually exclusive"));
        goto error;
    }

    if ((flags & VIR_DUMP_LIVE) && (flags & VIR_DUMP_RESET)) {
        virReportInvalidArg(flags, "%s",
                            _("live and reset flags are mutually exclusive"));
        goto error;
    }

    if (conn->driver->domainCoreDump) {
        int ret;
        char *absolute_to;

        /* We must absolutize the file path as the save is done out of process */
        if (virFileAbsPath(to, &absolute_to) < 0) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("could not build absolute core file path"));
            goto error;
        }

        ret = conn->driver->domainCoreDump(domain, absolute_to, flags);

        VIR_FREE(absolute_to);

        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainScreenshot:
 * @domain: a domain object
 * @stream: stream to use as output
 * @screen: monitor ID to take screenshot from
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Take a screenshot of current domain console as a stream. The image format
 * is hypervisor specific. Moreover, some hypervisors supports multiple
 * displays per domain. These can be distinguished by @screen argument.
 *
 * This call sets up a stream; subsequent use of stream API is necessary
 * to transfer actual data, determine how much data is successfully
 * transferred, and detect any errors.
 *
 * The screen ID is the sequential number of screen. In case of multiple
 * graphics cards, heads are enumerated before devices, e.g. having
 * two graphics cards, both with four heads, screen ID 5 addresses
 * the second head on the second card.
 *
 * Returns a string representing the mime-type of the image format, or
 * NULL upon error. The caller must free() the returned value.
 */
char *
virDomainScreenshot(virDomainPtr domain,
                    virStreamPtr stream,
                    unsigned int screen,
                    unsigned int flags)
{
    VIR_DOMAIN_DEBUG(domain, "stream=%p, flags=%x", stream, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (!VIR_IS_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_STREAM, __FUNCTION__);
        return NULL;
    }
    if (domain->conn->flags & VIR_CONNECT_RO ||
        stream->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (domain->conn->driver->domainScreenshot) {
        char * ret;
        ret = domain->conn->driver->domainScreenshot(domain, stream,
                                                     screen, flags);

        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
}

/**
 * virDomainShutdown:
 * @domain: a domain object
 *
 * Shutdown a domain, the domain object is still usable thereafter, but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request. Additionally, the hypervisor may check and support the domain
 * 'on_poweroff' XML setting resulting in a domain that reboots instead of
 * shutting down. For guests that react to a shutdown request, the differences
 * from virDomainDestroy() are that the guests disk storage will be in a
 * stable state rather than having the (virtual) power cord pulled, and
 * this command returns as soon as the shutdown request is issued rather
 * than blocking until the guest is no longer running.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdown(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainShutdown) {
        int ret;
        ret = conn->driver->domainShutdown(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainShutdownFlags:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainShutdownFlagValues
 *
 * Shutdown a domain, the domain object is still usable thereafter but
 * the domain OS is being stopped. Note that the guest OS may ignore the
 * request. Additionally, the hypervisor may check and support the domain
 * 'on_poweroff' XML setting resulting in a domain that reboots instead of
 * shutting down. For guests that react to a shutdown request, the differences
 * from virDomainDestroy() are that the guest's disk storage will be in a
 * stable state rather than having the (virtual) power cord pulled, and
 * this command returns as soon as the shutdown request is issued rather
 * than blocking until the guest is no longer running.
 *
 * If the domain is transient and has any snapshot metadata (see
 * virDomainSnapshotNum()), then that metadata will automatically
 * be deleted when the domain quits.
 *
 * If @flags is set to zero, then the hypervisor will choose the
 * method of shutdown it considers best. To have greater control
 * pass one or more of the virDomainShutdownFlagValues. The order
 * in which the hypervisor tries each shutdown method is undefined,
 * and a hypervisor is not required to support all methods.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainShutdownFlags(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainShutdownFlags) {
        int ret;
        ret = conn->driver->domainShutdownFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainReboot:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainRebootFlagValues
 *
 * Reboot a domain, the domain object is still usable thereafter, but
 * the domain OS is being stopped for a restart.
 * Note that the guest OS may ignore the request.
 * Additionally, the hypervisor may check and support the domain
 * 'on_reboot' XML setting resulting in a domain that shuts down instead
 * of rebooting.
 *
 * If @flags is set to zero, then the hypervisor will choose the
 * method of shutdown it considers best. To have greater control
 * pass one or more of the virDomainShutdownFlagValues. The order
 * in which the hypervisor tries each shutdown method is undefined,
 * and a hypervisor is not required to support all methods.
 *
 * To use guest agent (VIR_DOMAIN_REBOOT_GUEST_AGENT) the domain XML
 * must have <channel> configured.
 *
 * Due to implementation limitations in some drivers (the qemu driver,
 * for instance) it is not advised to migrate or save a guest that is
 * rebooting as a result of this API. Migrating such a guest can lead
 * to a plain shutdown on the destination.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainReboot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainReboot) {
        int ret;
        ret = conn->driver->domainReboot(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainReset:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reset a domain immediately without any guest OS shutdown.
 * Reset emulates the power reset button on a machine, where all
 * hardware sees the RST line set and reinitializes internal state.
 *
 * Note that there is a risk of data loss caused by reset without any
 * guest OS shutdown.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainReset(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainReset) {
        int ret;
        ret = conn->driver->domainReset(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("domain=%p", domain);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return domain->name;
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
    VIR_DOMAIN_DEBUG(domain, "uuid=%p", uuid);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgReturn(uuid, -1);

    memcpy(uuid, &domain->uuid[0], VIR_UUID_BUFLEN);

    return 0;
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

    VIR_DOMAIN_DEBUG(domain, "buf=%p", buf);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(buf, error);

    if (virDomainGetUUID(domain, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return 0;

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
    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return (unsigned int)-1;
    }
    return domain->id;
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

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    if (conn->driver->domainGetOSType) {
        char *ret;
        ret = conn->driver->domainGetOSType(domain);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Returns the memory size in kibibytes (blocks of 1024 bytes), or 0 in
 * case of error.
 */
unsigned long
virDomainGetMaxMemory(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return 0;
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxMemory) {
        unsigned long long ret;
        ret = conn->driver->domainGetMaxMemory(domain);
        if (ret == 0)
            goto error;
        if ((unsigned long) ret != ret) {
            virLibDomainError(VIR_ERR_OVERFLOW, _("result too large: %llu"),
                              ret);
            goto error;
        }
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return 0;
}

/**
 * virDomainSetMaxMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 *
 * Dynamically change the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
 *
 * This command is hypervisor-specific for whether active, persistent,
 * or both configurations are changed; for more control, use
 * virDomainSetMemoryFlags().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "memory=%lu", memory);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonZeroArgGoto(memory, error);

    conn = domain->conn;

    if (conn->driver->domainSetMaxMemory) {
        int ret;
        ret = conn->driver->domainSetMaxMemory(domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 *
 * Dynamically change the target amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
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

    VIR_DOMAIN_DEBUG(domain, "memory=%lu", memory);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonZeroArgGoto(memory, error);

    conn = domain->conn;

    if (conn->driver->domainSetMemory) {
        int ret;
        ret = conn->driver->domainSetMemory(domain, memory);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetMemoryFlags:
 * @domain: a domain object or NULL
 * @memory: the memory size in kibibytes (blocks of 1024 bytes)
 * @flags: bitwise-OR of virDomainMemoryModFlags
 *
 * Dynamically change the target amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set. If VIR_DOMAIN_AFFECT_LIVE is set, the change affects
 * a running domain and will fail if domain is not active.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified
 * (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain
 * modifies persistent setup, while an active domain is hypervisor-dependent
 * on whether just live or both live and persistent state is changed.
 * If VIR_DOMAIN_MEM_MAXIMUM is set, the change affects domain's maximum memory
 * size rather than current memory size.
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetMemoryFlags(virDomainPtr domain, unsigned long memory,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "memory=%lu, flags=%x", memory, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonZeroArgGoto(memory, error);

    conn = domain->conn;

    if (conn->driver->domainSetMemoryFlags) {
        int ret;
        ret = conn->driver->domainSetMemoryFlags(domain, memory, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetMemoryStatsPeriod:
 * @domain: a domain object or NULL
 * @period: the period in seconds for stats collection
 * @flags: bitwise-OR of virDomainMemoryModFlags
 *
 * Dynamically change the domain memory balloon driver statistics collection
 * period. Use 0 to disable and a positive value to enable.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set. If VIR_DOMAIN_AFFECT_LIVE is set, the change affects
 * a running domain and will fail if domain is not active.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified
 * (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain
 * modifies persistent setup, while an active domain is hypervisor-dependent
 * on whether just live or both live and persistent state is changed.
 *
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetMemoryStatsPeriod(virDomainPtr domain, int period,
                              unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "peroid=%d, flags=%x", period, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* This must be positive to set the balloon collection period */
    virCheckNonNegativeArgGoto(period, error);

    conn = domain->conn;

    if (conn->driver->domainSetMemoryStatsPeriod) {
        int ret;
        ret = conn->driver->domainSetMemoryStatsPeriod(domain, period, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/* Helper function called to validate incoming client array on any
 * interface that sets typed parameters in the hypervisor.  */
static int
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
 * virDomainSetMemoryParameters:
 * @domain: pointer to domain object
 * @params: pointer to memory parameter objects
 * @nparams: number of memory parameter (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the memory tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetMemoryParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);

    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetMemoryParameters) {
        int ret;
        ret = conn->driver->domainSetMemoryParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetMemoryParameters:
 * @domain: pointer to domain object
 * @params: pointer to memory parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of memory parameters; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all memory parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * Here is a sample code snippet:
 *
 *   if ((virDomainGetMemoryParameters(dom, NULL, &nparams, 0) == 0) &&
 *       (nparams != 0)) {
 *       if ((params = malloc(sizeof(*params) * nparams)) == NULL)
 *           goto error;
 *       memset(params, 0, sizeof(*params) * nparams);
 *       if (virDomainGetMemoryParameters(dom, params, &nparams, 0))
 *           goto error;
 *   }
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetMemoryParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetMemoryParameters) {
        int ret;
        ret = conn->driver->domainGetMemoryParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetNumaParameters:
 * @domain: pointer to domain object
 * @params: pointer to numa parameter objects
 * @nparams: number of numa parameters (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the numa tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetNumaParameters(virDomainPtr domain,
                           virTypedParameterPtr params,
                           int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);
    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetNumaParameters) {
        int ret;
        ret = conn->driver->domainSetNumaParameters(domain, params, nparams,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetNumaParameters:
 * @domain: pointer to domain object
 * @params: pointer to numa parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of numa parameters
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all numa parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * See virDomainGetMemoryParameters() for an equivalent usage example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */

int
virDomainGetNumaParameters(virDomainPtr domain,
                           virTypedParameterPtr params,
                           int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    conn = domain->conn;

    if (conn->driver->domainGetNumaParameters) {
        int ret;
        ret = conn->driver->domainGetNumaParameters(domain, params, nparams,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetBlkioParameters:
 * @domain: pointer to domain object
 * @params: pointer to blkio parameter objects
 * @nparams: number of blkio parameters (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the blkio tunables.
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetBlkioParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetBlkioParameters) {
        int ret;
        ret = conn->driver->domainSetBlkioParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetBlkioParameters:
 * @domain: pointer to domain object
 * @params: pointer to blkio parameter object
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of blkio parameters; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all blkio parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.
 *
 * See virDomainGetMemoryParameters() for an equivalent usage example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetBlkioParameters(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetBlkioParameters) {
        int ret;
        ret = conn->driver->domainGetBlkioParameters(domain, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "info=%p", info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);

    memset(info, 0, sizeof(virDomainInfo));

    conn = domain->conn;

    if (conn->driver->domainGetInfo) {
        int ret;
        ret = conn->driver->domainGetInfo(domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetState:
 * @domain: a domain object
 * @state: returned state of the domain (one of virDomainState)
 * @reason: returned reason which led to @state (one of virDomain*Reason
 * corresponding to the current state); it is allowed to be NULL
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract domain state. Each state can be accompanied with a reason (if known)
 * which led to the state.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetState(virDomainPtr domain,
                  int *state,
                  int *reason,
                  unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "state=%p, reason=%p, flags=%x",
                     state, reason, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(state, error);

    conn = domain->conn;
    if (conn->driver->domainGetState) {
        int ret;
        ret = conn->driver->domainGetState(domain, state, reason, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetControlInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainControlInfo structure allocated by the user
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract details about current state of control interface to a domain.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetControlInfo(virDomainPtr domain,
                        virDomainControlInfoPtr info,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, flags=%x", info, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(info, error);

    conn = domain->conn;
    if (conn->driver->domainGetControlInfo) {
        int ret;
        ret = conn->driver->domainGetControlInfo(domain, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetXMLDesc:
 * @domain: a domain object
 * @flags: bitwise-OR of virDomainXMLFlags
 *
 * Provide an XML description of the domain. The description may be reused
 * later to relaunch the domain with virDomainCreateXML().
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_XML_SECURE; this flag is rejected on read-only
 * connections.  If @flags includes VIR_DOMAIN_XML_INACTIVE, then the
 * XML represents the configuration that will be used on the next boot
 * of a persistent domain; otherwise, the configuration represents the
 * currently running domain.  If @flags contains
 * VIR_DOMAIN_XML_UPDATE_CPU, then the portion of the domain XML
 * describing CPU capabilities is modified to match actual
 * capabilities of the host.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, "%s",
                        _("virDomainGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainGetXMLDesc) {
        char *ret;
        ret = conn->driver->domainGetXMLDesc(domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
}

/**
 * virConnectDomainXMLFromNative:
 * @conn: a connection object
 * @nativeFormat: configuration format importing from
 * @nativeConfig: the configuration data to import
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, format=%s, config=%s, flags=%x",
              conn, nativeFormat, nativeConfig, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(nativeFormat, error);
    virCheckNonNullArgGoto(nativeConfig, error);

    if (conn->driver->connectDomainXMLFromNative) {
        char *ret;
        ret = conn->driver->connectDomainXMLFromNative(conn,
                                                       nativeFormat,
                                                       nativeConfig,
                                                       flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virConnectDomainXMLToNative:
 * @conn: a connection object
 * @nativeFormat: configuration format exporting to
 * @domainXml: the domain configuration to export
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reads a domain XML configuration document, and generates
 * a native configuration file describing the domain.
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
    VIR_DEBUG("conn=%p, format=%s, xml=%s, flags=%x",
              conn, nativeFormat, domainXml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(nativeFormat, error);
    virCheckNonNullArgGoto(domainXml, error);

    if (conn->driver->connectDomainXMLToNative) {
        char *ret;
        ret = conn->driver->connectDomainXMLToNative(conn,
                                                     nativeFormat,
                                                     domainXml,
                                                     flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}


/*
 * Sequence v1:
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Kill off VM if successful, resume if failed
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if unsuccessful
 *
 */
static virDomainPtr
virDomainMigrateVersion1(virDomainPtr domain,
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
    unsigned int destflags;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    ret = virDomainGetInfo(domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~VIR_MIGRATE_ABORT_ON_ERROR;

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
        (dconn, &cookie, &cookielen, uri, &uri_out, destflags, dname,
         bandwidth) == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("domainMigratePrepare did not set uri"));
        goto done;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare change URI? */

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
            (dconn, dname, cookie, cookielen, uri, destflags);
    else
        ddomain = virDomainLookupByName(dconn, dname);

 done:
    VIR_FREE(uri_out);
    VIR_FREE(cookie);
    return ddomain;
}

/*
 * Sequence v2:
 *
 *  Src: DumpXML
 *        - Generate XML to pass to dst
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Kill off VM if successful, resume if failed
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if unsuccessful
 *
 */
static virDomainPtr
virDomainMigrateVersion2(virDomainPtr domain,
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
    unsigned int getxml_flags = 0;
    int cancelled;
    unsigned long destflags;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

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
    if (!domain->conn->driver->domainGetXMLDesc) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        virDispatchError(domain->conn);
        return NULL;
    }

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_XML_MIGRATABLE)) {
        getxml_flags |= VIR_DOMAIN_XML_MIGRATABLE;
    } else {
        getxml_flags |= VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_UPDATE_CPU;
    }

    dom_xml = domain->conn->driver->domainGetXMLDesc(domain, getxml_flags);
    if (!dom_xml)
        return NULL;

    ret = virDomainGetInfo(domain, &info);
    if (ret == 0 && info.state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~VIR_MIGRATE_ABORT_ON_ERROR;

    VIR_DEBUG("Prepare2 %p flags=%lx", dconn, destflags);
    ret = dconn->driver->domainMigratePrepare2
        (dconn, &cookie, &cookielen, uri, &uri_out, destflags, dname,
         bandwidth, dom_xml);
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto done;

    if (uri == NULL && uri_out == NULL) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("domainMigratePrepare2 did not set uri"));
        virDispatchError(domain->conn);
        cancelled = 1;
        goto finish;
    }
    if (uri_out)
        uri = uri_out; /* Did domainMigratePrepare2 change URI? */

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", domain->conn);
    ret = domain->conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : domain->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen, uri, destflags, cancelled);

 done:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookie);
    return ddomain;
}


/*
 * Sequence v3:
 *
 *  Src: Begin
 *        - Generate XML to pass to dst
 *        - Generate optional cookie to pass to dst
 *
 *  Dst: Prepare
 *        - Get ready to accept incoming VM
 *        - Generate optional cookie to pass to src
 *
 *  Src: Perform
 *        - Start migration and wait for send completion
 *        - Generate optional cookie to pass to dst
 *
 *  Dst: Finish
 *        - Wait for recv completion and check status
 *        - Kill off VM if failed, resume if success
 *        - Generate optional cookie to pass to src
 *
 *  Src: Confirm
 *        - Kill off VM if success, resume if failed
 *
  * If useParams is true, params and nparams contain migration parameters and
  * we know it's safe to call the API which supports extensible parameters.
  * Otherwise, we have to use xmlin, dname, uri, and bandwidth and pass them
  * to the old-style APIs.
 */
static virDomainPtr
virDomainMigrateVersion3Full(virDomainPtr domain,
                             virConnectPtr dconn,
                             const char *xmlin,
                             const char *dname,
                             const char *uri,
                             unsigned long long bandwidth,
                             virTypedParameterPtr params,
                             int nparams,
                             bool useParams,
                             unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    char *dom_xml = NULL;
    int cookieinlen = 0;
    int cookieoutlen = 0;
    int ret;
    virDomainInfo info;
    virErrorPtr orig_err = NULL;
    int cancelled = 1;
    unsigned long protection = 0;
    bool notify_source = true;
    unsigned int destflags;
    int state;
    virTypedParameterPtr tmp;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, xmlin=%s, dname=%s, uri=%s, bandwidth=%llu, "
                     "params=%p, nparams=%d, useParams=%d, flags=%x",
                     dconn, NULLSTR(xmlin), NULLSTR(dname), NULLSTR(uri),
                     bandwidth, params, nparams, useParams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    if ((!useParams &&
         (!domain->conn->driver->domainMigrateBegin3 ||
          !domain->conn->driver->domainMigratePerform3 ||
          !domain->conn->driver->domainMigrateConfirm3 ||
          !dconn->driver->domainMigratePrepare3 ||
          !dconn->driver->domainMigrateFinish3)) ||
        (useParams &&
         (!domain->conn->driver->domainMigrateBegin3Params ||
          !domain->conn->driver->domainMigratePerform3Params ||
          !domain->conn->driver->domainMigrateConfirm3Params ||
          !dconn->driver->domainMigratePrepare3Params ||
          !dconn->driver->domainMigrateFinish3Params))) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return NULL;
    }

    if (virTypedParamsCopy(&tmp, params, nparams) < 0)
        return NULL;
    params = tmp;

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION))
        protection = VIR_MIGRATE_CHANGE_PROTECTION;

    VIR_DEBUG("Begin3 %p", domain->conn);
    if (useParams) {
        dom_xml = domain->conn->driver->domainMigrateBegin3Params
            (domain, params, nparams, &cookieout, &cookieoutlen,
             flags | protection);
    } else {
        dom_xml = domain->conn->driver->domainMigrateBegin3
            (domain, xmlin, &cookieout, &cookieoutlen,
             flags | protection, dname, bandwidth);
    }
    if (!dom_xml)
        goto done;

    if (useParams) {
        /* If source is new enough to support extensible migration parameters,
         * it's certainly new enough to support virDomainGetState. */
        ret = virDomainGetState(domain, &state, NULL, 0);
    } else {
        ret = virDomainGetInfo(domain, &info);
        state = info.state;
    }
    if (ret == 0 && state == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~VIR_MIGRATE_ABORT_ON_ERROR;

    VIR_DEBUG("Prepare3 %p flags=%x", dconn, destflags);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (useParams) {
        if (virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_XML,
                                        dom_xml) < 0)
            goto done;
        ret = dconn->driver->domainMigratePrepare3Params
            (dconn, params, nparams, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, &uri_out, destflags);
    } else {
        ret = dconn->driver->domainMigratePrepare3
            (dconn, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             uri, &uri_out, destflags, dname, bandwidth, dom_xml);
    }
    if (ret == -1) {
        if (protection) {
            /* Begin already started a migration job so we need to cancel it by
             * calling Confirm while making sure it doesn't overwrite the error
             */
            orig_err = virSaveLastError();
            goto confirm;
        } else {
            goto done;
        }
    }

    /* Did domainMigratePrepare3 change URI? */
    if (uri_out) {
        uri = uri_out;
        if (useParams &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_URI,
                                        uri_out) < 0)
            goto finish;
    } else if (!uri &&
               virTypedParamsGetString(params, nparams,
                                       VIR_MIGRATE_PARAM_URI, &uri) <= 0) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("domainMigratePrepare3 did not set uri"));
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        VIR_DEBUG("Offline migration, skipping Perform phase");
        VIR_FREE(cookieout);
        cookieoutlen = 0;
        cancelled = 0;
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s", domain->conn, uri);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    /* dconnuri not relevant in non-P2P modes, so left NULL here */
    if (useParams) {
        ret = domain->conn->driver->domainMigratePerform3Params
            (domain, NULL, params, nparams, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, flags | protection);
    } else {
        ret = domain->conn->driver->domainMigratePerform3
            (domain, NULL, cookiein, cookieinlen,
             &cookieout, &cookieoutlen, NULL,
             uri, flags | protection, dname, bandwidth);
    }

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0) {
        orig_err = virSaveLastError();
        /* Perform failed so we don't need to call confirm to let source know
         * about the failure.
         */
        notify_source = false;
    }

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0 ? 1 : 0;

finish:
    /*
     * The status code from the source is passed to the destination.
     * The dest can cleanup if the source indicated it failed to
     * send all migration data. Returns NULL for ddomain if
     * the dest was unable to complete migration.
     */
    VIR_DEBUG("Finish3 %p ret=%d", dconn, ret);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (useParams) {
        if (virTypedParamsGetString(params, nparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, NULL) <= 0 &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_NAME,
                                        domain->name) < 0) {
            ddomain = NULL;
        } else {
            ddomain = dconn->driver->domainMigrateFinish3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags, cancelled);
        }
    } else {
        dname = dname ? dname : domain->name;
        ddomain = dconn->driver->domainMigrateFinish3
            (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             NULL, uri, destflags, cancelled);
    }

    /* If ddomain is NULL, then we were unable to start
     * the guest on the target, and must restart on the
     * source. There is a small chance that the ddomain
     * is NULL due to an RPC failure, in which case
     * ddomain could in fact be running on the dest.
     * The lock manager plugins should take care of
     * safety in this scenario.
     */
    cancelled = ddomain == NULL ? 1 : 0;

    /* If finish3 set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        orig_err = virSaveLastError();

confirm:
    /*
     * If cancelled, then src VM will be restarted, else it will be killed.
     * Don't do this if migration failed on source and thus it was already
     * cancelled there.
     */
    if (notify_source) {
        VIR_DEBUG("Confirm3 %p ret=%d domain=%p", domain->conn, ret, domain);
        VIR_FREE(cookiein);
        cookiein = cookieout;
        cookieinlen = cookieoutlen;
        cookieout = NULL;
        cookieoutlen = 0;
        if (useParams) {
            ret = domain->conn->driver->domainMigrateConfirm3Params
                (domain, params, nparams, cookiein, cookieinlen,
                 flags | protection, cancelled);
        } else {
            ret = domain->conn->driver->domainMigrateConfirm3
                (domain, cookiein, cookieinlen,
                 flags | protection, cancelled);
        }
        /* If Confirm3 returns -1, there's nothing more we can
         * do, but fortunately worst case is that there is a
         * domain left in 'paused' state on source.
         */
        if (ret < 0) {
            VIR_WARN("Guest %s probably left in 'paused' state on source",
                     domain->name);
        }
    }

 done:
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(dom_xml);
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);
    virTypedParamsFree(params, nparams);
    return ddomain;
}

static virDomainPtr
virDomainMigrateVersion3(virDomainPtr domain,
                         virConnectPtr dconn,
                         const char *xmlin,
                         unsigned long flags,
                         const char *dname,
                         const char *uri,
                         unsigned long bandwidth)
{
    return virDomainMigrateVersion3Full(domain, dconn, xmlin, dname, uri,
                                        bandwidth, NULL, 0, false, flags);
}

static virDomainPtr
virDomainMigrateVersion3Params(virDomainPtr domain,
                               virConnectPtr dconn,
                               virTypedParameterPtr params,
                               int nparams,
                               unsigned int flags)
{
    return virDomainMigrateVersion3Full(domain, dconn, NULL, NULL, NULL, 0,
                                        params, nparams, true, flags);
}


 /*
  * In normal migration, the libvirt client co-ordinates communication
  * between the 2 libvirtd instances on source & dest hosts.
  *
  * In this peer-2-peer migration alternative, the libvirt client
  * only talks to the source libvirtd instance. The source libvirtd
  * then opens its own connection to the destination and co-ordinates
  * migration itself.
  *
  * If useParams is true, params and nparams contain migration parameters and
  * we know it's safe to call the API which supports extensible parameters.
  * Otherwise, we have to use xmlin, dname, uri, and bandwidth and pass them
  * to the old-style APIs.
  */
static int
virDomainMigratePeer2PeerFull(virDomainPtr domain,
                              const char *dconnuri,
                              const char *xmlin,
                              const char *dname,
                              const char *uri,
                              unsigned long long bandwidth,
                              virTypedParameterPtr params,
                              int nparams,
                              bool useParams,
                              unsigned int flags)
{
    virURIPtr tempuri = NULL;

    VIR_DOMAIN_DEBUG(domain,
                     "dconnuri=%s, xmlin=%s, dname=%s, uri=%s, bandwidth=%llu "
                     "params=%p, nparams=%d, useParams=%d, flags=%x",
                     dconnuri, NULLSTR(xmlin), NULLSTR(dname), NULLSTR(uri),
                     bandwidth, params, nparams, useParams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    if ((useParams && !domain->conn->driver->domainMigratePerform3Params) ||
        (!useParams &&
         !domain->conn->driver->domainMigratePerform &&
         !domain->conn->driver->domainMigratePerform3)) {
        virLibConnError(VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return -1;
    }

    if (!(tempuri = virURIParse(dconnuri)))
        return -1;
    if (!tempuri->server || STRPREFIX(tempuri->server, "localhost")) {
        virReportInvalidArg(dconnuri,
                            _("unable to parse server from dconnuri in %s"),
                            __FUNCTION__);
        virURIFree(tempuri);
        return -1;
    }
    virURIFree(tempuri);

    if (useParams) {
        VIR_DEBUG("Using migration protocol 3 with extensible parameters");
        return domain->conn->driver->domainMigratePerform3Params
                (domain, dconnuri, params, nparams,
                 NULL, 0, NULL, NULL, flags);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V3)) {
        VIR_DEBUG("Using migration protocol 3");
        return domain->conn->driver->domainMigratePerform3
                (domain, xmlin, NULL, 0, NULL, NULL, dconnuri,
                 uri, flags, dname, bandwidth);
    } else {
        VIR_DEBUG("Using migration protocol 2");
        if (xmlin) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("Unable to change target guest XML "
                              "during migration"));
            return -1;
        }
        if (uri) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Unable to override peer2peer migration URI"));
            return -1;
        }
        return domain->conn->driver->domainMigratePerform
                (domain, NULL, 0, dconnuri, flags, dname, bandwidth);
    }
}

static int
virDomainMigratePeer2Peer(virDomainPtr domain,
                          const char *xmlin,
                          unsigned long flags,
                          const char *dname,
                          const char *dconnuri,
                          const char *uri,
                          unsigned long bandwidth)
{
    return virDomainMigratePeer2PeerFull(domain, dconnuri, xmlin, dname, uri,
                                         bandwidth, NULL, 0, false, flags);
}

static int
virDomainMigratePeer2PeerParams(virDomainPtr domain,
                                const char *dconnuri,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags)
{
    return virDomainMigratePeer2PeerFull(domain, dconnuri, NULL, NULL, NULL, 0,
                                         params, nparams, true, flags);
}


/*
 * In normal migration, the libvirt client co-ordinates communication
 * between the 2 libvirtd instances on source & dest hosts.
 *
 * Some hypervisors support an alternative, direct migration where
 * there is no requirement for a libvirtd instance on the dest host.
 * In this case
 *
 * eg, XenD can talk direct to XenD, so libvirtd on dest does not
 * need to be involved at all, or even running
 */
static int
virDomainMigrateDirect(virDomainPtr domain,
                       const char *xmlin,
                       unsigned long flags,
                       const char *dname,
                       const char *uri,
                       unsigned long bandwidth)
{
    VIR_DOMAIN_DEBUG(domain,
                     "xmlin=%s, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     NULLSTR(xmlin), flags, NULLSTR(dname), NULLSTR(uri),
                     bandwidth);

    if (!domain->conn->driver->domainMigratePerform) {
        virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        virDispatchError(domain->conn);
        return -1;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_V3)) {
        VIR_DEBUG("Using migration protocol 3");
        /* dconn URI not relevant in direct migration, since no
         * target libvirtd is involved */
        return domain->conn->driver->domainMigratePerform3(domain,
                                                           xmlin,
                                                           NULL, /* cookiein */
                                                           0,    /* cookieinlen */
                                                           NULL, /* cookieoutlen */
                                                           NULL, /* cookieoutlen */
                                                           NULL, /* dconnuri */
                                                           uri,
                                                           flags,
                                                           dname,
                                                           bandwidth);
    } else {
        VIR_DEBUG("Using migration protocol 2");
        if (xmlin) {
            virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Unable to change target guest XML during migration"));
            return -1;
        }
        return domain->conn->driver->domainMigratePerform(domain,
                                                          NULL, /* cookie */
                                                          0,    /* cookielen */
                                                          uri,
                                                          flags,
                                                          dname,
                                                          bandwidth);
    }
}


/**
 * virDomainMigrate:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @uri: (optional) dest hostname/URI as seen from the source host
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
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
 *   VIR_MIGRATE_NON_SHARED_DISK Migration with non-shared storage with full
 *                               disk copy
 *   VIR_MIGRATE_NON_SHARED_INC  Migration with non-shared storage with
 *                               incremental disk copy
 *   VIR_MIGRATE_CHANGE_PROTECTION Protect against domain configuration
 *                                 changes during the migration process (set
 *                                 automatically when supported).
 *   VIR_MIGRATE_UNSAFE    Force migration even if it is considered unsafe.
 *   VIR_MIGRATE_OFFLINE Migrate offline
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
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
 *
 * In either case it is typically only necessary to specify a
 * URI if the destination host has multiple interfaces and a
 * specific interface is required to transmit migration data.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
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
virDomainMigrate(virDomainPtr domain,
                 virConnectPtr dconn,
                 unsigned long flags,
                 const char *dname,
                 const char *uri,
                 unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Now checkout the destination */
    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }
    if (dconn->flags & VIR_CONNECT_RO) {
        /* NB, deliberately report error against source object, not dest */
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the destination host"));
            goto error;
        }
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            char *dstURI = NULL;
            if (uri == NULL) {
                dstURI = virConnectGetURI(dconn);
                if (!dstURI)
                    return NULL;
            }

            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigratePeer2Peer(domain, NULL, flags, dname,
                                          uri ? uri : dstURI, NULL, bandwidth) < 0) {
                VIR_FREE(dstURI);
                goto error;
            }
            VIR_FREE(dstURI);

            ddomain = virDomainLookupByName(dconn, dname ? dname : domain->name);
        } else {
            /* This driver does not support peer to peer migration */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        /* Change protection requires support only on source side, and
         * is only needed in v3 migration, which automatically re-adds
         * the flag for just the source side.  We mask it out for
         * non-peer2peer to allow migration from newer source to an
         * older destination that rejects the flag.  */
        if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
            !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("cannot enforce change protection"));
            goto error;
        }
        flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot perform tunnelled migration without using peer2peer flag"));
            goto error;
        }

        /* Check that migration is supported by both drivers. */
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_V3) &&
            VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                     VIR_DRV_FEATURE_MIGRATION_V3)) {
            VIR_DEBUG("Using migration protocol 3");
            ddomain = virDomainMigrateVersion3(domain, dconn, NULL,
                                               flags, dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V2) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                          VIR_DRV_FEATURE_MIGRATION_V2)) {
            VIR_DEBUG("Using migration protocol 2");
            ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V1) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                            VIR_DRV_FEATURE_MIGRATION_V1)) {
            VIR_DEBUG("Using migration protocol 1");
            ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else {
            /* This driver does not support any migration method */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * virDomainMigrate2:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dxml: (optional) XML config for launching guest on target
 * @dname: (optional) rename domain to this at destination
 * @uri: (optional) dest hostname/URI as seen from the source host
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
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
 *   VIR_MIGRATE_NON_SHARED_DISK Migration with non-shared storage with full
 *                               disk copy
 *   VIR_MIGRATE_NON_SHARED_INC  Migration with non-shared storage with
 *                               incremental disk copy
 *   VIR_MIGRATE_CHANGE_PROTECTION Protect against domain configuration
 *                                 changes during the migration process (set
 *                                 automatically when supported).
 *   VIR_MIGRATE_UNSAFE    Force migration even if it is considered unsafe.
 *   VIR_MIGRATE_OFFLINE Migrate offline
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
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
 *
 * In either case it is typically only necessary to specify a
 * URI if the destination host has multiple interfaces and a
 * specific interface is required to transmit migration data.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
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
 * If the hypervisor supports it, @dxml can be used to alter
 * host-specific portions of the domain XML that will be used on
 * the destination.  For example, it is possible to alter the
 * backing filename that is associated with a disk device, in order
 * to account for naming differences between source and destination
 * in accessing the underlying storage.  The migration will fail
 * if @dxml would cause any guest-visible changes.  Pass NULL
 * if no changes are needed to the XML between source and destination.
 * @dxml cannot be used to rename the domain during migration (use
 * @dname for that purpose).  Domain name in @dxml must match the
 * original domain name.
 *
 * Returns the new domain object if the migration was successful,
 *   or NULL in case of error.  Note that the new domain object
 *   exists in the scope of the destination connection (dconn).
 */
virDomainPtr
virDomainMigrate2(virDomainPtr domain,
                  virConnectPtr dconn,
                  const char *dxml,
                  unsigned long flags,
                  const char *dname,
                  const char *uri,
                  unsigned long bandwidth)
{
    virDomainPtr ddomain = NULL;

    VIR_DOMAIN_DEBUG(domain,
                     "dconn=%p, flags=%lx, dname=%s, uri=%s, bandwidth=%lu",
                     dconn, flags, NULLSTR(dname), NULLSTR(uri), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Now checkout the destination */
    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }
    if (dconn->flags & VIR_CONNECT_RO) {
        /* NB, deliberately report error against source object, not dest */
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the destination host"));
            goto error;
        }
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            char *dstURI = virConnectGetURI(dconn);
            if (!dstURI)
                return NULL;

            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigratePeer2Peer(domain, dxml, flags, dname,
                                          dstURI, uri, bandwidth) < 0) {
                VIR_FREE(dstURI);
                goto error;
            }
            VIR_FREE(dstURI);

            ddomain = virDomainLookupByName(dconn, dname ? dname : domain->name);
        } else {
            /* This driver does not support peer to peer migration */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        /* Change protection requires support only on source side, and
         * is only needed in v3 migration, which automatically re-adds
         * the flag for just the source side.  We mask it out for
         * non-peer2peer to allow migration from newer source to an
         * older destination that rejects the flag.  */
        if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
            !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("cannot enforce change protection"));
            goto error;
        }
        flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("cannot perform tunnelled migration without using peer2peer flag"));
            goto error;
        }

        /* Check that migration is supported by both drivers. */
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_V3) &&
            VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                     VIR_DRV_FEATURE_MIGRATION_V3)) {
            VIR_DEBUG("Using migration protocol 3");
            ddomain = virDomainMigrateVersion3(domain, dconn, dxml,
                                               flags, dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V2) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                          VIR_DRV_FEATURE_MIGRATION_V2)) {
            VIR_DEBUG("Using migration protocol 2");
            if (dxml) {
                virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Unable to change target guest XML during migration"));
                goto error;
            }
            ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                            VIR_DRV_FEATURE_MIGRATION_V1) &&
                   VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                            VIR_DRV_FEATURE_MIGRATION_V1)) {
            VIR_DEBUG("Using migration protocol 1");
            if (dxml) {
                virLibConnError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Unable to change target guest XML during migration"));
                goto error;
            }
            ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                               dname, uri, bandwidth);
        } else {
            /* This driver does not support any migration method */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * virDomainMigrate3:
 * @domain: a domain object
 * @dconn: destination host (a connection object)
 * @params: (optional) migration parameters
 * @nparams: (optional) number of migration parameters in @params
 * @flags: bitwise-OR of virDomainMigrateFlags
 *
 * Migrate the domain object from its current host to the destination host
 * given by dconn (a connection to the destination host).
 *
 * See virDomainMigrateFlags documentation for description of individual flags.
 *
 * VIR_MIGRATE_TUNNELLED and VIR_MIGRATE_PEER2PEER are not supported by this
 * API, use virDomainMigrateToURI3 instead.
 *
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
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
virDomainMigrate3(virDomainPtr domain,
                  virConnectPtr dconn,
                  virTypedParameterPtr params,
                  unsigned int nparams,
                  unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    const char *compatParams[] = { VIR_MIGRATE_PARAM_URI,
                                   VIR_MIGRATE_PARAM_DEST_NAME,
                                   VIR_MIGRATE_PARAM_DEST_XML,
                                   VIR_MIGRATE_PARAM_BANDWIDTH };
    const char *uri = NULL;
    const char *dname = NULL;
    const char *dxml = NULL;
    unsigned long long bandwidth = 0;

    VIR_DOMAIN_DEBUG(domain, "dconn=%p, params=%p, nparms=%u flags=%x",
                     dconn, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    /* Now checkout the destination */
    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        goto error;
    }
    if (dconn->flags & VIR_CONNECT_RO) {
        /* NB, deliberately report error against source object, not dest */
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    if (flags & (VIR_MIGRATE_PEER2PEER | VIR_MIGRATE_TUNNELLED)) {
        virReportInvalidArg(flags, "%s",
                            _("use virDomainMigrateToURI3 for peer-to-peer "
                              "migration"));
        goto error;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the source host"));
            goto error;
        }
        if (!VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("offline migration is not supported by "
                              "the destination host"));
            goto error;
        }
    }

    /* Change protection requires support only on source side, and
     * is only needed in v3 migration, which automatically re-adds
     * the flag for just the source side.  We mask it out to allow
     * migration from newer source to an older destination that
     * rejects the flag.  */
    if (flags & VIR_MIGRATE_CHANGE_PROTECTION &&
        !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                  VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION)) {
        virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("cannot enforce change protection"));
        goto error;
    }
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    /* Prefer extensible API but fall back to older migration APIs if params
     * only contains parameters which were supported by the older API. */
    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_PARAMS) &&
        VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                 VIR_DRV_FEATURE_MIGRATION_PARAMS)) {
        VIR_DEBUG("Using migration protocol 3 with extensible parameters");
        ddomain = virDomainMigrateVersion3Params(domain, dconn, params,
                                                 nparams, flags);
        goto done;
    }

    if (!virTypedParamsCheck(params, nparams, compatParams,
                             ARRAY_CARDINALITY(compatParams))) {
        virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("Migration APIs with extensible parameters are not "
                          "supported but extended parameters were passed"));
        goto error;
    }

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI, &uri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML, &dxml) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, &bandwidth) < 0) {
        goto error;
    }

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_MIGRATION_V3) &&
        VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                 VIR_DRV_FEATURE_MIGRATION_V3)) {
        VIR_DEBUG("Using migration protocol 3");
        ddomain = virDomainMigrateVersion3(domain, dconn, dxml, flags,
                                           dname, uri, bandwidth);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V2) &&
               VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                      VIR_DRV_FEATURE_MIGRATION_V2)) {
        VIR_DEBUG("Using migration protocol 2");
        if (dxml) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("Unable to change target guest XML during "
                              "migration"));
            goto error;
        }
        ddomain = virDomainMigrateVersion2(domain, dconn, flags,
                                           dname, uri, bandwidth);
    } else if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                        VIR_DRV_FEATURE_MIGRATION_V1) &&
               VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                        VIR_DRV_FEATURE_MIGRATION_V1)) {
        VIR_DEBUG("Using migration protocol 1");
        if (dxml) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("Unable to change target guest XML during "
                              "migration"));
            goto error;
        }
        ddomain = virDomainMigrateVersion1(domain, dconn, flags,
                                           dname, uri, bandwidth);
    } else {
        /* This driver does not support any migration method */
        virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        goto error;
    }

done:
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
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
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
 *   VIR_MIGRATE_PAUSED    Leave the domain suspended on the remote side.
 *   VIR_MIGRATE_NON_SHARED_DISK Migration with non-shared storage with full
 *                               disk copy
 *   VIR_MIGRATE_NON_SHARED_INC  Migration with non-shared storage with
 *                               incremental disk copy
 *   VIR_MIGRATE_CHANGE_PROTECTION Protect against domain configuration
 *                                 changes during the migration process (set
 *                                 automatically when supported).
 *   VIR_MIGRATE_UNSAFE    Force migration even if it is considered unsafe.
 *   VIR_MIGRATE_OFFLINE Migrate offline
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
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
 *
 * If a hypervisor supports renaming domains during migration,
 * the dname parameter specifies the new name for the domain.
 * Setting dname to NULL keeps the domain name the same.  If domain
 * renaming is not supported by the hypervisor, dname must be NULL or
 * else an error will be returned.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
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
virDomainMigrateToURI(virDomainPtr domain,
                      const char *duri,
                      unsigned long flags,
                      const char *dname,
                      unsigned long bandwidth)
{
    VIR_DOMAIN_DEBUG(domain, "duri=%p, flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(duri), flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(duri, error);

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_OFFLINE &&
        !VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                  VIR_DRV_FEATURE_MIGRATION_OFFLINE)) {
        virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("offline migration is not supported by "
                          "the source host"));
        goto error;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigratePeer2Peer(domain, NULL, flags,
                                          dname, duri, NULL, bandwidth) < 0)
                goto error;
        } else {
            /* No peer to peer migration supported */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_DIRECT)) {
            VIR_DEBUG("Using direct migration");
            if (virDomainMigrateDirect(domain, NULL, flags,
                                       dname, duri, bandwidth) < 0)
                goto error;
        } else {
            /* Cannot do a migration with only the perform step */
            virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("direct migration is not supported by the"
                              " connection driver"));
            goto error;
        }
    }

    return 0;

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainMigrateToURI2:
 * @domain: a domain object
 * @dconnuri: (optional) URI for target libvirtd if @flags includes VIR_MIGRATE_PEER2PEER
 * @miguri: (optional) URI for invoking the migration, not if @flags includs VIR_MIGRATE_TUNNELLED
 * @dxml: (optional) XML config for launching guest on target
 * @flags: bitwise-OR of virDomainMigrateFlags
 * @dname: (optional) rename domain to this at destination
 * @bandwidth: (optional) specify migration bandwidth limit in MiB/s
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
 *   VIR_MIGRATE_PAUSED    Leave the domain suspended on the remote side.
 *   VIR_MIGRATE_NON_SHARED_DISK Migration with non-shared storage with full
 *                               disk copy
 *   VIR_MIGRATE_NON_SHARED_INC  Migration with non-shared storage with
 *                               incremental disk copy
 *   VIR_MIGRATE_CHANGE_PROTECTION Protect against domain configuration
 *                                 changes during the migration process (set
 *                                 automatically when supported).
 *   VIR_MIGRATE_UNSAFE    Force migration even if it is considered unsafe.
 *   VIR_MIGRATE_OFFLINE Migrate offline
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is set, the @dconnuri parameter
 * must be a valid libvirt connection URI, by which the source
 * libvirt driver can connect to the destination libvirt. If the
 * VIR_MIGRATE_PEER2PEER flag is NOT set, then @dconnuri must be
 * NULL.
 *
 * If the VIR_MIGRATE_TUNNELLED flag is NOT set, then the @miguri
 * parameter allows specification of a URI to use to initiate the
 * VM migration. It takes a hypervisor specific format. The uri_transports
 * element of the hypervisor capabilities XML includes details of the
 * supported URI schemes.
 *
 * VIR_MIGRATE_TUNNELLED requires that VIR_MIGRATE_PEER2PEER be set.
 *
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
 *
 * If a hypervisor supports changing the configuration of the guest
 * during migration, the @dxml parameter specifies the new config
 * for the guest. The configuration must include an identical set
 * of virtual devices, to ensure a stable guest ABI across migration.
 * Only parameters related to host side configuration can be
 * changed in the XML. Hypervisors will validate this and refuse to
 * allow migration if the provided XML would cause a change in the
 * guest ABI,
 *
 * If a hypervisor supports renaming domains during migration,
 * the dname parameter specifies the new name for the domain.
 * Setting dname to NULL keeps the domain name the same.  If domain
 * renaming is not supported by the hypervisor, dname must be NULL or
 * else an error will be returned.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
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
virDomainMigrateToURI2(virDomainPtr domain,
                       const char *dconnuri,
                       const char *miguri,
                       const char *dxml,
                       unsigned long flags,
                       const char *dname,
                       unsigned long bandwidth)
{
    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, miguri=%s, dxml=%s, "
                     "flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(dconnuri), NULLSTR(miguri), NULLSTR(dxml),
                     flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_P2P)) {
            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigratePeer2Peer(domain, dxml, flags,
                                          dname, dconnuri, miguri, bandwidth) < 0)
                goto error;
        } else {
            /* No peer to peer migration supported */
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
            goto error;
        }
    } else {
        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_DIRECT)) {
            VIR_DEBUG("Using direct migration");
            if (virDomainMigrateDirect(domain, dxml, flags,
                                       dname, miguri, bandwidth) < 0)
                goto error;
        } else {
            /* Cannot do a migration with only the perform step */
            virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                            _("direct migration is not supported by the"
                              " connection driver"));
            goto error;
        }
    }

    return 0;

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainMigrateToURI3:
 * @domain: a domain object
 * @dconnuri: (optional) URI for target libvirtd if @flags includes VIR_MIGRATE_PEER2PEER
 * @params: (optional) migration parameters
 * @nparams: (optional) number of migration parameters in @params
 * @flags: bitwise-OR of virDomainMigrateFlags
 *
 * Migrate the domain object from its current host to the destination host
 * given by URI.
 *
 * See virDomainMigrateFlags documentation for description of individual flags.
 *
 * The operation of this API hinges on the VIR_MIGRATE_PEER2PEER flag.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is set, the @dconnuri parameter must be a
 * valid libvirt connection URI, by which the source libvirt daemon can connect
 * to the destination libvirt.
 *
 * If the VIR_MIGRATE_PEER2PEER flag is NOT set, then @dconnuri must be NULL
 * and VIR_MIGRATE_PARAM_URI migration parameter must be filled in with
 * hypervisor specific URI used to initiate the migration. This is called
 * "direct" migration.
 *
 * VIR_MIGRATE_TUNNELLED requires that VIR_MIGRATE_PEER2PEER be set.
 *
 * If you want to copy non-shared storage within migration you
 * can use either VIR_MIGRATE_NON_SHARED_DISK or
 * VIR_MIGRATE_NON_SHARED_INC as they are mutually exclusive.
 *
 * There are many limitations on migration imposed by the underlying
 * technology - for example it may not be possible to migrate between
 * different processors even with the same architecture, or between
 * different types of hypervisor.
 *
 * Returns 0 if the migration succeeded, -1 upon error.
 */
int
virDomainMigrateToURI3(virDomainPtr domain,
                       const char *dconnuri,
                       virTypedParameterPtr params,
                       unsigned int nparams,
                       unsigned int flags)
{
    bool compat;
    const char *compatParams[] = { VIR_MIGRATE_PARAM_URI,
                                   VIR_MIGRATE_PARAM_DEST_NAME,
                                   VIR_MIGRATE_PARAM_DEST_XML,
                                   VIR_MIGRATE_PARAM_BANDWIDTH };
    const char *uri = NULL;
    const char *dname = NULL;
    const char *dxml = NULL;
    unsigned long long bandwidth = 0;

    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, params=%p, nparms=%u flags=%x",
                     NULLSTR(dconnuri), params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    /* First checkout the source */
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_DISK &&
        flags & VIR_MIGRATE_NON_SHARED_INC) {
        virReportInvalidArg(flags,
                            _("flags 'shared disk' and 'shared incremental' "
                              "in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    compat = virTypedParamsCheck(params, nparams, compatParams,
                                 ARRAY_CARDINALITY(compatParams));

    if (virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_URI, &uri) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_NAME, &dname) < 0 ||
        virTypedParamsGetString(params, nparams,
                                VIR_MIGRATE_PARAM_DEST_XML, &dxml) < 0 ||
        virTypedParamsGetULLong(params, nparams,
                                VIR_MIGRATE_PARAM_BANDWIDTH, &bandwidth) < 0) {
        goto error;
    }

    if (flags & VIR_MIGRATE_PEER2PEER) {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_P2P)) {
            virLibConnError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                            _("Peer-to-peer migration is not supported by "
                              "the connection driver"));
            goto error;
        }

        if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                     VIR_DRV_FEATURE_MIGRATION_PARAMS)) {
            VIR_DEBUG("Using peer2peer migration with extensible parameters");
            if (virDomainMigratePeer2PeerParams(domain, dconnuri, params,
                                                nparams, flags) < 0)
                goto error;
        } else if (compat) {
            VIR_DEBUG("Using peer2peer migration");
            if (virDomainMigratePeer2Peer(domain, dxml, flags, dname,
                                          dconnuri, uri, bandwidth) < 0)
                goto error;
        } else {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("Peer-to-peer migration with extensible "
                              "parameters is not supported but extended "
                              "parameters were passed"));
            goto error;
        }
    } else {
        if (!VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                      VIR_DRV_FEATURE_MIGRATION_DIRECT)) {
            /* Cannot do a migration with only the perform step */
            virLibConnError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                            _("Direct migration is not supported by the"
                              " connection driver"));
            goto error;
        }

        if (!compat) {
            virLibConnError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                            _("Direct migration does not support extensible "
                              "parameters"));
            goto error;
        }

        VIR_DEBUG("Using direct migration");
        if (virDomainMigrateDirect(domain, dxml, flags,
                                   dname, uri, bandwidth) < 0)
            goto error;
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
virDomainMigratePrepare(virConnectPtr dconn,
                        char **cookie,
                        int *cookielen,
                        const char *uri_in,
                        char **uri_out,
                        unsigned long flags,
                        const char *dname,
                        unsigned long bandwidth)
{
    VIR_DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p, "
              "flags=%lx, dname=%s, bandwidth=%lu", dconn, cookie, cookielen,
              NULLSTR(uri_in), uri_out, flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare) {
        int ret;
        ret = dconn->driver->domainMigratePrepare(dconn, cookie, cookielen,
                                                  uri_in, uri_out,
                                                  flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform(virDomainPtr domain,
                        const char *cookie,
                        int cookielen,
                        const char *uri,
                        unsigned long flags,
                        const char *dname,
                        unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cookie=%p, cookielen=%d, uri=%s, flags=%lx, "
                     "dname=%s, bandwidth=%lu", cookie, cookielen, uri, flags,
                     NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePerform) {
        int ret;
        ret = conn->driver->domainMigratePerform(domain, cookie, cookielen,
                                                 uri,
                                                 flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish(virConnectPtr dconn,
                       const char *dname,
                       const char *cookie,
                       int cookielen,
                       const char *uri,
                       unsigned long flags)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lx", dconn, NULLSTR(dname), cookie, cookielen,
              uri, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish(dconn, dname,
                                                 cookie, cookielen,
                                                 uri, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare2(virConnectPtr dconn,
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
              "flags=%lx, dname=%s, bandwidth=%lu, dom_xml=%s", dconn,
              cookie, cookielen, uri_in, uri_out, flags, NULLSTR(dname),
              bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare2) {
        int ret;
        ret = dconn->driver->domainMigratePrepare2(dconn, cookie, cookielen,
                                                   uri_in, uri_out,
                                                   flags, dname, bandwidth,
                                                   dom_xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish2(virConnectPtr dconn,
                        const char *dname,
                        const char *cookie,
                        int cookielen,
                        const char *uri,
                        unsigned long flags,
                        int retcode)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, "
              "flags=%lx, retcode=%d", dconn, NULLSTR(dname), cookie,
              cookielen, uri, flags, retcode);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish2) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish2(dconn, dname,
                                                  cookie, cookielen,
                                                  uri, flags,
                                                  retcode);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, stream=%p, flags=%lx, dname=%s, "
              "bandwidth=%lu, dom_xml=%s", conn, st, flags,
              NULLSTR(dname), bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn != st->conn) {
        virReportInvalidArg(conn,
                            _("conn in %s must match stream connection"),
                            __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
char *
virDomainMigrateBegin3(virDomainPtr domain,
                       const char *xmlin,
                       char **cookieout,
                       int *cookieoutlen,
                       unsigned long flags,
                       const char *dname,
                       unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlin=%s cookieout=%p, cookieoutlen=%p, "
                     "flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(xmlin), cookieout, cookieoutlen, flags,
                     NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateBegin3) {
        char *xml;
        xml = conn->driver->domainMigrateBegin3(domain, xmlin,
                                                cookieout, cookieoutlen,
                                                flags, dname, bandwidth);
        VIR_DEBUG("xml %s", NULLSTR(xml));
        if (!xml)
            goto error;
        return xml;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare3(virConnectPtr dconn,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         const char *uri_in,
                         char **uri_out,
                         unsigned long flags,
                         const char *dname,
                         unsigned long bandwidth,
                         const char *dom_xml)
{
    VIR_DEBUG("dconn=%p, cookiein=%p, cookieinlen=%d, cookieout=%p, "
              "cookieoutlen=%p, uri_in=%s, uri_out=%p, flags=%lx, dname=%s, "
              "bandwidth=%lu, dom_xml=%s",
              dconn, cookiein, cookieinlen, cookieout, cookieoutlen, uri_in,
              uri_out, flags, NULLSTR(dname), bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare3) {
        int ret;
        ret = dconn->driver->domainMigratePrepare3(dconn,
                                                   cookiein, cookieinlen,
                                                   cookieout, cookieoutlen,
                                                   uri_in, uri_out,
                                                   flags, dname, bandwidth,
                                                   dom_xml);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return -1;
}

/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel3(virConnectPtr conn,
                               virStreamPtr st,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned long flags,
                               const char *dname,
                               unsigned long bandwidth,
                               const char *dom_xml)

{
    VIR_DEBUG("conn=%p, stream=%p, cookiein=%p, cookieinlen=%d, cookieout=%p, "
              "cookieoutlen=%p, flags=%lx, dname=%s, bandwidth=%lu, "
              "dom_xml=%s",
              conn, st, cookiein, cookieinlen, cookieout, cookieoutlen, flags,
              NULLSTR(dname), bandwidth, dom_xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn != st->conn) {
        virReportInvalidArg(conn,
                            _("conn in %s must match stream connection"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel3) {
        int rv = conn->driver->domainMigratePrepareTunnel3(conn, st,
                                                           cookiein, cookieinlen,
                                                           cookieout, cookieoutlen,
                                                           flags, dname,
                                                           bandwidth, dom_xml);
        if (rv < 0)
            goto error;
        return rv;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform3(virDomainPtr domain,
                         const char *xmlin,
                         const char *cookiein,
                         int cookieinlen,
                         char **cookieout,
                         int *cookieoutlen,
                         const char *dconnuri,
                         const char *uri,
                         unsigned long flags,
                         const char *dname,
                         unsigned long bandwidth)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlin=%s cookiein=%p, cookieinlen=%d, "
                     "cookieout=%p, cookieoutlen=%p, dconnuri=%s, "
                     "uri=%s, flags=%lx, dname=%s, bandwidth=%lu",
                     NULLSTR(xmlin), cookiein, cookieinlen,
                     cookieout, cookieoutlen, NULLSTR(dconnuri),
                     NULLSTR(uri), flags, NULLSTR(dname), bandwidth);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePerform3) {
        int ret;
        ret = conn->driver->domainMigratePerform3(domain, xmlin,
                                                  cookiein, cookieinlen,
                                                  cookieout, cookieoutlen,
                                                  dconnuri, uri,
                                                  flags, dname, bandwidth);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish3(virConnectPtr dconn,
                        const char *dname,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        const char *dconnuri,
                        const char *uri,
                        unsigned long flags,
                        int cancelled)
{
    VIR_DEBUG("dconn=%p, dname=%s, cookiein=%p, cookieinlen=%d, cookieout=%p,"
              "cookieoutlen=%p, dconnuri=%s, uri=%s, flags=%lx, retcode=%d",
              dconn, NULLSTR(dname), cookiein, cookieinlen, cookieout,
              cookieoutlen, NULLSTR(dconnuri), NULLSTR(uri), flags, cancelled);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish3) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish3(dconn, dname,
                                                  cookiein, cookieinlen,
                                                  cookieout, cookieoutlen,
                                                  dconnuri, uri, flags,
                                                  cancelled);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigrateConfirm3(virDomainPtr domain,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned long flags,
                         int cancelled)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "cookiein=%p, cookieinlen=%d, flags=%lx, cancelled=%d",
                     cookiein, cookieinlen, flags, cancelled);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateConfirm3) {
        int ret;
        ret = conn->driver->domainMigrateConfirm3(domain,
                                                  cookiein, cookieinlen,
                                                  flags, cancelled);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
char *
virDomainMigrateBegin3Params(virDomainPtr domain,
                             virTypedParameterPtr params,
                             int nparams,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, "
                     "cookieout=%p, cookieoutlen=%p, flags=%x",
                     params, nparams, cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateBegin3Params) {
        char *xml;
        xml = conn->driver->domainMigrateBegin3Params(domain, params, nparams,
                                                      cookieout, cookieoutlen,
                                                      flags);
        VIR_DEBUG("xml %s", NULLSTR(xml));
        if (!xml)
            goto error;
        return xml;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepare3Params(virConnectPtr dconn,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               char **uri_out,
                               unsigned int flags)
{
    VIR_DEBUG("dconn=%p, params=%p, nparams=%d, cookiein=%p, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_out=%p, flags=%x",
              dconn, params, nparams, cookiein, cookieinlen,
              cookieout, cookieoutlen, uri_out, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigratePrepare3Params) {
        int ret;
        ret = dconn->driver->domainMigratePrepare3Params(dconn, params, nparams,
                                                         cookiein, cookieinlen,
                                                         cookieout, cookieoutlen,
                                                         uri_out, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePrepareTunnel3Params(virConnectPtr conn,
                                     virStreamPtr st,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     unsigned int flags)

{
    VIR_DEBUG("conn=%p, stream=%p, params=%p, nparams=%d, cookiein=%p, "
              "cookieinlen=%d, cookieout=%p, cookieoutlen=%p, flags=%x",
              conn, st, params, nparams, cookiein, cookieinlen,
              cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn != st->conn) {
        virReportInvalidArg(conn,
                            _("conn in %s must match stream connection"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePrepareTunnel3Params) {
        int rv;
        rv = conn->driver->domainMigratePrepareTunnel3Params(
                conn, st, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags);
        if (rv < 0)
            goto error;
        return rv;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigratePerform3Params(virDomainPtr domain,
                               const char *dconnuri,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "dconnuri=%s, params=%p, nparams=%d, cookiein=%p, "
                     "cookieinlen=%d, cookieout=%p, cookieoutlen=%p, flags=%x",
                     NULLSTR(dconnuri), params, nparams, cookiein,
                     cookieinlen, cookieout, cookieoutlen, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigratePerform3Params) {
        int ret;
        ret = conn->driver->domainMigratePerform3Params(
                domain, dconnuri, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
virDomainMigrateFinish3Params(virConnectPtr dconn,
                              virTypedParameterPtr params,
                              int nparams,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags,
                              int cancelled)
{
    VIR_DEBUG("dconn=%p, params=%p, nparams=%d, cookiein=%p, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%x, cancelled=%d",
              dconn, params, nparams, cookiein, cookieinlen, cookieout,
              cookieoutlen, flags, cancelled);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECT(dconn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (dconn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dconn->driver->domainMigrateFinish3Params) {
        virDomainPtr ret;
        ret = dconn->driver->domainMigrateFinish3Params(
                dconn, params, nparams, cookiein, cookieinlen,
                cookieout, cookieoutlen, flags, cancelled);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dconn);
    return NULL;
}


/*
 * Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
virDomainMigrateConfirm3Params(virDomainPtr domain,
                               virTypedParameterPtr params,
                               int nparams,
                               const char *cookiein,
                               int cookieinlen,
                               unsigned int flags,
                               int cancelled)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, cookiein=%p, "
                     "cookieinlen=%d, flags=%x, cancelled=%d",
                     params, nparams, cookiein, cookieinlen, flags, cancelled);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateConfirm3Params) {
        int ret;
        ret = conn->driver->domainMigrateConfirm3Params(
                domain, params, nparams,
                cookiein, cookieinlen, flags, cancelled);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);

    if (conn->driver->nodeGetInfo) {
        int ret;
        ret = conn->driver->nodeGetInfo(conn, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (conn->driver->connectGetCapabilities) {
        char *ret;
        ret = conn->driver->connectGetCapabilities(conn);
        if (!ret)
            goto error;
        VIR_DEBUG("conn=%p ret=%s", conn, ret);
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * if ((virNodeGetCPUStats(conn, cpuNum, NULL, &nparams, 0) == 0) &&
 *     (nparams != 0)) {
 *     if ((params = malloc(sizeof(virNodeCPUStats) * nparams)) == NULL)
 *         goto error;
 *     memset(params, 0, sizeof(virNodeCPUStats) * nparams);
 *     if (virNodeGetCPUStats(conn, cpuNum, params, &nparams, 0))
 *         goto error;
 * }
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
int virNodeGetCPUStats(virConnectPtr conn,
                       int cpuNum,
                       virNodeCPUStatsPtr params,
                       int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cpuNum=%d, params=%p, nparams=%d, flags=%x",
              conn, cpuNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (((cpuNum < 0) && (cpuNum != VIR_NODE_CPU_STATS_ALL_CPUS))) {
        virReportInvalidArg(cpuNum,
                            _("cpuNum in %s only accepts %d as a negative value"),
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
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * if ((virNodeGetMemoryStats(conn, cellNum, NULL, &nparams, 0) == 0) &&
 *     (nparams != 0)) {
 *     if ((params = malloc(sizeof(virNodeMemoryStats) * nparams)) == NULL)
 *         goto error;
 *     memset(params, cellNum, 0, sizeof(virNodeMemoryStats) * nparams);
 *     if (virNodeGetMemoryStats(conn, params, &nparams, 0))
 *         goto error;
 * }
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
int virNodeGetMemoryStats(virConnectPtr conn,
                          int cellNum,
                          virNodeMemoryStatsPtr params,
                          int *nparams, unsigned int flags)
{
    VIR_DEBUG("conn=%p, cellNum=%d, params=%p, nparams=%d, flags=%x",
              conn, cellNum, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (((cellNum < 0) && (cellNum != VIR_NODE_MEMORY_STATS_ALL_CELLS))) {
        virReportInvalidArg(cpuNum,
                            _("cellNum in %s only accepts %d as a negative value"),
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
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return 0;
    }

    if (conn->driver->nodeGetFreeMemory) {
        unsigned long long ret;
        ret = conn->driver->nodeGetFreeMemory(conn);
        if (ret == 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->nodeSuspendForDuration) {
        int ret;
        ret = conn->driver->nodeSuspendForDuration(conn, target,
                                                   duration, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainGetSchedulerType:
 * @domain: pointer to domain object
 * @nparams: pointer to number of scheduler parameters, can be NULL
 *           (return value)
 *
 * Get the scheduler type and the number of scheduler parameters.
 *
 * Returns NULL in case of error. The caller must free the returned string.
 */
char *
virDomainGetSchedulerType(virDomainPtr domain, int *nparams)
{
    virConnectPtr conn;
    char *schedtype;

    VIR_DOMAIN_DEBUG(domain, "nparams=%p", nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerType){
        schedtype = conn->driver->domainGetSchedulerType(domain, nparams);
        if (!schedtype)
            goto error;
        return schedtype;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
}


/**
 * virDomainGetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 *          (return value)
 * @nparams: pointer to number of scheduler parameter objects
 *          (this value should generally be as large as the returned value
 *           nparams of virDomainGetSchedulerType()); input and output
 *
 * Get all scheduler parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.  @nparams cannot be 0.
 *
 * It is hypervisor specific whether this returns the live or
 * persistent state; for more control, use
 * virDomainGetSchedulerParametersFlags().
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int *nparams)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p", params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckPositiveArgGoto(*nparams, error);

    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainGetSchedulerParameters(domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetSchedulerParametersFlags:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter object
 *          (return value)
 * @nparams: pointer to number of scheduler parameter
 *          (this value should be same than the returned value
 *           nparams of virDomainGetSchedulerType()); input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all scheduler parameters.  On input, @nparams gives the size of the
 * @params array; on output, @nparams gives how many slots were filled
 * with parameter information, which might be less but will not exceed
 * the input value.  @nparams cannot be 0.
 *
 * The value of @flags can be exactly VIR_DOMAIN_AFFECT_CURRENT,
 * VIR_DOMAIN_AFFECT_LIVE, or VIR_DOMAIN_AFFECT_CONFIG.
 *
 * Here is a sample code snippet:
 *
 * char *ret = virDomainGetSchedulerType(dom, &nparams);
 * if (ret && nparams != 0) {
 *     if ((params = malloc(sizeof(*params) * nparams)) == NULL)
 *         goto error;
 *     memset(params, 0, sizeof(*params) * nparams);
 *     if (virDomainGetSchedulerParametersFlags(dom, params, &nparams, 0))
 *         goto error;
 * }
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params, int *nparams,
                                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%p, flags=%x",
                     params, nparams, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckPositiveArgGoto(*nparams, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParametersFlags) {
        int ret;
        ret = conn->driver->domainGetSchedulerParametersFlags(domain, params,
                                                              nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetSchedulerParameters:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned value
 *           nparams of virDomainGetSchedulerType)
 *
 * Change all or a subset or the scheduler parameters.  It is
 * hypervisor-specific whether this sets live, persistent, or both
 * settings; for more control, use
 * virDomainSetSchedulerParametersFlags.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params, int nparams)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d", params, nparams);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetSchedulerParameters) {
        int ret;
        ret = conn->driver->domainSetSchedulerParameters(domain, params, nparams);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSetSchedulerParametersFlags:
 * @domain: pointer to domain object
 * @params: pointer to scheduler parameter objects
 * @nparams: number of scheduler parameter objects
 *          (this value can be the same or less than the returned value
 *           nparams of virDomainGetSchedulerType)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change a subset or all scheduler parameters.  The value of @flags
 * should be either VIR_DOMAIN_AFFECT_CURRENT, or a bitwise-or of
 * values from VIR_DOMAIN_AFFECT_LIVE and
 * VIR_DOMAIN_AFFECT_CURRENT, although hypervisors vary in which
 * flags are supported.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetSchedulerParametersFlags(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "params=%p, nparams=%d, flags=%x",
                     params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetSchedulerParametersFlags) {
        int ret;
        ret = conn->driver->domainSetSchedulerParametersFlags(domain,
                                                              params,
                                                              nparams,
                                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainBlockStats:
 * @dom: pointer to the domain object
 * @disk: path to the block device, or device shorthand
 * @stats: block device stats (returned)
 * @size: size of stats structure
 *
 * This function returns block device (disk) stats for block
 * devices attached to the domain.
 *
 * The @disk parameter is either the device target shorthand (the
 * <target dev='...'/> sub-element, such as "xvda"), or (since 0.9.8)
 * an unambiguous source name of the block device (the <source
 * file='...'/> sub-element, such as "/path/to/image").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
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
virDomainBlockStats(virDomainPtr dom, const char *disk,
                    virDomainBlockStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    struct _virDomainBlockStats stats2 = { -1, -1, -1, -1, -1 };

    VIR_DOMAIN_DEBUG(dom, "disk=%s, stats=%p, size=%zi", disk, stats, size);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(stats, error);
    if (size > sizeof(stats2)) {
        virReportInvalidArg(size,
                            _("size in %s must not exceed %zu"),
                            __FUNCTION__, sizeof(stats2));
        goto error;
    }
    conn = dom->conn;

    if (conn->driver->domainBlockStats) {
        if (conn->driver->domainBlockStats(dom, disk, &stats2) == -1)
            goto error;

        memcpy(stats, &stats2, size);
        return 0;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainBlockStatsFlags:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: pointer to block stats parameter object
 *          (return value)
 * @nparams: pointer to number of block stats; input and output
 * @flags: bitwise-OR of virTypedParameterFlags
 *
 * This function is to get block stats parameters for block
 * devices attached to the domain.
 *
 * The @disk parameter is either the device target shorthand (the
 * <target dev='...'/> sub-element, such as "xvda"), or (since 0.9.8)
 * an unambiguous source name of the block device (the <source
 * file='...'/> sub-element, such as "/path/to/image").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Domains may have more than one block device.  To get stats for
 * each you should make multiple calls to this function.
 *
 * On input, @nparams gives the size of the @params array; on output,
 * @nparams gives how many slots were filled with parameter
 * information, which might be less but will not exceed the input
 * value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. (Note that block devices of different types
 * might support different parameters, so it might be necessary to compute
 * @nparams for each block device). The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again. See virDomainGetMemoryParameters() for more details.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int virDomainBlockStatsFlags(virDomainPtr dom,
                             const char *disk,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     disk, params, nparams ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;
    conn = dom->conn;

    if (conn->driver->domainBlockStatsFlags) {
        int ret;
        ret = conn->driver->domainBlockStatsFlags(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
virDomainInterfaceStats(virDomainPtr dom, const char *path,
                        virDomainInterfaceStatsPtr stats, size_t size)
{
    virConnectPtr conn;
    struct _virDomainInterfaceStats stats2 = { -1, -1, -1, -1,
                                               -1, -1, -1, -1 };

    VIR_DOMAIN_DEBUG(dom, "path=%s, stats=%p, size=%zi",
                     path, stats, size);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(path, error);
    virCheckNonNullArgGoto(stats, error);
    if (size > sizeof(stats2)) {
        virReportInvalidArg(size,
                            _("size in %s must not exceed %zu"),
                            __FUNCTION__, sizeof(stats2));
        goto error;
    }

    conn = dom->conn;

    if (conn->driver->domainInterfaceStats) {
        if (conn->driver->domainInterfaceStats(dom, path, &stats2) == -1)
            goto error;

        memcpy(stats, &stats2, size);
        return 0;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

 /**
 * virDomainSetInterfaceParameters:
 * @domain: pointer to domain object
 * @device: the interface name or mac address
 * @params: pointer to interface parameter objects
 * @nparams: number of interface parameter (this value can be the same or
 *          less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change a subset or all parameters of interface; currently this
 * includes bandwidth parameters.  The value of @flags should be
 * either VIR_DOMAIN_AFFECT_CURRENT, or a bitwise-or of values
 * VIR_DOMAIN_AFFECT_LIVE and VIR_DOMAIN_AFFECT_CONFIG, although
 * hypervisors vary in which flags are supported.
 *
 * This function may require privileged access to the hypervisor.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int
virDomainSetInterfaceParameters(virDomainPtr domain,
                                const char *device,
                                virTypedParameterPtr params,
                                int nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "device=%s, params=%p, nparams=%d, flags=%x",
                     device, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(params, error);
    virCheckPositiveArgGoto(nparams, error);

    if (virTypedParameterValidateSet(domain->conn, params, nparams) < 0)
        goto error;

    conn = domain->conn;

    if (conn->driver->domainSetInterfaceParameters) {
        int ret;
        ret = conn->driver->domainSetInterfaceParameters(domain, device,
                                                         params, nparams,
                                                         flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

 /**
 * virDomainGetInterfaceParameters:
 * @domain: pointer to domain object
 * @device: the interface name or mac address
 * @params: pointer to interface parameter objects
 *          (return value, allocated by the caller)
 * @nparams: pointer to number of interface parameter; input and output
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all interface parameters. On input, @nparams gives the size of
 * the @params array; on output, @nparams gives how many slots were
 * filled with parameter information, which might be less but will not
 * exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0 on
 * input will cause @nparams on output to contain the number of parameters
 * supported by the hypervisor. The caller should then allocate @params
 * array, i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the
 * API again. See virDomainGetMemoryParameters() for an equivalent usage
 * example.
 *
 * This function may require privileged access to the hypervisor. This function
 * expects the caller to allocate the @params.
 *
 * Returns -1 in case of error, 0 in case of success.
 */

int
virDomainGetInterfaceParameters(virDomainPtr domain,
                                const char *device,
                                virTypedParameterPtr params,
                                int *nparams, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "device=%s, params=%p, nparams=%d, flags=%x",
                     device, params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0)
        virCheckNonNullArgGoto(params, error);

    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    conn = domain->conn;

    if (conn->driver->domainGetInterfaceParameters) {
        int ret;
        ret = conn->driver->domainGetInterfaceParameters(domain, device,
                                                         params, nparams,
                                                         flags);
        if (ret < 0)
            goto error;
        return ret;
    }
    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainMemoryStats:
 * @dom: pointer to the domain object
 * @stats: nr_stats-sized array of stat structures (returned)
 * @nr_stats: number of memory statistics requested
 * @flags: extra flags; not used yet, so callers should always pass 0
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
 * VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON:
 *     Current balloon value (in kb).
 *
 * Returns: The number of stats provided or -1 in case of failure.
 */
int virDomainMemoryStats(virDomainPtr dom, virDomainMemoryStatPtr stats,
                         unsigned int nr_stats, unsigned int flags)
{
    virConnectPtr conn;
    unsigned long nr_stats_ret = 0;

    VIR_DOMAIN_DEBUG(dom, "stats=%p, nr_stats=%u, flags=%x",
                     stats, nr_stats, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (!stats || nr_stats == 0)
        return 0;

    if (nr_stats > VIR_DOMAIN_MEMORY_STAT_NR)
        nr_stats = VIR_DOMAIN_MEMORY_STAT_NR;

    conn = dom->conn;
    if (conn->driver->domainMemoryStats) {
        nr_stats_ret = conn->driver->domainMemoryStats(dom, stats, nr_stats,
                                                       flags);
        if (nr_stats_ret == -1)
            goto error;
        return nr_stats_ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainBlockPeek:
 * @dom: pointer to the domain object
 * @disk: path to the block device, or device shorthand
 * @offset: offset within block device
 * @size: size to read
 * @buffer: return buffer (must be at least size bytes)
 * @flags: extra flags; not used yet, so callers should always pass 0
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
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
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
 * However, with 0.9.13 this RPC limit has been raised to 1M byte.
 * Starting with version 1.0.6 the RPC limit has been raised again.
 * Now large requests up to 16M byte are supported.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainBlockPeek(virDomainPtr dom,
                   const char *disk,
                   unsigned long long offset /* really 64 bits */,
                   size_t size,
                   void *buffer,
                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, offset=%lld, size=%zi, buffer=%p, flags=%x",
                     disk, offset, size, buffer, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    /* Allow size == 0 as an access test. */
    if (size > 0)
        virCheckNonNullArgGoto(buffer, error);

    if (conn->driver->domainBlockPeek) {
        int ret;
        ret = conn->driver->domainBlockPeek(dom, disk, offset, size,
                                            buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainBlockResize:
 * @dom: pointer to the domain object
 * @disk: path to the block image, or shorthand
 * @size: new size of the block image, see below for unit
 * @flags: bitwise-OR of virDomainBlockResizeFlags
 *
 * Resize a block device of domain while the domain is running.  If
 * @flags is 0, then @size is in kibibytes (blocks of 1024 bytes);
 * since 0.9.11, if @flags includes VIR_DOMAIN_BLOCK_RESIZE_BYTES,
 * @size is in bytes instead.  @size is taken directly as the new
 * size.  Depending on the file format, the hypervisor may round up
 * to the next alignment boundary.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it; this call requires privileged access to the
 * hypervisor.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */

int
virDomainBlockResize(virDomainPtr dom,
                     const char *disk,
                     unsigned long long size,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, size=%llu, flags=%x", disk, size, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockResize) {
        int ret;
        ret =conn->driver->domainBlockResize(dom, disk, size, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * @flags: bitwise-OR of virDomainMemoryFlags
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
 * However, with 0.9.13 this RPC limit has been raised to 1M byte.
 * Starting with version 1.0.6 the RPC limit has been raised again.
 * Now large requests up to 16M byte are supported.
 *
 * Returns: 0 in case of success or -1 in case of failure.
 */
int
virDomainMemoryPeek(virDomainPtr dom,
                    unsigned long long start /* really 64 bits */,
                    size_t size,
                    void *buffer,
                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "start=%lld, size=%zi, buffer=%p, flags=%x",
                     start, size, buffer, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
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

    /* Exactly one of these two flags must be set.  */
    if (!(flags & VIR_MEMORY_VIRTUAL) == !(flags & VIR_MEMORY_PHYSICAL)) {
        virReportInvalidArg(flags,
                            _("flags in %s must include VIR_MEMORY_VIRTUAL or VIR_MEMORY_PHYSICAL"),
                            __FUNCTION__);
        goto error;
    }

    /* Allow size == 0 as an access test. */
    if (size > 0)
        virCheckNonNullArgGoto(buffer, error);

    if (conn->driver->domainMemoryPeek) {
        int ret;
        ret = conn->driver->domainMemoryPeek(dom, start, size,
                                             buffer, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainGetBlockInfo:
 * @domain: a domain object
 * @disk: path to the block device, or device shorthand
 * @info: pointer to a virDomainBlockInfo structure allocated by the user
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract information about a domain's block device.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetBlockInfo(virDomainPtr domain, const char *disk,
                      virDomainBlockInfoPtr info, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, flags=%x", info, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(info, error);

    memset(info, 0, sizeof(virDomainBlockInfo));

    conn = domain->conn;

    if (conn->driver->domainGetBlockInfo) {
        int ret;
        ret = conn->driver->domainGetBlockInfo(domain, disk, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * overridden if it already exists.
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation on a transient domain with the same id as the
 * domain being defined; in that case, use virDomainBlockJobAbort() to
 * stop the block copy first.
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXML(virConnectPtr conn, const char *xml) {
    VIR_DEBUG("conn=%p, xml=%s", conn, xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(xml, error);

    if (conn->driver->domainDefineXML) {
        virDomainPtr ret;
        ret = conn->driver->domainDefineXML(conn, xml);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainUndefine:
 * @domain: pointer to a defined domain
 *
 * Undefine a domain. If the domain is running, it's converted to
 * transient domain, without stopping it. If the domain is inactive,
 * the domain configuration is removed.
 *
 * If the domain has a managed save image (see
 * virDomainHasManagedSaveImage()), or if it is inactive and has any
 * snapshot metadata (see virDomainSnapshotNum()), then the undefine will
 * fail. See virDomainUndefineFlags() for more control.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefine(virDomainPtr domain) {
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainUndefine) {
        int ret;
        ret = conn->driver->domainUndefine(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainUndefineFlags:
 * @domain: pointer to a defined domain
 * @flags: bitwise-OR of supported virDomainUndefineFlagsValues
 *
 * Undefine a domain. If the domain is running, it's converted to
 * transient domain, without stopping it. If the domain is inactive,
 * the domain configuration is removed.
 *
 * If the domain has a managed save image (see virDomainHasManagedSaveImage()),
 * then including VIR_DOMAIN_UNDEFINE_MANAGED_SAVE in @flags will also remove
 * that file, and omitting the flag will cause the undefine process to fail.
 *
 * If the domain is inactive and has any snapshot metadata (see
 * virDomainSnapshotNum()), then including
 * VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA in @flags will also remove
 * that metadata.  Omitting the flag will cause the undefine of an
 * inactive domain to fail.  Active snapshots will retain snapshot
 * metadata until the (now-transient) domain halts, regardless of
 * whether this flag is present.  On hypervisors where snapshots do
 * not use libvirt metadata, this flag has no effect.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefineFlags(virDomainPtr domain,
                       unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainUndefineFlags) {
        int ret;
        ret = conn->driver->domainUndefineFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->connectNumOfDefinedDomains) {
        int ret;
        ret = conn->driver->connectNumOfDefinedDomains(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * For active domains, see virConnectListDomains().  For more control over
 * the results, see virConnectListAllDomains().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a domain can be defined between
 * a call to virConnectNumOfDefinedDomains() and this call; you are only
 * guaranteed that all currently defined domains were listed if the return
 * is less than @maxids.  The client must call free() on each returned name.
 */
int
virConnectListDefinedDomains(virConnectPtr conn, char **const names,
                             int maxnames) {
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->driver->connectListDefinedDomains) {
        int ret;
        ret = conn->driver->connectListDefinedDomains(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListAllDomains:
 * @conn: Pointer to the hypervisor connection.
 * @domains: Pointer to a variable to store the array containing domain objects
 *           or NULL if the list is not required (just returns number of guests).
 * @flags: bitwise-OR of virConnectListAllDomainsFlags
 *
 * Collect a possibly-filtered list of all domains, and return an allocated
 * array of information for each.  This API solves the race inherent in
 * virConnectListDomains() and virConnectListDefinedDomains().
 *
 * Normally, all domains are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted domains.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a domain, and where all bits
 * within a group describe all possible domains.  Some hypervisors might
 * reject explicit bits from a group where the hypervisor cannot make a
 * distinction (for example, not all hypervisors can tell whether domains
 * have snapshots).  For a group supported by a given hypervisor, the
 * behavior when no bits of a group are set is identical to the behavior
 * when all bits in that group are set.  When setting bits from more than
 * one group, it is possible to select an impossible combination (such
 * as an inactive transient domain), in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_CONNECT_LIST_DOMAINS_ACTIVE (online
 * domains) and VIR_CONNECT_LIST_DOMAINS_INACTIVE (offline domains).
 *
 * The next group of @flags is VIR_CONNECT_LIST_DOMAINS_PERSISTENT (defined
 * domains) and VIR_CONNECT_LIST_DOMAINS_TRANSIENT (running but not defined).
 *
 * The next group of @flags covers various domain states:
 * VIR_CONNECT_LIST_DOMAINS_RUNNING, VIR_CONNECT_LIST_DOMAINS_PAUSED,
 * VIR_CONNECT_LIST_DOMAINS_SHUTOFF, and a catch-all for all other states
 * (such as crashed, this catch-all covers the possibility of adding new
 * states).
 *
 * The remaining groups cover boolean attributes commonly asked about
 * domains; they include VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE and
 * VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE, for filtering based on whether
 * a managed save image exists; VIR_CONNECT_LIST_DOMAINS_AUTOSTART and
 * VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART, for filtering based on autostart;
 * VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT and
 * VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT, for filtering based on whether
 * a domain has snapshots.
 *
 * Returns the number of domains found or -1 and sets domains to NULL in case of
 * error.  On success, the array stored into @domains is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count, to
 * make iteration easier. The caller is responsible for calling virDomainFree()
 * on each array element, then calling free() on @domains.
 *
 * Example of usage:
 * virDomainPtr *domains;
 * size_t i;
 * int ret;
 * unsigned int flags = VIR_CONNECT_LIST_DOMAINS_RUNNING |
 *                      VIR_CONNECT_LIST_DOMAINS_PERSISTENT;
 *
 * ret = virConnectListAllDomains(conn, &domains, flags);
 * if (ret < 0)
 *     error();
 *
 * for (i = 0; i < ret; i++) {
 *      do_something_with_domain(domains[i]);
 *
 *      //here or in a separate loop if needed
 *      virDomainFree(domains[i]);
 * }
 *
 * free(domains);
 */
int
virConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr **domains,
                         unsigned int flags)
{
    VIR_DEBUG("conn=%p, domains=%p, flags=%x", conn, domains, flags);

    virResetLastError();

    if (domains)
        *domains = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->connectListAllDomains) {
        int ret;
        ret = conn->driver->connectListAllDomains(conn, domains, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainCreate:
 * @domain: pointer to a defined domain
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.  The domain will be paused only
 * if restoring from managed state created from a paused domain.  For more
 * control, see virDomainCreateWithFlags().
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreate(virDomainPtr domain) {
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreate) {
        int ret;
        ret = conn->driver->domainCreate(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainCreateWithFlags:
 * @domain: pointer to a defined domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, or if the guest domain
 * has a managed save image that requested paused state (see
 * virDomainManagedSave()) the guest domain will be started, but its
 * CPUs will remain paused. The CPUs can later be manually started
 * using virDomainResume().  In all other cases, the guest domain will
 * be running.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * If the VIR_DOMAIN_START_BYPASS_CACHE flag is set, and there is a
 * managed save file for this domain (created by virDomainManagedSave()),
 * then libvirt will attempt to bypass the file system cache while restoring
 * the file, or fail if it cannot do so for the given system; this can allow
 * less pressure on file system cache, but also risks slowing loads from NFS.
 *
 * If the VIR_DOMAIN_START_FORCE_BOOT flag is set, then any managed save
 * file for this domain is discarded, and the domain boots from scratch.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreateWithFlags(virDomainPtr domain, unsigned int flags) {
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreateWithFlags) {
        int ret;
        ret = conn->driver->domainCreateWithFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainCreateWithFiles:
 * @domain: pointer to a defined domain
 * @nfiles: number of file descriptors passed
 * @files: list of file descriptors passed
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Launch a defined domain. If the call succeeds the domain moves from the
 * defined to the running domains pools.
 *
 * @files provides an array of file descriptors which will be
 * made available to the 'init' process of the guest. The file
 * handles exposed to the guest will be renumbered to start
 * from 3 (ie immediately following stderr). This is only
 * supported for guests which use container based virtualization
 * technology.
 *
 * If the VIR_DOMAIN_START_PAUSED flag is set, or if the guest domain
 * has a managed save image that requested paused state (see
 * virDomainManagedSave()) the guest domain will be started, but its
 * CPUs will remain paused. The CPUs can later be manually started
 * using virDomainResume().  In all other cases, the guest domain will
 * be running.
 *
 * If the VIR_DOMAIN_START_AUTODESTROY flag is set, the guest
 * domain will be automatically destroyed when the virConnectPtr
 * object is finally released. This will also happen if the
 * client application crashes / loses its connection to the
 * libvirtd daemon. Any domains marked for auto destroy will
 * block attempts at migration, save-to-file, or snapshots.
 *
 * If the VIR_DOMAIN_START_BYPASS_CACHE flag is set, and there is a
 * managed save file for this domain (created by virDomainManagedSave()),
 * then libvirt will attempt to bypass the file system cache while restoring
 * the file, or fail if it cannot do so for the given system; this can allow
 * less pressure on file system cache, but also risks slowing loads from NFS.
 *
 * If the VIR_DOMAIN_START_FORCE_BOOT flag is set, then any managed save
 * file for this domain is discarded, and the domain boots from scratch.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainCreateWithFiles(virDomainPtr domain, unsigned int nfiles,
                         int *files, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nfiles=%u, files=%p, flags=%x",
                     nfiles, files, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainCreateWithFiles) {
        int ret;
        ret = conn->driver->domainCreateWithFiles(domain,
                                                  nfiles, files,
                                                  flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "autostart=%p", autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(autostart, error);

    conn = domain->conn;

    if (conn->driver->domainGetAutostart) {
        int ret;
        ret = conn->driver->domainGetAutostart(domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "autostart=%d", autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSetAutostart) {
        int ret;
        ret = conn->driver->domainSetAutostart(domain, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainInjectNMI:
 * @domain: pointer to domain object, or NULL for Domain0
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Send NMI to the guest
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int virDomainInjectNMI(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainInjectNMI) {
        int ret;
        ret = conn->driver->domainInjectNMI(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSendKey:
 * @domain:    pointer to domain object, or NULL for Domain0
 * @codeset:   the code set of keycodes, from virKeycodeSet
 * @holdtime:  the duration (in milliseconds) that the keys will be held
 * @keycodes:  array of keycodes
 * @nkeycodes: number of keycodes, up to VIR_DOMAIN_SEND_KEY_MAX_KEYS
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Send key(s) to the guest.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int virDomainSendKey(virDomainPtr domain,
                     unsigned int codeset,
                     unsigned int holdtime,
                     unsigned int *keycodes,
                     int nkeycodes,
                     unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "codeset=%u, holdtime=%u, nkeycodes=%u, flags=%x",
                     codeset, holdtime, nkeycodes, flags);

    virResetLastError();

    if (keycodes == NULL ||
        nkeycodes <= 0 || nkeycodes > VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
        virLibDomainError(VIR_ERR_OPERATION_INVALID, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainSendKey) {
        int ret;
        ret = conn->driver->domainSendKey(domain, codeset, holdtime,
                                          keycodes, nkeycodes, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainSendProcessSignal:
 * @domain: pointer to domain object
 * @pid_value: a positive integer process ID, or negative integer process group ID
 * @signum: a signal from the virDomainProcessSignal enum
 * @flags: one of the virDomainProcessSignalFlag values
 *
 * Send a signal to the designated process in the guest
 *
 * The signal numbers must be taken from the virDomainProcessSignal
 * enum. These will be translated to the corresponding signal
 * number for the guest OS, by the guest agent delivering the
 * signal. If there is no mapping from virDomainProcessSignal to
 * the native OS signals, this API will report an error.
 *
 * If @pid_value is an integer greater than zero, it is
 * treated as a process ID. If @pid_value is an integer
 * less than zero, it is treated as a process group ID.
 * All the @pid_value numbers are from the container/guest
 * namespace. The value zero is not valid.
 *
 * Not all hypervisors will support sending signals to
 * arbitrary processes or process groups. If this API is
 * implemented the minimum requirement is to be able to
 * use @pid_value==1 (i.e. kill init). No other value is
 * required to be supported.
 *
 * If the @signum is VIR_DOMAIN_PROCESS_SIGNAL_NOP then this
 * API will simply report whether the process is running in
 * the container/guest.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int virDomainSendProcessSignal(virDomainPtr domain,
                               long long pid_value,
                               unsigned int signum,
                               unsigned int flags)
{
    virConnectPtr conn;
    VIR_DOMAIN_DEBUG(domain, "pid=%lld, signum=%u flags=%x",
                     pid_value, signum, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonZeroArgGoto(pid_value, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainSendProcessSignal) {
        int ret;
        ret = conn->driver->domainSendProcessSignal(domain,
                                                    pid_value,
                                                    signum,
                                                    flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * This function may require privileged access to the hypervisor.
 *
 * This command only changes the runtime configuration of the domain,
 * so can only be called on an active domain.  It is hypervisor-dependent
 * whether it also affects persistent configuration; for more control,
 * use virDomainSetVcpusFlags().
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nvcpus=%u", nvcpus);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonZeroArgGoto(nvcpus, error);

    conn = domain->conn;

    if (conn->driver->domainSetVcpus) {
        int ret;
        ret = conn->driver->domainSetVcpus(domain, nvcpus);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainSetVcpusFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @nvcpus: the new number of virtual CPUs for this domain, must be at least 1
 * @flags: bitwise-OR of virDomainVcpuFlags
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 * Note that this call may fail if the underlying virtualization hypervisor
 * does not support it or if growing the number is arbitrary limited.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE to affect a running
 * domain (which may fail if domain is not active), or
 * VIR_DOMAIN_AFFECT_CONFIG to affect the next boot via the XML
 * description of the domain.  Both flags may be set.
 * If neither flag is specified (that is, @flags is VIR_DOMAIN_AFFECT_CURRENT),
 * then an inactive domain modifies persistent setup, while an active domain
 * is hypervisor-dependent on whether just live or both live and persistent
 * state is changed.
 *
 * If @flags includes VIR_DOMAIN_VCPU_MAXIMUM, then
 * VIR_DOMAIN_AFFECT_LIVE must be clear, and only the maximum virtual
 * CPU limit is altered; generally, this value must be less than or
 * equal to virConnectGetMaxVcpus().  Otherwise, this call affects the
 * current virtual CPU limit, which must be less than or equal to the
 * maximum limit.
 *
 * If @flags includes VIR_DOMAIN_VCPU_GUEST, then the state of processors is
 * modified inside the guest instead of the hypervisor. This flag can only
 * be used with live guests and is incompatible with VIR_DOMAIN_VCPU_MAXIMUM.
 * The usage of this flag may require a guest agent configured.
 *
 * Not all hypervisors can support all flag combinations.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetVcpusFlags(virDomainPtr domain, unsigned int nvcpus,
                       unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "nvcpus=%u, flags=%x", nvcpus, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (flags & VIR_DOMAIN_VCPU_GUEST &&
        flags & VIR_DOMAIN_VCPU_MAXIMUM) {
        virReportInvalidArg(flags,
                            _("flags 'VIR_DOMAIN_VCPU_MAXIMUM' and "
                              "'VIR_DOMAIN_VCPU_GUEST' in '%s' are mutually "
                              "exclusive"), __FUNCTION__);
        goto error;
    }

    virCheckNonZeroArgGoto(nvcpus, error);

    if ((unsigned short) nvcpus != nvcpus) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %u"), nvcpus);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainSetVcpusFlags) {
        int ret;
        ret = conn->driver->domainSetVcpusFlags(domain, nvcpus, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetVcpusFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @flags: bitwise-OR of virDomainVcpuFlags
 *
 * Query the number of virtual CPUs used by the domain.  Note that
 * this call may fail if the underlying virtualization hypervisor does
 * not support it.  This function may require privileged access to the
 * hypervisor.
 *
 * If @flags includes VIR_DOMAIN_AFFECT_LIVE, this will query a
 * running domain (which will fail if domain is not active); if
 * it includes VIR_DOMAIN_AFFECT_CONFIG, this will query the XML
 * description of the domain.  It is an error to set both flags.
 * If neither flag is set (that is, VIR_DOMAIN_AFFECT_CURRENT),
 * then the configuration queried depends on whether the domain
 * is currently running.
 *
 * If @flags includes VIR_DOMAIN_VCPU_MAXIMUM, then the maximum
 * virtual CPU limit is queried.  Otherwise, this call queries the
 * current virtual CPU count.
 *
 * If @flags includes VIR_DOMAIN_VCPU_GUEST, then the state of the processors
 * is modified in the guest instead of the hypervisor. This flag is only usable
 * on live domains. Guest agent may be needed for this flag to be available.
 *
 * Returns the number of vCPUs in case of success, -1 in case of failure.
 */

int
virDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s "
                              "are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetVcpusFlags) {
        int ret;
        ret = conn->driver->domainGetVcpusFlags(domain, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainPinVcpu:
 * @domain: pointer to domain object, or NULL for Domain0
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * This function may require privileged access to the hypervisor.
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

    VIR_DOMAIN_DEBUG(domain, "vcpu=%u, cpumap=%p, maplen=%d",
                     vcpu, cpumap, maplen);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if ((unsigned short) vcpu != vcpu) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %u"), vcpu);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainPinVcpu) {
        int ret;
        ret = conn->driver->domainPinVcpu(domain, vcpu, cpumap, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainPinVcpuFlags:
 * @domain: pointer to domain object, or NULL for Domain0
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 * This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 * Not all hypervisors can support all flag combinations.
 *
 * See also virDomainGetVcpuPinInfo for querying this information.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 */
int
virDomainPinVcpuFlags(virDomainPtr domain, unsigned int vcpu,
                      unsigned char *cpumap, int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "vcpu=%u, cpumap=%p, maplen=%d, flags=%x",
                     vcpu, cpumap, maplen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(cpumap, error);
    virCheckPositiveArgGoto(maplen, error);

    if ((unsigned short) vcpu != vcpu) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %u"), vcpu);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainPinVcpuFlags) {
        int ret;
        ret = conn->driver->domainPinVcpuFlags(domain, vcpu, cpumap, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;

}

/**
 * virDomainGetVcpuPinInfo:
 * @domain: pointer to domain object, or NULL for Domain0
 * @ncpumaps: the number of cpumap (listed first to match virDomainGetVcpus)
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this
 *     domain (in 8-bit bytes) (OUT)
 *     It's assumed there is <ncpumaps> cpumap in cpumaps array.
 *     The memory allocated to cpumaps must be (ncpumaps * maplen) bytes
 *     (ie: calloc(ncpumaps, maplen)).
 *     One cpumap inside cpumaps has the format described in
 *     virDomainPinVcpu() API.
 *     Must not be NULL.
 * @maplen: the number of bytes in one cpumap, from 1 up to size of CPU map.
 *     Must be positive.
 * @flags: bitwise-OR of virDomainModificationImpact
 *     Must not be VIR_DOMAIN_AFFECT_LIVE and
 *     VIR_DOMAIN_AFFECT_CONFIG concurrently.
 *
 * Query the CPU affinity setting of all virtual CPUs of domain, store it
 * in cpumaps.
 *
 * Returns the number of virtual CPUs in case of success,
 * -1 in case of failure.
 */
int
virDomainGetVcpuPinInfo(virDomainPtr domain, int ncpumaps,
                        unsigned char *cpumaps, int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "ncpumaps=%d, cpumaps=%p, maplen=%d, flags=%x",
                     ncpumaps, cpumaps, maplen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(cpumaps, error);
    virCheckPositiveArgGoto(ncpumaps, error);
    virCheckPositiveArgGoto(maplen, error);

    if (INT_MULTIPLY_OVERFLOW(ncpumaps, maplen)) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %d * %d"),
                          ncpumaps, maplen);
        goto error;
    }

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetVcpuPinInfo) {
        int ret;
        ret = conn->driver->domainGetVcpuPinInfo(domain, ncpumaps,
                                                 cpumaps, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainPinEmulator:
 * @domain: pointer to domain object, or NULL for Domain0
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN)
 *      Each bit set to 1 means that corresponding CPU is usable.
 *      Bytes are stored in little-endian order: CPU0-7, 8-15...
 *      In each byte, lowest CPU number is least significant bit.
 * @maplen: number of bytes in cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      If maplen < size, missing bytes are set to zero.
 *      If maplen > size, failure code is returned.
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Dynamically change the real CPUs which can be allocated to all emulator
 * threads. This function may require privileged access to the hypervisor.
 *
 * @flags may include VIR_DOMAIN_AFFECT_LIVE or VIR_DOMAIN_AFFECT_CONFIG.
 * Both flags may be set.
 * If VIR_DOMAIN_AFFECT_LIVE is set, the change affects a running domain
 * and may fail if domain is not alive.
 * If VIR_DOMAIN_AFFECT_CONFIG is set, the change affects persistent state,
 * and will fail for transient domains. If neither flag is specified (that is,
 * @flags is VIR_DOMAIN_AFFECT_CURRENT), then an inactive domain modifies
 * persistent setup, while an active domain is hypervisor-dependent on whether
 * just live or both live and persistent state is changed.
 * Not all hypervisors can support all flag combinations.
 *
 * See also virDomainGetEmulatorPinInfo for querying this information.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 */
int
virDomainPinEmulator(virDomainPtr domain, unsigned char *cpumap,
                     int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cpumap=%p, maplen=%d, flags=%x",
                     cpumap, maplen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((cpumap == NULL) || (maplen < 1)) {
        virLibDomainError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainPinEmulator) {
        int ret;
        ret = conn->driver->domainPinEmulator(domain, cpumap, maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetEmulatorPinInfo:
 * @domain: pointer to domain object, or NULL for Domain0
 * @cpumap: pointer to a bit map of real CPUs for all emulator threads of
 *     this domain (in 8-bit bytes) (OUT)
 *     There is only one cpumap for all emulator threads.
 *     Must not be NULL.
 * @maplen: the number of bytes in one cpumap, from 1 up to size of CPU map.
 *     Must be positive.
 * @flags: bitwise-OR of virDomainModificationImpact
 *     Must not be VIR_DOMAIN_AFFECT_LIVE and
 *     VIR_DOMAIN_AFFECT_CONFIG concurrently.
 *
 * Query the CPU affinity setting of all emulator threads of domain, store
 * it in cpumap.
 *
 * Returns 1 in case of success,
 * 0 in case of no emulator threads are pined to pcpus,
 * -1 in case of failure.
 */
int
virDomainGetEmulatorPinInfo(virDomainPtr domain, unsigned char *cpumap,
                            int maplen, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cpumap=%p, maplen=%d, flags=%x",
                     cpumap, maplen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (!cpumap || maplen <= 0) {
        virLibDomainError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virLibDomainError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainGetEmulatorPinInfo) {
        int ret;
        ret = conn->driver->domainGetEmulatorPinInfo(domain, cpumap,
                                                     maplen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 *      If cpumaps is NULL, then no cpumap information is returned by the API.
 *      It's assumed there is <maxinfo> cpumap in cpumaps array.
 *      The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *      (ie: calloc(maxinfo, maplen)).
 *      One cpumap inside cpumaps has the format described in
 *      virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *      underlying virtualization system (Xen...).
 *      Must be zero when cpumaps is NULL and positive when it is non-NULL.
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer isn't NULL.  This call may fail
 * on an inactive domain.
 *
 * See also virDomainGetVcpuPinInfo for querying just cpumaps, including on
 * an inactive domain.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
virDomainGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
                  unsigned char *cpumaps, int maplen)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p, maxinfo=%d, cpumaps=%p, maplen=%d",
                     info, maxinfo, cpumaps, maplen);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);
    virCheckPositiveArgGoto(maxinfo, error);

    /* Ensure that domainGetVcpus (aka remoteDomainGetVcpus) does not
       try to memcpy anything into a NULL pointer.  */
    if (cpumaps)
        virCheckPositiveArgGoto(maplen, error);
    else
        virCheckZeroArgGoto(maplen, error);

    if (cpumaps && INT_MULTIPLY_OVERFLOW(maxinfo, maplen)) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %d * %d"),
                          maxinfo, maplen);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetVcpus) {
        int ret;
        ret = conn->driver->domainGetVcpus(domain, info, maxinfo,
                                           cpumaps, maplen);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * the same as virConnectGetMaxVcpus(). If the guest is running
 * this will reflect the maximum number of virtual CPUs the
 * guest was booted with.  For more details, see virDomainGetVcpusFlags().
 *
 * Returns the maximum of virtual CPU or -1 in case of error.
 */
int
virDomainGetMaxVcpus(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxVcpus) {
        int ret;
        ret = conn->driver->domainGetMaxVcpus(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "seclabel=%p", seclabel);

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(seclabel, error);

    conn = domain->conn;

    if (conn->driver->domainGetSecurityLabel) {
        int ret;
        ret = conn->driver->domainGetSecurityLabel(domain, seclabel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetSecurityLabelList:
 * @domain: a domain object
 * @seclabels: will be auto-allocated and filled with domains' security labels.
 * Caller must free memory on return.
 *
 * Extract the security labels of an active domain. The 'label' field
 * in the @seclabels argument will be initialized to the empty
 * string if the domain is not running under a security model.
 *
 * Returns number of elemnets in @seclabels on success, -1 in case of failure.
 */
int
virDomainGetSecurityLabelList(virDomainPtr domain,
                              virSecurityLabelPtr* seclabels)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "seclabels=%p", seclabels);

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (seclabels == NULL) {
        virLibDomainError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->driver->domainGetSecurityLabelList) {
        int ret;
        ret = conn->driver->domainGetSecurityLabelList(domain, seclabels);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}
/**
 * virDomainSetMetadata:
 * @domain: a domain object
 * @type: type of description, from virDomainMetadataType
 * @metadata: new metadata text
 * @key: XML namespace key, or NULL
 * @uri: XML namespace URI, or NULL
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Sets the appropriate domain element given by @type to the
 * value of @description.  A @type of VIR_DOMAIN_METADATA_DESCRIPTION
 * is free-form text; VIR_DOMAIN_METADATA_TITLE is free-form, but no
 * newlines are permitted, and should be short (although the length is
 * not enforced). For these two options @key and @uri are irrelevant and
 * must be set to NULL.
 *
 * For type VIR_DOMAIN_METADATA_ELEMENT @metadata  must be well-formed
 * XML belonging to namespace defined by @uri with local name @key.
 *
 * Passing NULL for @metadata says to remove that element from the
 * domain XML (passing the empty string leaves the element present).
 *
 * The resulting metadata will be present in virDomainGetXMLDesc(),
 * as well as quick access through virDomainGetMetadata().
 *
 * @flags controls whether the live domain, persistent configuration,
 * or both will be modified.
 *
 * Returns 0 on success, -1 in case of failure.
 */
int
virDomainSetMetadata(virDomainPtr domain,
                     int type,
                     const char *metadata,
                     const char *key,
                     const char *uri,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "type=%d, metadata='%s', key='%s', uri='%s', flags=%x",
                     type, NULLSTR(metadata), NULLSTR(key), NULLSTR(uri),
                     flags);

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        goto error;
    }

    conn = domain->conn;

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    switch (type) {
    case VIR_DOMAIN_METADATA_TITLE:
        if (metadata && strchr(metadata, '\n')) {
            virReportInvalidArg(metadata,
                                _("metadata title in %s can't contain newlines"),
                                __FUNCTION__);
            goto error;
        }
        /* fallthrough */
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        virCheckNullArgGoto(key, error);
        break;
    case VIR_DOMAIN_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        if (metadata)
            virCheckNonNullArgGoto(key, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    if (conn->driver->domainSetMetadata) {
        int ret;
        ret = conn->driver->domainSetMetadata(domain, type, metadata, key, uri,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetMetadata:
 * @domain: a domain object
 * @type: type of description, from virDomainMetadataType
 * @uri: XML namespace identifier
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Retrieves the appropriate domain element given by @type.
 * If VIR_DOMAIN_METADATA_ELEMENT is requested parameter @uri
 * must be set to the name of the namespace the requested elements
 * belong to, otherwise must be NULL.
 *
 * If an element of the domain XML is not present, the resulting
 * error will be VIR_ERR_NO_DOMAIN_METADATA.  This method forms
 * a shortcut for seeing information from virDomainSetMetadata()
 * without having to go through virDomainGetXMLDesc().
 *
 * @flags controls whether the live domain or persistent
 * configuration will be queried.
 *
 * Returns the metadata string on success (caller must free),
 * or NULL in case of failure.
 */
char *
virDomainGetMetadata(virDomainPtr domain,
                     int type,
                     const char *uri,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "type=%d, uri='%s', flags=%x",
                     type, NULLSTR(uri), flags);

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        goto error;
    }

    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    switch (type) {
    case VIR_DOMAIN_METADATA_TITLE:
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        virCheckNullArgGoto(uri, error);
        break;
    case VIR_DOMAIN_METADATA_ELEMENT:
        virCheckNonNullArgGoto(uri, error);
        break;
    default:
        /* For future expansion */
        break;
    }

    conn = domain->conn;

    if (conn->driver->domainGetMetadata) {
        char *ret;
        if (!(ret = conn->driver->domainGetMetadata(domain, type, uri, flags)))
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(secmodel, error);

    if (conn->driver->nodeGetSecurityModel) {
        int ret;
        ret = conn->driver->nodeGetSecurityModel(conn, secmodel);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "xml=%s", xml);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(xml, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainAttachDevice) {
       int ret;
       ret = conn->driver->domainAttachDevice(domain, xml);
       if (ret < 0)
          goto error;
       return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainAttachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Attach a virtual device to a domain, using the flags parameter
 * to control how the device is attached.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device allocation is made based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * allocated to the active domain instance only and is not added to the
 * persisted domain configuration.  VIR_DOMAIN_AFFECT_CONFIG
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

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(xml, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    VIR_DOMAIN_DEBUG(domain, "xml=%s", xml);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(xml, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    conn = domain->conn;

    if (conn->driver->domainDetachDevice) {
        int ret;
        ret = conn->driver->domainDetachDevice(domain, xml);
         if (ret < 0)
             goto error;
         return ret;
     }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainDetachDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Detach a virtual device from a domain, using the flags parameter
 * to control how the device is detached.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device allocation is removed based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * deallocated from the active domain instance only and is not from the
 * persisted domain configuration.  VIR_DOMAIN_AFFECT_CONFIG
 * specifies that the device shall be deallocated from the persisted domain
 * configuration only.  Note that the target hypervisor must return an
 * error if unable to satisfy flags.  E.g. the hypervisor driver will
 * return failure if LIVE is specified but it only supports removing the
 * persisted device allocation.
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation on the device being detached; in that case,
 * use virDomainBlockJobAbort() to stop the block copy first.
 *
 * Beware that depending on the hypervisor and device type, detaching a device
 * from a running domain may be asynchronous. That is, calling
 * virDomainDetachDeviceFlags may just request device removal while the device
 * is actually removed later (in cooperation with a guest OS). Previously,
 * this fact was ignored and the device could have been removed from domain
 * configuration before it was actually removed by the hypervisor causing
 * various failures on subsequent operations. To check whether the device was
 * successfully removed, either recheck domain configuration using
 * virDomainGetXMLDesc() or add handler for VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED
 * event. In case the device is already gone when virDomainDetachDeviceFlags
 * returns, the event is delivered before this API call ends. To help existing
 * clients work better in most cases, this API will try to transform an
 * asynchronous device removal that finishes shortly after the request into
 * a synchronous removal. In other words, this API may wait a bit for the
 * removal to complete in case it was not synchronous.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainDetachDeviceFlags(virDomainPtr domain,
                           const char *xml, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(xml, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainUpdateDeviceFlags:
 * @domain: pointer to domain object
 * @xml: pointer to XML description of one device
 * @flags: bitwise-OR of virDomainDeviceModifyFlags
 *
 * Change a virtual device on a domain, using the flags parameter
 * to control how the device is changed.  VIR_DOMAIN_AFFECT_CURRENT
 * specifies that the device change is made based on current domain
 * state.  VIR_DOMAIN_AFFECT_LIVE specifies that the device shall be
 * changed on the active domain instance only and is not added to the
 * persisted domain configuration. VIR_DOMAIN_AFFECT_CONFIG
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

    VIR_DOMAIN_DEBUG(domain, "xml=%s, flags=%x", xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(xml, error);

    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, freeMems=%p, startCell=%d, maxCells=%d",
          conn, freeMems, startCell, maxCells);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
virNetworkGetConnect(virNetworkPtr net)
{
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(net)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return net->conn;
}

/**
 * virConnectListAllNetworks:
 * @conn: Pointer to the hypervisor connection.
 * @nets: Pointer to a variable to store the array containing the network
 *        objects or NULL if the list is not required (just returns number
 *        of networks).
 * @flags: bitwise-OR of virConnectListAllNetworksFlags.
 *
 * Collect the list of networks, and allocate an array to store those
 * objects. This API solves the race inherent between virConnectListNetworks
 * and virConnectListDefinedNetworks.
 *
 * Normally, all networks are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted networks.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a network, and where all bits
 * within a group describe all possible networks.
 *
 * The first group of @flags is VIR_CONNECT_LIST_NETWORKS_ACTIVE (up) and
 * VIR_CONNECT_LIST_NETWORKS_INACTIVE (down) to filter the networks by state.
 *
 * The second group of @flags is VIR_CONNECT_LIST_NETWORKS_PERSISTENT (defined)
 * and VIR_CONNECT_LIST_NETWORKS_TRANSIENT (running but not defined), to filter
 * the networks by whether they have persistent config or not.
 *
 * The third group of @flags is VIR_CONNECT_LIST_NETWORKS_AUTOSTART
 * and VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART, to filter the networks by
 * whether they are marked as autostart or not.
 *
 * Returns the number of networks found or -1 and sets @nets to  NULL in case
 * of error.  On success, the array stored into @nets is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virNetworkFree() on each array element, then calling free() on @nets.
 */
int
virConnectListAllNetworks(virConnectPtr conn,
                          virNetworkPtr **nets,
                          unsigned int flags)
{
    VIR_DEBUG("conn=%p, nets=%p, flags=%x", conn, nets, flags);

    virResetLastError();

    if (nets)
        *nets = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->networkDriver &&
        conn->networkDriver->connectListAllNetworks) {
        int ret;
        ret = conn->networkDriver->connectListAllNetworks(conn, nets, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->networkDriver && conn->networkDriver->connectNumOfNetworks) {
        int ret;
        ret = conn->networkDriver->connectNumOfNetworks(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * For more control over the results, see virConnectListAllNetworks().
 *
 * Returns the number of networks found or -1 in case of error.  Note that
 * this command is inherently racy; a network can be started between a call
 * to virConnectNumOfNetworks() and this call; you are only guaranteed that
 * all currently active networks were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 */
int
virConnectListNetworks(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->networkDriver && conn->networkDriver->connectListNetworks) {
        int ret;
        ret = conn->networkDriver->connectListNetworks(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->networkDriver && conn->networkDriver->connectNumOfDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->connectNumOfDefinedNetworks(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * For more control over the results, see virConnectListAllNetworks().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a network can be defined between
 * a call to virConnectNumOfDefinedNetworks() and this call; you are only
 * guaranteed that all currently defined networks were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 */
int
virConnectListDefinedNetworks(virConnectPtr conn, char **const names,
                              int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->networkDriver && conn->networkDriver->connectListDefinedNetworks) {
        int ret;
        ret = conn->networkDriver->connectListDefinedNetworks(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(name, error);

    if (conn->networkDriver && conn->networkDriver->networkLookupByName) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(uuid, error);

    if (conn->networkDriver && conn->networkDriver->networkLookupByUUID){
        virNetworkPtr ret;
        ret = conn->networkDriver->networkLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
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
    VIR_DEBUG("conn=%p, xmlDesc=%s", conn, xmlDesc);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkCreateXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkCreateXML(conn, xmlDesc);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, xml=%s", conn, xml);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkDefineXML) {
        virNetworkPtr ret;
        ret = conn->networkDriver->networkDefineXML(conn, xml);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkUndefine) {
        int ret;
        ret = conn->networkDriver->networkUndefine(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(network->conn);
    return -1;
}

/**
 * virNetworkUpdate:
 * @network: pointer to a defined network
 * @section: which section of the network to update
 *           (see virNetworkUpdateSection for descriptions)
 * @command: what action to perform (add/delete/modify)
 *           (see virNetworkUpdateCommand for descriptions)
 * @parentIndex: which parent element, if there are multiple parents
 *           of the same type (e.g. which <ip> element when modifying
 *           a <dhcp>/<host> element), or "-1" for "don't care" or
 *           "automatically find appropriate one".
 * @xml: the XML description for the network, preferably in UTF-8
 * @flags: bitwise OR of virNetworkUpdateFlags.
 *
 * Update the definition of an existing network, either its live
 * running state, its persistent configuration, or both.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virNetworkUpdate(virNetworkPtr network,
                 unsigned int command, /* virNetworkUpdateCommand */
                 unsigned int section, /* virNetworkUpdateSection */
                 int parentIndex,
                 const char *xml,
                 unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, section=%d, parentIndex=%d, xml=%s, flags=0x%x",
              network, section, parentIndex, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(xml, error);

    if (conn->networkDriver && conn->networkDriver->networkUpdate) {
        int ret;
        ret = conn->networkDriver->networkUpdate(network, section, command,
                                                 parentIndex, xml, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkCreate) {
        int ret;
        ret = conn->networkDriver->networkCreate(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->networkDriver && conn->networkDriver->networkDestroy) {
        int ret;
        ret = conn->networkDriver->networkDestroy(network);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(network);
    return 0;
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
        virLibConnError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("network=%p refs=%d", network, network->object.refs);
    virObjectRef(network);
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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return network->name;
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
    VIR_DEBUG("network=%p, uuid=%p", network, uuid);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &network->uuid[0], VIR_UUID_BUFLEN);

    return 0;

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
    VIR_DEBUG("network=%p, buf=%p", network, buf);

    virResetLastError();

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(buf, error);

    if (virNetworkGetUUID(network, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return 0;

error:
    virDispatchError(network->conn);
    return -1;
}

/**
 * virNetworkGetXMLDesc:
 * @network: a network object
 * @flags: bitwise-OR of virNetworkXMLFlags
 *
 * Provide an XML description of the network. The description may be reused
 * later to relaunch the network with virNetworkCreateXML().
 *
 * Normally, if a network included a physical function, the output includes
 * all virtual functions tied to that physical interface.  If @flags includes
 * VIR_NETWORK_XML_INACTIVE, then the expansion of virtual interfaces is
 * not performed.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetXMLDesc(virNetworkPtr network, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("network=%p, flags=%x", network, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetXMLDesc) {
        char *ret;
        ret = conn->networkDriver->networkGetXMLDesc(network, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p", network);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetBridgeName) {
        char *ret;
        ret = conn->networkDriver->networkGetBridgeName(network);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p, autostart=%p", network, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(autostart, error);

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetAutostart) {
        int ret;
        ret = conn->networkDriver->networkGetAutostart(network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("network=%p, autostart=%d", network, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (network->conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkSetAutostart) {
        int ret;
        ret = conn->networkDriver->networkSetAutostart(network, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
virInterfaceGetConnect(virInterfacePtr iface)
{
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return iface->conn;
}

/**
 * virConnectListAllInterfaces:
 * @conn: Pointer to the hypervisor connection.
 * @ifaces: Pointer to a variable to store the array containing the interface
 *          objects or NULL if the list is not required (just returns number
 *          of interfaces).
 * @flags: bitwise-OR of virConnectListAllInterfacesFlags.
 *
 * Collect the list of interfaces, and allocate an array to store those
 * objects. This API solves the race inherent between virConnectListInterfaces
 * and virConnectListDefinedInterfaces.
 *
 * Normally, all interfaces are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted interfaces.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a interface, and where all bits
 * within a group describe all possible interfaces.
 *
 * The only group of @flags is VIR_CONNECT_LIST_INTERFACES_ACTIVE (up) and
 * VIR_CONNECT_LIST_INTERFACES_INACTIVE (down) to filter the interfaces by state.
 *
 * Returns the number of interfaces found or -1 and sets @ifaces to  NULL in case
 * of error.  On success, the array stored into @ifaces is guaranteed to have an
 * extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virStorageInterfaceFree() on each array element, then calling free() on @ifaces.
 */
int
virConnectListAllInterfaces(virConnectPtr conn,
                            virInterfacePtr **ifaces,
                            unsigned int flags)
{
    VIR_DEBUG("conn=%p, ifaces=%p, flags=%x", conn, ifaces, flags);

    virResetLastError();

    if (ifaces)
        *ifaces = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->interfaceDriver &&
        conn->interfaceDriver->connectListAllInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListAllInterfaces(conn, ifaces, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->connectNumOfInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectNumOfInterfaces(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * For more control over the results, see virConnectListAllInterfaces().
 *
 * Returns the number of interfaces found or -1 in case of error.  Note that
 * this command is inherently racy; a interface can be started between a call
 * to virConnectNumOfInterfaces() and this call; you are only guaranteed that
 * all currently active interfaces were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 */
int
virConnectListInterfaces(virConnectPtr conn, char **const names, int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->interfaceDriver && conn->interfaceDriver->connectListInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListInterfaces(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->connectNumOfDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectNumOfDefinedInterfaces(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * For more control over the results, see virConnectListAllInterfaces().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a interface can be defined between
 * a call to virConnectNumOfDefinedInterfaces() and this call; you are only
 * guaranteed that all currently defined interfaces were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 */
int
virConnectListDefinedInterfaces(virConnectPtr conn,
                                char **const names,
                                int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->interfaceDriver && conn->interfaceDriver->connectListDefinedInterfaces) {
        int ret;
        ret = conn->interfaceDriver->connectListDefinedInterfaces(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(name, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByName) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, macstr=%s", conn, macstr);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(macstr, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceLookupByMACString) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceLookupByMACString(conn, macstr);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return iface->name;
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
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return iface->mac;
}

/**
 * virInterfaceGetXMLDesc:
 * @iface: an interface object
 * @flags: bitwise-OR of extraction flags. Current valid bits:
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
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = iface->conn;

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceGetXMLDesc) {
        char *ret;
        ret = conn->interfaceDriver->interfaceGetXMLDesc(iface, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(iface->conn);
    return NULL;
}

/**
 * virInterfaceDefineXML:
 * @conn: pointer to the hypervisor connection
 * @xml: the XML description for the interface, preferably in UTF-8
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Define an interface (or modify existing interface configuration).
 *
 * Normally this change in the interface configuration is immediately
 * permanent/persistent, but if virInterfaceChangeBegin() has been
 * previously called (i.e. if an interface config transaction is
 * open), the new interface definition will only become permanent if
 * virInterfaceChangeCommit() is called prior to the next reboot of
 * the system running libvirtd. Prior to that time, it can be
 * explicitly removed using virInterfaceChangeRollback(), or will be
 * automatically removed during the next reboot of the system running
 * libvirtd.
 *
 * Returns NULL in case of error, a pointer to the interface otherwise
 */
virInterfacePtr
virInterfaceDefineXML(virConnectPtr conn, const char *xml, unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=%x", conn, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(xml, error);

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDefineXML) {
        virInterfacePtr ret;
        ret = conn->interfaceDriver->interfaceDefineXML(conn, xml, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Normally this change in the interface configuration is
 * permanent/persistent, but if virInterfaceChangeBegin() has been
 * previously called (i.e. if an interface config transaction is
 * open), the removal of the interface definition will only become
 * permanent if virInterfaceChangeCommit() is called prior to the next
 * reboot of the system running libvirtd. Prior to that time, the
 * definition can be explicitly restored using
 * virInterfaceChangeRollback(), or will be automatically restored
 * during the next reboot of the system running libvirtd.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceUndefine(virInterfacePtr iface) {
    virConnectPtr conn;
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceUndefine) {
        int ret;
        ret = conn->interfaceDriver->interfaceUndefine(iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(iface->conn);
    return -1;
}

/**
 * virInterfaceCreate:
 * @iface: pointer to a defined interface
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Activate an interface (i.e. call "ifup").
 *
 * If there was an open network config transaction at the time this
 * interface was defined (that is, if virInterfaceChangeBegin() had
 * been called), the interface will be brought back down (and then
 * undefined) if virInterfaceChangeRollback() is called.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virInterfaceCreate(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceCreate) {
        int ret;
        ret = conn->interfaceDriver->interfaceCreate(iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(iface->conn);
    return -1;
}

/**
 * virInterfaceDestroy:
 * @iface: an interface object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * deactivate an interface (ie call "ifdown")
 * This does not remove the interface from the config, and
 * does not free the associated virInterfacePtr object.
 *

 * If there is an open network config transaction at the time this
 * interface is destroyed (that is, if virInterfaceChangeBegin() had
 * been called), and if the interface is later undefined and then
 * virInterfaceChangeRollback() is called, the restoral of the
 * interface definition will also bring the interface back up.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceDestroy(virInterfacePtr iface, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("iface=%p, flags=%x", iface, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = iface->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceDestroy) {
        int ret;
        ret = conn->interfaceDriver->interfaceDestroy(iface, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibConnError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("iface=%p refs=%d", iface, iface->object.refs);
    virObjectRef(iface);
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
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibInterfaceError(VIR_ERR_INVALID_INTERFACE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(iface);
    return 0;
}

/**
 * virInterfaceChangeBegin:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This function creates a restore point to which one can return
 * later by calling virInterfaceChangeRollback(). This function should
 * be called before any transaction with interface configuration.
 * Once it is known that a new configuration works, it can be committed via
 * virInterfaceChangeCommit(), which frees the restore point.
 *
 * If virInterfaceChangeBegin() is called when a transaction is
 * already opened, this function will fail, and a
 * VIR_ERR_INVALID_OPERATION will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeBegin(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceChangeBegin) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeBegin(conn, flags);
        if (ret < 0)
           goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virInterfaceChangeCommit:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This commits the changes made to interfaces and frees the restore point
 * created by virInterfaceChangeBegin().
 *
 * If virInterfaceChangeCommit() is called when a transaction is not
 * opened, this function will fail, and a VIR_ERR_INVALID_OPERATION
 * will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeCommit(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver && conn->interfaceDriver->interfaceChangeCommit) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeCommit(conn, flags);
        if (ret < 0)
           goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virInterfaceChangeRollback:
 * @conn: pointer to hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This cancels changes made to interfaces settings by restoring previous
 * state created by virInterfaceChangeBegin().
 *
 * If virInterfaceChangeRollback() is called when a transaction is not
 * opened, this function will fail, and a VIR_ERR_INVALID_OPERATION
 * will be logged.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virInterfaceChangeRollback(virConnectPtr conn, unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibInterfaceError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->interfaceDriver &&
        conn->interfaceDriver->interfaceChangeRollback) {
        int ret;
        ret = conn->interfaceDriver->interfaceChangeRollback(conn, flags);
        if (ret < 0)
           goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
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
virStoragePoolGetConnect(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return pool->conn;
}

/**
 * virConnectListAllStoragePools:
 * @conn: Pointer to the hypervisor connection.
 * @pools: Pointer to a variable to store the array containing storage pool
 *         objects or NULL if the list is not required (just returns number
 *         of pools).
 * @flags: bitwise-OR of virConnectListAllStoragePoolsFlags.
 *
 * Collect the list of storage pools, and allocate an array to store those
 * objects. This API solves the race inherent between
 * virConnectListStoragePools and virConnectListDefinedStoragePools.
 *
 * Normally, all storage pools are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted pools.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a pool, and where all bits
 * within a group describe all possible pools.
 *
 * The first group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE (online)
 * and VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE (offline) to filter the pools
 * by state.
 *
 * The second group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_PERSITENT
 * (defined) and VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT (running but not
 * defined), to filter the pools by whether they have persistent config or not.
 *
 * The third group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART
 * and VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART, to filter the pools by
 * whether they are marked as autostart or not.
 *
 * The last group of @flags is provided to filter the pools by the types,
 * the flags include:
 * VIR_CONNECT_LIST_STORAGE_POOLS_DIR
 * VIR_CONNECT_LIST_STORAGE_POOLS_FS
 * VIR_CONNECT_LIST_STORAGE_POOLS_NETFS
 * VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL
 * VIR_CONNECT_LIST_STORAGE_POOLS_DISK
 * VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI
 * VIR_CONNECT_LIST_STORAGE_POOLS_SCSI
 * VIR_CONNECT_LIST_STORAGE_POOLS_MPATH
 * VIR_CONNECT_LIST_STORAGE_POOLS_RBD
 * VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG
 *
 * Returns the number of storage pools found or -1 and sets @pools to
 * NULL in case of error.  On success, the array stored into @pools is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virStoragePoolFree() on each array element, then calling
 * free() on @pools.
 */
int
virConnectListAllStoragePools(virConnectPtr conn,
                              virStoragePoolPtr **pools,
                              unsigned int flags)
{
    VIR_DEBUG("conn=%p, pools=%p, flags=%x", conn, pools, flags);

    virResetLastError();

    if (pools)
        *pools = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->storageDriver &&
        conn->storageDriver->connectListAllStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListAllStoragePools(conn, pools, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
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
virConnectNumOfStoragePools(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->storageDriver && conn->storageDriver->connectNumOfStoragePools) {
        int ret;
        ret = conn->storageDriver->connectNumOfStoragePools(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Provides the list of names of active storage pools up to maxnames.
 * If there are more than maxnames, the remaining names will be silently
 * ignored.
 *
 * For more control over the results, see virConnectListAllStoragePools().
 *
 * Returns the number of pools found or -1 in case of error.  Note that
 * this command is inherently racy; a pool can be started between a call to
 * virConnectNumOfStoragePools() and this call; you are only guaranteed
 * that all currently active pools were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 */
int
virConnectListStoragePools(virConnectPtr conn,
                           char **const names,
                           int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->storageDriver && conn->storageDriver->connectListStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListStoragePools(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->storageDriver && conn->storageDriver->connectNumOfDefinedStoragePools) {
        int ret;
        ret = conn->storageDriver->connectNumOfDefinedStoragePools(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Provides the list of names of inactive storage pools up to maxnames.
 * If there are more than maxnames, the remaining names will be silently
 * ignored.
 *
 * For more control over the results, see virConnectListAllStoragePools().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a pool can be defined between
 * a call to virConnectNumOfDefinedStoragePools() and this call; you are only
 * guaranteed that all currently defined pools were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 */
int
virConnectListDefinedStoragePools(virConnectPtr conn,
                                  char **const names,
                                  int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->storageDriver && conn->storageDriver->connectListDefinedStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListDefinedStoragePools(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectFindStoragePoolSources:
 * @conn: pointer to hypervisor connection
 * @type: type of storage pool sources to discover
 * @srcSpec: XML document specifying discovery source
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, type=%s, src=%s, flags=%x",
              conn, NULLSTR(type), NULLSTR(srcSpec), flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(type, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->connectFindStoragePoolSources) {
        char *ret;
        ret = conn->storageDriver->connectFindStoragePoolSources(conn, type, srcSpec, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(name, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolLookupByName) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuid, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolLookupByUUID) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
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
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (vol->conn->storageDriver && vol->conn->storageDriver->storagePoolLookupByVolume) {
        virStoragePoolPtr ret;
        ret = vol->conn->storageDriver->storagePoolLookupByVolume(vol);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return NULL;
}

/**
 * virStoragePoolCreateXML:
 * @conn: pointer to hypervisor connection
 * @xmlDesc: XML description for new pool
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolCreateXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolCreateXML(conn, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virStoragePoolDefineXML:
 * @conn: pointer to hypervisor connection
 * @xml: XML description for new pool
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, xml=%s, flags=%x", conn, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(xml, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolDefineXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolDefineXML(conn, xml, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virStoragePoolBuild:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStoragePoolBuildFlags
 *
 * Currently only filesystem pool accepts flags VIR_STORAGE_POOL_BUILD_OVERWRITE
 * and VIR_STORAGE_POOL_BUILD_NO_OVERWRITE.
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
    VIR_DEBUG("pool=%p, flags=%x", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolBuild) {
        int ret;
        ret = conn->storageDriver->storagePoolBuild(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolUndefine) {
        int ret;
        ret = conn->storageDriver->storagePoolUndefine(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolCreate:
 * @pool: pointer to storage pool
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("pool=%p, flags=%x", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolCreate) {
        int ret;
        ret = conn->storageDriver->storagePoolCreate(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolDestroy) {
        int ret;
        ret = conn->storageDriver->storagePoolDestroy(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return -1;
}

/**
 * virStoragePoolDelete:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStoragePoolDeleteFlags
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
    VIR_DEBUG("pool=%p, flags=%x", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolDelete) {
        int ret;
        ret = conn->storageDriver->storagePoolDelete(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(pool);
    return 0;

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
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("pool=%p refs=%d", pool, pool->object.refs);
    virObjectRef(pool);
    return 0;
}

/**
 * virStoragePoolRefresh:
 * @pool: pointer to storage pool
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("pool=%p, flags=%x", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storagePoolRefresh) {
        int ret;
        ret = conn->storageDriver->storagePoolRefresh(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return pool->name;
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
    VIR_DEBUG("pool=%p, uuid=%p", pool, uuid);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &pool->uuid[0], VIR_UUID_BUFLEN);

    return 0;

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
    VIR_DEBUG("pool=%p, buf=%p", pool, buf);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(buf, error);

    if (virStoragePoolGetUUID(pool, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return 0;

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
    VIR_DEBUG("pool=%p, info=%p", pool, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);

    memset(info, 0, sizeof(virStoragePoolInfo));

    conn = pool->conn;

    if (conn->storageDriver->storagePoolGetInfo) {
        int ret;
        ret = conn->storageDriver->storagePoolGetInfo(pool, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetXMLDesc:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStorageXMLFlags
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
    VIR_DEBUG("pool=%p, flags=%x", pool, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->storagePoolGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->storagePoolGetXMLDesc(pool, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p, autostart=%p", pool, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(autostart, error);

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->storagePoolGetAutostart) {
        int ret;
        ret = conn->storageDriver->storagePoolGetAutostart(pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p, autostart=%d", pool, autostart);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (pool->conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->storagePoolSetAutostart) {
        int ret;
        ret = conn->storageDriver->storagePoolSetAutostart(pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return -1;
}

/**
 * virStoragePoolListAllVolumes:
 * @pool: Pointer to storage pool
 * @vols: Pointer to a variable to store the array containing storage volume
 *        objects or NULL if the list is not required (just returns number
 *        of volumes).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of storage volumes, and allocate an array to store those
 * objects.
 *
 * Returns the number of storage volumes found or -1 and sets @vols to
 * NULL in case of error.  On success, the array stored into @vols is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virStorageVolFree() on each array element, then calling
 * free() on @vols.
 */
int
virStoragePoolListAllVolumes(virStoragePoolPtr pool,
                             virStorageVolPtr **vols,
                             unsigned int flags)
{
    VIR_DEBUG("pool=%p, vols=%p, flags=%x", pool, vols, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (pool->conn->storageDriver &&
        pool->conn->storageDriver->storagePoolListAllVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolListAllVolumes(pool, vols, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->storagePoolNumOfVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolNumOfVolumes(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * To list the volume objects directly, see virStoragePoolListAllVolumes().
 *
 * Returns the number of names fetched, or -1 on error
 */
int
virStoragePoolListVolumes(virStoragePoolPtr pool,
                          char **const names,
                          int maxnames)
{
    VIR_DEBUG("pool=%p, names=%p, maxnames=%d", pool, names, maxnames);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storagePoolListVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolListVolumes(pool, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
virStorageVolGetConnect(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
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
    VIR_DEBUG("pool=%p, name=%s", pool, name);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(name, error);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storageVolLookupByName) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolLookupByName(pool, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, key=%s", conn, key);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(key, error);

    if (conn->storageDriver && conn->storageDriver->storageVolLookupByKey) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->storageVolLookupByKey(conn, key);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, path=%s", conn, path);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(path, error);

    if (conn->storageDriver && conn->storageDriver->storageVolLookupByPath) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->storageVolLookupByPath(conn, path);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return vol->name;
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
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return vol->key;
}


/**
 * virStorageVolCreateXML:
 * @pool: pointer to storage pool
 * @xmlDesc: description of volume to create
 * @flags: bitwise-OR of virStorageVolCreateFlags
 *
 * Create a storage volume within a pool based
 * on an XML description. Not all pools support
 * creation of volumes.
 *
 * Since 1.0.1 VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA
 * in flags can be used to get higher performance with
 * qcow2 image files which don't support full preallocation,
 * by creating a sparse image file with metadata.
 *
 * Returns the storage volume, or NULL on error
 */
virStorageVolPtr
virStorageVolCreateXML(virStoragePoolPtr pool,
                       const char *xmlDesc,
                       unsigned int flags)
{
    VIR_DEBUG("pool=%p, xmlDesc=%s, flags=%x", pool, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(xmlDesc, error);

    if (pool->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->storageVolCreateXML) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolCreateXML(pool, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolCreateXMLFrom:
 * @pool: pointer to parent pool for the new volume
 * @xmlDesc: description of volume to create
 * @clonevol: storage volume to use as input
 * @flags: bitwise-OR of virStorageVolCreateFlags
 *
 * Create a storage volume in the parent pool, using the
 * 'clonevol' volume as input. Information for the new
 * volume (name, perms)  are passed via a typical volume
 * XML description.
 *
 * Since 1.0.1 VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA
 * in flags can be used to get higher performance with
 * qcow2 image files which don't support full preallocation,
 * by creating a sparse image file with metadata.
 *
 * Returns the storage volume, or NULL on error
 */
virStorageVolPtr
virStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                           const char *xmlDesc,
                           virStorageVolPtr clonevol,
                           unsigned int flags)
{
    VIR_DEBUG("pool=%p, xmlDesc=%s, clonevol=%p, flags=%x",
              pool, xmlDesc, clonevol, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (!VIR_IS_STORAGE_VOL(clonevol)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(xmlDesc, error);

    if (pool->conn->flags & VIR_CONNECT_RO ||
        clonevol->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (pool->conn->storageDriver &&
        pool->conn->storageDriver->storageVolCreateXMLFrom) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolCreateXMLFrom(pool, xmlDesc,
                                                          clonevol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolDownload:
 * @vol: pointer to volume to download from
 * @stream: stream to use as output
 * @offset: position in @vol to start reading from
 * @length: limit on amount of data to download
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Download the content of the volume as a stream. If @length
 * is zero, then the remaining contents of the volume after
 * @offset will be downloaded.
 *
 * This call sets up an asynchronous stream; subsequent use of
 * stream APIs is necessary to transfer the actual data,
 * determine how much data is successfully transferred, and
 * detect any errors. The results will be unpredictable if
 * another active stream is writing to the storage volume.
 *
 * Returns 0, or -1 upon error.
 */
int
virStorageVolDownload(virStorageVolPtr vol,
                      virStreamPtr stream,
                      unsigned long long offset,
                      unsigned long long length,
                      unsigned int flags)
{
    VIR_DEBUG("vol=%p, stream=%p, offset=%llu, length=%llu, flags=%x",
              vol, stream, offset, length, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return -1;
    }

    if (!VIR_IS_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_STREAM, __FUNCTION__);
        return -1;
    }

    if (vol->conn->flags & VIR_CONNECT_RO ||
        stream->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (vol->conn->storageDriver &&
        vol->conn->storageDriver->storageVolDownload) {
        int ret;
        ret = vol->conn->storageDriver->storageVolDownload(vol,
                                                           stream,
                                                           offset,
                                                           length,
                                                           flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolUpload:
 * @vol: pointer to volume to upload
 * @stream: stream to use as input
 * @offset: position to start writing to
 * @length: limit on amount of data to upload
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Upload new content to the volume from a stream. This call
 * will fail if @offset + @length exceeds the size of the
 * volume. Otherwise, if @length is non-zero, an error
 * will be raised if an attempt is made to upload greater
 * than @length bytes of data.
 *
 * This call sets up an asynchronous stream; subsequent use of
 * stream APIs is necessary to transfer the actual data,
 * determine how much data is successfully transferred, and
 * detect any errors. The results will be unpredictable if
 * another active stream is writing to the storage volume.
 *
 * Returns 0, or -1 upon error.
 */
int
virStorageVolUpload(virStorageVolPtr vol,
                    virStreamPtr stream,
                    unsigned long long offset,
                    unsigned long long length,
                    unsigned int flags)
{
    VIR_DEBUG("vol=%p, stream=%p, offset=%llu, length=%llu, flags=%x",
              vol, stream, offset, length, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibConnError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return -1;
    }

    if (!VIR_IS_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_STREAM, __FUNCTION__);
        return -1;
    }

    if (vol->conn->flags & VIR_CONNECT_RO ||
        stream->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (vol->conn->storageDriver &&
        vol->conn->storageDriver->storageVolUpload) {
        int ret;
        ret = vol->conn->storageDriver->storageVolUpload(vol,
                                                  stream,
                                                  offset,
                                                  length,
                                                  flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolDelete:
 * @vol: pointer to storage volume
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("vol=%p, flags=%x", vol, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storageVolDelete) {
        int ret;
        ret = conn->storageDriver->storageVolDelete(vol, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolWipe:
 * @vol: pointer to storage volume
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("vol=%p, flags=%x", vol, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storageVolWipe) {
        int ret;
        ret = conn->storageDriver->storageVolWipe(vol, flags);
        if (ret < 0) {
            goto error;
        }
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolWipePattern:
 * @vol: pointer to storage volume
 * @algorithm: one of virStorageVolWipeAlgorithm
 * @flags: future flags, use 0 for now
 *
 * Similar to virStorageVolWipe, but one can choose
 * between different wiping algorithms.
 *
 * Returns 0 on success, or -1 on error.
 */
int
virStorageVolWipePattern(virStorageVolPtr vol,
                         unsigned int algorithm,
                         unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, algorithm=%u, flags=%x", vol, algorithm, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storageVolWipePattern) {
        int ret;
        ret = conn->storageDriver->storageVolWipePattern(vol, algorithm, flags);
        if (ret < 0) {
            goto error;
        }
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(vol);
    return 0;
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
        virLibConnError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("vol=%p refs=%d", vol, vol->object.refs);
    virObjectRef(vol);
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
    VIR_DEBUG("vol=%p, info=%p", vol, info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);

    memset(info, 0, sizeof(virStorageVolInfo));

    conn = vol->conn;

    if (conn->storageDriver->storageVolGetInfo){
        int ret;
        ret = conn->storageDriver->storageVolGetInfo(vol, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolGetXMLDesc:
 * @vol: pointer to storage volume
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("vol=%p, flags=%x", vol, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->storageVolGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->storageVolGetXMLDesc(vol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Returns the storage volume path, or NULL on error. The
 * caller must free() the returned path after use.
 */
char *
virStorageVolGetPath(virStorageVolPtr vol)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->storageVolGetPath) {
        char *ret;
        ret = conn->storageDriver->storageVolGetPath(vol);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return NULL;
}

/**
 * virStorageVolResize:
 * @vol: pointer to storage volume
 * @capacity: new capacity, in bytes
 * @flags: bitwise-OR of virStorageVolResizeFlags
 *
 * Changes the capacity of the storage volume @vol to @capacity. The
 * operation will fail if the new capacity requires allocation that would
 * exceed the remaining free space in the parent pool.  The contents of
 * the new capacity will appear as all zero bytes. The capacity value will
 * be rounded to the granularity supported by the hypervisor.
 *
 * Normally, the operation will attempt to affect capacity with a minimum
 * impact on allocation (that is, the default operation favors a sparse
 * resize).  If @flags contains VIR_STORAGE_VOL_RESIZE_ALLOCATE, then the
 * operation will ensure that allocation is sufficient for the new
 * capacity; this may make the operation take noticeably longer.
 *
 * Normally, the operation treats @capacity as the new size in bytes;
 * but if @flags contains VIR_STORAGE_VOL_RESIZE_DELTA, then @capacity
 * represents the size difference to add to the current size.  It is
 * up to the storage pool implementation whether unaligned requests are
 * rounded up to the next valid boundary, or rejected.
 *
 * Normally, this operation should only be used to enlarge capacity;
 * but if @flags contains VIR_STORAGE_VOL_RESIZE_SHRINK, it is possible to
 * attempt a reduction in capacity even though it might cause data loss.
 * If VIR_STORAGE_VOL_RESIZE_DELTA is also present, then @capacity is
 * subtracted from the current size; without it, @capacity represents
 * the absolute new size regardless of whether it is larger or smaller
 * than the current size.
 *
 * Returns 0 on success, or -1 on error.
 */
int
virStorageVolResize(virStorageVolPtr vol,
                    unsigned long long capacity,
                    unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p capacity=%llu flags=%x", vol, capacity, flags);

    virResetLastError();

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = vol->conn;

    if (conn->flags & VIR_CONNECT_RO) {
       virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
       goto error;
    }

    /* Zero capacity is only valid with either delta or shrink.  */
    if (capacity == 0 && !((flags & VIR_STORAGE_VOL_RESIZE_DELTA) ||
                           (flags & VIR_STORAGE_VOL_RESIZE_SHRINK))) {
        virReportInvalidArg(capacity,
                            _("capacity in %s cannot be zero without 'delta' or 'shrink' flags set"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storageVolResize) {
        int ret;
        ret = conn->storageDriver->storageVolResize(vol, capacity, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(vol->conn);
    return -1;
}

/**
 * virNodeNumOfDevices:
 * @conn: pointer to the hypervisor connection
 * @cap: capability name
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, cap=%s, flags=%x", conn, NULLSTR(cap), flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeNumOfDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->nodeNumOfDevices(conn, cap, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListAllNodeDevices:
 * @conn: Pointer to the hypervisor connection.
 * @devices: Pointer to a variable to store the array containing the node
 *           device objects or NULL if the list is not required (just returns
 *           number of node devices).
 * @flags: bitwise-OR of virConnectListAllNodeDevices.
 *
 * Collect the list of node devices, and allocate an array to store those
 * objects.
 *
 * Normally, all node devices are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted node devices.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a node device, and where all bits
 * within a group describe all possible node devices.
 *
 * Only one group of the @flags is provided to filter the node devices by
 * capability type, flags include:
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPORTS
 *   VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC
 *
 * Returns the number of node devices found or -1 and sets @devices to NULL in
 * case of error.  On success, the array stored into @devices is guaranteed to
 * have an extra allocated element set to NULL but not included in the return
 * count, to make iteration easier.  The caller is responsible for calling
 * virNodeDeviceFree() on each array element, then calling free() on
 * @devices.
 */
int
virConnectListAllNodeDevices(virConnectPtr conn,
                             virNodeDevicePtr **devices,
                             unsigned int flags)
{
    VIR_DEBUG("conn=%p, devices=%p, flags=%x", conn, devices, flags);

    virResetLastError();

    if (devices)
        *devices = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->connectListAllNodeDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->connectListAllNodeDevices(conn, devices, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of node devices, and store their names in @names
 *
 * For more control over the results, see virConnectListAllNodeDevices().
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
    VIR_DEBUG("conn=%p, cap=%s, names=%p, maxnames=%d, flags=%x",
          conn, cap, names, maxnames, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeListDevices) {
        int ret;
        ret = conn->nodeDeviceDriver->nodeListDevices(conn, cap, names, maxnames, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, name=%p", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(name, error);

    if (conn->nodeDeviceDriver && conn->nodeDeviceDriver->nodeDeviceLookupByName) {
        virNodeDevicePtr ret;
        ret = conn->nodeDeviceDriver->nodeDeviceLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virNodeDeviceLookupSCSIHostByWWN:
 * @conn: pointer to the hypervisor connection
 * @wwnn: WWNN of the SCSI Host.
 * @wwpn: WWPN of the SCSI Host.
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Lookup SCSI Host which is capable with 'fc_host' by its WWNN and WWPN.
 *
 * Returns a virNodeDevicePtr if found, NULL otherwise.
 */
virNodeDevicePtr
virNodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                                 const char *wwnn,
                                 const char *wwpn,
                                 unsigned int flags)
{
    VIR_DEBUG("conn=%p, wwnn=%p, wwpn=%p, flags=%x", conn, wwnn, wwpn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckNonNullArgGoto(wwnn, error);
    virCheckNonNullArgGoto(wwpn, error);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->nodeDeviceLookupSCSIHostByWWN) {
        virNodeDevicePtr ret;
        ret = conn->nodeDeviceDriver->nodeDeviceLookupSCSIHostByWWN(conn, wwnn,
                                                             wwpn, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virNodeDeviceGetXMLDesc:
 * @dev: pointer to the node device
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Fetch an XML document describing all aspects of
 * the device.
 *
 * Returns the XML document, or NULL on error
 */
char *virNodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags)
{
    VIR_DEBUG("dev=%p, conn=%p, flags=%x", dev, dev ? dev->conn : NULL, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceGetXMLDesc) {
        char *ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceGetXMLDesc(dev, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (!dev->parent) {
        if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceGetParent) {
            dev->parent = dev->conn->nodeDeviceDriver->nodeDeviceGetParent(dev);
        } else {
            virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceNumOfCaps) {
        int ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceNumOfCaps(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("dev=%p, conn=%p, names=%p, maxnames=%d",
          dev, dev ? dev->conn : NULL, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (dev->conn->nodeDeviceDriver && dev->conn->nodeDeviceDriver->nodeDeviceListCaps) {
        int ret;
        ret = dev->conn->nodeDeviceDriver->nodeDeviceListCaps(dev, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(dev);
    return 0;
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
        virLibConnError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("dev=%p refs=%d", dev, dev->object.refs);
    virObjectRef(dev);
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
 * If the caller needs control over which backend driver will be used
 * during PCI device assignment (to use something other than the
 * default, for example VFIO), the newer virNodeDeviceDetachFlags()
 * API should be used instead.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceDettach(virNodeDevicePtr dev)
{
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->driver->nodeDeviceDettach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceDettach(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dev->conn);
    return -1;
}

/**
 * virNodeDeviceDetachFlags:
 * @dev: pointer to the node device
 * @driverName: name of backend driver that will be used
 *              for later device assignment to a domain. NULL
 *              means "use the hypervisor default driver"
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Detach the node device from the node itself so that it may be
 * assigned to a guest domain.
 *
 * Depending on the hypervisor, this may involve operations such as
 * unbinding any device drivers from the device, binding the device to
 * a dummy device driver and resetting the device. Different backend
 * drivers expect the device to be bound to different dummy
 * devices. For example, QEMU's "kvm" backend driver (the default)
 * expects the device to be bound to "pci-stub", but its "vfio"
 * backend driver expects the device to be bound to "vfio-pci".
 *
 * If the device is currently in use by the node, this method may
 * fail.
 *
 * Once the device is not assigned to any guest, it may be re-attached
 * to the node using the virNodeDeviceReAttach() method.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virNodeDeviceDetachFlags(virNodeDevicePtr dev,
                         const char *driverName,
                         unsigned int flags)
{
    VIR_DEBUG("dev=%p, conn=%p driverName=%s flags=%x",
              dev, dev ? dev->conn : NULL,
              driverName ? driverName : "(default)", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->driver->nodeDeviceDetachFlags) {
        int ret;
        ret = dev->conn->driver->nodeDeviceDetachFlags(dev, driverName, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dev->conn);
    return -1;
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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->driver->nodeDeviceReAttach) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReAttach(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dev->conn);
    return -1;
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
    VIR_DEBUG("dev=%p, conn=%p", dev, dev ? dev->conn : NULL);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->driver->nodeDeviceReset) {
        int ret;
        ret = dev->conn->driver->nodeDeviceReset(dev);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dev->conn);
    return -1;
}


/**
 * virNodeDeviceCreateXML:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the device to be created
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->nodeDeviceDriver &&
        conn->nodeDeviceDriver->nodeDeviceCreateXML) {
        virNodeDevicePtr dev = conn->nodeDeviceDriver->nodeDeviceCreateXML(conn, xmlDesc, flags);
        if (dev == NULL)
            goto error;
        return dev;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("dev=%p", dev);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NODE_DEVICE(dev)) {
        virLibNodeDeviceError(VIR_ERR_INVALID_NODE_DEVICE, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dev->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dev->conn->nodeDeviceDriver &&
        dev->conn->nodeDeviceDriver->nodeDeviceDestroy) {
        int retval = dev->conn->nodeDeviceDriver->nodeDeviceDestroy(dev);
        if (retval < 0) {
            goto error;
        }

        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * If the callback wishes to keep the domain object after the callback returns,
 * it shall take a reference to it, by calling virDomainRef.
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
    VIR_DEBUG("conn=%p, cb=%p, opaque=%p, freecb=%p", conn, cb, opaque, freecb);
    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(cb, error);

    if ((conn->driver) && (conn->driver->connectDomainEventRegister)) {
        int ret;
        ret = conn->driver->connectDomainEventRegister(conn, cb, opaque, freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * function.
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
    VIR_DEBUG("conn=%p, cb=%p", conn, cb);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(cb, error);

    if ((conn->driver) && (conn->driver->connectDomainEventDeregister)) {
        int ret;
        ret = conn->driver->connectDomainEventDeregister(conn, cb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
virSecretGetConnect(virSecretPtr secret)
{
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
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
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->secretDriver != NULL &&
        conn->secretDriver->connectNumOfSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->connectNumOfSecrets(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListAllSecrets:
 * @conn: Pointer to the hypervisor connection.
 * @secrets: Pointer to a variable to store the array containing the secret
 *           objects or NULL if the list is not required (just returns the
 *           number of secrets).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of secrets, and allocate an array to store those
 * objects.
 *
 * Normally, all secrets are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted secrets. The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a secret, and where all bits
 * within a group describe all possible secrets.
 *
 * The first group of @flags is used to filter secrets by its storage
 * location. Flag VIR_CONNECT_LIST_SECRETS_EPHEMERAL selects secrets that
 * are kept only in memory. Flag VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL
 * selects secrets that are kept in persistent storage.
 *
 * The second group of @flags is used to filter secrets by privacy. Flag
 * VIR_CONNECT_LIST_SECRETS_PRIVATE seclets secrets that are never revealed
 * to any caller of libvirt nor to any other node. Flag
 * VIR_CONNECT_LIST_SECRETS_NO_PRIVATE selects non-private secrets.
 *
 * Returns the number of secrets found or -1 and sets @secrets to NULL in case
 * of error.  On success, the array stored into @secrets is guaranteed to
 * have an extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virSecretFree() on each array element, then calling free() on @secrets.
 */
int
virConnectListAllSecrets(virConnectPtr conn,
                         virSecretPtr **secrets,
                         unsigned int flags)
{
    VIR_DEBUG("conn=%p, secrets=%p, flags=%x", conn, secrets, flags);

    virResetLastError();

    if (secrets)
        *secrets = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->secretDriver &&
        conn->secretDriver->connectListAllSecrets) {
        int ret;
        ret = conn->secretDriver->connectListAllSecrets(conn, secrets, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(uuids, error);
    virCheckNonNegativeArgGoto(maxuuids, error);

    if (conn->secretDriver != NULL && conn->secretDriver->connectListSecrets != NULL) {
        int ret;

        ret = conn->secretDriver->connectListSecrets(conn, uuids, maxuuids);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuid, error);

    if (conn->secretDriver &&
        conn->secretDriver->secretLookupByUUID) {
        virSecretPtr ret;
        ret = conn->secretDriver->secretLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
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
    VIR_DEBUG("conn=%p, usageType=%d usageID=%s", conn, usageType, NULLSTR(usageID));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(usageID, error);

    if (conn->secretDriver &&
        conn->secretDriver->secretLookupByUsage) {
        virSecretPtr ret;
        ret = conn->secretDriver->secretLookupByUsage(conn, usageType, usageID);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virSecretDefineXML:
 * @conn: virConnect connection
 * @xml: XML describing the secret.
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, xml=%s, flags=%x", conn, xml, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(xml, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretDefineXML != NULL) {
        virSecretPtr ret;

        ret = conn->secretDriver->secretDefineXML(conn, xml, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &secret->uuid[0], VIR_UUID_BUFLEN);

    return 0;

error:
    virDispatchError(secret->conn);
    return -1;
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
    VIR_DEBUG("secret=%p, buf=%p", secret, buf);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(buf, error);

    if (virSecretGetUUID(secret, &uuid[0]))
        goto error;

    virUUIDFormat(uuid, buf);
    return 0;

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
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    return secret->usageType;
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
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return secret->usageID;
}


/**
 * virSecretGetXMLDesc:
 * @secret: A virSecret secret
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DEBUG("secret=%p, flags=%x", secret, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = secret->conn;
    if (conn->secretDriver != NULL && conn->secretDriver->secretGetXMLDesc != NULL) {
        char *ret;

        ret = conn->secretDriver->secretGetXMLDesc(secret, flags);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virSecretSetValue:
 * @secret: A virSecret secret
 * @value: Value of the secret
 * @value_size: Size of the value
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DEBUG("secret=%p, value=%p, value_size=%zu, flags=%x", secret, value,
              value_size, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(value, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretSetValue != NULL) {
        int ret;

        ret = conn->secretDriver->secretSetValue(secret, value, value_size, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virSecretGetValue:
 * @secret: A virSecret connection
 * @value_size: Place for storing size of the secret value
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DEBUG("secret=%p, value_size=%p, flags=%x", secret, value_size, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }
    virCheckNonNullArgGoto(value_size, error);

    if (conn->secretDriver != NULL && conn->secretDriver->secretGetValue != NULL) {
        unsigned char *ret;

        ret = conn->secretDriver->secretGetValue(secret, value_size, flags, 0);
        if (ret == NULL)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = secret->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibSecretError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->secretDriver != NULL && conn->secretDriver->secretUndefine != NULL) {
        int ret;

        ret = conn->secretDriver->secretUndefine(secret);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("secret=%p refs=%d", secret, secret->object.refs);
    virObjectRef(secret);
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
    VIR_DEBUG("secret=%p", secret);

    virResetLastError();

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibSecretError(VIR_ERR_INVALID_SECRET, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(secret);
    return 0;
}


/**
 * virStreamNew:
 * @conn: pointer to the connection
 * @flags: bitwise-OR of virStreamFlags
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

    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    st = virGetStream(conn);
    if (st)
        st->flags = flags;
    else
        virDispatchError(conn);

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
        virLibConnError(VIR_ERR_INVALID_STREAM, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("stream=%p refs=%d", stream, stream->object.refs);
    virObjectRef(stream);
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
 * confirmation from the driver, or detect any error.
 *
 * This method may not be used if a stream source has been
 * registered.
 *
 * Errors are not guaranteed to be reported synchronously
 * with the call, but may instead be delayed until a
 * subsequent call.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *     virStreamPtr st = virStreamNew(conn, 0);
 *     int fd = open("demo.iso", O_RDONLY)
 *
 *     virConnectUploadFile(conn, "demo.iso", st);
 *
 *     while (1) {
 *          char buf[1024];
 *          int got = read(fd, buf, 1024);
 *          if (got < 0) {
 *             virStreamAbort(st);
 *             break;
 *          }
 *          if (got == 0) {
 *             virStreamFinish(st);
 *             break;
 *          }
 *          int offset = 0;
 *          while (offset < got) {
 *             int sent = virStreamSend(st, buf+offset, got-offset)
 *             if (sent < 0) {
 *                virStreamAbort(st);
 *                goto done;
 *             }
 *             offset += sent;
 *          }
 *      }
 *      if (virStreamFinish(st) < 0)
 *         ... report an error ....
 *    done:
 *      virStreamFree(st);
 *      close(fd);
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
    VIR_DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(data, error);

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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamRecv:
 * @stream: pointer to the stream object
 * @data: buffer to read into from stream
 * @nbytes: size of @data buffer
 *
 * Reads a series of bytes from the stream. This method may
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
 *     virStreamPtr st = virStreamNew(conn, 0);
 *     int fd = open("demo.iso", O_WRONLY, 0600)
 *
 *     virConnectDownloadFile(conn, "demo.iso", st);
 *
 *     while (1) {
 *         char buf[1024];
 *         int got = virStreamRecv(st, buf, 1024);
 *         if (got < 0)
 *            break;
 *         if (got == 0) {
 *            virStreamFinish(st);
 *            break;
 *         }
 *         int offset = 0;
 *         while (offset < got) {
 *            int sent = write(fd, buf+offset, got-offset)
 *            if (sent < 0) {
 *               virStreamAbort(st);
 *               goto done;
 *            }
 *            offset += sent;
 *         }
 *     }
 *     if (virStreamFinish(st) < 0)
 *        ... report an error ....
 *   done:
 *     virStreamFree(st);
 *     close(fd);
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
    VIR_DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(data, error);

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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(handler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("data sources cannot be used for non-blocking streams"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(bytes, want) < 0)
        goto cleanup;

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
    VIR_DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(handler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("data sinks cannot be used for non-blocking streams"));
        goto cleanup;
    }


    if (VIR_ALLOC_N(bytes, want) < 0)
        goto cleanup;

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
    VIR_DEBUG("stream=%p, events=%d, cb=%p, opaque=%p, ff=%p", stream, events, cb, opaque, ff);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (stream->driver &&
        stream->driver->streamEventAddCallback) {
        int ret;
        ret = (stream->driver->streamEventAddCallback)(stream, events, cb, opaque, ff);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * is guaranteed to succeed if a callback is already registered
 *
 * Returns 0 on success, -1 if no callback is registered
 */
int virStreamEventUpdateCallback(virStreamPtr stream,
                                 int events)
{
    VIR_DEBUG("stream=%p, events=%d", stream, events);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (stream->driver &&
        stream->driver->streamEventUpdateCallback) {
        int ret;
        ret = (stream->driver->streamEventUpdateCallback)(stream, events);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (stream->driver &&
        stream->driver->streamEventRemoveCallback) {
        int ret;
        ret = (stream->driver->streamEventRemoveCallback)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (stream->driver &&
        stream->driver->streamFinish) {
        int ret;
        ret = (stream->driver->streamFinish)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (!stream->driver) {
        VIR_DEBUG("aborting unused stream");
        return 0;
    }

    if (stream->driver->streamAbort) {
        int ret;
        ret = (stream->driver->streamAbort)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STREAM(stream)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    /* XXX Enforce shutdown before free'ing resources ? */

    virObjectUnref(stream);
    return 0;
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
    VIR_DEBUG("dom=%p", dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (dom->conn->driver->domainIsActive) {
        int ret;
        ret = dom->conn->driver->domainIsActive(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (dom->conn->driver->domainIsPersistent) {
        int ret;
        ret = dom->conn->driver->domainIsPersistent(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainIsUpdated:
 * @dom: pointer to the domain object
 *
 * Determine if the domain has been updated.
 *
 * Returns 1 if updated, 0 if not, -1 on error
 */
int virDomainIsUpdated(virDomainPtr dom)
{
    VIR_DOMAIN_DEBUG(dom);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (dom->conn->driver->domainIsUpdated) {
        int ret;
        ret = dom->conn->driver->domainIsUpdated(dom);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(net)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (net->conn->networkDriver->networkIsActive) {
        int ret;
        ret = net->conn->networkDriver->networkIsActive(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("net=%p", net);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NETWORK(net)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (net->conn->networkDriver->networkIsPersistent) {
        int ret;
        ret = net->conn->networkDriver->networkIsPersistent(net);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (pool->conn->storageDriver->storagePoolIsActive) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolIsActive(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (pool->conn->storageDriver->storagePoolIsPersistent) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolIsPersistent(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->connectNumOfNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectNumOfNWFilters(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectListAllNWFilters:
 * @conn: Pointer to the hypervisor connection.
 * @filters: Pointer to a variable to store the array containing the network
 *           filter objects or NULL if the list is not required (just returns
 *           number of network filters).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of network filters, and allocate an array to store those
 * objects.
 *
 * Returns the number of network filters found or -1 and sets @filters to  NULL
 * in case of error.  On success, the array stored into @filters is guaranteed to
 * have an extra allocated element set to NULL but not included in the return count,
 * to make iteration easier.  The caller is responsible for calling
 * virNWFilterFree() on each array element, then calling free() on @filters.
 */
int
virConnectListAllNWFilters(virConnectPtr conn,
                           virNWFilterPtr **filters,
                           unsigned int flags)
{
    VIR_DEBUG("conn=%p, filters=%p, flags=%x", conn, filters, flags);

    virResetLastError();

    if (filters)
        *filters = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->nwfilterDriver &&
        conn->nwfilterDriver->connectListAllNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectListAllNWFilters(conn, filters, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->connectListNWFilters) {
        int ret;
        ret = conn->nwfilterDriver->connectListNWFilters(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, name=%s", conn, name);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(name, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByName) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuid, error);

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterLookupByUUID){
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %s must be a valid UUID"),
                            __FUNCTION__);
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
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virObjectUnref(nwfilter);
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
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return nwfilter->name;
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
    VIR_DEBUG("nwfilter=%p, uuid=%p", nwfilter, uuid);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(uuid, error);

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
    VIR_DEBUG("nwfilter=%p, buf=%p", nwfilter, buf);

    virResetLastError();

    if (!VIR_IS_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(buf, error);

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
    VIR_DEBUG("conn=%p, xmlDesc=%s", conn, xmlDesc);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterDefineXML) {
        virNWFilterPtr ret;
        ret = conn->nwfilterDriver->nwfilterDefineXML(conn, xmlDesc);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
    VIR_DEBUG("nwfilter=%p", nwfilter);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = nwfilter->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNWFilterError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterUndefine) {
        int ret;
        ret = conn->nwfilterDriver->nwfilterUndefine(nwfilter);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(nwfilter->conn);
    return -1;
}


/**
 * virNWFilterGetXMLDesc:
 * @nwfilter: a nwfilter object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Provide an XML description of the network filter. The description may be
 * reused later to redefine the network filter with virNWFilterCreateXML().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNWFilterGetXMLDesc(virNWFilterPtr nwfilter, unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("nwfilter=%p, flags=%x", nwfilter, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibNWFilterError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = nwfilter->conn;

    if (conn->nwfilterDriver && conn->nwfilterDriver->nwfilterGetXMLDesc) {
        char *ret;
        ret = conn->nwfilterDriver->nwfilterGetXMLDesc(nwfilter, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
        virLibConnError(VIR_ERR_INVALID_NWFILTER, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("nwfilter=%p refs=%d", nwfilter, nwfilter->object.refs);
    virObjectRef(nwfilter);
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
    VIR_DEBUG("iface=%p", iface);

    virResetLastError();

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (iface->conn->interfaceDriver->interfaceIsActive) {
        int ret;
        ret = iface->conn->interfaceDriver->interfaceIsActive(iface);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->driver->connectIsEncrypted) {
        int ret;
        ret = conn->driver->connectIsEncrypted(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
int virConnectIsSecure(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->driver->connectIsSecure) {
        int ret;
        ret = conn->driver->connectIsSecure(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectCompareCPU:
 * @conn: virConnect connection
 * @xmlDesc: XML describing the CPU to compare with host CPU
 * @flags: extra flags; not used yet, so callers should always pass 0
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
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=%x", conn, xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return VIR_CPU_COMPARE_ERROR;
    }
    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->driver->connectCompareCPU) {
        int ret;

        ret = conn->driver->connectCompareCPU(conn, xmlDesc, flags);
        if (ret == VIR_CPU_COMPARE_ERROR)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgReturn(arch, -1);

    if (conn->driver->connectGetCPUModelNames) {
        int ret;

        ret = conn->driver->connectGetCPUModelNames(conn, arch, models, flags);
        if (ret < 0)
            goto error;

        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * Returns XML description of the computed CPU or NULL on error.
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    virCheckNonNullArgGoto(xmlCPUs, error);

    if (conn->driver->connectBaselineCPU) {
        char *cpu;

        cpu = conn->driver->connectBaselineCPU(conn, xmlCPUs, ncpus, flags);
        if (!cpu)
            goto error;
        return cpu;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
 * This function returns a limited amount of information in comparison
 * to virDomainGetJobStats().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetJobInfo(virDomainPtr domain, virDomainJobInfoPtr info)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "info=%p", info);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(info, error);

    memset(info, 0, sizeof(virDomainJobInfo));

    conn = domain->conn;

    if (conn->driver->domainGetJobInfo) {
        int ret;
        ret = conn->driver->domainGetJobInfo(domain, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainGetJobStats:
 * @domain: a domain object
 * @type: where to store the job type (one of virDomainJobType)
 * @params: where to store job statistics
 * @nparams: number of items in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract information about progress of a background job on a domain.
 * Will return an error if the domain is not active. The function returns
 * a superset of progress information provided by virDomainGetJobInfo.
 * Possible fields returned in @params are defined by VIR_DOMAIN_JOB_*
 * macros and new fields will likely be introduced in the future so callers
 * may receive fields that they do not understand in case they talk to a
 * newer server.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetJobStats(virDomainPtr domain,
                     int *type,
                     virTypedParameterPtr *params,
                     int *nparams,
                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "type=%p, params=%p, nparams=%p, flags=%x",
                     type, params, nparams, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNullArgGoto(type, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNullArgGoto(nparams, error);

    conn = domain->conn;

    if (conn->driver->domainGetJobStats) {
        int ret;
        ret = conn->driver->domainGetJobStats(domain, type, params,
                                              nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}


/**
 * virDomainAbortJob:
 * @domain: a domain object
 *
 * Requests that the current background job be aborted at the
 * soonest opportunity.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainAbortJob(virDomainPtr domain)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainAbortJob) {
        int ret;
        ret = conn->driver->domainAbortJob(domain);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainMigrateSetMaxDowntime:
 * @domain: a domain object
 * @downtime: maximum tolerable downtime for live migration, in milliseconds
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DOMAIN_DEBUG(domain, "downtime=%llu, flags=%x", downtime, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateSetMaxDowntime) {
        if (conn->driver->domainMigrateSetMaxDowntime(domain, downtime, flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainMigrateGetCompressionCache:
 * @domain: a domain object
 * @cacheSize: return value of current size of the cache (in bytes)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Gets current size of the cache (in bytes) used for compressing repeatedly
 * transferred memory pages during live migration.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateGetCompressionCache(virDomainPtr domain,
                                    unsigned long long *cacheSize,
                                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cacheSize=%p, flags=%x", cacheSize, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(cacheSize, error);

    if (conn->driver->domainMigrateGetCompressionCache) {
        if (conn->driver->domainMigrateGetCompressionCache(domain, cacheSize,
                                                           flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainMigrateSetCompressionCache:
 * @domain: a domain object
 * @cacheSize: size of the cache (in bytes) used for compression
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Sets size of the cache (in bytes) used for compressing repeatedly
 * transferred memory pages during live migration. It's supposed to be called
 * while the domain is being live-migrated as a reaction to migration progress
 * and increasing number of compression cache misses obtained from
 * virDomainGetJobStats.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetCompressionCache(virDomainPtr domain,
                                    unsigned long long cacheSize,
                                    unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cacheSize=%llu, flags=%x", cacheSize, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateSetCompressionCache) {
        if (conn->driver->domainMigrateSetCompressionCache(domain, cacheSize,
                                                           flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainMigrateSetMaxSpeed:
 * @domain: a domain object
 * @bandwidth: migration bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * The maximum bandwidth (in MiB/s) that will be used to do migration
 * can be specified with the bandwidth parameter. Not all hypervisors
 * will support a bandwidth cap
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateSetMaxSpeed(virDomainPtr domain,
                            unsigned long bandwidth,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "bandwidth=%lu, flags=%x", bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateSetMaxSpeed) {
        if (conn->driver->domainMigrateSetMaxSpeed(domain, bandwidth, flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainMigrateGetMaxSpeed:
 * @domain: a domain object
 * @bandwidth: return value of current migration bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the current maximum bandwidth (in MiB/s) that will be used if the
 * domain is migrated.  Not all hypervisors will support a bandwidth limit.
 *
 * Returns 0 in case of success, -1 otherwise.
 */
int
virDomainMigrateGetMaxSpeed(virDomainPtr domain,
                            unsigned long *bandwidth,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "bandwidth = %p, flags=%x", bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(bandwidth, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainMigrateGetMaxSpeed) {
        if (conn->driver->domainMigrateGetMaxSpeed(domain, bandwidth, flags) < 0)
            goto error;
        return 0;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_DOMAIN_EVENT_CALLBACK() macro to cast the supplied function pointer
 * to match the signature of this method.
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback returns,
 * it shall take a reference to it, by calling virDomainRef.
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
    VIR_DOMAIN_DEBUG(dom, "conn=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
                     conn, eventID, cb, opaque, freecb);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (dom != NULL &&
        !(VIR_IS_CONNECTED_DOMAIN(dom) && dom->conn == conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(conn);
        return -1;
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);
    if (eventID >= VIR_DOMAIN_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %s must be less than %d"),
                            __FUNCTION__, VIR_DOMAIN_EVENT_ID_LAST);
        goto error;
    }

    if ((conn->driver) && (conn->driver->connectDomainEventRegisterAny)) {
        int ret;
        ret = conn->driver->connectDomainEventRegisterAny(conn, dom, eventID, cb, opaque, freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virCheckNonNegativeArgGoto(callbackID, error);

    if ((conn->driver) && (conn->driver->connectDomainEventDeregisterAny)) {
        int ret;
        ret = conn->driver->connectDomainEventDeregisterAny(conn, callbackID);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainManagedSave:
 * @dom: pointer to the domain
 * @flags: bitwise-OR of virDomainSaveRestoreFlags
 *
 * This method will suspend a domain and save its memory contents to
 * a file on disk. After the call, if successful, the domain is not
 * listed as running anymore.
 * The difference from virDomainSave() is that libvirt is keeping track of
 * the saved state itself, and will reuse it once the domain is being
 * restarted (automatically or via an explicit libvirt call).
 * As a result any running domain is sure to not have a managed saved image.
 * This also implies that managed save only works on persistent domains,
 * since the domain must still exist in order to use virDomainCreate() to
 * restart it.
 *
 * If @flags includes VIR_DOMAIN_SAVE_BYPASS_CACHE, then libvirt will
 * attempt to bypass the file system cache while creating the file, or
 * fail if it cannot do so for the given system; this can allow less
 * pressure on file system cache, but also risks slowing saves to NFS.
 *
 * Normally, the managed saved state will remember whether the domain
 * was running or paused, and start will resume to the same state.
 * Specifying VIR_DOMAIN_SAVE_RUNNING or VIR_DOMAIN_SAVE_PAUSED in
 * @flags will override the default saved into the file.  These two
 * flags are mutually exclusive.
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int virDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((flags & VIR_DOMAIN_SAVE_RUNNING) && (flags & VIR_DOMAIN_SAVE_PAUSED)) {
        virReportInvalidArg(flags,
                            _("running and paused flags in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainManagedSave) {
        int ret;

        ret = conn->driver->domainManagedSave(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainHasManagedSaveImage:
 * @dom: pointer to the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainManagedSaveRemove:
 * @dom: pointer to the domain
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Remove any managed save image for this domain.
 *
 * Returns 0 in case of success, and -1 in case of error
 */
int virDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainManagedSaveRemove) {
        int ret;

        ret = conn->driver->domainManagedSaveRemove(dom, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotGetName:
 * @snapshot: a snapshot object
 *
 * Get the public name for that snapshot
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * as its lifetime will be the same as the snapshot object.
 */
const char *
virDomainSnapshotGetName(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return snapshot->name;
}

/**
 * virDomainSnapshotGetDomain:
 * @snapshot: a snapshot object
 *
 * Provides the domain pointer associated with a snapshot.  The
 * reference counter on the domain is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do not use this
 * function.  Instead, store the domain and the snapshot object together.
 *
 * Returns the domain or NULL.
 */
virDomainPtr
virDomainSnapshotGetDomain(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return snapshot->domain;
}

/**
 * virDomainSnapshotGetConnect:
 * @snapshot: a snapshot object
 *
 * Provides the connection pointer associated with a snapshot.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * WARNING: When writing libvirt bindings in other languages, do not use this
 * function.  Instead, store the connection and the snapshot object together.
 *
 * Returns the connection or NULL.
 */
virConnectPtr
virDomainSnapshotGetConnect(virDomainSnapshotPtr snapshot)
{
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }
    return snapshot->domain->conn;
}

/**
 * virDomainSnapshotCreateXML:
 * @domain: a domain object
 * @xmlDesc: string containing an XML description of the domain
 * @flags: bitwise-OR of virDomainSnapshotCreateFlags
 *
 * Creates a new snapshot of a domain based on the snapshot xml
 * contained in xmlDesc.
 *
 * If @flags is 0, the domain can be active, in which case the
 * snapshot will be a system checkpoint (both disk state and runtime
 * VM state such as RAM contents), where reverting to the snapshot is
 * the same as resuming from hibernation (TCP connections may have
 * timed out, but everything else picks up where it left off); or
 * the domain can be inactive, in which case the snapshot includes
 * just the disk state prior to booting.  The newly created snapshot
 * becomes current (see virDomainSnapshotCurrent()), and is a child
 * of any previous current snapshot.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE, then this
 * is a request to reinstate snapshot metadata that was previously
 * discarded, rather than creating a new snapshot.  This can be used
 * to recreate a snapshot hierarchy on a destination, then remove it
 * on the source, in order to allow migration (since migration
 * normally fails if snapshot metadata still remains on the source
 * machine).  When redefining snapshot metadata, the current snapshot
 * will not be altered unless the VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT
 * flag is also present.  It is an error to request the
 * VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT flag without
 * VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.  On some hypervisors,
 * redefining an existing snapshot can be used to alter host-specific
 * portions of the domain XML to be used during revert (such as
 * backing filenames associated with disk devices), but must not alter
 * guest-visible layout.  When redefining a snapshot name that does
 * not exist, the hypervisor may validate that reverting to the
 * snapshot appears to be possible (for example, disk images have
 * snapshot contents by the requested name).  Not all hypervisors
 * support these flags.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA, then the
 * domain's disk images are modified according to @xmlDesc, but then
 * the just-created snapshot has its metadata deleted.  This flag is
 * incompatible with VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_HALT, then the domain
 * will be inactive after the snapshot completes, regardless of whether
 * it was active before; otherwise, a running domain will still be
 * running after the snapshot.  This flag is invalid on transient domains,
 * and is incompatible with VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_LIVE, then the domain
 * is not paused while creating the snapshot. This increases the size
 * of the memory dump file, but reduces downtime of the guest while
 * taking the snapshot. Some hypervisors only support this flag during
 * external checkpoints.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY, then the
 * snapshot will be limited to the disks described in @xmlDesc, and no
 * VM state will be saved.  For an active guest, the disk image may be
 * inconsistent (as if power had been pulled), and specifying this
 * with the VIR_DOMAIN_SNAPSHOT_CREATE_HALT flag risks data loss.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE, then the
 * libvirt will attempt to use guest agent to freeze and thaw all
 * file systems in use within domain OS. However, if the guest agent
 * is not present, an error is thrown. Moreover, this flag requires
 * VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY to be passed as well.
 *
 * By default, if the snapshot involves external files, and any of the
 * destination files already exist as a non-empty regular file, the
 * snapshot is rejected to avoid losing contents of those files.
 * However, if @flags includes VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT,
 * then the destination files must already exist and contain content
 * identical to the source files (this allows a management app to
 * pre-create files with relative backing file names, rather than the
 * default of creating with absolute backing file names).
 *
 * Be aware that although libvirt prefers to report errors up front with
 * no other effect, some hypervisors have certain types of failures where
 * the overall command can easily fail even though the guest configuration
 * was partially altered (for example, if a disk snapshot request for two
 * disks fails on the second disk, but the first disk alteration cannot be
 * rolled back).  If this API call fails, it is therefore normally
 * necessary to follow up with virDomainGetXMLDesc() and check each disk
 * to determine if any partial changes occurred.  However, if @flags
 * contains VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC, then libvirt guarantees
 * that this command will not alter any disks unless the entire set of
 * changes can be done atomically, making failure recovery simpler (note
 * that it is still possible to fail after disks have changed, but only
 * in the much rarer cases of running out of memory or disk space).
 *
 * Some hypervisors may prevent this operation if there is a current
 * block copy operation; in that case, use virDomainBlockJobAbort()
 * to stop the block copy first.
 *
 * Returns an (opaque) virDomainSnapshotPtr on success, NULL on failure.
 */
virDomainSnapshotPtr
virDomainSnapshotCreateXML(virDomainPtr domain,
                           const char *xmlDesc,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "xmlDesc=%s, flags=%x", xmlDesc, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(xmlDesc, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT) &&
        !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE)) {
        virReportInvalidArg(flags,
                            _("use of 'current' flag in %s requires 'redefine' flag"),
                            __FUNCTION__);
        goto error;
    }
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) &&
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA)) {
        virReportInvalidArg(flags,
                            _("'redefine' and 'no metadata' flags in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE) &&
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        virReportInvalidArg(flags,
                            _("'redefine' and 'halt' flags in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSnapshotCreateXML) {
        virDomainSnapshotPtr ret;
        ret = conn->driver->domainSnapshotCreateXML(domain, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotGetXMLDesc:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of subset of virDomainXMLFlags
 *
 * Provide an XML description of the domain snapshot.
 *
 * No security-sensitive data will be included unless @flags contains
 * VIR_DOMAIN_XML_SECURE; this flag is rejected on read-only
 * connections.  For this API, @flags should not contain either
 * VIR_DOMAIN_XML_INACTIVE or VIR_DOMAIN_XML_UPDATE_CPU.
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = snapshot->domain->conn;

    if ((conn->flags & VIR_CONNECT_RO) && (flags & VIR_DOMAIN_XML_SECURE)) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, "%s",
                        _("virDomainSnapshotGetXMLDesc with secure flag"));
        goto error;
    }

    if (conn->driver->domainSnapshotGetXMLDesc) {
        char *ret;
        ret = conn->driver->domainSnapshotGetXMLDesc(snapshot, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotNum:
 * @domain: a domain object
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Provides the number of domain snapshots for this domain.
 *
 * By default, this command covers all snapshots; it is also possible to
 * limit things to just snapshots with no parents, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 */
int
virDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotListNames:
 * @domain: a domain object
 * @names: array to collect the list of names of snapshots
 * @nameslen: size of @names
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots for the given domain, and store
 * their names in @names.  The value to use for @nameslen can be determined
 * by virDomainSnapshotNum() with the same @flags.
 *
 * By default, this command covers all snapshots; it is also possible to
 * limit things to just snapshots with no parents, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Note that this command is inherently racy: another connection can
 * define a new snapshot between a call to virDomainSnapshotNum() and
 * this call.  You are only guaranteed that all currently defined
 * snapshots were listed if the return is less than @nameslen.  Likewise,
 * you should be prepared for virDomainSnapshotLookupByName() to fail when
 * converting a name from this call into a snapshot object, if another
 * connection deletes the snapshot in the meantime.  For more control over
 * the results, see virDomainListAllSnapshots().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 * The caller is responsible to call free() for each member of the array.
 */
int
virDomainSnapshotListNames(virDomainPtr domain, char **names, int nameslen,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "names=%p, nameslen=%d, flags=%x",
                     names, nameslen, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(nameslen, error);

    if (conn->driver->domainSnapshotListNames) {
        int ret = conn->driver->domainSnapshotListNames(domain, names,
                                                        nameslen, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainListAllSnapshots:
 * @domain: a domain object
 * @snaps: pointer to variable to store the array containing snapshot objects,
 *         or NULL if the list is not required (just returns number of
 *         snapshots)
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots for the given domain, and allocate
 * an array to store those objects.  This API solves the race inherent in
 * virDomainSnapshotListNames().
 *
 * By default, this command covers all snapshots; it is also possible to
 * limit things to just snapshots with no parents, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_ROOTS.  Additional filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 and sets @snaps to
 * NULL in case of error.  On success, the array stored into @snaps is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virDomainSnapshotFree() on each array element, then calling
 * free() on @snaps.
 */
int
virDomainListAllSnapshots(virDomainPtr domain, virDomainSnapshotPtr **snaps,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "snaps=%p, flags=%x", snaps, flags);

    virResetLastError();

    if (snaps)
        *snaps = NULL;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if (conn->driver->domainListAllSnapshots) {
        int ret = conn->driver->domainListAllSnapshots(domain, snaps, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotNumChildren:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Provides the number of child snapshots for this domain snapshot.
 *
 * By default, this command covers only direct children; it is also possible
 * to expand things to cover all descendants, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS.  Also, some filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 */
int
virDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;
    if (conn->driver->domainSnapshotNumChildren) {
        int ret = conn->driver->domainSnapshotNumChildren(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotListChildrenNames:
 * @snapshot: a domain snapshot object
 * @names: array to collect the list of names of snapshots
 * @nameslen: size of @names
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots that are children of the given
 * snapshot, and store their names in @names.  The value to use for
 * @nameslen can be determined by virDomainSnapshotNumChildren() with
 * the same @flags.
 *
 * By default, this command covers only direct children; it is also possible
 * to expand things to cover all descendants, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS.  Also, some filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 * Note that this command is inherently racy: another connection can
 * define a new snapshot between a call to virDomainSnapshotNumChildren()
 * and this call.  You are only guaranteed that all currently defined
 * snapshots were listed if the return is less than @nameslen.  Likewise,
 * you should be prepared for virDomainSnapshotLookupByName() to fail when
 * converting a name from this call into a snapshot object, if another
 * connection deletes the snapshot in the meantime.  For more control over
 * the results, see virDomainSnapshotListAllChildren().
 *
 * Returns the number of domain snapshots found or -1 in case of error.
 * The caller is responsible to call free() for each member of the array.
 */
int
virDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                   char **names, int nameslen,
                                   unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, names=%p, nameslen=%d, flags=%x",
              snapshot, names, nameslen, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    virCheckNonNullArgGoto(names, error);
    virCheckNonNegativeArgGoto(nameslen, error);

    if (conn->driver->domainSnapshotListChildrenNames) {
        int ret = conn->driver->domainSnapshotListChildrenNames(snapshot,
                                                                names,
                                                                nameslen,
                                                                flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotListAllChildren:
 * @snapshot: a domain snapshot object
 * @snaps: pointer to variable to store the array containing snapshot objects,
 *         or NULL if the list is not required (just returns number of
 *         snapshots)
 * @flags: bitwise-OR of supported virDomainSnapshotListFlags
 *
 * Collect the list of domain snapshots that are children of the given
 * snapshot, and allocate an array to store those objects.  This API solves
 * the race inherent in virDomainSnapshotListChildrenNames().
 *
 * By default, this command covers only direct children; it is also possible
 * to expand things to cover all descendants, when @flags includes
 * VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS.  Also, some filters are provided in
 * groups, where each group contains bits that describe mutually exclusive
 * attributes of a snapshot, and where all bits within a group describe
 * all possible snapshots.  Some hypervisors might reject explicit bits
 * from a group where the hypervisor cannot make a distinction.  For a
 * group supported by a given hypervisor, the behavior when no bits of a
 * group are set is identical to the behavior when all bits in that group
 * are set.  When setting bits from more than one group, it is possible to
 * select an impossible combination, in that case a hypervisor may return
 * either 0 or an error.
 *
 * The first group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_LEAVES and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES, to filter based on snapshots that
 * have no further children (a leaf snapshot).
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_METADATA and
 * VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA, for filtering snapshots based on
 * whether they have metadata that would prevent the removal of the last
 * reference to a domain.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE,
 * VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE, and VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY,
 * for filtering snapshots based on what domain state is tracked by the
 * snapshot.
 *
 * The next group of @flags is VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL and
 * VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL, for filtering snapshots based on
 * whether the snapshot is stored inside the disk images or as
 * additional files.
 *
 * Returns the number of domain snapshots found or -1 and sets @snaps to
 * NULL in case of error.  On success, the array stored into @snaps is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virDomainSnapshotFree() on each array element, then calling
 * free() on @snaps.
 */
int
virDomainSnapshotListAllChildren(virDomainSnapshotPtr snapshot,
                                 virDomainSnapshotPtr **snaps,
                                 unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, snaps=%p, flags=%x", snapshot, snaps, flags);

    virResetLastError();

    if (snaps)
        *snaps = NULL;

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotListAllChildren) {
        int ret = conn->driver->domainSnapshotListAllChildren(snapshot, snaps,
                                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotLookupByName:
 * @domain: a domain object
 * @name: name for the domain snapshot
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DOMAIN_DEBUG(domain, "name=%s, flags=%x", name, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    virCheckNonNullArgGoto(name, error);

    if (conn->driver->domainSnapshotLookupByName) {
        virDomainSnapshotPtr dom;
        dom = conn->driver->domainSnapshotLookupByName(domain, name, flags);
        if (!dom)
            goto error;
        return dom;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainHasCurrentSnapshot:
 * @domain: pointer to the domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the domain has a current snapshot.
 *
 * Returns 1 if such snapshot exists, 0 if it doesn't, -1 on error.
 */
int
virDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotCurrent:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
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

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    if (conn->driver->domainSnapshotCurrent) {
        virDomainSnapshotPtr snap;
        snap = conn->driver->domainSnapshotCurrent(domain, flags);
        if (!snap)
            goto error;
        return snap;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotGetParent:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the parent snapshot for @snapshot, if any.
 *
 * Returns a domain snapshot object or NULL in case of failure.  If the
 * given snapshot is a root (no parent), then the VIR_ERR_NO_DOMAIN_SNAPSHOT
 * error is raised.
 */
virDomainSnapshotPtr
virDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotGetParent) {
        virDomainSnapshotPtr snap;
        snap = conn->driver->domainSnapshotGetParent(snapshot, flags);
        if (!snap)
            goto error;
        return snap;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainSnapshotIsCurrent:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the given snapshot is the domain's current snapshot.  See
 * also virDomainHasCurrentSnapshot().
 *
 * Returns 1 if current, 0 if not current, or -1 on error.
 */
int virDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                               unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotIsCurrent) {
        int ret;
        ret = conn->driver->domainSnapshotIsCurrent(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotHasMetadata:
 * @snapshot: a snapshot object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Determine if the given snapshot is associated with libvirt metadata
 * that would prevent the deletion of the domain.
 *
 * Returns 1 if the snapshot has metadata, 0 if the snapshot exists without
 * help from libvirt, or -1 on error.
 */
int virDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                                 unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;

    if (conn->driver->domainSnapshotHasMetadata) {
        int ret;
        ret = conn->driver->domainSnapshotHasMetadata(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainRevertToSnapshot:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of virDomainSnapshotRevertFlags
 *
 * Revert the domain to a given snapshot.
 *
 * Normally, the domain will revert to the same state the domain was
 * in while the snapshot was taken (whether inactive, running, or
 * paused), except that disk snapshots default to reverting to
 * inactive state.  Including VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING in
 * @flags overrides the snapshot state to guarantee a running domain
 * after the revert; or including VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED in
 * @flags guarantees a paused domain after the revert.  These two
 * flags are mutually exclusive.  While a persistent domain does not
 * need either flag, it is not possible to revert a transient domain
 * into an inactive state, so transient domains require the use of one
 * of these two flags.
 *
 * Reverting to any snapshot discards all configuration changes made since
 * the last snapshot.  Additionally, reverting to a snapshot from a running
 * domain is a form of data loss, since it discards whatever is in the
 * guest's RAM at the time.  Since the very nature of keeping snapshots
 * implies the intent to roll back state, no additional confirmation is
 * normally required for these lossy effects.
 *
 * However, there are two particular situations where reverting will
 * be refused by default, and where @flags must include
 * VIR_DOMAIN_SNAPSHOT_REVERT_FORCE to acknowledge the risks.  1) Any
 * attempt to revert to a snapshot that lacks the metadata to perform
 * ABI compatibility checks (generally the case for snapshots that
 * lack a full <domain> when listed by virDomainSnapshotGetXMLDesc(),
 * such as those created prior to libvirt 0.9.5).  2) Any attempt to
 * revert a running domain to an active state that requires starting a
 * new hypervisor instance rather than reusing the existing hypervisor
 * (since this would terminate all connections to the domain, such as
 * such as VNC or Spice graphics) - this condition arises from active
 * snapshots that are provably ABI incomaptible, as well as from
 * inactive snapshots with a @flags request to start the domain after
 * the revert.
 *
 * Returns 0 if the creation is successful, -1 on error.
 */
int
virDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                          unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((flags & VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING) &&
        (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
        virReportInvalidArg(flags,
                            _("running and paused flags in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainRevertToSnapshot) {
        int ret = conn->driver->domainRevertToSnapshot(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotDelete:
 * @snapshot: a domain snapshot object
 * @flags: bitwise-OR of supported virDomainSnapshotDeleteFlags
 *
 * Delete the snapshot.
 *
 * If @flags is 0, then just this snapshot is deleted, and changes
 * from this snapshot are automatically merged into children
 * snapshots.  If @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN,
 * then this snapshot and any descendant snapshots are deleted.  If
 * @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, then any
 * descendant snapshots are deleted, but this snapshot remains.  These
 * two flags are mutually exclusive.
 *
 * If @flags includes VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY, then
 * any snapshot metadata tracked by libvirt is removed while keeping
 * the snapshot contents intact; if a hypervisor does not require any
 * libvirt metadata to track snapshots, then this flag is silently
 * ignored.
 *
 * Returns 0 if the selected snapshot(s) were successfully deleted,
 * -1 on error.
 */
int
virDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                        unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("snapshot=%p, flags=%x", snapshot, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = snapshot->domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if ((flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN) &&
        (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        virReportInvalidArg(flags,
                            _("children and children_only flags in %s are "
                              "mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainSnapshotDelete) {
        int ret = conn->driver->domainSnapshotDelete(snapshot, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainSnapshotRef:
 * @snapshot: the snapshot to hold a reference on
 *
 * Increment the reference count on the snapshot. For each
 * additional call to this method, there shall be a corresponding
 * call to virDomainSnapshotFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection and domain remain open until all threads have finished
 * using the snapshot. ie, each new thread using a snapshot would
 * increment the reference count.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSnapshotRef(virDomainSnapshotPtr snapshot)
{
    if ((!VIR_IS_DOMAIN_SNAPSHOT(snapshot))) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    VIR_DEBUG("snapshot=%p, refs=%d", snapshot, snapshot->object.refs);
    virObjectRef(snapshot);
    return 0;
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
    VIR_DEBUG("snapshot=%p", snapshot);

    virResetLastError();

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibDomainSnapshotError(VIR_ERR_INVALID_DOMAIN_SNAPSHOT,
                                  __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    virObjectUnref(snapshot);
    return 0;
}

/**
 * virDomainOpenConsole:
 * @dom: a domain object
 * @dev_name: the console, serial or parallel port device alias, or NULL
 * @st: a stream to associate with the console
 * @flags: bitwise-OR of virDomainConsoleFlags
 *
 * This opens the backend associated with a console, serial or
 * parallel port device on a guest, if the backend is supported.
 * If the @dev_name is omitted, then the first console or serial
 * device is opened. The console is associated with the passed
 * in @st stream, which should have been opened in non-blocking
 * mode for bi-directional I/O.
 *
 * By default, when @flags is 0, the open will fail if libvirt
 * detects that the console is already in use by another client;
 * passing VIR_DOMAIN_CONSOLE_FORCE will cause libvirt to forcefully
 * remove the other client prior to opening this console.
 *
 * If flag VIR_DOMAIN_CONSOLE_SAFE the console is opened only in the
 * case where the hypervisor driver supports safe (mutually exclusive)
 * console handling.
 *
 * Older servers did not support either flag, and also did not forbid
 * simultaneous clients on a console, with potentially confusing results.
 * When passing @flags of 0 in order to support a wider range of server
 * versions, it is up to the client to ensure mutual exclusion.
 *
 * Returns 0 if the console was opened, -1 on error
 */
int virDomainOpenConsole(virDomainPtr dom,
                         const char *dev_name,
                         virStreamPtr st,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "dev_name=%s, st=%p, flags=%x",
                     NULLSTR(dev_name), st, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainOpenConsole) {
        int ret;
        ret = conn->driver->domainOpenConsole(dom, dev_name, st, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainOpenChannel:
 * @dom: a domain object
 * @name: the channel name, or NULL
 * @st: a stream to associate with the channel
 * @flags: bitwise-OR of virDomainChannelFlags
 *
 * This opens the host interface associated with a channel device on a
 * guest, if the host interface is supported.  If @name is given, it
 * can match either the device alias (e.g. "channel0"), or the virtio
 * target name (e.g. "org.qemu.guest_agent.0").  If @name is omitted,
 * then the first channel is opened. The channel is associated with
 * the passed in @st stream, which should have been opened in
 * non-blocking mode for bi-directional I/O.
 *
 * By default, when @flags is 0, the open will fail if libvirt detects
 * that the channel is already in use by another client; passing
 * VIR_DOMAIN_CHANNEL_FORCE will cause libvirt to forcefully remove the
 * other client prior to opening this channel.
 *
 * Returns 0 if the channel was opened, -1 on error
 */
int virDomainOpenChannel(virDomainPtr dom,
                         const char *name,
                         virStreamPtr st,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "name=%s, st=%p, flags=%x",
                     NULLSTR(name), st, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = dom->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainOpenChannel) {
        int ret;
        ret = conn->driver->domainOpenChannel(dom, name, st, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainBlockJobAbort:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @flags: bitwise-OR of virDomainBlockJobAbortFlags
 *
 * Cancel the active block job on the given disk.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * If the current block job for @disk is VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, then
 * by default, this function performs a synchronous operation and the caller
 * may assume that the operation has completed when 0 is returned.  However,
 * BlockJob operations may take a long time to cancel, and during this time
 * further domain interactions may be unresponsive.  To avoid this problem,
 * pass VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC in the @flags argument to enable
 * asynchronous behavior, returning as soon as possible.  When the job has
 * been canceled, a BlockJob event will be emitted, with status
 * VIR_DOMAIN_BLOCK_JOB_CANCELED (even if the ABORT_ASYNC flag was not
 * used); it is also possible to poll virDomainBlockJobInfo() to see if
 * the job cancellation is still pending.  This type of job can be restarted
 * to pick up from where it left off.
 *
 * If the current block job for @disk is VIR_DOMAIN_BLOCK_JOB_TYPE_COPY, then
 * the default is to abort the mirroring and revert to the source disk;
 * adding @flags of VIR_DOMAIN_BLOCK_JOB_ABORT_PIVOT causes this call to
 * fail with VIR_ERR_BLOCK_COPY_ACTIVE if the copy is not fully populated,
 * otherwise it will swap the disk over to the copy to end the mirroring.  An
 * event will be issued when the job is ended, and it is possible to use
 * VIR_DOMAIN_BLOCK_JOB_ABORT_ASYNC to control whether this command waits
 * for the completion of the job.  Restarting this job requires starting
 * over from the beginning of the first phase.
 *
 * Returns -1 in case of failure, 0 when successful.
 */
int virDomainBlockJobAbort(virDomainPtr dom, const char *disk,
                           unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, flags=%x", disk, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockJobAbort) {
        int ret;
        ret = conn->driver->domainBlockJobAbort(dom, disk, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainGetBlockJobInfo:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @info: pointer to a virDomainBlockJobInfo structure
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Request block job information for the given disk.  If an operation is active
 * @info will be updated with the current progress.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Returns -1 in case of failure, 0 when nothing found, 1 when info was found.
 */
int virDomainGetBlockJobInfo(virDomainPtr dom, const char *disk,
                             virDomainBlockJobInfoPtr info, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, info=%p, flags=%x", disk, info, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    virCheckNonNullArgGoto(disk, error);
    virCheckNonNullArgGoto(info, error);

    if (conn->driver->domainGetBlockJobInfo) {
        int ret;
        ret = conn->driver->domainGetBlockJobInfo(dom, disk, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainBlockJobSetSpeed:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @bandwidth: specify bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Set the maximimum allowable bandwidth that a block job may consume.  If
 * bandwidth is 0, the limit will revert to the hypervisor default.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * Returns -1 in case of failure, 0 when successful.
 */
int virDomainBlockJobSetSpeed(virDomainPtr dom, const char *disk,
                              unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, bandwidth=%lu, flags=%x",
                     disk, bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockJobSetSpeed) {
        int ret;
        ret = conn->driver->domainBlockJobSetSpeed(dom, disk, bandwidth, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainBlockPull:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @bandwidth: (optional) specify copy bandwidth limit in MiB/s
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Populate a disk image with data from its backing image.  Once all data from
 * its backing image has been pulled, the disk no longer depends on a backing
 * image.  This function pulls data for the entire device in the background.
 * Progress of the operation can be checked with virDomainGetBlockJobInfo() and
 * the operation can be aborted with virDomainBlockJobAbort().  When finished,
 * an asynchronous event is raised to indicate the final status.  To move
 * data in the opposite direction, see virDomainBlockCommit().
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or (since 0.9.5) the device target shorthand
 * (the <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do the copy can be
 * specified with the bandwidth parameter.  If set to 0, libvirt will choose a
 * suitable default.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still be
 * possible for a later call to virDomainBlockJobSetSpeed() to succeed.
 * The actual speed can be determined with virDomainGetBlockJobInfo().
 *
 * This is shorthand for virDomainBlockRebase() with a NULL base.
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int virDomainBlockPull(virDomainPtr dom, const char *disk,
                       unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, bandwidth=%lu, flags=%x",
                     disk, bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockPull) {
        int ret;
        ret = conn->driver->domainBlockPull(dom, disk, bandwidth, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockRebase:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @base: path to backing file to keep, or NULL for no backing file
 * @bandwidth: (optional) specify copy bandwidth limit in MiB/s
 * @flags: bitwise-OR of virDomainBlockRebaseFlags
 *
 * Populate a disk image with data from its backing image chain, and
 * setting the backing image to @base, or alternatively copy an entire
 * backing chain to a new file @base.
 *
 * When @flags is 0, this starts a pull, where @base must be the absolute
 * path of one of the backing images further up the chain, or NULL to
 * convert the disk image so that it has no backing image.  Once all
 * data from its backing image chain has been pulled, the disk no
 * longer depends on those intermediate backing images.  This function
 * pulls data for the entire device in the background.  Progress of
 * the operation can be checked with virDomainGetBlockJobInfo() with a
 * job type of VIR_DOMAIN_BLOCK_JOB_TYPE_PULL, and the operation can be
 * aborted with virDomainBlockJobAbort().  When finished, an asynchronous
 * event is raised to indicate the final status, and the job no longer
 * exists.  If the job is aborted, a new one can be started later to
 * resume from the same point.
 *
 * When @flags includes VIR_DOMAIN_BLOCK_REBASE_COPY, this starts a copy,
 * where @base must be the name of a new file to copy the chain to.  By
 * default, the copy will pull the entire source chain into the destination
 * file, but if @flags also contains VIR_DOMAIN_BLOCK_REBASE_SHALLOW, then
 * only the top of the source chain will be copied (the source and
 * destination have a common backing file).  By default, @base will be
 * created with the same file format as the source, but this can be altered
 * by adding VIR_DOMAIN_BLOCK_REBASE_COPY_RAW to force the copy to be raw
 * (does not make sense with the shallow flag unless the source is also raw),
 * or by using VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT to reuse an existing file
 * with initial contents identical to the backing file of the source (this
 * allows a management app to pre-create files with relative backing file
 * names, rather than the default of absolute backing file names; as a
 * security precaution, you should generally only use reuse_ext with the
 * shallow flag and a non-raw destination file).
 *
 * A copy job has two parts; in the first phase, the @bandwidth parameter
 * affects how fast the source is pulled into the destination, and the job
 * can only be canceled by reverting to the source file; progress in this
 * phase can be tracked via the virDomainBlockJobInfo() command, with a
 * job type of VIR_DOMAIN_BLOCK_JOB_TYPE_COPY.  The job transitions to the
 * second phase when the job info states cur == end, and remains alive to
 * mirror all further changes to both source and destination.  The user
 * must call virDomainBlockJobAbort() to end the mirroring while choosing
 * whether to revert to source or pivot to the destination.  An event is
 * issued when the job ends, and depending on the hypervisor, an event may
 * also be issued when the job transitions from pulling to mirroring.  If
 * the job is aborted, a new job will have to start over from the beginning
 * of the first phase.
 *
 * Some hypervisors will restrict certain actions, such as virDomainSave()
 * or virDomainDetachDevice(), while a copy job is active; they may
 * also restrict a copy job to transient domains.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the
 * <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do the copy can be
 * specified with the bandwidth parameter.  If set to 0, libvirt will choose a
 * suitable default.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still be
 * possible for a later call to virDomainBlockJobSetSpeed() to succeed.
 * The actual speed can be determined with virDomainGetBlockJobInfo().
 *
 * When @base is NULL and @flags is 0, this is identical to
 * virDomainBlockPull().
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int virDomainBlockRebase(virDomainPtr dom, const char *disk,
                         const char *base, unsigned long bandwidth,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (flags & VIR_DOMAIN_BLOCK_REBASE_COPY) {
        virCheckNonNullArgGoto(base, error);
    } else if (flags & (VIR_DOMAIN_BLOCK_REBASE_SHALLOW |
                        VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT |
                        VIR_DOMAIN_BLOCK_REBASE_COPY_RAW)) {
        virReportInvalidArg(flags,
                            _("use of flags in %s requires a copy job"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainBlockRebase) {
        int ret;
        ret = conn->driver->domainBlockRebase(dom, disk, base, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainBlockCommit:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @base: path to backing file to merge into, or NULL for default
 * @top: path to file within backing chain that contains data to be merged,
 *       or NULL to merge all possible data
 * @bandwidth: (optional) specify commit bandwidth limit in MiB/s
 * @flags: bitwise-OR of virDomainBlockCommitFlags
 *
 * Commit changes that were made to temporary top-level files within a disk
 * image backing file chain into a lower-level base file.  In other words,
 * take all the difference between @base and @top, and update @base to contain
 * that difference; after the commit, any portion of the chain that previously
 * depended on @top will now depend on @base, and all files after @base up
 * to and including @top will now be invalidated.  A typical use of this
 * command is to reduce the length of a backing file chain after taking an
 * external disk snapshot.  To move data in the opposite direction, see
 * virDomainBlockPull().
 *
 * This command starts a long-running commit block job, whose status may
 * be tracked by virDomainBlockJobInfo() with a job type of
 * VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT, and the operation can be aborted with
 * virDomainBlockJobAbort().  When finished, an asynchronous event is
 * raised to indicate the final status, and the job no longer exists.  If
 * the job is aborted, it is up to the hypervisor whether starting a new
 * job will resume from the same point, or start over.
 *
 * Be aware that this command may invalidate files even if it is aborted;
 * the user is cautioned against relying on the contents of invalidated
 * intermediate files such as @top without manually rebasing those files
 * to use a backing file of a read-only copy of @base prior to the point
 * where the commit operation was started (although such a rebase cannot
 * be safely done until the commit has successfully completed).  However,
 * the domain itself will not have any issues; the active layer remains
 * valid throughout the entire commit operation.  As a convenience,
 * if @flags contains VIR_DOMAIN_BLOCK_COMMIT_DELETE, this command will
 * unlink all files that were invalidated, after the commit successfully
 * completes.
 *
 * By default, if @base is NULL, the commit target will be the bottom of
 * the backing chain; if @flags contains VIR_DOMAIN_BLOCK_COMMIT_SHALLOW,
 * then the immediate backing file of @top will be used instead.  If @top
 * is NULL, the active image at the top of the chain will be used.  Some
 * hypervisors place restrictions on how much can be committed, and might
 * fail if @base is not the immediate backing file of @top, or if @top is
 * the active layer in use by a running domain, or if @top is not the
 * top-most file; restrictions may differ for online vs. offline domains.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the
 * <target dev='...'/> sub-element, such as "xvda").  Valid names
 * can be found by calling virDomainGetXMLDesc() and inspecting
 * elements within //domain/devices/disk.
 *
 * The maximum bandwidth (in MiB/s) that will be used to do the commit can be
 * specified with the bandwidth parameter.  If set to 0, libvirt will choose a
 * suitable default.  Some hypervisors do not support this feature and will
 * return an error if bandwidth is not 0; in this case, it might still be
 * possible for a later call to virDomainBlockJobSetSpeed() to succeed.
 * The actual speed can be determined with virDomainGetBlockJobInfo().
 *
 * Returns 0 if the operation has started, -1 on failure.
 */
int virDomainBlockCommit(virDomainPtr dom, const char *disk,
                         const char *base, const char *top,
                         unsigned long bandwidth, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, base=%s, top=%s, bandwidth=%lu, flags=%x",
                     disk, NULLSTR(base), NULLSTR(top), bandwidth, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    conn = dom->conn;

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);

    if (conn->driver->domainBlockCommit) {
        int ret;
        ret = conn->driver->domainBlockCommit(dom, disk, base, top, bandwidth,
                                              flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virDomainOpenGraphics:
 * @dom: pointer to domain object
 * @idx: index of graphics config to open
 * @fd: file descriptor to attach graphics to
 * @flags: bitwise-OR of virDomainOpenGraphicsFlags
 *
 * This will attempt to connect the file descriptor @fd, to
 * the graphics backend of @dom. If @dom has multiple graphics
 * backends configured, then @idx will determine which one is
 * opened, starting from @idx 0.
 *
 * To disable any authentication, pass the VIR_DOMAIN_OPEN_GRAPHICS_SKIPAUTH
 * constant for @flags.
 *
 * The caller should use an anonymous socketpair to open
 * @fd before invocation.
 *
 * This method can only be used when connected to a local
 * libvirt hypervisor, over a UNIX domain socket. Attempts
 * to use this method over a TCP connection will always fail
 *
 * Returns 0 on success, -1 on failure
 */
int virDomainOpenGraphics(virDomainPtr dom,
                          unsigned int idx,
                          int fd,
                          unsigned int flags)
{
    struct stat sb;
    VIR_DOMAIN_DEBUG(dom, "idx=%u, fd=%d, flags=%x",
                     idx, fd, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNegativeArgGoto(fd, error);

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access file descriptor %d"), fd);
        goto error;
    }

    if (!S_ISSOCK(sb.st_mode)) {
        virReportInvalidArg(fd,
                          _("fd %d in %s must be a socket"),
                            fd, __FUNCTION__);
        goto error;
    }

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (!VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                  VIR_DRV_FEATURE_FD_PASSING)) {
        virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        goto error;
    }

    if (dom->conn->driver->domainOpenGraphics) {
        int ret;
        ret = dom->conn->driver->domainOpenGraphics(dom, idx, fd, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}


/**
 * virConnectSetKeepAlive:
 * @conn: pointer to a hypervisor connection
 * @interval: number of seconds of inactivity before a keepalive message is sent
 * @count: number of messages that can be sent in a row
 *
 * Start sending keepalive messages after interval second of inactivity and
 * consider the connection to be broken when no response is received after
 * count keepalive messages sent in a row.  In other words, sending count + 1
 * keepalive message results in closing the connection.  When interval is <= 0,
 * no keepalive messages will be sent.  When count is 0, the connection will be
 * automatically closed after interval seconds of inactivity without sending
 * any keepalive messages.
 *
 * Note: client has to implement and run event loop to be able to use keepalive
 * messages.  Failure to do so may result in connections being closed
 * unexpectedly.
 *
 * Note: This API function controls only keepalive messages sent by the client.
 * If the server is configured to use keepalive you still need to run the event
 * loop to respond to them, even if you disable keepalives by this function.
 *
 * Returns -1 on error, 0 on success, 1 when remote party doesn't support
 * keepalive messages.
 */
int virConnectSetKeepAlive(virConnectPtr conn,
                           int interval,
                           unsigned int count)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, interval=%d, count=%u", conn, interval, count);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->connectSetKeepAlive) {
        ret = conn->driver->connectSetKeepAlive(conn, interval, count);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

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
int virConnectIsAlive(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }
    if (conn->driver->connectIsAlive) {
        int ret;
        ret = conn->driver->connectIsAlive(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
int virConnectRegisterCloseCallback(virConnectPtr conn,
                                    virConnectCloseFunc cb,
                                    void *opaque,
                                    virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virObjectRef(conn);

    virMutexLock(&conn->lock);
    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback) {
        virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
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
    virObjectUnref(conn);
    virDispatchError(NULL);
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
int virConnectUnregisterCloseCallback(virConnectPtr conn,
                                      virConnectCloseFunc cb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virMutexLock(&conn->lock);
    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback != cb) {
        virLibConnError(VIR_ERR_OPERATION_INVALID, "%s",
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
    virDispatchError(NULL);
    return -1;
}

/**
 * virDomainSetBlockIoTune:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: Pointer to blkio parameter objects
 * @nparams: Number of blkio parameters (this value can be the same or
 *           less than the number of parameters supported)
 * @flags: bitwise-OR of virDomainModificationImpact
 *
 * Change all or a subset of the per-device block IO tunables.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the <target
 * dev='...'/> sub-element, such as "xvda").  Valid names can be found
 * by calling virDomainGetXMLDesc() and inspecting elements
 * within //domain/devices/disk.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int virDomainSetBlockIoTune(virDomainPtr dom,
                            const char *disk,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     disk, params, nparams, flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    virCheckNonNullArgGoto(disk, error);
    virCheckPositiveArgGoto(nparams, error);
    virCheckNonNullArgGoto(params, error);

    if (virTypedParameterValidateSet(dom->conn, params, nparams) < 0)
        goto error;

    conn = dom->conn;

    if (conn->driver->domainSetBlockIoTune) {
        int ret;
        ret = conn->driver->domainSetBlockIoTune(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainGetBlockIoTune:
 * @dom: pointer to domain object
 * @disk: path to the block device, or device shorthand
 * @params: Pointer to blkio parameter object
 *          (return value, allocated by the caller)
 * @nparams: Pointer to number of blkio parameters
 * @flags: bitwise-OR of virDomainModificationImpact and virTypedParameterFlags
 *
 * Get all block IO tunable parameters for a given device.  On input,
 * @nparams gives the size of the @params array; on output, @nparams
 * gives how many slots were filled with parameter information, which
 * might be less but will not exceed the input value.
 *
 * As a special case, calling with @params as NULL and @nparams as 0
 * on input will cause @nparams on output to contain the number of
 * parameters supported by the hypervisor, either for the given @disk
 * (note that block devices of different types might support different
 * parameters), or if @disk is NULL, for all possible disks. The
 * caller should then allocate @params array,
 * i.e. (sizeof(@virTypedParameter) * @nparams) bytes and call the API
 * again.  See virDomainGetMemoryParameters() for more details.
 *
 * The @disk parameter is either an unambiguous source name of the
 * block device (the <source file='...'/> sub-element, such as
 * "/path/to/image"), or the device target shorthand (the <target
 * dev='...'/> sub-element, such as "xvda").  Valid names can be found
 * by calling virDomainGetXMLDesc() and inspecting elements
 * within //domain/devices/disk.  This parameter cannot be NULL
 * unless @nparams is 0 on input.
 *
 * Returns -1 in case of error, 0 in case of success.
 */
int virDomainGetBlockIoTune(virDomainPtr dom,
                            const char *disk,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(dom, "disk=%s, params=%p, nparams=%d, flags=%x",
                     NULLSTR(disk), params, (nparams) ? *nparams : -1, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    virCheckNonNullArgGoto(nparams, error);
    virCheckNonNegativeArgGoto(*nparams, error);
    if (*nparams != 0) {
        virCheckNonNullArgGoto(params, error);
        virCheckNonNullArgGoto(disk, error);
    }

    if (VIR_DRV_SUPPORTS_FEATURE(dom->conn->driver, dom->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    /* At most one of these two flags should be set.  */
    if ((flags & VIR_DOMAIN_AFFECT_LIVE) &&
        (flags & VIR_DOMAIN_AFFECT_CONFIG)) {
        virReportInvalidArg(flags,
                            _("flags 'affect live' and 'affect config' in %s are mutually exclusive"),
                            __FUNCTION__);
        goto error;
    }
    conn = dom->conn;

    if (conn->driver->domainGetBlockIoTune) {
        int ret;
        ret = conn->driver->domainGetBlockIoTune(dom, disk, params, nparams, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainGetCPUStats:
 * @domain: domain to query
 * @params: array to populate on output
 * @nparams: number of parameters per cpu
 * @start_cpu: which cpu to start with, or -1 for summary
 * @ncpus: how many cpus to query
 * @flags: bitwise-OR of virTypedParameterFlags
 *
 * Get statistics relating to CPU usage attributable to a single
 * domain (in contrast to the statistics returned by
 * virNodeGetCPUStats() for all processes on the host).  @dom
 * must be running (an inactive domain has no attributable cpu
 * usage).  On input, @params must contain at least @nparams * @ncpus
 * entries, allocated by the caller.
 *
 * If @start_cpu is -1, then @ncpus must be 1, and the returned
 * results reflect the statistics attributable to the entire
 * domain (such as user and system time for the process as a
 * whole).  Otherwise, @start_cpu represents which cpu to start
 * with, and @ncpus represents how many consecutive processors to
 * query, with statistics attributable per processor (such as
 * per-cpu usage).  If @ncpus is larger than the number of cpus
 * available to query, then the trailing part of the array will
 * be unpopulated.
 *
 * The remote driver imposes a limit of 128 @ncpus and 16 @nparams;
 * the number of parameters per cpu should not exceed 16, but if you
 * have a host with more than 128 CPUs, your program should split
 * the request into multiple calls.
 *
 * As special cases, if @params is NULL and @nparams is 0 and
 * @ncpus is 1, and the return value will be how many
 * statistics are available for the given @start_cpu.  This number
 * may be different for @start_cpu of -1 than for any non-negative
 * value, but will be the same for all non-negative @start_cpu.
 * Likewise, if @params is NULL and @nparams is 0 and @ncpus is 0,
 * the number of cpus available to query is returned.  From the
 * host perspective, this would typically match the cpus member
 * of virNodeGetInfo(), but might be less due to host cpu hotplug.
 *
 * For now, @flags is unused, and the statistics all relate to the
 * usage from the host perspective.  It is possible that a future
 * version will support a flag that queries the cpu usage from the
 * guest's perspective, where the maximum cpu to query would be
 * related to virDomainGetVcpusFlags() rather than virNodeGetInfo().
 * An individual guest vcpu cannot be reliably mapped back to a
 * specific host cpu unless a single-processor vcpu pinning was used,
 * but when @start_cpu is -1, any difference in usage between a host
 * and guest perspective would serve as a measure of hypervisor overhead.
 *
 * Typical use sequence is below.
 *
 * getting total stats: set start_cpu as -1, ncpus 1
 * virDomainGetCPUStats(dom, NULL, 0, -1, 1, 0) => nparams
 * params = calloc(nparams, sizeof(virTypedParameter))
 * virDomainGetCPUStats(dom, params, nparams, -1, 1, 0) => total stats.
 *
 * getting per-cpu stats:
 * virDomainGetCPUStats(dom, NULL, 0, 0, 0, 0) => ncpus
 * virDomainGetCPUStats(dom, NULL, 0, 0, 1, 0) => nparams
 * params = calloc(ncpus * nparams, sizeof(virTypedParameter))
 * virDomainGetCPUStats(dom, params, nparams, 0, ncpus, 0) => per-cpu stats
 *
 * Returns -1 on failure, or the number of statistics that were
 * populated per cpu on success (this will be less than the total
 * number of populated @params, unless @ncpus was 1; and may be
 * less than @nparams).  The populated parameters start at each
 * stride of @nparams, which means the results may be discontiguous;
 * any unpopulated parameters will be zeroed on success (this includes
 * skipped elements if @nparams is too large, and tail elements if
 * @ncpus is too large).  The caller is responsible for freeing any
 * returned string parameters.
 */
int virDomainGetCPUStats(virDomainPtr domain,
                         virTypedParameterPtr params,
                         unsigned int nparams,
                         int start_cpu,
                         unsigned int ncpus,
                         unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "params=%p, nparams=%d, start_cpu=%d, ncpus=%u, flags=%x",
                     params, nparams, start_cpu, ncpus, flags);
    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;
    /* Special cases:
     * start_cpu must be non-negative, or else -1
     * if start_cpu is -1, ncpus must be 1
     * params == NULL must match nparams == 0
     * ncpus must be non-zero unless params == NULL
     * nparams * ncpus must not overflow (RPC may restrict it even more)
     */
    if (start_cpu == -1) {
        if (ncpus != 1) {
            virReportInvalidArg(start_cpu,
                                _("ncpus in %s must be 1 when start_cpu is -1"),
                                __FUNCTION__);
            goto error;
        }
    } else {
        virCheckNonNegativeArgGoto(start_cpu, error);
    }
    if (nparams)
        virCheckNonNullArgGoto(params, error);
    else
        virCheckNullArgGoto(params, error);
    if (ncpus == 0)
        virCheckNullArgGoto(params, error);

    if (nparams && ncpus > UINT_MAX / nparams) {
        virLibDomainError(VIR_ERR_OVERFLOW, _("input too large: %u * %u"),
                          nparams, ncpus);
        goto error;
    }
    if (VIR_DRV_SUPPORTS_FEATURE(domain->conn->driver, domain->conn,
                                 VIR_DRV_FEATURE_TYPED_PARAM_STRING))
        flags |= VIR_TYPED_PARAM_STRING_OKAY;

    if (conn->driver->domainGetCPUStats) {
        int ret;

        ret = conn->driver->domainGetCPUStats(domain, params, nparams,
                                              start_cpu, ncpus, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibDomainError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return -1;
}

/**
 * virDomainGetDiskErrors:
 * @dom: a domain object
 * @errors: array to populate on output
 * @maxerrors: size of @errors array
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * The function populates @errors array with all disks that encountered an
 * I/O error.  Disks with no error will not be returned in the @errors array.
 * Each disk is identified by its target (the dev attribute of target
 * subelement in domain XML), such as "vda", and accompanied with the error
 * that was seen on it.  The caller is also responsible for calling free()
 * on each disk name returned.
 *
 * In a special case when @errors is NULL and @maxerrors is 0, the function
 * returns preferred size of @errors that the caller should use to get all
 * disk errors.
 *
 * Since calling virDomainGetDiskErrors(dom, NULL, 0, 0) to get preferred size
 * of @errors array and getting the errors are two separate operations, new
 * disks may be hotplugged to the domain and new errors may be encountered
 * between the two calls.  Thus, this function may not return all disk errors
 * because the supplied array is not large enough.  Such errors may, however,
 * be detected by listening to domain events.
 *
 * Returns number of disks with errors filled in the @errors array or -1 on
 * error.
 */
int
virDomainGetDiskErrors(virDomainPtr dom,
                       virDomainDiskErrorPtr errors,
                       unsigned int maxerrors,
                       unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "errors=%p, maxerrors=%u, flags=%x",
                     errors, maxerrors, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if ((!errors && maxerrors) || (errors && !maxerrors)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        goto error;
    }

    if (dom->conn->driver->domainGetDiskErrors) {
        int ret = dom->conn->driver->domainGetDiskErrors(dom, errors,
                                                         maxerrors, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}

/**
 * virDomainGetHostname:
 * @domain: a domain object
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Get the hostname for that domain.
 *
 * Dependent on hypervisor used, this may require a guest agent to be
 * available.
 *
 * Returns the hostname which must be freed by the caller, or
 * NULL if there was an error.
 */
char *
virDomainGetHostname(virDomainPtr domain, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "flags=%x", flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    if (conn->driver->domainGetHostname) {
        char *ret;
        ret = conn->driver->domainGetHostname(domain, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(domain->conn);
    return NULL;
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (conn->driver->nodeGetCPUMap) {
        int ret = conn->driver->nodeGetCPUMap(conn, cpumap, online, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}

/**
 * virDomainFSTrim:
 * @dom: a domain object
 * @mountPoint: which mount point to trim
 * @minimum: Minimum contiguous free range to discard in bytes
 * @flags: extra flags, not used yet, so callers should always pass 0
 *
 * Calls FITRIM within the guest (hence guest agent may be
 * required depending on hypervisor used). Either call it on each
 * mounted filesystem (@mountPoint is NULL) or just on specified
 * @mountPoint. @minimum hints that free ranges smaller than this
 * may be ignored (this is a hint and the guest may not respect
 * it).  By increasing this value, the fstrim operation will
 * complete more quickly for filesystems with badly fragmented
 * free space, although not all blocks will be discarded.
 * If @minimum is not zero, the command may fail.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virDomainFSTrim(virDomainPtr dom,
                const char *mountPoint,
                unsigned long long minimum,
                unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom, "mountPoint=%s, minimum=%llu, flags=%x",
                     mountPoint, minimum, flags);

    virResetLastError();

    if (!VIR_IS_DOMAIN(dom)) {
        virLibDomainError(VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    if (dom->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (dom->conn->driver->domainFSTrim) {
        int ret = dom->conn->driver->domainFSTrim(dom, mountPoint,
                                                  minimum, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(dom->conn);
    return -1;
}
