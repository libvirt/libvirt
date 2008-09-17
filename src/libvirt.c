/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005,2006,2008 Red Hat, Inc.
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

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include "getpass.h"

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include "internal.h"
#include "driver.h"

#include "uuid.h"
#include "util.h"
#include "memory.h"

#ifdef WITH_TEST
#include "test.h"
#endif
#ifdef WITH_XEN
#include "xen_unified.h"
#endif
#ifdef WITH_REMOTE
#include "remote_internal.h"
#endif
#ifdef WITH_QEMU
#include "qemu_driver.h"
#endif
#ifdef WITH_OPENVZ
#include "openvz_driver.h"
#endif
#ifdef WITH_LXC
#include "lxc_driver.h"
#endif
#include "storage_driver.h"

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to guarantee coherent pointer state ?
 */

static virDriverPtr virDriverTab[MAX_DRIVERS];
static int virDriverTabCount = 0;
static virNetworkDriverPtr virNetworkDriverTab[MAX_DRIVERS];
static int virNetworkDriverTabCount = 0;
static virStorageDriverPtr virStorageDriverTab[MAX_DRIVERS];
static int virStorageDriverTabCount = 0;
#ifdef WITH_LIBVIRTD
static virStateDriverPtr virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount = 0;
#endif
static int initialized = 0;

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

#ifdef ENABLE_DEBUG
int debugFlag = 0;
#endif

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
    if (err != 0)
        return -1;
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
#ifdef ENABLE_DEBUG
    char *debugEnv;
#endif
    if (initialized)
        return(0);
    initialized = 1;

#ifdef ENABLE_DEBUG
    debugEnv = getenv("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv && *debugEnv != '0')
        debugFlag = 1;
#endif

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
#ifdef WITH_TEST
    if (testRegister() == -1) return -1;
#endif
#ifdef WITH_XEN
    if (xenUnifiedRegister () == -1) return -1;
#endif
#ifdef WITH_LIBVIRTD
#ifdef WITH_QEMU
    if (qemudRegister() == -1) return -1;
#endif
#ifdef WITH_OPENVZ
    if (openvzRegister() == -1) return -1;
#endif
#ifdef WITH_LXC
    if (lxcRegister() == -1) return -1;
#endif
    if (storageRegister() == -1) return -1;
#ifdef WITH_REMOTE
    if (remoteRegister () == -1) return -1;
#endif
#endif

    return(0);
}



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

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_NONE, error, VIR_ERR_ERROR,
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

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_NONE, error, VIR_ERR_WARNING,
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

    errmsg = __virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_DOMAIN) {
        conn = domain->conn;
    }
    __virRaiseError(conn, domain, NULL, VIR_FROM_DOM, error, VIR_ERR_ERROR,
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

    errmsg = __virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_NETWORK) {
        conn = network->conn;
    }
    __virRaiseError(conn, NULL, network, VIR_FROM_NET, error, VIR_ERR_ERROR,
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

    errmsg = __virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_STORAGE_POOL)
        conn = pool->conn;

    __virRaiseError(conn, NULL, NULL, VIR_FROM_STORAGE, error, VIR_ERR_ERROR,
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

    errmsg = __virErrorMsg(error, info);
    if (error != VIR_ERR_INVALID_STORAGE_VOL)
        conn = vol->conn;

    __virRaiseError(conn, NULL, NULL, VIR_FROM_STORAGE, error, VIR_ERR_ERROR,
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

    virNetworkDriverTab[virNetworkDriverTabCount] = driver;
    return virNetworkDriverTabCount++;
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

    virStorageDriverTab[virStorageDriverTabCount] = driver;
    return virStorageDriverTabCount++;
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

int __virStateInitialize(void) {
    int i, ret = 0;

    if (virInitialize() < 0)
        return -1;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->initialize &&
            virStateDriverTab[i]->initialize() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateCleanup(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->cleanup &&
            virStateDriverTab[i]->cleanup() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateReload(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->reload &&
            virStateDriverTab[i]->reload() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateActive(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->active &&
            virStateDriverTab[i]->active())
            ret = 1;
    }
    return ret;
}

int __virStateSigDispatcher(siginfo_t *siginfo) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->sigHandler &&
            virStateDriverTab[i]->sigHandler(siginfo))
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
    int i;
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
        for (i = 0;i < virDriverTabCount;i++) {
            if ((virDriverTab[i] != NULL) &&
                (STRCASEEQ(virDriverTab[i]->name, type))) {
                *typeVer = virDriverTab[i]->ver;
                break;
            }
        }
        if (i >= virDriverTabCount) {
            *typeVer = 0;
            virLibConnError(NULL, VIR_ERR_NO_SUPPORT, type);
            return (-1);
        }
    }
    return (0);
}

static virConnectPtr
do_open (const char *name,
         virConnectAuthPtr auth,
         int flags)
{
    int i, res;
    virConnectPtr ret = NULL;
    xmlURIPtr uri;

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
            const char *use = NULL;
            const char *latest;
            int probes = 0;
            for (i = 0; i < virDriverTabCount; i++) {
                if ((virDriverTab[i]->probe != NULL) &&
                    ((latest = virDriverTab[i]->probe()) != NULL)) {
                    probes++;

                    DEBUG("Probed %s", latest);
                    /*
                     * if running a xen kernel, give it priority over
                     * QEmu emulation
                     */
                    if (STREQ(latest, "xen:///"))
                        use = latest;
                    else if (use == NULL)
                        use = latest;
                }
            }
            if (use == NULL) {
                name = "xen:///";
                DEBUG("Could not probe any hypervisor defaulting to %s",
                      name);
            } else {
                name = use;
                DEBUG("Using %s as default URI, %d hypervisor found",
                      use, probes);
            }
        }
    }

    /* Convert xen -> xen:/// for back compat */
    if (STRCASEEQ(name, "xen"))
        name = "xen:///";

    /* Convert xen:// -> xen:/// because xmlParseURI cannot parse the
     * former.  This allows URIs such as xen://localhost to work.
     */
    if (STREQ (name, "xen://"))
        name = "xen:///";

    ret = virGetConnect();
    if (ret == NULL)
        return NULL;

    uri = xmlParseURI (name);
    if (!uri) {
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
          uri->scheme, uri->opaque, uri->authority, uri->server,
          uri->user, uri->port, uri->path);

    ret->name = strdup (name);
    if (!ret->name) {
        virLibConnError (ret, VIR_ERR_NO_MEMORY, _("allocating conn->name"));
        goto failed;
    }

    /* Cleansing flags */
    ret->flags = flags & VIR_CONNECT_RO;

    for (i = 0; i < virDriverTabCount; i++) {
        DEBUG("trying driver %d (%s) ...",
              i, virDriverTab[i]->name);
        res = virDriverTab[i]->open (ret, uri, auth, flags);
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
        res = virNetworkDriverTab[i]->open (ret, uri, auth, flags);
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


    /* Secondary driver for storage. Optional */
    for (i = 0; i < virStorageDriverTabCount; i++) {
        res = virStorageDriverTab[i]->open (ret, uri, auth, flags);
#ifdef ENABLE_DEBUG
        DEBUG("storage driver %d %s returned %s",
              i, virStorageDriverTab[i]->name,
              res == VIR_DRV_OPEN_SUCCESS ? "SUCCESS" :
              (res == VIR_DRV_OPEN_DECLINED ? "DECLINED" :
               (res == VIR_DRV_OPEN_ERROR ? "ERROR" : "unknown status")));
#endif
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

    xmlFreeURI (uri);

    return ret;

failed:
    if (ret->driver) ret->driver->close (ret);
    if (uri) xmlFreeURI(uri);

    /* If no global error was set, copy any error set
       in the connection object we're about to dispose of */
    if (__lastErr.code == VIR_ERR_OK) {
        memcpy(&__lastErr, &ret->err, sizeof(ret->err));
        memset(&ret->err, 0, sizeof(ret->err));
    }

    /* Still no error set, then raise a generic error */
    if (__lastErr.code == VIR_ERR_OK)
        virLibConnError (NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to open connection"));

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

    DEBUG("name=%s, auth=%p, flags=%d", name, auth, flags);
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

    if (!VIR_IS_CONNECT(conn))
        return (-1);

    if (conn->networkDriver)
        conn->networkDriver->close (conn);
    if (conn->storageDriver)
        conn->storageDriver->close (conn);
    conn->driver->close (conn);

    if (virUnrefConnect(conn) < 0)
        return (-1);
    return (0);
}

/* Not for public use.  This function is part of the internal
 * implementation of driver features in the remote case.
 */
int
__virDrvSupportsFeature (virConnectPtr conn, int feature)
{
    DEBUG("conn=%p, feature=%d", conn, feature);

    if (!VIR_IS_CONNECT(conn))
        return (-1);

    return VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn, feature);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (hvVer == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->version)
        return conn->driver->version (conn, hvVer);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getHostname)
        return conn->driver->getHostname (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    /* Drivers may override getURI, but if they don't then
     * we provide a default implementation.
     */
    if (conn->driver->getURI)
        return conn->driver->getURI (conn);

    name = strdup (conn->name);
    if (!name) {
        virLibConnError (conn, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return NULL;
    }
    return name;
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->getMaxVcpus)
        return conn->driver->getMaxVcpus (conn, type);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((ids == NULL) || (maxids < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->listDomains)
        return conn->driver->listDomains (conn, ids, maxids);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->numOfDomains)
        return conn->driver->numOfDomains (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    return dom->conn;
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: string containing an XML description of the domain
 * @flags: callers should always pass 0
 *
 * Launch a new Linux guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires privileged access to the hypervisor.
 * The domain is not persistent, so its definition will disappear when it
 * is destroyed, or if the host is restarted (see virDomainDefineXML() to
 * define persistent domains).
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags)
{
    DEBUG("conn=%p, xmlDesc=%s, flags=%d", conn, xmlDesc, flags);

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainCreateLinux)
        return conn->driver->domainCreateLinux (conn, xmlDesc, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainLookupByID)
        return conn->driver->domainLookupByID (conn, id);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainLookupByUUID)
        return conn->driver->domainLookupByUUID (conn, uuid);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);

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
        return (NULL);
    }
    for (i = 0; i < VIR_UUID_BUFLEN; i++)
        uuid[i] = raw[i] & 0xFF;

    return virDomainLookupByUUID(conn, &uuid[0]);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainLookupByName)
        return conn->driver->domainLookupByName (conn, name);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->domainDestroy)
        return conn->driver->domainDestroy (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (virUnrefDomain(domain) < 0)
        return (-1);
    return(0);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainSuspend)
        return conn->driver->domainSuspend (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainResume)
        return conn->driver->domainResume (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (to == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
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

    if (conn->driver->domainSave)
        return conn->driver->domainSave (domain, to);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    if (from == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /*
     * We must absolutize the file path as the restore is done out of process
     * TODO: check for URI when libxml2 is linked in.
     */
    if (from[0] != '/') {
        unsigned int len, t;

        t = strlen(from);
        if (getcwd(filepath, sizeof(filepath) - (t + 3)) == NULL)
            return (-1);
        len = strlen(filepath);
        /* that should be covered by getcwd() semantic, but be 100% sure */
        if (len > sizeof(filepath) - (t + 3))
            return (-1);
        filepath[len] = '/';
        strcpy(&filepath[len + 1], from);
        from = &filepath[0];
    }

    if (conn->driver->domainRestore)
        return conn->driver->domainRestore (conn, from);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (to == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
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

    if (conn->driver->domainCoreDump)
        return conn->driver->domainCoreDump (domain, to, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainShutdown)
        return conn->driver->domainShutdown (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainReboot)
        return conn->driver->domainReboot (domain, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (virDomainGetUUID(domain, &uuid[0]))
        return (-1);

    virUUIDFormat(uuid, buf);
    return (0);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    conn = domain->conn;

    if (conn->driver->domainGetOSType)
        return conn->driver->domainGetOSType (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxMemory)
        return conn->driver->domainGetMaxMemory (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    if (memory < 4096) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;

    if (conn->driver->domainSetMaxMemory)
        return conn->driver->domainSetMaxMemory (domain, memory);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    if (memory < 4096) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainSetMemory)
        return conn->driver->domainSetMemory (domain, memory);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memset(info, 0, sizeof(virDomainInfo));

    conn = domain->conn;

    if (conn->driver->domainGetInfo)
        return conn->driver->domainGetInfo (domain, info);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/**
 * virDomainGetXMLDesc:
 * @domain: a domain object
 * @flags: an OR'ed set of virDomainXMLFlags
 *
 * Provide an XML description of the domain. The description may be reused
 * later to relaunch the domain with virDomainCreateLinux().
 *
 * Returns a 0 terminated UTF-8 encoded XML instance, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virDomainGetXMLDesc(virDomainPtr domain, int flags)
{
    virConnectPtr conn;
    DEBUG("domain=%p, flags=%d", domain, flags);

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    conn = domain->conn;

    if (conn->driver->domainDumpXML)
        return conn->driver->domainDumpXML (domain, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    int cookielen = 0, ret;
    DEBUG("domain=%p, dconn=%p, flags=%lu, dname=%s, uri=%s, bandwidth=%lu",
          domain, dconn, flags, dname, uri, bandwidth);

    if (!VIR_IS_DOMAIN (domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    conn = domain->conn;        /* Source connection. */
    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    /* Check that migration is supported by both drivers. */
    if (!VIR_DRV_SUPPORTS_FEATURE (conn->driver, conn,
                                   VIR_DRV_FEATURE_MIGRATION_V1) ||
        !VIR_DRV_SUPPORTS_FEATURE (dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_V1)) {
        virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        return NULL;
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
    ret = dconn->driver->domainMigratePrepare
        (dconn, &cookie, &cookielen, uri, &uri_out, flags, dname, bandwidth);
    if (ret == -1) goto done;
    if (uri == NULL && uri_out == NULL) {
        virLibConnError (conn, VIR_ERR_INTERNAL_ERROR,
                         _("domainMigratePrepare did not set uri"));
        goto done;
    }
    if (uri_out) uri = uri_out; /* Did domainMigratePrepare change URI? */

    assert (uri != NULL);

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    ret = conn->driver->domainMigratePerform
        (domain, cookie, cookielen, uri, flags, dname, bandwidth);

    if (ret == -1) goto done;

    /* Get the destination domain and return it or error.
     * 'domain' no longer actually exists at this point (or so we hope), but
     * we still use the object in memory in order to get the name.
     */
    dname = dname ? dname : domain->name;
    if (dconn->driver->domainMigrateFinish)
        ddomain = dconn->driver->domainMigrateFinish
            (dconn, dname, cookie, cookielen, uri, flags);
    else
        ddomain = virDomainLookupByName (dconn, dname);

 done:
    free (uri_out);
    free (cookie);
    return ddomain;
}

/* Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
__virDomainMigratePrepare (virConnectPtr dconn,
                           char **cookie,
                           int *cookielen,
                           const char *uri_in,
                           char **uri_out,
                           unsigned long flags,
                           const char *dname,
                           unsigned long bandwidth)
{
    DEBUG("dconn=%p, cookie=%p, cookielen=%p, uri_in=%s, uri_out=%p, flags=%lu, dname=%s, bandwidth=%lu", dconn, cookie, cookielen, uri_in, uri_out, flags, dname, bandwidth);

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (dconn->driver->domainMigratePrepare)
        return dconn->driver->domainMigratePrepare (dconn, cookie, cookielen,
                                                    uri_in, uri_out,
                                                    flags, dname, bandwidth);

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/* Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
int
__virDomainMigratePerform (virDomainPtr domain,
                           const char *cookie,
                           int cookielen,
                           const char *uri,
                           unsigned long flags,
                           const char *dname,
                           unsigned long bandwidth)
{
    virConnectPtr conn;
    DEBUG("domain=%p, cookie=%p, cookielen=%d, uri=%s, flags=%lu, dname=%s, bandwidth=%lu", domain, cookie, cookielen, uri, flags, dname, bandwidth);

    if (!VIR_IS_DOMAIN (domain)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (conn->driver->domainMigratePerform)
        return conn->driver->domainMigratePerform (domain, cookie, cookielen,
                                                   uri,
                                                   flags, dname, bandwidth);

    virLibDomainError (domain, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/* Not for public use.  This function is part of the internal
 * implementation of migration in the remote case.
 */
virDomainPtr
__virDomainMigrateFinish (virConnectPtr dconn,
                          const char *dname,
                          const char *cookie,
                          int cookielen,
                          const char *uri,
                          unsigned long flags)
{
    DEBUG("dconn=%p, dname=%s, cookie=%p, cookielen=%d, uri=%s, flags=%lu", dconn, dname, cookie, cookielen, uri, flags);

    if (!VIR_IS_CONNECT (dconn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (dconn->driver->domainMigrateFinish)
        return dconn->driver->domainMigrateFinish (dconn, dname,
                                                   cookie, cookielen,
                                                   uri, flags);

    virLibConnError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->nodeGetInfo)
        return conn->driver->nodeGetInfo (conn, info);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getCapabilities)
        return conn->driver->getCapabilities (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}

/**
 * virNodeGetFreeMemory:
 * @conn: pointer to the hypervisor connection
 *
 * provides the free memory available on the Node
 *
 * Returns the available free memory in kilobytes or 0 in case of error
 */
unsigned long long
virNodeGetFreeMemory(virConnectPtr conn)
{
    DEBUG("conn=%p", conn);

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return 0;
    }

    if (conn->driver->getFreeMemory)
        return conn->driver->getFreeMemory (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerType){
        schedtype = conn->driver->domainGetSchedulerType (domain, nparams);
        return schedtype;
    }

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (conn->driver->domainGetSchedulerParameters)
        return conn->driver->domainGetSchedulerParameters (domain, params, nparams);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (conn->driver->domainSetSchedulerParameters)
        return conn->driver->domainSetSchedulerParameters (domain, params, nparams);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!stats || size > sizeof stats2) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

    if (conn->driver->domainBlockStats) {
        if (conn->driver->domainBlockStats (dom, path, &stats2) == -1)
            return -1;

        memcpy (stats, &stats2, size);
        return 0;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!stats || size > sizeof stats2) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

    if (conn->driver->domainInterfaceStats) {
        if (conn->driver->domainInterfaceStats (dom, path, &stats2) == -1)
            return -1;

        memcpy (stats, &stats2, size);
        return 0;
    }

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

    if (!path) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("path is NULL"));
        return -1;
    }

    if (flags != 0) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("flags must be zero"));
        return -1;
    }

    /* Allow size == 0 as an access test. */
    if (size > 0 && !buffer) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("buffer is NULL"));
        return -1;
    }

    if (conn->driver->domainBlockPeek)
        return conn->driver->domainBlockPeek (dom, path, offset, size,
                                              buffer, flags);

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN (dom)) {
        virLibDomainError (NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = dom->conn;

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
        return -1;
    }

    /* Allow size == 0 as an access test. */
    if (size > 0 && !buffer) {
        virLibDomainError (dom, VIR_ERR_INVALID_ARG,
                           _("buffer is NULL but size is non-zero"));
        return -1;
    }

    if (conn->driver->domainMemoryPeek)
        return conn->driver->domainMemoryPeek (dom, start, size,
                                               buffer, flags);

    virLibDomainError (dom, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * virDomainUndefine().
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXML(virConnectPtr conn, const char *xml) {
    DEBUG("conn=%p, xml=%s", conn, xml);

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->driver->domainDefineXML)
        return conn->driver->domainDefineXML (conn, xml);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->domainUndefine)
        return conn->driver->domainUndefine (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->numOfDefinedDomains)
        return conn->driver->numOfDefinedDomains (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->listDefinedDomains)
        return conn->driver->listDefinedDomains (conn, names, maxnames);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->domainCreate)
        return conn->driver->domainCreate (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainGetAutostart)
        return conn->driver->domainGetAutostart (domain, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainSetAutostart)
        return conn->driver->domainSetAutostart (domain, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (nvcpus < 1) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;

    if (conn->driver->domainSetVcpus)
        return conn->driver->domainSetVcpus (domain, nvcpus);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if ((vcpu > 32000) || (cpumap == NULL) || (maplen < 1)) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainPinVcpu)
        return conn->driver->domainPinVcpu (domain, vcpu, cpumap, maplen);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if ((info == NULL) || (maxinfo < 1)) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    if (cpumaps != NULL && maplen < 1) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainGetVcpus)
        return conn->driver->domainGetVcpus (domain, info, maxinfo,
                                             cpumaps, maplen);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    conn = domain->conn;

    if (conn->driver->domainGetMaxVcpus)
        return conn->driver->domainGetMaxVcpus (domain);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;

    if (conn->driver->domainAttachDevice)
        return conn->driver->domainAttachDevice (domain, xml);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }
    conn = domain->conn;

    if (conn->driver->domainDetachDevice)
        return conn->driver->domainDetachDevice (domain, xml);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((freeMems == NULL) || (maxCells <= 0) || (startCell < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->driver->nodeGetCellsFreeMemory)
        return conn->driver->nodeGetCellsFreeMemory (conn, freeMems, startCell, maxCells);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_NETWORK (net)) {
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->numOfNetworks)
        return conn->networkDriver->numOfNetworks (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->listNetworks)
        return conn->networkDriver->listNetworks (conn, names, maxnames);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->numOfDefinedNetworks)
        return conn->networkDriver->numOfDefinedNetworks (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->listDefinedNetworks)
        return conn->networkDriver->listDefinedNetworks (conn,
                                                         names, maxnames);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->networkDriver && conn->networkDriver->networkLookupByName)
        return conn->networkDriver->networkLookupByName (conn, name);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->networkDriver && conn->networkDriver->networkLookupByUUID)
        return conn->networkDriver->networkLookupByUUID (conn, uuid);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
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
        return (NULL);
    }
    for (i = 0; i < VIR_UUID_BUFLEN; i++)
        uuid[i] = raw[i] & 0xFF;

    return virNetworkLookupByUUID(conn, &uuid[0]);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }

    if (conn->networkDriver && conn->networkDriver->networkCreateXML)
        return conn->networkDriver->networkCreateXML (conn, xmlDesc);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->networkDriver && conn->networkDriver->networkDefineXML)
        return conn->networkDriver->networkDefineXML (conn, xml);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->networkUndefine)
        return conn->networkDriver->networkUndefine (network);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (network == NULL) {
        TODO
        return (-1);
    }
    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->networkCreate)
        return conn->networkDriver->networkCreate (network);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }

    conn = network->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibNetworkError(network, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->networkDriver && conn->networkDriver->networkDestroy)
        return conn->networkDriver->networkDestroy (network);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (virUnrefNetwork(network) < 0)
        return (-1);
    return(0);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memcpy(uuid, &network->uuid[0], VIR_UUID_BUFLEN);

    return (0);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (virNetworkGetUUID(network, &uuid[0]))
        return (-1);

    virUUIDFormat(uuid, buf);
    return (0);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkDumpXML)
        return conn->networkDriver->networkDumpXML (network, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetBridgeName)
        return conn->networkDriver->networkGetBridgeName (network);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkGetAutostart)
        return conn->networkDriver->networkGetAutostart (network, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkSetAutostart)
        return conn->networkDriver->networkSetAutostart (network, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
virStoragePoolGetConnect (virStoragePoolPtr pool)
{
    DEBUG("pool=%p", pool);

    if (!VIR_IS_STORAGE_POOL (pool)) {
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->numOfPools)
        return conn->storageDriver->numOfPools (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->listPools)
        return conn->storageDriver->listPools (conn, names, maxnames);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->numOfDefinedPools)
        return conn->storageDriver->numOfDefinedPools (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->listDefinedPools)
        return conn->storageDriver->listDefinedPools (conn, names, maxnames);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }
    if (type == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }

    if (conn->storageDriver && conn->storageDriver->findPoolSources)
        return conn->storageDriver->findPoolSources(conn, type, srcSpec, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->poolLookupByName)
        return conn->storageDriver->poolLookupByName (conn, name);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->poolLookupByUUID)
        return conn->storageDriver->poolLookupByUUID (conn, uuid);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuidstr == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    return virStoragePoolLookupByUUID(conn, uuid);
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

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }

    if (vol->conn->storageDriver && vol->conn->storageDriver->poolLookupByVolume)
        return vol->conn->storageDriver->poolLookupByVolume (vol);

    virLibConnError (vol->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->poolCreateXML)
        return conn->storageDriver->poolCreateXML (conn, xmlDesc, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        virLibConnError(conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }
    if (xml == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->poolDefineXML)
        return conn->storageDriver->poolDefineXML (conn, xml, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolBuild)
        return conn->storageDriver->poolBuild (pool, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolUndefine)
        return conn->storageDriver->poolUndefine (pool);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (pool == NULL) {
        TODO;
        return (-1);
    }
    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolCreate)
        return conn->storageDriver->poolCreate (pool, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolDestroy)
        return conn->storageDriver->poolDestroy (pool);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolDelete)
        return conn->storageDriver->poolDelete (pool, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (virUnrefStoragePool(pool) < 0)
        return (-1);
    return(0);

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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStoragePoolError(pool, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->poolRefresh)
        return conn->storageDriver->poolRefresh (pool, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memcpy(uuid, &pool->uuid[0], VIR_UUID_BUFLEN);

    return (0);

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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (virStoragePoolGetUUID(pool, &uuid[0]))
        return (-1);

    virUUIDFormat(uuid, buf);
    return (0);

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

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memset(info, 0, sizeof(virStoragePoolInfo));

    conn = pool->conn;

    if (conn->storageDriver->poolGetInfo)
        return conn->storageDriver->poolGetInfo (pool, info);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolGetXMLDesc)
        return conn->storageDriver->poolGetXMLDesc (pool, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }
    if (!autostart) {
        virLibStoragePoolError(pool, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolGetAutostart)
        return conn->storageDriver->poolGetAutostart (pool, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibStoragePoolError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->poolSetAutostart)
        return conn->storageDriver->poolSetAutostart (pool, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->poolNumOfVolumes)
        return pool->conn->storageDriver->poolNumOfVolumes (pool);

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_POOL, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames < 0)) {
        virLibConnError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->poolListVolumes)
        return pool->conn->storageDriver->poolListVolumes (pool, names, maxnames);

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->volLookupByName)
        return pool->conn->storageDriver->volLookupByName (pool, name);

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (key == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->volLookupByKey)
        return conn->storageDriver->volLookupByKey (conn, key);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (path == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (conn->storageDriver && conn->storageDriver->volLookupByPath)
        return conn->storageDriver->volLookupByPath (conn, path);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_POOL(pool)) {
        virLibConnError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }

    if (pool->conn->flags & VIR_CONNECT_RO) {
        virLibConnError(pool->conn, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }

    if (pool->conn->storageDriver && pool->conn->storageDriver->volCreateXML)
        return pool->conn->storageDriver->volCreateXML (pool, xmldesc, flags);

    virLibConnError (pool->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }

    conn = vol->conn;
    if (conn->flags & VIR_CONNECT_RO) {
        virLibStorageVolError(vol, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    if (conn->storageDriver && conn->storageDriver->volDelete)
        return conn->storageDriver->volDelete (vol, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}


/**
 * virStorageVolFree:
 * @vol: pointer to storage volume
 *
 * Release the storage volume handle. The underlying
 * storage volume contains to exist
 *
 * Return 0 on success, or -1 on error
 */
int
virStorageVolFree(virStorageVolPtr vol)
{
    DEBUG("vol=%p", vol);

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }
    if (virUnrefStorageVol(vol) < 0)
        return (-1);
    return(0);
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

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibStorageVolError(vol, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memset(info, 0, sizeof(virStorageVolInfo));

    conn = vol->conn;

    if (conn->storageDriver->volGetInfo)
        return conn->storageDriver->volGetInfo (vol, info);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibStorageVolError(vol, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->volGetXMLDesc)
        return conn->storageDriver->volGetXMLDesc (vol, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    if (!VIR_IS_STORAGE_VOL(vol)) {
        virLibStorageVolError(NULL, VIR_ERR_INVALID_STORAGE_VOL, __FUNCTION__);
        return (NULL);
    }

    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->volGetPath)
        return conn->storageDriver->volGetPath (vol);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}




/* Not for public use.  Combines the elements of a virStringList
 * into a single string.
 */
char *virStringListJoin(const virStringList *list, const char *pre,
                        const char *post, const char *sep)
{
    size_t pre_len = strlen(pre);
    size_t sep_len = strlen(sep);
    size_t len = pre_len + strlen(post);
    const virStringList *p;
    char *retval;

    for (p = list; p; p = p->next)
        len += p->len + sep_len;
    if (VIR_ALLOC_N(retval, len+1) < 0)
        return NULL;
    strcpy(retval, pre);
    len = pre_len;
    for (p = list; p; p = p->next) {
        strcpy(retval + len, p->val);
        len += p->len;
        strcpy(retval + len, sep);
        len += sep_len;
    }
    strcpy(retval + len, post);

    return retval;
}


void virStringListFree(virStringList *list)
{
    while (list) {
        virStringList *p = list->next;
        VIR_FREE(list);
        list = p;
    }
}
