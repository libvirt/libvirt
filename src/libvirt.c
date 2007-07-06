/*
 * libvirt.c: Main interfaces for the libvirt library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005,2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvirt/libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "driver.h"

#include "xml.h"
#include "test.h"
#include "xen_unified.h"
#include "remote_internal.h"
#include "qemu_driver.h"

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to garantee coherent pointer state ?
 */

static virDriverPtr virDriverTab[MAX_DRIVERS];
static int virDriverTabCount = 0;
static virNetworkDriverPtr virNetworkDriverTab[MAX_DRIVERS];
static int virNetworkDriverTabCount = 0;
static virStateDriverPtr virStateDriverTab[MAX_DRIVERS];
static int virStateDriverTabCount = 0;
static int initialized = 0;

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

    if (!bindtextdomain(GETTEXT_PACKAGE, LOCALEBASEDIR))
        return (-1);

    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virConnectOpen.
     */
#ifdef WITH_TEST
    if (testRegister() == -1) return -1;
#endif
#ifdef WITH_QEMU
    if (qemudRegister() == -1) return -1;
#endif
#ifdef WITH_XEN
    if (xenUnifiedRegister () == -1) return -1;
#endif
#ifdef WITH_REMOTE
    if (remoteRegister () == -1) return -1;
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
 * @error: the error noumber
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

    if (virInitialize() < 0)
        return -1;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->initialize() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateCleanup(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->cleanup() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateReload(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->reload() < 0)
            ret = -1;
    }
    return ret;
}

int __virStateActive(void) {
    int i, ret = 0;

    for (i = 0 ; i < virStateDriverTabCount ; i++) {
        if (virStateDriverTab[i]->active())
            ret = 1;
    }
    return ret;
}



/**
 * virGetVersion:
 * @libVer: return value for the library version (OUT)
 * @type: the type of connection/driver looked at
 * @typeVer: return value for the version of the hypervisor (OUT)
 *
 * Provides two information back, @libVer is the version of the library
 * while @typeVer will be the version of the hypervisor type @type against
 * which the library was compiled. If @type is NULL, "Xen" is assumed, if
 * @type is unknown or not availble, an error code will be returned and 
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
	        (!strcasecmp(virDriverTab[i]->name, type))) {
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
do_open (const char *name, int flags)
{
    int i, res;
    virConnectPtr ret = NULL;

    /* Convert NULL or "" to xen:/// for back compat */
    if (!name || name[0] == '\0')
        name = "xen:///";

    /* Convert xen -> xen:/// for back compat */
    if (!strcasecmp(name, "xen"))
        name = "xen:///";

    if (!initialized)
        if (virInitialize() < 0)
	    return NULL;

    ret = virGetConnect();
    if (ret == NULL) {
        virLibConnError(NULL, VIR_ERR_NO_MEMORY, _("allocating connection"));
        goto failed;
    }

    for (i = 0; i < virDriverTabCount; i++) {
        res = virDriverTab[i]->open (ret, name, flags);
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
        res = virNetworkDriverTab[i]->open (ret, name, flags);
        if (res == VIR_DRV_OPEN_ERROR) {
	    virLibConnWarning (NULL, VIR_WAR_NO_NETWORK, 
	                       "Is the daemon running ?");
            break;
        } else if (res == VIR_DRV_OPEN_SUCCESS) {
            ret->networkDriver = virNetworkDriverTab[i];
            break;
        }
    }

    if (flags & VIR_DRV_OPEN_RO) {
        ret->flags = VIR_CONNECT_RO;
    }

    return ret;

failed:
    if (ret->driver) ret->driver->close (ret);
	virFreeConnect(ret);
    return (NULL);
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
    return do_open (name, 0);
}

/**
 * virConnectOpenReadOnly:
 * @name: URI of the hypervisor
 *
 * This function should be called first to get a restricted connection to the 
 * libbrary functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 *
 * URIs are documented at http://libvirt.org/uri.html
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    return do_open (name, VIR_DRV_OPEN_RO);
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
    if (!VIR_IS_CONNECT(conn))
        return (-1);

    if (conn->networkDriver)
        conn->networkDriver->close (conn);
    conn->driver->close (conn);

    if (virFreeConnect(conn) < 0)
        return (-1);
    return (0);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * hypervisor call, i.e. with priviledged access to the hypervisor, not
 * with a Read-Only connection.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
int
virConnectGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getURI)
        return conn->driver->getURI (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virDomainGetConnect (virDomainPtr dom)
{
    if (!VIR_IS_DOMAIN (dom)) {
        virLibDomainError (dom, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    return dom->conn;
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @xmlDesc: an XML description of the domain
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain, based on an XML description similar
 * to the one returned by virDomainGetXMLDesc()
 * This function may requires priviledged access to the hypervisor.
 * 
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                     unsigned int flags)
{
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 *
 * Returns a new domain object or NULL in case of failure.  If the
 * domain cannot be found, then VIR_ERR_NO_DOMAIN error is raised.
 */
virDomainPtr
virDomainLookupByID(virConnectPtr conn, int id)
{
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * already and all resources used by it are given back to the hypervisor.
 * The data structure is freed and should not be used thereafter if the
 * call does not return an error.
 * This function may requires priviledged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (virFreeDomain(domain->conn, domain) < 0)
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
 * This function may requires priviledged access.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * This function may requires priviledged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (uuid == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (domain->id == 0) {
        memset(uuid, 0, VIR_UUID_BUFLEN);
    } else {
#if 0
        /* Probably legacy code: It appears that we always fill in
         * the UUID when creating the virDomain structure, so this
         * shouldn't be necessary.
         */
        if ((domain->uuid[0] == 0) && (domain->uuid[1] == 0) &&
            (domain->uuid[2] == 0) && (domain->uuid[3] == 0) &&
            (domain->uuid[4] == 0) && (domain->uuid[5] == 0) &&
            (domain->uuid[6] == 0) && (domain->uuid[7] == 0) &&
            (domain->uuid[8] == 0) && (domain->uuid[9] == 0) &&
            (domain->uuid[10] == 0) && (domain->uuid[11] == 0) &&
            (domain->uuid[12] == 0) && (domain->uuid[13] == 0) &&
            (domain->uuid[14] == 0) && (domain->uuid[15] == 0))
            xenDaemonDomainLookupByName_ids(domain->conn, domain->name,
                                &domain->uuid[0]);
#endif
        memcpy(uuid, &domain->uuid[0], VIR_UUID_BUFLEN);
    }
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    
    if (virDomainGetUUID(domain, &uuid[0]))
        return (-1);

    snprintf(buf, VIR_UUID_STRING_BUFLEN,
	"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      uuid[0], uuid[1], uuid[2], uuid[3],
                      uuid[4], uuid[5], uuid[6], uuid[7],
                      uuid[8], uuid[9], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);
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
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * This function requires priviledged access to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * This function may requires priviledged access to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMemory(virDomainPtr domain, unsigned long memory)
{
    virConnectPtr conn;

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * @flags: and OR'ed set of extraction flags, not used yet
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    conn = domain->conn;

    if (conn->driver->domainDumpXML)
        return conn->driver->domainDumpXML (domain, flags);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * Returns NULL in case of error, or a pointer to an opaque
 * virCapabilities structure (virCapabilitiesPtr).
 * The client must free the returned string after use.
 */
char *
virConnectGetCapabilities (virConnectPtr conn)
{
    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

    if (conn->driver->getCapabilities)
        return conn->driver->getCapabilities (conn);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return NULL;
    }
    conn = domain->conn;

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return NULL;
    }

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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return -1;
    }
    conn = domain->conn;

    if (!VIR_IS_CONNECT (conn)) {
        virLibConnError (conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (conn->driver->domainSetSchedulerParameters)
        return conn->driver->domainSetSchedulerParameters (domain, params, nparams);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
 * define a domain, but does not start it
 *
 * Returns NULL in case of error, a pointer to the domain otherwise
 */
virDomainPtr
virDomainDefineXML(virConnectPtr conn, const char *xml) {
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * undefine a domain but does not stop it if it is running
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
virDomainUndefine(virDomainPtr domain) {
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * Provides the number of inactive domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDefinedDomains(virConnectPtr conn)
{
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
 * list the defined domains, stores the pointers to the names in @names
 * 
 * Returns the number of names provided in the array or -1 in case of error
 */
int
virConnectListDefinedDomains(virConnectPtr conn, char **const names,
                             int maxnames) {
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * This function requires priviledged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
virDomainSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    virConnectPtr conn;

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * This function requires priviledged access to the hypervisor.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */
int
virDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                 unsigned char *cpumap, int maplen)
{
    virConnectPtr conn;

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 *	If cpumaps is NULL, then no cupmap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in
 *      virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 * 
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer is'nt NULL.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
virDomainGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
		  unsigned char *cpumaps, int maplen)
{
    virConnectPtr conn;

    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
virDomainAttachDevice(virDomainPtr domain, char *xml)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
virDomainDetachDevice(virDomainPtr domain, char *xml)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
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
 * virNetworkGetConnect:
 * @net: pointer to a network
 *
 * Provides the connection pointer associated with a network.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 */
virConnectPtr
virNetworkGetConnect (virNetworkPtr net)
{
    if (!VIR_IS_NETWORK (net)) {
        virLibNetworkError (net, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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
    if (network == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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
 * already and all resources used by it are given back to the hypervisor.
 * The data structure is freed and should not be used thereafter if the
 * call does not return an error.
 * This function may requires priviledged access
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virNetworkDestroy(virNetworkPtr network)
{
    virConnectPtr conn;

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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
    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (virFreeNetwork(network->conn, network) < 0)
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
    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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
    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }
    if (buf == NULL) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    if (virNetworkGetUUID(network, &uuid[0]))
	return (-1);

    snprintf(buf, VIR_UUID_STRING_BUFLEN,
	"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      uuid[0], uuid[1], uuid[2], uuid[3],
                      uuid[4], uuid[5], uuid[6], uuid[7],
                      uuid[8], uuid[9], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
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

    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (-1);
    }

    conn = network->conn;

    if (conn->networkDriver && conn->networkDriver->networkSetAutostart)
        return conn->networkDriver->networkSetAutostart (network, autostart);

    virLibConnError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
