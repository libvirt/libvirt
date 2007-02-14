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

#include <xs.h>

#include "internal.h"
#include "driver.h"
#include "xen_internal.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xm_internal.h"
#include "proxy_internal.h"
#include "xml.h"
#include "test.h"
#include "qemu_internal.h"

/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to garantee coherent pointer state ?
 * - memory wrappers for malloc/free ?
 */

static virDriverPtr virDriverTab[MAX_DRIVERS];
static virNetworkDriverPtr virNetworkDriverTab[MAX_DRIVERS];
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
    int i;

    if (initialized)
        return(0);
    initialized = 1;

    if (!bindtextdomain(GETTEXT_PACKAGE, LOCALEBASEDIR))
        return (-1);

    /*
     * should not be needed but...
     */
    for (i = 0;i < MAX_DRIVERS;i++) {
         virDriverTab[i] = NULL;
         virNetworkDriverTab[i] = NULL;
    }

    /*
     * Note that the order is important the first ones have a higher priority
     */
    xenHypervisorRegister();
    xenProxyRegister();
    xenDaemonRegister();
    xenStoreRegister();
    xenXMRegister();
    testRegister();
    qemuRegister();

    return(0);
}



/**
 * virLibConnError:
 * @conn: the connection if available
 * @error: the error noumber
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
 * virLibConnError:
 * @conn: the connection if available
 * @error: the error noumber
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

static int
_virRegisterDriver(void *driver, int isNetwork)
{
    void **drivers;
    int i;

    if (!initialized)
        if (virInitialize() < 0)
	    return -1;

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(-1);
    }
    drivers = isNetwork ? (void **) virNetworkDriverTab : (void **) virDriverTab;
    for (i = 0;i < MAX_DRIVERS;i++) {
        if (drivers[i] == driver)
	    return(i);
    }
    for (i = 0;i < MAX_DRIVERS;i++) {
        if (drivers[i] == NULL) {
	    drivers[i] = driver;
	    return(i);
	}
    }
    virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
    return(-1);
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
    return _virRegisterDriver(driver, 1);
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
    return _virRegisterDriver(driver, 0);
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
	for (i = 0;i < MAX_DRIVERS;i++) {
	    if ((virDriverTab[i] != NULL) &&
	        (!strcmp(virDriverTab[i]->name, type))) {
		*typeVer = virDriverTab[i]->ver;
		break;
	    }
	}
        if (i >= MAX_DRIVERS) {
            *typeVer = 0;
            virLibConnError(NULL, VIR_ERR_NO_SUPPORT, type);
            return (-1);
        }
    }
    return (0);
}

/**
 * virConnectOpen:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a connection to the 
 * Hypervisor and xen store
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpen(const char *name)
{
    int i, res, for_xen = 0;
    virConnectPtr ret = NULL;

    if (!initialized)
        if (virInitialize() < 0)
	    return NULL;

    if (name == NULL) {
        name = "Xen";
	for_xen = 1;
    } else if (!strncasecmp(name, "xen", 3)) {
	for_xen = 1;
    }

    ret = virGetConnect();
    if (ret == NULL) {
        virLibConnError(NULL, VIR_ERR_NO_MEMORY, _("allocating connection"));
        goto failed;
    }

    for (i = 0;i < MAX_DRIVERS;i++) {
        if ((virDriverTab[i] != NULL) && (virDriverTab[i]->open != NULL)) {
	    res = virDriverTab[i]->open(ret, name, VIR_DRV_OPEN_QUIET);
	    /*
	     * For a default connect to Xen make sure we manage to contact
	     * all related drivers.
	     */
	    if ((res < 0) && (for_xen) &&
	        (!strncasecmp(virDriverTab[i]->name, "xen", 3)) &&
		(virDriverTab[i]->no != VIR_DRV_XEN_PROXY))
		goto failed;
	    if (res == 0)
	        ret->drivers[ret->nb_drivers++] = virDriverTab[i];
	}
    }

    for (i = 0;i < MAX_DRIVERS;i++) {
        if ((virNetworkDriverTab[i] != NULL) && (virNetworkDriverTab[i]->open != NULL) &&
	    (res = virNetworkDriverTab[i]->open(ret, name, VIR_DRV_OPEN_QUIET)) == 0) {
            ret->networkDrivers[ret->nb_network_drivers++] = virNetworkDriverTab[i];
        }
    }

    if (ret->nb_drivers == 0 || ret->nb_network_drivers == 0) {
	/* we failed to find an adequate driver */
	virLibConnError(NULL, VIR_ERR_NO_SUPPORT, name);
	goto failed;
    }

    return (ret);

failed:
    if (ret != NULL) {
	for (i = 0;i < ret->nb_drivers;i++) {
	    if ((ret->drivers[i] != NULL) && (ret->drivers[i]->close != NULL))
	        ret->drivers[i]->close(ret);
	}
	for (i = 0;i < ret->nb_network_drivers;i++) {
	    if ((ret->networkDrivers[i] != NULL) && (ret->networkDrivers[i]->close != NULL))
	        ret->networkDrivers[i]->close(ret);
	}
	virFreeConnect(ret);
    }
    return (NULL);
}

/**
 * virConnectOpenReadOnly:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a restricted connection to the 
 * libbrary functionalities. The set of APIs usable are then restricted
 * on the available methods to control the domains.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpenReadOnly(const char *name)
{
    int i, res;
    virConnectPtr ret = NULL;

    if (!initialized)
        if (virInitialize() < 0)
	    return NULL;

    if (name == NULL)
        name = "Xen";

    ret = virGetConnect();
    if (ret == NULL) {
        virLibConnError(NULL, VIR_ERR_NO_MEMORY, _("allocating connection"));
        goto failed;
    }

    for (i = 0;i < MAX_DRIVERS;i++) {
        if ((virDriverTab[i] != NULL) && (virDriverTab[i]->open != NULL)) {
	    res = virDriverTab[i]->open(ret, name,
	                                VIR_DRV_OPEN_QUIET | VIR_DRV_OPEN_RO);
	    if (res == 0)
	        ret->drivers[ret->nb_drivers++] = virDriverTab[i];

	}
        if ((virNetworkDriverTab[i] != NULL) && (virNetworkDriverTab[i]->open != NULL) &&
	    (res = virNetworkDriverTab[i]->open(ret, name, VIR_DRV_OPEN_QUIET)) == 0) {
            ret->networkDrivers[ret->nb_network_drivers++] = virNetworkDriverTab[i];
        }
    }
    if (ret->nb_drivers == 0) {
	if (name == NULL)
	    virLibConnError(NULL, VIR_ERR_NO_CONNECT,
			    _("Xen Daemon or Xen Store"));
	else
	    /* we failed to find an adequate driver */
	    virLibConnError(NULL, VIR_ERR_NO_SUPPORT, name);
	goto failed;
    }
    ret->flags = VIR_CONNECT_RO;

    return (ret);

failed:
    if (ret != NULL) {
	for (i = 0;i < ret->nb_drivers;i++) {
	    if ((ret->drivers[i] != NULL) && (ret->drivers[i]->close != NULL))
	        ret->drivers[i]->close(ret);
	}
	for (i = 0;i < ret->nb_network_drivers;i++) {
	    if ((ret->networkDrivers[i] != NULL) && (ret->networkDrivers[i]->close != NULL))
	        ret->networkDrivers[i]->close(ret);
	}
	virFreeConnect(ret);
    }
    return (NULL);
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
    int i;

    if (!VIR_IS_CONNECT(conn))
        return (-1);
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) && (conn->drivers[i]->close != NULL))
	    conn->drivers[i]->close(conn);
    }
    for (i = 0;i < conn->nb_network_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) && (conn->networkDrivers[i]->close != NULL))
	    conn->networkDrivers[i]->close(conn);
    }
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
 */
const char *
virConnectGetType(virConnectPtr conn)
{
    int i;
    const char *ret;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->type != NULL)) {
	    ret = conn->drivers[i]->type(conn);
	    if (ret != NULL)
	        return(ret);
	}
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->name != NULL)) {
	    return(conn->drivers[i]->name);
	}
    }
    return(NULL);
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
    int ret, i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (hvVer == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->version != NULL)) {
	    ret = conn->drivers[i]->version(conn, hvVer);
	    if (ret == 0)
	        return(0);
	}
    }

    return (-1);
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
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((ids == NULL) || (maxids <= 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->listDomains != NULL)) {
	    ret = conn->drivers[i]->listDomains(conn, ids, maxids);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return (-1);
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
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->numOfDomains != NULL)) {
	    ret = conn->drivers[i]->numOfDomains(conn);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
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
    virDomainPtr ret;
    int i;

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

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainCreateLinux != NULL)) {
	    ret = conn->drivers[i]->domainCreateLinux(conn, xmlDesc, flags);
	    if (ret != NULL)
	        return(ret);
	}
    }
    return(NULL);
}


/**
 * virDomainLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByID(virConnectPtr conn, int id)
{
    virDomainPtr ret;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainLookupByID != NULL)) {
	    ret = conn->drivers[i]->domainLookupByID(conn, id);
	    if (ret)
	        return(ret);
	}
    }

    return (NULL);
}

/**
 * virDomainLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr ret;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainLookupByUUID != NULL)) {
	    ret = conn->drivers[i]->domainLookupByUUID(conn, uuid);
	    if (ret)
	        return(ret);
	}
    }

    return (NULL);
}

/**
 * virDomainLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure
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
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByName(virConnectPtr conn, const char *name)
{
    virDomainPtr ret = NULL;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainLookupByName != NULL)) {
	    ret = conn->drivers[i]->domainLookupByName(conn, name);
	    if (ret)
	        return(ret);
	}
    }
    return (NULL);
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
    int i;
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

    /*
     * Go though the driver registered entry points but use the 
     * XEN_HYPERVISOR directly only as a last mechanism
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no != VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainDestroy != NULL)) {
	    if (conn->drivers[i]->domainDestroy(domain) == 0)
	        return (0);
	}
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no == VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainDestroy != NULL)) {
	    if (conn->drivers[i]->domainDestroy(domain) == 0)
	        return (0);
	}
    }

        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int i;
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

    /*
     * Go though the driver registered entry points but use the 
     * XEN_HYPERVISOR directly only as a last mechanism
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no != VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainSuspend != NULL)) {
	    if (conn->drivers[i]->domainSuspend(domain) == 0)
	        return (0);
	}
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no == VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainSuspend != NULL)) {
	    if (conn->drivers[i]->domainSuspend(domain) == 0)
	        return (0);
	}
    }

        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int i;
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

    /*
     * Go though the driver registered entry points but use the 
     * XEN_HYPERVISOR directly only as a last mechanism
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no != VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainResume != NULL)) {
	    if (conn->drivers[i]->domainResume(domain) == 0)
	        return(0);
	}
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no == VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainResume != NULL)) {
	    if (conn->drivers[i]->domainResume(domain) == 0)
	        return(0);
	}
    }

    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainSave != NULL)) {
	    ret = conn->drivers[i]->domainSave(domain, to);
	    if (ret == 0)
	        return(0);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainSave != NULL)) {
	    ret = conn->drivers[i]->domainRestore(conn, from);
	    if (ret == 0)
	        return(0);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainCoreDump != NULL)) {
	    ret = conn->drivers[i]->domainCoreDump(domain, to, flags);
	    if (ret == 0)
	        return(0);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret = -1, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainShutdown != NULL)) {
	    if (conn->drivers[i]->domainShutdown(domain) == 0)
	        ret = 0;
	}
    }

    if (ret != 0) {
        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (ret);
    }

    return (ret);
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
    int ret = -1, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainReboot != NULL)) {
	    if (conn->drivers[i]->domainReboot(domain, flags) == 0)
	        ret = 0;
	}
    }

    if (ret != 0) {
        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (ret);
    }

    return (ret);
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
    char *str = NULL;
    int i;

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    for (i = 0;i < domain->conn->nb_drivers;i++) {
	if ((domain->conn->drivers[i] != NULL) &&
	    (domain->conn->drivers[i]->domainGetOSType != NULL)) {
	    str = domain->conn->drivers[i]->domainGetOSType(domain);
	    if (str != NULL)
	        break;
	}
    }

    return (str);
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
    unsigned long ret = 0;
    virConnectPtr conn;
    int i;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }

    conn = domain->conn;

    /*
     * in that case instead of trying only though one method try all availble.
     * If needed that can be changed back if it's a performcance problem.
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainGetMaxMemory != NULL)) {
	    ret = conn->drivers[i]->domainGetMaxMemory(domain);
	    if (ret != 0)
	        return(ret);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret = -1 , i;
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

    /*
     * in that case instead of trying only though one method try all availble.
     * If needed that can be changed back if it's a performcance problem.
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainSetMaxMemory != NULL)) {
	    if (conn->drivers[i]->domainSetMaxMemory(domain, memory) == 0)
	        ret = 0;
	}
    }
    if (ret != 0) {
        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (-1);
    }
    return (ret);
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
    int ret = -1 , i;
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

    /*
     * in that case instead of trying only though one method try all availble.
     * If needed that can be changed back if it's a performcance problem.
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainSetMemory != NULL)) {
	    if (conn->drivers[i]->domainSetMemory(domain, memory) == 0)
	        ret = 0;
	}
    }
    if (ret != 0) {
        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (-1);
    }
    return (ret);
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
    int i;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memset(info, 0, sizeof(virDomainInfo));

    for (i = 0;i < domain->conn->nb_drivers;i++) {
	if ((domain->conn->drivers[i] != NULL) &&
	    (domain->conn->drivers[i]->domainGetInfo != NULL)) {
	    if (domain->conn->drivers[i]->domainGetInfo(domain, info) == 0)
	        return 0;
	}
    }

    return (-1);
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
    int i;
    char *ret = NULL;
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    for (i = 0;i < domain->conn->nb_drivers;i++) {
	if ((domain->conn->drivers[i] != NULL) &&
	    (domain->conn->drivers[i]->domainDumpXML != NULL)) {
            ret = domain->conn->drivers[i]->domainDumpXML(domain, flags);
	    if (ret)
	        break;
	}
    }
    if (!ret) {
        virLibConnError(domain->conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (NULL);
    }
    return(ret);
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
virNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info) {
    int i;
    int ret = -1;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->nodeGetInfo != NULL)) {
	    ret = conn->drivers[i]->nodeGetInfo(conn, info);
	    if (ret == 0)
	        break;
	}
    }
    if (ret != 0) {
        virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (-1);
    }
    return(0);
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
    virDomainPtr ret = NULL;
    int i;

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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainDefineXML != NULL)) {
            ret = conn->drivers[i]->domainDefineXML(conn, xml);
	    if (ret)
	        return(ret);
	}
    }

    return(ret);
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
    int ret, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainUndefine != NULL)) {
	    ret = conn->drivers[i]->domainUndefine(domain);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
}

/**
 * virConnectNumOfDefinedDomains:
 * @conn: pointer to the hypervisor connection
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
virConnectNumOfDefinedDomains(virConnectPtr conn)
{
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->numOfDefinedDomains != NULL)) {
	    ret = conn->drivers[i]->numOfDefinedDomains(conn);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
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
virConnectListDefinedDomains(virConnectPtr conn, const char **names,
                             int maxnames) {
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames <= 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->listDefinedDomains != NULL)) {
	    ret = conn->drivers[i]->listDefinedDomains(conn, names, maxnames);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return (-1);
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
    int i, ret = -1;
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

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainCreate != NULL)) {
	    ret = conn->drivers[i]->domainCreate(domain);
	    if (ret == 0)
	        return(ret);
	}
    }
    return(ret);
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
    int i;
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

    /*
     * Go though the driver registered entry points but use the 
     * XEN_HYPERVISOR directly only as a last mechanism
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no != VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainSetVcpus != NULL)) {
	    if (conn->drivers[i]->domainSetVcpus(domain, nvcpus) == 0)
	        return(0);
	}
    }
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->no == VIR_DRV_XEN_HYPERVISOR) &&
	    (conn->drivers[i]->domainSetVcpus != NULL)) {
	    if (conn->drivers[i]->domainSetVcpus(domain, nvcpus) == 0)
	        return(0);
	}
    }

    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int i;
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

    /*
     * Go though the driver registered entry points
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainPinVcpu != NULL)) {
	    if (conn->drivers[i]->domainPinVcpu(domain, vcpu,
	                                        cpumap, maplen) == 0)
	        return(0);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret;
    int i;
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

    /*
     * Go though the driver registered entry points
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainGetVcpus != NULL)) {
	    ret = conn->drivers[i]->domainGetVcpus(domain, info, maxinfo,
	                                           cpumaps, maplen);
	    if (ret >= 0)
	        return(ret);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret;
    int i;
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

    /*
     * Go though the driver registered entry points
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainAttachDevice != NULL)) {
	    ret = conn->drivers[i]->domainAttachDevice(domain, xml);
	    if (ret >= 0)
	        return(ret);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret;
    int i;
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

    /*
     * Go though the driver registered entry points
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) &&
	    (conn->drivers[i]->domainDetachDevice != NULL)) {
	    ret = conn->drivers[i]->domainDetachDevice(domain, xml);
	    if (ret >= 0)
	        return(ret);
	}
    }
    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_network_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->numOfNetworks != NULL)) {
	    ret = conn->networkDrivers[i]->numOfNetworks(conn);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
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
virConnectListNetworks(virConnectPtr conn, const char **names, int maxnames)
{
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames <= 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->listNetworks != NULL)) {
	    ret = conn->networkDrivers[i]->listNetworks(conn, names, maxnames);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return (-1);
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
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->numOfDefinedNetworks != NULL)) {
	    ret = conn->networkDrivers[i]->numOfDefinedNetworks(conn);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
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
virConnectListDefinedNetworks(virConnectPtr conn, const char **names,
                              int maxnames) {
    int ret = -1;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((names == NULL) || (maxnames <= 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->listDefinedNetworks != NULL)) {
	    ret = conn->networkDrivers[i]->listDefinedNetworks(conn, names, maxnames);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return (-1);
}

/**
 * virNetworkLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the network
 *
 * Try to lookup a network on the given hypervisor based on its name.
 *
 * Returns a new network object or NULL in case of failure
 */
virNetworkPtr
virNetworkLookupByName(virConnectPtr conn, const char *name)
{
    virNetworkPtr ret = NULL;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkLookupByName != NULL)) {
	    ret = conn->networkDrivers[i]->networkLookupByName(conn, name);
	    if (ret)
	        return(ret);
	}
    }
    return (NULL);
}

/**
 * virNetworkLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the raw UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * Returns a new network object or NULL in case of failure
 */
virNetworkPtr
virNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virNetworkPtr ret;
    int i;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkLookupByUUID != NULL)) {
	    ret = conn->networkDrivers[i]->networkLookupByUUID(conn, uuid);
	    if (ret)
	        return(ret);
	}
    }

    return (NULL);
}

/**
 * virNetworkLookupByUUIDString:
 * @conn: pointer to the hypervisor connection
 * @uuidstr: the string UUID for the network
 *
 * Try to lookup a network on the given hypervisor based on its UUID.
 *
 * Returns a new network object or NULL in case of failure
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
    virNetworkPtr ret;
    int i;

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

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkCreateXML != NULL)) {
	    ret = conn->networkDrivers[i]->networkCreateXML(conn, xmlDesc);
	    if (ret != NULL)
	        return(ret);
	}
    }
    return(NULL);
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
virNetworkDefineXML(virConnectPtr conn, const char *xml) {
    virNetworkPtr ret = NULL;
    int i;

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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkDefineXML != NULL)) {
            ret = conn->networkDrivers[i]->networkDefineXML(conn, xml);
	    if (ret)
	        return(ret);
	}
    }

    return(ret);
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
    int ret, i;
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

    /* Go though the driver registered entry points */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkUndefine != NULL)) {
	    ret = conn->networkDrivers[i]->networkUndefine(network);
	    if (ret >= 0)
	        return(ret);
	}
    }

    return(-1);
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
virNetworkCreate(virNetworkPtr network) {
    int i, ret = -1;
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

    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkCreate != NULL)) {
	    ret = conn->networkDrivers[i]->networkCreate(network);
	    if (ret == 0)
	        return(ret);
	}
    }
    return(ret);
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
    int i;
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

    /*
     * Go though the driver registered entry points
     */
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->networkDrivers[i] != NULL) &&
	    (conn->networkDrivers[i]->networkDestroy != NULL)) {
	    if (conn->networkDrivers[i]->networkDestroy(network) == 0)
	        return (0);
	}
    }

    virLibConnError(conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
    return (-1);
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
    int i;
    char *ret = NULL;
    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibNetworkError(network, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    for (i = 0;i < network->conn->nb_network_drivers;i++) {
	if ((network->conn->networkDrivers[i] != NULL) &&
	    (network->conn->networkDrivers[i]->networkDumpXML != NULL)) {
            ret = network->conn->networkDrivers[i]->networkDumpXML(network, flags);
	    if (ret)
	        break;
	}
    }
    if (!ret) {
        virLibConnError(network->conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (NULL);
    }
    return(ret);
}

/**
 * virNetworkGetBridgeName:
 * @network: a network object
 *
 * Return a bridge interface name to which a domain may connect
 * a network interface in order to join the network.
 *
 * Returns a 0 terminated interface name, or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
virNetworkGetBridgeName(virNetworkPtr network)
{
    int i;
    char *ret = NULL;
    if (!VIR_IS_NETWORK(network)) {
        virLibNetworkError(network, VIR_ERR_INVALID_NETWORK, __FUNCTION__);
        return (NULL);
    }

    for (i = 0;i < network->conn->nb_network_drivers;i++) {
	if ((network->conn->networkDrivers[i] != NULL) &&
	    (network->conn->networkDrivers[i]->networkGetBridgeName != NULL)) {
            ret = network->conn->networkDrivers[i]->networkGetBridgeName(network);
	    if (ret)
	        break;
	}
    }
    if (!ret) {
        virLibConnError(network->conn, VIR_ERR_CALL_FAILED, __FUNCTION__);
        return (NULL);
    }
    return(ret);
}
