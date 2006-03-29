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

#include "libvirt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <xs.h>

#include "internal.h"
#include "driver.h"
#include "xen_internal.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "hash.h"
#include "xml.h"


/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to garantee coherent pointer state ?
 * - error reporting layer
 * - memory wrappers for malloc/free ?
 */

static virDriverPtr virDriverTab[MAX_DRIVERS];
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

    /*
     * should not be needed but...
     */
    for (i = 0;i < MAX_DRIVERS;i++) 
         virDriverTab[i] = NULL;

    /*
     * Note that the order is important the first ones have a higher priority
     */
    xenHypervisorRegister();
    xenDaemonRegister();
    xenStoreRegister();
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
    __virRaiseError(conn, NULL, VIR_FROM_NONE, error, VIR_ERR_ERROR,
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
    __virRaiseError(conn, domain, VIR_FROM_DOM, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info);
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
    int i;

    if (!initialized)
        virInitialize();

    if (driver == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
	return(-1);
    }
    for (i = 0;i < MAX_DRIVERS;i++) {
        if (virDriverTab[i] == driver)
	    return(i);
    }
    for (i = 0;i < MAX_DRIVERS;i++) {
        if (virDriverTab[i] == NULL) {
	    virDriverTab[i] = driver;
	    return(i);
	}
    }
    virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
    return(-1);
}

/**
 * virGetVersion:
 * @libVer: return value for the library version (OUT)
 * @type: hypervisor type
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
    if (!initialized)
        virInitialize();

    if (libVer == NULL)
        return (-1);
    *libVer = LIBVIR_VERSION_NUMBER;

    if (typeVer != NULL) {
        if ((type == NULL) || (!strcasecmp(type, "Xen"))) {
            if ((DOM0_INTERFACE_VERSION & 0xFFFF0000) == (0xAAAA0000)) {
                /* one time glitch hopefully ! */
                *typeVer = 2 * 1000000 +
                    ((DOM0_INTERFACE_VERSION >> 8) & 0xFF) * 1000 +
                    (DOM0_INTERFACE_VERSION & 0xFF);
            } else {
                *typeVer = (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
                    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
                    (DOM0_INTERFACE_VERSION & 0xFFFF);
            }
        } else {
            *typeVer = 0;
            virLibConnError(NULL, VIR_ERR_NO_SUPPORT, "type");
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
    int i, res;
    virConnectPtr ret = NULL;

    if (!initialized)
        virInitialize();

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL) {
        virLibConnError(NULL, VIR_ERR_NO_MEMORY, "Allocating connection");
        goto failed;
    }
    memset(ret, 0, sizeof(virConnect));
    ret->magic = VIR_CONNECT_MAGIC;
    ret->nb_drivers = 0;

    for (i = 0;i < MAX_DRIVERS;i++) {
        if ((virDriverTab[i] != NULL) && (virDriverTab[i]->open != NULL)) {
	    res = virDriverTab[i]->open(ret, name, 0);
	    /*
	     * For a default connect to Xen make sure we manage to contact
	     * all related drivers.
	     */
	    if ((res < 0) && (name == NULL) &&
	        (!strcmp(virDriverTab[i]->name, "Xen")))
		goto failed;
	    if (res == 0)
	        ret->drivers[ret->nb_drivers++] = virDriverTab[i];
	}
    }

    if (ret->nb_drivers == 0) {
	/* we failed to find an adequate driver */
	virLibConnError(NULL, VIR_ERR_NO_SUPPORT, name);
	goto failed;
    }

    ret->domains = virHashCreate(20);
    if (ret->domains == NULL)
        goto failed;
    ret->flags = 0;

    return (ret);

failed:
    if (ret != NULL) {
	for (i = 0;i < ret->nb_drivers;i++) {
	    if ((ret->drivers[i] != NULL) && (ret->drivers[i]->close != NULL))
	        ret->drivers[i]->close(ret);
	}
        free(ret);
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
        virInitialize();

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL) {
        virLibConnError(NULL, VIR_ERR_NO_MEMORY, "Allocating connection");
        goto failed;
    }
    memset(ret, 0, sizeof(virConnect));
    ret->magic = VIR_CONNECT_MAGIC;
    ret->nb_drivers = 0;

    for (i = 0;i < MAX_DRIVERS;i++) {
        if ((virDriverTab[i] != NULL) && (virDriverTab[i]->open != NULL)) {
	    res = virDriverTab[i]->open(ret, name,
	                                VIR_DRV_OPEN_QUIET | VIR_DRV_OPEN_RO);
	    if (res == 0)
	        ret->drivers[ret->nb_drivers++] = virDriverTab[i];
	}
    }
    if (ret->nb_drivers == 0) {
	if (name == NULL)
	    virLibConnError(NULL, VIR_ERR_NO_CONNECT,
			    "could not connect to Xen Daemon nor Xen Store");
	else
	    /* we failed to find an adequate driver */
	    virLibConnError(NULL, VIR_ERR_NO_SUPPORT, name);
	goto failed;
    }

    ret->domains = virHashCreate(20);
    if (ret->domains == NULL)
        goto failed;
    ret->flags = VIR_CONNECT_RO;

    return (ret);

failed:
    if (ret != NULL) {
	for (i = 0;i < ret->nb_drivers;i++) {
	    if ((ret->drivers[i] != NULL) && (ret->drivers[i]->close != NULL))
	        ret->drivers[i]->close(ret);
	}
        free(ret);
    }
    return (NULL);
}

/**
 * virDomainFreeName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virDomainFreeName(virDomainPtr domain, const char *name ATTRIBUTE_UNUSED)
{
    return (virDomainFree(domain));
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
    virHashFree(conn->domains, (virHashDeallocator) virDomainFreeName);
    conn->domains = NULL;
    for (i = 0;i < conn->nb_drivers;i++) {
	if ((conn->drivers[i] != NULL) && (conn->drivers[i]->close != NULL))
	    conn->drivers[i]->close(conn);
    }
    conn->magic = -1;
    free(conn);
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
    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    return ("Xen");
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
    unsigned long ver;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if (hvVer == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /* this can't be extracted from the Xenstore */
    if (conn->handle < 0) {
        *hvVer = 0;
        return (0);
    }

    ver = xenHypervisorGetVersion(conn, hvVer);
    return (0);
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
    unsigned int i;
    long id;
    char **idlist = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    if ((ids == NULL) || (maxids <= 0)) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    /*
     * try first though the Xen Daemon
     */
    idlist = xenDaemonListDomains(conn);
    if (idlist != NULL) {
        for (ret = 0, i = 0; (idlist[i] != NULL) && (ret < maxids); i++) {
            id = xenDaemonDomainLookupByName_ids(conn, idlist[i], NULL);
            if (id >= 0)
                ids[ret++] = (int) id;
        }
	free(idlist);
        return(ret);
    }

    /*
     * Then fallback to the XenStore
     */
    ret = xenStoreListDomains(conn, ids, maxids);
    return (ret);
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
    char **idlist = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (-1);
    }

    /* TODO: there must be a way to do that with an hypervisor call too ! */
    /* 
     * try first with Xend interface
     */
    idlist = xenDaemonListDomains(conn);
    if (idlist != NULL) {
        char **tmp = idlist;

        ret = 0;
        while (*tmp != NULL) {
            tmp++;
            ret++;
        }
	free(idlist);
	return(ret);
    }
    /* Then Xen Store */
    return(xenStoreNumOfDomains(conn));
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
virDomainCreateLinux(virConnectPtr conn,
                     const char *xmlDesc,
                     unsigned int flags ATTRIBUTE_UNUSED)
{
    int ret;
    char *sexpr;
    char *name = NULL;
    virDomainPtr dom;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    sexpr = virDomainParseXMLDesc(xmlDesc, &name);
    if ((sexpr == NULL) || (name == NULL)) {
        if (sexpr != NULL)
            free(sexpr);
        if (name != NULL)
            free(name);

        return (NULL);
    }

    ret = xenDaemonDomainCreateLinux(conn, sexpr);
    free(sexpr);
    if (ret != 0) {
        fprintf(stderr, "Failed to create domain %s\n", name);
        goto error;
    }

    ret = xend_wait_for_devices(conn, name);
    if (ret != 0) {
        fprintf(stderr, "Failed to get devices for domain %s\n", name);
        goto error;
    }

    dom = virDomainLookupByName(conn, name);
    if (dom == NULL) {
        goto error;
    }

    ret = xenDaemonDomainResume(dom);
    if (ret != 0) {
        fprintf(stderr, "Failed to resume new domain %s\n", name);
        xenDaemonDomainDestroy(dom);
        goto error;
    }

    dom = virDomainLookupByName(conn, name);
    free(name);

    return (dom);
  error:
    if (name != NULL)
        free(name);
    return (NULL);
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
    char *path = NULL;
    virDomainPtr ret;
    char *name = NULL;
    unsigned char uuid[16];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (id < 0) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* lookup is easier with the Xen store so try it first */
    if (conn->xshandle != NULL) {
        path = xs_get_domain_path(conn->xshandle, (unsigned int) id);
    }
    /* fallback to xend API then */
    if (path == NULL) {
        char **names = xenDaemonListDomains(conn);
        char **tmp = names;
        int ident;

        if (names != NULL) {
            while (*tmp != NULL) {
                ident = xenDaemonDomainLookupByName_ids(conn, *tmp, &uuid[0]);
                if (ident == id) {
                    name = strdup(*tmp);
                    break;
                }
                tmp++;
            }
            free(names);
        }
    }

    ret = (virDomainPtr) malloc(sizeof(virDomain));
    if (ret == NULL) {
        goto error;
    }
    memset(ret, 0, sizeof(virDomain));
    ret->magic = VIR_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->handle = id;
    ret->path = path;
    ret->name = name;
    memcpy(&ret->uuid[0], uuid, 16);
    if (ret->name == NULL) {
        goto error;
    }

    return (ret);
  error:
    if (ret != NULL)
        free(path);
    if (path != NULL)
        free(path);
    if (path != NULL)
        free(path);
    return (NULL);
}

/**
 * virDomainLookupByUUID:
 * @conn: pointer to the hypervisor connection
 * @uuid: the UUID string for the domain
 *
 * Try to lookup a domain on the given hypervisor based on its UUID.
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr ret;
    char *name = NULL;
    char **names;
    char **tmp;
    unsigned char ident[16];
    int id = -1;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (uuid == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    names = xenDaemonListDomains(conn);
    tmp = names;

    if (names == NULL) {
        TODO                    /* try to fallback to xenstore lookup */
            return (NULL);
    }
    while (*tmp != NULL) {
        id = xenDaemonDomainLookupByName_ids(conn, *tmp, &ident[0]);
        if (id >= 0) {
            if (!memcmp(uuid, ident, 16)) {
                name = strdup(*tmp);
                break;
            }
        }
        tmp++;
    }
    free(names);

    if (name == NULL)
        return (NULL);

    ret = (virDomainPtr) malloc(sizeof(virDomain));
    if (ret == NULL) {
        if (name != NULL)
            free(name);
        return (NULL);
    }
    memset(ret, 0, sizeof(virDomain));
    ret->magic = VIR_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->handle = id;
    ret->name = name;
    ret->path = 0;
    memcpy(ret->uuid, uuid, 16);

    return (ret);
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

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (name == NULL) {
        virLibConnError(conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    /* try first though Xend */
    ret = xenDaemonDomainLookupByName(conn, name);
    if (ret != NULL) {
        return(ret);
    }

    /* then though the XenStore */
    ret = xenStoreDomainLookupByName(conn, name);
    if (ret != NULL) {
        return(ret);
    }

    return (ret);
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
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    /*
     * try first with the xend method
     */
    ret = xenDaemonDomainDestroy(domain);
    if (ret == 0) {
        virDomainFree(domain);
        return (0);
    }

    ret = xenHypervisorDestroyDomain(domain);
    if (ret < 0)
        return (-1);

    virDomainFree(domain);
    return (0);
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
    domain->magic = -1;
    domain->handle = -1;
    if (domain->path != NULL)
        free(domain->path);
    if (domain->name)
        free(domain->name);
    free(domain);
    return (0);
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
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    /* first try though the Xen daemon */
    ret = xenDaemonDomainSuspend(domain);
    if (ret == 0)
        return (0);

    /* then try a direct hypervisor access */
    return (xenHypervisorPauseDomain(domain));
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
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    /* first try though the Xen daemon */
    ret = xenDaemonDomainResume(domain);
    if (ret == 0)
        return (0);

    /* then try a direct hypervisor access */
    return (xenHypervisorResumeDomain(domain));
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
    int ret;
    char filepath[4096];

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
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

    ret = xenDaemonDomainSave(domain, to);
    return (ret);
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
    int ret;
    char filepath[4096];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(conn, VIR_ERR_INVALID_CONN, __FUNCTION__);
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

    ret = xenDaemonDomainRestore(conn, from);
    return (ret);
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
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }

    /*
     * try first with the xend daemon
     */
    ret = xenDaemonDomainShutdown(domain);
    if (ret == 0) {
        domain->flags |= DOMAIN_IS_SHUTDOWN;
        return (0);
    }

    /*
     * this is very hackish, the domU kernel probes for a special 
     * node in the xenstore and launch the shutdown command if found.
     */
    ret = xenDaemonDomainShutdown(domain);
    if (ret == 0) {
        domain->flags |= DOMAIN_IS_SHUTDOWN;
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
 * @uuid: pointer to a 16 bytes array
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

    if (domain->handle == 0) {
        memset(uuid, 0, 16);
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
        memcpy(uuid, &domain->uuid[0], 16);
    }
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
    return (domain->handle);
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
    char *vm, *str = NULL;

    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }

    vm = virDomainGetVM(domain);
    if (vm) {
        str = virDomainGetVMInfo(domain, vm, "image/ostype");
        free(vm);
    }
    if (str == NULL)
        str = strdup("linux");

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

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (0);
    }

    /*
     * try first with the hypervisor if available
     */
    if (!(domain->conn->flags & VIR_CONNECT_RO)) {
        virDomainInfo dominfo;
        int tmp;

        tmp = xenHypervisorGetDomainInfo(domain, &dominfo);
        if (tmp >= 0)
	    return(dominfo.maxMem);
    }
    ret = xenStoreDomainGetMaxMemory(domain);
    if (ret > 0)
        return(ret);
    ret = xenDaemonDomainGetMaxMemory(domain);
    return (ret);
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
    int ret;
    char s[256], v[30];

    if (memory < 4096) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }
    if (domain == NULL) {
        TODO
	return (-1);
    }
    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO)
        return (-1);

    ret = xenDaemonDomainSetMaxMemory(domain, memory);
    if (ret == 0)
        return(0);

    ret = xenHypervisorSetMaxMemory(domain, memory);
    if (ret < 0)
        return (-1);

    if (domain->conn->xshandle != NULL) {
	/*
	 * try to update at the Xenstore level too
	 * Failing to do so should not be considered fatal though as long
	 * as the hypervisor call succeeded
	 */
	snprintf(s, 255, "/local/domain/%d/memory/target", domain->handle);
	s[255] = 0;
	snprintf(v, 29, "%lu", memory);
	v[30] = 0;

	if (!xs_write(domain->conn->xshandle, 0, &s[0], &v[0], strlen(v)))
	    ret = -1;
    }

    return (ret);
}

/**
 * virDomainGetInfo:
 * @domain: a domain object
 * @info: pointer to a virDomainInfo structure allocated by the user
 * 
 * Extract information about a domain. Note that if the connection
 * used to get the domain is limited only a partial set of the informations
 * can be extracted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    int ret;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (-1);
    }
    if (info == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    memset(info, 0, sizeof(virDomainInfo));

    /*
     * if we have direct access though the hypervisor do a direct call
     */
    if (domain->conn->handle >= 0) {
        ret = xenHypervisorGetDomainInfo(domain, info);
        if (ret == 0)
	    return (0);
    }

    /*
     * try to extract the informations though access to the Xen Daemon
     */
    if (xenDaemonDomainGetInfo(domain, info) == 0)
        return (0);

    /*
     * last fallback, try to get the informations from the Xen store
     */
    if (xenStoreGetDomainInfo(domain, info) == 0)
        return (0);

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
    if (!VIR_IS_DOMAIN(domain)) {
        virLibDomainError(domain, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        return (NULL);
    }
    if (flags != 0) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    return (xenDaemonDomainDumpXML(domain));
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
