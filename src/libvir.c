/*
 * libvir.c: Main interfaces for the libvir library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvir.h"
#include "xen_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xs.h>
#include "internal.h"
#include "hash.h"


/*
 * TODO:
 * - use lock to protect against concurrent accesses ?
 * - use reference counting to garantee coherent pointer state ?
 * - error reporting layer
 * - memory wrappers for malloc/free ?
 */

#define VIR_CONNECT_MAGIC 0x4F23DEAD

/*
 * Flags for Xen connections
 */
#define VIR_CONNECT_RO 1

/**
 * _virConnect:
 *
 * Internal structure associated to a connection
 */
struct _virConnect {
    unsigned int magic;		/* specific value to check */
    int	         handle;	/* internal handle used for hypercall */
    struct xs_handle *xshandle;	/* handle to talk to the xenstore */
    virHashTablePtr   domains;	/* hash table for known domains */
    int          flags;		/* a set of connection flags */
};

#define VIR_DOMAIN_MAGIC 0xDEAD4321

/**
 * _virDomain:
 *
 * Internal structure associated to a domain
 */
struct _virDomain {
    unsigned int magic;		/* specific value to check */
    virConnectPtr conn;		/* pointer back to the connection */
    char        *name;		/* the domain external name */
    char        *path;		/* the domain internal path */
    int	         handle;	/* internal handle for the dmonain ID */
};

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
virGetVersion(unsigned long *libVer, const char *type, unsigned long *typeVer) {
    if (libVer == NULL)
        return(-1);
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
	    return(-1);
	}
    }
    return(0);
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
virConnectOpen(const char *name) {
    virConnectPtr ret = NULL;
    int handle = -1;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    handle = xenHypervisorOpen();
    if (handle == -1)
        goto failed;
    xshandle = xs_daemon_open();
    if (xshandle == NULL)
        goto failed;

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = VIR_CONNECT_MAGIC;
    ret->handle = handle;
    ret->xshandle = xshandle;
    ret->domains = virHashCreate(20);
    ret->flags = 0;
    if (ret->domains == NULL)
        goto failed;

    return(ret);
failed:
    if (handle >= 0)
        xenHypervisorClose(handle);
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    if (ret != NULL)
        free(ret);
    return(NULL);
}

/**
 * virConnectOpenReadOnly:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a read-only connection to the 
 * xen store. The set of APIs usable are then restricted.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
virConnectPtr
virConnectOpenReadOnly(const char *name) {
    virConnectPtr ret = NULL;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    xshandle = xs_daemon_open_readonly();
    if (xshandle == NULL)
        goto failed;

    ret = (virConnectPtr) malloc(sizeof(virConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = VIR_CONNECT_MAGIC;
    ret->handle = -1;
    ret->xshandle = xshandle;
    ret->domains = virHashCreate(20);
    ret->flags = VIR_CONNECT_RO;
    if (ret->domains == NULL)
        goto failed;

    return(ret);
failed:
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    if (ret != NULL)
        free(ret);
    return(NULL);
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
virDomainFreeName(virDomainPtr domain, const char *name ATTRIBUTE_UNUSED) {
    return(virDomainFree(domain));
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
virConnectClose(virConnectPtr conn) {
    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC))
        return(-1);

    virHashFree(conn->domains, (virHashDeallocator) virDomainFreeName);
    conn->magic = -1;
    xs_daemon_close(conn->xshandle);
    conn->xshandle = NULL;
    if (conn->handle != -1)
	xenHypervisorClose(conn->handle);
    conn->handle = -1;
    free(conn);
    return(0);
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
virConnectGetType(virConnectPtr conn) {
    if (conn == NULL)
        return(NULL);
    
    return("Xen");
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
virConnectGetVersion(virConnectPtr conn, unsigned long *hvVer) {
    unsigned long ver;

    if ((conn == NULL) || (hvVer == NULL) || (conn->magic != VIR_CONNECT_MAGIC))
        return(-1);
    
    /* this can't be extracted from the Xenstore */
    if (conn->handle < 0) {
        *hvVer = 0;
        return(0);
    }

    ver = xenHypervisorGetVersion(conn->handle);
    *hvVer = (ver >> 16) * 1000000 + (ver & 0xFFFF) * 1000;
    return(0);
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
virConnectListDomains(virConnectPtr conn, int *ids, int maxids) {
    struct xs_transaction_handle* t;
    int ret = -1;
    unsigned int num, i;
    long id;
    char **idlist = NULL, *endptr;

    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC) ||
        (ids == NULL) || (maxids <= 0))
        return(-1);
    
    t = xs_transaction_start(conn->xshandle);
    if (t == NULL)
        goto done;

    idlist = xs_directory(conn->xshandle, t, "/local/domain", &num);
    if (idlist == NULL)
        goto done;

    for (ret = 0,i = 0;(i < num) && (ret < maxids);i++) {
        id = strtol(idlist[i], &endptr, 10);
	if ((endptr == idlist[i]) || (*endptr != 0)) {
	    ret = -1;
	    goto done;
	}
	ids[ret++] = (int) id;
    }

done:
    if (t != NULL)
	xs_transaction_end(conn->xshandle, t, 0);
    if (idlist != NULL)
        free(idlist);

    return(ret);
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
virConnectNumOfDomains(virConnectPtr conn) {
    struct xs_transaction_handle* t;
    int ret = -1;
    unsigned int num;
    char **idlist = NULL;

    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC))
        return(-1);
    
    t = xs_transaction_start(conn->xshandle);
    if (t) {
        idlist = xs_directory(conn->xshandle, t, "/local/domain", &num);
        if (idlist) {
            free(idlist);
	    ret = num;
        }
        xs_transaction_end(conn->xshandle, t, 0);
    }
    return(ret);
}

/**
 * virDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @kernel_path: the file path to the kernel image
 * @initrd_path: an optional file path to an initrd
 * @cmdline: optional command line parameters for the kernel
 * @memory: the memory size in kilobytes
 * @flags: an optional set of virDomainFlags
 *
 * Launch a new Linux guest domain 
 * 
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainCreateLinux(virConnectPtr conn, const char *kernel_path,
		     const char *initrd_path ATTRIBUTE_UNUSED,
		     const char *cmdline ATTRIBUTE_UNUSED,
		     unsigned long memory,
		     unsigned int flags ATTRIBUTE_UNUSED) {
    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC) ||
        (kernel_path == NULL) || (memory < 4096))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * virDomainLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor
 *
 * Returns a new domain object or NULL in case of failure
 */
virDomainPtr
virDomainLookupByName(virConnectPtr conn, const char *name) {
    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC) || (name == NULL))
        return(NULL);
    TODO
    return(NULL);
}

#if 0
/* Not used ATM */
/**
 * virConnectDoStoreQuery:
 * @conn: pointer to the hypervisor connection
 * @path: the absolute path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
virConnectDoStoreQuery(virConnectPtr conn, const char *path) {
    struct xs_transaction_handle* t;
    char *ret = NULL;
    unsigned int len = 0;

    t = xs_transaction_start(conn->xshandle);
    if (t == NULL)
        goto done;

    ret = xs_read(conn->xshandle, t, path, &len);

done:
    if (t != NULL)
	xs_transaction_end(conn->xshandle, t, 0);
    return(ret);
}
#endif

/**
 * virConnectDoStoreList:
 * @conn: pointer to the hypervisor connection
 * @path: the absolute path of the directory in the store to list
 * @nb: OUT pointer to the number of items found
 *
 * Internal API querying the Xenstore for a list
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char **
virConnectDoStoreList(virConnectPtr conn, const char *path, unsigned int *nb) {
    struct xs_transaction_handle* t;
    char **ret = NULL;

    t = xs_transaction_start(conn->xshandle);
    if (t == NULL)
        goto done;

    ret = xs_directory(conn->xshandle, t, path, nb);

done:
    if (t != NULL)
	xs_transaction_end(conn->xshandle, t, 0);
    return(ret);
}

/**
 * virDomainDoStoreQuery:
 * @domain: a domain object
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
virDomainDoStoreQuery(virDomainPtr domain, const char *path) {
    struct xs_transaction_handle* t;
    char s[256];
    char *ret = NULL;
    unsigned int len = 0;

    snprintf(s, 255, "/local/domain/%d/%s", domain->handle, path);
    s[255] = 0;

    t = xs_transaction_start(domain->conn->xshandle);
    if (t == NULL)
        goto done;

    ret = xs_read(domain->conn->xshandle, t, &s[0], &len);

done:
    if (t != NULL)
	xs_transaction_end(domain->conn->xshandle, t, 0);
    return(ret);
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
virDomainLookupByID(virConnectPtr conn, int id) {
    char *path;
    virDomainPtr ret;

    if ((conn == NULL) || (conn->magic != VIR_CONNECT_MAGIC) || (id < 0))
        return(NULL);

    path = xs_get_domain_path(conn->xshandle, (unsigned int) id);
    if (path == NULL) {
        return(NULL);
    }
    ret = (virDomainPtr) malloc(sizeof(virDomain));
    if (ret == NULL) {
        free(path);
	return(NULL);
    }
    ret->magic = VIR_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->handle = id;
    ret->path = path;
    ret->name = virDomainDoStoreQuery(ret, "name");

    return(ret);
}

/**
 * virDomainDestroy:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 * The data structure is freed and should not be used thereafter if the
 * call does not return an error.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainDestroy(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(-1);
    TODO
    
    return(virDomainFree(domain));
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
virDomainFree(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(-1);
    domain->magic = -1;
    domain->handle = -1;
    if (domain->path != NULL)
        free(domain->path);
    if (domain->name)
        free(domain->name);
    free(domain);
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
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSuspend(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * virDomainResume:
 * @domain: a domain object
 *
 * Resume an suspended domain, the process is restarted from the state where
 * it was frozen by calling virSuspendDomain().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainResume(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
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
virDomainGetName(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(NULL);
    return(domain->name);
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
virDomainGetID(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return((unsigned int) -1);
    return(domain->handle);
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
virDomainGetMaxMemory(virDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC))
        return(0);
    TODO
    return(0);
}

/**
 * virDomainSetMaxMemory:
 * @domain: a domain object or NULL
 * @memory: the memory size in kilobytes
 * 
 * Dynamically change the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this change the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainSetMaxMemory(virDomainPtr domain, unsigned long memory) {
    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC) ||
        (memory < 4096))
        return(-1);
    TODO
    return(-1);
}

/**
 * virDomainGetInfo:
 * @domain: a domain object or NULL
 * @info: pointer to a virDomainInfo structure allocated by the user
 * 
 * Extract information about a domain. Note that if the connection
 * used to get the domain is limited only a partial set of the informations
 * can be extracted.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
virDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info) {
    int ret;

    if ((domain == NULL) || (domain->magic != VIR_DOMAIN_MAGIC) ||
        (info == NULL))
	return(-1);
    memset(info, 0, sizeof(virDomainInfo));
    if (domain->conn->flags & VIR_CONNECT_RO) {
        char *tmp, **tmp2;
	unsigned int nb_vcpus;
	char request[200];

	tmp = virDomainDoStoreQuery(domain, "running");
	if (tmp != NULL) {
	    if (tmp[0] == '1')
		info->state = VIR_DOMAIN_RUNNING;
	    free(tmp);
	} else {
	    info->state = VIR_DOMAIN_NONE;
	}
	tmp = virDomainDoStoreQuery(domain, "memory/target");
	if (tmp != NULL) {
	    info->memory = atol(tmp);
	    info->maxMem = atol(tmp);
	    free(tmp);
	} else {
	    info->memory = 0;
	    info->maxMem = 0;
	}
#if 0
        /* doesn't seems to work */
	tmp = virDomainDoStoreQuery(domain, "cpu_time");
	if (tmp != NULL) {
	    info->cpuTime = atol(tmp);
	    free(tmp);
	} else {
	    info->cpuTime = 0;
	}
#endif
        snprintf(request, 199, "/local/domain/%d/cpu", domain->handle);
	request[199] = 0;
	tmp2 = virConnectDoStoreList(domain->conn, request, &nb_vcpus);
	if (tmp2 != NULL) {
	    info->nrVirtCpu = nb_vcpus;
	    free(tmp2);
	}

    } else {
        dom0_getdomaininfo_t dominfo;

	dominfo.domain = domain->handle;
        ret = xenHypervisorGetDomainInfo(domain->conn->handle, domain->handle,
	                                 &dominfo);
        if (ret < 0)
	    return(-1);
	switch (dominfo.flags & 0xFF) {
	    case DOMFLAGS_DYING:
	        info->state = VIR_DOMAIN_SHUTDOWN;
		break;
	    case DOMFLAGS_SHUTDOWN:
	        info->state = VIR_DOMAIN_SHUTOFF;
		break;
	    case DOMFLAGS_PAUSED:
	        info->state = VIR_DOMAIN_PAUSED;
		break;
	    case DOMFLAGS_BLOCKED:
	        info->state = VIR_DOMAIN_BLOCKED;
		break;
	    case DOMFLAGS_RUNNING:
	        info->state = VIR_DOMAIN_RUNNING;
		break;
	    default:
	        info->state = VIR_DOMAIN_NONE;
	}

	/*
	 * the API brings back the cpu time in nanoseconds,
	 * convert to microseconds, same thing convert to

	 */
	info->cpuTime = dominfo.cpu_time;
	info->memory = dominfo.tot_pages * 4;
	info->maxMem = dominfo.max_pages * 4;
	info->nrVirtCpu = dominfo.nr_online_vcpus;
    }
    return(0);
}
