/*
 * libxen.h: Main interfaces for the libxen library to handle virtualization
 *           domains from a process running in domain 0
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libxen.h"

#include <stdio.h>
#include <stdlib.h>
#include <xenctrl.h>
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

#define XEN_CONNECT_MAGIC 0x4F23DEAD

/*
 * Flags for Xen connections
 */
#define XEN_CONNECT_RO 1

/**
 * _xenConnect:
 *
 * Internal structure associated to a connection
 */
struct _xenConnect {
    unsigned int magic;		/* specific value to check */
    int	         handle;	/* internal handle used for hypercall */
    struct xs_handle *xshandle;	/* handle to talk to the xenstore */
    xenHashTablePtr   domains;	/* hash table for known domains */
    int          flags;		/* a set of connection flags */
};

#define XEN_DOMAIN_MAGIC 0xDEAD4321

/**
 * _xenDomain:
 *
 * Internal structure associated to a domain
 */
struct _xenDomain {
    unsigned int magic;		/* specific value to check */
    xenConnectPtr conn;		/* pointer back to the connection */
    char        *name;		/* the domain external name */
    char        *path;		/* the domain internal path */
    int	         handle;	/* internal handle for the dmonain ID */
};

/**
 * xenConnectOpen:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a connection to the 
 * Hypervisor and xen store
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
xenConnectPtr
xenConnectOpen(const char *name) {
    xenConnectPtr ret = NULL;
    int handle = -1;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    handle = xc_interface_open();
    if (handle == -1)
        goto failed;
    xshandle = xs_daemon_open();
    if (xshandle == NULL)
        goto failed;

    ret = (xenConnectPtr) malloc(sizeof(xenConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = XEN_CONNECT_MAGIC;
    ret->handle = handle;
    ret->xshandle = xshandle;
    ret->domains = xenHashCreate(20);
    ret->flags = 0;
    if (ret->domains == NULL)
        goto failed;

    return(ret);
failed:
    if (handle >= 0)
        xc_interface_close(handle);
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    if (ret != NULL)
        free(ret);
    return(NULL);
}

/**
 * xenConnectOpenReadOnly:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a read-only connection to the 
 * xen store. The set of APIs usable are then restricted.
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
xenConnectPtr
xenConnectOpenReadOnly(const char *name) {
    xenConnectPtr ret = NULL;
    int handle = -1;
    struct xs_handle *xshandle = NULL;

    /* we can only talk to the local Xen supervisor ATM */
    if (name != NULL) 
        return(NULL);

    xshandle = xs_daemon_open_readonly();
    if (xshandle == NULL)
        goto failed;

    ret = (xenConnectPtr) malloc(sizeof(xenConnect));
    if (ret == NULL)
        goto failed;
    ret->magic = XEN_CONNECT_MAGIC;
    ret->handle = -1;
    ret->xshandle = xshandle;
    ret->domains = xenHashCreate(20);
    ret->flags = XEN_CONNECT_RO;
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
 * xenDomainDestroyName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
xenDomainDestroyName(xenDomainPtr domain, const char *name ATTRIBUTE_UNUSED) {
    return(xenDomainDestroy(domain));
}

/**
 * xenConnectClose:
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
xenConnectClose(xenConnectPtr conn) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC))
        return(-1);

    xenHashFree(conn->domains, (xenHashDeallocator) xenDomainDestroyName);
    conn->magic = -1;
    xs_daemon_close(conn->xshandle);
    conn->xshandle = NULL;
    if (conn->handle != -1)
	xc_interface_close(conn->handle);
    conn->handle = -1;
    free(conn);
    return(0);
}

/**
 * xenConnectGetVersion:
 * @conn: pointer to the hypervisor connection
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error or major * 10,000 + minor * 100 + rev otherwise
 */
unsigned long
xenConnectGetVersion(xenConnectPtr conn) {
    if (conn == NULL)
        return(-1);
}

/**
 * xenDomainCreateLinux:
 * @conn: pointer to the hypervisor connection
 * @kernel_path: the file path to the kernel image
 * @initrd_path: an optional file path to an initrd
 * @cmdline: optional command line parameters for the kernel
 * @memory: the memory size in kilobytes
 * @flags: an optional set of xenDomainFlags
 *
 * Launch a new Linux guest domain 
 * 
 * Returns a new domain object or NULL in case of failure
 */
xenDomainPtr
xenDomainCreateLinux(xenConnectPtr conn, const char *kernel_path,
		     const char *initrd_path, const char *cmdline,
		     unsigned long memory, unsigned int flags) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) ||
        (kernel_path == NULL) || (memory < 4096))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * xenDomainLookupByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor
 *
 * Returns a new domain object or NULL in case of failure
 */
xenDomainPtr
xenDomainLookupByName(xenConnectPtr conn, const char *name) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) || (name == NULL))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * xenConnectDoStoreQuery:
 * @conn: pointer to the hypervisor connection
 * @path: the absolute path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
xenConnectDoStoreQuery(xenConnectPtr conn, const char *path) {
    struct xs_transaction_handle* t;
    char s[256];
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

/**
 * xenDomainDoStoreQuery:
 * @domain: a domain object
 * @path: the relative path of the data in the store to retrieve
 *
 * Internal API querying the Xenstore for a string value.
 *
 * Returns a string which must be freed by the caller or NULL in case of error
 */
static char *
xenDomainDoStoreQuery(xenDomainPtr domain, const char *path) {
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
 * xenDomainLookupByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
xenDomainPtr
xenDomainLookupByID(xenConnectPtr conn, int id) {
    char *path;
    xenDomainPtr ret;
    xc_dominfo_t info;
    int res;

    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) || (id < 0))
        return(NULL);

    if ((conn->flags & XEN_CONNECT_RO) == 0) {
	res = xc_domain_getinfo(conn->handle, (uint32_t) id, 1, &info);
	if (res != 1) {
	    return(NULL);
	}
    }
    
    path = xs_get_domain_path(conn->xshandle, (unsigned int) id);
    if (path == NULL) {
        return(NULL);
    }
    ret = (xenDomainPtr) malloc(sizeof(xenDomain));
    if (ret == NULL) {
        free(path);
	return(NULL);
    }
    ret->magic = XEN_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->handle = id;
    ret->path = path;
    ret->name = xenDomainDoStoreQuery(ret, "name");

    return(ret);
}

/**
 * xenDomainDestroy:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
xenDomainDestroy(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * xenDomainSuspend:
 * @domain: a domain object
 *
 * Suspends an active domain, the process is frozen without further access
 * to CPU resources and I/O but the memory used by the domain at the 
 * hypervisor level will stay allocated. Use xenResumeDomain() to reactivate
 * the domain.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
xenDomainSuspend(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * xenResumeDomain:
 * @domain: a domain object
 *
 * Resume an suspended domain, the process is restarted from the state where
 * it was frozen by calling xenSuspendDomain().
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
xenDomainResume(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * xenDomainGetName:
 * @domain: a domain object
 *
 * Get the public name for that domain
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the domain object.
 */
const char *
xenDomainGetName(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(NULL);
    return(domain->name);
}

/**
 * xenDomainGetID:
 * @domain: a domain object
 *
 * Get the hypervisor ID number for the domain
 *
 * Returns the domain ID number or (unsigned int) -1 in case of error
 */
unsigned int
xenDomainGetID(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return((unsigned int) -1);
    return(domain->handle);
}

/**
 * xenDomainGetMaxMemory:
 * @domain: a domain object or NULL
 * 
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenDomainGetMaxMemory(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(0);
    TODO
    return(0);
}

/**
 * xenDomainSetMaxMemory:
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
xenDomainSetMaxMemory(xenDomainPtr domain, unsigned long memory) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC) ||
        (memory < 4096))
        return(-1);
    TODO
    return(-1);
}

