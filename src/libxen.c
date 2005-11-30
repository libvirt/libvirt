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
    int	         handle;	/* internal handle for the dmonain ID */
};

/**
 * xenGetConnect:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a connection to the 
 * Hypervisor and xen store
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
xenConnectPtr
xenOpenConnect(const char *name) {
    xenConnectPtr ret;
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
    if (ret->domains == NULL)
        goto failed;

    return(ret);
failed:
    if (handle >= 0)
        xc_interface_close(handle);
    if (xshandle != NULL)
        xs_daemon_close(xshandle);
    return(NULL);
}

/**
 * xenDestroyDomainName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
xenDestroyDomainName(xenDomainPtr domain, const char *name ATTRIBUTE_UNUSED) {
    return(xenDestroyDomain(domain));
}

/**
 * xenCloseConnect:
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
xenCloseConnect(xenConnectPtr conn) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC))
        return(-1);

    xenHashFree(conn->domains, (xenHashDeallocator) xenDestroyDomainName);
    conn->magic = -1;
    xs_daemon_close(conn->xshandle);
    conn->xshandle = NULL;
    xc_interface_close(conn->handle);
    conn->handle = -1;
    free(conn);
    return(0);
}

/**
 * xenGetVersion:
 * @conn: pointer to the hypervisor connection
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error or major * 10,000 + minor * 100 + rev otherwise
 */
unsigned long
xenGetVersion(xenConnectPtr conn) {
    if (conn == NULL)
        return(-1);
}

/**
 * xenCreateLinuxDomain:
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
xenCreateLinuxDomain(xenConnectPtr conn, const char *kernel_path,
		     const char *initrd_path, const char *cmdline,
		     unsigned long memory, unsigned int flags) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) ||
        (kernel_path == NULL) || (memory < 4096))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * xenDomainByName:
 * @conn: pointer to the hypervisor connection
 * @name: name for the domain
 *
 * Try to lookup a domain on the given hypervisor
 *
 * Returns a new domain object or NULL in case of failure
 */
xenDomainPtr
xenDomainByName(xenConnectPtr conn, const char *name) {
    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) || (name == NULL))
        return(NULL);
    TODO
    return(NULL);
}

/**
 * xenDomainByID:
 * @conn: pointer to the hypervisor connection
 * @id: the domain ID number
 *
 * Try to find a domain based on the hypervisor ID number
 *
 * Returns a new domain object or NULL in case of failure
 */
xenDomainPtr
xenDomainByID(xenConnectPtr conn, int id) {
    char *path;
    xenDomainPtr ret;
    xc_dominfo_t info;
    int res;

    if ((conn == NULL) || (conn->magic != XEN_CONNECT_MAGIC) || (id < 0))
        return(NULL);

    res = xc_domain_getinfo(conn->handle, (uint32_t) id, 1, &info);
    if (res != 1) {
        return(NULL);
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
    ret->name = path;

    return(ret);
}

/**
 * xenDestroyDomain:
 * @domain: a domain object
 *
 * Destroy the domain object. The running instance is shutdown if not down
 * already and all resources used by it are given back to the hypervisor.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
int
xenDestroyDomain(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * xenSuspendDomain:
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
xenSuspendDomain(xenDomainPtr domain) {
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
xenResumeDomain(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(-1);
    TODO
    return(-1);
}

/**
 * xenGetName:
 * @domain: a domain object
 *
 * Get the public name for that domain
 *
 * Returns a pointer to the name or NULL, the string need not be deallocated
 * its lifetime will be the same as the domain object.
 */
const char *
xenGetName(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(NULL);
    return(domain->name);
}

/**
 * xenGetID:
 * @domain: a domain object
 *
 * Get the hypervisor ID number for the domain
 *
 * Returns the domain ID number or (unsigned int) -1 in case of error
 */
unsigned int
xenGetID(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return((unsigned int) -1);
    return(domain->handle);
}

/**
 * xenGetMaxMemory:
 * @domain: a domain object or NULL
 * 
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenGetMaxMemory(xenDomainPtr domain) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC))
        return(0);
    TODO
    return(0);
}

/**
 * xenSetMaxMemory:
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
xenSetMaxMemory(xenDomainPtr domain, unsigned long memory) {
    if ((domain == NULL) || (domain->magic != XEN_DOMAIN_MAGIC) ||
        (memory < 4096))
        return(-1);
    TODO
    return(-1);
}

