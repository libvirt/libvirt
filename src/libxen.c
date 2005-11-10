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
#include "internal.h"

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
};

/**
 * xenGetConnect:
 * @name: optional argument currently unused, pass NULL
 *
 * This function should be called first to get a connection to the 
 * Hypervisor
 *
 * Returns a pointer to the hypervisor connection or NULL in case of error
 */
xenConnectPtr
xenOpenConnect(const char *name) {
    xenConnectPtr ret;
    int handle;

    handle = xc_interface_open();
    if (handle == -1) {
        return(NULL);
    }
    ret = (xenConnectPtr) malloc(sizeof(xenConnect));
    if (ret == NULL) {
        xc_interface_close(handle);
        return(NULL);
    }
    ret->magic = XEN_CONNECT_MAGIC;
    ret->handle = handle;

    return(ret);
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

    conn->magic = -1;
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
    if ((conn == NULL) || (kernel_path == NULL) || (memory < 4096))
        return(NULL);
    TODO
    return(NULL);
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
    if (domain == NULL)
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
    if (domain == NULL)
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
    if (domain == NULL)
        return(-1);
    TODO
    return(-1);
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
    if ((domain == NULL) || (memory < 4096))
        return(-1);
    TODO
    return(-1);
}

