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
    return(NULL);
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
    /*
     * TODO:
     * Free the domain pointers associated to this connection
     */
    conn->magic = -1;
    free(conn);
    return(0);
}

/**
 * xenGetVersion:
 * @conn: pointer to the hypervisor connection
 *
 * Get the version level of the Hypervisor running
 */
