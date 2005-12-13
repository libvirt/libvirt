/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_INTERNAL_H__
#define __VIR_INTERNAL_H__

#include "hash.h"
#include "libvir.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
#ifdef __GNUC__
#ifdef HAVE_ANSIDECL_H
#include <ansidecl.h>
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((unused))
#endif
#else
#define ATTRIBUTE_UNUSED
#endif

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    fprintf(stderr, "Unimplemented block at %s:%d\n",			\
            __FILE__, __LINE__);

/**
 * VIR_CONNECT_MAGIC:
 *
 * magic value used to protect the API when pointers to connection structures
 * are passed down by the uers.
 */
#define VIR_CONNECT_MAGIC 0x4F23DEAD

/**
 * VIR_DOMAIN_MAGIC:
 *
 * magic value used to protect the API when pointers to domain structures
 * are passed down by the uers.
 */
#define VIR_DOMAIN_MAGIC 0xDEAD4321

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VIR_INTERNAL_H__ */
