/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_INTERNAL_H__
#define __VIR_INTERNAL_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <libxml/threads.h>

#include "hash.h"
#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"
#include "driver.h"
#include <libintl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _(str) dgettext(GETTEXT_PACKAGE, (str))
#define _N(str) dgettext(GETTEXT_PACKAGE, (str))
#define gettext_noop(str) (str)

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

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec) /* empty */
# endif
/* The __-protected variants of `format' and `printf' attributes
   are accepted by gcc versions 2.6.4 (effectively 2.7) and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7)
#  define __format__ format
#  define __printf__ printf
# endif
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
#define VIR_CONNECT_MAGIC 	0x4F23DEAD
#define VIR_IS_CONNECT(obj)	((obj) && (obj)->magic==VIR_CONNECT_MAGIC)


/**
 * VIR_DOMAIN_MAGIC:
 *
 * magic value used to protect the API when pointers to domain structures
 * are passed down by the uers.
 */
#define VIR_DOMAIN_MAGIC		0xDEAD4321
#define VIR_IS_DOMAIN(obj)		((obj) && (obj)->magic==VIR_DOMAIN_MAGIC)
#define VIR_IS_CONNECTED_DOMAIN(obj)	(VIR_IS_DOMAIN(obj) && VIR_IS_CONNECT((obj)->conn))

#define MAX_DRIVERS 5

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
    unsigned int magic;     /* specific value to check */

    int uses;               /* reference count */
    /* the list of available drivers for that connection */
    virDriverPtr      drivers[MAX_DRIVERS];
    int               nb_drivers;

    /* extra data needed by drivers */
    int handle;             /* internal handle used for hypercall */
    struct xs_handle *xshandle;/* handle to talk to the xenstore */
    int proxy;              /* file descriptor if using the proxy */

    /* connection to xend */
    int type;               /* PF_UNIX or PF_INET */
    int len;                /* lenght of addr */
    struct sockaddr *addr;  /* type of address used */
    struct sockaddr_un addr_un;     /* the unix address */
    struct sockaddr_in addr_in;     /* the inet address */

    /* error stuff */
    virError err;           /* the last error */
    virErrorFunc handler;   /* associated handlet */
    void *userData;         /* the user data */

    /* misc */
    xmlMutexPtr domains_mux;/* a mutex to protect the domain hash table */
    virHashTablePtr domains;/* hash table for known domains */
    int flags;              /* a set of connection flags */
};

/**
* virDomainFlags:
*
* a set of special flag values associated to the domain
*/

enum {
    DOMAIN_IS_SHUTDOWN = (1 << 0),  /* the domain is being shutdown */
    DOMAIN_IS_DEFINED  = (1 << 1)   /* the domain is defined not running */
} virDomainFlags;

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    unsigned int magic;     /* specific value to check */
    int uses;               /* reference count */
    virConnectPtr conn;     /* pointer back to the connection */
    char *name;             /* the domain external name */
    char *path;             /* the domain internal path */
    int handle;             /* internal handle for the domnain ID */
    int flags;              /* extra flags */
    unsigned char uuid[16]; /* the domain unique identifier */
    char *xml;              /* the XML description for defined domains */
};

/*
* Internal routines
*/
char *virDomainGetVM(virDomainPtr domain);
char *virDomainGetVMInfo(virDomainPtr domain,
			 const char *vm, const char *name);

/************************************************************************
 *									*
 *		API for error handling					*
 *									*
 ************************************************************************/
void __virRaiseError(virConnectPtr conn,
		     virDomainPtr dom,
		     int domain,
		     int code,
		     virErrorLevel level,
		     const char *str1,
		     const char *str2,
		     const char *str3,
		     int int1, int int2, const char *msg, ...);
const char *__virErrorMsg(virErrorNumber error, const char *info);

/************************************************************************
 *									*
 *	API for domain/connections (de)allocations and lookups		*
 *									*
 ************************************************************************/

virConnectPtr	virGetConnect	(void);
int		virFreeConnect	(virConnectPtr conn);
virDomainPtr	virGetDomain	(virConnectPtr conn,
				 const char *name,
				 const unsigned char *uuid);
int		virFreeDomain	(virConnectPtr conn,
				 virDomainPtr domain);
virDomainPtr	virGetDomainByID(virConnectPtr conn,
				 int id);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_INTERNAL_H__ */
