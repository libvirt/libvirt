/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_INTERNAL_H__
#define __VIR_INTERNAL_H__

#include <errno.h>
#include <limits.h>

#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

#include "gettext.h"

#include "hash.h"
#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"
#include "driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* On architectures which lack these limits, define them (ie. Cygwin).
 * Note that the libvirt code should be robust enough to handle the
 * case where actual value is longer than these limits (eg. by setting
 * length correctly in second argument to gethostname and by always
 * using strncpy instead of strcpy).
 */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define _(str) dgettext(GETTEXT_PACKAGE, (str))
#define N_(str) dgettext(GETTEXT_PACKAGE, (str))

/* String equality tests, suggested by Jim Meyering. */
#define STREQ(a,b) (strcmp((a),(b)) == 0)
#define STRCASEEQ(a,b) (strcasecmp((a),(b)) == 0)
#define STRNEQ(a,b) (strcmp((a),(b)) != 0)
#define STRCASENEQ(a,b) (strcasecmp((a),(b)) != 0)
#define STREQLEN(a,b,n) (strncmp((a),(b),(n)) == 0)
#define STRCASEEQLEN(a,b,n) (strncasecmp((a),(b),(n)) == 0)
#define STRNEQLEN(a,b,n) (strncmp((a),(b),(n)) != 0)
#define STRCASENEQLEN(a,b,n) (strncasecmp((a),(b),(n)) != 0)

/* C99 uses __func__.  __FUNCTION__ is legacy. */
#ifndef __GNUC__
#define __FUNCTION__ __func__
#endif

#ifdef __GNUC__
/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

/**
 * ATTRIBUTE_FORMAT
 *
 * Macro used to check printf/scanf-like functions, if compiling
 * with gcc.
 */
#ifndef ATTRIBUTE_FORMAT
#define ATTRIBUTE_FORMAT(args...) __attribute__((__format__ (args)))
#endif

#else
#define ATTRIBUTE_UNUSED
#define ATTRIBUTE_FORMAT(...)
#endif				/* __GNUC__ */

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

/**
 * VIR_NETWORK_MAGIC:
 *
 * magic value used to protect the API when pointers to network structures
 * are passed down by the uers.
 */
#define VIR_NETWORK_MAGIC		0xDEAD1234
#define VIR_IS_NETWORK(obj)		((obj) && (obj)->magic==VIR_NETWORK_MAGIC)
#define VIR_IS_CONNECTED_NETWORK(obj)	(VIR_IS_NETWORK(obj) && VIR_IS_CONNECT((obj)->conn))

/*
 * arbitrary limitations
 */
#define MAX_DRIVERS 10
#define MIN_XEN_GUEST_SIZE 64  /* 64 megabytes */

/**
 * _virConnect:
 *
 * Internal structure associated to a connection
 */
struct _virConnect {
    unsigned int magic;     /* specific value to check */

    int uses;               /* reference count */

    /* The underlying hypervisor driver and network driver. */
    virDriverPtr      driver;
    virNetworkDriverPtr networkDriver;

    /* Private data pointer which can be used by driver and
     * network driver as they wish.
     * NB: 'private' is a reserved word in C++.
     */
    void *            privateData;
    void *            networkPrivateData;

    /* Per-connection error. */
    virError err;           /* the last error */
    virErrorFunc handler;   /* associated handlet */
    void *userData;         /* the user data */

    /* misc */
    xmlMutexPtr hashes_mux;/* a mutex to protect the domain and networks hash tables */
    virHashTablePtr domains;/* hash table for known domains */
    virHashTablePtr networks;/* hash table for known domains */
    int flags;              /* a set of connection flags */
    char *name;                 /* connection URI */
};

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    unsigned int magic;                  /* specific value to check */
    int uses;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the domain external name */
    int id;                              /* the domain ID */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the domain unique identifier */
};

/**
* _virNetwork:
*
* Internal structure associated to a domain
*/
struct _virNetwork {
    unsigned int magic;                  /* specific value to check */
    int uses;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network unique identifier */
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
		     virNetworkPtr net,
		     int domain,
		     int code,
		     virErrorLevel level,
		     const char *str1,
		     const char *str2,
		     const char *str3,
		     int int1, int int2, const char *msg, ...)
  ATTRIBUTE_FORMAT(printf, 12, 13);
const char *__virErrorMsg(virErrorNumber error, const char *info);

/************************************************************************
 *									*
 *	API for domain/connections (de)allocations and lookups		*
 *									*
 ************************************************************************/

virConnectPtr	virGetConnect	(void);
int		virFreeConnect	(virConnectPtr conn);
virDomainPtr	__virGetDomain	(virConnectPtr conn,
				 const char *name,
				 const unsigned char *uuid);
int		virFreeDomain	(virConnectPtr conn,
				 virDomainPtr domain);
virNetworkPtr	__virGetNetwork	(virConnectPtr conn,
				 const char *name,
				 const unsigned char *uuid);
int		virFreeNetwork	(virConnectPtr conn,
				 virNetworkPtr domain);

#define virGetDomain(c,n,u) __virGetDomain((c),(n),(u))
#define virGetNetwork(c,n,u) __virGetNetwork((c),(n),(u))

int __virStateInitialize(void);
int __virStateCleanup(void);
int __virStateReload(void);
int __virStateActive(void);
#define virStateInitialize() __virStateInitialize()
#define virStateCleanup() __virStateCleanup()
#define virStateReload() __virStateReload()
#define virStateActive() __virStateActive()

int __virDrvSupportsFeature (virConnectPtr conn, int feature);

int __virDomainMigratePrepare (virConnectPtr dconn, char **cookie, int *cookielen, const char *uri_in, char **uri_out, unsigned long flags, const char *dname, unsigned long bandwidth);
int __virDomainMigratePerform (virDomainPtr domain, const char *cookie, int cookielen, const char *uri, unsigned long flags, const char *dname, unsigned long bandwidth);
virDomainPtr __virDomainMigrateFinish (virConnectPtr dconn, const char *dname, const char *cookie, int cookielen, const char *uri, unsigned long flags);

/* Like strtol, but produce an "int" result, and check more carefully.
   Return 0 upon success;  return -1 to indicate failure.
   When END_PTR is NULL, the byte after the final valid digit must be NUL.
   Otherwise, it's like strtol and lets the caller check any suffix for
   validity.  This function is careful to return -1 when the string S
   represents a number that is not representable as an "int". */
static inline int
xstrtol_i(char const *s, char **end_ptr, int base, int *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like xstrtol_i, above, but produce an "unsigned int" value.  */
static inline int
xstrtol_ui(char const *s, char **end_ptr, int base, unsigned int *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_INTERNAL_H__ */

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
