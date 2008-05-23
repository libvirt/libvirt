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

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define PTHREAD_MUTEX_T(v) pthread_mutex_t v
#else
/* Mutex functions disappear if we don't have pthread. */
#define PTHREAD_MUTEX_T(v) /*empty*/
#define pthread_mutex_init(lk,p) /*empty*/
#define pthread_mutex_destroy(lk) /*empty*/
#define pthread_mutex_lock(lk) /*empty*/
#define pthread_mutex_unlock(lk) /*empty*/
#endif

/* The library itself is allowed to use deprecated functions /
 * variables, so effectively undefine the deprecated attribute
 * which would otherwise be defined in libvirt.h.
 */
#define VIR_DEPRECATED /*empty*/

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
#define STRPREFIX(a,b) (strncmp((a),(b),strlen((b))) == 0)

#define NUL_TERMINATE(buf) do { (buf)[sizeof(buf)-1] = '\0'; } while (0)
#define ARRAY_CARDINALITY(Array) (sizeof (Array) / sizeof *(Array))

/* If configured with --enable-debug=yes then library calls
 * are printed to stderr for debugging.
 */
#ifdef ENABLE_DEBUG
extern int debugFlag;
#define VIR_DEBUG(category, fmt,...)                                    \
    do { if (debugFlag) fprintf (stderr, "DEBUG: %s: %s (" fmt ")\n", category, __func__, __VA_ARGS__); } while (0)
#else
#define VIR_DEBUG(category, fmt,...) \
    do { } while (0)
#endif /* !ENABLE_DEBUG */

/* C99 uses __func__.  __FUNCTION__ is legacy. */
#ifndef __GNUC__
#define __FUNCTION__ __func__
#endif

#ifdef __GNUC__

#ifndef __GNUC_PREREQ
#define __GNUC_PREREQ(maj,min) 0
#endif

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

#ifndef ATTRIBUTE_RETURN_CHECK
#if __GNUC_PREREQ (3, 4)
#define ATTRIBUTE_RETURN_CHECK __attribute__((__warn_unused_result__))
#else
#define ATTRIBUTE_RETURN_CHECK
#endif
#endif

#else
#define ATTRIBUTE_UNUSED
#define ATTRIBUTE_FORMAT(...)
#define ATTRIBUTE_RETURN_CHECK
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
 * are passed down by the users.
 */
#define VIR_DOMAIN_MAGIC		0xDEAD4321
#define VIR_IS_DOMAIN(obj)		((obj) && (obj)->magic==VIR_DOMAIN_MAGIC)
#define VIR_IS_CONNECTED_DOMAIN(obj)	(VIR_IS_DOMAIN(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_NETWORK_MAGIC:
 *
 * magic value used to protect the API when pointers to network structures
 * are passed down by the users.
 */
#define VIR_NETWORK_MAGIC		0xDEAD1234
#define VIR_IS_NETWORK(obj)		((obj) && (obj)->magic==VIR_NETWORK_MAGIC)
#define VIR_IS_CONNECTED_NETWORK(obj)	(VIR_IS_NETWORK(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_STORAGE_POOL_MAGIC:
 *
 * magic value used to protect the API when pointers to storage pool structures
 * are passed down by the users.
 */
#define VIR_STORAGE_POOL_MAGIC		0xDEAD5678
#define VIR_IS_STORAGE_POOL(obj)		((obj) && (obj)->magic==VIR_STORAGE_POOL_MAGIC)
#define VIR_IS_CONNECTED_STORAGE_POOL(obj)	(VIR_IS_STORAGE_POOL(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_STORAGE_VOL_MAGIC:
 *
 * magic value used to protect the API when pointers to storage vol structures
 * are passed down by the users.
 */
#define VIR_STORAGE_VOL_MAGIC		0xDEAD8765
#define VIR_IS_STORAGE_VOL(obj)		((obj) && (obj)->magic==VIR_STORAGE_VOL_MAGIC)
#define VIR_IS_CONNECTED_STORAGE_VOL(obj)	(VIR_IS_STORAGE_VOL(obj) && VIR_IS_CONNECT((obj)->conn))

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
    int flags;              /* a set of connection flags */
    char *name;                 /* connection URI */

    /* The underlying hypervisor driver and network driver. */
    virDriverPtr      driver;
    virNetworkDriverPtr networkDriver;
    virStorageDriverPtr storageDriver;

    /* Private data pointer which can be used by driver and
     * network driver as they wish.
     * NB: 'private' is a reserved word in C++.
     */
    void *            privateData;
    void *            networkPrivateData;
    void *            storagePrivateData;

    /* Per-connection error. */
    virError err;           /* the last error */
    virErrorFunc handler;   /* associated handlet */
    void *userData;         /* the user data */

    /*
     * The lock mutex must be acquired before accessing/changing
     * any of members following this point, or changing the ref
     * count of any virDomain/virNetwork object associated with
     * this connection
     */
    PTHREAD_MUTEX_T (lock);
    virHashTablePtr domains;  /* hash table for known domains */
    virHashTablePtr networks; /* hash table for known domains */
    virHashTablePtr storagePools;/* hash table for known storage pools */
    virHashTablePtr storageVols;/* hash table for known storage vols */
    int refs;                 /* reference count */
};

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
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
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network unique identifier */
};

/**
* _virStoragePool:
*
* Internal structure associated to a storage pool
*/
struct _virStoragePool {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the storage pool external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the storage pool unique identifier */
};

/**
* _virStorageVol:
*
* Internal structure associated to a storage volume
*/
struct _virStorageVol {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *pool;                          /* Pool name of owner */
    char *name;                          /* the storage vol external name */
    /* XXX currently abusing path for this. Ought not to be so evil */
    char key[PATH_MAX];                  /* unique key for storage vol */
};


/************************************************************************
 *									*
 *		API for error handling					*
 *									*
 ************************************************************************/
extern virError __lastErr;
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

virConnectPtr  virGetConnect   (void);
int            virUnrefConnect (virConnectPtr conn);
virDomainPtr   __virGetDomain  (virConnectPtr conn,
                                const char *name,
                                const unsigned char *uuid);
int            virUnrefDomain  (virDomainPtr domain);
virNetworkPtr  __virGetNetwork (virConnectPtr conn,
                                const char *name,
                                const unsigned char *uuid);
int           virUnrefNetwork  (virNetworkPtr network);

virStoragePoolPtr __virGetStoragePool (virConnectPtr conn,
                                       const char *name,
                                       const unsigned char *uuid);
int               virUnrefStoragePool (virStoragePoolPtr pool);
virStorageVolPtr  __virGetStorageVol  (virConnectPtr conn,
                                       const char *pool,
                                       const char *name,
                                       const char *key);
int               virUnrefStorageVol  (virStorageVolPtr vol);

#define virGetDomain(c,n,u) __virGetDomain((c),(n),(u))
#define virGetNetwork(c,n,u) __virGetNetwork((c),(n),(u))
#define virGetStoragePool(c,n,u) __virGetStoragePool((c),(n),(u))
#define virGetStorageVol(c,p,n,u) __virGetStorageVol((c),(p),(n),(u))

int __virStateInitialize(void);
int __virStateCleanup(void);
int __virStateReload(void);
int __virStateActive(void);
int __virStateSigDispatcher(siginfo_t *siginfo);
#define virStateInitialize() __virStateInitialize()
#define virStateCleanup() __virStateCleanup()
#define virStateReload() __virStateReload()
#define virStateActive() __virStateActive()
#define virStateSigDispatcher(s) __virStateSigDispatcher(s)

int __virDrvSupportsFeature (virConnectPtr conn, int feature);

int __virDomainMigratePrepare (virConnectPtr dconn, char **cookie, int *cookielen, const char *uri_in, char **uri_out, unsigned long flags, const char *dname, unsigned long bandwidth);
int __virDomainMigratePerform (virDomainPtr domain, const char *cookie, int cookielen, const char *uri, unsigned long flags, const char *dname, unsigned long bandwidth);
virDomainPtr __virDomainMigrateFinish (virConnectPtr dconn, const char *dname, const char *cookie, int cookielen, const char *uri, unsigned long flags);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* __VIR_INTERNAL_H__ */
