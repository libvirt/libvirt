/* -*- c -*-
 * libvirt.h:
 * Summary: core interfaces for the libvirt library
 * Description: Provides the interfaces of the libvirt library to handle
 *              virtualized domains
 *
 * Copy:  Copyright (C) 2005,2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_VIRLIB_H__
#define __VIR_VIRLIB_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef VIR_DEPRECATED
  /* The feature is present in gcc-3.1 and newer.  */
# if __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 1)
#  define VIR_DEPRECATED __attribute__((__deprecated__))
# else
#  define VIR_DEPRECATED /* nothing */
# endif
#endif /* VIR_DEPRECATED */

/**
 * virConnect:
 *
 * a virConnect is a private structure representing a connection to
 * the Hypervisor.
 */
typedef struct _virConnect virConnect;

/**
 * virConnectPtr:
 *
 * a virConnectPtr is pointer to a virConnect private structure, this is the
 * type used to reference a connection to the Hypervisor in the API.
 */
typedef virConnect *virConnectPtr;

/**
 * virDomain:
 *
 * a virDomain is a private structure representing a domain.
 */
typedef struct _virDomain virDomain;

/**
 * virDomainPtr:
 *
 * a virDomainPtr is pointer to a virDomain private structure, this is the
 * type used to reference a domain in the API.
 */
typedef virDomain *virDomainPtr;

/**
 * virDomainState:
 *
 * A domain may be in different states at a given point in time
 */
typedef enum {
     VIR_DOMAIN_NOSTATE = 0, /* no state */
     VIR_DOMAIN_RUNNING = 1, /* the domain is running */
     VIR_DOMAIN_BLOCKED = 2, /* the domain is blocked on resource */
     VIR_DOMAIN_PAUSED  = 3, /* the domain is paused by user */
     VIR_DOMAIN_SHUTDOWN= 4, /* the domain is being shut down */
     VIR_DOMAIN_SHUTOFF = 5, /* the domain is shut off */
     VIR_DOMAIN_CRASHED = 6  /* the domain is crashed */
} virDomainState;

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfo is a structure filled by virDomainGetInfo() and extracting
 * runtime information for a given active Domain
 */

typedef struct _virDomainInfo virDomainInfo;

struct _virDomainInfo {
    unsigned char state;        /* the running state, one of virDomainState */
    unsigned long maxMem;       /* the maximum memory in KBytes allowed */
    unsigned long memory;       /* the memory in KBytes used by the domain */
    unsigned short nrVirtCpu;   /* the number of virtual CPUs for the domain */
    unsigned long long cpuTime; /* the CPU time used in nanoseconds */
};

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfoPtr is a pointer to a virDomainInfo structure.
 */

typedef virDomainInfo *virDomainInfoPtr;

/**
 * virDomainCreateFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 */
typedef enum {
     VIR_DOMAIN_NONE = 0
} virDomainCreateFlags;

/**
 * VIR_SECURITY_LABEL_BUFLEN:
 *
 * Macro providing the maximum length of the virSecurityLabel label string.
 * Note that this value is based on that used by Labeled NFS.
 */
#define VIR_SECURITY_LABEL_BUFLEN (4096 + 1)

/**
 * virSecurityLabel:
 *
 * a virSecurityLabel is a structure filled by virDomainGetSecurityLabel(),
 * providing the security label and associated attributes for the specified
 * domain.
 *
 */
typedef struct _virSecurityLabel {
    char label[VIR_SECURITY_LABEL_BUFLEN];    /* security label string */
    int enforcing;                            /* 1 if security policy is being enforced for domain */
} virSecurityLabel;

/**
 * virSecurityLabelPtr:
 *
 * a virSecurityLabelPtr is a pointer to a virSecurityLabel.
 */
typedef virSecurityLabel *virSecurityLabelPtr;

/**
 * VIR_SECURITY_MODEL_BUFLEN:
 *
 * Macro providing the maximum length of the virSecurityModel model string.
 */
#define VIR_SECURITY_MODEL_BUFLEN (256 + 1)

/**
 * VIR_SECURITY_DOI_BUFLEN:
 *
 * Macro providing the maximum length of the virSecurityModel doi string.
 */
#define VIR_SECURITY_DOI_BUFLEN (256 + 1)

/**
 * virSecurityModel:
 *
 * a virSecurityModel is a structure filled by virNodeGetSecurityModel(),
 * providing the per-hypervisor security model and DOI attributes for the
 * specified domain.
 *
 */
typedef struct _virSecurityModel {
    char model[VIR_SECURITY_MODEL_BUFLEN];      /* security model string */
    char doi[VIR_SECURITY_DOI_BUFLEN];          /* domain of interpetation */
} virSecurityModel;

/**
 * virSecurityModelPtr:
 *
 * a virSecurityModelPtr is a pointer to a virSecurityModel.
 */
typedef virSecurityModel *virSecurityModelPtr;

/**
 * virNodeInfoPtr:
 *
 * a virNodeInfo is a structure filled by virNodeGetInfo() and providing
 * the information for the Node.
 */

typedef struct _virNodeInfo virNodeInfo;

struct _virNodeInfo {
    char model[32];     /* string indicating the CPU model */
    unsigned long memory;/* memory size in kilobytes */
    unsigned int cpus;  /* the number of active CPUs */
    unsigned int mhz;   /* expected CPU frequency */
    unsigned int nodes; /* the number of NUMA cell, 1 for uniform mem access */
    unsigned int sockets;/* number of CPU socket per node */
    unsigned int cores; /* number of core per socket */
    unsigned int threads;/* number of threads per core */
};


/**
 * virDomainSchedParameterType:
 *
 * A scheduler parameter field type
 */
typedef enum {
    VIR_DOMAIN_SCHED_FIELD_INT     = 1, /* integer case */
    VIR_DOMAIN_SCHED_FIELD_UINT    = 2, /* unsigned integer case */
    VIR_DOMAIN_SCHED_FIELD_LLONG   = 3, /* long long case */
    VIR_DOMAIN_SCHED_FIELD_ULLONG  = 4, /* unsigned long long case */
    VIR_DOMAIN_SCHED_FIELD_DOUBLE  = 5, /* double case */
    VIR_DOMAIN_SCHED_FIELD_BOOLEAN = 6  /* boolean(character) case */
} virSchedParameterType;

/**
 * VIR_DOMAIN_SCHED_FIELD_LENGTH:
 *
 * Macro providing the field length of virSchedParameter
 */

#define VIR_DOMAIN_SCHED_FIELD_LENGTH 80

/**
 * virDomainSchedParameter:
 *
 * a virDomainSchedParameter is the set of scheduler parameters
 */

typedef struct _virSchedParameter virSchedParameter;

struct _virSchedParameter {
    char field[VIR_DOMAIN_SCHED_FIELD_LENGTH];  /* parameter name */
    int type;   /* parameter type */
    union {
        int i;                          /* data for integer case */
        unsigned int ui;        /* data for unsigned integer case */
        long long int l;        /* data for long long integer case */
        unsigned long long int ul;      /* data for unsigned long long integer case */
        double d;       /* data for double case */
        char b;         /* data for char case */
    } value; /* parameter value */
};

/**
 * virSchedParameterPtr:
 *
 * a virSchedParameterPtr is a pointer to a virSchedParameter structure.
 */

typedef virSchedParameter *virSchedParameterPtr;

/*
 * Fetch scheduler parameters, caller allocates 'params' field of size 'nparams'
 */
int     virDomainGetSchedulerParameters (virDomainPtr domain,
                                         virSchedParameterPtr params,
                                         int *nparams);

/*
 * Change scheduler parameters
 */
int     virDomainSetSchedulerParameters (virDomainPtr domain,
                                         virSchedParameterPtr params,
                                         int nparams);

/**
 * virDomainBlockStats:
 *
 * Block device stats for virDomainBlockStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
 */
typedef struct _virDomainBlockStats virDomainBlockStatsStruct;

struct _virDomainBlockStats {
  long long rd_req; /* number of read requests */
  long long rd_bytes; /* number of read bytes */
  long long wr_req; /* number of write requests */
  long long wr_bytes; /* number of written bytes */
  long long errs;   /* In Xen this returns the mysterious 'oo_req'. */
};

/**
 * virDomainBlockStatsPtr:
 *
 * A pointer to a virDomainBlockStats structure
 */
typedef virDomainBlockStatsStruct *virDomainBlockStatsPtr;

/**
 * virDomainInterfaceStats:
 *
 * Network interface stats for virDomainInterfaceStats.
 *
 * Hypervisors may return a field set to ((long long)-1) which indicates
 * that the hypervisor does not support that statistic.
 *
 * NB. Here 'long long' means 64 bit integer.
 */
typedef struct _virDomainInterfaceStats virDomainInterfaceStatsStruct;

struct _virDomainInterfaceStats {
  long long rx_bytes;
  long long rx_packets;
  long long rx_errs;
  long long rx_drop;
  long long tx_bytes;
  long long tx_packets;
  long long tx_errs;
  long long tx_drop;
};

/**
 * virDomainInterfaceStatsPtr:
 *
 * A pointer to a virDomainInterfaceStats structure
 */
typedef virDomainInterfaceStatsStruct *virDomainInterfaceStatsPtr;


/* Domain migration flags. */
typedef enum {
  VIR_MIGRATE_LIVE              = 1, /* live migration */
} virDomainMigrateFlags;

/* Domain migration. */
virDomainPtr virDomainMigrate (virDomainPtr domain, virConnectPtr dconn,
                               unsigned long flags, const char *dname,
                               const char *uri, unsigned long bandwidth);

/**
 * VIR_NODEINFO_MAXCPUS:
 * @nodeinfo: virNodeInfo instance
 *
 * This macro is to calculate the total number of CPUs supported
 * but not necessary active in the host.
 */


#define VIR_NODEINFO_MAXCPUS(nodeinfo) ((nodeinfo).nodes*(nodeinfo).sockets*(nodeinfo).cores*(nodeinfo).threads)

/**
 * virNodeInfoPtr:
 *
 * a virNodeInfoPtr is a pointer to a virNodeInfo structure.
 */

typedef virNodeInfo *virNodeInfoPtr;

/**
 * virConnectFlags
 *
 * Flags when opening a connection to a hypervisor
 */
typedef enum {
    VIR_CONNECT_RO = 1,    /* A readonly connection */
} virConnectFlags;


typedef enum {
    VIR_CRED_USERNAME = 1,     /* Identity to act as */
    VIR_CRED_AUTHNAME = 2,     /* Identify to authorize as */
    VIR_CRED_LANGUAGE = 3,     /* RFC 1766 languages, comma separated */
    VIR_CRED_CNONCE = 4,       /* client supplies a nonce */
    VIR_CRED_PASSPHRASE = 5,   /* Passphrase secret */
    VIR_CRED_ECHOPROMPT = 6,   /* Challenge response */
    VIR_CRED_NOECHOPROMPT = 7, /* Challenge response */
    VIR_CRED_REALM = 8,        /* Authentication realm */
    VIR_CRED_EXTERNAL = 9,     /* Externally managed credential */

    /* More may be added - expect the unexpected */
} virConnectCredentialType;

struct _virConnectCredential {
    int type; /* One of virConnectCredentialType constants */
    const char *prompt; /* Prompt to show to user */
    const char *challenge; /* Additional challenge to show */
    const char *defresult; /* Optional default result */
    char *result; /* Result to be filled with user response (or defresult) */
    unsigned int resultlen; /* Length of the result */
};

typedef struct _virConnectCredential virConnectCredential;
typedef virConnectCredential *virConnectCredentialPtr;


/**
 * virConnectCredCallbackPtr
 *
 * @param authtype type of authentication being performed
 * @param cred list of virConnectCredential object to fetch from user
 * @param ncred size of cred list
 * @param cbdata opaque data passed to virConnectOpenAuth
 *
 * When authentication requires one or more interactions, this callback
 * is invoked. For each interaction supplied, data must be gathered
 * from the user and filled in to the 'result' and 'resultlen' fields.
 * If an interaction can not be filled, fill in NULL and 0.
 *
 * Return 0 if all interactions were filled, or -1 upon error
 */
typedef int (*virConnectAuthCallbackPtr)(virConnectCredentialPtr cred,
                                         unsigned int ncred,
                                         void *cbdata);

struct _virConnectAuth {
    int *credtype; /* List of supported virConnectCredentialType values */
    unsigned int ncredtype;

    virConnectAuthCallbackPtr cb; /* Callback used to collect credentials */
    void *cbdata;
};


typedef struct _virConnectAuth virConnectAuth;
typedef virConnectAuth *virConnectAuthPtr;

extern virConnectAuthPtr virConnectAuthPtrDefault;

/**
 * VIR_UUID_BUFLEN:
 *
 * This macro provides the length of the buffer required
 * for virDomainGetUUID()
 */

#define VIR_UUID_BUFLEN (16)

/**
 * VIR_UUID_STRING_BUFLEN:
 *
 * This macro provides the length of the buffer required
 * for virDomainGetUUIDString()
 */

#define VIR_UUID_STRING_BUFLEN (36+1)

/* library versioning */

/**
 * LIBVIR_VERSION_NUMBER:
 *
 * Macro providing the version of the library as
 * version * 1,000,000 + minor * 1000 + micro
 */

#define LIBVIR_VERSION_NUMBER 7001

int                     virGetVersion           (unsigned long *libVer,
                                                 const char *type,
                                                 unsigned long *typeVer);

/*
 * Connection and disconnections to the Hypervisor
 */
int                     virInitialize           (void);

virConnectPtr           virConnectOpen          (const char *name);
virConnectPtr           virConnectOpenReadOnly  (const char *name);
virConnectPtr           virConnectOpenAuth      (const char *name,
                                                 virConnectAuthPtr auth,
                                                 int flags);
int                     virConnectRef           (virConnectPtr conn);
int                     virConnectClose         (virConnectPtr conn);
const char *            virConnectGetType       (virConnectPtr conn);
int                     virConnectGetVersion    (virConnectPtr conn,
                                                 unsigned long *hvVer);
char *                  virConnectGetHostname   (virConnectPtr conn);
char *                  virConnectGetURI        (virConnectPtr conn);


/*
 * Capabilities of the connection / driver.
 */

int                     virConnectGetMaxVcpus   (virConnectPtr conn,
                                                 const char *type);
int                     virNodeGetInfo          (virConnectPtr conn,
                                                 virNodeInfoPtr info);
char *                  virConnectGetCapabilities (virConnectPtr conn);

unsigned long long      virNodeGetFreeMemory    (virConnectPtr conn);

int                     virNodeGetSecurityModel (virConnectPtr conn,
                                                 virSecurityModelPtr secmodel);

/*
 * Gather list of running domains
 */
int                     virConnectListDomains   (virConnectPtr conn,
                                                 int *ids,
                                                 int maxids);

/*
 * Number of domains
 */
int                     virConnectNumOfDomains  (virConnectPtr conn);


/*
 * Get connection from domain.
 */
virConnectPtr           virDomainGetConnect     (virDomainPtr domain);

/*
 * Domain creation and destruction
 */
virDomainPtr            virDomainCreateXML      (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);
virDomainPtr            virDomainLookupByName   (virConnectPtr conn,
                                                 const char *name);
virDomainPtr            virDomainLookupByID     (virConnectPtr conn,
                                                 int id);
virDomainPtr            virDomainLookupByUUID   (virConnectPtr conn,
                                                 const unsigned char *uuid);
virDomainPtr            virDomainLookupByUUIDString     (virConnectPtr conn,
                                                        const char *uuid);

int                     virDomainShutdown       (virDomainPtr domain);
int                     virDomainReboot         (virDomainPtr domain,
                                                 unsigned int flags);
int                     virDomainDestroy        (virDomainPtr domain);
int                     virDomainRef            (virDomainPtr domain);
int                     virDomainFree           (virDomainPtr domain);

/*
 * Domain suspend/resume
 */
int                     virDomainSuspend        (virDomainPtr domain);
int                     virDomainResume         (virDomainPtr domain);

/*
 * Domain save/restore
 */
int                     virDomainSave           (virDomainPtr domain,
                                                 const char *to);
int                     virDomainRestore        (virConnectPtr conn,
                                                 const char *from);

/*
 * Domain core dump
 */
int                     virDomainCoreDump       (virDomainPtr domain,
                                                 const char *to,
                                                 int flags);

/*
 * Domain runtime information
 */
int                     virDomainGetInfo        (virDomainPtr domain,
                                                 virDomainInfoPtr info);

/*
 * Return scheduler type in effect 'sedf', 'credit', 'linux'
 */
char *                  virDomainGetSchedulerType(virDomainPtr domain,
                                                 int *nparams);

/*
 * Dynamic control of domains
 */
const char *            virDomainGetName        (virDomainPtr domain);
unsigned int            virDomainGetID          (virDomainPtr domain);
int                     virDomainGetUUID        (virDomainPtr domain,
                                                 unsigned char *uuid);
int                     virDomainGetUUIDString  (virDomainPtr domain,
                                                char *buf);
char *                  virDomainGetOSType      (virDomainPtr domain);
unsigned long           virDomainGetMaxMemory   (virDomainPtr domain);
int                     virDomainSetMaxMemory   (virDomainPtr domain,
                                                 unsigned long memory);
int                     virDomainSetMemory      (virDomainPtr domain,
                                                 unsigned long memory);
int                     virDomainGetMaxVcpus    (virDomainPtr domain);
int                     virDomainGetSecurityLabel (virDomainPtr domain,
                                                   virSecurityLabelPtr seclabel);

/*
 * XML domain description
 */
/**
 * virDomainXMLFlags:
 *
 * Flags available for virDomainGetXMLDesc
 */

typedef enum {
    VIR_DOMAIN_XML_SECURE = 1, /* dump security sensitive information too */
    VIR_DOMAIN_XML_INACTIVE = 2/* dump inactive domain information */
} virDomainXMLFlags;

char *                  virDomainGetXMLDesc     (virDomainPtr domain,
                                                 int flags);


char *                  virConnectDomainXMLFromNative(virConnectPtr conn,
                                                      const char *nativeFormat,
                                                      const char *nativeConfig,
                                                      unsigned int flags);
char *                  virConnectDomainXMLToNative(virConnectPtr conn,
                                                    const char *nativeFormat,
                                                    const char *domainXml,
                                                    unsigned int flags);

int                     virDomainBlockStats     (virDomainPtr dom,
                                                 const char *path,
                                                 virDomainBlockStatsPtr stats,
                                                 size_t size);
int                     virDomainInterfaceStats (virDomainPtr dom,
                                                 const char *path,
                                                 virDomainInterfaceStatsPtr stats,
                                                 size_t size);
int                     virDomainBlockPeek (virDomainPtr dom,
                                            const char *path,
                                            unsigned long long offset,
                                            size_t size,
                                            void *buffer,
                                            unsigned int flags);

/* Memory peeking flags. */
typedef enum {
  VIR_MEMORY_VIRTUAL              = 1, /* addresses are virtual addresses */
  VIR_MEMORY_PHYSICAL             = 2, /* addresses are physical addresses */
} virDomainMemoryFlags;

int                     virDomainMemoryPeek (virDomainPtr dom,
                                             unsigned long long start,
                                             size_t size,
                                             void *buffer,
                                             unsigned int flags);

/*
 * defined but not running domains
 */
virDomainPtr            virDomainDefineXML      (virConnectPtr conn,
                                                 const char *xml);
int                     virDomainUndefine       (virDomainPtr domain);
int                     virConnectNumOfDefinedDomains  (virConnectPtr conn);
int                     virConnectListDefinedDomains (virConnectPtr conn,
                                                 char **const names,
                                                 int maxnames);
int                     virDomainCreate         (virDomainPtr domain);

int                     virDomainGetAutostart   (virDomainPtr domain,
                                                 int *autostart);
int                     virDomainSetAutostart   (virDomainPtr domain,
                                                 int autostart);

/**
 * virVcpuInfo: structure for information about a virtual CPU in a domain.
 */

typedef enum {
    VIR_VCPU_OFFLINE    = 0,    /* the virtual CPU is offline */
    VIR_VCPU_RUNNING    = 1,    /* the virtual CPU is running */
    VIR_VCPU_BLOCKED    = 2,    /* the virtual CPU is blocked on resource */
} virVcpuState;

typedef struct _virVcpuInfo virVcpuInfo;
struct _virVcpuInfo {
    unsigned int number;        /* virtual CPU number */
    int state;                  /* value from virVcpuState */
    unsigned long long cpuTime; /* CPU time used, in nanoseconds */
    int cpu;                    /* real CPU number, or -1 if offline */
};
typedef virVcpuInfo *virVcpuInfoPtr;

int                     virDomainSetVcpus       (virDomainPtr domain,
                                                 unsigned int nvcpus);

int                     virDomainPinVcpu        (virDomainPtr domain,
                                                 unsigned int vcpu,
                                                 unsigned char *cpumap,
                                                 int maplen);

/**
 * VIR_USE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * USE_CPU macro set the bit (CPU usable) of the related cpu in cpumap.
 */

#define VIR_USE_CPU(cpumap,cpu) (cpumap[(cpu)/8] |= (1<<((cpu)%8)))

/**
 * VIR_UNUSE_CPU:
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes) (IN/OUT)
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * USE_CPU macro reset the bit (CPU not usable) of the related cpu in cpumap.
 */

#define VIR_UNUSE_CPU(cpumap,cpu)       (cpumap[(cpu)/8] &= ~(1<<((cpu)%8)))

/**
 * VIR_CPU_MAPLEN:
 * @cpu: number of physical CPUs
 *
 * This macro is to be used in conjunction with virDomainPinVcpu() API.
 * It returns the length (in bytes) required to store the complete
 * CPU map between a single virtual & all physical CPUs of a domain.
 */

#define VIR_CPU_MAPLEN(cpu)      (((cpu)+7)/8)


int                     virDomainGetVcpus       (virDomainPtr domain,
                                                 virVcpuInfoPtr info,
                                                 int maxinfo,
                                                 unsigned char *cpumaps,
                                                 int maplen);

/**
 * VIR_CPU_USABLE:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpu: the physical CPU number
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() API.
 * VIR_CPU_USABLE macro returns a non zero value (true) if the cpu
 * is usable by the vcpu, and 0 otherwise.
 */

#define VIR_CPU_USABLE(cpumaps,maplen,vcpu,cpu) \
        (cpumaps[((vcpu)*(maplen))+((cpu)/8)] & (1<<((cpu)%8)))

/**
 * VIR_COPY_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 * @cpumap: pointer to a cpumap (in 8-bit bytes) (OUT)
 *      This cpumap must be previously allocated by the caller
 *      (ie: malloc(maplen))
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_COPY_CPUMAP macro extract the cpumap of
 * the specified vcpu from cpumaps array and copy it into cpumap to be used
 * later by virDomainPinVcpu() API.
 */
#define VIR_COPY_CPUMAP(cpumaps,maplen,vcpu,cpumap) \
        memcpy(cpumap, &(cpumaps[(vcpu)*(maplen)]), (maplen))


/**
 * VIR_GET_CPUMAP:
 * @cpumaps: pointer to an array of cpumap (in 8-bit bytes) (IN)
 * @maplen: the length (in bytes) of one cpumap
 * @vcpu: the virtual CPU number
 *
 * This macro is to be used in conjunction with virDomainGetVcpus() and
 * virDomainPinVcpu() APIs. VIR_GET_CPUMAP macro returns a pointer to the
 * cpumap of the specified vcpu from cpumaps array.
 */
#define VIR_GET_CPUMAP(cpumaps,maplen,vcpu)     &(cpumaps[(vcpu)*(maplen)])

int virDomainAttachDevice(virDomainPtr domain, const char *xml);
int virDomainDetachDevice(virDomainPtr domain, const char *xml);

/*
 * NUMA support
 */

int                      virNodeGetCellsFreeMemory(virConnectPtr conn,
                                                   unsigned long long *freeMems,
                                                   int startCell,
                                                   int maxCells);

/*
 * Virtual Networks API
 */

/**
 * virNetwork:
 *
 * a virNetwork is a private structure representing a virtual network.
 */
typedef struct _virNetwork virNetwork;

/**
 * virNetworkPtr:
 *
 * a virNetworkPtr is pointer to a virNetwork private structure, this is the
 * type used to reference a virtual network in the API.
 */
typedef virNetwork *virNetworkPtr;

/*
 * Get connection from network.
 */
virConnectPtr           virNetworkGetConnect    (virNetworkPtr network);

/*
 * List active networks
 */
int                     virConnectNumOfNetworks (virConnectPtr conn);
int                     virConnectListNetworks  (virConnectPtr conn,
                                                 char **const names,
                                                 int maxnames);

/*
 * List inactive networks
 */
int                     virConnectNumOfDefinedNetworks  (virConnectPtr conn);
int                     virConnectListDefinedNetworks   (virConnectPtr conn,
                                                         char **const names,
                                                         int maxnames);

/*
 * Lookup network by name or uuid
 */
virNetworkPtr           virNetworkLookupByName          (virConnectPtr conn,
                                                         const char *name);
virNetworkPtr           virNetworkLookupByUUID          (virConnectPtr conn,
                                                         const unsigned char *uuid);
virNetworkPtr           virNetworkLookupByUUIDString    (virConnectPtr conn,
                                                         const char *uuid);

/*
 * Create active transient network
 */
virNetworkPtr           virNetworkCreateXML     (virConnectPtr conn,
                                                 const char *xmlDesc);

/*
 * Define inactive persistent network
 */
virNetworkPtr           virNetworkDefineXML     (virConnectPtr conn,
                                                 const char *xmlDesc);

/*
 * Delete persistent network
 */
int                     virNetworkUndefine      (virNetworkPtr network);

/*
 * Activate persistent network
 */
int                     virNetworkCreate        (virNetworkPtr network);

/*
 * Network destroy/free
 */
int                     virNetworkDestroy       (virNetworkPtr network);
int                     virNetworkRef           (virNetworkPtr network);
int                     virNetworkFree          (virNetworkPtr network);

/*
 * Network information
 */
const char*             virNetworkGetName       (virNetworkPtr network);
int                     virNetworkGetUUID       (virNetworkPtr network,
                                                 unsigned char *uuid);
int                     virNetworkGetUUIDString (virNetworkPtr network,
                                                 char *buf);
char *                  virNetworkGetXMLDesc    (virNetworkPtr network,
                                                 int flags);
char *                  virNetworkGetBridgeName (virNetworkPtr network);

int                     virNetworkGetAutostart  (virNetworkPtr network,
                                                 int *autostart);
int                     virNetworkSetAutostart  (virNetworkPtr network,
                                                 int autostart);

/*
 * Physical host interface configuration API
 */

/**
 * virInterface:
 *
 * a virInterface is a private structure representing a virtual interface.
 */
typedef struct _virInterface virInterface;

/**
 * virInterfacePtr:
 *
 * a virInterfacePtr is pointer to a virInterface private structure, this is the
 * type used to reference a virtual interface in the API.
 */
typedef virInterface *virInterfacePtr;

virConnectPtr           virInterfaceGetConnect    (virInterfacePtr iface);

int                     virConnectNumOfInterfaces (virConnectPtr conn);
int                     virConnectListInterfaces  (virConnectPtr conn,
                                                   char **const names,
                                                   int maxnames);

int                     virConnectNumOfDefinedInterfaces (virConnectPtr conn);
int                     virConnectListDefinedInterfaces  (virConnectPtr conn,
                                                          char **const names,
                                                          int maxnames);

virInterfacePtr         virInterfaceLookupByName  (virConnectPtr conn,
                                                   const char *name);
virInterfacePtr         virInterfaceLookupByMACString (virConnectPtr conn,
                                                       const char *mac);

const char*             virInterfaceGetName       (virInterfacePtr iface);
const char*             virInterfaceGetMACString  (virInterfacePtr iface);

char *                  virInterfaceGetXMLDesc    (virInterfacePtr iface,
                                                   unsigned int flags);
virInterfacePtr         virInterfaceDefineXML     (virConnectPtr conn,
                                                   const char *xmlDesc,
                                                   unsigned int flags);

int                     virInterfaceUndefine      (virInterfacePtr iface);

int                     virInterfaceCreate        (virInterfacePtr iface,
                                                   unsigned int flags);

int                     virInterfaceDestroy       (virInterfacePtr iface,
                                                   unsigned int flags);

int                     virInterfaceRef           (virInterfacePtr iface);
int                     virInterfaceFree          (virInterfacePtr iface);

/**
 * virStoragePool:
 *
 * a virStoragePool is a private structure representing a storage pool
 */
typedef struct _virStoragePool virStoragePool;

/**
 * virStoragePoolPtr:
 *
 * a virStoragePoolPtr is pointer to a virStoragePool private structure, this is the
 * type used to reference a storage pool in the API.
 */
typedef virStoragePool *virStoragePoolPtr;


typedef enum {
  VIR_STORAGE_POOL_INACTIVE = 0, /* Not running */
  VIR_STORAGE_POOL_BUILDING = 1, /* Initializing pool, not available */
  VIR_STORAGE_POOL_RUNNING = 2,  /* Running normally */
  VIR_STORAGE_POOL_DEGRADED = 3, /* Running degraded */
} virStoragePoolState;


typedef enum {
  VIR_STORAGE_POOL_BUILD_NEW  = 0,   /* Regular build from scratch */
  VIR_STORAGE_POOL_BUILD_REPAIR = 1, /* Repair / reinitialize */
  VIR_STORAGE_POOL_BUILD_RESIZE = 2  /* Extend existing pool */
} virStoragePoolBuildFlags;

typedef enum {
  VIR_STORAGE_POOL_DELETE_NORMAL = 0, /* Delete metadata only    (fast) */
  VIR_STORAGE_POOL_DELETE_ZEROED = 1,  /* Clear all data to zeros (slow) */
} virStoragePoolDeleteFlags;

typedef struct _virStoragePoolInfo virStoragePoolInfo;

struct _virStoragePoolInfo {
  int state;                     /* virStoragePoolState flags */
  unsigned long long capacity;   /* Logical size bytes */
  unsigned long long allocation; /* Current allocation bytes */
  unsigned long long available;  /* Remaining free space bytes */
};

typedef virStoragePoolInfo *virStoragePoolInfoPtr;


/**
 * virStorageVol:
 *
 * a virStorageVol is a private structure representing a storage volume
 */
typedef struct _virStorageVol virStorageVol;

/**
 * virStorageVolPtr:
 *
 * a virStorageVolPtr is pointer to a virStorageVol private structure, this is the
 * type used to reference a storage volume in the API.
 */
typedef virStorageVol *virStorageVolPtr;


typedef enum {
  VIR_STORAGE_VOL_FILE = 0,     /* Regular file based volumes */
  VIR_STORAGE_VOL_BLOCK = 1,    /* Block based volumes */
} virStorageVolType;

typedef enum {
  VIR_STORAGE_VOL_DELETE_NORMAL = 0, /* Delete metadata only    (fast) */
  VIR_STORAGE_VOL_DELETE_ZEROED = 1,  /* Clear all data to zeros (slow) */
} virStorageVolDeleteFlags;

typedef struct _virStorageVolInfo virStorageVolInfo;

struct _virStorageVolInfo {
  int type;                      /* virStorageVolType flags */
  unsigned long long capacity;   /* Logical size bytes */
  unsigned long long allocation; /* Current allocation bytes */
};

typedef virStorageVolInfo *virStorageVolInfoPtr;

/*
 * Get connection from pool.
 */
virConnectPtr           virStoragePoolGetConnect        (virStoragePoolPtr pool);

/*
 * List active storage pools
 */
int                     virConnectNumOfStoragePools     (virConnectPtr conn);
int                     virConnectListStoragePools      (virConnectPtr conn,
                                                         char **const names,
                                                         int maxnames);

/*
 * List inactive storage pools
 */
int                     virConnectNumOfDefinedStoragePools(virConnectPtr conn);
int                     virConnectListDefinedStoragePools(virConnectPtr conn,
                                                          char **const names,
                                                          int maxnames);

/*
 * Query a host for storage pools of a particular type
 */
char *                  virConnectFindStoragePoolSources(virConnectPtr conn,
                                                         const char *type,
                                                         const char *srcSpec,
                                                         unsigned int flags);

/*
 * Lookup pool by name or uuid
 */
virStoragePoolPtr       virStoragePoolLookupByName      (virConnectPtr conn,
                                                         const char *name);
virStoragePoolPtr       virStoragePoolLookupByUUID      (virConnectPtr conn,
                                                         const unsigned char *uuid);
virStoragePoolPtr       virStoragePoolLookupByUUIDString(virConnectPtr conn,
                                                         const char *uuid);
virStoragePoolPtr       virStoragePoolLookupByVolume    (virStorageVolPtr vol);

/*
 * Creating/destroying pools
 */
virStoragePoolPtr       virStoragePoolCreateXML         (virConnectPtr conn,
                                                         const char *xmlDesc,
                                                         unsigned int flags);
virStoragePoolPtr       virStoragePoolDefineXML         (virConnectPtr conn,
                                                         const char *xmlDesc,
                                                         unsigned int flags);
int                     virStoragePoolBuild             (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolUndefine          (virStoragePoolPtr pool);
int                     virStoragePoolCreate            (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolDestroy           (virStoragePoolPtr pool);
int                     virStoragePoolDelete            (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolRef               (virStoragePoolPtr pool);
int                     virStoragePoolFree              (virStoragePoolPtr pool);
int                     virStoragePoolRefresh           (virStoragePoolPtr pool,
                                                         unsigned int flags);

/*
 * StoragePool information
 */
const char*             virStoragePoolGetName           (virStoragePoolPtr pool);
int                     virStoragePoolGetUUID           (virStoragePoolPtr pool,
                                                         unsigned char *uuid);
int                     virStoragePoolGetUUIDString     (virStoragePoolPtr pool,
                                                         char *buf);

int                     virStoragePoolGetInfo           (virStoragePoolPtr vol,
                                                         virStoragePoolInfoPtr info);

char *                  virStoragePoolGetXMLDesc        (virStoragePoolPtr pool,
                                                         unsigned int flags);

int                     virStoragePoolGetAutostart      (virStoragePoolPtr pool,
                                                         int *autostart);
int                     virStoragePoolSetAutostart      (virStoragePoolPtr pool,
                                                         int autostart);

/*
 * List/lookup storage volumes within a pool
 */
int                     virStoragePoolNumOfVolumes      (virStoragePoolPtr pool);
int                     virStoragePoolListVolumes       (virStoragePoolPtr pool,
                                                         char **const names,
                                                         int maxnames);

virConnectPtr           virStorageVolGetConnect         (virStorageVolPtr vol);

/*
 * Lookup volumes based on various attributes
 */
virStorageVolPtr        virStorageVolLookupByName       (virStoragePoolPtr pool,
                                                         const char *name);
virStorageVolPtr        virStorageVolLookupByKey        (virConnectPtr conn,
                                                         const char *key);
virStorageVolPtr        virStorageVolLookupByPath       (virConnectPtr conn,
                                                         const char *path);


const char*             virStorageVolGetName            (virStorageVolPtr vol);
const char*             virStorageVolGetKey             (virStorageVolPtr vol);

virStorageVolPtr        virStorageVolCreateXML          (virStoragePoolPtr pool,
                                                         const char *xmldesc,
                                                         unsigned int flags);
virStorageVolPtr        virStorageVolCreateXMLFrom      (virStoragePoolPtr pool,
                                                         const char *xmldesc,
                                                         virStorageVolPtr clonevol,
                                                         unsigned int flags);
int                     virStorageVolDelete             (virStorageVolPtr vol,
                                                         unsigned int flags);
int                     virStorageVolRef                (virStorageVolPtr vol);
int                     virStorageVolFree               (virStorageVolPtr vol);

int                     virStorageVolGetInfo            (virStorageVolPtr vol,
                                                         virStorageVolInfoPtr info);
char *                  virStorageVolGetXMLDesc         (virStorageVolPtr pool,
                                                         unsigned int flags);

char *                  virStorageVolGetPath            (virStorageVolPtr vol);

/*
 * Deprecated calls
 */
virDomainPtr            virDomainCreateLinux    (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);

/*
 * Host device enumeration
 */

/**
 * virNodeDevice:
 *
 * A virNodeDevice contains a node (host) device details.
 */

typedef struct _virNodeDevice virNodeDevice;

/**
 * virNodeDevicePtr:
 *
 * A virNodeDevicePtr is a pointer to a virNodeDevice structure.  Get
 * one via virNodeDeviceLookupByKey, virNodeDeviceLookupByName, or
 * virNodeDeviceCreate.  Be sure to Call virNodeDeviceFree when done
 * using a virNodeDevicePtr obtained from any of the above functions to
 * avoid leaking memory.
 */

typedef virNodeDevice *virNodeDevicePtr;


int                     virNodeNumOfDevices     (virConnectPtr conn,
                                                 const char *cap,
                                                 unsigned int flags);

int                     virNodeListDevices      (virConnectPtr conn,
                                                 const char *cap,
                                                 char **const names,
                                                 int maxnames,
                                                 unsigned int flags);

virNodeDevicePtr        virNodeDeviceLookupByName (virConnectPtr conn,
                                                   const char *name);

const char *            virNodeDeviceGetName     (virNodeDevicePtr dev);

const char *            virNodeDeviceGetParent   (virNodeDevicePtr dev);

int                     virNodeDeviceNumOfCaps   (virNodeDevicePtr dev);

int                     virNodeDeviceListCaps    (virNodeDevicePtr dev,
                                                  char **const names,
                                                  int maxnames);

char *                  virNodeDeviceGetXMLDesc (virNodeDevicePtr dev,
                                                 unsigned int flags);

int                     virNodeDeviceRef        (virNodeDevicePtr dev);
int                     virNodeDeviceFree       (virNodeDevicePtr dev);

int                     virNodeDeviceDettach    (virNodeDevicePtr dev);
int                     virNodeDeviceReAttach   (virNodeDevicePtr dev);
int                     virNodeDeviceReset      (virNodeDevicePtr dev);

virNodeDevicePtr        virNodeDeviceCreateXML  (virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);

int                     virNodeDeviceDestroy    (virNodeDevicePtr dev);

/*
 * Domain Event Notification
 */

/**
 * virDomainEventType:
 *
 * a virDomainEventType is emitted during domain lifecycle events
 */
typedef enum {
      VIR_DOMAIN_EVENT_DEFINED = 0,
      VIR_DOMAIN_EVENT_UNDEFINED = 1,
      VIR_DOMAIN_EVENT_STARTED = 2,
      VIR_DOMAIN_EVENT_SUSPENDED = 3,
      VIR_DOMAIN_EVENT_RESUMED = 4,
      VIR_DOMAIN_EVENT_STOPPED = 5,
} virDomainEventType;

/**
 * virDomainEventDefinedDetailType:
 *
 * Details on the caused of the 'defined' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_DEFINED_ADDED = 0,     /* Newly created config file */
    VIR_DOMAIN_EVENT_DEFINED_UPDATED = 1,   /* Changed config file */
} virDomainEventDefinedDetailType;

/**
 * virDomainEventUndefinedDetailType:
 *
 * Details on the caused of the 'undefined' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_UNDEFINED_REMOVED = 0, /* Deleted the config file */
} virDomainEventUndefinedDetailType;

/**
 * virDomainEventStartedDetailType:
 *
 * Details on the caused of the 'started' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_STARTED_BOOTED = 0,   /* Normal startup from boot */
    VIR_DOMAIN_EVENT_STARTED_MIGRATED = 1, /* Incoming migration from another host */
    VIR_DOMAIN_EVENT_STARTED_RESTORED = 2, /* Restored from a state file */
} virDomainEventStartedDetailType;

/**
 * virDomainEventSuspendedDetailType:
 *
 * Details on the caused of the 'suspended' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_SUSPENDED_PAUSED = 0,   /* Normal suspend due to admin pause */
    VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED = 1, /* Suspended for offline migration */
} virDomainEventSuspendedDetailType;

/**
 * virDomainEventResumedDetailType:
 *
 * Details on the caused of the 'resumed' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_RESUMED_UNPAUSED = 0,   /* Normal resume due to admin unpause */
    VIR_DOMAIN_EVENT_RESUMED_MIGRATED = 1,   /* Resumed for completion of migration */
} virDomainEventResumedDetailType;

/**
 * virDomainEventStoppedDetailType:
 *
 * Details on the caused of the 'stopped' lifecycle event
 */
typedef enum {
    VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN = 0,  /* Normal shutdown */
    VIR_DOMAIN_EVENT_STOPPED_DESTROYED = 1, /* Forced poweroff from host */
    VIR_DOMAIN_EVENT_STOPPED_CRASHED = 2,   /* Guest crashed */
    VIR_DOMAIN_EVENT_STOPPED_MIGRATED = 3,  /* Migrated off to another host */
    VIR_DOMAIN_EVENT_STOPPED_SAVED = 4,     /* Saved to a state file */
    VIR_DOMAIN_EVENT_STOPPED_FAILED = 5,    /* Host emulator/mgmt failed */
} virDomainEventStoppedDetailType;


/**
 * virConnectDomainEventCallback:
 * @conn: virConnect connection
 * @dom: The domain on which the event occured
 * @event: The specfic virDomainEventType which occured
 * @detail: event specific detail information
 * @opaque: opaque user data
 *
 * A callback function to be registered, and called when a domain event occurs
 */
typedef int (*virConnectDomainEventCallback)(virConnectPtr conn,
                                             virDomainPtr dom,
                                             int event,
                                             int detail,
                                             void *opaque);

typedef void (*virFreeCallback)(void *opaque);

int virConnectDomainEventRegister(virConnectPtr conn,
                                  virConnectDomainEventCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb);

int virConnectDomainEventDeregister(virConnectPtr conn,
                                    virConnectDomainEventCallback cb);

/*
 * Events Implementation
 */

/**
 * virEventHandleType:
 *
 * a virEventHandleType is used similar to POLLxxx FD events, but is specific
 * to libvirt. A client app must translate to, and from POLL events when using
 * this construct.
 */
typedef enum {
    VIR_EVENT_HANDLE_READABLE  = (1 << 0),
    VIR_EVENT_HANDLE_WRITABLE  = (1 << 1),
    VIR_EVENT_HANDLE_ERROR     = (1 << 2),
    VIR_EVENT_HANDLE_HANGUP    = (1 << 3),
} virEventHandleType;

/**
 * virEventHandleCallback:
 *
 * @watch: watch on which the event occurred
 * @fd: file handle on which the event occurred
 * @events: bitset of events from virEventHandleType constants
 * @opaque: user data registered with handle
 *
 * Callback for receiving file handle events. The callback will
 * be invoked once for each event which is pending.
 */
typedef void (*virEventHandleCallback)(int watch, int fd, int events, void *opaque);

/**
 * virEventAddHandleFunc:
 * @fd: file descriptor to listen on
 * @event: bitset of events on which to fire the callback
 * @cb: the callback to be called when an event occurrs
 * @opaque: user data to pass to the callback
 * @ff: the callback invoked to free opaque data blob
 *
 * Part of the EventImpl, this callback Adds a file handle callback to
 * listen for specific events. The same file handle can be registered
 * multiple times provided the requested event sets are non-overlapping
 *
 * If the opaque user data requires free'ing when the handle
 * is unregistered, then a 2nd callback can be supplied for
 * this purpose.
 *
 * Returns a handle watch number to be used for updating
 * and unregistering for events
 */
typedef int (*virEventAddHandleFunc)(int fd, int event,
                                     virEventHandleCallback cb,
                                     void *opaque,
                                     virFreeCallback ff);

/**
 * virEventUpdateHandleFunc:
 * @watch: file descriptor watch to modify
 * @event: new events to listen on
 *
 * Part of the EventImpl, this user-provided callback is notified when
 * events to listen on change
 */
typedef void (*virEventUpdateHandleFunc)(int watch, int event);

/**
 * virEventRemoveHandleFunc:
 * @watch: file descriptor watch to stop listening on
 *
 * Part of the EventImpl, this user-provided callback is notified when
 * an fd is no longer being listened on.
 *
 * If a virEventHandleFreeFunc was supplied when the handle was
 * registered, it will be invoked some time during, or after this
 * function call, when it is safe to release the user data.
 */
typedef int (*virEventRemoveHandleFunc)(int watch);

/**
 * virEventTimeoutCallback:
 *
 * @timer: timer id emitting the event
 * @opaque: user data registered with handle
 *
 * callback for receiving timer events
 */
typedef void (*virEventTimeoutCallback)(int timer, void *opaque);

/**
 * virEventAddTimeoutFunc:
 * @timeout: The timeout to monitor
 * @cb: the callback to call when timeout has expired
 * @opaque: user data to pass to the callback
 * @ff: the callback invoked to free opaque data blob
 *
 * Part of the EventImpl, this user-defined callback handles adding an
 * event timeout.
 *
 * If the opaque user data requires free'ing when the handle
 * is unregistered, then a 2nd callback can be supplied for
 * this purpose.
 *
 * Returns a timer value
 */
typedef int (*virEventAddTimeoutFunc)(int timeout,
                                      virEventTimeoutCallback cb,
                                      void *opaque,
                                      virFreeCallback ff);

/**
 * virEventUpdateTimeoutFunc:
 * @timer: the timer to modify
 * @timeout: the new timeout value
 *
 * Part of the EventImpl, this user-defined callback updates an
 * event timeout.
 */
typedef void (*virEventUpdateTimeoutFunc)(int timer, int timeout);

/**
 * virEventRemoveTimeoutFunc:
 * @timer: the timer to remove
 *
 * Part of the EventImpl, this user-defined callback removes a timer
 *
 * If a virEventTimeoutFreeFunc was supplied when the handle was
 * registered, it will be invoked some time during, or after this
 * function call, when it is safe to release the user data.
 *
 * Returns 0 on success, -1 on failure
 */
typedef int (*virEventRemoveTimeoutFunc)(int timer);

void virEventRegisterImpl(virEventAddHandleFunc addHandle,
                          virEventUpdateHandleFunc updateHandle,
                          virEventRemoveHandleFunc removeHandle,
                          virEventAddTimeoutFunc addTimeout,
                          virEventUpdateTimeoutFunc updateTimeout,
                          virEventRemoveTimeoutFunc removeTimeout);

/*
 * Secret manipulation API
 */

/**
 * virSecret:
 *
 * A virSecret stores a secret value (e.g. a passphrase or encryption key)
 * and associated metadata.
 */
typedef struct _virSecret virSecret;
typedef virSecret *virSecretPtr;

typedef enum {
    VIR_SECRET_USAGE_TYPE_NONE = 0,
    VIR_SECRET_USAGE_TYPE_VOLUME = 1,
    /* Expect more owner types later... */
} virSecretUsageType;

virConnectPtr           virSecretGetConnect     (virSecretPtr secret);
int                     virConnectNumOfSecrets  (virConnectPtr conn);
int                     virConnectListSecrets   (virConnectPtr conn,
                                                 char **uuids,
                                                 int maxuuids);
virSecretPtr            virSecretLookupByUUID(virConnectPtr conn,
                                              const unsigned char *uuid);
virSecretPtr            virSecretLookupByUUIDString(virConnectPtr conn,
                                                    const char *uuid);
virSecretPtr            virSecretLookupByUsage(virConnectPtr conn,
                                               int usageType,
                                               const char *usageID);
virSecretPtr            virSecretDefineXML      (virConnectPtr conn,
                                                 const char *xml,
                                                 unsigned int flags);
int                     virSecretGetUUID        (virSecretPtr secret,
                                                 unsigned char *buf);
int                     virSecretGetUUIDString  (virSecretPtr secret,
                                                 char *buf);
int                     virSecretGetUsageType   (virSecretPtr secret);
const char *            virSecretGetUsageID     (virSecretPtr secret);
char *                  virSecretGetXMLDesc     (virSecretPtr secret,
                                                 unsigned int flags);
int                     virSecretSetValue       (virSecretPtr secret,
                                                 const unsigned char *value,
                                                 size_t value_size,
                                                 unsigned int flags);
unsigned char *         virSecretGetValue       (virSecretPtr secret,
                                                 size_t *value_size,
                                                 unsigned int flags);
int                     virSecretUndefine       (virSecretPtr secret);
int                     virSecretRef            (virSecretPtr secret);
int                     virSecretFree           (virSecretPtr secret);

#ifdef __cplusplus
}
#endif

#endif /* __VIR_VIRLIB_H__ */
