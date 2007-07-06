/*
 * xen_internal.c: direct access to Xen hypervisor level
 *
 * Copyright (C) 2005, 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifdef WITH_XEN

#include <stdio.h>
#include <string.h>
/* required for uint8_t, uint32_t, etc ... */
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <stdint.h>
#include <regex.h>
#include <errno.h>
#include <sys/utsname.h>

/* required for dom0_getdomaininfo_t */
#include <xen/dom0_ops.h>
#include <xen/version.h>
#include <xen/xen.h>
#include <xen/linux/privcmd.h>

/* required for shutdown flags */
#include <xen/sched.h>

#include "buf.h"

/* #define DEBUG */
/*
 * so far there is 2 versions of the structures usable for doing
 * hypervisor calls.
 */
/* the old one */
typedef struct v0_hypercall_struct {
    unsigned long op;
    unsigned long arg[5];
} v0_hypercall_t;
#define XEN_V0_IOCTL_HYPERCALL_CMD \
        _IOC(_IOC_NONE, 'P', 0, sizeof(v0_hypercall_t))

/* the new one */
typedef struct v1_hypercall_struct
{
    uint64_t op;
    uint64_t arg[5];
} v1_hypercall_t;
#define XEN_V1_IOCTL_HYPERCALL_CMD                  \
    _IOC(_IOC_NONE, 'P', 0, sizeof(v1_hypercall_t))

typedef v1_hypercall_t hypercall_t;

#ifndef __HYPERVISOR_sysctl
#define __HYPERVISOR_sysctl 35
#endif
#ifndef __HYPERVISOR_domctl
#define __HYPERVISOR_domctl 36
#endif

static int xen_ioctl_hypercall_cmd = 0;
static int initialized = 0;
static int in_init = 0;
static int hv_version = 0;
static int hypervisor_version = 2;
static int sys_interface_version = -1;
static int dom_interface_version = -1;
static int kb_per_pages = 0;

/* Regular expressions used by xenHypervisorGetCapabilities, and
 * compiled once by xenHypervisorInit.  Note that these are POSIX.2
 * extended regular expressions (regex(7)).
 */
static const char *flags_hvm_re = "^flags[[:blank:]]+:.* (vmx|svm)[[:space:]]";
static regex_t flags_hvm_rec;
static const char *flags_pae_re = "^flags[[:blank:]]+:.* pae[[:space:]]";
static regex_t flags_pae_rec;
static const char *xen_cap_re = "(xen|hvm)-[[:digit:]]+\\.[[:digit:]]+-(x86_32|x86_64|ia64|powerpc64)(p|be)?";
static regex_t xen_cap_rec;

/*
 * The content of the structures for a getdomaininfolist system hypercall
 */
#ifndef DOMFLAGS_DYING
#define DOMFLAGS_DYING     (1<<0) /* Domain is scheduled to die.             */
#define DOMFLAGS_HVM       (1<<1) /* Domain is HVM                           */
#define DOMFLAGS_SHUTDOWN  (1<<2) /* The guest OS has shut down.             */
#define DOMFLAGS_PAUSED    (1<<3) /* Currently paused by control software.   */
#define DOMFLAGS_BLOCKED   (1<<4) /* Currently blocked pending an event.     */
#define DOMFLAGS_RUNNING   (1<<5) /* Domain is currently running.            */
#define DOMFLAGS_CPUMASK      255 /* CPU to which this domain is bound.      */
#define DOMFLAGS_CPUSHIFT       8
#define DOMFLAGS_SHUTDOWNMASK 255 /* DOMFLAGS_SHUTDOWN guest-supplied code.  */
#define DOMFLAGS_SHUTDOWNSHIFT 16
#endif

/*
 * These flags explain why a system is in the state of "shutdown".  Normally,
 * They are defined in xen/sched.h
 */
#ifndef SHUTDOWN_poweroff
#define SHUTDOWN_poweroff   0  /* Domain exited normally. Clean up and kill. */
#define SHUTDOWN_reboot     1  /* Clean up, kill, and then restart.          */
#define SHUTDOWN_suspend    2  /* Clean up, save suspend info, kill.         */
#define SHUTDOWN_crash      3  /* Tell controller we've crashed.             */
#endif

#define XEN_V0_OP_GETDOMAININFOLIST	38
#define XEN_V1_OP_GETDOMAININFOLIST	38
#define XEN_V2_OP_GETDOMAININFOLIST	6

struct xen_v0_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* falgs, see before */
    uint64_t tot_pages;	/* total number of pages used */
    uint64_t max_pages;	/* maximum number of pages allowed */
    unsigned long shared_info_frame; /* MFN of shared_info struct */
    uint64_t cpu_time;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
};
typedef struct xen_v0_getdomaininfo xen_v0_getdomaininfo;

struct xen_v2_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* falgs, see before */
    uint64_t tot_pages;	/* total number of pages used */
    uint64_t max_pages;	/* maximum number of pages allowed */
    uint64_t shared_info_frame; /* MFN of shared_info struct */
    uint64_t cpu_time;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
};
typedef struct xen_v2_getdomaininfo xen_v2_getdomaininfo;


/* As of Hypervisor Call v2,  DomCtl v5 we are now 8-byte aligned
   even on 32-bit archs when dealing with uint64_t */
#define ALIGN_64 __attribute__((aligned(8)))

struct xen_v2d5_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* falgs, see before */
    uint64_t tot_pages ALIGN_64;	/* total number of pages used */
    uint64_t max_pages ALIGN_64;	/* maximum number of pages allowed */
    uint64_t shared_info_frame ALIGN_64; /* MFN of shared_info struct */
    uint64_t cpu_time ALIGN_64;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
};
typedef struct xen_v2d5_getdomaininfo xen_v2d5_getdomaininfo;

union xen_getdomaininfo {
    struct xen_v0_getdomaininfo v0;
    struct xen_v2_getdomaininfo v2;
    struct xen_v2d5_getdomaininfo v2d5;
};
typedef union xen_getdomaininfo xen_getdomaininfo;

union xen_getdomaininfolist {
    struct xen_v0_getdomaininfo *v0;
    struct xen_v2_getdomaininfo *v2;
    struct xen_v2d5_getdomaininfo *v2d5;
};
typedef union xen_getdomaininfolist xen_getdomaininfolist;


struct xen_v2_getschedulerid {
    uint32_t sched_id; /* Get Scheduler ID from Xen */
};
typedef struct xen_v2_getschedulerid xen_v2_getschedulerid;


union xen_getschedulerid {
    struct xen_v2_getschedulerid *v2;
};
typedef union xen_getschedulerid xen_getschedulerid;


#define XEN_GETDOMAININFOLIST_ALLOC(domlist, size)                      \
    (hypervisor_version < 2 ?                                           \
     ((domlist.v0 = malloc(sizeof(xen_v0_getdomaininfo)*(size))) != NULL) : \
     (dom_interface_version < 5 ?                                       \
      ((domlist.v2 = malloc(sizeof(xen_v2_getdomaininfo)*(size))) != NULL) : \
      ((domlist.v2d5 = malloc(sizeof(xen_v2d5_getdomaininfo)*(size))) != NULL)))

#define XEN_GETDOMAININFOLIST_FREE(domlist)        \
    (hypervisor_version < 2 ?                      \
     free(domlist.v0) :                            \
     (dom_interface_version < 5 ?                  \
      free(domlist.v2) :                           \
      free(domlist.v2d5)))

#define XEN_GETDOMAININFOLIST_CLEAR(domlist, size)                     \
    (hypervisor_version < 2 ?                                          \
     memset(domlist.v0, 0, sizeof(xen_v0_getdomaininfo) * size) :      \
     (dom_interface_version < 5 ?                                      \
      memset(domlist.v2, 0, sizeof(xen_v2_getdomaininfo) * size) :     \
      memset(domlist.v2d5, 0, sizeof(xen_v2d5_getdomaininfo) * size)))

#define XEN_GETDOMAININFOLIST_DOMAIN(domlist, n)    \
    (hypervisor_version < 2 ?                       \
     domlist.v0[n].domain :                         \
     (dom_interface_version < 5 ?                   \
      domlist.v2[n].domain :                        \
      domlist.v2d5[n].domain))

#define XEN_GETDOMAININFOLIST_DATA(domlist)        \
    (hypervisor_version < 2 ?                      \
     (void*)(domlist->v0) :                        \
     (dom_interface_version < 5 ?                  \
      (void*)(domlist->v2) :                       \
      (void*)(domlist->v2d5)))

#define XEN_GETDOMAININFO_SIZE                     \
    (hypervisor_version < 2 ?                      \
     sizeof(xen_v0_getdomaininfo) :                \
     (dom_interface_version < 5 ?                  \
      sizeof(xen_v2_getdomaininfo) :               \
      sizeof(xen_v2d5_getdomaininfo)))

#define XEN_GETDOMAININFO_CLEAR(dominfo)                           \
    (hypervisor_version < 2 ?                                      \
     memset(&(dominfo.v0), 0, sizeof(xen_v0_getdomaininfo)) :      \
     (dom_interface_version < 5 ?                                  \
      memset(&(dominfo.v2), 0, sizeof(xen_v2_getdomaininfo)) :     \
      memset(&(dominfo.v2d5), 0, sizeof(xen_v2d5_getdomaininfo))))

#define XEN_GETDOMAININFO_DOMAIN(dominfo)       \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.domain :                        \
     (dom_interface_version < 5 ?               \
      dominfo.v2.domain :                       \
      dominfo.v2d5.domain))

#define XEN_GETDOMAININFO_CPUTIME(dominfo)      \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.cpu_time :                      \
     (dom_interface_version < 5 ?               \
      dominfo.v2.cpu_time :                     \
      dominfo.v2d5.cpu_time))

#define XEN_GETDOMAININFO_CPUCOUNT(dominfo)     \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.nr_online_vcpus :               \
     (dom_interface_version < 5 ?               \
      dominfo.v2.nr_online_vcpus :              \
      dominfo.v2d5.nr_online_vcpus))

#define XEN_GETDOMAININFO_MAXCPUID(dominfo)  \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.max_vcpu_id :                   \
     (dom_interface_version < 5 ?               \
      dominfo.v2.max_vcpu_id :                  \
      dominfo.v2d5.max_vcpu_id))

#define XEN_GETDOMAININFO_FLAGS(dominfo)        \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.flags :                         \
     (dom_interface_version < 5 ?               \
      dominfo.v2.flags :                        \
      dominfo.v2d5.flags))

#define XEN_GETDOMAININFO_TOT_PAGES(dominfo)    \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.tot_pages :                     \
     (dom_interface_version < 5 ?               \
      dominfo.v2.tot_pages :                    \
      dominfo.v2d5.tot_pages))

#define XEN_GETDOMAININFO_MAX_PAGES(dominfo)    \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.max_pages :                     \
     (dom_interface_version < 5 ?               \
      dominfo.v2.max_pages :                    \
      dominfo.v2d5.max_pages))



struct xen_v0_getdomaininfolistop {
    domid_t   first_domain;
    uint32_t  max_domains;
    struct xen_v0_getdomaininfo *buffer;
    uint32_t  num_domains;
};
typedef struct xen_v0_getdomaininfolistop xen_v0_getdomaininfolistop;


struct xen_v2_getdomaininfolistop {
    domid_t   first_domain;
    uint32_t  max_domains;
    struct xen_v2_getdomaininfo *buffer;
    uint32_t  num_domains;
};
typedef struct xen_v2_getdomaininfolistop xen_v2_getdomaininfolistop;

/* As of HV version 2, sysctl version 3 the *buffer pointer is 64-bit aligned */
struct xen_v2s3_getdomaininfolistop {
    domid_t   first_domain;
    uint32_t  max_domains;
    union {
        struct xen_v2d5_getdomaininfo *v;
        uint64_t pad ALIGN_64;
    } buffer;
    uint32_t  num_domains;
};
typedef struct xen_v2s3_getdomaininfolistop xen_v2s3_getdomaininfolistop;



struct xen_v0_domainop {
    domid_t   domain;
};
typedef struct xen_v0_domainop xen_v0_domainop;

/*
 * The informations for a destroydomain system hypercall
 */
#define XEN_V0_OP_DESTROYDOMAIN	9
#define XEN_V1_OP_DESTROYDOMAIN	9
#define XEN_V2_OP_DESTROYDOMAIN	2

/*
 * The informations for a pausedomain system hypercall
 */
#define XEN_V0_OP_PAUSEDOMAIN	10
#define XEN_V1_OP_PAUSEDOMAIN	10
#define XEN_V2_OP_PAUSEDOMAIN	3

/*
 * The informations for an unpausedomain system hypercall
 */
#define XEN_V0_OP_UNPAUSEDOMAIN	11
#define XEN_V1_OP_UNPAUSEDOMAIN	11
#define XEN_V2_OP_UNPAUSEDOMAIN	4

/*
 * The informations for an setmaxmem system hypercall
 */
#define XEN_V0_OP_SETMAXMEM	28
#define XEN_V1_OP_SETMAXMEM	28
#define XEN_V2_OP_SETMAXMEM	11

struct xen_v0_setmaxmem {
    domid_t	domain;
    uint64_t	maxmem;
};
typedef struct xen_v0_setmaxmem xen_v0_setmaxmem;
typedef struct xen_v0_setmaxmem xen_v1_setmaxmem;

struct xen_v2_setmaxmem {
    uint64_t	maxmem;
};
typedef struct xen_v2_setmaxmem xen_v2_setmaxmem;

struct xen_v2d5_setmaxmem {
    uint64_t	maxmem ALIGN_64;
};
typedef struct xen_v2d5_setmaxmem xen_v2d5_setmaxmem;

/*
 * The informations for an setmaxvcpu system hypercall
 */
#define XEN_V0_OP_SETMAXVCPU	41
#define XEN_V1_OP_SETMAXVCPU	41
#define XEN_V2_OP_SETMAXVCPU	15

struct xen_v0_setmaxvcpu {
    domid_t	domain;
    uint32_t	maxvcpu;
};
typedef struct xen_v0_setmaxvcpu xen_v0_setmaxvcpu;
typedef struct xen_v0_setmaxvcpu xen_v1_setmaxvcpu;

struct xen_v2_setmaxvcpu {
    uint32_t	maxvcpu;
};
typedef struct xen_v2_setmaxvcpu xen_v2_setmaxvcpu;

/*
 * The informations for an setvcpumap system hypercall
 * Note that between 1 and 2 the limitation to 64 physical CPU was lifted
 * hence the difference in structures
 */
#define XEN_V0_OP_SETVCPUMAP	20
#define XEN_V1_OP_SETVCPUMAP	20
#define XEN_V2_OP_SETVCPUMAP	9

struct xen_v0_setvcpumap {
    domid_t	domain;
    uint32_t	vcpu;
    cpumap_t    cpumap;
};
typedef struct xen_v0_setvcpumap xen_v0_setvcpumap;
typedef struct xen_v0_setvcpumap xen_v1_setvcpumap;

struct xen_v2_cpumap {
    uint8_t    *bitmap;
    uint32_t    nr_cpus;
};
struct xen_v2_setvcpumap {
    uint32_t	vcpu;
    struct xen_v2_cpumap cpumap;
};
typedef struct xen_v2_setvcpumap xen_v2_setvcpumap;

/* HV version 2, Dom version 5 requires 64-bit alignment */
struct xen_v2d5_cpumap {
    union {
        uint8_t    *v;
        uint64_t   pad ALIGN_64;
    } bitmap;
    uint32_t    nr_cpus;
};
struct xen_v2d5_setvcpumap {
    uint32_t	vcpu;
    struct xen_v2d5_cpumap cpumap;
};
typedef struct xen_v2d5_setvcpumap xen_v2d5_setvcpumap;

/*
 * The informations for an vcpuinfo system hypercall
 */
#define XEN_V0_OP_GETVCPUINFO   43
#define XEN_V1_OP_GETVCPUINFO	43
#define XEN_V2_OP_GETVCPUINFO   14

struct xen_v0_vcpuinfo {
    domid_t	domain;		/* owner's domain */
    uint32_t	vcpu;		/* the vcpu number */
    uint8_t	online;		/* seen as on line */
    uint8_t	blocked;	/* blocked on event */
    uint8_t	running;	/* scheduled on CPU */
    uint64_t    cpu_time;	/* nanosecond of CPU used */
    uint32_t	cpu;		/* current mapping */
    cpumap_t	cpumap;		/* deprecated in V2 */
};
typedef struct xen_v0_vcpuinfo xen_v0_vcpuinfo;
typedef struct xen_v0_vcpuinfo xen_v1_vcpuinfo;

struct xen_v2_vcpuinfo {
    uint32_t	vcpu;		/* the vcpu number */
    uint8_t	online;		/* seen as on line */
    uint8_t	blocked;	/* blocked on event */
    uint8_t	running;	/* scheduled on CPU */
    uint64_t    cpu_time;	/* nanosecond of CPU used */
    uint32_t	cpu;		/* current mapping */
};
typedef struct xen_v2_vcpuinfo xen_v2_vcpuinfo;

struct xen_v2d5_vcpuinfo {
    uint32_t	vcpu;		/* the vcpu number */
    uint8_t	online;		/* seen as on line */
    uint8_t	blocked;	/* blocked on event */
    uint8_t	running;	/* scheduled on CPU */
    uint64_t    cpu_time ALIGN_64; /* nanosecond of CPU used */
    uint32_t	cpu;		/* current mapping */
};
typedef struct xen_v2d5_vcpuinfo xen_v2d5_vcpuinfo;

/*
 * from V2 the pinning of a vcpu is read with a separate call
 */
#define XEN_V2_OP_GETVCPUMAP	25
typedef struct xen_v2_setvcpumap xen_v2_getvcpumap;
typedef struct xen_v2d5_setvcpumap xen_v2d5_getvcpumap;

/*
 * from V2 we get the scheduler information
 */
#define XEN_V2_OP_GETSCHEDULERID	4

/*
 * from V2 we get the scheduler parameter
 */
#define XEN_V2_OP_SCHEDULER		16
/* Scheduler types. */
#define XEN_SCHEDULER_SEDF       4
#define XEN_SCHEDULER_CREDIT     5
/* get/set scheduler parameters */
#define XEN_DOMCTL_SCHEDOP_putinfo 0
#define XEN_DOMCTL_SCHEDOP_getinfo 1

struct xen_v2_setschedinfo {
    uint32_t sched_id;
    uint32_t cmd;
    union {
        struct xen_domctl_sched_sedf {
            uint64_t period ALIGN_64;
            uint64_t slice  ALIGN_64;
            uint64_t latency ALIGN_64;
            uint32_t extratime;
            uint32_t weight;
        } sedf;
        struct xen_domctl_sched_credit {
            uint16_t weight;
            uint16_t cap;
        } credit;
    } u;
};
typedef struct xen_v2_setschedinfo xen_v2_setschedinfo;
typedef struct xen_v2_setschedinfo xen_v2_getschedinfo;


/*
 * The hypercall operation structures also have changed on
 * changeset 86d26e6ec89b
 */
/* the old structure */
struct xen_op_v0 {
    uint32_t cmd;
    uint32_t interface_version;
    union {
        xen_v0_getdomaininfolistop getdomaininfolist;
        xen_v0_domainop          domain;
        xen_v0_setmaxmem         setmaxmem;
        xen_v0_setmaxvcpu        setmaxvcpu;
        xen_v0_setvcpumap        setvcpumap;
        xen_v0_vcpuinfo          getvcpuinfo;
        uint8_t padding[128];
    } u;
};
typedef struct xen_op_v0 xen_op_v0;
typedef struct xen_op_v0 xen_op_v1;

/* the new structure for systems operations */
struct xen_op_v2_sys {
    uint32_t cmd;
    uint32_t interface_version;
    union {
        xen_v2_getdomaininfolistop   getdomaininfolist;
        xen_v2s3_getdomaininfolistop getdomaininfolists3;
        xen_v2_getschedulerid        getschedulerid;
        uint8_t padding[128];
    } u;
};
typedef struct xen_op_v2_sys xen_op_v2_sys;

/* the new structure for domains operation */
struct xen_op_v2_dom {
    uint32_t cmd;
    uint32_t interface_version;
    domid_t  domain;
    union {
        xen_v2_setmaxmem         setmaxmem;
        xen_v2d5_setmaxmem       setmaxmemd5;
        xen_v2_setmaxvcpu        setmaxvcpu;
        xen_v2_setvcpumap        setvcpumap;
        xen_v2d5_setvcpumap      setvcpumapd5;
        xen_v2_vcpuinfo          getvcpuinfo;
        xen_v2d5_vcpuinfo        getvcpuinfod5;
        xen_v2_getvcpumap        getvcpumap;
        xen_v2d5_getvcpumap      getvcpumapd5;
        xen_v2_setschedinfo      setschedinfo;
        xen_v2_getschedinfo      getschedinfo;
        uint8_t padding[128];
    } u;
};
typedef struct xen_op_v2_dom xen_op_v2_dom;

#include "internal.h"
#include "driver.h"
#include "xen_unified.h"
#include "xen_internal.h"

#define XEN_HYPERVISOR_SOCKET "/proc/xen/privcmd"

#ifndef PROXY
static const char * xenHypervisorGetType(virConnectPtr conn);
static unsigned long xenHypervisorGetMaxMemory(virDomainPtr domain);
#endif

#ifndef PROXY
struct xenUnifiedDriver xenHypervisorDriver = {
    xenHypervisorOpen, /* open */
    xenHypervisorClose, /* close */
    xenHypervisorGetType, /* type */
    xenHypervisorGetVersion, /* version */
    NULL, /* hostname */
    NULL, /* URI */
    NULL, /* nodeGetInfo */
    xenHypervisorGetCapabilities, /* getCapabilities */
    xenHypervisorListDomains, /* listDomains */
    xenHypervisorNumOfDomains, /* numOfDomains */
    NULL, /* domainCreateLinux */
    xenHypervisorPauseDomain, /* domainSuspend */
    xenHypervisorResumeDomain, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    xenHypervisorDestroyDomain, /* domainDestroy */
    NULL, /* domainGetOSType */
    xenHypervisorGetMaxMemory, /* domainGetMaxMemory */
    xenHypervisorSetMaxMemory, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    xenHypervisorGetDomainInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
    xenHypervisorSetVcpus, /* domainSetVcpus */
    xenHypervisorPinVcpu, /* domainPinVcpu */
    xenHypervisorGetVcpus, /* domainGetVcpus */
    xenHypervisorGetVcpuMax, /* domainGetMaxVcpus */
    NULL, /* domainDumpXML */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
    xenHypervisorGetSchedulerType, /* domainGetSchedulerType */
    xenHypervisorGetSchedulerParameters, /* domainGetSchedulerParameters */
    xenHypervisorSetSchedulerParameters, /* domainSetSchedulerParameters */
};
#endif /* !PROXY */

/**
 * virXenError:
 * @error: the error number
 * @info: extra information string
 * @value: extra information number
 *
 * Handle an error at the xend daemon interface
 */
static void
virXenError(virErrorNumber error, const char *info, int value)
{
    const char *errmsg;

    if ((error == VIR_ERR_OK) || (in_init != 0))
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info);
}

#ifndef PROXY

/**
 * virXenErrorFunc:
 * @error: the error number
 * @func: the function failing
 * @info: extra information string
 * @value: extra information number
 *
 * Handle an error at the xend daemon interface
 */
static void
virXenErrorFunc(virErrorNumber error, const char *func, const char *info,
                int value)
{
    char fullinfo[1000];
    const char *errmsg;

    if ((error == VIR_ERR_OK) || (in_init != 0))
        return;


    errmsg = __virErrorMsg(error, info);
    if (func != NULL) {
        snprintf(fullinfo, 999, "%s: %s", func, info);
	fullinfo[999] = 0;
	__virRaiseError(NULL, NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
			errmsg, fullinfo, NULL, value, 0, errmsg, fullinfo);
    } else {
	__virRaiseError(NULL, NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
			errmsg, info, NULL, value, 0, errmsg, info);
    }
}

#endif /* PROXY */

/**
 * virXenPerror:
 * @conn: the connection (if available)
 * @msg: name of system call or file (as in perror(3))
 *
 * Raise error from a failed system call, using errno as the source.
 */
static void
virXenPerror (virConnectPtr conn, const char *msg)
{
    char *msg_s;

    msg_s = malloc (strlen (msg) + 10);
    if (msg_s) {
        strcpy (msg_s, msg);
        strcat (msg_s, ": %s");
    }

    __virRaiseError (conn, NULL, NULL,
                     VIR_FROM_XEN, VIR_ERR_SYSTEM_ERROR, VIR_ERR_ERROR,
                     msg, NULL, NULL, errno, 0,
                     msg_s ? msg_s : msg, strerror (errno));
}

/**
 * xenHypervisorDoV0Op:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hyperviros operation structure
 *
 * Do an hypervisor operation though the old interface,
 * this leads to an hypervisor call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoV0Op(int handle, xen_op_v0 * op)
{
    int ret;
    v0_hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = hv_version << 8;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(*op));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(*op));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}
/**
 * xenHypervisorDoV1Op:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hyperviros operation structure
 *
 * Do an hypervisor v1 operation, this leads to an hypervisor call through
 * ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoV1Op(int handle, xen_op_v1* op)
{
    int ret;
    hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = DOM0_INTERFACE_VERSION;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(*op));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(*op));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}

/**
 * xenHypervisorDoV2Sys:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor operation structure
 *
 * Do an hypervisor v2 stsyem operation, this leads to an hypervisor
 * call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoV2Sys(int handle, xen_op_v2_sys* op)
{
    int ret;
    hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = sys_interface_version;
    hc.op = __HYPERVISOR_sysctl;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(*op));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " sys ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(*op));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}

/**
 * xenHypervisorDoV2Dom:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor domain operation structure
 *
 * Do an hypervisor v2 domain operation, this leads to an hypervisor
 * call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoV2Dom(int handle, xen_op_v2_dom* op)
{
    int ret;
    hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = dom_interface_version;
    hc.op = __HYPERVISOR_domctl;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(*op));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(*op));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}

/**
 * virXen_getdomaininfolist:
 * @handle: the hypervisor handle
 * @first_domain: first domain in the range
 * @maxids: maximum number of domains to list
 * @dominfos: output structures
 *
 * Do a low level hypercall to list existing domains informations
 *
 * Returns the number of domains or -1 in case of failure
 */
static int
virXen_getdomaininfolist(int handle, int first_domain, int maxids,
                         xen_getdomaininfolist *dominfos)
{
    int ret = -1;

    if (mlock(XEN_GETDOMAININFOLIST_DATA(dominfos),
              XEN_GETDOMAININFO_SIZE * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    XEN_GETDOMAININFO_SIZE * maxids);
        return (-1);
    }
    if (hypervisor_version > 1) {
        xen_op_v2_sys op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETDOMAININFOLIST;

        if (sys_interface_version < 3) {
            op.u.getdomaininfolist.first_domain = (domid_t) first_domain;
            op.u.getdomaininfolist.max_domains = maxids;
            op.u.getdomaininfolist.buffer = dominfos->v2;
            op.u.getdomaininfolist.num_domains = maxids;
        } else {
            op.u.getdomaininfolists3.first_domain = (domid_t) first_domain;
            op.u.getdomaininfolists3.max_domains = maxids;
            op.u.getdomaininfolists3.buffer.v = dominfos->v2d5;
            op.u.getdomaininfolists3.num_domains = maxids;
        }
        ret = xenHypervisorDoV2Sys(handle, &op);

        if (ret == 0) {
            if (sys_interface_version < 3)
                ret = op.u.getdomaininfolist.num_domains;
            else
                ret = op.u.getdomaininfolists3.num_domains;
        }
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_GETDOMAININFOLIST;
        op.u.getdomaininfolist.first_domain = (domid_t) first_domain;
        op.u.getdomaininfolist.max_domains = maxids;
        op.u.getdomaininfolist.buffer = dominfos->v0;
        op.u.getdomaininfolist.num_domains = maxids;
        ret = xenHypervisorDoV1Op(handle, &op);
        if (ret == 0)
            ret = op.u.getdomaininfolist.num_domains;
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_GETDOMAININFOLIST;
        op.u.getdomaininfolist.first_domain = (domid_t) first_domain;
        op.u.getdomaininfolist.max_domains = maxids;
        op.u.getdomaininfolist.buffer = dominfos->v0;
        op.u.getdomaininfolist.num_domains = maxids;
        ret = xenHypervisorDoV0Op(handle, &op);
        if (ret == 0)
            ret = op.u.getdomaininfolist.num_domains;
    }
    if (munlock(XEN_GETDOMAININFOLIST_DATA(dominfos),
                XEN_GETDOMAININFO_SIZE * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    XEN_GETDOMAININFO_SIZE * maxids);
        ret = -1;
    }
    return(ret);
}

static int
virXen_getdomaininfo(int handle, int first_domain,
                     xen_getdomaininfo *dominfo) {
    xen_getdomaininfolist dominfos;

    if (hypervisor_version < 2) {
        dominfos.v0 = &(dominfo->v0);
    } else {
        dominfos.v2 = &(dominfo->v2);
    }

    return virXen_getdomaininfolist(handle, first_domain, 1, &dominfos);
}


#ifndef PROXY
/**
 * xenHypervisorGetSchedulerType:
 * @domain: pointer to the Xen Hypervisor block
 * @nparams:give a number of scheduler parameters.
 *
 * Do a low level hypercall to get scheduler type
 *
 * Returns scheduler name or NULL in case of failure
 */
char *
xenHypervisorGetSchedulerType(virDomainPtr domain, int *nparams)
{
    char *schedulertype = NULL;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenErrorFunc(VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
			"domain or conn is NULL", 0);
        return NULL;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0) {
        virXenErrorFunc(VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
			"priv->handle or domain->id invalid", 0);
        return NULL;
    }

    /*
     * Support only dom_interface_version >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (dom_interface_version < 5) {
        virXenErrorFunc(VIR_ERR_NO_XEN, __FUNCTION__,
		        "unsupported in dom interface < 5", 0);
        return NULL;
    }

    if (hypervisor_version > 1) {
        xen_op_v2_sys op;
        int ret;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op);
        if (ret < 0)
	    return(NULL);

        switch (op.u.getschedulerid.sched_id){
	    case XEN_SCHEDULER_SEDF:
		schedulertype = strdup("sedf");
		if (nparams)
		    *nparams = 6;
		break;
	    case XEN_SCHEDULER_CREDIT:
		schedulertype = strdup("credit");
		if (nparams)
		    *nparams = 2;
		break;
	    default:
		break;
        }
    }

    return schedulertype;
}

static const char *str_weight = "weight";
static const char *str_cap = "cap";

/**
 * xenHypervisorGetSchedulerParameters:
 * @domain: pointer to the Xen Hypervisor block
 * @params: pointer to scheduler parameters.
 *     This memory area should be allocated before calling.
 * @nparams:this parameter should be same as
 *     a given number of scheduler parameters.
 *     from xenHypervisorGetSchedulerType().
 *
 * Do a low level hypercall to get scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenHypervisorGetSchedulerParameters(virDomainPtr domain,
				 virSchedParameterPtr params, int *nparams)
{
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenErrorFunc(VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
			"domain or conn is NULL", 0);
        return -1;
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0) {
        virXenErrorFunc(VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
			"priv->handle or domain->id invalid", 0);
        return -1;
    }

    /*
     * Support only dom_interface_version >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (dom_interface_version < 5) {
        virXenErrorFunc(VIR_ERR_NO_XEN, __FUNCTION__,
			"unsupported in dom interface < 5", 0);
        return -1;
    }

    if (hypervisor_version > 1) {
        xen_op_v2_sys op_sys;
        xen_op_v2_dom op_dom;
        int ret;

        memset(&op_sys, 0, sizeof(op_sys));
        op_sys.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op_sys);
        if (ret < 0)
	    return -1;

        switch (op_sys.u.getschedulerid.sched_id){
	    case XEN_SCHEDULER_SEDF:
		/* TODO: Implement for Xen/SEDF */
		TODO
		return(-1);
	    case XEN_SCHEDULER_CREDIT:
		if (*nparams < 2)
		    return(-1);
		memset(&op_dom, 0, sizeof(op_dom));
		op_dom.cmd = XEN_V2_OP_SCHEDULER;
		op_dom.domain = (domid_t) domain->id;
		op_dom.u.getschedinfo.sched_id = XEN_SCHEDULER_CREDIT;
		op_dom.u.getschedinfo.cmd = XEN_DOMCTL_SCHEDOP_getinfo;
		ret = xenHypervisorDoV2Dom(priv->handle, &op_dom);
		if (ret < 0)
		    return(-1);

		strncpy (params[0].field, str_weight, VIR_DOMAIN_SCHED_FIELD_LENGTH);
        params[0].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
		params[0].type = VIR_DOMAIN_SCHED_FIELD_UINT;
		params[0].value.ui = op_dom.u.getschedinfo.u.credit.weight;

		strncpy (params[1].field, str_cap, VIR_DOMAIN_SCHED_FIELD_LENGTH);
        params[1].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
		params[1].type = VIR_DOMAIN_SCHED_FIELD_UINT;
		params[1].value.ui = op_dom.u.getschedinfo.u.credit.cap;

		*nparams = 2;
		break;
	    default:
		virXenErrorFunc(VIR_ERR_INVALID_ARG, __FUNCTION__,
			"Unknown scheduler", op_sys.u.getschedulerid.sched_id);
		return -1;
        }
    }

    return 0;
}

/**
 * xenHypervisorSetSchedulerParameters:
 * @domain: pointer to the Xen Hypervisor block
 * @nparams:give a number of scheduler setting parameters .
 *
 * Do a low level hypercall to set scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenHypervisorSetSchedulerParameters(virDomainPtr domain,
				 virSchedParameterPtr params, int nparams)
{
    int i;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL)) {
        virXenErrorFunc (VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
	                 "domain or conn is NULL", 0);
        return -1;
    }

    if ((nparams == 0) || (params == NULL)) {
	virXenErrorFunc (VIR_ERR_INVALID_ARG, __FUNCTION__,
			 "Noparameters given", 0);
	return(-1);
    }

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0) {
        virXenErrorFunc (VIR_ERR_INTERNAL_ERROR, __FUNCTION__,
	                 "priv->handle or domain->id invalid", 0);
        return -1;
    }

    /*
     * Support only dom_interface_version >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (dom_interface_version < 5) {
        virXenErrorFunc(VIR_ERR_NO_XEN, __FUNCTION__,
			"unsupported in dom interface < 5", 0);
        return -1;
    }

    if (hypervisor_version > 1) {
        xen_op_v2_sys op_sys;
        xen_op_v2_dom op_dom;
        int ret;

        memset(&op_sys, 0, sizeof(op_sys));
        op_sys.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op_sys);
        if (ret == -1) return -1;

        switch (op_sys.u.getschedulerid.sched_id){
        case XEN_SCHEDULER_SEDF:
            /* TODO: Implement for Xen/SEDF */
            TODO
	    return(-1);
        case XEN_SCHEDULER_CREDIT: {
            int weight_set = 0;
            int cap_set = 0;

            memset(&op_dom, 0, sizeof(op_dom));
            op_dom.cmd = XEN_V2_OP_SCHEDULER;
            op_dom.domain = (domid_t) domain->id;
            op_dom.u.getschedinfo.sched_id = XEN_SCHEDULER_CREDIT;
            op_dom.u.getschedinfo.cmd = XEN_DOMCTL_SCHEDOP_putinfo;

            /*
             * credit scheduler parameters
             * following values do not change the parameters
             */
            op_dom.u.getschedinfo.u.credit.weight = 0;
            op_dom.u.getschedinfo.u.credit.cap    = (uint16_t)~0U;

            for (i = 0; i < nparams; i++) {
                if (STREQ (params[i].field, str_weight) &&
                    params[i].type == VIR_DOMAIN_SCHED_FIELD_UINT) {
                    op_dom.u.getschedinfo.u.credit.weight = params[i].value.ui;
		    weight_set = 1;
		} else if (STREQ (params[i].field, str_cap) &&
                    params[i].type == VIR_DOMAIN_SCHED_FIELD_UINT) {
                    op_dom.u.getschedinfo.u.credit.cap = params[i].value.ui;
		    cap_set = 1;
	        } else {
		    virXenErrorFunc (VIR_ERR_INVALID_ARG, __FUNCTION__,
	     "Credit scheduler accepts 'cap' and 'weight' integer parameters",
				     0);
		    return(-1);
		}
            }

            ret = xenHypervisorDoV2Dom(priv->handle, &op_dom);
            if (ret < 0)
	        return -1;
            break;
	}
        default:
            virXenErrorFunc(VIR_ERR_INVALID_ARG, __FUNCTION__,
                        "Unknown scheduler", op_sys.u.getschedulerid.sched_id);
            return -1;
        }
    }
     
    return 0;
}

/**
 * virXen_pausedomain:
 * @handle: the hypervisor handle
 * @id: the domain id
 *
 * Do a low level hypercall to pause the domain
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_pausedomain(int handle, int id)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_PAUSEDOMAIN;
        op.domain = (domid_t) id;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_PAUSEDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_PAUSEDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return(ret);
}

/**
 * virXen_unpausedomain:
 * @handle: the hypervisor handle
 * @id: the domain id
 *
 * Do a low level hypercall to unpause the domain
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_unpausedomain(int handle, int id)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_UNPAUSEDOMAIN;
        op.domain = (domid_t) id;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_UNPAUSEDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_UNPAUSEDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return(ret);
}

/**
 * virXen_destroydomain:
 * @handle: the hypervisor handle
 * @id: the domain id
 *
 * Do a low level hypercall to destroy the domain
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_destroydomain(int handle, int id)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_DESTROYDOMAIN;
        op.domain = (domid_t) id;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_DESTROYDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_DESTROYDOMAIN;
        op.u.domain.domain = (domid_t) id;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return(ret);
}

/**
 * virXen_setmaxmem:
 * @handle: the hypervisor handle
 * @id: the domain id
 * @memory: the amount of memory in kilobytes
 *
 * Do a low level hypercall to change the max memory amount
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_setmaxmem(int handle, int id, unsigned long memory)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_SETMAXMEM;
        op.domain = (domid_t) id;
        if (dom_interface_version < 5)
            op.u.setmaxmem.maxmem = memory;
        else
            op.u.setmaxmemd5.maxmem = memory;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_SETMAXMEM;
        op.u.setmaxmem.domain = (domid_t) id;
        op.u.setmaxmem.maxmem = memory;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_SETMAXMEM;
        op.u.setmaxmem.domain = (domid_t) id;
        op.u.setmaxmem.maxmem = memory;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return(ret);
}

/**
 * virXen_setmaxvcpus:
 * @handle: the hypervisor handle
 * @id: the domain id
 * @vcpus: the numbers of vcpus
 *
 * Do a low level hypercall to change the max vcpus amount
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_setmaxvcpus(int handle, int id, unsigned int vcpus)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_SETMAXVCPU;
        op.domain = (domid_t) id;
        op.u.setmaxvcpu.maxvcpu = vcpus;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hypervisor_version == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_SETMAXVCPU;
        op.u.setmaxvcpu.domain = (domid_t) id;
        op.u.setmaxvcpu.maxvcpu = vcpus;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hypervisor_version == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_SETMAXVCPU;
        op.u.setmaxvcpu.domain = (domid_t) id;
        op.u.setmaxvcpu.maxvcpu = vcpus;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return(ret);
}

/**
 * virXen_setvcpumap:
 * @handle: the hypervisor handle
 * @id: the domain id
 * @vcpu: the vcpu to map
 * @cpumap: the bitmap for this vcpu
 * @maplen: the size of the bitmap in bytes
 *
 * Do a low level hypercall to change the pinning for vcpu
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_setvcpumap(int handle, int id, unsigned int vcpu,
                  unsigned char * cpumap, int maplen)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        if (mlock(cpumap, maplen) < 0) {
            virXenError(VIR_ERR_XEN_CALL, " locking", maplen);
            return (-1);
        }
        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_SETVCPUMAP;
        op.domain = (domid_t) id;
        if (dom_interface_version < 5) {
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap.bitmap = cpumap;
            op.u.setvcpumap.cpumap.nr_cpus = maplen * 8;
        } else {
            op.u.setvcpumapd5.vcpu = vcpu;
            op.u.setvcpumapd5.cpumap.bitmap.v = cpumap;
            op.u.setvcpumapd5.cpumap.nr_cpus = maplen * 8;
        }
        ret = xenHypervisorDoV2Dom(handle, &op);

        if (munlock(cpumap, maplen) < 0) {
            virXenError(VIR_ERR_XEN_CALL, " release", maplen);
            ret = -1;
        }
    } else {
        cpumap_t xen_cpumap; /* limited to 64 CPUs in old hypervisors */
        uint64_t *pm = &xen_cpumap;
        int j;

        if ((maplen > (int)sizeof(cpumap_t)) || (sizeof(cpumap_t) & 7))
            return (-1);

        memset(pm, 0, sizeof(cpumap_t));
        for (j = 0; j < maplen; j++)
            *(pm + (j / 8)) |= cpumap[j] << (8 * (j & 7));

        if (hypervisor_version == 1) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V1_OP_SETVCPUMAP;
            op.u.setvcpumap.domain = (domid_t) id;
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap = xen_cpumap;
            ret = xenHypervisorDoV1Op(handle, &op);
        } else if (hypervisor_version == 0) {
            xen_op_v0 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V0_OP_SETVCPUMAP;
            op.u.setvcpumap.domain = (domid_t) id;
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap = xen_cpumap;
            ret = xenHypervisorDoV0Op(handle, &op);
        }
    }
    return(ret);
}
#endif /* !PROXY*/

/**
 * virXen_getvcpusinfo:
 * @handle: the hypervisor handle
 * @id: the domain id
 * @vcpu: the vcpu to map
 * @cpumap: the bitmap for this vcpu
 * @maplen: the size of the bitmap in bytes
 *
 * Do a low level hypercall to change the pinning for vcpu
 *
 * Returns 0 or -1 in case of failure
 */
static int
virXen_getvcpusinfo(int handle, int id, unsigned int vcpu, virVcpuInfoPtr ipt,
                    unsigned char *cpumap, int maplen)
{
    int ret = -1;

    if (hypervisor_version > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETVCPUINFO;
        op.domain = (domid_t) id;
        if (dom_interface_version < 5)
            op.u.getvcpuinfo.vcpu = (uint16_t) vcpu;
        else
            op.u.getvcpuinfod5.vcpu = (uint16_t) vcpu;
        ret = xenHypervisorDoV2Dom(handle, &op);

        if (ret < 0)
            return(-1);
        ipt->number = vcpu;
        if (dom_interface_version < 5) {
            if (op.u.getvcpuinfo.online) {
                if (op.u.getvcpuinfo.running)
                    ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfo.blocked)
                    ipt->state = VIR_VCPU_BLOCKED;
            } else
                ipt->state = VIR_VCPU_OFFLINE;

            ipt->cpuTime = op.u.getvcpuinfo.cpu_time;
            ipt->cpu = op.u.getvcpuinfo.online ? (int)op.u.getvcpuinfo.cpu : -1;
        } else {
            if (op.u.getvcpuinfod5.online) {
                if (op.u.getvcpuinfod5.running)
                    ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfod5.blocked)
                    ipt->state = VIR_VCPU_BLOCKED;
            } else
                ipt->state = VIR_VCPU_OFFLINE;

            ipt->cpuTime = op.u.getvcpuinfod5.cpu_time;
            ipt->cpu = op.u.getvcpuinfod5.online ? (int)op.u.getvcpuinfod5.cpu : -1;
        }
        if ((cpumap != NULL) && (maplen > 0)) {
            if (mlock(cpumap, maplen) < 0) {
                virXenError(VIR_ERR_XEN_CALL, " locking", maplen);
                return (-1);
            }
            memset(cpumap, 0, maplen);
            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V2_OP_GETVCPUMAP;
            op.domain = (domid_t) id;
            if (dom_interface_version < 5) {
                op.u.getvcpumap.vcpu = vcpu;
                op.u.getvcpumap.cpumap.bitmap = cpumap;
                op.u.getvcpumap.cpumap.nr_cpus = maplen * 8;
            } else {
                op.u.getvcpumapd5.vcpu = vcpu;
                op.u.getvcpumapd5.cpumap.bitmap.v = cpumap;
                op.u.getvcpumapd5.cpumap.nr_cpus = maplen * 8;
            }
            ret = xenHypervisorDoV2Dom(handle, &op);
            if (munlock(cpumap, maplen) < 0) {
                virXenError(VIR_ERR_XEN_CALL, " release", maplen);
                ret = -1;
            }
        }
    } else {
        int mapl = maplen;
        int cpu;

        if (maplen > (int)sizeof(cpumap_t))
            mapl = (int)sizeof(cpumap_t);

        if (hypervisor_version == 1) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V1_OP_GETVCPUINFO;
            op.u.getvcpuinfo.domain = (domid_t) id;
            op.u.getvcpuinfo.vcpu = vcpu;
            ret = xenHypervisorDoV1Op(handle, &op);
            if (ret < 0)
                return(-1);
            ipt->number = vcpu;
            if (op.u.getvcpuinfo.online) {
                if (op.u.getvcpuinfo.running) ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfo.blocked) ipt->state = VIR_VCPU_BLOCKED;
            }
            else ipt->state = VIR_VCPU_OFFLINE;
            ipt->cpuTime = op.u.getvcpuinfo.cpu_time;
            ipt->cpu = op.u.getvcpuinfo.online ? (int)op.u.getvcpuinfo.cpu : -1;
            if ((cpumap != NULL) && (maplen > 0)) {
                for (cpu = 0; cpu < (mapl * 8); cpu++) {
                    if (op.u.getvcpuinfo.cpumap & ((uint64_t)1<<cpu))
                        VIR_USE_CPU(cpumap, cpu);
                }
            }
        } else if (hypervisor_version == 0) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V0_OP_GETVCPUINFO;
            op.u.getvcpuinfo.domain = (domid_t) id;
            op.u.getvcpuinfo.vcpu = vcpu;
            ret = xenHypervisorDoV0Op(handle, &op);
            if (ret < 0)
                return(-1);
            ipt->number = vcpu;
            if (op.u.getvcpuinfo.online) {
                if (op.u.getvcpuinfo.running) ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfo.blocked) ipt->state = VIR_VCPU_BLOCKED;
            }
            else ipt->state = VIR_VCPU_OFFLINE;
            ipt->cpuTime = op.u.getvcpuinfo.cpu_time;
            ipt->cpu = op.u.getvcpuinfo.online ? (int)op.u.getvcpuinfo.cpu : -1;
            if ((cpumap != NULL) && (maplen > 0)) {
                for (cpu = 0; cpu < (mapl * 8); cpu++) {
                    if (op.u.getvcpuinfo.cpumap & ((uint64_t)1<<cpu))
                        VIR_USE_CPU(cpumap, cpu);
                }
            }
        }
    }
    return(ret);
}

/**
 * xenHypervisorInit:
 *
 * Initialize the hypervisor layer. Try to detect the kind of interface
 * used i.e. pre or post changeset 10277
 */
int
xenHypervisorInit(void)
{
    int fd, ret, cmd, errcode;
    hypercall_t hc;
    v0_hypercall_t v0_hc;
    xen_getdomaininfo info;
    virVcpuInfoPtr ipt = NULL;

    if (initialized) {
        if (hypervisor_version == -1)
            return (-1);
        return(0);
    }
    initialized = 1;
    in_init = 1;

    /* Compile regular expressions used by xenHypervisorGetCapabilities.
     * Note that errors here are really internal errors since these
     * regexps should never fail to compile.
     */
    errcode = regcomp (&flags_hvm_rec, flags_hvm_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror (errcode, &flags_hvm_rec, error, sizeof error);
        regfree (&flags_hvm_rec);
        virXenError (VIR_ERR_INTERNAL_ERROR, error, 0);
        in_init = 0;
        return -1;
    }
    errcode = regcomp (&flags_pae_rec, flags_pae_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror (errcode, &flags_pae_rec, error, sizeof error);
        regfree (&flags_pae_rec);
        regfree (&flags_hvm_rec);
        virXenError (VIR_ERR_INTERNAL_ERROR, error, 0);
        in_init = 0;
        return -1;
    }
    errcode = regcomp (&xen_cap_rec, xen_cap_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror (errcode, &xen_cap_rec, error, sizeof error);
        regfree (&xen_cap_rec);
        regfree (&flags_pae_rec);
        regfree (&flags_hvm_rec);
        virXenError (VIR_ERR_INTERNAL_ERROR, error, 0);
        in_init = 0;
        return -1;
    }

    /* Xen hypervisor version detection begins. */
    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        hypervisor_version = -1;
        return(-1);
    }
    fd = ret;

    /*
     * The size of the hypervisor call block changed July 2006
     * this detect if we are using the new or old hypercall_t structure
     */
    hc.op = __HYPERVISOR_xen_version;
    hc.arg[0] = (unsigned long) XENVER_version;
    hc.arg[1] = 0;

    cmd = IOCTL_PRIVCMD_HYPERCALL;
    ret = ioctl(fd, cmd, (unsigned long) &hc);

    if ((ret != -1) && (ret != 0)) {
#ifdef DEBUG
        fprintf(stderr, "Using new hypervisor call: %X\n", ret);
#endif
        hv_version = ret;
        xen_ioctl_hypercall_cmd = cmd;
        goto detect_v2;
    }

    /*
     * check if the old hypercall are actually working
     */
    v0_hc.op = __HYPERVISOR_xen_version;
    v0_hc.arg[0] = (unsigned long) XENVER_version;
    v0_hc.arg[1] = 0;
    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(v0_hypercall_t));
    ret = ioctl(fd, cmd, (unsigned long) &v0_hc);
    if ((ret != -1) && (ret != 0)) {
#ifdef DEBUG
        fprintf(stderr, "Using old hypervisor call: %X\n", ret);
#endif
        hv_version = ret;
        xen_ioctl_hypercall_cmd = cmd;
        hypervisor_version = 0;
        goto done;
    }

    /*
     * we faild to make any hypercall
     */

    hypervisor_version = -1;
    virXenError(VIR_ERR_XEN_CALL, " ioctl ", IOCTL_PRIVCMD_HYPERCALL);
    close(fd);
    in_init = 0;
    return(-1);

 detect_v2:
    /*
     * The hypercalls were refactored into 3 different section in August 2006
     * Try to detect if we are running a version post 3.0.2 with the new ones
     * or the old ones
     */
    hypervisor_version = 2;

    ipt = malloc(sizeof(virVcpuInfo));
    if (ipt == NULL){
#ifdef DEBUG
        fprintf(stderr, "Memory allocation failed at xenHypervisorInit()\n");
#endif
        return(-1);
    }
    /* Currently consider RHEL5.0 Fedora7 and xen-unstable */
    sys_interface_version = 2; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* RHEL 5.0 */
        dom_interface_version = 3; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0){
#ifdef DEBUG
            fprintf(stderr, "Using hypervisor call v2, sys ver2 dom ver3\n");
#endif
            goto done;
        }
        /* Fedora 7 */
        dom_interface_version = 4; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0){
#ifdef DEBUG
            fprintf(stderr, "Using hypervisor call v2, sys ver2 dom ver4\n");
#endif
            goto done;
        }
    }

    sys_interface_version = 3; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* xen-unstable */
        dom_interface_version = 5; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0){
#ifdef DEBUG
            fprintf(stderr, "Using hypervisor call v2, sys ver3 dom ver5\n");
#endif
            goto done;
        }
    }

    hypervisor_version = 1;
    sys_interface_version = -1;
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
#ifdef DEBUG
        fprintf(stderr, "Using hypervisor call v1\n");
#endif
        goto done;
    }

    /*
     * we faild to make the getdomaininfolist hypercall
     */

    hypervisor_version = -1;
    virXenError(VIR_ERR_XEN_CALL, " ioctl ", IOCTL_PRIVCMD_HYPERCALL);
    close(fd);
    in_init = 0;
    if (ipt)
        free(ipt);
    return(-1);

 done:
    close(fd);
    in_init = 0;
    if (ipt)
        free(ipt);
    return(0);
}

/**
 * xenHypervisorOpen:
 * @conn: pointer to the connection block
 * @name: URL for the target, NULL for local
 * @flags: combination of virDrvOpenFlag(s)
 *
 * Connects to the Xen hypervisor.
 *
 * Returns 0 or -1 in case of error.
 */
int
xenHypervisorOpen(virConnectPtr conn,
                  const char *name ATTRIBUTE_UNUSED,
                  int flags ATTRIBUTE_UNUSED)
{
    int ret;
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (initialized == 0)
        if (xenHypervisorInit() == -1)
            return -1;

    priv->handle = -1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        virXenError(VIR_ERR_NO_XEN, XEN_HYPERVISOR_SOCKET, 0);
        return (-1);
    }

    priv->handle = ret;

    return(0);
}

/**
 * xenHypervisorClose:
 * @conn: pointer to the connection block
 *
 * Close the connection to the Xen hypervisor.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
xenHypervisorClose(virConnectPtr conn)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return (-1);

    priv = (xenUnifiedPrivatePtr) conn->privateData;

    if (priv->handle < 0)
        return -1;

    ret = close(priv->handle);
    if (ret < 0)
        return (-1);

    return (0);
}


#ifndef PROXY
/**
 * xenHypervisorGetType:
 * @conn: pointer to the Xen Hypervisor block
 *
 * Get the version level of the Hypervisor running.
 *
 * Returns -1 in case of error, 0 otherwise. if the version can't be
 *    extracted by lack of capacities returns 0 and @hvVer is 0, otherwise
 *    @hvVer value is major * 1,000,000 + minor * 1,000 + release
 */
static const char *
xenHypervisorGetType(virConnectPtr conn)
{
    if (!VIR_IS_CONNECT(conn)) {
        virXenError(VIR_ERR_INVALID_CONN, __FUNCTION__, 0);
        return (NULL);
    }
    return("Xen");
}
#endif

/**
 * xenHypervisorGetVersion:
 * @conn: pointer to the connection block
 * @hvVer: where to store the version
 *
 * Call the hypervisor to extracts his own internal API version
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xenHypervisorGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return -1;
    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0 || hvVer == NULL)
        return (-1);
    *hvVer = (hv_version >> 16) * 1000000 + (hv_version & 0xFFFF) * 1000;
    return(0);
}

/**
 * xenHypervisorGetCapabilities:
 * @conn: pointer to the connection block
 * @cpuinfo: file handle containing /proc/cpuinfo data, or NULL
 * @capabilities: file handle containing /sys/hypervisor/properties/capabilities data, or NULL
 *
 * Return the capabilities of this hypervisor.
 */
char *
xenHypervisorMakeCapabilitiesXML(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 const char *hostmachine,
                                 FILE *cpuinfo, FILE *capabilities)
{
    char line[1024], *str, *token;
    regmatch_t subs[4];
    char *saveptr = NULL;
    int i, r;

    char hvm_type[4] = ""; /* "vmx" or "svm" (or "" if not in CPU). */
    int host_pae = 0;
    struct guest_arch {
        const char *model;
        int bits;
        int hvm;
        int pae;
        int nonpae;
        int ia64_be;
    } guest_archs[32];
    int nr_guest_archs = 0;

    virBufferPtr xml;
    char *xml_str;

    memset(guest_archs, 0, sizeof(guest_archs));

    /* /proc/cpuinfo: flags: Intel calls HVM "vmx", AMD calls it "svm".
     * It's not clear if this will work on IA64, let alone other
     * architectures and non-Linux. (XXX)
     */
    if (cpuinfo) {
        while (fgets (line, sizeof line, cpuinfo)) {
            if (regexec (&flags_hvm_rec, line, sizeof(subs)/sizeof(regmatch_t), subs, 0) == 0
                && subs[0].rm_so != -1) {
                strncpy (hvm_type,
                         &line[subs[1].rm_so], subs[1].rm_eo-subs[1].rm_so+1);
                hvm_type[subs[1].rm_eo-subs[1].rm_so] = '\0';
            } else if (regexec (&flags_pae_rec, line, 0, NULL, 0) == 0)
                host_pae = 1;
        }
    }

    /* Most of the useful info is in /sys/hypervisor/properties/capabilities
     * which is documented in the code in xen-unstable.hg/xen/arch/.../setup.c.
     *
     * It is a space-separated list of supported guest architectures.
     *
     * For x86:
     *    TYP-VER-ARCH[p]
     *    ^   ^   ^    ^
     *    |   |   |    +-- PAE supported
     *    |   |   +------- x86_32 or x86_64
     *    |   +----------- the version of Xen, eg. "3.0"
     *    +--------------- "xen" or "hvm" for para or full virt respectively
     *
     * For PPC this file appears to be always empty (?)
     *
     * For IA64:
     *    TYP-VER-ARCH[be]
     *    ^   ^   ^    ^
     *    |   |   |    +-- Big-endian supported
     *    |   |   +------- always "ia64"
     *    |   +----------- the version of Xen, eg. "3.0"
     *    +--------------- "xen" or "hvm" for para or full virt respectively
     */

    /* Expecting one line in this file - ignore any more. */
    if (fgets (line, sizeof line, capabilities)) {
        /* Split the line into tokens.  strtok_r is OK here because we "own"
         * this buffer.  Parse out the features from each token.
         */
        for (str = line, nr_guest_archs = 0;
             nr_guest_archs < sizeof guest_archs / sizeof guest_archs[0]
                 && (token = strtok_r (str, " ", &saveptr)) != NULL;
             str = NULL) {

            if (regexec (&xen_cap_rec, token, sizeof subs / sizeof subs[0],
                         subs, 0) == 0) {
                int hvm = strncmp (&token[subs[1].rm_so], "hvm", 3) == 0;
                const char *model;
                int bits, pae = 0, nonpae = 0, ia64_be = 0;
                if (strncmp (&token[subs[2].rm_so], "x86_32", 6) == 0) {
                    model = "i686";
                    bits = 32;
                    if (strncmp (&token[subs[3].rm_so], "p", 1) == 0)
                        pae = 1;
                    else
                        nonpae = 1;
                }
                else if (strncmp (&token[subs[2].rm_so], "x86_64", 6) == 0) {
                    model = "x86_64";
                    bits = 64;
                }
                else if (strncmp (&token[subs[2].rm_so], "ia64", 4) == 0) {
                    model = "ia64";
                    bits = 64;
                    if (strncmp (&token[subs[3].rm_so], "be", 2) == 0)
                        ia64_be = 1;
                }
                else if (strncmp (&token[subs[2].rm_so], "powerpc64", 4) == 0) {
                    model = "ppc64";
                    bits = 64;
                } else {
                    /* XXX surely no other Xen archs exist  */
                    continue;
                }

                /* Search for existing matching (model,hvm) tuple */
                for (i = 0 ; i < nr_guest_archs ; i++) {
                    if (!strcmp(guest_archs[i].model, model) &&
                        guest_archs[i].hvm == hvm) {
                        break;
                    }
                }

                /* Too many arch flavours - highly unlikely ! */
                if (i >= sizeof(guest_archs)/sizeof(guest_archs[0]))
                    continue;
                /* Didn't find a match, so create a new one */
                if (i == nr_guest_archs)
                    nr_guest_archs++;

                guest_archs[i].model = model;
                guest_archs[i].bits = bits;
                guest_archs[i].hvm = hvm;

                /* Careful not to overwrite a previous positive
                   setting with a negative one here - some archs
                   can do both pae & non-pae, but Xen reports
                   separately capabilities so we're merging archs */
                if (pae)
                    guest_archs[i].pae = pae;
                if (nonpae)
                    guest_archs[i].nonpae = nonpae;
                if (ia64_be)
                    guest_archs[i].ia64_be = ia64_be;
            }
        }
    }

    /* Construct the final XML. */
    xml = virBufferNew (1024);
    if (!xml) {
        virXenError(VIR_ERR_NO_MEMORY, __FUNCTION__, 0);
        return NULL;
    }
    r = virBufferVSprintf (xml,
                           "\
<capabilities>\n\
  <host>\n\
    <cpu>\n\
      <arch>%s</arch>\n\
      <features>\n",
                           hostmachine);
    if (r == -1) goto vir_buffer_failed;

    if (strcmp (hvm_type, "") != 0) {
        r = virBufferVSprintf (xml,
                               "\
        <%s/>\n",
                               hvm_type);
        if (r == -1) goto vir_buffer_failed;
    }
    if (host_pae) {
        r = virBufferAdd (xml, "\
        <pae/>\n", -1);
        if (r == -1) goto vir_buffer_failed;
    }
    r = virBufferAdd (xml,
                      "\
      </features>\n\
    </cpu>\n\
  </host>\n", -1);
    if (r == -1) goto vir_buffer_failed;

    for (i = 0; i < nr_guest_archs; ++i) {
        r = virBufferVSprintf (xml,
                               "\
\n\
  <guest>\n\
    <os_type>%s</os_type>\n\
    <arch name=\"%s\">\n\
      <wordsize>%d</wordsize>\n\
      <domain type=\"xen\"></domain>\n",
                               guest_archs[i].hvm ? "hvm" : "xen",
                               guest_archs[i].model,
                               guest_archs[i].bits);
        if (r == -1) goto vir_buffer_failed;
        if (guest_archs[i].hvm) {
            r = virBufferVSprintf (xml,
                              "\
      <emulator>/usr/lib%s/xen/bin/qemu-dm</emulator>\n\
      <machine>pc</machine>\n\
      <machine>isapc</machine>\n\
      <loader>/usr/lib/xen/boot/hvmloader</loader>\n",
                                   guest_archs[i].bits == 64 ? "64" : "");
            if (r == -1) goto vir_buffer_failed;
        }
        r = virBufferAdd (xml,
                          "\
    </arch>\n\
    <features>\n", -1);
        if (r == -1) goto vir_buffer_failed;
        if (guest_archs[i].pae) {
            r = virBufferAdd (xml,
                              "\
      <pae/>\n", -1);
            if (r == -1) goto vir_buffer_failed;
        }
        if (guest_archs[i].nonpae) {
            r = virBufferAdd (xml,
                              "\
      <nonpae/>\n", -1);
            if (r == -1) goto vir_buffer_failed;
        }
        if (guest_archs[i].ia64_be) {
            r = virBufferAdd (xml,
                              "\
      <ia64_be/>\n", -1);
            if (r == -1) goto vir_buffer_failed;
        }
        r = virBufferAdd (xml,
                          "\
    </features>\n\
  </guest>\n", -1);
        if (r == -1) goto vir_buffer_failed;
    }
    r = virBufferAdd (xml,
                      "\
</capabilities>\n", -1);
    if (r == -1) goto vir_buffer_failed;
    xml_str = strdup (xml->content);
    if (!xml_str) goto vir_buffer_failed;
    virBufferFree (xml);

    return xml_str;

 vir_buffer_failed:
    virXenError(VIR_ERR_NO_MEMORY, __FUNCTION__, 0);
    virBufferFree (xml);
    return NULL;
}

/**
 * xenHypervisorGetCapabilities:
 * @conn: pointer to the connection block
 *
 * Return the capabilities of this hypervisor.
 */
char *
xenHypervisorGetCapabilities (virConnectPtr conn)
{
    char *xml;
    FILE *cpuinfo, *capabilities;
    struct utsname utsname;

    /* Really, this never fails - look at the man-page. */
    uname (&utsname);

    cpuinfo = fopen ("/proc/cpuinfo", "r");
    if (cpuinfo == NULL) {
        if (errno != ENOENT) {
            virXenPerror (conn, "/proc/cpuinfo");
            return NULL;
        }
    }

    capabilities = fopen ("/sys/hypervisor/properties/capabilities", "r");
    if (capabilities == NULL) {
        if (errno != ENOENT) {
            fclose(cpuinfo);
            virXenPerror (conn, "/sys/hypervisor/properties/capabilities");
            return NULL;
        }
    }

    xml = xenHypervisorMakeCapabilitiesXML(conn, utsname.machine, cpuinfo, capabilities);

    if (cpuinfo)
        fclose(cpuinfo);
    if (capabilities)
        fclose(capabilities);

    return xml;
}

/**
 * xenHypervisorNumOfDomains:
 * @conn: pointer to the connection block
 *
 * Provides the number of active domains.
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenHypervisorNumOfDomains(virConnectPtr conn)
{
    xen_getdomaininfolist dominfos;
    int ret, nbids;
    static int last_maxids = 2;
    int maxids = last_maxids;
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return -1;
    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0)
        return (-1);

 retry:
    if (!(XEN_GETDOMAININFOLIST_ALLOC(dominfos, maxids))) {
        virXenError(VIR_ERR_NO_MEMORY, _("allocating %d domain info"),
                    maxids);
        return(-1);
    }

    XEN_GETDOMAININFOLIST_CLEAR(dominfos, maxids);

    ret = virXen_getdomaininfolist(priv->handle, 0, maxids, &dominfos);

    XEN_GETDOMAININFOLIST_FREE(dominfos);

    if (ret < 0)
        return (-1);

    nbids = ret;
    /* Can't possibly have more than 65,000 concurrent guests
     * so limit how many times we try, to avoid increasing
     * without bound & thus allocating all of system memory !
     * XXX I'll regret this comment in a few years time ;-)
     */
    if (nbids == maxids) {
        if (maxids < 65000) {
            last_maxids *= 2;
            maxids *= 2;
            goto retry;
        }
        nbids = -1;
    }
    if ((nbids < 0) || (nbids > maxids))
        return(-1);
    return(nbids);
}

/**
 * xenHypervisorListDomains:
 * @conn: pointer to the connection block
 * @ids: array to collect the list of IDs of active domains
 * @maxids: size of @ids
 *
 * Collect the list of active domains, and store their ID in @maxids
 *
 * Returns the number of domain found or -1 in case of error
 */
int
xenHypervisorListDomains(virConnectPtr conn, int *ids, int maxids)
{
    xen_getdomaininfolist dominfos;
    int ret, nbids, i;
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0 ||
        (ids == NULL) || (maxids < 1))
        return (-1);

    if (!(XEN_GETDOMAININFOLIST_ALLOC(dominfos, maxids))) {
        virXenError(VIR_ERR_NO_MEMORY, "allocating %d domain info",
                    maxids);
        return(-1);
    }

    XEN_GETDOMAININFOLIST_CLEAR(dominfos, maxids);
    memset(ids, 0, maxids * sizeof(int));

    ret = virXen_getdomaininfolist(priv->handle, 0, maxids, &dominfos);

    if (ret < 0) {
        XEN_GETDOMAININFOLIST_FREE(dominfos);
        return (-1);
    }

    nbids = ret;
    if ((nbids < 0) || (nbids > maxids)) {
        XEN_GETDOMAININFOLIST_FREE(dominfos);
        return(-1);
    }

    for (i = 0;i < nbids;i++) {
        ids[i] = XEN_GETDOMAININFOLIST_DOMAIN(dominfos, i);
    }

    XEN_GETDOMAININFOLIST_FREE(dominfos);
    return (nbids);
}

/**
 * xenHypervisorGetMaxVcpus:
 *
 * Returns the maximum of CPU defined by Xen.
 */
int
xenHypervisorGetMaxVcpus(virConnectPtr conn,
                         const char *type ATTRIBUTE_UNUSED)
{
    xenUnifiedPrivatePtr priv;

    if (conn == NULL)
        return -1;
    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0)
        return (-1);

    return MAX_VIRT_CPUS;
}

/**
 * xenHypervisorGetDomMaxMemory:
 * @conn: connection data
 * @id: domain id
 *
 * Retrieve the maximum amount of physical memory allocated to a
 * domain.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenHypervisorGetDomMaxMemory(virConnectPtr conn, int id)
{
    xenUnifiedPrivatePtr priv;
    xen_getdomaininfo dominfo;
    int ret;

    if (conn == NULL)
        return 0;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0)
        return 0;

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE) / 1024;
	if (kb_per_pages <= 0) 
	    kb_per_pages = 4;
    }

    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(priv->handle, id, &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != id))
        return (0);

    return((unsigned long) XEN_GETDOMAININFO_MAX_PAGES(dominfo) * kb_per_pages);
}

#ifndef PROXY
/**
 * xenHypervisorGetMaxMemory:
 * @domain: a domain object or NULL
 *
 * Retrieve the maximum amount of physical memory allocated to a
 * domain. If domain is NULL, then this get the amount of memory reserved
 * to Domain0 i.e. the domain where the application runs.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
static unsigned long
xenHypervisorGetMaxMemory(virDomainPtr domain)
{
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL))
        return 0;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0)
        return (0);

    return(xenHypervisorGetDomMaxMemory(domain->conn, domain->id));
}
#endif

/**
 * xenHypervisorGetDomInfo:
 * @conn: connection data
 * @id: the domain ID
 * @info: the place where information should be stored
 *
 * Do an hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomInfo(virConnectPtr conn, int id, virDomainInfoPtr info)
{
    xenUnifiedPrivatePtr priv;
    xen_getdomaininfo dominfo;
    int ret;
    uint32_t domain_flags, domain_state, domain_shutdown_cause;

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE) / 1024;
	if (kb_per_pages <= 0) 
	    kb_per_pages = 4;
    }

    if (conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) conn->privateData;
    if (priv->handle < 0 || info == NULL)
        return (-1);

    memset(info, 0, sizeof(virDomainInfo));
    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(priv->handle, id, &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != id))
        return (-1);

    domain_flags = XEN_GETDOMAININFO_FLAGS(dominfo);
    domain_flags &= ~DOMFLAGS_HVM; /* Mask out HVM flags */
    domain_state = domain_flags & 0xFF; /* Mask out high bits */
    switch (domain_state) {
	case DOMFLAGS_DYING:
	    info->state = VIR_DOMAIN_SHUTDOWN;
	    break;
	case DOMFLAGS_SHUTDOWN:
            /* The domain is shutdown.  Determine the cause. */
            domain_shutdown_cause = domain_flags >> DOMFLAGS_SHUTDOWNSHIFT;
            switch (domain_shutdown_cause) {
                case SHUTDOWN_crash:
                    info->state = VIR_DOMAIN_CRASHED;
                    break;
                default:
                    info->state = VIR_DOMAIN_SHUTOFF;
            }
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
     * kilobytes from page counts
     */
    info->cpuTime = XEN_GETDOMAININFO_CPUTIME(dominfo);
    info->memory = XEN_GETDOMAININFO_TOT_PAGES(dominfo) * kb_per_pages;
    info->maxMem = XEN_GETDOMAININFO_MAX_PAGES(dominfo);
    if(info->maxMem != UINT_MAX)
        info->maxMem *= kb_per_pages;
    info->nrVirtCpu = XEN_GETDOMAININFO_CPUCOUNT(dominfo);
    return (0);
}

/**
 * xenHypervisorGetDomainInfo:
 * @domain: pointer to the domain block
 * @info: the place where information should be stored
 *
 * Do an hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomainInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL))
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || info == NULL ||
        (domain->id < 0))
        return (-1);

    return(xenHypervisorGetDomInfo(domain->conn, domain->id, info));

}

#ifndef PROXY
/**
 * xenHypervisorPauseDomain:
 * @domain: pointer to the domain block
 *
 * Do an hypervisor call to pause the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorPauseDomain(virDomainPtr domain)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL))
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0)
        return (-1);

    ret = virXen_pausedomain(priv->handle, domain->id);
    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorResumeDomain:
 * @domain: pointer to the domain block
 *
 * Do an hypervisor call to resume the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorResumeDomain(virDomainPtr domain)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL))
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0)
        return (-1);

    ret = virXen_unpausedomain(priv->handle, domain->id);
    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorDestroyDomain:
 * @domain: pointer to the domain block
 *
 * Do an hypervisor call to destroy the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorDestroyDomain(virDomainPtr domain)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0)
        return (-1);

    ret = virXen_destroydomain(priv->handle, domain->id);
    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorSetMaxMemory:
 * @domain: pointer to the domain block
 * @memory: the max memory size in kilobytes.
 *
 * Do an hypervisor call to change the maximum amount of memory used
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorSetMaxMemory(virDomainPtr domain, unsigned long memory)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0)
        return (-1);

    ret = virXen_setmaxmem(priv->handle, domain->id, memory);
    if (ret < 0)
        return (-1);
    return (0);
}
#endif /* PROXY */

#ifndef PROXY
/**
 * xenHypervisorSetVcpus:
 * @domain: pointer to domain object
 * @nvcpus: the new number of virtual CPUs for this domain
 *
 * Dynamically change the number of virtual CPUs used by the domain.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
xenHypervisorSetVcpus(virDomainPtr domain, unsigned int nvcpus)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || domain->id < 0 || nvcpus < 1)
        return (-1);

    ret = virXen_setmaxvcpus(priv->handle, domain->id, nvcpus);
    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorPinVcpu:
 * @domain: pointer to domain object
 * @vcpu: virtual CPU number
 * @cpumap: pointer to a bit map of real CPUs (in 8-bit bytes)
 * @maplen: length of cpumap in bytes
 *
 * Dynamically change the real CPUs which can be allocated to a virtual CPU.
 *
 * Returns 0 in case of success, -1 in case of failure.
 */

int
xenHypervisorPinVcpu(virDomainPtr domain, unsigned int vcpu,
                     unsigned char *cpumap, int maplen)
{
    int ret;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || (domain->id < 0) ||
        (cpumap == NULL) || (maplen < 1))
        return (-1);

    ret = virXen_setvcpumap(priv->handle, domain->id, vcpu,
                            cpumap, maplen);
    if (ret < 0)
        return (-1);
    return (0);
}
#endif

/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to an bit map of real CPUs for all vcpus of this domain (in 8-bit bytes) (OUT)
 *	If cpumaps is NULL, then no cupmap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer is'nt NULL.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
#ifndef PROXY
int
xenHypervisorGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
                      unsigned char *cpumaps, int maplen)
{
    xen_getdomaininfo dominfo;
    int ret;
    xenUnifiedPrivatePtr priv;
    virVcpuInfoPtr ipt;
    int nbinfo, i;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0 || (domain->id < 0) ||
        (info == NULL) || (maxinfo < 1) ||
        (sizeof(cpumap_t) & 7))
        return (-1);
    if ((cpumaps != NULL) && (maplen < 1))
        return -1;

    /* first get the number of virtual CPUs in this domain */
    XEN_GETDOMAININFO_CLEAR(dominfo);
    ret = virXen_getdomaininfo(priv->handle, domain->id,
                               &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != domain->id))
        return (-1);
    nbinfo = XEN_GETDOMAININFO_CPUCOUNT(dominfo) + 1;
    if (nbinfo > maxinfo) nbinfo = maxinfo;

    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0, ipt = info; i < nbinfo; i++, ipt++) {
        if ((cpumaps != NULL) && (i < maxinfo)) {
            ret = virXen_getvcpusinfo(priv->handle, domain->id, i,
                                      ipt,
                                      (unsigned char *)VIR_GET_CPUMAP(cpumaps, maplen, i),
                                      maplen);
            if (ret < 0)
                return(-1);
        } else {
            ret = virXen_getvcpusinfo(priv->handle, domain->id, i,
                                      ipt, NULL, 0);
            if (ret < 0)
                return(-1);
        }
    }
    return nbinfo;
}
#endif /* PROXY */

/**
 * xenHypervisorGetVcpuMax:
 *
 *  Returns the maximum number of virtual CPUs supported for
 *  the guest VM. If the guest is inactive, this is the maximum
 *  of CPU defined by Xen. If the guest is running this reflect
 *  the maximum number of virtual CPUs the guest was booted with.
 */
int
xenHypervisorGetVcpuMax(virDomainPtr domain)
{
    xen_getdomaininfo dominfo;
    int ret;
    int maxcpu;
    xenUnifiedPrivatePtr priv;

    if (domain == NULL || domain->conn == NULL)
        return -1;

    priv = (xenUnifiedPrivatePtr) domain->conn->privateData;
    if (priv->handle < 0)
        return (-1);

    /* inactive domain */
    if (domain->id < 0) {
        maxcpu = MAX_VIRT_CPUS;
    } else {
        XEN_GETDOMAININFO_CLEAR(dominfo);
        ret = virXen_getdomaininfo(priv->handle, domain->id,
                                   &dominfo);

        if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != domain->id))
            return (-1);
        maxcpu = XEN_GETDOMAININFO_MAXCPUID(dominfo) + 1;
    }

    return maxcpu;
}

#endif /* WITH_XEN */
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
