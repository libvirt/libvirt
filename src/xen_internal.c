/*
 * xen_internal.c: direct access to Xen hypervisor level
 *
 * Copyright (C) 2005, 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

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

/* required for dom0_getdomaininfo_t */
#include <xen/dom0_ops.h>
#include <xen/version.h>
#include <xen/xen.h>
#include <xen/linux/privcmd.h>

/* required for shutdown flags */
#include <xen/sched.h>

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

/*
 * The content of the structures for a getdomaininfolist system hypercall
 */
#ifndef DOMFLAGS_DYING
#define DOMFLAGS_DYING     (1<<0) /* Domain is scheduled to die.             */
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

union xen_getdomaininfo {
    struct xen_v0_getdomaininfo v0;
    struct xen_v2_getdomaininfo v2;
};
typedef union xen_getdomaininfo xen_getdomaininfo;

union xen_getdomaininfolist {
    struct xen_v0_getdomaininfo *v0;
    struct xen_v2_getdomaininfo *v2;
};
typedef union xen_getdomaininfolist xen_getdomaininfolist;

#define XEN_GETDOMAININFOLIST_ALLOC(domlist, size)                      \
    (hypervisor_version < 2 ?                                           \
     ((domlist.v0 = malloc(sizeof(xen_v0_getdomaininfo)*(size))) != NULL) : \
     ((domlist.v2 = malloc(sizeof(xen_v2_getdomaininfo)*(size))) != NULL))

#define XEN_GETDOMAININFOLIST_FREE(domlist)     \
    (hypervisor_version < 2 ?                   \
     free(domlist.v0) :                         \
     free(domlist.v2))

#define XEN_GETDOMAININFOLIST_CLEAR(domlist, size)                  \
    (hypervisor_version < 2 ?                                       \
     memset(domlist.v0, 0, sizeof(xen_v0_getdomaininfo) * size) :   \
     memset(domlist.v2, 0, sizeof(xen_v2_getdomaininfo) * size))

#define XEN_GETDOMAININFOLIST_DOMAIN(domlist, n)    \
    (hypervisor_version < 2 ?                       \
     domlist.v0[n].domain :                         \
     domlist.v2[n].domain)

#define XEN_GETDOMAININFOLIST_DATA(domlist)     \
    (hypervisor_version < 2 ?                   \
     (void*)(domlist->v0) :                     \
     (void*)(domlist->v2))

#define XEN_GETDOMAININFO_SIZE                  \
    (hypervisor_version < 2 ?                   \
     sizeof(xen_v0_getdomaininfo) :             \
     sizeof(xen_v2_getdomaininfo))

#define XEN_GETDOMAININFO_CLEAR(dominfo)                        \
    (hypervisor_version < 2 ?                                   \
     memset(&(dominfo.v0), 0, sizeof(xen_v0_getdomaininfo)) :   \
     memset(&(dominfo.v2), 0, sizeof(xen_v2_getdomaininfo)))

#define XEN_GETDOMAININFO_DOMAIN(dominfo)       \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.domain :                        \
     dominfo.v2.domain)

#define XEN_GETDOMAININFO_CPUTIME(dominfo)      \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.cpu_time :                      \
     dominfo.v2.cpu_time)

#define XEN_GETDOMAININFO_CPUCOUNT(dominfo)     \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.nr_online_vcpus :               \
     dominfo.v2.nr_online_vcpus)

#define XEN_GETDOMAININFO_FLAGS(dominfo)        \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.flags :                         \
     dominfo.v2.flags)

#define XEN_GETDOMAININFO_TOT_PAGES(dominfo)    \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.tot_pages :                     \
     dominfo.v2.tot_pages)

#define XEN_GETDOMAININFO_MAX_PAGES(dominfo)    \
    (hypervisor_version < 2 ?                   \
     dominfo.v0.max_pages :                     \
     dominfo.v2.max_pages)



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
#define XEN_V2_OP_SETMAXMEM	14

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
    domid_t	domain;		/* owner's domain */
    uint32_t	vcpu;		/* the vcpu number */
    uint8_t	online;		/* seen as on line */
    uint8_t	blocked;	/* blocked on event */
    uint8_t	running;	/* scheduled on CPU */
    uint64_t    cpu_time;	/* nanosecond of CPU used */
    uint32_t	cpu;		/* current mapping */
};
typedef struct xen_v2_vcpuinfo xen_v2_vcpuinfo;

/*
 * from V2 the pinning of a vcpu is read with a separate call
 */
#define XEN_V2_OP_GETVCPUMAP	25
typedef struct xen_v2_setvcpumap xen_v2_getvcpumap;

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
        xen_v2_getdomaininfolistop getdomaininfolist;
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
        xen_v2_setmaxvcpu        setmaxvcpu;
        xen_v2_setvcpumap        setvcpumap;
        xen_v2_vcpuinfo          getvcpuinfo;
        xen_v2_getvcpumap        getvcpumap;
        uint8_t padding[128];
    } u;
};
typedef struct xen_op_v2_dom xen_op_v2_dom;

#include "internal.h"
#include "driver.h"
#include "xen_internal.h"

#define XEN_HYPERVISOR_SOCKET "/proc/xen/privcmd"

#ifndef PROXY
static const char * xenHypervisorGetType(virConnectPtr conn);
static unsigned long xenHypervisorGetMaxMemory(virDomainPtr domain);
#endif
static int xenHypervisorInit(void);

#ifndef PROXY
static virDriver xenHypervisorDriver = {
    VIR_DRV_XEN_HYPERVISOR,
    "Xen",
    (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
    (DOM0_INTERFACE_VERSION & 0xFFFF),
    xenHypervisorInit, /* init */
    xenHypervisorOpen, /* open */
    xenHypervisorClose, /* close */
    xenHypervisorGetType, /* type */
    xenHypervisorGetVersion, /* version */
    NULL, /* nodeGetInfo */
    xenHypervisorListDomains, /* listDomains */
    xenHypervisorNumOfDomains, /* numOfDomains */
    NULL, /* domainCreateLinux */
    NULL, /* domainLookupByID */
    NULL, /* domainLookupByUUID */
    NULL, /* domainLookupByName */
    xenHypervisorPauseDomain, /* domainSuspend */
    xenHypervisorResumeDomain, /* domainResume */
    NULL, /* domainShutdown */
    NULL, /* domainReboot */
    xenHypervisorDestroyDomain, /* domainDestroy */
    NULL, /* domainFree */
    NULL, /* domainGetName */
    NULL, /* domainGetID */
    NULL, /* domainGetUUID */
    NULL, /* domainGetOSType */
    xenHypervisorGetMaxMemory, /* domainGetMaxMemory */
    xenHypervisorSetMaxMemory, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    xenHypervisorGetDomainInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL, /* domainRestore */
    xenHypervisorSetVcpus, /* domainSetVcpus */
    xenHypervisorPinVcpu, /* domainPinVcpu */
    xenHypervisorGetVcpus, /* domainGetVcpus */
    NULL, /* domainDumpXML */
    NULL, /* listDefinedDomains */
    NULL, /* numOfDefinedDomains */
    NULL, /* domainCreate */
    NULL, /* domainDefineXML */
    NULL, /* domainUndefine */
};
#endif /* !PROXY */

/**
 * virXenError:
 * @conn: the connection if available
 * @error: the error number
 * @info: extra information string
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
    __virRaiseError(NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
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

#ifndef PROXY
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
#endif /* PROXY */

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
        op.u.getdomaininfolist.first_domain = (domid_t) first_domain;
        op.u.getdomaininfolist.max_domains = maxids;
        op.u.getdomaininfolist.buffer = dominfos->v2;
        op.u.getdomaininfolist.num_domains = maxids;
        ret = xenHypervisorDoV2Sys(handle, &op);
        if (ret == 0)
            ret = op.u.getdomaininfolist.num_domains;
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
        op.u.setmaxmem.maxmem = memory;
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
        op.u.setvcpumap.vcpu = vcpu;
        op.u.setvcpumap.cpumap.bitmap = cpumap;
        op.u.setvcpumap.cpumap.nr_cpus = maplen * 8;
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
        op.u.setvcpumap.vcpu = vcpu;
        ret = xenHypervisorDoV2Dom(handle, &op);
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
            if (mlock(cpumap, maplen) < 0) {
                virXenError(VIR_ERR_XEN_CALL, " locking", maplen);
                return (-1);
            }
            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V2_OP_GETVCPUMAP;
            op.domain = (domid_t) id;
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap.bitmap = cpumap;
            op.u.setvcpumap.cpumap.nr_cpus = maplen * 8;
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
#endif /* !PROXY*/

/**
 * xenHypervisorInit:
 *
 * Initialize the hypervisor layer. Try to detect the kind of interface
 * used i.e. pre or post changeset 10277
 */
int xenHypervisorInit(void)
{
    int fd, ret, cmd;
    hypercall_t hc;
    v0_hypercall_t v0_hc;
    xen_getdomaininfo info;

    if (initialized) {
        if (hypervisor_version == -1)
            return(-1);
        return(0);
    }
    initialized = 1;
    in_init = 1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        hypervisor_version = -1;
        return (-1);
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
    /* TODO: one probably will need to autodetect thse subversions too */
    sys_interface_version = 2; /* XEN_SYSCTL_INTERFACE_VERSION */
    dom_interface_version = 3; /* XEN_DOMCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
#ifdef DEBUG
        fprintf(stderr, "Using hypervisor call v2, sys version 2\n");
#endif
        goto done;
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
    return(-1);

 done:
    close(fd);
    in_init = 0;
    return(0);
}

#ifndef PROXY
/**
 * xenHypervisorRegister:
 *
 * Registers the xenHypervisor driver
 */
void xenHypervisorRegister(void)
{
    if (initialized == 0)
        xenHypervisorInit();

    virRegisterDriver(&xenHypervisorDriver);
}
#endif /* !PROXY */

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
xenHypervisorOpen(virConnectPtr conn, const char *name, int flags)
{
    int ret;

    if (initialized == 0)
        xenHypervisorInit();

    if ((name != NULL) && (strcasecmp(name, "xen")))
        return(-1);

    conn->handle = -1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
            virXenError(VIR_ERR_NO_XEN, XEN_HYPERVISOR_SOCKET, 0);
        return (-1);
    }
    conn->handle = ret;

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

    if ((conn == NULL) || (conn->handle < 0))
        return (-1);

    ret = close(conn->handle);
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
    if ((conn == NULL) || (conn->handle < 0) || (hvVer == NULL))
        return (-1);
    *hvVer = (hv_version >> 16) * 1000000 + (hv_version & 0xFFFF) * 1000;
    return(0);
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

    if ((conn == NULL) || (conn->handle < 0))
        return (-1);

 retry:
    if (!(XEN_GETDOMAININFOLIST_ALLOC(dominfos, maxids))) {
        virXenError(VIR_ERR_NO_MEMORY, _("allocating %d domain info"),
                    maxids);
        return(-1);
    }

    XEN_GETDOMAININFOLIST_CLEAR(dominfos, maxids);

    ret = virXen_getdomaininfolist(conn->handle, 0, maxids, &dominfos);

    XEN_GETDOMAININFOLIST_FREE(dominfos);

    if (ret < 0)
        return (-1);

    nbids = ret;
    if (nbids == maxids) {
        last_maxids *= 2;
        maxids *= 2;
        goto retry;
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

    if ((conn == NULL) || (conn->handle < 0) ||
        (ids == NULL) || (maxids < 1))
        return (-1);

    if (!(XEN_GETDOMAININFOLIST_ALLOC(dominfos, maxids))) {
        virXenError(VIR_ERR_NO_MEMORY, "allocating %d domain info",
                    maxids);
        return(-1);
    }

    XEN_GETDOMAININFOLIST_CLEAR(dominfos, maxids);
    memset(ids, 0, maxids * sizeof(int));

    ret = virXen_getdomaininfolist(conn->handle, 0, maxids, &dominfos);

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
    xen_getdomaininfo dominfo;
    int ret;

    if ((conn == NULL) || (conn->handle < 0))
        return (0);

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE) / 1024;
	if (kb_per_pages <= 0) 
	    kb_per_pages = 4;
    }

    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(conn->handle, id, &dominfo);

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
    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (0);

    return(xenHypervisorGetDomMaxMemory(domain->conn, domain->handle));
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
    xen_getdomaininfo dominfo;
    int ret;
    uint32_t domain_flags, domain_state, domain_shutdown_cause;

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE) / 1024;
	if (kb_per_pages <= 0) 
	    kb_per_pages = 4;
    }

    if ((conn == NULL) || (conn->handle < 0) || (info == NULL))
        return (-1);

    memset(info, 0, sizeof(virDomainInfo));
    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(conn->handle, id, &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != id))
        return (-1);

    domain_flags = XEN_GETDOMAININFO_FLAGS(dominfo);
    domain_state = domain_flags & 0xFF;
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
    info->maxMem = XEN_GETDOMAININFO_MAX_PAGES(dominfo) * kb_per_pages;
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
    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0) || (info == NULL) ||
        (domain->handle < 0))
        return (-1);
    return(xenHypervisorGetDomInfo(domain->conn, domain->handle, info));

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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    ret = virXen_pausedomain(domain->conn->handle, domain->handle);
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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    ret = virXen_unpausedomain(domain->conn->handle, domain->handle);
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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    ret = virXen_destroydomain(domain->conn->handle, domain->handle);
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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    ret = virXen_setmaxmem(domain->conn->handle, domain->handle, memory);
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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0) || (nvcpus < 1))
        return (-1);

    ret = virXen_setmaxvcpus(domain->conn->handle, domain->handle, nvcpus);
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

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0) || (cpumap == NULL) || (maplen < 1))
        return (-1);

    ret = virXen_setvcpumap(domain->conn->handle, domain->handle, vcpu,
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

    virVcpuInfoPtr ipt;
    int nbinfo, i;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->conn->handle < 0)
        || (info == NULL) || (maxinfo < 1)
        || (sizeof(cpumap_t) & 7))
        return (-1);
    if ((cpumaps != NULL) && (maplen < 1))
        return -1;

    /* first get the number of virtual CPUs in this domain */
    XEN_GETDOMAININFO_CLEAR(dominfo);
    ret = virXen_getdomaininfo(domain->conn->handle, domain->handle,
                               &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != domain->handle))
        return (-1);
    nbinfo = XEN_GETDOMAININFO_CPUCOUNT(dominfo) + 1;
    if (nbinfo > maxinfo) nbinfo = maxinfo;

    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0, ipt = info; i < nbinfo; i++, ipt++) {
        if ((cpumaps != NULL) && (i < maxinfo)) {
            ret = virXen_getvcpusinfo(domain->conn->handle, domain->handle, i,
                                      ipt,
                                      (unsigned char *)VIR_GET_CPUMAP(cpumaps, maplen, i),
                                      maplen);
            if (ret < 0)
                return(-1);
        } else {
            ret = virXen_getvcpusinfo(domain->conn->handle, domain->handle, i,
                                      ipt, NULL, 0);
            if (ret < 0)
                return(-1);
        }
    }
    return nbinfo;
}
#endif

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
