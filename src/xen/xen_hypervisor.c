/*
 * xen_hypervisor.c: direct access to Xen hypervisor level
 *
 * Copyright (C) 2005-2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

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
#include <regex.h>
#include <errno.h>

#ifdef __sun
# include <sys/systeminfo.h>

# include <priv.h>

# ifndef PRIV_XVM_CONTROL
#  define PRIV_XVM_CONTROL ((const char *)"xvm_control")
# endif

#endif /* __sun */

/* required for dom0_getdomaininfo_t */
#include <xen/dom0_ops.h>
#include <xen/version.h>
#ifdef HAVE_XEN_LINUX_PRIVCMD_H
# include <xen/linux/privcmd.h>
#else
# ifdef HAVE_XEN_SYS_PRIVCMD_H
#  include <xen/sys/privcmd.h>
# endif
#endif

/* required for shutdown flags */
#include <xen/sched.h>

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "driver.h"
#include "xen_driver.h"
#include "xen_hypervisor.h"
#include "xs_internal.h"
#include "virnetdevtap.h"
#include "block_stats.h"
#include "xend_internal.h"
#include "virbuffer.h"
#include "capabilities.h"
#include "viralloc.h"
#include "virthread.h"
#include "virfile.h"
#include "virnodesuspend.h"
#include "virtypedparam.h"
#include "virendian.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_XEN

VIR_LOG_INIT("xen.xen_hypervisor");

/*
 * so far there is 2 versions of the structures usable for doing
 * hypervisor calls.
 */
/* the old one */
typedef struct v0_hypercall_struct {
    unsigned long op;
    unsigned long arg[5];
} v0_hypercall_t;

#ifdef __linux__
# define XEN_V0_IOCTL_HYPERCALL_CMD \
        _IOC(_IOC_NONE, 'P', 0, sizeof(v0_hypercall_t))
/* the new one */
typedef struct v1_hypercall_struct
{
    uint64_t op;
    uint64_t arg[5];
} v1_hypercall_t;
# define XEN_V1_IOCTL_HYPERCALL_CMD                  \
    _IOC(_IOC_NONE, 'P', 0, sizeof(v1_hypercall_t))
typedef v1_hypercall_t hypercall_t;
#elif defined(__sun)
typedef privcmd_hypercall_t hypercall_t;
#else
# error "unsupported platform"
#endif

#ifndef __HYPERVISOR_sysctl
# define __HYPERVISOR_sysctl 35
#endif
#ifndef __HYPERVISOR_domctl
# define __HYPERVISOR_domctl 36
#endif

#define SYS_IFACE_MIN_VERS_NUMA 4

static int xen_ioctl_hypercall_cmd;
static struct xenHypervisorVersions hv_versions = {
    .hv = 0,
    .hypervisor = 2,
    .sys_interface = -1,
    .dom_interface = -1,
};

static int kb_per_pages;

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
# define DOMFLAGS_DYING     (1<<0) /* Domain is scheduled to die.             */
# define DOMFLAGS_HVM       (1<<1) /* Domain is HVM                           */
# define DOMFLAGS_SHUTDOWN  (1<<2) /* The guest OS has shut down.             */
# define DOMFLAGS_PAUSED    (1<<3) /* Currently paused by control software.   */
# define DOMFLAGS_BLOCKED   (1<<4) /* Currently blocked pending an event.     */
# define DOMFLAGS_RUNNING   (1<<5) /* Domain is currently running.            */
# define DOMFLAGS_CPUMASK      255 /* CPU to which this domain is bound.      */
# define DOMFLAGS_CPUSHIFT       8
# define DOMFLAGS_SHUTDOWNMASK 255 /* DOMFLAGS_SHUTDOWN guest-supplied code.  */
# define DOMFLAGS_SHUTDOWNSHIFT 16
#endif

/*
 * These flags explain why a system is in the state of "shutdown".  Normally,
 * They are defined in xen/sched.h
 */
#ifndef SHUTDOWN_poweroff
# define SHUTDOWN_poweroff   0  /* Domain exited normally. Clean up and kill. */
# define SHUTDOWN_reboot     1  /* Clean up, kill, and then restart.          */
# define SHUTDOWN_suspend    2  /* Clean up, save suspend info, kill.         */
# define SHUTDOWN_crash      3  /* Tell controller we've crashed.             */
#endif

#define XEN_V0_OP_GETDOMAININFOLIST	38
#define XEN_V1_OP_GETDOMAININFOLIST	38
#define XEN_V2_OP_GETDOMAININFOLIST	6

struct xen_v0_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* flags, see before */
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
    uint32_t flags;	/* flags, see before */
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
    uint32_t flags;	/* flags, see before */
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

struct xen_v2d6_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* flags, see before */
    uint64_t tot_pages ALIGN_64;	/* total number of pages used */
    uint64_t max_pages ALIGN_64;	/* maximum number of pages allowed */
    uint64_t shr_pages ALIGN_64;    /* number of shared pages */
    uint64_t shared_info_frame ALIGN_64; /* MFN of shared_info struct */
    uint64_t cpu_time ALIGN_64;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
};
typedef struct xen_v2d6_getdomaininfo xen_v2d6_getdomaininfo;

struct xen_v2d7_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* flags, see before */
    uint64_t tot_pages ALIGN_64;	/* total number of pages used */
    uint64_t max_pages ALIGN_64;	/* maximum number of pages allowed */
    uint64_t shr_pages ALIGN_64;    /* number of shared pages */
    uint64_t shared_info_frame ALIGN_64; /* MFN of shared_info struct */
    uint64_t cpu_time ALIGN_64;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
    uint32_t cpupool;
};
typedef struct xen_v2d7_getdomaininfo xen_v2d7_getdomaininfo;

struct xen_v2d8_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* flags, see before */
    uint64_t tot_pages ALIGN_64;	/* total number of pages used */
    uint64_t max_pages ALIGN_64;	/* maximum number of pages allowed */
    uint64_t shr_pages ALIGN_64;    /* number of shared pages */
    uint64_t paged_pages ALIGN_64;    /* number of paged pages */
    uint64_t shared_info_frame ALIGN_64; /* MFN of shared_info struct */
    uint64_t cpu_time ALIGN_64;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
    uint32_t cpupool;
};
typedef struct xen_v2d8_getdomaininfo xen_v2d8_getdomaininfo;

struct xen_v2d9_getdomaininfo {
    domid_t  domain;	/* the domain number */
    uint32_t flags;	/* flags, see before */
    uint64_t tot_pages ALIGN_64;	/* total number of pages used */
    uint64_t max_pages ALIGN_64;	/* maximum number of pages allowed */
    uint64_t outstanding_pages ALIGN_64;
    uint64_t shr_pages ALIGN_64;    /* number of shared pages */
    uint64_t paged_pages ALIGN_64;    /* number of paged pages */
    uint64_t shared_info_frame ALIGN_64; /* MFN of shared_info struct */
    uint64_t cpu_time ALIGN_64;  /* CPU time used */
    uint32_t nr_online_vcpus;  /* Number of VCPUs currently online. */
    uint32_t max_vcpu_id; /* Maximum VCPUID in use by this domain. */
    uint32_t ssidref;
    xen_domain_handle_t handle;
    uint32_t cpupool;
};
typedef struct xen_v2d9_getdomaininfo xen_v2d9_getdomaininfo;

union xen_getdomaininfo {
    struct xen_v0_getdomaininfo v0;
    struct xen_v2_getdomaininfo v2;
    struct xen_v2d5_getdomaininfo v2d5;
    struct xen_v2d6_getdomaininfo v2d6;
    struct xen_v2d7_getdomaininfo v2d7;
    struct xen_v2d8_getdomaininfo v2d8;
    struct xen_v2d9_getdomaininfo v2d9;
};
typedef union xen_getdomaininfo xen_getdomaininfo;

union xen_getdomaininfolist {
    struct xen_v0_getdomaininfo *v0;
    struct xen_v2_getdomaininfo *v2;
    struct xen_v2d5_getdomaininfo *v2d5;
    struct xen_v2d6_getdomaininfo *v2d6;
    struct xen_v2d7_getdomaininfo *v2d7;
    struct xen_v2d8_getdomaininfo *v2d8;
    struct xen_v2d9_getdomaininfo *v2d9;
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

struct xen_v2s4_availheap {
    uint32_t min_bitwidth;  /* Smallest address width (zero if don't care). */
    uint32_t max_bitwidth;  /* Largest address width (zero if don't care). */
    int32_t  node;          /* NUMA node (-1 for sum across all nodes). */
    uint64_t avail_bytes;   /* Bytes available in the specified region. */
};

typedef struct xen_v2s4_availheap  xen_v2s4_availheap;

struct xen_v2s5_availheap {
    uint32_t min_bitwidth;  /* Smallest address width (zero if don't care). */
    uint32_t max_bitwidth;  /* Largest address width (zero if don't care). */
    int32_t  node;          /* NUMA node (-1 for sum across all nodes). */
    uint64_t avail_bytes ALIGN_64;   /* Bytes available in the specified region. */
};

typedef struct xen_v2s5_availheap  xen_v2s5_availheap;


#define XEN_GETDOMAININFOLIST_ALLOC(domlist, size)                      \
    (hv_versions.hypervisor < 2 ?                                       \
     (VIR_ALLOC_N(domlist.v0, (size)) == 0) :                           \
     (hv_versions.dom_interface >= 9 ?                                  \
      (VIR_ALLOC_N(domlist.v2d9, (size)) == 0) :                        \
     (hv_versions.dom_interface == 8 ?                                  \
      (VIR_ALLOC_N(domlist.v2d8, (size)) == 0) :                        \
     (hv_versions.dom_interface == 7 ?                                  \
      (VIR_ALLOC_N(domlist.v2d7, (size)) == 0) :                        \
     (hv_versions.dom_interface == 6 ?                                  \
      (VIR_ALLOC_N(domlist.v2d6, (size)) == 0) :                        \
     (hv_versions.dom_interface == 5 ?                                  \
      (VIR_ALLOC_N(domlist.v2d5, (size)) == 0) :                        \
      (VIR_ALLOC_N(domlist.v2, (size)) == 0)))))))

#define XEN_GETDOMAININFOLIST_FREE(domlist)            \
    (hv_versions.hypervisor < 2 ?                      \
     VIR_FREE(domlist.v0) :                            \
     (hv_versions.dom_interface >= 9 ?                 \
      VIR_FREE(domlist.v2d9) :                         \
     (hv_versions.dom_interface == 8 ?                 \
      VIR_FREE(domlist.v2d8) :                         \
     (hv_versions.dom_interface == 7 ?                 \
      VIR_FREE(domlist.v2d7) :                         \
     (hv_versions.dom_interface == 6 ?                 \
      VIR_FREE(domlist.v2d6) :                         \
     (hv_versions.dom_interface == 5 ?                 \
      VIR_FREE(domlist.v2d5) :                         \
      VIR_FREE(domlist.v2)))))))

#define XEN_GETDOMAININFOLIST_CLEAR(domlist, size)            \
    (hv_versions.hypervisor < 2 ?                             \
     memset(domlist.v0, 0, sizeof(*domlist.v0) * size) :      \
     (hv_versions.dom_interface >= 9 ?                        \
      memset(domlist.v2d9, 0, sizeof(*domlist.v2d9) * size) : \
     (hv_versions.dom_interface == 8 ?                        \
      memset(domlist.v2d8, 0, sizeof(*domlist.v2d8) * size) : \
     (hv_versions.dom_interface == 7 ?                        \
      memset(domlist.v2d7, 0, sizeof(*domlist.v2d7) * size) : \
     (hv_versions.dom_interface == 6 ?                        \
      memset(domlist.v2d6, 0, sizeof(*domlist.v2d6) * size) : \
     (hv_versions.dom_interface == 5 ?                        \
      memset(domlist.v2d5, 0, sizeof(*domlist.v2d5) * size) : \
      memset(domlist.v2, 0, sizeof(*domlist.v2) * size)))))))

#define XEN_GETDOMAININFOLIST_DOMAIN(domlist, n)    \
    (hv_versions.hypervisor < 2 ?                   \
     domlist.v0[n].domain :                         \
     (hv_versions.dom_interface >= 9 ?              \
      domlist.v2d9[n].domain :                      \
     (hv_versions.dom_interface == 8 ?              \
      domlist.v2d8[n].domain :                      \
     (hv_versions.dom_interface == 7 ?              \
      domlist.v2d7[n].domain :                      \
     (hv_versions.dom_interface == 6 ?              \
      domlist.v2d6[n].domain :                      \
     (hv_versions.dom_interface == 5 ?              \
      domlist.v2d5[n].domain :                      \
      domlist.v2[n].domain))))))

#define XEN_GETDOMAININFOLIST_UUID(domlist, n)      \
    (hv_versions.hypervisor < 2 ?                   \
     domlist.v0[n].handle :                         \
     (hv_versions.dom_interface >= 9 ?              \
      domlist.v2d9[n].handle :                      \
     (hv_versions.dom_interface == 8 ?              \
      domlist.v2d8[n].handle :                      \
     (hv_versions.dom_interface == 7 ?              \
      domlist.v2d7[n].handle :                      \
     (hv_versions.dom_interface == 6 ?              \
      domlist.v2d6[n].handle :                      \
     (hv_versions.dom_interface == 5 ?              \
      domlist.v2d5[n].handle :                      \
      domlist.v2[n].handle))))))

#define XEN_GETDOMAININFOLIST_DATA(domlist)        \
    (hv_versions.hypervisor < 2 ?                  \
     (void*)(domlist->v0) :                        \
     (hv_versions.dom_interface >= 9 ?             \
      (void*)(domlist->v2d9) :                     \
     (hv_versions.dom_interface == 8 ?             \
      (void*)(domlist->v2d8) :                     \
     (hv_versions.dom_interface == 7 ?             \
      (void*)(domlist->v2d7) :                     \
     (hv_versions.dom_interface == 6 ?             \
      (void*)(domlist->v2d6) :                     \
     (hv_versions.dom_interface == 5 ?             \
      (void*)(domlist->v2d5) :                     \
      (void*)(domlist->v2)))))))

#define XEN_GETDOMAININFO_SIZE                     \
    (hv_versions.hypervisor < 2 ?                  \
     sizeof(xen_v0_getdomaininfo) :                \
     (hv_versions.dom_interface >= 9 ?             \
      sizeof(xen_v2d9_getdomaininfo) :             \
     (hv_versions.dom_interface == 8 ?             \
      sizeof(xen_v2d8_getdomaininfo) :             \
     (hv_versions.dom_interface == 7 ?             \
      sizeof(xen_v2d7_getdomaininfo) :             \
     (hv_versions.dom_interface == 6 ?             \
      sizeof(xen_v2d6_getdomaininfo) :             \
     (hv_versions.dom_interface == 5 ?             \
      sizeof(xen_v2d5_getdomaininfo) :             \
      sizeof(xen_v2_getdomaininfo)))))))

#define XEN_GETDOMAININFO_CLEAR(dominfo)                           \
    (hv_versions.hypervisor < 2 ?                                  \
     memset(&(dominfo.v0), 0, sizeof(xen_v0_getdomaininfo)) :      \
     (hv_versions.dom_interface >= 9 ?                             \
      memset(&(dominfo.v2d9), 0, sizeof(xen_v2d9_getdomaininfo)) : \
     (hv_versions.dom_interface == 8 ?                             \
      memset(&(dominfo.v2d8), 0, sizeof(xen_v2d8_getdomaininfo)) : \
     (hv_versions.dom_interface == 7 ?                             \
      memset(&(dominfo.v2d7), 0, sizeof(xen_v2d7_getdomaininfo)) : \
     (hv_versions.dom_interface == 6 ?                             \
      memset(&(dominfo.v2d6), 0, sizeof(xen_v2d6_getdomaininfo)) : \
     (hv_versions.dom_interface == 5 ?                             \
      memset(&(dominfo.v2d5), 0, sizeof(xen_v2d5_getdomaininfo)) : \
      memset(&(dominfo.v2), 0, sizeof(xen_v2_getdomaininfo))))))))

#define XEN_GETDOMAININFO_DOMAIN(dominfo)       \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.domain :                        \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.domain :                     \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.domain :                     \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.domain :                     \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.domain :                     \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.domain :                     \
      dominfo.v2.domain))))))

#define XEN_GETDOMAININFO_CPUTIME(dominfo)      \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.cpu_time :                      \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.cpu_time :                   \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.cpu_time :                   \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.cpu_time :                   \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.cpu_time :                   \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.cpu_time :                   \
      dominfo.v2.cpu_time))))))


#define XEN_GETDOMAININFO_CPUCOUNT(dominfo)     \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.nr_online_vcpus :               \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.nr_online_vcpus :            \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.nr_online_vcpus :            \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.nr_online_vcpus :            \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.nr_online_vcpus :            \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.nr_online_vcpus :            \
      dominfo.v2.nr_online_vcpus))))))

#define XEN_GETDOMAININFO_MAXCPUID(dominfo)     \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.max_vcpu_id :                   \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.max_vcpu_id :                \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.max_vcpu_id :                \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.max_vcpu_id :                \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.max_vcpu_id :                \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.max_vcpu_id :                \
      dominfo.v2.max_vcpu_id))))))

#define XEN_GETDOMAININFO_FLAGS(dominfo)        \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.flags :                         \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.flags :                      \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.flags :                      \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.flags :                      \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.flags :                      \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.flags :                      \
      dominfo.v2.flags))))))

#define XEN_GETDOMAININFO_TOT_PAGES(dominfo)    \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.tot_pages :                     \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.tot_pages :                  \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.tot_pages :                  \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.tot_pages :                  \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.tot_pages :                  \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.tot_pages :                  \
      dominfo.v2.tot_pages))))))

#define XEN_GETDOMAININFO_MAX_PAGES(dominfo)    \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.max_pages :                     \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.max_pages :                  \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.max_pages :                  \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.max_pages :                  \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.max_pages :                  \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.max_pages :                  \
      dominfo.v2.max_pages))))))

#define XEN_GETDOMAININFO_UUID(dominfo)         \
    (hv_versions.hypervisor < 2 ?               \
     dominfo.v0.handle :                        \
     (hv_versions.dom_interface >= 9 ?          \
      dominfo.v2d9.handle :                     \
     (hv_versions.dom_interface == 8 ?          \
      dominfo.v2d8.handle :                     \
     (hv_versions.dom_interface == 7 ?          \
      dominfo.v2d7.handle :                     \
     (hv_versions.dom_interface == 6 ?          \
      dominfo.v2d6.handle :                     \
     (hv_versions.dom_interface == 5 ?          \
      dominfo.v2d5.handle :                     \
      dominfo.v2.handle))))))


static int
lock_pages(void *addr, size_t len)
{
#ifdef __linux__
    if (mlock(addr, len) < 0) {
        virReportSystemError(errno,
                             _("Unable to lock %zu bytes of memory"),
                             len);
        return -1;
    }
    return 0;
#elif defined(__sun)
    return 0;
#endif
}

static int
unlock_pages(void *addr, size_t len)
{
#ifdef __linux__
    if (munlock(addr, len) < 0) {
        virReportSystemError(errno,
                             _("Unable to unlock %zu bytes of memory"),
                             len);
        return -1;
    }
    return 0;
#elif defined(__sun)
    return 0;
#endif
}


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
#ifdef __BIG_ENDIAN__
    struct {
        int __pad[(sizeof(long long) - sizeof(struct xen_v2d5_getdomaininfo *)) / sizeof(int)];
        struct xen_v2d5_getdomaininfo *v;
    } buffer;
#else
    union {
        struct xen_v2d5_getdomaininfo *v;
        uint64_t pad ALIGN_64;
    } buffer;
#endif
    uint32_t  num_domains;
};
typedef struct xen_v2s3_getdomaininfolistop xen_v2s3_getdomaininfolistop;



struct xen_v0_domainop {
    domid_t   domain;
};
typedef struct xen_v0_domainop xen_v0_domainop;

/*
 * The information for a pausedomain system hypercall
 */
#define XEN_V0_OP_PAUSEDOMAIN	10
#define XEN_V1_OP_PAUSEDOMAIN	10
#define XEN_V2_OP_PAUSEDOMAIN	3

/*
 * The information for an unpausedomain system hypercall
 */
#define XEN_V0_OP_UNPAUSEDOMAIN	11
#define XEN_V1_OP_UNPAUSEDOMAIN	11
#define XEN_V2_OP_UNPAUSEDOMAIN	4

/*
 * The information for a setmaxmem system hypercall
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
 * The information for a setvcpumap system hypercall
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
#ifdef __BIG_ENDIAN__
    struct {
        int __pad[(sizeof(long long) - sizeof(uint8_t *)) / sizeof(int)];
        uint8_t *v;
    } bitmap;
#else
    union {
        uint8_t    *v;
        uint64_t   pad ALIGN_64;
    } bitmap;
#endif
    uint32_t    nr_cpus;
};
struct xen_v2d5_setvcpumap {
    uint32_t	vcpu;
    struct xen_v2d5_cpumap cpumap;
};
typedef struct xen_v2d5_setvcpumap xen_v2d5_setvcpumap;

/*
 * The information for a vcpuinfo system hypercall
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
 * from V2 we get the available heap information
 */
#define XEN_V2_OP_GETAVAILHEAP		9

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
        xen_v2s4_availheap           availheap;
        xen_v2s5_availheap           availheap5;
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


#ifdef __linux__
# define XEN_HYPERVISOR_SOCKET	"/proc/xen/privcmd"
# define HYPERVISOR_CAPABILITIES	"/sys/hypervisor/properties/capabilities"
#elif defined(__sun)
# define XEN_HYPERVISOR_SOCKET	"/dev/xen/privcmd"
#else
# error "unsupported platform"
#endif

/**
 * xenHypervisorDoV0Op:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor operation structure
 *
 * Do a hypervisor operation though the old interface,
 * this leads to a hypervisor call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoV0Op(int handle, xen_op_v0 * op)
{
    int ret;
    v0_hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = hv_versions.hv << 8;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (lock_pages(op, sizeof(dom0_op_t)) < 0)
        return -1;

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virReportSystemError(errno,
                             _("Unable to issue hypervisor ioctl %d"),
                             xen_ioctl_hypercall_cmd);
    }

    if (unlock_pages(op, sizeof(dom0_op_t)) < 0)
        ret = -1;

    if (ret < 0)
        return -1;

    return 0;
}
/**
 * xenHypervisorDoV1Op:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor operation structure
 *
 * Do a hypervisor v1 operation, this leads to a hypervisor call through
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

    if (lock_pages(op, sizeof(dom0_op_t)) < 0)
        return -1;

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virReportSystemError(errno,
                             _("Unable to issue hypervisor ioctl %d"),
                             xen_ioctl_hypercall_cmd);
    }

    if (unlock_pages(op, sizeof(dom0_op_t)) < 0)
        ret = -1;

    if (ret < 0)
        return -1;

    return 0;
}

/**
 * xenHypervisorDoV2Sys:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor operation structure
 *
 * Do a hypervisor v2 system operation, this leads to a hypervisor
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
    op->interface_version = hv_versions.sys_interface;
    hc.op = __HYPERVISOR_sysctl;
    hc.arg[0] = (unsigned long) op;

    if (lock_pages(op, sizeof(dom0_op_t)) < 0)
        return -1;

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virReportSystemError(errno,
                             _("Unable to issue hypervisor ioctl %d"),
                             xen_ioctl_hypercall_cmd);
    }

    if (unlock_pages(op, sizeof(dom0_op_t)) < 0)
        ret = -1;

    if (ret < 0)
        return -1;

    return 0;
}

/**
 * xenHypervisorDoV2Dom:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hypervisor domain operation structure
 *
 * Do a hypervisor v2 domain operation, this leads to a hypervisor
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
    op->interface_version = hv_versions.dom_interface;
    hc.op = __HYPERVISOR_domctl;
    hc.arg[0] = (unsigned long) op;

    if (lock_pages(op, sizeof(dom0_op_t)) < 0)
        return -1;

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virReportSystemError(errno,
                             _("Unable to issue hypervisor ioctl %d"),
                             xen_ioctl_hypercall_cmd);
    }

    if (unlock_pages(op, sizeof(dom0_op_t)) < 0)
        ret = -1;

    if (ret < 0)
        return -1;

    return 0;
}

/**
 * virXen_getdomaininfolist:
 * @handle: the hypervisor handle
 * @first_domain: first domain in the range
 * @maxids: maximum number of domains to list
 * @dominfos: output structures
 *
 * Do a low level hypercall to list existing domains information
 *
 * Returns the number of domains or -1 in case of failure
 */
static int
virXen_getdomaininfolist(int handle,
                         int first_domain,
                         int maxids,
                         xen_getdomaininfolist *dominfos)
{
    int ret = -1;

    if (lock_pages(XEN_GETDOMAININFOLIST_DATA(dominfos),
                   XEN_GETDOMAININFO_SIZE * maxids) < 0)
        return -1;

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_sys op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETDOMAININFOLIST;

        if (hv_versions.sys_interface < 3) {
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
            if (hv_versions.sys_interface < 3)
                ret = op.u.getdomaininfolist.num_domains;
            else
                ret = op.u.getdomaininfolists3.num_domains;
        }
    } else if (hv_versions.hypervisor == 1) {
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
    } else if (hv_versions.hypervisor == 0) {
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
    if (unlock_pages(XEN_GETDOMAININFOLIST_DATA(dominfos),
                     XEN_GETDOMAININFO_SIZE * maxids) < 0)
        ret = -1;

    return ret;
}

static int
virXen_getdomaininfo(int handle, int first_domain, xen_getdomaininfo *dominfo)
{
    xen_getdomaininfolist dominfos;

    if (hv_versions.hypervisor < 2) {
        dominfos.v0 = &(dominfo->v0);
    } else {
        dominfos.v2 = &(dominfo->v2);
    }

    return virXen_getdomaininfolist(handle, first_domain, 1, &dominfos);
}


/**
 * xenHypervisorGetSchedulerType:
 * @conn: the hypervisor connection
 * @nparams:give a number of scheduler parameters.
 *
 * Do a low level hypercall to get scheduler type
 *
 * Returns scheduler name or NULL in case of failure
 */
char *
xenHypervisorGetSchedulerType(virConnectPtr conn,
                              int *nparams)
{
    char *schedulertype = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    /*
     * Support only hv_versions.dom_interface >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (hv_versions.dom_interface < 5) {
        virReportError(VIR_ERR_NO_XEN, "%s",
                       _("unsupported in dom interface < 5"));
        return NULL;
    }

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_sys op;
        int ret;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op);
        if (ret < 0)
            return NULL;

        switch (op.u.getschedulerid.sched_id) {
            case XEN_SCHEDULER_SEDF:
                ignore_value(VIR_STRDUP(schedulertype, "sedf"));
                if (nparams)
                    *nparams = XEN_SCHED_SEDF_NPARAM;
                break;
            case XEN_SCHEDULER_CREDIT:
                ignore_value(VIR_STRDUP(schedulertype, "credit"));
                if (nparams)
                    *nparams = XEN_SCHED_CRED_NPARAM;
                break;
            default:
                break;
        }
    }

    return schedulertype;
}

/**
 * xenHypervisorGetSchedulerParameters:
 * @conn: the hypervisor connection
 * @def: domain configuration
 * @params: pointer to scheduler parameters.
 *     This memory area should be allocated before calling.
 * @nparams: this parameter must be at least as large as
 *     the given number of scheduler parameters.
 *     from xenHypervisorGetSchedulerType().
 *
 * Do a low level hypercall to get scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenHypervisorGetSchedulerParameters(virConnectPtr conn,
                                    virDomainDefPtr def,
                                    virTypedParameterPtr params,
                                    int *nparams)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    /*
     * Support only hv_versions.dom_interface >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (hv_versions.dom_interface < 5) {
        virReportError(VIR_ERR_NO_XEN, "%s",
                       _("unsupported in dom interface < 5"));
        return -1;
    }

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_sys op_sys;
        xen_op_v2_dom op_dom;
        int ret;

        memset(&op_sys, 0, sizeof(op_sys));
        op_sys.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op_sys);
        if (ret < 0)
            return -1;

        switch (op_sys.u.getschedulerid.sched_id) {
            case XEN_SCHEDULER_SEDF:
                if (*nparams < XEN_SCHED_SEDF_NPARAM) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   "%s", _("Invalid parameter count"));
                    return -1;
                }

                /* TODO: Implement for Xen/SEDF */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SEDF schedular parameters not supported"));
                return -1;
            case XEN_SCHEDULER_CREDIT:
                memset(&op_dom, 0, sizeof(op_dom));
                op_dom.cmd = XEN_V2_OP_SCHEDULER;
                op_dom.domain = (domid_t) def->id;
                op_dom.u.getschedinfo.sched_id = XEN_SCHEDULER_CREDIT;
                op_dom.u.getschedinfo.cmd = XEN_DOMCTL_SCHEDOP_getinfo;
                ret = xenHypervisorDoV2Dom(priv->handle, &op_dom);
                if (ret < 0)
                    return -1;

                if (virTypedParameterAssign(&params[0],
                                            VIR_DOMAIN_SCHEDULER_WEIGHT,
                                            VIR_TYPED_PARAM_UINT,
                                            op_dom.u.getschedinfo.u.credit.weight) < 0)
                    return -1;

                if (*nparams > 1 &&
                    virTypedParameterAssign(&params[1],
                                            VIR_DOMAIN_SCHEDULER_CAP,
                                            VIR_TYPED_PARAM_UINT,
                                            op_dom.u.getschedinfo.u.credit.cap) < 0)
                        return -1;

                if (*nparams > XEN_SCHED_CRED_NPARAM)
                    *nparams = XEN_SCHED_CRED_NPARAM;
                break;
            default:
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Unknown scheduler %d"),
                               op_sys.u.getschedulerid.sched_id);
                return -1;
        }
    }

    return 0;
}

/**
 * xenHypervisorSetSchedulerParameters:
 * @conn: the hypervisor connection
 * @def: domain configuration
 * @nparams:give a number of scheduler setting parameters .
 *
 * Do a low level hypercall to set scheduler parameters
 *
 * Returns 0 or -1 in case of failure
 */
int
xenHypervisorSetSchedulerParameters(virConnectPtr conn,
                                    virDomainDefPtr def,
                                    virTypedParameterPtr params,
                                    int nparams)
{
    size_t i;
    unsigned int val;
    xenUnifiedPrivatePtr priv = conn->privateData;
    char buf[256];

    if (nparams == 0) {
        /* nothing to do, exit early */
        return 0;
    }

    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_SCHEDULER_CAP,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    /*
     * Support only hv_versions.dom_interface >=5
     * (Xen3.1.0 or later)
     * TODO: check on Xen 3.0.3
     */
    if (hv_versions.dom_interface < 5) {
        virReportError(VIR_ERR_NO_XEN, "%s",
                       _("unsupported in dom interface < 5"));
        return -1;
    }

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_sys op_sys;
        xen_op_v2_dom op_dom;
        int ret;

        memset(&op_sys, 0, sizeof(op_sys));
        op_sys.cmd = XEN_V2_OP_GETSCHEDULERID;
        ret = xenHypervisorDoV2Sys(priv->handle, &op_sys);
        if (ret == -1) return -1;

        switch (op_sys.u.getschedulerid.sched_id) {
        case XEN_SCHEDULER_SEDF:
            /* TODO: Implement for Xen/SEDF */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("SEDF schedular parameters not supported"));
            return -1;
        case XEN_SCHEDULER_CREDIT: {
            memset(&op_dom, 0, sizeof(op_dom));
            op_dom.cmd = XEN_V2_OP_SCHEDULER;
            op_dom.domain = (domid_t) def->id;
            op_dom.u.getschedinfo.sched_id = XEN_SCHEDULER_CREDIT;
            op_dom.u.getschedinfo.cmd = XEN_DOMCTL_SCHEDOP_putinfo;

            /*
             * credit scheduler parameters
             * following values do not change the parameters
             */
            op_dom.u.getschedinfo.u.credit.weight = 0;
            op_dom.u.getschedinfo.u.credit.cap    = (uint16_t)~0U;

            for (i = 0; i < nparams; i++) {
                memset(&buf, 0, sizeof(buf));
                if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_WEIGHT)) {
                    val = params[i].value.ui;
                    if ((val < 1) || (val > USHRT_MAX)) {
                        virReportError(VIR_ERR_INVALID_ARG,
                                       _("Credit scheduler weight parameter (%d) "
                                         "is out of range (1-65535)"), val);
                        return -1;
                    }
                    op_dom.u.getschedinfo.u.credit.weight = val;
                } else if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_CAP)) {
                    val = params[i].value.ui;
                    if (val >= USHRT_MAX) {
                        virReportError(VIR_ERR_INVALID_ARG,
                                       _("Credit scheduler cap parameter (%d) is "
                                         "out of range (0-65534)"), val);
                        return -1;
                    }
                    op_dom.u.getschedinfo.u.credit.cap = val;
                }
            }

            ret = xenHypervisorDoV2Dom(priv->handle, &op_dom);
            if (ret < 0)
                return -1;
            break;
        }
        default:
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unknown scheduler %d"),
                           op_sys.u.getschedulerid.sched_id);
            return -1;
        }
    }

    return 0;
}


int
xenHypervisorDomainBlockStats(virConnectPtr conn,
                              virDomainDefPtr def,
                              const char *path,
                              virDomainBlockStatsPtr stats)
{
#ifdef __linux__
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret;

    xenUnifiedLock(priv);
    /* Need to lock because it hits the xenstore handle :-( */
    ret = xenLinuxDomainBlockStats(priv, def, path, stats);
    xenUnifiedUnlock(priv);
    return ret;
#else
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("block statistics not supported on this platform"));
    return -1;
#endif
}

/* Paths have the form vif<domid>.<n> (this interface checks that
 * <domid> is the real domain ID and returns an error if not).
 *
 * In future we may allow you to query bridge stats (virbrX or
 * xenbrX), but that will probably be through a separate
 * virNetwork interface, as yet not decided.
 */
int
xenHypervisorDomainInterfaceStats(virDomainDefPtr def,
                                  const char *path,
                                  virDomainInterfaceStatsPtr stats)
{
#ifdef __linux__
    int rqdomid, device;

    /* Verify that the vif requested is one belonging to the current
     * domain.
     */
    if (sscanf(path, "vif%d.%d", &rqdomid, &device) != 2) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid path, should be vif<domid>.<n>."));
        return -1;
    }
    if (rqdomid != def->id) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid path, vif<domid> should match this domain ID"));
        return -1;
    }

    return virNetDevTapInterfaceStats(path, stats);
#else
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("/proc/net/dev: Interface not found"));
    return -1;
#endif
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

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_SETMAXMEM;
        op.domain = (domid_t) id;
        if (hv_versions.dom_interface < 5)
            op.u.setmaxmem.maxmem = memory;
        else
            op.u.setmaxmemd5.maxmem = memory;
        ret = xenHypervisorDoV2Dom(handle, &op);
    } else if (hv_versions.hypervisor == 1) {
        xen_op_v1 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V1_OP_SETMAXMEM;
        op.u.setmaxmem.domain = (domid_t) id;
        op.u.setmaxmem.maxmem = memory;
        ret = xenHypervisorDoV1Op(handle, &op);
    } else if (hv_versions.hypervisor == 0) {
        xen_op_v0 op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V0_OP_SETMAXMEM;
        op.u.setmaxmem.domain = (domid_t) id;
        op.u.setmaxmem.maxmem = memory;
        ret = xenHypervisorDoV0Op(handle, &op);
    }
    return ret;
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
virXen_setvcpumap(int handle,
                  int id,
                  unsigned int vcpu,
                  unsigned char * cpumap,
                  int maplen)
{
    int ret = -1;
    unsigned char *new = NULL;
    unsigned char *bitmap = NULL;
    uint32_t nr_cpus;

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_dom op;

        if (lock_pages(cpumap, maplen) < 0)
            return -1;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_SETVCPUMAP;
        op.domain = (domid_t) id;

        /* The allocated memory to cpumap must be 'sizeof(uint64_t)' byte *
         * for Xen, and also nr_cpus must be 'sizeof(uint64_t) * 8'       */
        if (maplen < 8) {
            if (VIR_ALLOC_N(new, sizeof(uint64_t)) < 0)
                return -1;
            memcpy(new, cpumap, maplen);
            bitmap = new;
            nr_cpus = sizeof(uint64_t) * 8;
        } else {
            bitmap = cpumap;
            nr_cpus = maplen * 8;
        }

        if (hv_versions.dom_interface < 5) {
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap.bitmap = bitmap;
            op.u.setvcpumap.cpumap.nr_cpus = nr_cpus;
        } else {
            op.u.setvcpumapd5.vcpu = vcpu;
            op.u.setvcpumapd5.cpumap.bitmap.v = bitmap;
            op.u.setvcpumapd5.cpumap.nr_cpus = nr_cpus;
        }
        ret = xenHypervisorDoV2Dom(handle, &op);
        VIR_FREE(new);

        if (unlock_pages(cpumap, maplen) < 0)
            ret = -1;
    } else {
        cpumap_t xen_cpumap; /* limited to 64 CPUs in old hypervisors */
        char buf[8] = "";

        if (maplen > sizeof(cpumap_t) || sizeof(cpumap_t) != sizeof(uint64_t))
            return -1;
        /* Supply trailing 0s if user's input array was short */
        memcpy(buf, cpumap, maplen);
        xen_cpumap = virReadBufInt64LE(buf);

        if (hv_versions.hypervisor == 1) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V1_OP_SETVCPUMAP;
            op.u.setvcpumap.domain = (domid_t) id;
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap = xen_cpumap;
            ret = xenHypervisorDoV1Op(handle, &op);
        } else if (hv_versions.hypervisor == 0) {
            xen_op_v0 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V0_OP_SETVCPUMAP;
            op.u.setvcpumap.domain = (domid_t) id;
            op.u.setvcpumap.vcpu = vcpu;
            op.u.setvcpumap.cpumap = xen_cpumap;
            ret = xenHypervisorDoV0Op(handle, &op);
        }
    }
    return ret;
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
virXen_getvcpusinfo(int handle,
                    int id,
                    unsigned int vcpu,
                    virVcpuInfoPtr ipt,
                    unsigned char *cpumap,
                    int maplen)
{
    int ret = -1;

    if (hv_versions.hypervisor > 1) {
        xen_op_v2_dom op;

        memset(&op, 0, sizeof(op));
        op.cmd = XEN_V2_OP_GETVCPUINFO;
        op.domain = (domid_t) id;
        if (hv_versions.dom_interface < 5)
            op.u.getvcpuinfo.vcpu = (uint16_t) vcpu;
        else
            op.u.getvcpuinfod5.vcpu = (uint16_t) vcpu;
        ret = xenHypervisorDoV2Dom(handle, &op);

        if (ret < 0)
            return -1;
        ipt->number = vcpu;
        if (hv_versions.dom_interface < 5) {
            if (op.u.getvcpuinfo.online) {
                if (op.u.getvcpuinfo.running)
                    ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfo.blocked)
                    ipt->state = VIR_VCPU_BLOCKED;
            } else {
                ipt->state = VIR_VCPU_OFFLINE;
            }

            ipt->cpuTime = op.u.getvcpuinfo.cpu_time;
            ipt->cpu = op.u.getvcpuinfo.online ? (int)op.u.getvcpuinfo.cpu : -1;
        } else {
            if (op.u.getvcpuinfod5.online) {
                if (op.u.getvcpuinfod5.running)
                    ipt->state = VIR_VCPU_RUNNING;
                if (op.u.getvcpuinfod5.blocked)
                    ipt->state = VIR_VCPU_BLOCKED;
            } else {
                ipt->state = VIR_VCPU_OFFLINE;
            }

            ipt->cpuTime = op.u.getvcpuinfod5.cpu_time;
            ipt->cpu = op.u.getvcpuinfod5.online ? (int)op.u.getvcpuinfod5.cpu : -1;
        }
        if ((cpumap != NULL) && (maplen > 0)) {
            if (lock_pages(cpumap, maplen) < 0)
                return -1;

            memset(cpumap, 0, maplen);
            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V2_OP_GETVCPUMAP;
            op.domain = (domid_t) id;
            if (hv_versions.dom_interface < 5) {
                op.u.getvcpumap.vcpu = vcpu;
                op.u.getvcpumap.cpumap.bitmap = cpumap;
                op.u.getvcpumap.cpumap.nr_cpus = maplen * 8;
            } else {
                op.u.getvcpumapd5.vcpu = vcpu;
                op.u.getvcpumapd5.cpumap.bitmap.v = cpumap;
                op.u.getvcpumapd5.cpumap.nr_cpus = maplen * 8;
            }
            ret = xenHypervisorDoV2Dom(handle, &op);
            if (unlock_pages(cpumap, maplen) < 0)
                ret = -1;
        }
    } else {
        int mapl = maplen;
        int cpu;

        if (maplen > (int)sizeof(cpumap_t))
            mapl = (int)sizeof(cpumap_t);

        if (hv_versions.hypervisor == 1) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V1_OP_GETVCPUINFO;
            op.u.getvcpuinfo.domain = (domid_t) id;
            op.u.getvcpuinfo.vcpu = vcpu;
            ret = xenHypervisorDoV1Op(handle, &op);
            if (ret < 0)
                return -1;
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
        } else if (hv_versions.hypervisor == 0) {
            xen_op_v1 op;

            memset(&op, 0, sizeof(op));
            op.cmd = XEN_V0_OP_GETVCPUINFO;
            op.u.getvcpuinfo.domain = (domid_t) id;
            op.u.getvcpuinfo.vcpu = vcpu;
            ret = xenHypervisorDoV0Op(handle, &op);
            if (ret < 0)
                return -1;
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
    return ret;
}

/**
 * xenHypervisorInit:
 * @override_versions: pointer to optional struct xenHypervisorVersions with
 *     version information used instead of automatic version detection.
 *
 * Initialize the hypervisor layer. Try to detect the kind of interface
 * used i.e. pre or post changeset 10277
 *
 * Returns 0 or -1 in case of failure
 */
int
xenHypervisorInit(struct xenHypervisorVersions *override_versions)
{
    int fd, ret, cmd, errcode;
    hypercall_t hc;
    v0_hypercall_t v0_hc;
    xen_getdomaininfo info;
    virVcpuInfoPtr ipt = NULL;

    /* Compile regular expressions used by xenHypervisorGetCapabilities.
     * Note that errors here are really internal errors since these
     * regexps should never fail to compile.
     */
    errcode = regcomp(&flags_hvm_rec, flags_hvm_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror(errcode, &flags_hvm_rec, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", error);
        return -1;
    }
    errcode = regcomp(&flags_pae_rec, flags_pae_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror(errcode, &flags_pae_rec, error, sizeof(error));
        regfree(&flags_hvm_rec);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", error);
        return -1;
    }
    errcode = regcomp(&xen_cap_rec, xen_cap_re, REG_EXTENDED);
    if (errcode != 0) {
        char error[100];
        regerror(errcode, &xen_cap_rec, error, sizeof(error));
        regfree(&flags_pae_rec);
        regfree(&flags_hvm_rec);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", error);
        return -1;
    }

    if (override_versions) {
      hv_versions = *override_versions;
      return 0;
    }

    /* Xen hypervisor version detection begins. */
    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        hv_versions.hypervisor = -1;
        return -1;
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
        VIR_DEBUG("Using new hypervisor call: %X", ret);
        hv_versions.hv = ret;
        xen_ioctl_hypercall_cmd = cmd;
        goto detect_v2;
    }

#ifndef __sun
    /*
     * check if the old hypercall are actually working
     */
    v0_hc.op = __HYPERVISOR_xen_version;
    v0_hc.arg[0] = (unsigned long) XENVER_version;
    v0_hc.arg[1] = 0;
    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(v0_hypercall_t));
    ret = ioctl(fd, cmd, (unsigned long) &v0_hc);
    if ((ret != -1) && (ret != 0)) {
        VIR_DEBUG("Using old hypervisor call: %X", ret);
        hv_versions.hv = ret;
        xen_ioctl_hypercall_cmd = cmd;
        hv_versions.hypervisor = 0;
        goto done;
    }
#endif

    /*
     * we failed to make any hypercall
     */

    hv_versions.hypervisor = -1;
    virReportSystemError(errno,
                         _("Unable to issue hypervisor ioctl %lu"),
                         (unsigned long)IOCTL_PRIVCMD_HYPERCALL);
    VIR_FORCE_CLOSE(fd);
    return -1;

 detect_v2:
    /*
     * The hypercalls were refactored into 3 different section in August 2006
     * Try to detect if we are running a version post 3.0.2 with the new ones
     * or the old ones
     */
    hv_versions.hypervisor = 2;

    if (VIR_ALLOC(ipt) < 0)
        return -1;
    /* Currently consider RHEL5.0 Fedora7, xen-3.1, and xen-unstable */
    hv_versions.sys_interface = 2; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* RHEL 5.0 */
        hv_versions.dom_interface = 3; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver2 dom ver3");
            goto done;
        }
        /* Fedora 7 */
        hv_versions.dom_interface = 4; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver2 dom ver4");
            goto done;
        }
    }

    hv_versions.sys_interface = 3; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* xen-3.1 */
        hv_versions.dom_interface = 5; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver3 dom ver5");
            goto done;
        }
    }

    hv_versions.sys_interface = 4; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* Fedora 8 */
        hv_versions.dom_interface = 5; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver4 dom ver5");
            goto done;
        }
    }

    hv_versions.sys_interface = 6; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        /* Xen 3.2, Fedora 9 */
        hv_versions.dom_interface = 5; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver6 dom ver5");
            goto done;
        }
    }

    /* Xen 4.0 */
    hv_versions.sys_interface = 7; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        hv_versions.dom_interface = 6; /* XEN_DOMCTL_INTERFACE_VERSION */
        VIR_DEBUG("Using hypervisor call v2, sys ver7 dom ver6");
        goto done;
    }

    /* Xen 4.1
     * sysctl version 8 -> xen-unstable c/s 21118:28e5409e3fb3
     * domctl version 7 -> xen-unstable c/s 21212:de94884a669c
     * domctl version 8 -> xen-unstable c/s 23874:651aed73b39c
     */
    hv_versions.sys_interface = 8; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        hv_versions.dom_interface = 7; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver8 dom ver7");
            goto done;
        }
        hv_versions.dom_interface = 8; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver8 dom ver8");
            goto done;
        }
    }

    /* Xen 4.2
     * sysctl version 9 -> xen-unstable c/s 24102:dc8e55c90604
     * domctl version 8 -> unchanged from Xen 4.1
     */
    hv_versions.sys_interface = 9; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        hv_versions.dom_interface = 8; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver9 dom ver8");
            goto done;
        }
    }

    /* Xen 4.3
     * sysctl version 10 -> xen-unstable commit bec8f17e
     * domctl version 9 -> xen-unstable commit 65c9792d
     */
    hv_versions.sys_interface = 10; /* XEN_SYSCTL_INTERFACE_VERSION */
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        hv_versions.dom_interface = 9; /* XEN_DOMCTL_INTERFACE_VERSION */
        if (virXen_getvcpusinfo(fd, 0, 0, ipt, NULL, 0) == 0) {
            VIR_DEBUG("Using hypervisor call v2, sys ver10 dom ver9");
            goto done;
        }
    }

    hv_versions.hypervisor = 1;
    hv_versions.sys_interface = -1;
    if (virXen_getdomaininfo(fd, 0, &info) == 1) {
        VIR_DEBUG("Using hypervisor call v1");
        goto done;
    }

    /*
     * we failed to make the getdomaininfolist hypercall
     */
    hv_versions.hypervisor = -1;
    virReportSystemError(errno,
                         _("Unable to issue hypervisor ioctl %lu"),
                         (unsigned long)IOCTL_PRIVCMD_HYPERCALL);
    VIR_DEBUG("Failed to find any Xen hypervisor method");
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(ipt);
    return -1;

 done:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(ipt);
    return 0;
}


static int xenHypervisorOnceInit(void)
{
    return xenHypervisorInit(NULL);
}

VIR_ONCE_GLOBAL_INIT(xenHypervisor)

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
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    int ret;
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, -1);

    if (xenHypervisorInitialize() < 0)
        return -1;

    priv->handle = -1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        virReportError(VIR_ERR_NO_XEN, "%s", XEN_HYPERVISOR_SOCKET);
        return -1;
    }

    priv->handle = ret;

    return 0;
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
    xenUnifiedPrivatePtr priv = conn->privateData;

    ret = VIR_CLOSE(priv->handle);
    if (ret < 0)
        return -1;

    return 0;
}


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
xenHypervisorGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *hvVer)
{
    *hvVer = (hv_versions.hv >> 16) * 1000000 + (hv_versions.hv & 0xFFFF) * 1000;
    return 0;
}

struct guest_arch {
    virArch arch;
    int hvm;
    int pae;
    int nonpae;
    int ia64_be;
};


static virCapsPtr
xenHypervisorBuildCapabilities(virConnectPtr conn, virArch hostarch,
                               int host_pae,
                               const char *hvm_type,
                               struct guest_arch *guest_archs,
                               int nr_guest_archs)
{
    virCapsPtr caps;
    size_t i;
    int hv_major = hv_versions.hv >> 16;
    int hv_minor = hv_versions.hv & 0xFFFF;

    if ((caps = virCapabilitiesNew(hostarch, true, true)) == NULL)
        goto no_memory;

    if (hvm_type && STRNEQ(hvm_type, "") &&
        virCapabilitiesAddHostFeature(caps, hvm_type) < 0)
        goto no_memory;
    if (host_pae &&
        virCapabilitiesAddHostFeature(caps, "pae") < 0)
        goto no_memory;


    if (virCapabilitiesAddHostMigrateTransport(caps,
                                               "xenmigr") < 0)
        goto no_memory;


    if (hv_versions.sys_interface >= SYS_IFACE_MIN_VERS_NUMA && conn != NULL) {
        if (xenDaemonNodeGetTopology(conn, caps) != 0) {
            virObjectUnref(caps);
            return NULL;
        }
    }

    for (i = 0; i < nr_guest_archs; ++i) {
        virCapsGuestPtr guest;
        char const *const xen_machines[] = {guest_archs[i].hvm ? "xenfv" : "xenpv"};
        virCapsGuestMachinePtr *machines;

        if ((machines = virCapabilitiesAllocMachines(xen_machines, 1)) == NULL)
            goto no_memory;

        if ((guest = virCapabilitiesAddGuest(caps,
                                             guest_archs[i].hvm ? VIR_DOMAIN_OSTYPE_HVM : VIR_DOMAIN_OSTYPE_XEN,
                                             guest_archs[i].arch,
                                             (hostarch == VIR_ARCH_X86_64 ?
                                              "/usr/lib64/xen/bin/qemu-dm" :
                                              "/usr/lib/xen/bin/qemu-dm"),
                                             (guest_archs[i].hvm ?
                                              "/usr/lib/xen/boot/hvmloader" :
                                              NULL),
                                             1,
                                             machines)) == NULL) {
            virCapabilitiesFreeMachines(machines, 1);
            goto no_memory;
        }
        machines = NULL;

        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_XEN,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto no_memory;

        if (guest_archs[i].pae &&
            virCapabilitiesAddGuestFeature(guest,
                                           "pae",
                                           true,
                                           false) == NULL)
            goto no_memory;

        if (guest_archs[i].nonpae &&
            virCapabilitiesAddGuestFeature(guest,
                                           "nonpae",
                                           true,
                                           false) == NULL)
            goto no_memory;

        if (guest_archs[i].ia64_be &&
            virCapabilitiesAddGuestFeature(guest,
                                           "ia64_be",
                                           true,
                                           false) == NULL)
            goto no_memory;

        if (guest_archs[i].hvm) {
            if (virCapabilitiesAddGuestFeature(guest,
                                               "acpi",
                                               true, true) == NULL)
                goto no_memory;

            /* In Xen 3.1.0, APIC is always on and can't be toggled */
            if (virCapabilitiesAddGuestFeature(guest,
                                               "apic",
                                               true,
                                               !(hv_major > 3 &&
                                                 hv_minor > 0)) == NULL)
                goto no_memory;

            /* Xen 3.3.x and beyond supports enabling/disabling
             * hardware assisted paging.  Default is off.
             */
            if ((hv_major == 3 && hv_minor >= 3) || (hv_major > 3))
                if (virCapabilitiesAddGuestFeature(guest,
                                                   "hap",
                                                   true,
                                                   true) == NULL)
                    goto no_memory;

            /* Xen 3.4.x and beyond supports the Viridian (Hyper-V)
             * enlightenment interface.  Default is off.
             */
            if ((hv_major == 3 && hv_minor >= 4) || (hv_major > 3))
                if (virCapabilitiesAddGuestFeature(guest,
                                                   "viridian",
                                                   false,
                                                   true) == NULL)
                    goto no_memory;
        }

    }

    return caps;

 no_memory:
    virObjectUnref(caps);
    return NULL;
}

#ifdef __sun

static int
get_cpu_flags(virConnectPtr conn, const char **hvm, int *pae, int *longmode)
{
    struct {
        uint32_t r_eax, r_ebx, r_ecx, r_edx;
    } regs;

    char tmpbuf[20];
    int ret = 0;
    int fd;

    /* returns -1, errno 22 if in 32-bit mode */
    *longmode = (sysinfo(SI_ARCHITECTURE_64, tmpbuf, sizeof(tmpbuf)) != -1);

    if ((fd = open("/dev/cpu/self/cpuid", O_RDONLY)) == -1 ||
        pread(fd, &regs, sizeof(regs), 0) != sizeof(regs)) {
        virReportSystemError(errno, "%s", _("could not read CPU flags"));
        goto out;
    }

    *pae = 0;
    *hvm = "";

    if (STRPREFIX((const char *)&regs.r_ebx, "AuthcAMDenti")) {
        if (pread(fd, &regs, sizeof(regs), 0x80000001) == sizeof(regs)) {
            /* Read secure virtual machine bit (bit 2 of ECX feature ID) */
            if ((regs.r_ecx >> 2) & 1)
                *hvm = "svm";
            if ((regs.r_edx >> 6) & 1)
                *pae = 1;
        }
    } else if (STRPREFIX((const char *)&regs.r_ebx, "GenuntelineI")) {
        if (pread(fd, &regs, sizeof(regs), 0x00000001) == sizeof(regs)) {
            /* Read VMXE feature bit (bit 5 of ECX feature ID) */
            if ((regs.r_ecx >> 5) & 1)
                *hvm = "vmx";
            if ((regs.r_edx >> 6) & 1)
                *pae = 1;
        }
    }

    ret = 1;

 out:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

static virCapsPtr
xenHypervisorMakeCapabilitiesSunOS(virConnectPtr conn)
{
    struct guest_arch guest_arches[32];
    size_t i = 0;
    virCapsPtr caps = NULL;
    int pae, longmode;
    const char *hvm;

    if (!get_cpu_flags(conn, &hvm, &pae, &longmode))
        return NULL;

    guest_arches[i].arch = VIR_ARCH_I686;
    guest_arches[i].hvm = 0;
    guest_arches[i].pae = pae;
    guest_arches[i].nonpae = !pae;
    guest_arches[i].ia64_be = 0;
    i++;

    if (longmode) {
        guest_arches[i].arch = VIR_ARCH_X86_64;
        guest_arches[i].hvm = 0;
        guest_arches[i].pae = 0;
        guest_arches[i].nonpae = 0;
        guest_arches[i].ia64_be = 0;
        i++;
    }

    if (hvm[0] != '\0') {
        guest_arches[i].arch = VIR_ARCH_I686;
        guest_arches[i].hvm = 1;
        guest_arches[i].pae = pae;
        guest_arches[i].nonpae = 1;
        guest_arches[i].ia64_be = 0;
        i++;

        if (longmode) {
            guest_arches[i].arch = VIR_ARCH_X86_64;
            guest_arches[i].hvm = 1;
            guest_arches[i].pae = 0;
            guest_arches[i].nonpae = 0;
            guest_arches[i].ia64_be = 0;
            i++;
        }
    }

    caps = xenHypervisorBuildCapabilities(conn,
                                          virArchFromHost(),
                                          pae, hvm,
                                          guest_arches, i);

    return caps;
}

#endif /* __sun */

/**
 * xenHypervisorMakeCapabilitiesInternal:
 * @conn: pointer to the connection block
 * @cpuinfo: file handle containing /proc/cpuinfo data, or NULL
 * @capabilities: file handle containing /sys/hypervisor/properties/capabilities data, or NULL
 *
 * Return the capabilities of this hypervisor.
 */
virCapsPtr
xenHypervisorMakeCapabilitiesInternal(virConnectPtr conn,
                                      virArch hostarch,
                                      FILE *cpuinfo,
                                      FILE *capabilities)
{
    char line[1024], *str, *token;
    regmatch_t subs[4];
    char *saveptr = NULL;
    size_t i;

    char hvm_type[4] = ""; /* "vmx" or "svm" (or "" if not in CPU). */
    int host_pae = 0;
    struct guest_arch guest_archs[32];
    int nr_guest_archs = 0;
    virCapsPtr caps = NULL;

    memset(guest_archs, 0, sizeof(guest_archs));

    /* /proc/cpuinfo: flags: Intel calls HVM "vmx", AMD calls it "svm".
     * It's not clear if this will work on IA64, let alone other
     * architectures and non-Linux. (XXX)
     */
    if (cpuinfo) {
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (regexec(&flags_hvm_rec, line, sizeof(subs)/sizeof(regmatch_t), subs, 0) == 0
                && subs[0].rm_so != -1) {
                if (virStrncpy(hvm_type,
                               &line[subs[1].rm_so],
                               subs[1].rm_eo-subs[1].rm_so,
                               sizeof(hvm_type)) == NULL)
                    goto no_memory;
            } else if (regexec(&flags_pae_rec, line, 0, NULL, 0) == 0) {
                host_pae = 1;
            }
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
    if ((capabilities) && (fgets(line, sizeof(line), capabilities))) {
        /* Split the line into tokens.  strtok_r is OK here because we "own"
         * this buffer.  Parse out the features from each token.
         */
        for (str = line, nr_guest_archs = 0;
             nr_guest_archs < sizeof(guest_archs) / sizeof(guest_archs[0])
                 && (token = strtok_r(str, " ", &saveptr)) != NULL;
             str = NULL) {

            if (regexec(&xen_cap_rec, token, sizeof(subs) / sizeof(subs[0]),
                        subs, 0) == 0) {
                int hvm = STRPREFIX(&token[subs[1].rm_so], "hvm");
                int pae = 0, nonpae = 0, ia64_be = 0;
                virArch arch;

                if (STRPREFIX(&token[subs[2].rm_so], "x86_32")) {
                    arch = VIR_ARCH_I686;
                    if (subs[3].rm_so != -1 &&
                        STRPREFIX(&token[subs[3].rm_so], "p"))
                        pae = 1;
                    else
                        nonpae = 1;
                } else if (STRPREFIX(&token[subs[2].rm_so], "x86_64")) {
                    arch = VIR_ARCH_X86_64;
                } else if (STRPREFIX(&token[subs[2].rm_so], "ia64")) {
                    arch = VIR_ARCH_ITANIUM;
                    if (subs[3].rm_so != -1 &&
                        STRPREFIX(&token[subs[3].rm_so], "be"))
                        ia64_be = 1;
                } else if (STRPREFIX(&token[subs[2].rm_so], "powerpc64")) {
                    arch = VIR_ARCH_PPC64;
                } else {
                    /* XXX surely no other Xen archs exist. Arrrrrrrrrm  */
                    continue;
                }

                /* Search for existing matching (model,hvm) tuple */
                for (i = 0; i < nr_guest_archs; i++) {
                    if (guest_archs[i].arch == arch &&
                        guest_archs[i].hvm == hvm) {
                        break;
                    }
                }

                /* Too many arch flavours - highly unlikely ! */
                if (i >= ARRAY_CARDINALITY(guest_archs))
                    continue;
                /* Didn't find a match, so create a new one */
                if (i == nr_guest_archs)
                    nr_guest_archs++;

                guest_archs[i].arch = arch;
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

    if ((caps = xenHypervisorBuildCapabilities(conn,
                                               hostarch,
                                               host_pae,
                                               hvm_type,
                                               guest_archs,
                                               nr_guest_archs)) == NULL)
        goto no_memory;

    return caps;

 no_memory:
    virObjectUnref(caps);
    return NULL;
}

/**
 * xenHypervisorMakeCapabilities:
 *
 * Return the capabilities of this hypervisor.
 */
virCapsPtr
xenHypervisorMakeCapabilities(virConnectPtr conn)
{
#ifdef __sun
    return xenHypervisorMakeCapabilitiesSunOS(conn);
#else
    virCapsPtr caps = NULL;
    FILE *cpuinfo, *capabilities;

    cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo == NULL) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("cannot read file %s"),
                                 "/proc/cpuinfo");
            return NULL;
        }
    }

    capabilities = fopen("/sys/hypervisor/properties/capabilities", "r");
    if (capabilities == NULL) {
        if (errno != ENOENT) {
            VIR_FORCE_FCLOSE(cpuinfo);
            virReportSystemError(errno,
                                 _("cannot read file %s"),
                                 "/sys/hypervisor/properties/capabilities");
            return NULL;
        }
    }

    caps = xenHypervisorMakeCapabilitiesInternal(conn,
                                                 virArchFromHost(),
                                                 cpuinfo,
                                                 capabilities);
    if (caps == NULL)
        goto cleanup;

    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

 cleanup:
    VIR_FORCE_FCLOSE(cpuinfo);
    VIR_FORCE_FCLOSE(capabilities);

    return caps;
#endif /* __sun */
}



/**
 * xenHypervisorGetCapabilities:
 * @conn: pointer to the connection block
 *
 * Return the capabilities of this hypervisor.
 */
char *
xenHypervisorGetCapabilities(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    return virCapabilitiesFormatXML(priv->caps);
}


char *
xenHypervisorDomainGetOSType(virConnectPtr conn,
                             virDomainDefPtr def)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xen_getdomaininfo dominfo;
    char *ostype = NULL;

    /* HV's earlier than 3.1.0 don't include the HVM flags in guests status*/
    if (hv_versions.hypervisor < 2 ||
        hv_versions.dom_interface < 4) {
        return xenDaemonDomainGetOSType(conn, def);
    }

    XEN_GETDOMAININFO_CLEAR(dominfo);

    if (virXen_getdomaininfo(priv->handle, def->id, &dominfo) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get domain details"));
        return NULL;
    }

    if (XEN_GETDOMAININFO_DOMAIN(dominfo) != def->id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get domain details"));
        return NULL;
    }

    ignore_value(VIR_STRDUP(ostype,
                            XEN_GETDOMAININFO_FLAGS(dominfo) & DOMFLAGS_HVM ?
                            "hvm" : "linux"));
    return ostype;
}

int
xenHypervisorHasDomain(virConnectPtr conn, int id)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xen_getdomaininfo dominfo;

    XEN_GETDOMAININFO_CLEAR(dominfo);

    if (virXen_getdomaininfo(priv->handle, id, &dominfo) < 0)
        return 0;

    if (XEN_GETDOMAININFO_DOMAIN(dominfo) != id)
        return 0;

    return 1;
}


virDomainDefPtr
xenHypervisorLookupDomainByID(virConnectPtr conn, int id)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xen_getdomaininfo dominfo;
    virDomainDefPtr ret;
    char *name;

    XEN_GETDOMAININFO_CLEAR(dominfo);

    if (virXen_getdomaininfo(priv->handle, id, &dominfo) < 0)
        return NULL;

    if (XEN_GETDOMAININFO_DOMAIN(dominfo) != id)
        return NULL;

    xenUnifiedLock(priv);
    name = xenStoreDomainGetName(conn, id);
    xenUnifiedUnlock(priv);
    if (!name)
        return NULL;

    ret = virDomainDefNewFull(name,
                              XEN_GETDOMAININFO_UUID(dominfo),
                              id);
    VIR_FREE(name);
    return ret;
}


virDomainDefPtr
xenHypervisorLookupDomainByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    xen_getdomaininfolist dominfos;
    xenUnifiedPrivatePtr priv = conn->privateData;
    virDomainDefPtr ret;
    char *name;
    int maxids = 100, nids, id;
    size_t i;

 retry:
    if (!(XEN_GETDOMAININFOLIST_ALLOC(dominfos, maxids))) {
        virReportOOMError();
        return NULL;
    }

    XEN_GETDOMAININFOLIST_CLEAR(dominfos, maxids);

    nids = virXen_getdomaininfolist(priv->handle, 0, maxids, &dominfos);

    if (nids < 0) {
        XEN_GETDOMAININFOLIST_FREE(dominfos);
        return NULL;
    }

    /* Can't possibly have more than 65,000 concurrent guests
     * so limit how many times we try, to avoid increasing
     * without bound & thus allocating all of system memory !
     * XXX I'll regret this comment in a few years time ;-)
     */
    if (nids == maxids) {
        XEN_GETDOMAININFOLIST_FREE(dominfos);
        if (maxids < 65000) {
            maxids *= 2;
            goto retry;
        }
        return NULL;
    }

    id = -1;
    for (i = 0; i < nids; i++) {
        if (memcmp(XEN_GETDOMAININFOLIST_UUID(dominfos, i), uuid, VIR_UUID_BUFLEN) == 0) {
            id = XEN_GETDOMAININFOLIST_DOMAIN(dominfos, i);
            break;
        }
    }
    XEN_GETDOMAININFOLIST_FREE(dominfos);

    if (id == -1)
        return NULL;

    xenUnifiedLock(priv);
    name = xenStoreDomainGetName(conn, id);
    xenUnifiedUnlock(priv);
    if (!name)
        return NULL;

    ret = virDomainDefNewFull(name, uuid, id);
    if (ret)
        ret->id = id;
    VIR_FREE(name);
    return ret;
}

/**
 * xenHypervisorGetMaxVcpus:
 *
 * Returns the maximum of CPU defined by Xen.
 */
int
xenHypervisorGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                         const char *type ATTRIBUTE_UNUSED)
{
    return MAX_VIRT_CPUS;
}

/**
 * xenHypervisorDomMaxMemory:
 * @dom: domain
 *
 * Retrieve the maximum amount of physical memory allocated to a
 * domain.
 *
 * Returns the memory size in kilobytes or 0 in case of error.
 */
unsigned long
xenHypervisorGetMaxMemory(virConnectPtr conn,
                          virDomainDefPtr def)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xen_getdomaininfo dominfo;
    int ret;

    if (kb_per_pages == 0) {
        kb_per_pages = virGetSystemPageSizeKB();
        if (kb_per_pages <= 0)
            kb_per_pages = 4;
    }

    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(priv->handle, def->id, &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != def->id))
        return 0;

    return (unsigned long) XEN_GETDOMAININFO_MAX_PAGES(dominfo) * kb_per_pages;
}


/**
 * xenHypervisorGetDomInfo:
 * @conn: connection data
 * @id: the domain ID
 * @info: the place where information should be stored
 *
 * Do a hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomInfo(virConnectPtr conn, int id, virDomainInfoPtr info)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    xen_getdomaininfo dominfo;
    int ret;
    uint32_t domain_flags, domain_state, domain_shutdown_cause;

    if (kb_per_pages == 0) {
        kb_per_pages = virGetSystemPageSizeKB();
        if (kb_per_pages <= 0)
            kb_per_pages = 4;
    }

    memset(info, 0, sizeof(virDomainInfo));
    XEN_GETDOMAININFO_CLEAR(dominfo);

    ret = virXen_getdomaininfo(priv->handle, id, &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != id))
        return -1;

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
            info->state = VIR_DOMAIN_NOSTATE;
    }

    /*
     * the API brings back the cpu time in nanoseconds,
     * convert to microseconds, same thing convert to
     * kilobytes from page counts
     */
    info->cpuTime = XEN_GETDOMAININFO_CPUTIME(dominfo);
    info->memory = XEN_GETDOMAININFO_TOT_PAGES(dominfo) * kb_per_pages;
    info->maxMem = XEN_GETDOMAININFO_MAX_PAGES(dominfo);
    if (info->maxMem != UINT_MAX)
        info->maxMem *= kb_per_pages;
    info->nrVirtCpu = XEN_GETDOMAININFO_CPUCOUNT(dominfo);
    return 0;
}

/**
 * xenHypervisorGetDomainInfo:
 * @domain: pointer to the domain block
 * @info: the place where information should be stored
 *
 * Do a hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomainInfo(virConnectPtr conn,
                           virDomainDefPtr def,
                           virDomainInfoPtr info)
{
    return xenHypervisorGetDomInfo(conn, def->id, info);
}

/**
 * xenHypervisorGetDomainState:
 * @domain: pointer to the domain block
 * @state: returned state of the domain
 * @reason: returned reason for the state
 *
 * Do a hypervisor call to get the related set of domain information.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomainState(virConnectPtr conn,
                            virDomainDefPtr def,
                            int *state,
                            int *reason)
{
    virDomainInfo info;

    if (xenHypervisorGetDomInfo(conn, def->id, &info) < 0)
        return -1;

    *state = info.state;
    if (reason)
        *reason = 0;

    return 0;
}

/**
 * xenHypervisorNodeGetCellsFreeMemory:
 * @conn: pointer to the hypervisor connection
 * @freeMems: pointer to the array of unsigned long long
 * @startCell: index of first cell to return freeMems info on.
 * @maxCells: Maximum number of cells for which freeMems information can
 *            be returned.
 *
 * This call returns the amount of free memory in one or more NUMA cells.
 * The @freeMems array must be allocated by the caller and will be filled
 * with the amount of free memory in kilobytes for each cell requested,
 * starting with startCell (in freeMems[0]), up to either
 * (startCell + maxCells), or the number of additional cells in the node,
 * whichever is smaller.
 *
 * Returns the number of entries filled in freeMems, or -1 in case of error.
 */
int
xenHypervisorNodeGetCellsFreeMemory(virConnectPtr conn,
                                    unsigned long long *freeMems,
                                    int startCell,
                                    int maxCells)
{
    xen_op_v2_sys op_sys;
    size_t i;
    int cell;
    int ret;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (priv->nbNodeCells < 0) {
        virReportError(VIR_ERR_XEN_CALL, "%s",
                       _("cannot determine actual number of cells"));
        return -1;
    }

    if ((maxCells < 1) || (startCell >= priv->nbNodeCells)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument"));
        return -1;
    }

    /*
     * Support only hv_versions.sys_interface >=4
     */
    if (hv_versions.sys_interface < SYS_IFACE_MIN_VERS_NUMA) {
        virReportError(VIR_ERR_XEN_CALL, "%s",
                       _("unsupported in sys interface < 4"));
        return -1;
    }

    memset(&op_sys, 0, sizeof(op_sys));
    op_sys.cmd = XEN_V2_OP_GETAVAILHEAP;

    for (cell = startCell, i = 0;
         cell < priv->nbNodeCells && i < maxCells; cell++, i++) {
        if (hv_versions.sys_interface >= 5)
            op_sys.u.availheap5.node = cell;
        else
            op_sys.u.availheap.node = cell;
        ret = xenHypervisorDoV2Sys(priv->handle, &op_sys);
        if (ret < 0)
            return -1;
        if (hv_versions.sys_interface >= 5)
            freeMems[i] = op_sys.u.availheap5.avail_bytes;
        else
            freeMems[i] = op_sys.u.availheap.avail_bytes;
    }
    return i;
}


/**
 * xenHypervisorSetMaxMemory:
 * @domain: pointer to the domain block
 * @memory: the max memory size in kilobytes.
 *
 * Do a hypervisor call to change the maximum amount of memory used
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorSetMaxMemory(virConnectPtr conn,
                          virDomainDefPtr def,
                          unsigned long memory)
{
    int ret;
    xenUnifiedPrivatePtr priv = conn->privateData;

    ret = virXen_setmaxmem(priv->handle, def->id, memory);
    if (ret < 0)
        return -1;
    return 0;
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
xenHypervisorPinVcpu(virConnectPtr conn,
                     virDomainDefPtr def,
                     unsigned int vcpu,
                     unsigned char *cpumap,
                     int maplen)
{
    int ret;
    xenUnifiedPrivatePtr priv = conn->privateData;

    ret = virXen_setvcpumap(priv->handle, def->id, vcpu,
                            cpumap, maplen);
    if (ret < 0)
        return -1;
    return 0;
}

/**
 * virDomainGetVcpus:
 * @domain: pointer to domain object, or NULL for Domain0
 * @info: pointer to an array of virVcpuInfo structures (OUT)
 * @maxinfo: number of structures in info array
 * @cpumaps: pointer to a bit map of real CPUs for all vcpus of this domain (in 8-bit bytes) (OUT)
 *	If cpumaps is NULL, then no cpumap information is returned by the API.
 *	It's assumed there is <maxinfo> cpumap in cpumaps array.
 *	The memory allocated to cpumaps must be (maxinfo * maplen) bytes
 *	(ie: calloc(maxinfo, maplen)).
 *	One cpumap inside cpumaps has the format described in virDomainPinVcpu() API.
 * @maplen: number of bytes in one cpumap, from 1 up to size of CPU map in
 *	underlying virtualization system (Xen...).
 *
 * Extract information about virtual CPUs of domain, store it in info array
 * and also in cpumaps if this pointer isn't NULL.
 *
 * Returns the number of info filled in case of success, -1 in case of failure.
 */
int
xenHypervisorGetVcpus(virConnectPtr conn,
                      virDomainDefPtr def,
                      virVcpuInfoPtr info,
                      int maxinfo,
                      unsigned char *cpumaps,
                      int maplen)
{
    xen_getdomaininfo dominfo;
    int ret;
    xenUnifiedPrivatePtr priv = conn->privateData;
    virVcpuInfoPtr ipt;
    int nbinfo;
    size_t i;

    if (sizeof(cpumap_t) & 7) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid cpumap_t size"));
        return -1;
    }

    /* first get the number of virtual CPUs in this domain */
    XEN_GETDOMAININFO_CLEAR(dominfo);
    ret = virXen_getdomaininfo(priv->handle, def->id,
                               &dominfo);

    if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != def->id)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot get domain details"));
        return -1;
    }
    nbinfo = XEN_GETDOMAININFO_CPUCOUNT(dominfo) + 1;
    if (nbinfo > maxinfo) nbinfo = maxinfo;

    if (cpumaps != NULL)
        memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0, ipt = info; i < nbinfo; i++, ipt++) {
        if ((cpumaps != NULL) && (i < maxinfo)) {
            ret = virXen_getvcpusinfo(priv->handle, def->id, i,
                                      ipt,
                                      (unsigned char *)VIR_GET_CPUMAP(cpumaps, maplen, i),
                                      maplen);
            if (ret < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot get VCPUs info"));
                return -1;
            }
        } else {
            ret = virXen_getvcpusinfo(priv->handle, def->id, i,
                                      ipt, NULL, 0);
            if (ret < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot get VCPUs info"));
                return -1;
            }
        }
    }
    return nbinfo;
}

/**
 * xenHypervisorGetVcpuMax:
 *
 *  Returns the maximum number of virtual CPUs supported for
 *  the guest VM. If the guest is inactive, this is the maximum
 *  of CPU defined by Xen. If the guest is running this reflect
 *  the maximum number of virtual CPUs the guest was booted with.
 */
int
xenHypervisorGetVcpuMax(virConnectPtr conn,
                        virDomainDefPtr def)
{
    xen_getdomaininfo dominfo;
    int ret;
    int maxcpu;
    xenUnifiedPrivatePtr priv = conn->privateData;

    /* inactive domain */
    if (def->id < 0) {
        maxcpu = MAX_VIRT_CPUS;
    } else {
        XEN_GETDOMAININFO_CLEAR(dominfo);
        ret = virXen_getdomaininfo(priv->handle, def->id,
                                   &dominfo);

        if ((ret < 0) || (XEN_GETDOMAININFO_DOMAIN(dominfo) != def->id))
            return -1;
        maxcpu = XEN_GETDOMAININFO_MAXCPUID(dominfo) + 1;
    }

    return maxcpu;
}

/**
 * xenHavePrivilege()
 *
 * Return true if the current process should be able to connect to Xen.
 */
int
xenHavePrivilege(void)
{
#ifdef __sun
    return priv_ineffect(PRIV_XVM_CONTROL);
#else
    return access(XEN_HYPERVISOR_SOCKET, R_OK) == 0;
#endif
}
