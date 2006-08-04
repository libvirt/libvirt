/*
 * xen_internal.c: direct access to Xen hypervisor level
 *
 * Copyright (C) 2005 Red Hat, Inc.
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

/* #ifndef __LINUX_PUBLIC_PRIVCMD_H__ */
typedef struct old_hypercall_struct {
    unsigned long op;
    unsigned long arg[5];
} old_hypercall_t;
#define XEN_OLD_IOCTL_HYPERCALL_CMD \
        _IOC(_IOC_NONE, 'P', 0, sizeof(old_hypercall_t))

typedef struct privcmd_hypercall hypercall_t;
#define XEN_IOCTL_HYPERCALL_CMD IOCTL_PRIVCMD_HYPERCALL

static int xen_ioctl_hypercall_cmd = 0;
static int old_hypervisor = 0;
static int initialized = 0;
static int hv_version = 0;

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
    NULL /* domainRestore */
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

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}

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
    old_hypercall_t old_hc;

    if (initialized) {
        if (old_hypervisor == -1)
	    return(-1);
	return(0);
    }
    initialized = 1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
	old_hypervisor = -1;
        return (-1);
    }
    fd = ret;

    hc.op = __HYPERVISOR_xen_version;
    hc.arg[0] = (unsigned long) XENVER_version;
    hc.arg[1] = 0;

    cmd = IOCTL_PRIVCMD_HYPERCALL;
    ret = ioctl(fd, cmd, (unsigned long) &hc);

    if ((ret != -1) && (ret != 0)) {
        /* fprintf(stderr, "Using new hypervisor call: %X\n", ret); */
	hv_version = ret;
	xen_ioctl_hypercall_cmd = cmd;
        old_hypervisor = 0;
	goto done;
    }
    
    old_hc.op = __HYPERVISOR_xen_version;
    old_hc.arg[0] = (unsigned long) XENVER_version;
    old_hc.arg[1] = 0;
    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(old_hypercall_t));
    ret = ioctl(fd, cmd, (unsigned long) &old_hc);
    if ((ret != -1) && (ret != 0)) {
        /* fprintf(stderr, "Using old hypervisor call: %X\n", ret); */
	hv_version = ret;
	xen_ioctl_hypercall_cmd = cmd;
        old_hypervisor = 1;
	goto done;
    }

    old_hypervisor = -1;
    virXenError(VIR_ERR_XEN_CALL, " ioctl ", IOCTL_PRIVCMD_HYPERCALL);
    close(fd);
    return(-1);

done:
    close(fd);
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

/**
 * xenHypervisorDoOldOp:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hyperviros operation structure
 *
 * Do an hypervisor operation though the old interface,
 * this leads to an hypervisor call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoOldOp(int handle, dom0_op_t * op)
{
    int ret;
    old_hypercall_t hc;

    memset(&hc, 0, sizeof(hc));
    op->interface_version = hv_version << 8;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(dom0_op_t));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(dom0_op_t));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}
/**
 * xenHypervisorDoOp:
 * @handle: the handle to the Xen hypervisor
 * @op: pointer to the hyperviros operation structure
 *
 * Do an hypervisor operation, this leads to an hypervisor call through ioctl.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
xenHypervisorDoOp(int handle, dom0_op_t * op)
{
    int ret;
    hypercall_t hc;

    if (old_hypervisor)
        return(xenHypervisorDoOldOp(handle, op));
 
    memset(&hc, 0, sizeof(hc));
    op->interface_version = DOM0_INTERFACE_VERSION;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(dom0_op_t));
        return (-1);
    }

    ret = ioctl(handle, xen_ioctl_hypercall_cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", xen_ioctl_hypercall_cmd);
    }

    if (munlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " releasing", sizeof(dom0_op_t));
        ret = -1;
    }

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
    dom0_op_t op;
    dom0_getdomaininfo_t *dominfos;
    int ret, nbids;
    static int last_maxids = 2;
    int maxids = last_maxids;

    if ((conn == NULL) || (conn->handle < 0))
        return (-1);

retry:
    dominfos = malloc(maxids * sizeof(dom0_getdomaininfo_t));
    if (dominfos == NULL) {
        virXenError(VIR_ERR_NO_MEMORY, "failed to allocate %d domain info",
	            maxids);
	return(-1);
    }
    
    memset(dominfos, 0, sizeof(dom0_getdomaininfo_t) * maxids);

    if (mlock(dominfos, sizeof(dom0_getdomaininfo_t) * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t) * maxids);
	free(dominfos);
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) 0;
    op.u.getdomaininfolist.max_domains = maxids;
    op.u.getdomaininfolist.buffer = dominfos;
    op.u.getdomaininfolist.num_domains = maxids;

    ret = xenHypervisorDoOp(conn->handle, &op);

    if (munlock(dominfos, sizeof(dom0_getdomaininfo_t) * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t) * maxids);
        ret = -1;
    }

    free(dominfos);

    if (ret < 0)
        return (-1);

    nbids = op.u.getdomaininfolist.num_domains;
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
    dom0_op_t op;
    dom0_getdomaininfo_t *dominfos;
    int ret, nbids, i;

    if ((conn == NULL) || (conn->handle < 0) ||
        (ids == NULL) || (maxids < 1))
        return (-1);

    dominfos = malloc(maxids * sizeof(dom0_getdomaininfo_t));
    if (dominfos == NULL) {
        virXenError(VIR_ERR_NO_MEMORY, "failed to allocate %d domain info",
	            maxids);
	return(-1);
    }
    
    memset(dominfos, 0, sizeof(dom0_getdomaininfo_t) * maxids);
    memset(ids, 0, maxids * sizeof(int));

    if (mlock(dominfos, sizeof(dom0_getdomaininfo_t) * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t) * maxids);
	free(dominfos);
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) 0;
    op.u.getdomaininfolist.max_domains = maxids;
    op.u.getdomaininfolist.buffer = dominfos;
    op.u.getdomaininfolist.num_domains = maxids;

    ret = xenHypervisorDoOp(conn->handle, &op);

    if (munlock(dominfos, sizeof(dom0_getdomaininfo_t) * maxids) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t) * maxids);
        ret = -1;
    }

    if (ret < 0) {
	free(dominfos);
        return (-1);
    }

    nbids = op.u.getdomaininfolist.num_domains;
    if ((nbids < 0) || (nbids > maxids)) {
	free(dominfos);
        return(-1);
    }

    for (i = 0;i < nbids;i++) {
        ids[i] = dominfos[i].domain;
    }

    free(dominfos);
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
    dom0_op_t op;
    dom0_getdomaininfo_t dominfo;
    int ret;

    if ((conn == NULL) || (conn->handle < 0))
        return (0);

    memset(&dominfo, 0, sizeof(dom0_getdomaininfo_t));

    if (mlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t));
        return (0);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) id;
    op.u.getdomaininfolist.max_domains = 1;
    op.u.getdomaininfolist.buffer = &dominfo;
    op.u.getdomaininfolist.num_domains = 1;
    dominfo.domain = id;

    ret = xenHypervisorDoOp(conn->handle, &op);

    if (munlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t));
        ret = -1;
    }

    if (ret < 0)
        return (0);

    return((unsigned long) dominfo.max_pages * 4);
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
    dom0_op_t op;
    dom0_getdomaininfo_t dominfo;
    int ret;

    if ((conn == NULL) || (conn->handle < 0) || (info == NULL))
        return (-1);

    memset(info, 0, sizeof(virDomainInfo));
    memset(&dominfo, 0, sizeof(dom0_getdomaininfo_t));

    if (mlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t));
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) id;
    op.u.getdomaininfolist.max_domains = 1;
    op.u.getdomaininfolist.buffer = &dominfo;
    op.u.getdomaininfolist.num_domains = 1;
    dominfo.domain = id;

    ret = xenHypervisorDoOp(conn->handle, &op);

    if (munlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    switch (dominfo.flags & 0xFF) {
	case DOMFLAGS_DYING:
	    info->state = VIR_DOMAIN_SHUTDOWN;
	    break;
	case DOMFLAGS_SHUTDOWN:
	    info->state = VIR_DOMAIN_SHUTOFF;
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
    info->cpuTime = dominfo.cpu_time;
    info->memory = dominfo.tot_pages * 4;
    info->maxMem = dominfo.max_pages * 4;
    info->nrVirtCpu = dominfo.nr_online_vcpus;
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
    dom0_op_t op;
    int ret;

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    op.cmd = DOM0_PAUSEDOMAIN;
    op.u.pausedomain.domain = (domid_t) domain->handle;

    ret = xenHypervisorDoOp(domain->conn->handle, &op);

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
    dom0_op_t op;
    int ret;

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    op.cmd = DOM0_UNPAUSEDOMAIN;
    op.u.unpausedomain.domain = (domid_t) domain->handle;

    ret = xenHypervisorDoOp(domain->conn->handle, &op);

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
    dom0_op_t op;
    int ret;

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = (domid_t) domain->handle;

    ret = xenHypervisorDoOp(domain->conn->handle, &op);

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
    dom0_op_t op;
    int ret;

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0))
        return (-1);

    op.cmd = DOM0_SETDOMAINMAXMEM;
    op.u.setdomainmaxmem.domain = (domid_t) domain->handle;
    op.u.setdomainmaxmem.max_memkb = memory;

    ret = xenHypervisorDoOp(domain->conn->handle, &op);

    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorCheckID:
 * @domain: pointer to the domain block
 * @info: the place where information should be stored
 *
 * Do an hypervisor call to verify the domain ID is valid
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorCheckID(virConnectPtr conn, int id)
{
    dom0_op_t op;
    dom0_getdomaininfo_t dominfo;
    int ret;

    if ((conn->handle < 0) || (id < 0))
        return (-1);

    memset(&dominfo, 0, sizeof(dom0_getdomaininfo_t));

    if (mlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t));
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) id;
    op.u.getdomaininfolist.max_domains = 1;
    op.u.getdomaininfolist.buffer = &dominfo;
    op.u.getdomaininfolist.num_domains = 1;
    dominfo.domain = id;

    ret = xenHypervisorDoOp(conn->handle, &op);

    if (munlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t));
        ret = -1;
    }

    if (ret < 0)
        return (-1);

    return (0);
}

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
    dom0_op_t op;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->conn->handle < 0)
     || (nvcpus < 1))
        return (-1);
    op.cmd = DOM0_MAX_VCPUS;
    op.u.max_vcpus.domain = (domid_t) domain->handle;
    op.u.max_vcpus.max = nvcpus;
    if (xenHypervisorDoOp(domain->conn->handle, &op) < 0)
        return (-1);
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
xenHypervisorPinVcpu(virDomainPtr domain, unsigned int vcpu,
                     unsigned char *cpumap, int maplen)
{
    dom0_op_t op;
    uint64_t *pm = (uint64_t *)&op.u.setvcpuaffinity.cpumap; 
    int j;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->conn->handle < 0)
     || (cpumap == NULL) || (maplen < 1) || (maplen > (int)sizeof(cpumap_t))
     || (sizeof(cpumap_t) & 7))
        return (-1);
    op.cmd = DOM0_SETVCPUAFFINITY;
    op.u.setvcpuaffinity.domain = (domid_t) domain->handle;
    op.u.setvcpuaffinity.vcpu = vcpu;
    memset(pm, 0, sizeof(cpumap_t));
    for (j = 0; j < maplen; j++)
        *(pm + (j / 8)) |= cpumap[j] << (8 * (j & 7));
    if (xenHypervisorDoOp(domain->conn->handle, &op) < 0)
        return (-1);
    return 0;
}

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
int
xenHypervisorGetVcpus(virDomainPtr domain, virVcpuInfoPtr info, int maxinfo,
		      unsigned char *cpumaps, int maplen)
{
    dom0_op_t op;
    uint64_t *pm = (uint64_t *)&op.u.getvcpuinfo.cpumap; 
    virVcpuInfoPtr ipt;
    int nbinfo, mapl, i;
    unsigned char *cpumap;
    int vcpu, cpu;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->conn->handle < 0)
     || (info == NULL) || (maxinfo < 1)
     || (sizeof(cpumap_t) & 7))
        return (-1);
    if (cpumaps != NULL && maplen < 1)
	return -1;

    /* first get the number of virtual CPUs in this domain */
    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t) domain->handle;
    if (xenHypervisorDoOp(domain->conn->handle, &op) < 0)
        return (-1);
    nbinfo = (int)op.u.getdomaininfo.max_vcpu_id + 1;
    if (nbinfo > maxinfo) nbinfo = maxinfo;

    if (cpumaps != NULL)
	memset(cpumaps, 0, maxinfo * maplen);

    op.cmd = DOM0_GETVCPUINFO;
    for (i=0, ipt=info; i < nbinfo; i++, ipt++) {
        vcpu = op.u.getvcpuinfo.vcpu = i;
        if (xenHypervisorDoOp(domain->conn->handle, &op) < 0)
            return (-1);
        ipt->number = i;
        if (op.u.getvcpuinfo.online) {
            if (op.u.getvcpuinfo.running) ipt->state = VIR_VCPU_RUNNING;
            if (op.u.getvcpuinfo.blocked) ipt->state = VIR_VCPU_BLOCKED;
        }
        else ipt->state = VIR_VCPU_OFFLINE;
        ipt->cpuTime = op.u.getvcpuinfo.cpu_time;
        ipt->cpu = op.u.getvcpuinfo.online ? (int)op.u.getvcpuinfo.cpu : -1;
	if (cpumaps != NULL && vcpu >= 0 && vcpu < maxinfo) {
	    cpumap = (unsigned char *)VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
	    mapl = (maplen > (int)sizeof(cpumap_t)) ? (int)sizeof(cpumap_t) : maplen;
            for (cpu = 0; cpu < (mapl * CHAR_BIT); cpu++) {
		if (*pm & ((uint64_t)1<<cpu))
		    VIR_USE_CPU(cpumap, cpu);
	    }
	}
    }
    return nbinfo;
}
