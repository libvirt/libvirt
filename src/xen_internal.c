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

#include <stdint.h>

/* required for dom0_getdomaininfo_t */
#include <xen/dom0_ops.h>
#include <xen/version.h>
#include <xen/xen.h>

#ifndef __LINUX_PUBLIC_PRIVCMD_H__
typedef struct hypercall_struct {
    unsigned long op;
    unsigned long arg[5];
} hypercall_t;
#endif


#include "internal.h"
#include "driver.h"
#include "xen_internal.h"

#define XEN_HYPERVISOR_SOCKET "/proc/xen/privcmd"

static const char * xenHypervisorGetType(virConnectPtr conn);

static virDriver xenHypervisorDriver = {
    "Xen",
    (DOM0_INTERFACE_VERSION >> 24) * 1000000 +
    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +
    (DOM0_INTERFACE_VERSION & 0xFFFF),
    NULL, /* init */
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
    NULL, /* domainGetMaxMemory */
    xenHypervisorSetMaxMemory, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    xenHypervisorGetDomainInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL /* domainRestore */
};

/**
 * xenHypervisorRegister:
 *
 * Registers the xenHypervisor driver
 */
void xenHypervisorRegister(void)
{
    virRegisterDriver(&xenHypervisorDriver);
}

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
    unsigned int cmd;
    hypercall_t hc;

    op->interface_version = DOM0_INTERFACE_VERSION;
    hc.op = __HYPERVISOR_dom0_op;
    hc.arg[0] = (unsigned long) op;

    if (mlock(op, sizeof(dom0_op_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking", sizeof(dom0_op_t));
        return (-1);
    }

    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(hc));
    ret = ioctl(handle, cmd, (unsigned long) &hc);
    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " ioctl ", cmd);
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
    int ret;
    unsigned int cmd;
    hypercall_t hc;

    if ((conn == NULL) || (conn->handle < 0) || (hvVer == NULL))
        return (-1);
    *hvVer = 0;

    hc.op = __HYPERVISOR_xen_version;
    hc.arg[0] = (unsigned long) XENVER_version;
    hc.arg[1] = 0;

    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(hc));
    ret = ioctl(conn->handle, cmd, (unsigned long) &hc);

    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " getting version ", XENVER_version);
        return (-1);
    }
    *hvVer = (ret >> 16) * 1000000 + (ret & 0xFFFF) * 1000;
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
 * xenHypervisorGetDomainInfo:
 * @domain: pointer to the domain block
 * @info: the place where informations should be stored
 *
 * Do an hypervisor call to get the related set of domain informations.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomainInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    dom0_op_t op;
    dom0_getdomaininfo_t dominfo;
    int ret;

    if ((domain == NULL) || (domain->conn == NULL) ||
        (domain->conn->handle < 0) || (info == NULL))
        return (-1);

    memset(info, 0, sizeof(virDomainInfo));
    memset(&dominfo, 0, sizeof(dom0_getdomaininfo_t));

    if (mlock(&dominfo, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t));
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) domain->handle;
    op.u.getdomaininfolist.max_domains = 1;
    op.u.getdomaininfolist.buffer = &dominfo;
    op.u.getdomaininfolist.num_domains = 1;
    dominfo.domain = domain->handle;

    ret = xenHypervisorDoOp(domain->conn->handle, &op);

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
