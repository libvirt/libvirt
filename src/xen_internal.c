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
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

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

static virDriver xenHypervisorDriver = {
    "Xen",
    NULL, /* init */
    xenHypervisorOpen, /* open */
    xenHypervisorClose, /* close */
    NULL, /* type */
    xenHypervisorGetVersion, /* version */
    NULL, /* listDomains */
    NULL, /* numOfDomains */
    NULL, /* domainCreateLinux */
    NULL, /* domainLookupByID */
    NULL, /* domainLookupByUUID */
    NULL, /* domainLookupByName */
    xenHypervisorPauseDomain, /* domainSuspend */
    xenHypervisorResumeDomain, /* domainResume */
    NULL, /* domainShutdown */
    xenHypervisorDestroyDomain, /* domainDestroy */
    NULL, /* domainFree */
    NULL, /* domainGetName */
    NULL, /* domainGetID */
    NULL, /* domainGetUUID */
    NULL, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    xenHypervisorSetMaxMemory, /* domainSetMaxMemory */
    xenHypervisorGetDomainInfo, /* domainGetInfo */
    NULL, /* domainSave */
    NULL /* domainRestore */
};

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

    if ((name != NULL) && (strcmp(name, "xen")))
        return(-1);

    conn->handle = -1;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
            virXenError(VIR_ERR_NO_XEN, XEN_HYPERVISOR_SOCKET, 0);
        return (-1);
    }
    conn->handle = ret;

    return (ret);
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

    if (mlock(info, sizeof(dom0_getdomaininfo_t)) < 0) {
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

    if (munlock(info, sizeof(dom0_getdomaininfo_t)) < 0) {
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
