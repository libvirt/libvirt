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
#include "xen_internal.h"

#define XEN_HYPERVISOR_SOCKET "/proc/xen/privcmd"

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
 * @quiet: don'r raise an error on failure if set
 *
 * Connects to the Xen hypervisor.
 *
 * Returns the handle or -1 in case of error.
 */
int
xenHypervisorOpen(int quiet)
{
    int ret;

    ret = open(XEN_HYPERVISOR_SOCKET, O_RDWR);
    if (ret < 0) {
        if (!quiet)
            virXenError(VIR_ERR_NO_XEN, XEN_HYPERVISOR_SOCKET, 0);
        return (-1);
    }

    return (ret);
}

/**
 * xenHypervisorClose:
 * @handle: the handle to the Xen hypervisor
 *
 * Close the connection to the Xen hypervisor.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
xenHypervisorClose(int handle)
{
    int ret;

    if (handle < 0)
        return (-1);

    ret = close(handle);
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
 * @handle: the handle to the Xen hypervisor
 *
 * Call the hypervisor to extracts his own internal API version
 *
 * Returns the hypervisor running version or 0 in case of error.
 */
unsigned long
xenHypervisorGetVersion(int handle)
{
    int ret;
    unsigned int cmd;
    hypercall_t hc;

    hc.op = __HYPERVISOR_xen_version;
    hc.arg[0] = (unsigned long) XENVER_version;
    hc.arg[1] = 0;

    cmd = _IOC(_IOC_NONE, 'P', 0, sizeof(hc));
    ret = ioctl(handle, cmd, (unsigned long) &hc);

    if (ret < 0) {
        virXenError(VIR_ERR_XEN_CALL, " getting version ", XENVER_version);
        return (0);
    }
    /*
     * use unsigned long in case the version grows behind expectations
     * allowed by int
     */
    return ((unsigned long) ret);
}

/**
 * xenHypervisorGetDomainInfo:
 * @handle: the handle to the Xen hypervisor
 * @domain: the domain ID
 * @info: the place where informations should be stored
 *
 * Do an hypervisor call to get the related set of domain informations.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorGetDomainInfo(int handle, int domain,
                           dom0_getdomaininfo_t * info)
{
    dom0_op_t op;
    int ret;

    if (info == NULL)
        return (-1);

    memset(info, 0, sizeof(dom0_getdomaininfo_t));

    if (mlock(info, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " locking",
                    sizeof(dom0_getdomaininfo_t));
        return (-1);
    }

    op.cmd = DOM0_GETDOMAININFOLIST;
    op.u.getdomaininfolist.first_domain = (domid_t) domain;
    op.u.getdomaininfolist.max_domains = 1;
    op.u.getdomaininfolist.buffer = info;
    op.u.getdomaininfolist.num_domains = 1;
    info->domain = domain;

    ret = xenHypervisorDoOp(handle, &op);

    if (munlock(info, sizeof(dom0_getdomaininfo_t)) < 0) {
        virXenError(VIR_ERR_XEN_CALL, " release",
                    sizeof(dom0_getdomaininfo_t));
        ret = -1;
    }

    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorPauseDomain:
 * @handle: the handle to the Xen hypervisor
 * @domain: the domain ID
 *
 * Do an hypervisor call to pause the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorPauseDomain(int handle, int domain)
{
    dom0_op_t op;
    int ret;

    op.cmd = DOM0_PAUSEDOMAIN;
    op.u.pausedomain.domain = (domid_t) domain;

    ret = xenHypervisorDoOp(handle, &op);

    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorResumeDomain:
 * @handle: the handle to the Xen hypervisor
 * @domain: the domain ID
 *
 * Do an hypervisor call to resume the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorResumeDomain(int handle, int domain)
{
    dom0_op_t op;
    int ret;

    op.cmd = DOM0_UNPAUSEDOMAIN;
    op.u.unpausedomain.domain = (domid_t) domain;

    ret = xenHypervisorDoOp(handle, &op);

    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorDestroyDomain:
 * @handle: the handle to the Xen hypervisor
 * @domain: the domain ID
 *
 * Do an hypervisor call to destroy the given domain
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorDestroyDomain(int handle, int domain)
{
    dom0_op_t op;
    int ret;

    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = (domid_t) domain;

    ret = xenHypervisorDoOp(handle, &op);

    if (ret < 0)
        return (-1);
    return (0);
}

/**
 * xenHypervisorSetMaxMemory:
 * @handle: the handle to the Xen hypervisor
 * @domain: the domain ID
 * @memory: the max memory size in kilobytes.
 *
 * Do an hypervisor call to change the maximum amount of memory used
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenHypervisorSetMaxMemory(int handle, int domain, unsigned long memory)
{
    dom0_op_t op;
    int ret;

    op.cmd = DOM0_SETDOMAINMAXMEM;
    op.u.setdomainmaxmem.domain = (domid_t) domain;
    op.u.setdomainmaxmem.max_memkb = memory;

    ret = xenHypervisorDoOp(handle, &op);

    if (ret < 0)
        return (-1);
    return (0);
}
