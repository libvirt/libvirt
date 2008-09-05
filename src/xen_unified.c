/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

/* Note:
 *
 * This driver provides a unified interface to the five
 * separate underlying Xen drivers (xen_internal, proxy_internal,
 * xend_internal, xs_internal and xm_internal).  Historically
 * the body of libvirt.c handled the five Xen drivers,
 * and contained Xen-specific code.
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <xen/dom0_ops.h>
#include <libxml/uri.h>

#include "internal.h"

#include "xen_unified.h"

#include "xen_internal.h"
#include "proxy_internal.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xm_internal.h"
#include "xml.h"
#include "util.h"
#include "memory.h"

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt,__VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

static int
xenUnifiedNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info);
static int
xenUnifiedDomainGetMaxVcpus (virDomainPtr dom);
static int
xenUnifiedDomainGetVcpus (virDomainPtr dom,
                          virVcpuInfoPtr info, int maxinfo,
                          unsigned char *cpumaps, int maplen);

/* The five Xen drivers below us. */
static struct xenUnifiedDriver *drivers[XEN_UNIFIED_NR_DRIVERS] = {
    [XEN_UNIFIED_HYPERVISOR_OFFSET] = &xenHypervisorDriver,
    [XEN_UNIFIED_PROXY_OFFSET] = &xenProxyDriver,
    [XEN_UNIFIED_XEND_OFFSET] = &xenDaemonDriver,
    [XEN_UNIFIED_XS_OFFSET] = &xenStoreDriver,
    [XEN_UNIFIED_XM_OFFSET] = &xenXMDriver,
};

/**
 * xenUnifiedError:
 * @conn: the connection
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the xend daemon interface
 */
static void
xenUnifiedError (virConnectPtr conn, virErrorNumber error, const char *info)
{
    const char *errmsg;

    errmsg = __virErrorMsg (error, info);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
                     errmsg, info, NULL, 0, 0, errmsg, info);
}

/*
 * Helper functions currently used in the NUMA code
 * Those variables should not be accessed directly but through helper
 * functions xenNbCells() and xenNbCpu() available to all Xen backends
 */
static int nbNodeCells = -1;
static int nbNodeCpus = -1;

/**
 * xenNumaInit:
 * @conn: pointer to the hypervisor connection
 *
 * Initializer for previous variables. We currently assume that
 * the number of physical CPU and the number of NUMA cell is fixed
 * until reboot which might be false in future Xen implementations.
 */
static void
xenNumaInit(virConnectPtr conn) {
    virNodeInfo nodeInfo;
    int ret;

    ret = xenUnifiedNodeGetInfo(conn, &nodeInfo);
    if (ret < 0)
        return;
    nbNodeCells = nodeInfo.nodes;
    nbNodeCpus = nodeInfo.cpus;
}

/**
 * xenNbCells:
 * @conn: pointer to the hypervisor connection
 *
 * Number of NUMA cells present in the actual Node
 *
 * Returns the number of NUMA cells available on that Node
 */
int xenNbCells(virConnectPtr conn) {
    if (nbNodeCells < 0)
        xenNumaInit(conn);
    return(nbNodeCells);
}

/**
 * xenNbCpus:
 * @conn: pointer to the hypervisor connection
 *
 * Number of CPUs present in the actual Node
 *
 * Returns the number of CPUs available on that Node
 */
int xenNbCpus(virConnectPtr conn) {
    if (nbNodeCpus < 0)
        xenNumaInit(conn);
    return(nbNodeCpus);
}

/**
 * xenDomainUsedCpus:
 * @dom: the domain
 *
 * Analyze which set of CPUs are used by the domain and
 * return a string providing the ranges.
 *
 * Returns the string which needs to be freed by the caller or
 *         NULL if the domain uses all CPU or in case of error.
 */
char *
xenDomainUsedCpus(virDomainPtr dom)
{
    char *res = NULL;
    int nb_cpu, ncpus;
    int nb_vcpu;
    char *cpulist = NULL;
    unsigned char *cpumap = NULL;
    size_t cpumaplen;
    int nb = 0;
    int n, m;
    virVcpuInfoPtr cpuinfo = NULL;
    virNodeInfo nodeinfo;

    if (!VIR_IS_CONNECTED_DOMAIN(dom))
        return (NULL);

    nb_cpu = xenNbCpus(dom->conn);
    if (nb_cpu <= 0)
        return(NULL);
    nb_vcpu = xenUnifiedDomainGetMaxVcpus(dom);
    if (nb_vcpu <= 0)
        return(NULL);
    if (xenUnifiedNodeGetInfo(dom->conn, &nodeinfo) < 0)
        return(NULL);

    if (VIR_ALLOC_N(cpulist, nb_cpu) < 0)
        goto done;
    if (VIR_ALLOC_N(cpuinfo, nb_vcpu) < 0)
        goto done;
    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    if (xalloc_oversized(nb_vcpu, cpumaplen) ||
        VIR_ALLOC_N(cpumap, nb_vcpu * cpumaplen) < 0)
        goto done;

    if ((ncpus = xenUnifiedDomainGetVcpus(dom, cpuinfo, nb_vcpu,
                                          cpumap, cpumaplen)) >= 0) {
        for (n = 0 ; n < ncpus ; n++) {
            for (m = 0 ; m < nb_cpu; m++) {
                if ((cpulist[m] == 0) &&
                    (VIR_CPU_USABLE(cpumap, cpumaplen, n, m))) {
                    cpulist[m] = 1;
                    nb++;
                    /* if all CPU are used just return NULL */
                    if (nb == nb_cpu)
                        goto done;

                }
            }
        }
        res = virDomainCpuSetFormat(dom->conn, cpulist, nb_cpu);
    }

done:
    VIR_FREE(cpulist);
    VIR_FREE(cpumap);
    VIR_FREE(cpuinfo);
    return(res);
}

/*----- Dispatch functions. -----*/

/* These dispatch functions follow the model used historically
 * by libvirt.c -- trying each low-level Xen driver in turn
 * until one succeeds.  However since we know what low-level
 * drivers can perform which functions, it is probably better
 * in future to optimise these dispatch functions to just call
 * the single function (or small number of appropriate functions)
 * in the low level drivers directly.
 */

static const char *
xenUnifiedProbe (void)
{
#ifdef __linux__
    if (virFileExists("/proc/xen"))
        return("xen:///");
#endif
#ifdef __sun__
    FILE *fh;

    if (fh = fopen("/dev/xen/domcaps", "r")) {
        fclose(fh);
        return("xen:///");
    }
#endif
    return(NULL);
}

static int
xenUnifiedOpen (virConnectPtr conn, xmlURIPtr uri, virConnectAuthPtr auth, int flags)
{
    int i, ret = VIR_DRV_OPEN_DECLINED;
    xenUnifiedPrivatePtr priv;

    /* Refuse any scheme which isn't "xen://" or "http://". */
    if (uri->scheme &&
        STRCASENEQ(uri->scheme, "xen") &&
        STRCASENEQ(uri->scheme, "http"))
        return VIR_DRV_OPEN_DECLINED;

    /* xmlParseURI will parse a naked string like "foo" as a URI with
     * a NULL scheme.  That's not useful for us because we want to only
     * allow full pathnames (eg. ///var/lib/xen/xend-socket).  Decline
     * anything else.
     */
    if (!uri->scheme && (!uri->path || uri->path[0] != '/'))
        return VIR_DRV_OPEN_DECLINED;

    /* Refuse any xen:// URI with a server specified - allow remote to do it */
    if (uri->scheme && STRCASEEQ(uri->scheme, "xen") && uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* Allocate per-connection private data. */
    if (VIR_ALLOC(priv) < 0) {
        xenUnifiedError (NULL, VIR_ERR_NO_MEMORY, "allocating private data");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = priv;

    priv->handle = -1;
    priv->xendConfigVersion = -1;
    priv->type = -1;
    priv->len = -1;
    priv->addr = NULL;
    priv->xshandle = NULL;
    priv->proxy = -1;


    /* Hypervisor is only run as root & required to succeed */
    if (getuid() == 0) {
        DEBUG0("Trying hypervisor sub-driver");
        if (drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->open(conn, uri, auth, flags) ==
            VIR_DRV_OPEN_SUCCESS) {
            DEBUG0("Activated hypervisor sub-driver");
            priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] = 1;
        }
    }

    /* XenD is required to suceed if root.
     * If it fails as non-root, then the proxy driver may take over
     */
    DEBUG0("Trying XenD sub-driver");
    if (drivers[XEN_UNIFIED_XEND_OFFSET]->open(conn, uri, auth, flags) ==
        VIR_DRV_OPEN_SUCCESS) {
        DEBUG0("Activated XenD sub-driver");
        priv->opened[XEN_UNIFIED_XEND_OFFSET] = 1;

        /* XenD is active, so try the xm & xs drivers too, both requird to
         * succeed if root, optional otherwise */
        if (priv->xendConfigVersion <= 2) {
            DEBUG0("Trying XM sub-driver");
            if (drivers[XEN_UNIFIED_XM_OFFSET]->open(conn, uri, auth, flags) ==
                VIR_DRV_OPEN_SUCCESS) {
                DEBUG0("Activated XM sub-driver");
                priv->opened[XEN_UNIFIED_XM_OFFSET] = 1;
            }
        }
        DEBUG0("Trying XS sub-driver");
        if (drivers[XEN_UNIFIED_XS_OFFSET]->open(conn, uri, auth, flags) ==
            VIR_DRV_OPEN_SUCCESS) {
            DEBUG0("Activated XS sub-driver");
            priv->opened[XEN_UNIFIED_XS_OFFSET] = 1;
        } else {
            if (getuid() == 0)
                goto fail; /* XS is mandatory as root */
        }
    } else {
        if (getuid() == 0) {
            goto fail; /* XenD is mandatory as root */
        } else {
#if WITH_PROXY
            DEBUG0("Trying proxy sub-driver");
            if (drivers[XEN_UNIFIED_PROXY_OFFSET]->open(conn, uri, auth, flags) ==
                VIR_DRV_OPEN_SUCCESS) {
                DEBUG0("Activated proxy sub-driver");
                priv->opened[XEN_UNIFIED_PROXY_OFFSET] = 1;
            } else {
                goto fail; /* Proxy is mandatory if XenD failed */
            }
#else
            DEBUG0("Handing off for remote driver");
            ret = VIR_DRV_OPEN_DECLINED; /* Let remote_driver try instead */
            goto clean;
#endif
        }
    }

    if (!(priv->caps = xenHypervisorMakeCapabilities(conn))) {
        DEBUG0("Failed to make capabilities");
        goto fail;
    }

    return VIR_DRV_OPEN_SUCCESS;

fail:
    ret = VIR_DRV_OPEN_ERROR;
#ifndef WITH_PROXY
clean:
#endif
    DEBUG0("Failed to activate a mandatory sub-driver");
    for (i = 0 ; i < XEN_UNIFIED_NR_DRIVERS ; i++)
        if (priv->opened[i]) drivers[i]->close(conn);
    VIR_FREE(priv);
    return ret;
}

#define GET_PRIVATE(conn) \
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) (conn)->privateData

static int
xenUnifiedClose (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;

    virCapabilitiesFree(priv->caps);
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->close)
            (void) drivers[i]->close (conn);

    free (conn->privateData);
    conn->privateData = NULL;

    return 0;
}

static const char *
xenUnifiedType (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i])
            return "Xen";

    return NULL;
}

/* Which features are supported by this driver? */
static int
xenUnifiedSupportsFeature (virConnectPtr conn ATTRIBUTE_UNUSED, int feature)
{
    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V1: return 1;
    default: return 0;
    }
}

static int
xenUnifiedVersion (virConnectPtr conn, unsigned long *hvVer)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->version &&
            drivers[i]->version (conn, hvVer) == 0)
            return 0;

    return -1;
}

/* NB: Even if connected to the proxy, we're still on the
 * same machine.
 */
static char *
xenUnifiedGetHostname (virConnectPtr conn)
{
    int r;
    char hostname [HOST_NAME_MAX+1], *str;

    r = gethostname (hostname, HOST_NAME_MAX+1);
    if (r == -1) {
        xenUnifiedError (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    str = strdup (hostname);
    if (str == NULL) {
        xenUnifiedError (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    return str;
}

static int
xenUnifiedGetMaxVcpus (virConnectPtr conn, const char *type)
{
    GET_PRIVATE(conn);

    if (type && STRCASENEQ (type, "Xen")) {
        xenUnifiedError (conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorGetMaxVcpus (conn, type);
    else {
        xenUnifiedError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        return -1;
    }
}

static int
xenUnifiedNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->nodeGetInfo &&
            drivers[i]->nodeGetInfo (conn, info) == 0)
            return 0;

    return -1;
}

static char *
xenUnifiedGetCapabilities (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;
    char *ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->getCapabilities) {
            ret = drivers[i]->getCapabilities (conn);
            if (ret) return ret;
        }

    return NULL;
}

static int
xenUnifiedListDomains (virConnectPtr conn, int *ids, int maxids)
{
    GET_PRIVATE(conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->listDomains) {
            ret = drivers[i]->listDomains (conn, ids, maxids);
            if (ret >= 0) return ret;
        }

    return -1;
}

static int
xenUnifiedNumOfDomains (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->numOfDomains) {
            ret = drivers[i]->numOfDomains (conn);
            if (ret >= 0) return ret;
        }

    return -1;
}

static virDomainPtr
xenUnifiedDomainCreateLinux (virConnectPtr conn,
                             const char *xmlDesc, unsigned int flags)
{
    GET_PRIVATE(conn);
    int i;
    virDomainPtr ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainCreateLinux) {
            ret = drivers[i]->domainCreateLinux (conn, xmlDesc, flags);
            if (ret) return ret;
        }

    return NULL;
}

/* Assumption made in underlying drivers:
 * If the domain is "not found" and there is no other error, then
 * the Lookup* functions return a NULL but do not set virterror.
 */
static virDomainPtr
xenUnifiedDomainLookupByID (virConnectPtr conn, int id)
{
    GET_PRIVATE(conn);
    virDomainPtr ret;

    /* Reset any connection-level errors in virterror first, in case
     * there is one hanging around from a previous call.
     */
    virConnResetLastError (conn);

    /* Try hypervisor/xenstore combo. */
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorLookupDomainByID (conn, id);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try proxy. */
    if (priv->opened[XEN_UNIFIED_PROXY_OFFSET]) {
        ret = xenProxyLookupByID (conn, id);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonLookupByID (conn, id);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Not found. */
    xenUnifiedError (conn, VIR_ERR_NO_DOMAIN, __FUNCTION__);
    return NULL;
}

static virDomainPtr
xenUnifiedDomainLookupByUUID (virConnectPtr conn,
                              const unsigned char *uuid)
{
    GET_PRIVATE(conn);
    virDomainPtr ret;

    /* Reset any connection-level errors in virterror first, in case
     * there is one hanging around from a previous call.
     */
    virConnResetLastError (conn);

    /* Try hypervisor/xenstore combo. */
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorLookupDomainByUUID (conn, uuid);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try proxy. */
    if (priv->opened[XEN_UNIFIED_PROXY_OFFSET]) {
        ret = xenProxyLookupByUUID (conn, uuid);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonLookupByUUID (conn, uuid);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try XM for inactive domains. */
    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        ret = xenXMDomainLookupByUUID (conn, uuid);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Not found. */
    xenUnifiedError (conn, VIR_ERR_NO_DOMAIN, __FUNCTION__);
    return NULL;
}

static virDomainPtr
xenUnifiedDomainLookupByName (virConnectPtr conn,
                              const char *name)
{
    GET_PRIVATE(conn);
    virDomainPtr ret;

    /* Reset any connection-level errors in virterror first, in case
     * there is one hanging around from a previous call.
     */
    virConnResetLastError (conn);

    /* Try proxy. */
    if (priv->opened[XEN_UNIFIED_PROXY_OFFSET]) {
        ret = xenProxyLookupByName (conn, name);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonLookupByName (conn, name);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try xenstore for inactive domains. */
    if (priv->opened[XEN_UNIFIED_XS_OFFSET]) {
        ret = xenStoreLookupByName (conn, name);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Try XM for inactive domains. */
    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        ret = xenXMDomainLookupByName (conn, name);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Not found. */
    xenUnifiedError (conn, VIR_ERR_NO_DOMAIN, __FUNCTION__);
    return NULL;
}

static int
xenUnifiedDomainSuspend (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_HYPERVISOR_OFFSET &&
            priv->opened[i] &&
            drivers[i]->domainSuspend &&
            drivers[i]->domainSuspend (dom) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainSuspend &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainSuspend (dom) == 0)
        return 0;

    return -1;
}

static int
xenUnifiedDomainResume (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_HYPERVISOR_OFFSET &&
            priv->opened[i] &&
            drivers[i]->domainResume &&
            drivers[i]->domainResume (dom) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainResume &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainResume (dom) == 0)
        return 0;

    return -1;
}

static int
xenUnifiedDomainShutdown (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainShutdown &&
            drivers[i]->domainShutdown (dom) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainReboot (virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainReboot &&
            drivers[i]->domainReboot (dom, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainDestroy (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_HYPERVISOR_OFFSET &&
            priv->opened[i] &&
            drivers[i]->domainDestroy &&
            drivers[i]->domainDestroy (dom) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainDestroy &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainDestroy (dom) == 0)
        return 0;

    return -1;
}

static char *
xenUnifiedDomainGetOSType (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;
    char *ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainGetOSType) {
            ret = drivers[i]->domainGetOSType (dom);
            if (ret) return ret;
        }

    return NULL;
}

static unsigned long
xenUnifiedDomainGetMaxMemory (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;
    unsigned long ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainGetMaxMemory) {
            ret = drivers[i]->domainGetMaxMemory (dom);
            if (ret != 0) return ret;
        }

    return 0;
}

static int
xenUnifiedDomainSetMaxMemory (virDomainPtr dom, unsigned long memory)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainSetMaxMemory &&
            drivers[i]->domainSetMaxMemory (dom, memory) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainSetMemory (virDomainPtr dom, unsigned long memory)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainSetMemory &&
            drivers[i]->domainSetMemory (dom, memory) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainGetInfo (virDomainPtr dom, virDomainInfoPtr info)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainGetInfo &&
            drivers[i]->domainGetInfo (dom, info) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainSave (virDomainPtr dom, const char *to)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainSave &&
            drivers[i]->domainSave (dom, to) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainRestore (virConnectPtr conn, const char *from)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainRestore &&
            drivers[i]->domainRestore (conn, from) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainCoreDump (virDomainPtr dom, const char *to, int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainCoreDump &&
            drivers[i]->domainCoreDump (dom, to, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainSetVcpus (virDomainPtr dom, unsigned int nvcpus)
{
    GET_PRIVATE(dom->conn);
    int i;

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_HYPERVISOR_OFFSET &&
            priv->opened[i] &&
            drivers[i]->domainSetVcpus &&
            drivers[i]->domainSetVcpus (dom, nvcpus) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainSetVcpus &&
        drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->domainSetVcpus (dom, nvcpus) == 0)
        return 0;

    return -1;
}

static int
xenUnifiedDomainPinVcpu (virDomainPtr dom, unsigned int vcpu,
                         unsigned char *cpumap, int maplen)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->domainPinVcpu &&
            drivers[i]->domainPinVcpu (dom, vcpu, cpumap, maplen) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainGetVcpus (virDomainPtr dom,
                          virVcpuInfoPtr info, int maxinfo,
                          unsigned char *cpumaps, int maplen)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainGetVcpus) {
            ret = drivers[i]->domainGetVcpus (dom, info, maxinfo, cpumaps, maplen);
            if (ret > 0)
                return ret;
        }
    return -1;
}

static int
xenUnifiedDomainGetMaxVcpus (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainGetMaxVcpus) {
            ret = drivers[i]->domainGetMaxVcpus (dom);
            if (ret != 0) return ret;
        }

    return -1;
}

static char *
xenUnifiedDomainDumpXML (virDomainPtr dom, int flags)
{
    GET_PRIVATE(dom->conn);

    if (dom->id == -1 && priv->xendConfigVersion < 3 ) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainDumpXML(dom, flags);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
            char *cpus, *res;
            cpus = xenDomainUsedCpus(dom);
            res = xenDaemonDomainDumpXML(dom, flags, cpus);
            VIR_FREE(cpus);
            return(res);
        }
        if (priv->opened[XEN_UNIFIED_PROXY_OFFSET])
            return xenProxyDomainDumpXML(dom, flags);
    }

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}

static int
xenUnifiedDomainMigratePrepare (virConnectPtr dconn,
                                char **cookie,
                                int *cookielen,
                                const char *uri_in,
                                char **uri_out,
                                unsigned long flags,
                                const char *dname,
                                unsigned long resource)
{
    GET_PRIVATE(dconn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainMigratePrepare (dconn, cookie, cookielen,
                                              uri_in, uri_out,
                                              flags, dname, resource);

    xenUnifiedError (dconn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainMigratePerform (virDomainPtr dom,
                                const char *cookie,
                                int cookielen,
                                const char *uri,
                                unsigned long flags,
                                const char *dname,
                                unsigned long resource)
{
    GET_PRIVATE(dom->conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainMigratePerform (dom, cookie, cookielen, uri,
                                              flags, dname, resource);

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static virDomainPtr
xenUnifiedDomainMigrateFinish (virConnectPtr dconn,
                               const char *dname,
                               const char *cookie ATTRIBUTE_UNUSED,
                               int cookielen ATTRIBUTE_UNUSED,
                               const char *uri ATTRIBUTE_UNUSED,
                               unsigned long flags ATTRIBUTE_UNUSED)
{
    return xenUnifiedDomainLookupByName (dconn, dname);
}

static int
xenUnifiedListDefinedDomains (virConnectPtr conn, char **const names,
                              int maxnames)
{
    GET_PRIVATE(conn);
    int i;
    int ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->listDefinedDomains) {
            ret = drivers[i]->listDefinedDomains (conn, names, maxnames);
            if (ret >= 0) return ret;
        }

    return -1;
}

static int
xenUnifiedNumOfDefinedDomains (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;
    int ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->numOfDefinedDomains) {
            ret = drivers[i]->numOfDefinedDomains (conn);
            if (ret >= 0) return ret;
        }

    return -1;
}

static int
xenUnifiedDomainCreate (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainCreate &&
            drivers[i]->domainCreate (dom) == 0)
            return 0;

    return -1;
}

static virDomainPtr
xenUnifiedDomainDefineXML (virConnectPtr conn, const char *xml)
{
    GET_PRIVATE(conn);
    int i;
    virDomainPtr ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainDefineXML) {
            ret = drivers[i]->domainDefineXML (conn, xml);
            if (ret) return ret;
        }

    return NULL;
}

static int
xenUnifiedDomainUndefine (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainUndefine &&
            drivers[i]->domainUndefine (dom) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainAttachDevice (virDomainPtr dom, const char *xml)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainAttachDevice &&
            drivers[i]->domainAttachDevice (dom, xml) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainDetachDevice (virDomainPtr dom, const char *xml)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainDetachDevice &&
            drivers[i]->domainDetachDevice (dom, xml) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainGetAutostart (virDomainPtr dom, int *autostart)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainGetAutostart &&
            drivers[i]->domainGetAutostart (dom, autostart) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainSetAutostart (virDomainPtr dom, int autostart)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainSetAutostart &&
            drivers[i]->domainSetAutostart (dom, autostart) == 0)
            return 0;

    return -1;
}

static char *
xenUnifiedDomainGetSchedulerType (virDomainPtr dom, int *nparams)
{
    GET_PRIVATE(dom->conn);
    int i;
    char *schedulertype;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; i++) {
        if (priv->opened[i] && drivers[i]->domainGetSchedulerType) {
            schedulertype = drivers[i]->domainGetSchedulerType (dom, nparams);
            if (schedulertype != NULL)
                return(schedulertype);
        }
    }
    return(NULL);
}

static int
xenUnifiedDomainGetSchedulerParameters (virDomainPtr dom,
                    virSchedParameterPtr params, int *nparams)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i) {
        if (priv->opened[i] && drivers[i]->domainGetSchedulerParameters) {
           ret = drivers[i]->domainGetSchedulerParameters(dom, params, nparams);
           if (ret == 0)
               return(0);
        }
    }
    return(-1);
}

static int
xenUnifiedDomainSetSchedulerParameters (virDomainPtr dom,
                    virSchedParameterPtr params, int nparams)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i) {
        if (priv->opened[i] && drivers[i]->domainSetSchedulerParameters) {
           ret = drivers[i]->domainSetSchedulerParameters(dom, params, nparams);
           if (ret == 0)
               return 0;
        }
    }

    return(-1);
}

static int
xenUnifiedDomainBlockStats (virDomainPtr dom, const char *path,
                            struct _virDomainBlockStats *stats)
{
    GET_PRIVATE (dom->conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorDomainBlockStats (dom, path, stats);

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainInterfaceStats (virDomainPtr dom, const char *path,
                                struct _virDomainInterfaceStats *stats)
{
    GET_PRIVATE (dom->conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorDomainInterfaceStats (dom, path, stats);

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainBlockPeek (virDomainPtr dom, const char *path,
                           unsigned long long offset, size_t size,
                           void *buffer, unsigned int flags ATTRIBUTE_UNUSED)
{
    int r;
    GET_PRIVATE (dom->conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        r = xenDaemonDomainBlockPeek (dom, path, offset, size, buffer);
        if (r != -2) return r;
        /* r == -2 means declined, so fall through to XM driver ... */
    }

    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        if (xenXMDomainBlockPeek (dom, path, offset, size, buffer) == 0)
            return 0;
    }

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedNodeGetCellsFreeMemory (virConnectPtr conn, unsigned long long *freeMems,
                                  int startCell, int maxCells)
{
    GET_PRIVATE (conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorNodeGetCellsFreeMemory (conn, freeMems,
                                                    startCell, maxCells);

    xenUnifiedError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static unsigned long long
xenUnifiedNodeGetFreeMemory (virConnectPtr conn)
{
    unsigned long long freeMem = 0;
    int ret;
    GET_PRIVATE (conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorNodeGetCellsFreeMemory (conn, &freeMem,
                                                    -1, 1);
        if (ret != 1)
            return (0);
        return(freeMem);
    }

    xenUnifiedError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return(0);
}

/*----- Register with libvirt.c, and initialise Xen drivers. -----*/

#define HV_VERSION ((DOM0_INTERFACE_VERSION >> 24) * 1000000 +         \
                    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +   \
                    (DOM0_INTERFACE_VERSION & 0xFFFF))

/* The interface which we export upwards to libvirt.c. */
static virDriver xenUnifiedDriver = {
    .no = VIR_DRV_XEN_UNIFIED,
    .name = "Xen",
    .ver = HV_VERSION,
    .probe 			= xenUnifiedProbe,
    .open 			= xenUnifiedOpen,
    .close 			= xenUnifiedClose,
    .supports_feature   = xenUnifiedSupportsFeature,
    .type 			= xenUnifiedType,
    .version 			= xenUnifiedVersion,
    .getHostname    = xenUnifiedGetHostname,
    .getMaxVcpus 			= xenUnifiedGetMaxVcpus,
    .nodeGetInfo 			= xenUnifiedNodeGetInfo,
    .getCapabilities 		= xenUnifiedGetCapabilities,
    .listDomains 			= xenUnifiedListDomains,
    .numOfDomains 		= xenUnifiedNumOfDomains,
    .domainCreateLinux 		= xenUnifiedDomainCreateLinux,
    .domainLookupByID 		= xenUnifiedDomainLookupByID,
    .domainLookupByUUID 		= xenUnifiedDomainLookupByUUID,
    .domainLookupByName 		= xenUnifiedDomainLookupByName,
    .domainSuspend 		= xenUnifiedDomainSuspend,
    .domainResume 		= xenUnifiedDomainResume,
    .domainShutdown 		= xenUnifiedDomainShutdown,
    .domainReboot 		= xenUnifiedDomainReboot,
    .domainDestroy 		= xenUnifiedDomainDestroy,
    .domainGetOSType 		= xenUnifiedDomainGetOSType,
    .domainGetMaxMemory 		= xenUnifiedDomainGetMaxMemory,
    .domainSetMaxMemory 		= xenUnifiedDomainSetMaxMemory,
    .domainSetMemory 		= xenUnifiedDomainSetMemory,
    .domainGetInfo 		= xenUnifiedDomainGetInfo,
    .domainSave 			= xenUnifiedDomainSave,
    .domainRestore 		= xenUnifiedDomainRestore,
    .domainCoreDump 		= xenUnifiedDomainCoreDump,
    .domainSetVcpus 		= xenUnifiedDomainSetVcpus,
    .domainPinVcpu 		= xenUnifiedDomainPinVcpu,
    .domainGetVcpus 		= xenUnifiedDomainGetVcpus,
    .domainGetMaxVcpus 		= xenUnifiedDomainGetMaxVcpus,
    .domainDumpXML 		= xenUnifiedDomainDumpXML,
    .listDefinedDomains 		= xenUnifiedListDefinedDomains,
    .numOfDefinedDomains 		= xenUnifiedNumOfDefinedDomains,
    .domainCreate 		= xenUnifiedDomainCreate,
    .domainDefineXML 		= xenUnifiedDomainDefineXML,
    .domainUndefine 		= xenUnifiedDomainUndefine,
    .domainAttachDevice 		= xenUnifiedDomainAttachDevice,
    .domainDetachDevice 		= xenUnifiedDomainDetachDevice,
    .domainGetAutostart             = xenUnifiedDomainGetAutostart,
    .domainSetAutostart             = xenUnifiedDomainSetAutostart,
    .domainGetSchedulerType	= xenUnifiedDomainGetSchedulerType,
    .domainGetSchedulerParameters	= xenUnifiedDomainGetSchedulerParameters,
    .domainSetSchedulerParameters	= xenUnifiedDomainSetSchedulerParameters,
    .domainMigratePrepare		= xenUnifiedDomainMigratePrepare,
    .domainMigratePerform		= xenUnifiedDomainMigratePerform,
    .domainMigrateFinish		= xenUnifiedDomainMigrateFinish,
    .domainBlockStats	= xenUnifiedDomainBlockStats,
    .domainInterfaceStats = xenUnifiedDomainInterfaceStats,
    .domainBlockPeek	= xenUnifiedDomainBlockPeek,
    .nodeGetCellsFreeMemory = xenUnifiedNodeGetCellsFreeMemory,
    .getFreeMemory = xenUnifiedNodeGetFreeMemory,
};

/**
 * xenUnifiedRegister:
 *
 * Register xen related drivers
 *
 * Returns the driver priority or -1 in case of error.
 */
int
xenUnifiedRegister (void)
{
    /* Ignore failures here. */
    (void) xenHypervisorInit ();
    (void) xenXMInit ();

    return virRegisterDriver (&xenUnifiedDriver);
}

