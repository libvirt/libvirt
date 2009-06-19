/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007, 2008, 2009 Red Hat, Inc.
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

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "xen_unified.h"

#include "xen_internal.h"
#include "proxy_internal.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xm_internal.h"
#if WITH_XEN_INOTIFY
#include "xen_inotify.h"
#endif
#include "xml.h"
#include "util.h"
#include "memory.h"
#include "node_device_conf.h"
#include "pci.h"

#define VIR_FROM_THIS VIR_FROM_XEN

static int
xenUnifiedNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info);
static int
xenUnifiedDomainGetMaxVcpus (virDomainPtr dom);
static int
xenUnifiedDomainGetVcpus (virDomainPtr dom,
                          virVcpuInfoPtr info, int maxinfo,
                          unsigned char *cpumaps, int maplen);

/* The five Xen drivers below us. */
static struct xenUnifiedDriver const * const drivers[XEN_UNIFIED_NR_DRIVERS] = {
    [XEN_UNIFIED_HYPERVISOR_OFFSET] = &xenHypervisorDriver,
    [XEN_UNIFIED_PROXY_OFFSET] = &xenProxyDriver,
    [XEN_UNIFIED_XEND_OFFSET] = &xenDaemonDriver,
    [XEN_UNIFIED_XS_OFFSET] = &xenStoreDriver,
    [XEN_UNIFIED_XM_OFFSET] = &xenXMDriver,
#if WITH_XEN_INOTIFY
    [XEN_UNIFIED_INOTIFY_OFFSET] = &xenInotifyDriver,
#endif
};

static int inside_daemon;

#define xenUnifiedError(conn, code, fmt...)                                  \
        virReportErrorHelper(conn, VIR_FROM_XEN, code, __FILE__,           \
                               __FUNCTION__, __LINE__, fmt)

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
    xenUnifiedPrivatePtr priv;
    int ret;

    ret = xenUnifiedNodeGetInfo(conn, &nodeInfo);
    if (ret < 0)
        return;

    priv = conn->privateData;

    priv->nbNodeCells = nodeInfo.nodes;
    priv->nbNodeCpus = nodeInfo.cpus;
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
    int ncpus;
    int nb_vcpu;
    char *cpulist = NULL;
    unsigned char *cpumap = NULL;
    size_t cpumaplen;
    int nb = 0;
    int n, m;
    virVcpuInfoPtr cpuinfo = NULL;
    virNodeInfo nodeinfo;
    xenUnifiedPrivatePtr priv;

    if (!VIR_IS_CONNECTED_DOMAIN(dom))
        return (NULL);

    priv = dom->conn->privateData;

    if (priv->nbNodeCpus <= 0)
        return(NULL);
    nb_vcpu = xenUnifiedDomainGetMaxVcpus(dom);
    if (nb_vcpu <= 0)
        return(NULL);
    if (xenUnifiedNodeGetInfo(dom->conn, &nodeinfo) < 0)
        return(NULL);

    if (VIR_ALLOC_N(cpulist, priv->nbNodeCpus) < 0)
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
            for (m = 0 ; m < priv->nbNodeCpus; m++) {
                if ((cpulist[m] == 0) &&
                    (VIR_CPU_USABLE(cpumap, cpumaplen, n, m))) {
                    cpulist[m] = 1;
                    nb++;
                    /* if all CPU are used just return NULL */
                    if (nb == priv->nbNodeCpus)
                        goto done;

                }
            }
        }
        res = virDomainCpuSetFormat(dom->conn, cpulist, priv->nbNodeCpus);
    }

done:
    VIR_FREE(cpulist);
    VIR_FREE(cpumap);
    VIR_FREE(cpuinfo);
    return(res);
}

#ifdef WITH_LIBVIRTD

static int
xenInitialize (int privileged ATTRIBUTE_UNUSED)
{
    inside_daemon = 1;
    return 0;
}

static virStateDriver state_driver = {
    .initialize = xenInitialize,
};

#endif

/*----- Dispatch functions. -----*/

/* These dispatch functions follow the model used historically
 * by libvirt.c -- trying each low-level Xen driver in turn
 * until one succeeds.  However since we know what low-level
 * drivers can perform which functions, it is probably better
 * in future to optimise these dispatch functions to just call
 * the single function (or small number of appropriate functions)
 * in the low level drivers directly.
 */

static int
xenUnifiedProbe (void)
{
#ifdef __linux__
    if (virFileExists("/proc/xen"))
        return 1;
#endif
#ifdef __sun
    FILE *fh;

    if (fh = fopen("/dev/xen/domcaps", "r")) {
        fclose(fh);
        return 1;
    }
#endif
    return 0;
}

static virDrvOpenStatus
xenUnifiedOpen (virConnectPtr conn, virConnectAuthPtr auth, int flags)
{
    int i, ret = VIR_DRV_OPEN_DECLINED;
    xenUnifiedPrivatePtr priv;
    virDomainEventCallbackListPtr cbList;

#ifdef __sun
    /*
     * Only the libvirtd instance can open this driver.
     * Everything else falls back to the remote driver.
     */
    if (!inside_daemon)
        return VIR_DRV_OPEN_DECLINED;
#endif

    if (conn->uri == NULL) {
        if (!xenUnifiedProbe())
            return VIR_DRV_OPEN_DECLINED;

        conn->uri = xmlParseURI("xen:///");
        if (!conn->uri) {
            virReportOOMError (NULL);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (conn->uri->scheme) {
            /* Decline any scheme which isn't "xen://" or "http://". */
            if (STRCASENEQ(conn->uri->scheme, "xen") &&
                STRCASENEQ(conn->uri->scheme, "http"))
                return VIR_DRV_OPEN_DECLINED;


            /* Return an error if the path isn't '' or '/' */
            if (conn->uri->path &&
                STRNEQ(conn->uri->path, "") &&
                STRNEQ(conn->uri->path, "/")) {
                xenUnifiedError(NULL, VIR_ERR_INTERNAL_ERROR,
                                _("unexpected Xen URI path '%s', try xen:///"),
                                conn->uri->path);
                return VIR_DRV_OPEN_ERROR;
            }

            /* Decline any xen:// URI with a server specified, allowing remote
             * driver to handle, but keep any http:/// URIs */
            if (STRCASEEQ(conn->uri->scheme, "xen") &&
                conn->uri->server)
                return VIR_DRV_OPEN_DECLINED;
        } else {
            /* Special case URI for Xen driver only:
             *
             * Treat a plain path as a Xen UNIX socket path, and give
             * error unless path is absolute
             */
            if (!conn->uri->path || conn->uri->path[0] != '/') {
                xenUnifiedError(NULL, VIR_ERR_INTERNAL_ERROR,
                                _("unexpected Xen URI path '%s', try ///var/lib/xen/xend-socket"),
                                NULLSTR(conn->uri->path));
                return VIR_DRV_OPEN_ERROR;
            }
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    /* Allocate per-connection private data. */
    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError (NULL);
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&priv->lock) < 0) {
        xenUnifiedError (NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("cannot initialise mutex"));
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }

    /* Allocate callback list */
    if (VIR_ALLOC(cbList) < 0) {
        virReportOOMError (NULL);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = priv;

    priv->domainEventCallbacks = cbList;

    priv->handle = -1;
    priv->xendConfigVersion = -1;
    priv->xshandle = NULL;
    priv->proxy = -1;


    /* Hypervisor is only run with privilege & required to succeed */
    if (xenHavePrivilege()) {
        DEBUG0("Trying hypervisor sub-driver");
        if (drivers[XEN_UNIFIED_HYPERVISOR_OFFSET]->open(conn, auth, flags) ==
            VIR_DRV_OPEN_SUCCESS) {
            DEBUG0("Activated hypervisor sub-driver");
            priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] = 1;
        }
    }

    /* XenD is required to succeed if privileged.
     * If it fails as non-root, then the proxy driver may take over
     */
    DEBUG0("Trying XenD sub-driver");
    if (drivers[XEN_UNIFIED_XEND_OFFSET]->open(conn, auth, flags) ==
        VIR_DRV_OPEN_SUCCESS) {
        DEBUG0("Activated XenD sub-driver");
        priv->opened[XEN_UNIFIED_XEND_OFFSET] = 1;

        /* XenD is active, so try the xm & xs drivers too, both requird to
         * succeed if root, optional otherwise */
        if (priv->xendConfigVersion <= 2) {
            DEBUG0("Trying XM sub-driver");
            if (drivers[XEN_UNIFIED_XM_OFFSET]->open(conn, auth, flags) ==
                VIR_DRV_OPEN_SUCCESS) {
                DEBUG0("Activated XM sub-driver");
                priv->opened[XEN_UNIFIED_XM_OFFSET] = 1;
            }
        }
        DEBUG0("Trying XS sub-driver");
        if (drivers[XEN_UNIFIED_XS_OFFSET]->open(conn, auth, flags) ==
            VIR_DRV_OPEN_SUCCESS) {
            DEBUG0("Activated XS sub-driver");
            priv->opened[XEN_UNIFIED_XS_OFFSET] = 1;
        } else {
            if (xenHavePrivilege())
                goto fail; /* XS is mandatory when privileged */
        }
    } else {
        if (xenHavePrivilege()) {
            goto fail; /* XenD is mandatory when privileged */
        } else {
#if WITH_PROXY
            DEBUG0("Trying proxy sub-driver");
            if (drivers[XEN_UNIFIED_PROXY_OFFSET]->open(conn, auth, flags) ==
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

    xenNumaInit(conn);

    if (!(priv->caps = xenHypervisorMakeCapabilities(conn))) {
        DEBUG0("Failed to make capabilities");
        goto fail;
    }

#if WITH_XEN_INOTIFY
    if (xenHavePrivilege()) {
        DEBUG0("Trying Xen inotify sub-driver");
        if (drivers[XEN_UNIFIED_INOTIFY_OFFSET]->open(conn, auth, flags) ==
            VIR_DRV_OPEN_SUCCESS) {
            DEBUG0("Activated Xen inotify sub-driver");
            priv->opened[XEN_UNIFIED_INOTIFY_OFFSET] = 1;
        }
    }
#endif

    return VIR_DRV_OPEN_SUCCESS;

fail:
    ret = VIR_DRV_OPEN_ERROR;
#ifndef WITH_PROXY
clean:
#endif
    DEBUG0("Failed to activate a mandatory sub-driver");
    for (i = 0 ; i < XEN_UNIFIED_NR_DRIVERS ; i++)
        if (priv->opened[i]) drivers[i]->close(conn);
    virMutexDestroy(&priv->lock);
    VIR_FREE(priv);
    conn->privateData = NULL;
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
    virDomainEventCallbackListFree(priv->domainEventCallbacks);

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->close)
            (void) drivers[i]->close (conn);

    virMutexDestroy(&priv->lock);
    VIR_FREE(conn->privateData);

    return 0;
}


#define HV_VERSION ((DOM0_INTERFACE_VERSION >> 24) * 1000000 +         \
                    ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +   \
                    (DOM0_INTERFACE_VERSION & 0xFFFF))

unsigned long xenUnifiedVersion(void)
{
    return HV_VERSION;
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
xenUnifiedGetVersion (virConnectPtr conn, unsigned long *hvVer)
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
    char *result;

    result = virGetHostname();
    if (result == NULL) {
        virReportSystemError(conn, errno,
                             "%s", _("cannot lookup hostname"));
        return NULL;
    }
    /* Caller frees this string. */
    return result;
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
    xenUnifiedPrivatePtr priv = conn->privateData;
    char *xml;

    if (!(xml = virCapabilitiesFormatXML(priv->caps))) {
        virReportOOMError(conn);
        return NULL;
    }

    return xml;
}

static int
xenUnifiedListDomains (virConnectPtr conn, int *ids, int maxids)
{
    GET_PRIVATE(conn);
    int ret;

    /* Try xenstore. */
    if (priv->opened[XEN_UNIFIED_XS_OFFSET]) {
        ret = xenStoreListDomains (conn, ids, maxids);
        if (ret >= 0) return ret;
    }

    /* Try HV. */
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorListDomains (conn, ids, maxids);
        if (ret >= 0) return ret;
    }

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonListDomains (conn, ids, maxids);
        if (ret >= 0) return ret;
    }

    /* Try proxy. */
    if (priv->opened[XEN_UNIFIED_PROXY_OFFSET]) {
        ret = xenProxyListDomains (conn, ids, maxids);
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
xenUnifiedDomainCreateXML (virConnectPtr conn,
                           const char *xmlDesc, unsigned int flags)
{
    GET_PRIVATE(conn);
    int i;
    virDomainPtr ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainCreateXML) {
            ret = drivers[i]->domainCreateXML (conn, xmlDesc, flags);
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

    /* Prefer xend for setting max memory */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        if (xenDaemonDomainSetMaxMemory (dom, memory) == 0)
            return 0;
    }

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_XEND_OFFSET &&
            priv->opened[i] &&
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
            xenUnifiedLock(priv);
            cpus = xenDomainUsedCpus(dom);
            xenUnifiedUnlock(priv);
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


static char *
xenUnifiedDomainXMLFromNative(virConnectPtr conn,
                              const char *format,
                              const char *config,
                              unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    virConfPtr conf = NULL;
    GET_PRIVATE(conn);

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        xenUnifiedError(conn, VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        return NULL;
    }

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        conf = virConfReadMem(config, strlen(config), 0);
        if (!conf)
            goto cleanup;

        def = xenXMDomainConfigParse(conn, conf);
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        def = xenDaemonParseSxprString(conn, config, priv->xendConfigVersion);
    }
    if (!def)
        goto cleanup;

    ret = virDomainDefFormat(conn, def, 0);

cleanup:
    virDomainDefFree(def);
    return ret;
}


#define MAX_CONFIG_SIZE (1024 * 65)
static char *
xenUnifiedDomainXMLToNative(virConnectPtr conn,
                            const char *format,
                            const char *xmlData,
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    virConfPtr conf = NULL;
    GET_PRIVATE(conn);

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        xenUnifiedError(conn, VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(def = virDomainDefParseString(conn,
                                        priv->caps,
                                        xmlData,
                                        0)))
        goto cleanup;

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        int len = MAX_CONFIG_SIZE;
        conf = xenXMDomainConfigFormat(conn, def);
        if (!conf)
            goto cleanup;

        if (VIR_ALLOC_N(ret, len) < 0) {
            virReportOOMError(conn);
            goto cleanup;
        }

        if (virConfWriteMem(ret, &len, conf) < 0) {
            VIR_FREE(ret);
            goto cleanup;
        }
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        ret = xenDaemonFormatSxpr(conn, def, priv->xendConfigVersion);
    }

cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return ret;
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

    if (priv->xendConfigVersion < 3) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainGetAutostart(dom, autostart);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
            return xenDaemonDomainGetAutostart(dom, autostart);
    }

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainSetAutostart (virDomainPtr dom, int autostart)
{
    GET_PRIVATE(dom->conn);

    if (priv->xendConfigVersion < 3) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainSetAutostart(dom, autostart);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
            return xenDaemonDomainSetAutostart(dom, autostart);
    }

    xenUnifiedError (dom->conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

static int
xenUnifiedDomainEventRegister (virConnectPtr conn,
                               virConnectDomainEventCallback callback,
                               void *opaque,
                               void (*freefunc)(void *))
{
    GET_PRIVATE (conn);

    int ret;
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    ret = virDomainEventCallbackListAdd(conn, priv->domainEventCallbacks,
                                        callback, opaque, freefunc);

    if (ret == 0)
        conn->refs++;

    xenUnifiedUnlock(priv);
    return (ret);
}

static int
xenUnifiedDomainEventDeregister (virConnectPtr conn,
                                 virConnectDomainEventCallback callback)
{
    int ret;
    GET_PRIVATE (conn);
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError (conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (priv->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDelete(conn, priv->domainEventCallbacks,
                                                   callback);
    else
        ret = virDomainEventCallbackListRemove(conn, priv->domainEventCallbacks,
                                               callback);

    if (ret == 0)
        virUnrefConnect(conn);

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedNodeDeviceGetPciInfo (virNodeDevicePtr dev,
                           unsigned *domain,
                           unsigned *bus,
                           unsigned *slot,
                           unsigned *function)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDevCapsDefPtr cap;
    char *xml = NULL;
    int ret = -1;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto out;

    def = virNodeDeviceDefParseString(dev->conn, xml, EXISTING_DEVICE);
    if (!def)
        goto out;

    cap = def->caps;
    while (cap) {
        if (cap->type == VIR_NODE_DEV_CAP_PCI_DEV) {
            *domain   = cap->data.pci_dev.domain;
            *bus      = cap->data.pci_dev.bus;
            *slot     = cap->data.pci_dev.slot;
            *function = cap->data.pci_dev.function;
            break;
        }

        cap = cap->next;
    }

    if (!cap) {
        xenUnifiedError(dev->conn, VIR_ERR_INVALID_ARG,
                        _("device %s is not a PCI device"), dev->name);
        goto out;
    }

    ret = 0;
out:
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
xenUnifiedNodeDeviceDettach (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (xenUnifiedNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciDettachDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}

static int
xenUnifiedNodeDeviceReAttach (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (xenUnifiedNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciReAttachDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}

static int
xenUnifiedNodeDeviceReset (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (xenUnifiedNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(dev->conn, domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciResetDevice(dev->conn, pci) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(dev->conn, pci);
    return ret;
}


/*----- Register with libvirt.c, and initialise Xen drivers. -----*/

/* The interface which we export upwards to libvirt.c. */
static virDriver xenUnifiedDriver = {
    VIR_DRV_XEN_UNIFIED,
    "Xen",
    xenUnifiedOpen, /* open */
    xenUnifiedClose, /* close */
    xenUnifiedSupportsFeature, /* supports_feature */
    xenUnifiedType, /* type */
    xenUnifiedGetVersion, /* version */
    xenUnifiedGetHostname, /* getHostname */
    xenUnifiedGetMaxVcpus, /* getMaxVcpus */
    xenUnifiedNodeGetInfo, /* nodeGetInfo */
    xenUnifiedGetCapabilities, /* getCapabilities */
    xenUnifiedListDomains, /* listDomains */
    xenUnifiedNumOfDomains, /* numOfDomains */
    xenUnifiedDomainCreateXML, /* domainCreateXML */
    xenUnifiedDomainLookupByID, /* domainLookupByID */
    xenUnifiedDomainLookupByUUID, /* domainLookupByUUID */
    xenUnifiedDomainLookupByName, /* domainLookupByName */
    xenUnifiedDomainSuspend, /* domainSuspend */
    xenUnifiedDomainResume, /* domainResume */
    xenUnifiedDomainShutdown, /* domainShutdown */
    xenUnifiedDomainReboot, /* domainReboot */
    xenUnifiedDomainDestroy, /* domainDestroy */
    xenUnifiedDomainGetOSType, /* domainGetOSType */
    xenUnifiedDomainGetMaxMemory, /* domainGetMaxMemory */
    xenUnifiedDomainSetMaxMemory, /* domainSetMaxMemory */
    xenUnifiedDomainSetMemory, /* domainSetMemory */
    xenUnifiedDomainGetInfo, /* domainGetInfo */
    xenUnifiedDomainSave, /* domainSave */
    xenUnifiedDomainRestore, /* domainRestore */
    xenUnifiedDomainCoreDump, /* domainCoreDump */
    xenUnifiedDomainSetVcpus, /* domainSetVcpus */
    xenUnifiedDomainPinVcpu, /* domainPinVcpu */
    xenUnifiedDomainGetVcpus, /* domainGetVcpus */
    xenUnifiedDomainGetMaxVcpus, /* domainGetMaxVcpus */
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    xenUnifiedDomainDumpXML, /* domainDumpXML */
    xenUnifiedDomainXMLFromNative, /* domainXmlFromNative */
    xenUnifiedDomainXMLToNative, /* domainXmlToNative */
    xenUnifiedListDefinedDomains, /* listDefinedDomains */
    xenUnifiedNumOfDefinedDomains, /* numOfDefinedDomains */
    xenUnifiedDomainCreate, /* domainCreate */
    xenUnifiedDomainDefineXML, /* domainDefineXML */
    xenUnifiedDomainUndefine, /* domainUndefine */
    xenUnifiedDomainAttachDevice, /* domainAttachDevice */
    xenUnifiedDomainDetachDevice, /* domainDetachDevice */
    xenUnifiedDomainGetAutostart, /* domainGetAutostart */
    xenUnifiedDomainSetAutostart, /* domainSetAutostart */
    xenUnifiedDomainGetSchedulerType, /* domainGetSchedulerType */
    xenUnifiedDomainGetSchedulerParameters, /* domainGetSchedulerParameters */
    xenUnifiedDomainSetSchedulerParameters, /* domainSetSchedulerParameters */
    xenUnifiedDomainMigratePrepare, /* domainMigratePrepare */
    xenUnifiedDomainMigratePerform, /* domainMigratePerform */
    xenUnifiedDomainMigrateFinish, /* domainMigrateFinish */
    xenUnifiedDomainBlockStats, /* domainBlockStats */
    xenUnifiedDomainInterfaceStats, /* domainInterfaceStats */
    xenUnifiedDomainBlockPeek, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    xenUnifiedNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    xenUnifiedNodeGetFreeMemory, /* getFreeMemory */
    xenUnifiedDomainEventRegister, /* domainEventRegister */
    xenUnifiedDomainEventDeregister, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    xenUnifiedNodeDeviceDettach, /* nodeDeviceDettach */
    xenUnifiedNodeDeviceReAttach, /* nodeDeviceReAttach */
    xenUnifiedNodeDeviceReset, /* nodeDeviceReset */
};

/**
 * xenRegister:
 *
 * Register xen related drivers
 *
 * Returns the driver priority or -1 in case of error.
 */
int
xenRegister (void)
{
    /* Ignore failures here. */
    (void) xenHypervisorInit ();

#ifdef WITH_LIBVIRTD
    if (virRegisterStateDriver (&state_driver) == -1) return -1;
#endif

    return virRegisterDriver (&xenUnifiedDriver);
}

/**
 * xenUnifiedDomainInfoListFree:
 *
 * Free the Domain Info List
 */
void
xenUnifiedDomainInfoListFree(xenUnifiedDomainInfoListPtr list)
{
    int i;

    if (list == NULL)
        return;

    for (i=0; i<list->count; i++) {
        VIR_FREE(list->doms[i]->name);
        VIR_FREE(list->doms[i]);
    }
    VIR_FREE(list);
}

/**
 * xenUnifiedAddDomainInfo:
 *
 * Add name and uuid to the domain info list
 *
 * Returns: 0 on success, -1 on failure
 */
int
xenUnifiedAddDomainInfo(xenUnifiedDomainInfoListPtr list,
                        int id, char *name,
                        unsigned char *uuid)
{
    xenUnifiedDomainInfoPtr info;
    int n;

    /* check if we already have this callback on our list */
    for (n=0; n < list->count; n++) {
        if (STREQ(list->doms[n]->name, name) &&
            !memcmp(list->doms[n]->uuid, uuid, VIR_UUID_BUFLEN)) {
            DEBUG0("WARNING: dom already tracked");
            return -1;
        }
    }

    if (VIR_ALLOC(info) < 0)
        goto memory_error;
    if (!(info->name = strdup(name)))
        goto memory_error;

    memcpy(info->uuid, uuid, VIR_UUID_BUFLEN);
    info->id = id;

    /* Make space on list */
    n = list->count;
    if (VIR_REALLOC_N(list->doms, n + 1) < 0) {
        goto memory_error;
    }

    list->doms[n] = info;
    list->count++;
    return 0;
memory_error:
    virReportOOMError (NULL);
    if (info)
        VIR_FREE(info->name);
    VIR_FREE(info);
    return -1;
}

/**
 * xenUnifiedRemoveDomainInfo:
 *
 * Removes name and uuid to the domain info list
 *
 * Returns: 0 on success, -1 on failure
 */
int
xenUnifiedRemoveDomainInfo(xenUnifiedDomainInfoListPtr list,
                           int id, char *name,
                           unsigned char *uuid)
{
    int i;
    for (i = 0 ; i < list->count ; i++) {
        if( list->doms[i]->id == id &&
            STREQ(list->doms[i]->name, name) &&
            !memcmp(list->doms[i]->uuid, uuid, VIR_UUID_BUFLEN)) {

            VIR_FREE(list->doms[i]->name);
            VIR_FREE(list->doms[i]);

            if (i < (list->count - 1))
                memmove(list->doms + i,
                        list->doms + i + 1,
                        sizeof(*(list->doms)) *
                                (list->count - (i + 1)));

            if (VIR_REALLOC_N(list->doms,
                              list->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            list->count--;

            return 0;
        }
    }
    return -1;
}

static void
xenUnifiedDomainEventDispatchFunc(virConnectPtr conn,
                                  virDomainEventPtr event,
                                  virConnectDomainEventCallback cb,
                                  void *cbopaque,
                                  void *opaque)
{
    xenUnifiedPrivatePtr priv = opaque;

    /*
     * Release the lock while the callback is running so that
     * we're re-entrant safe for callback work - the callback
     * may want to invoke other virt functions & we have already
     * protected the one piece of state we have - the callback
     * list
     */
    xenUnifiedUnlock(priv);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    xenUnifiedLock(priv);
}

/**
 * xenUnifiedDomainEventDispatch:
 * @priv: the connection to dispatch events on
 * @event: the event to dispatch
 *
 * Dispatch domain events to registered callbacks
 *
 * The caller must hold the lock in 'priv' before invoking
 *
 */
void xenUnifiedDomainEventDispatch (xenUnifiedPrivatePtr priv,
                                    virDomainEventPtr event)
{
    if (!priv)
        return;

    priv->domainEventDispatching = 1;

    if (priv->domainEventCallbacks) {
        virDomainEventDispatch(event,
                               priv->domainEventCallbacks,
                               xenUnifiedDomainEventDispatchFunc,
                               priv);

        /* Purge any deleted callbacks */
        virDomainEventCallbackListPurgeMarked(priv->domainEventCallbacks);
    }

    virDomainEventFree(event);

    priv->domainEventDispatching = 0;
}

void xenUnifiedLock(xenUnifiedPrivatePtr priv)
{
    virMutexLock(&priv->lock);
}

void xenUnifiedUnlock(xenUnifiedPrivatePtr priv)
{
    virMutexUnlock(&priv->lock);
}
