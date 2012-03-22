/*
 * xen_driver.c: Unified Xen driver.
 *
 * Copyright (C) 2007-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#include <config.h>

/* Note:
 *
 * This driver provides a unified interface to the five
 * separate underlying Xen drivers (xen_internal,
 * xend_internal, xs_internal and xm_internal).  Historically
 * the body of libvirt.c handled the five Xen drivers,
 * and contained Xen-specific code.
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <xen/dom0_ops.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "xen_driver.h"

#include "xen_sxpr.h"
#include "xen_xm.h"
#include "xen_hypervisor.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xm_internal.h"
#if WITH_XEN_INOTIFY
# include "xen_inotify.h"
#endif
#include "xml.h"
#include "util.h"
#include "memory.h"
#include "node_device_conf.h"
#include "pci.h"
#include "uuid.h"
#include "fdstream.h"
#include "virfile.h"
#include "viruri.h"
#include "command.h"
#include "virnodesuspend.h"

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
    [XEN_UNIFIED_XEND_OFFSET] = &xenDaemonDriver,
    [XEN_UNIFIED_XS_OFFSET] = &xenStoreDriver,
    [XEN_UNIFIED_XM_OFFSET] = &xenXMDriver,
#if WITH_XEN_INOTIFY
    [XEN_UNIFIED_INOTIFY_OFFSET] = &xenInotifyDriver,
#endif
};

#if defined WITH_LIBVIRTD || defined __sun
static int inside_daemon;
#endif

#define xenUnifiedError(code, ...)                                         \
        virReportErrorHelper(VIR_FROM_XEN, code, __FILE__,                 \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

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
        return NULL;

    priv = dom->conn->privateData;

    if (priv->nbNodeCpus <= 0)
        return NULL;
    nb_vcpu = xenUnifiedDomainGetMaxVcpus(dom);
    if (nb_vcpu <= 0)
        return NULL;
    if (xenUnifiedNodeGetInfo(dom->conn, &nodeinfo) < 0)
        return NULL;

    if (VIR_ALLOC_N(cpulist, priv->nbNodeCpus) < 0) {
        virReportOOMError();
        goto done;
    }
    if (VIR_ALLOC_N(cpuinfo, nb_vcpu) < 0) {
        virReportOOMError();
        goto done;
    }
    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    if (xalloc_oversized(nb_vcpu, cpumaplen) ||
        VIR_ALLOC_N(cpumap, nb_vcpu * cpumaplen) < 0) {
        virReportOOMError();
        goto done;
    }

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
        res = virDomainCpuSetFormat(cpulist, priv->nbNodeCpus);
    }

done:
    VIR_FREE(cpulist);
    VIR_FREE(cpumap);
    VIR_FREE(cpuinfo);
    return res;
}

#ifdef WITH_LIBVIRTD

static int
xenInitialize (int privileged ATTRIBUTE_UNUSED)
{
    inside_daemon = 1;
    return 0;
}

static virStateDriver state_driver = {
    .name = "Xen",
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
    int fd;

    if ((fd = open("/dev/xen/domcaps", O_RDONLY)) >= 0) {
        VIR_FORCE_CLOSE(fd);
        return 1;
    }
#endif
    return 0;
}

#ifdef WITH_LIBXL
static int
xenUnifiedXendProbe (void)
{
    virCommandPtr cmd;
    int status;
    int ret = 0;

    cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
    if (virCommandRun(cmd, &status) == 0 && status == 0)
        ret = 1;
    virCommandFree(cmd);

    return ret;
}
#endif



static virDrvOpenStatus
xenUnifiedOpen (virConnectPtr conn, virConnectAuthPtr auth, unsigned int flags)
{
    int i, ret = VIR_DRV_OPEN_DECLINED;
    xenUnifiedPrivatePtr priv;

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

        if (!(conn->uri = virURIParse("xen:///")))
            return VIR_DRV_OPEN_ERROR;
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
                xenUnifiedError(VIR_ERR_INTERNAL_ERROR,
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
            return VIR_DRV_OPEN_DECLINED;
        }
    }

#ifdef WITH_LIBXL
    /* Decline xen:// URI if xend is not running and libxenlight
     * driver is potentially available. */
    if (!xenUnifiedXendProbe())
        return VIR_DRV_OPEN_DECLINED;
#endif

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    /* Allocate per-connection private data. */
    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&priv->lock) < 0) {
        xenUnifiedError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("cannot initialize mutex"));
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(priv->domainEvents = virDomainEventStateNew())) {
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = priv;

    priv->handle = -1;
    priv->xendConfigVersion = -1;
    priv->xshandle = NULL;


    /* Hypervisor is only run with privilege & required to succeed */
    if (xenHavePrivilege()) {
        VIR_DEBUG("Trying hypervisor sub-driver");
        if (xenHypervisorOpen(conn, auth, flags) == VIR_DRV_OPEN_SUCCESS) {
            VIR_DEBUG("Activated hypervisor sub-driver");
            priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] = 1;
        }
    }

    /* XenD is required to succeed if privileged */
    VIR_DEBUG("Trying XenD sub-driver");
    if (xenDaemonOpen(conn, auth, flags) == VIR_DRV_OPEN_SUCCESS) {
        VIR_DEBUG("Activated XenD sub-driver");
        priv->opened[XEN_UNIFIED_XEND_OFFSET] = 1;

        /* XenD is active, so try the xm & xs drivers too, both requird to
         * succeed if root, optional otherwise */
        if (priv->xendConfigVersion <= XEND_CONFIG_VERSION_3_0_3) {
            VIR_DEBUG("Trying XM sub-driver");
            if (xenXMOpen(conn, auth, flags) == VIR_DRV_OPEN_SUCCESS) {
                VIR_DEBUG("Activated XM sub-driver");
                priv->opened[XEN_UNIFIED_XM_OFFSET] = 1;
            }
        }
        VIR_DEBUG("Trying XS sub-driver");
        if (xenStoreOpen(conn, auth, flags) == VIR_DRV_OPEN_SUCCESS) {
            VIR_DEBUG("Activated XS sub-driver");
            priv->opened[XEN_UNIFIED_XS_OFFSET] = 1;
        } else {
            if (xenHavePrivilege())
                goto fail; /* XS is mandatory when privileged */
        }
    } else {
        if (xenHavePrivilege()) {
            goto fail; /* XenD is mandatory when privileged */
        } else {
            VIR_DEBUG("Handing off for remote driver");
            ret = VIR_DRV_OPEN_DECLINED; /* Let remote_driver try instead */
            goto clean;
        }
    }

    xenNumaInit(conn);

    if (!(priv->caps = xenHypervisorMakeCapabilities(conn))) {
        VIR_DEBUG("Failed to make capabilities");
        goto fail;
    }

#if WITH_XEN_INOTIFY
    if (xenHavePrivilege()) {
        VIR_DEBUG("Trying Xen inotify sub-driver");
        if (xenInotifyOpen(conn, auth, flags) == VIR_DRV_OPEN_SUCCESS) {
            VIR_DEBUG("Activated Xen inotify sub-driver");
            priv->opened[XEN_UNIFIED_INOTIFY_OFFSET] = 1;
        }
    }
#endif

    return VIR_DRV_OPEN_SUCCESS;

fail:
    ret = VIR_DRV_OPEN_ERROR;
clean:
    VIR_DEBUG("Failed to activate a mandatory sub-driver");
    for (i = 0 ; i < XEN_UNIFIED_NR_DRIVERS ; i++)
        if (priv->opened[i])
            drivers[i]->xenClose(conn);
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
    virDomainEventStateFree(priv->domainEvents);

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i])
            drivers[i]->xenClose(conn);

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
    case VIR_DRV_FEATURE_MIGRATION_V1:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
        return 1;
    default:
        return 0;
    }
}

static int
xenUnifiedGetVersion (virConnectPtr conn, unsigned long *hvVer)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->xenVersion &&
            drivers[i]->xenVersion (conn, hvVer) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
xenUnifiedIsSecure(virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int ret = 1;

    /* All drivers are secure, except for XenD over TCP */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET] &&
        priv->addrfamily != AF_UNIX)
        ret = 0;

    return ret;
}

static int
xenUnifiedIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* XenD reconnects for each request */
    return 1;
}

int
xenUnifiedGetMaxVcpus (virConnectPtr conn, const char *type)
{
    GET_PRIVATE(conn);

    if (type && STRCASENEQ (type, "Xen")) {
        xenUnifiedError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorGetMaxVcpus (conn, type);
    else {
        xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        return -1;
    }
}

static int
xenUnifiedNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info)
{
    GET_PRIVATE(conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonNodeGetInfo(conn, info);
    return -1;
}

static char *
xenUnifiedGetCapabilities (virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    char *xml;

    if (!(xml = virCapabilitiesFormatXML(priv->caps))) {
        virReportOOMError();
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

    return -1;
}

static int
xenUnifiedNumOfDomains (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int ret;

    /* Try xenstore. */
    if (priv->opened[XEN_UNIFIED_XS_OFFSET]) {
        ret = xenStoreNumOfDomains (conn);
        if (ret >= 0) return ret;
    }

    /* Try HV. */
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorNumOfDomains (conn);
        if (ret >= 0) return ret;
    }

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonNumOfDomains (conn);
        if (ret >= 0) return ret;
    }

    return -1;
}

static virDomainPtr
xenUnifiedDomainCreateXML (virConnectPtr conn,
                           const char *xmlDesc, unsigned int flags)
{
    GET_PRIVATE(conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonCreateXML(conn, xmlDesc, flags);
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

    /* Try xend. */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonLookupByID (conn, id);
        if (ret || conn->err.code != VIR_ERR_OK)
            return ret;
    }

    /* Not found. */
    xenUnifiedError(VIR_ERR_NO_DOMAIN, __FUNCTION__);
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
    xenUnifiedError(VIR_ERR_NO_DOMAIN, __FUNCTION__);
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
    xenUnifiedError(VIR_ERR_NO_DOMAIN, __FUNCTION__);
    return NULL;
}


static int
xenUnifiedDomainIsActive(virDomainPtr dom)
{
    virDomainPtr currdom;
    int ret = -1;

    /* ID field in dom may be outdated, so re-lookup */
    currdom = xenUnifiedDomainLookupByUUID(dom->conn, dom->uuid);

    if (currdom) {
        ret = currdom->id == -1 ? 0 : 1;
        virDomainFree(currdom);
    }

    return ret;
}

static int
xenUnifiedDomainIsPersistent(virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    virDomainPtr currdom = NULL;
    int ret = -1;

    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        /* Old Xen, pre-inactive domain management.
         * If the XM driver can see the guest, it is definitely persistent */
        currdom = xenXMDomainLookupByUUID(dom->conn, dom->uuid);
        if (currdom)
            ret = 1;
        else
            ret = 0;
    } else {
        /* New Xen with inactive domain management */
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
            currdom = xenDaemonLookupByUUID(dom->conn, dom->uuid);
            if (currdom) {
                if (currdom->id == -1) {
                    /* If its inactive, then trivially, it must be persistent */
                    ret = 1;
                } else {
                    char *path;
                    char uuidstr[VIR_UUID_STRING_BUFLEN];

                    /* If its running there's no official way to tell, so we
                     * go behind xend's back & look at the config dir */

                    virUUIDFormat(dom->uuid, uuidstr);
                    if (virAsprintf(&path, "%s/%s", XEND_DOMAINS_DIR, uuidstr) < 0) {
                        virReportOOMError();
                        goto done;
                    }
                    if (access(path, R_OK) == 0)
                        ret = 1;
                    else if (errno == ENOENT)
                        ret = 0;
                }
            }
        }
    }

done:
    if (currdom)
        virDomainFree(currdom);

    return ret;
}

static int
xenUnifiedDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
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
            drivers[i]->xenDomainSuspend &&
            drivers[i]->xenDomainSuspend (dom) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        xenHypervisorPauseDomain(dom) == 0)
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
            drivers[i]->xenDomainResume &&
            drivers[i]->xenDomainResume (dom) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        xenHypervisorResumeDomain(dom) == 0)
        return 0;

    return -1;
}

static int
xenUnifiedDomainShutdownFlags(virDomainPtr dom,
                              unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    virCheckFlags(0, -1);

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->xenDomainShutdown &&
            drivers[i]->xenDomainShutdown(dom) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainShutdown(virDomainPtr dom)
{
    return xenUnifiedDomainShutdownFlags(dom, 0);
}

static int
xenUnifiedDomainReboot (virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->xenDomainReboot &&
            drivers[i]->xenDomainReboot (dom, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainDestroyFlags(virDomainPtr dom,
                             unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    virCheckFlags(0, -1);

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (i != XEN_UNIFIED_HYPERVISOR_OFFSET &&
            priv->opened[i] &&
            drivers[i]->xenDomainDestroyFlags &&
            drivers[i]->xenDomainDestroyFlags(dom, flags) == 0)
            return 0;

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] &&
        xenHypervisorDestroyDomainFlags(dom, flags) == 0)
        return 0;

    return -1;
}

static int
xenUnifiedDomainDestroy(virDomainPtr dom)
{
    return xenUnifiedDomainDestroyFlags(dom, 0);
}

static char *
xenUnifiedDomainGetOSType (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;
    char *ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainGetOSType) {
            ret = drivers[i]->xenDomainGetOSType (dom);
            if (ret) return ret;
        }

    return NULL;
}

static unsigned long long
xenUnifiedDomainGetMaxMemory (virDomainPtr dom)
{
    GET_PRIVATE(dom->conn);
    int i;
    unsigned long long ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainGetMaxMemory) {
            ret = drivers[i]->xenDomainGetMaxMemory (dom);
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
            drivers[i]->xenDomainSetMaxMemory &&
            drivers[i]->xenDomainSetMaxMemory (dom, memory) == 0)
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
            drivers[i]->xenDomainSetMemory &&
            drivers[i]->xenDomainSetMemory (dom, memory) == 0)
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
            drivers[i]->xenDomainGetInfo &&
            drivers[i]->xenDomainGetInfo (dom, info) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainGetState(virDomainPtr dom,
                         int *state,
                         int *reason,
                         unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int ret;

    virCheckFlags(0, -1);

    /* trying drivers in the same order as GetInfo for consistent results:
     * hypervisor, xend, xs, and xm */

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET]) {
        ret = xenHypervisorGetDomainState(dom, state, reason, flags);
        if (ret >= 0)
            return ret;
    }

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonDomainGetState(dom, state, reason, flags);
        if (ret >= 0)
            return ret;
    }

    if (priv->opened[XEN_UNIFIED_XS_OFFSET]) {
        ret = xenStoreDomainGetState(dom, state, reason, flags);
        if (ret >= 0)
            return ret;
    }

    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        ret = xenXMDomainGetState(dom, state, reason, flags);
        if (ret >= 0)
            return ret;
    }

    return -1;
}

static int
xenUnifiedDomainSaveFlags(virDomainPtr dom, const char *to, const char *dxml,
                          unsigned int flags)
{
    GET_PRIVATE(dom->conn);

    virCheckFlags(0, -1);
    if (dxml) {
        xenUnifiedError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("xml modification unsupported"));
        return -1;
    }

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainSave(dom, to);
    return -1;
}

static int
xenUnifiedDomainSave(virDomainPtr dom, const char *to)
{
    return xenUnifiedDomainSaveFlags(dom, to, NULL, 0);
}

static int
xenUnifiedDomainRestoreFlags(virConnectPtr conn, const char *from,
                             const char *dxml, unsigned int flags)
{
    GET_PRIVATE(conn);

    virCheckFlags(0, -1);
    if (dxml) {
        xenUnifiedError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                        _("xml modification unsupported"));
        return -1;
    }

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainRestore(conn, from);
    return -1;
}

static int
xenUnifiedDomainRestore (virConnectPtr conn, const char *from)
{
    return xenUnifiedDomainRestoreFlags(conn, from, NULL, 0);
}

static int
xenUnifiedDomainCoreDump (virDomainPtr dom, const char *to, unsigned int flags)
{
    GET_PRIVATE(dom->conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainCoreDump(dom, to, flags);
    return -1;
}

static int
xenUnifiedDomainSetVcpusFlags (virDomainPtr dom, unsigned int nvcpus,
                               unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int ret;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    /* At least one of LIVE or CONFIG must be set.  MAXIMUM cannot be
     * mixed with LIVE.  */
    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0 ||
        (flags & (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) ==
         (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) {
        xenUnifiedError(VIR_ERR_INVALID_ARG,
                        _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }
    if (!nvcpus || (unsigned short) nvcpus != nvcpus) {
        xenUnifiedError(VIR_ERR_INVALID_ARG,
                        _("argument out of range: %d"), nvcpus);
        return -1;
    }

    /* Try non-hypervisor methods first, then hypervisor direct method
     * as a last resort.
     */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonDomainSetVcpusFlags(dom, nvcpus, flags);
        if (ret != -2)
            return ret;
    }
    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        ret = xenXMDomainSetVcpusFlags(dom, nvcpus, flags);
        if (ret != -2)
            return ret;
    }
    if (flags == VIR_DOMAIN_VCPU_LIVE)
        return xenHypervisorSetVcpus(dom, nvcpus);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainSetVcpus (virDomainPtr dom, unsigned int nvcpus)
{
    unsigned int flags = VIR_DOMAIN_VCPU_LIVE;
    xenUnifiedPrivatePtr priv;

    /* Per the documented API, it is hypervisor-dependent whether this
     * affects just _LIVE or _LIVE|_CONFIG; in xen's case, that
     * depends on xendConfigVersion.  */
    if (dom) {
        priv = dom->conn->privateData;
        if (priv->xendConfigVersion >= XEND_CONFIG_VERSION_3_0_4)
            flags |= VIR_DOMAIN_VCPU_CONFIG;
    }
    return xenUnifiedDomainSetVcpusFlags(dom, nvcpus, flags);
}

static int
xenUnifiedDomainPinVcpu (virDomainPtr dom, unsigned int vcpu,
                         unsigned char *cpumap, int maplen)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] &&
            drivers[i]->xenDomainPinVcpu &&
            drivers[i]->xenDomainPinVcpu (dom, vcpu, cpumap, maplen) == 0)
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
        if (priv->opened[i] && drivers[i]->xenDomainGetVcpus) {
            ret = drivers[i]->xenDomainGetVcpus (dom, info, maxinfo, cpumaps, maplen);
            if (ret > 0)
                return ret;
        }
    return -1;
}

static int
xenUnifiedDomainGetVcpusFlags (virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int ret;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        ret = xenDaemonDomainGetVcpusFlags(dom, flags);
        if (ret != -2)
            return ret;
    }
    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        ret = xenXMDomainGetVcpusFlags(dom, flags);
        if (ret != -2)
            return ret;
    }
    if (flags == (VIR_DOMAIN_VCPU_CONFIG | VIR_DOMAIN_VCPU_MAXIMUM))
        return xenHypervisorGetVcpuMax(dom);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainGetMaxVcpus (virDomainPtr dom)
{
    return xenUnifiedDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE |
                                               VIR_DOMAIN_VCPU_MAXIMUM));
}

static char *
xenUnifiedDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);

    if (dom->id == -1 && priv->xendConfigVersion < XEND_CONFIG_VERSION_3_0_4) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainGetXMLDesc(dom, flags);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
            char *cpus, *res;
            xenUnifiedLock(priv);
            cpus = xenDomainUsedCpus(dom);
            xenUnifiedUnlock(priv);
            res = xenDaemonDomainGetXMLDesc(dom, flags, cpus);
            VIR_FREE(cpus);
            return res;
        }
    }

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return NULL;
}


static char *
xenUnifiedDomainXMLFromNative(virConnectPtr conn,
                              const char *format,
                              const char *config,
                              unsigned int flags)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    virConfPtr conf = NULL;
    int id;
    char * tty;
    int vncport;
    GET_PRIVATE(conn);

    virCheckFlags(0, NULL);

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        xenUnifiedError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        return NULL;
    }

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        conf = virConfReadMem(config, strlen(config), 0);
        if (!conf)
            goto cleanup;

        def = xenParseXM(conf, priv->xendConfigVersion, priv->caps);
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        id = xenGetDomIdFromSxprString(config, priv->xendConfigVersion);
        xenUnifiedLock(priv);
        tty = xenStoreDomainGetConsolePath(conn, id);
        vncport = xenStoreDomainGetVNCPort(conn, id);
        xenUnifiedUnlock(priv);
        def = xenParseSxprString(config, priv->xendConfigVersion, tty,
                                       vncport);
    }
    if (!def)
        goto cleanup;

    ret = virDomainDefFormat(def, 0);

cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return ret;
}


#define MAX_CONFIG_SIZE (1024 * 65)
static char *
xenUnifiedDomainXMLToNative(virConnectPtr conn,
                            const char *format,
                            const char *xmlData,
                            unsigned int flags)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    virConfPtr conf = NULL;
    GET_PRIVATE(conn);

    virCheckFlags(0, NULL);

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        xenUnifiedError(VIR_ERR_INVALID_ARG,
                        _("unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(def = virDomainDefParseString(priv->caps, xmlData,
                                        1 << VIR_DOMAIN_VIRT_XEN, 0)))
        goto cleanup;

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        int len = MAX_CONFIG_SIZE;
        conf = xenFormatXM(conn, def, priv->xendConfigVersion);
        if (!conf)
            goto cleanup;

        if (VIR_ALLOC_N(ret, len) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virConfWriteMem(ret, &len, conf) < 0) {
            VIR_FREE(ret);
            goto cleanup;
        }
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        ret = xenFormatSxpr(conn, def, priv->xendConfigVersion);
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

    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainMigratePrepare (dconn, cookie, cookielen,
                                              uri_in, uri_out,
                                              flags, dname, resource);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonDomainMigratePerform (dom, cookie, cookielen, uri,
                                              flags, dname, resource);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static virDomainPtr
xenUnifiedDomainMigrateFinish (virConnectPtr dconn,
                               const char *dname,
                               const char *cookie ATTRIBUTE_UNUSED,
                               int cookielen ATTRIBUTE_UNUSED,
                               const char *uri ATTRIBUTE_UNUSED,
                               unsigned long flags)
{
    virDomainPtr dom = NULL;
    char *domain_xml = NULL;
    virDomainPtr dom_new = NULL;

    virCheckFlags(XEN_MIGRATION_FLAGS, NULL);

    dom = xenUnifiedDomainLookupByName (dconn, dname);
    if (! dom) {
        return NULL;
    }

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        domain_xml = xenDaemonDomainGetXMLDesc(dom, 0, NULL);
        if (! domain_xml) {
            xenUnifiedError(VIR_ERR_MIGRATE_PERSIST_FAILED,
                            "%s", _("failed to get XML representation of migrated domain"));
            goto failure;
        }

        dom_new = xenDaemonDomainDefineXML (dconn, domain_xml);
        if (! dom_new) {
            xenUnifiedError(VIR_ERR_MIGRATE_PERSIST_FAILED,
                            "%s", _("failed to define domain on destination host"));
            goto failure;
        }

        /* Free additional reference added by Define */
        virDomainFree (dom_new);
    }

    VIR_FREE (domain_xml);

    return dom;


failure:
    virDomainFree (dom);

    VIR_FREE (domain_xml);

    return NULL;
}

static int
xenUnifiedListDefinedDomains (virConnectPtr conn, char **const names,
                              int maxnames)
{
    GET_PRIVATE(conn);
    int i;
    int ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenListDefinedDomains) {
            ret = drivers[i]->xenListDefinedDomains (conn, names, maxnames);
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
        if (priv->opened[i] && drivers[i]->xenNumOfDefinedDomains) {
            ret = drivers[i]->xenNumOfDefinedDomains (conn);
            if (ret >= 0) return ret;
        }

    return -1;
}

static int
xenUnifiedDomainCreateWithFlags (virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    virCheckFlags(0, -1);

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainCreate &&
            drivers[i]->xenDomainCreate (dom) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainCreate (virDomainPtr dom)
{
    return xenUnifiedDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
xenUnifiedDomainDefineXML (virConnectPtr conn, const char *xml)
{
    GET_PRIVATE(conn);
    int i;
    virDomainPtr ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainDefineXML) {
            ret = drivers[i]->xenDomainDefineXML (conn, xml);
            if (ret) return ret;
        }

    return NULL;
}

static int
xenUnifiedDomainUndefineFlags (virDomainPtr dom, unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    virCheckFlags(0, -1);
    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainUndefine &&
            drivers[i]->xenDomainUndefine (dom) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainUndefine (virDomainPtr dom) {
    return xenUnifiedDomainUndefineFlags(dom, 0);
}

static int
xenUnifiedDomainAttachDevice (virDomainPtr dom, const char *xml)
{
    GET_PRIVATE(dom->conn);
    int i;
    unsigned int flags = VIR_DOMAIN_DEVICE_MODIFY_LIVE;

    /*
     * HACK: xend with xendConfigVersion >= 3 does not support changing live
     * config without touching persistent config, we add the extra flag here
     * to make this API work
     */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET] &&
        priv->xendConfigVersion >= XEND_CONFIG_VERSION_3_0_4)
        flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainAttachDeviceFlags &&
            drivers[i]->xenDomainAttachDeviceFlags(dom, xml, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainAttachDeviceFlags (virDomainPtr dom, const char *xml,
                                   unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainAttachDeviceFlags &&
            drivers[i]->xenDomainAttachDeviceFlags(dom, xml, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainDetachDevice (virDomainPtr dom, const char *xml)
{
    GET_PRIVATE(dom->conn);
    int i;
    unsigned int flags = VIR_DOMAIN_DEVICE_MODIFY_LIVE;

    /*
     * HACK: xend with xendConfigVersion >= 3 does not support changing live
     * config without touching persistent config, we add the extra flag here
     * to make this API work
     */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET] &&
        priv->xendConfigVersion >= XEND_CONFIG_VERSION_3_0_4)
        flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainDetachDeviceFlags &&
            drivers[i]->xenDomainDetachDeviceFlags(dom, xml, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainDetachDeviceFlags (virDomainPtr dom, const char *xml,
                                   unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->xenDomainDetachDeviceFlags &&
            drivers[i]->xenDomainDetachDeviceFlags(dom, xml, flags) == 0)
            return 0;

    return -1;
}

static int
xenUnifiedDomainUpdateDeviceFlags (virDomainPtr dom, const char *xml,
                                   unsigned int flags)
{
    GET_PRIVATE(dom->conn);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        return xenDaemonUpdateDeviceFlags(dom, xml, flags);
    return -1;
}

static int
xenUnifiedDomainGetAutostart (virDomainPtr dom, int *autostart)
{
    GET_PRIVATE(dom->conn);

    if (priv->xendConfigVersion < XEND_CONFIG_VERSION_3_0_4) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainGetAutostart(dom, autostart);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
            return xenDaemonDomainGetAutostart(dom, autostart);
    }

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainSetAutostart (virDomainPtr dom, int autostart)
{
    GET_PRIVATE(dom->conn);

    if (priv->xendConfigVersion < XEND_CONFIG_VERSION_3_0_4) {
        if (priv->opened[XEN_UNIFIED_XM_OFFSET])
            return xenXMDomainSetAutostart(dom, autostart);
    } else {
        if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
            return xenDaemonDomainSetAutostart(dom, autostart);
    }

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static char *
xenUnifiedDomainGetSchedulerType (virDomainPtr dom, int *nparams)
{
    GET_PRIVATE(dom->conn);
    int i;
    char *schedulertype;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; i++) {
        if (priv->opened[i] && drivers[i]->xenDomainGetSchedulerType) {
            schedulertype = drivers[i]->xenDomainGetSchedulerType (dom, nparams);
            if (schedulertype != NULL)
                return schedulertype;
        }
    }
    return NULL;
}

static int
xenUnifiedDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                            virTypedParameterPtr params,
                                            int *nparams,
                                            unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    virCheckFlags(0, -1);

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i) {
        if (priv->opened[i] && drivers[i]->xenDomainGetSchedulerParameters) {
           ret = drivers[i]->xenDomainGetSchedulerParameters(dom, params, nparams);
           if (ret == 0)
               return 0;
        }
    }
    return -1;
}

static int
xenUnifiedDomainGetSchedulerParameters(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int *nparams)
{
    return xenUnifiedDomainGetSchedulerParametersFlags(dom, params,
                                                       nparams, 0);
}

static int
xenUnifiedDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                            virTypedParameterPtr params,
                                            int nparams,
                                            unsigned int flags)
{
    GET_PRIVATE(dom->conn);
    int i, ret;

    virCheckFlags(0, -1);

    /* do the hypervisor call last to get better error */
    for (i = XEN_UNIFIED_NR_DRIVERS - 1; i >= 0; i--) {
        if (priv->opened[i] && drivers[i]->xenDomainSetSchedulerParameters) {
           ret = drivers[i]->xenDomainSetSchedulerParameters(dom, params, nparams);
           if (ret == 0)
               return 0;
        }
    }

    return -1;
}

static int
xenUnifiedDomainSetSchedulerParameters(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int nparams)
{
    return xenUnifiedDomainSetSchedulerParametersFlags(dom, params,
                                                       nparams, 0);
}

static int
xenUnifiedDomainBlockStats (virDomainPtr dom, const char *path,
                            struct _virDomainBlockStats *stats)
{
    GET_PRIVATE (dom->conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorDomainBlockStats (dom, path, stats);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainInterfaceStats (virDomainPtr dom, const char *path,
                                struct _virDomainInterfaceStats *stats)
{
    GET_PRIVATE (dom->conn);

    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        return xenHypervisorDomainInterfaceStats (dom, path, stats);

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return -1;
}

static int
xenUnifiedDomainBlockPeek (virDomainPtr dom, const char *path,
                           unsigned long long offset, size_t size,
                           void *buffer, unsigned int flags)
{
    int r;
    GET_PRIVATE (dom->conn);

    virCheckFlags(0, -1);

    if (priv->opened[XEN_UNIFIED_XEND_OFFSET]) {
        r = xenDaemonDomainBlockPeek (dom, path, offset, size, buffer);
        if (r != -2) return r;
        /* r == -2 means declined, so fall through to XM driver ... */
    }

    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        if (xenXMDomainBlockPeek (dom, path, offset, size, buffer) == 0)
            return 0;
    }

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
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
            return 0;
        return freeMem;
    }

    xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
    return 0;
}


static int
xenUnifiedDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback callback,
                              void *opaque,
                              virFreeCallback freefunc)
{
    GET_PRIVATE (conn);

    int ret;
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    ret = virDomainEventStateRegister(conn, priv->domainEvents,
                                      callback, opaque, freefunc);

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback callback)
{
    int ret;
    GET_PRIVATE (conn);
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    ret = virDomainEventStateDeregister(conn,
                                        priv->domainEvents,
                                        callback);

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedDomainEventRegisterAny(virConnectPtr conn,
                                 virDomainPtr dom,
                                 int eventID,
                                 virConnectDomainEventGenericCallback callback,
                                 void *opaque,
                                 virFreeCallback freefunc)
{
    GET_PRIVATE (conn);

    int ret;
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (virDomainEventStateRegisterID(conn, priv->domainEvents,
                                      dom, eventID,
                                      callback, opaque, freefunc, &ret) < 0)
        ret = -1;

    xenUnifiedUnlock(priv);
    return ret;
}

static int
xenUnifiedDomainEventDeregisterAny(virConnectPtr conn,
                                   int callbackID)
{
    int ret;
    GET_PRIVATE (conn);
    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        xenUnifiedError(VIR_ERR_NO_SUPPORT, __FUNCTION__);
        xenUnifiedUnlock(priv);
        return -1;
    }

    ret = virDomainEventStateDeregisterID(conn,
                                          priv->domainEvents,
                                          callbackID);

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

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
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
        xenUnifiedError(VIR_ERR_INVALID_ARG,
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

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciDettachDevice(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(pci);
    return ret;
}

static int
xenUnifiedNodeDeviceAssignedDomainId (virNodeDevicePtr dev)
{
    int numdomains;
    int ret = -1, i;
    int *ids = NULL;
    char *bdf = NULL;
    char *xref = NULL;
    unsigned int domain, bus, slot, function;
    virConnectPtr conn = dev->conn;
    xenUnifiedPrivatePtr priv = conn->privateData;

    /* Get active domains */
    numdomains = xenUnifiedNumOfDomains(conn);
    if (numdomains < 0) {
        return ret;
    }
    if (numdomains > 0){
        if (VIR_ALLOC_N(ids, numdomains) < 0) {
            virReportOOMError();
            goto out;
        }
        if ((numdomains = xenUnifiedListDomains(conn, &ids[0], numdomains)) < 0) {
            goto out;
        }
    }

    /* Get pci bdf */
    if (xenUnifiedNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        goto out;

    if (virAsprintf(&bdf, "%04x:%02x:%02x.%0x",
                    domain, bus, slot, function) < 0) {
        virReportOOMError();
        goto out;
    }

    xenUnifiedLock(priv);
    /* Check if bdf is assigned to one of active domains */
    for (i = 0; i < numdomains; i++ ) {
        xref = xenStoreDomainGetPCIID(conn, ids[i], bdf);
        if (xref == NULL) {
            continue;
        } else {
            ret = ids[i];
            break;
        }
    }
    xenUnifiedUnlock(priv);

    VIR_FREE(xref);
    VIR_FREE(bdf);
out:
    VIR_FREE(ids);

    return ret;
}

static int
xenUnifiedNodeDeviceReAttach (virNodeDevicePtr dev)
{
    pciDevice *pci;
    unsigned domain, bus, slot, function;
    int ret = -1;
    int domid;

    if (xenUnifiedNodeDeviceGetPciInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    /* Check if device is assigned to an active guest */
    if ((domid = xenUnifiedNodeDeviceAssignedDomainId(dev)) >= 0) {
        xenUnifiedError(VIR_ERR_INTERNAL_ERROR,
                        _("Device %s has been assigned to guest %d"),
                        dev->name, domid);
        goto out;
    }

    if (pciReAttachDevice(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(pci);
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

    pci = pciGetDevice(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (pciResetDevice(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
out:
    pciFreeDevice(pci);
    return ret;
}


static int
xenUnifiedDomainOpenConsole(virDomainPtr dom,
                            const char *dev_name,
                            virStreamPtr st,
                            unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;
    virDomainChrDefPtr chr = NULL;

    virCheckFlags(0, -1);

    if (dom->id == -1) {
        xenUnifiedError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("domain is not running"));
        goto cleanup;
    }

    if (dev_name) {
        /* XXX support device aliases in future */
        xenUnifiedError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("Named device aliases are not supported"));
        goto cleanup;
    }

    def = xenDaemonDomainFetch(dom->conn, dom->id, dom->name, NULL);
    if (!def)
        goto cleanup;

    if (def->nconsoles)
        chr = def->consoles[0];
    else if (def->nserials)
        chr = def->serials[0];

    if (!chr) {
        xenUnifiedError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot find default console device"));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        xenUnifiedError(VIR_ERR_INTERNAL_ERROR,
                        _("character device %s is not using a PTY"), dev_name);
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virDomainDefFree(def);
    return ret;
}
/*----- Register with libvirt.c, and initialize Xen drivers. -----*/

/* The interface which we export upwards to libvirt.c. */
static virDriver xenUnifiedDriver = {
    .no = VIR_DRV_XEN_UNIFIED,
    .name = "Xen",
    .open = xenUnifiedOpen, /* 0.0.3 */
    .close = xenUnifiedClose, /* 0.0.3 */
    .supports_feature = xenUnifiedSupportsFeature, /* 0.3.2 */
    .type = xenUnifiedType, /* 0.0.3 */
    .version = xenUnifiedGetVersion, /* 0.0.3 */
    .getHostname = virGetHostname, /* 0.7.3 */
    .getMaxVcpus = xenUnifiedGetMaxVcpus, /* 0.2.1 */
    .nodeGetInfo = xenUnifiedNodeGetInfo, /* 0.1.0 */
    .getCapabilities = xenUnifiedGetCapabilities, /* 0.2.1 */
    .listDomains = xenUnifiedListDomains, /* 0.0.3 */
    .numOfDomains = xenUnifiedNumOfDomains, /* 0.0.3 */
    .domainCreateXML = xenUnifiedDomainCreateXML, /* 0.0.3 */
    .domainLookupByID = xenUnifiedDomainLookupByID, /* 0.0.3 */
    .domainLookupByUUID = xenUnifiedDomainLookupByUUID, /* 0.0.5 */
    .domainLookupByName = xenUnifiedDomainLookupByName, /* 0.0.3 */
    .domainSuspend = xenUnifiedDomainSuspend, /* 0.0.3 */
    .domainResume = xenUnifiedDomainResume, /* 0.0.3 */
    .domainShutdown = xenUnifiedDomainShutdown, /* 0.0.3 */
    .domainShutdownFlags = xenUnifiedDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = xenUnifiedDomainReboot, /* 0.1.0 */
    .domainDestroy = xenUnifiedDomainDestroy, /* 0.0.3 */
    .domainDestroyFlags = xenUnifiedDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = xenUnifiedDomainGetOSType, /* 0.0.3 */
    .domainGetMaxMemory = xenUnifiedDomainGetMaxMemory, /* 0.0.3 */
    .domainSetMaxMemory = xenUnifiedDomainSetMaxMemory, /* 0.0.3 */
    .domainSetMemory = xenUnifiedDomainSetMemory, /* 0.1.1 */
    .domainGetInfo = xenUnifiedDomainGetInfo, /* 0.0.3 */
    .domainGetState = xenUnifiedDomainGetState, /* 0.9.2 */
    .domainSave = xenUnifiedDomainSave, /* 0.0.3 */
    .domainSaveFlags = xenUnifiedDomainSaveFlags, /* 0.9.4 */
    .domainRestore = xenUnifiedDomainRestore, /* 0.0.3 */
    .domainRestoreFlags = xenUnifiedDomainRestoreFlags, /* 0.9.4 */
    .domainCoreDump = xenUnifiedDomainCoreDump, /* 0.1.9 */
    .domainSetVcpus = xenUnifiedDomainSetVcpus, /* 0.1.4 */
    .domainSetVcpusFlags = xenUnifiedDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = xenUnifiedDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = xenUnifiedDomainPinVcpu, /* 0.1.4 */
    .domainGetVcpus = xenUnifiedDomainGetVcpus, /* 0.1.4 */
    .domainGetMaxVcpus = xenUnifiedDomainGetMaxVcpus, /* 0.2.1 */
    .domainGetXMLDesc = xenUnifiedDomainGetXMLDesc, /* 0.0.3 */
    .domainXMLFromNative = xenUnifiedDomainXMLFromNative, /* 0.6.4 */
    .domainXMLToNative = xenUnifiedDomainXMLToNative, /* 0.6.4 */
    .listDefinedDomains = xenUnifiedListDefinedDomains, /* 0.1.1 */
    .numOfDefinedDomains = xenUnifiedNumOfDefinedDomains, /* 0.1.5 */
    .domainCreate = xenUnifiedDomainCreate, /* 0.1.1 */
    .domainCreateWithFlags = xenUnifiedDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = xenUnifiedDomainDefineXML, /* 0.1.1 */
    .domainUndefine = xenUnifiedDomainUndefine, /* 0.1.1 */
    .domainUndefineFlags = xenUnifiedDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = xenUnifiedDomainAttachDevice, /* 0.1.9 */
    .domainAttachDeviceFlags = xenUnifiedDomainAttachDeviceFlags, /* 0.7.7 */
    .domainDetachDevice = xenUnifiedDomainDetachDevice, /* 0.1.9 */
    .domainDetachDeviceFlags = xenUnifiedDomainDetachDeviceFlags, /* 0.7.7 */
    .domainUpdateDeviceFlags = xenUnifiedDomainUpdateDeviceFlags, /* 0.8.0 */
    .domainGetAutostart = xenUnifiedDomainGetAutostart, /* 0.4.4 */
    .domainSetAutostart = xenUnifiedDomainSetAutostart, /* 0.4.4 */
    .domainGetSchedulerType = xenUnifiedDomainGetSchedulerType, /* 0.2.3 */
    .domainGetSchedulerParameters = xenUnifiedDomainGetSchedulerParameters, /* 0.2.3 */
    .domainGetSchedulerParametersFlags = xenUnifiedDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = xenUnifiedDomainSetSchedulerParameters, /* 0.2.3 */
    .domainSetSchedulerParametersFlags = xenUnifiedDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainMigratePrepare = xenUnifiedDomainMigratePrepare, /* 0.3.2 */
    .domainMigratePerform = xenUnifiedDomainMigratePerform, /* 0.3.2 */
    .domainMigrateFinish = xenUnifiedDomainMigrateFinish, /* 0.3.2 */
    .domainBlockStats = xenUnifiedDomainBlockStats, /* 0.3.2 */
    .domainInterfaceStats = xenUnifiedDomainInterfaceStats, /* 0.3.2 */
    .domainBlockPeek = xenUnifiedDomainBlockPeek, /* 0.4.4 */
    .nodeGetCellsFreeMemory = xenUnifiedNodeGetCellsFreeMemory, /* 0.3.3 */
    .nodeGetFreeMemory = xenUnifiedNodeGetFreeMemory, /* 0.3.3 */
    .domainEventRegister = xenUnifiedDomainEventRegister, /* 0.5.0 */
    .domainEventDeregister = xenUnifiedDomainEventDeregister, /* 0.5.0 */
    .nodeDeviceDettach = xenUnifiedNodeDeviceDettach, /* 0.6.1 */
    .nodeDeviceReAttach = xenUnifiedNodeDeviceReAttach, /* 0.6.1 */
    .nodeDeviceReset = xenUnifiedNodeDeviceReset, /* 0.6.1 */
    .isEncrypted = xenUnifiedIsEncrypted, /* 0.7.3 */
    .isSecure = xenUnifiedIsSecure, /* 0.7.3 */
    .domainIsActive = xenUnifiedDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = xenUnifiedDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = xenUnifiedDomainIsUpdated, /* 0.8.6 */
    .domainEventRegisterAny = xenUnifiedDomainEventRegisterAny, /* 0.8.0 */
    .domainEventDeregisterAny = xenUnifiedDomainEventDeregisterAny, /* 0.8.0 */
    .domainOpenConsole = xenUnifiedDomainOpenConsole, /* 0.8.6 */
    .isAlive = xenUnifiedIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = nodeSuspendForDuration, /* 0.9.8 */
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
    (void) xenHypervisorInit (NULL);

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
    VIR_FREE(list->doms);
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
            VIR_DEBUG("WARNING: dom already tracked");
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
    virReportOOMError();
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

    virDomainEventStateQueue(priv->domainEvents, event);
}

void xenUnifiedLock(xenUnifiedPrivatePtr priv)
{
    virMutexLock(&priv->lock);
}

void xenUnifiedUnlock(xenUnifiedPrivatePtr priv)
{
    virMutexUnlock(&priv->lock);
}
