/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifdef WITH_XEN

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
xenUnifiedOpen (virConnectPtr conn, const char *name, int flags)
{
    int i, j;
    xenUnifiedPrivatePtr priv;
    xmlURIPtr uri;

    uri = xmlParseURI(name);
    if (uri == NULL) {
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Refuse any scheme which isn't "xen://" or "http://". */
    if (uri->scheme &&
        strcasecmp(uri->scheme, "xen") != 0 &&
        strcasecmp(uri->scheme, "http") != 0) {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }

    /* xmlParseURI will parse a naked string like "foo" as a URI with
     * a NULL scheme.  That's not useful for us because we want to only
     * allow full pathnames (eg. ///var/lib/xen/xend-socket).  Decline
     * anything else.
     */
    if (!uri->scheme && name[0] != '/') {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Refuse any xen:// URI with a server specified - allow remote to do it */
    if (uri->scheme && strcasecmp(uri->scheme, "xen") == 0 && uri->server) {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }

    xmlFreeURI(uri);

    /* Allocate per-connection private data. */
    priv = calloc (1, sizeof *priv);
    if (!priv) {
        xenUnifiedError (NULL, VIR_ERR_NO_MEMORY, "allocating private data");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = priv;

    priv->name = strdup (name);
    if (!priv->name) {
        xenUnifiedError (NULL, VIR_ERR_NO_MEMORY, "allocating priv->name");
        free (priv);
        return VIR_DRV_OPEN_ERROR;
    }

    priv->handle = -1;
    priv->xendConfigVersion = -1;
    priv->type = -1;
    priv->len = -1;
    priv->addr = NULL;
    priv->xshandle = NULL;
    priv->proxy = -1;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i) {
        priv->opened[i] = 0;

        /* Only use XM driver for Xen <= 3.0.3 (ie xendConfigVersion <= 2) */
        if (drivers[i] == &xenXMDriver &&
            priv->xendConfigVersion > 2)
            continue;

        /* Ignore proxy for root */
        if (i == XEN_UNIFIED_PROXY_OFFSET && getuid() == 0)
            continue;

        if (drivers[i]->open &&
            drivers[i]->open (conn, name, flags) == VIR_DRV_OPEN_SUCCESS)
            priv->opened[i] = 1;

        /* If as root, then all drivers must succeed.
           If non-root, then only proxy must succeed */
        if (!priv->opened[i] &&
            (getuid() == 0 || i == XEN_UNIFIED_PROXY_OFFSET)) {
            for (j = 0; j < i; ++j)
                if (priv->opened[j]) drivers[j]->close (conn);
            free (priv->name);
            free (priv);
            /* The assumption is that one of the underlying drivers
             * has set virterror already.
             */
            return VIR_DRV_OPEN_ERROR;
        }
    }

    return VIR_DRV_OPEN_SUCCESS;
}

#define GET_PRIVATE(conn) \
    xenUnifiedPrivatePtr priv = (xenUnifiedPrivatePtr) (conn)->privateData

static int
xenUnifiedClose (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->close)
            (void) drivers[i]->close (conn);

    free (priv->name);
    free (conn->privateData);
    conn->privateData = NULL;

    return 0;
}

static const char *
xenUnifiedType (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    int i;
    const char *ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->type) {
            ret = drivers[i]->type (conn);
            if (ret) return ret;
        }

    return NULL;
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

/* The name is recorded (canonicalised) in xenUnifiedOpen. */
static char *
xenUnifiedGetURI (virConnectPtr conn)
{
    GET_PRIVATE(conn);
    char *str;

    str = strdup (priv->name);
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

    if (priv->opened[i] &&
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
    int i;
    char *ret;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainDumpXML) {
            ret = drivers[i]->domainDumpXML (dom, flags);
            if (ret) return ret;
        }

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
xenUnifiedDomainAttachDevice (virDomainPtr dom, char *xml)
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
xenUnifiedDomainDetachDevice (virDomainPtr dom, char *xml)
{
    GET_PRIVATE(dom->conn);
    int i;

    for (i = 0; i < XEN_UNIFIED_NR_DRIVERS; ++i)
        if (priv->opened[i] && drivers[i]->domainDetachDevice &&
            drivers[i]->domainDetachDevice (dom, xml) == 0)
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

/*----- Register with libvirt.c, and initialise Xen drivers. -----*/

#define VERSION ((DOM0_INTERFACE_VERSION >> 24) * 1000000 +         \
                 ((DOM0_INTERFACE_VERSION >> 16) & 0xFF) * 1000 +	\
                 (DOM0_INTERFACE_VERSION & 0xFFFF))

/* The interface which we export upwards to libvirt.c. */
static virDriver xenUnifiedDriver = {
    .no = VIR_DRV_XEN_UNIFIED,
    .name = "Xen",
    .ver = VERSION,
    .open 			= xenUnifiedOpen,
    .close 			= xenUnifiedClose,
    .type 			= xenUnifiedType,
    .version 			= xenUnifiedVersion,
    .getHostname    = xenUnifiedGetHostname,
    .getURI         = xenUnifiedGetURI,
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
    .domainGetSchedulerType	= xenUnifiedDomainGetSchedulerType,
    .domainGetSchedulerParameters	= xenUnifiedDomainGetSchedulerParameters,
    .domainSetSchedulerParameters	= xenUnifiedDomainSetSchedulerParameters,
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
    (void) xenProxyInit ();
    (void) xenDaemonInit ();
    (void) xenStoreInit ();
    (void) xenXMInit ();

    return virRegisterDriver (&xenUnifiedDriver);
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
