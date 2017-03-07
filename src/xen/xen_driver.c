/*
 * xen_driver.c: Unified Xen driver.
 *
 * Copyright (C) 2007-2015 Red Hat, Inc.
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

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "xen_driver.h"

#include "xen_sxpr.h"
#include "xen_xm.h"
#include "xen_common.h"
#include "xen_hypervisor.h"
#include "xend_internal.h"
#include "xs_internal.h"
#include "xm_internal.h"
#if WITH_XEN_INOTIFY
# include "xen_inotify.h"
#endif
#include "virxml.h"
#include "viralloc.h"
#include "node_device_conf.h"
#include "virpci.h"
#include "viruuid.h"
#include "virfdstream.h"
#include "virfile.h"
#include "viruri.h"
#include "vircommand.h"
#include "virnodesuspend.h"
#include "virhostmem.h"
#include "configmake.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_XEN

VIR_LOG_INIT("xen.xen_driver");

#define XEN_SAVE_DIR LOCALSTATEDIR "/lib/libvirt/xen/save"

static int
xenUnifiedNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);

static int
xenUnifiedDomainGetVcpusFlagsInternal(virDomainPtr dom,
                                      virDomainDefPtr def,
                                      unsigned int flags);

static int
xenUnifiedDomainGetVcpusInternal(virDomainPtr dom,
                                 virDomainDefPtr def,
                                 virVcpuInfoPtr info,
                                 int maxinfo,
                                 unsigned char *cpumaps,
                                 int maplen);


static bool is_privileged;
static virSysinfoDefPtr hostsysinfo;

static virDomainDefPtr xenGetDomainDefForID(virConnectPtr conn, int id)
{
    virDomainDefPtr ret;

    ret = xenHypervisorLookupDomainByID(conn, id);

    if (!ret && virGetLastError() == NULL)
        virReportError(VIR_ERR_NO_DOMAIN, __FUNCTION__);

    return ret;
}


static virDomainDefPtr xenGetDomainDefForName(virConnectPtr conn, const char *name)
{
    virDomainDefPtr ret;

    ret = xenDaemonLookupByName(conn, name);

    if (!ret && virGetLastError() == NULL)
        virReportError(VIR_ERR_NO_DOMAIN, __FUNCTION__);

    return ret;
}


static virDomainDefPtr xenGetDomainDefForUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virDomainDefPtr ret;

    ret = xenHypervisorLookupDomainByUUID(conn, uuid);

    /* Try xend for inactive domains. */
    if (!ret)
        ret = xenDaemonLookupByUUID(conn, uuid);

    if (!ret && virGetLastError() == NULL)
        virReportError(VIR_ERR_NO_DOMAIN, __FUNCTION__);

    return ret;
}


static virDomainDefPtr xenGetDomainDefForDom(virDomainPtr dom)
{
    /* UUID lookup is more efficient than name lookup */
    return xenGetDomainDefForUUID(dom->conn, dom->uuid);
}


/**
 * xenNumaInit:
 * @conn: pointer to the hypervisor connection
 *
 * Initializer for previous variables. We currently assume that
 * the number of physical CPU and the number of NUMA cell is fixed
 * until reboot which might be false in future Xen implementations.
 */
static void
xenNumaInit(virConnectPtr conn)
{
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
 * @def: the domain definition
 *
 * Analyze which set of CPUs are used by the domain and
 * return a string providing the ranges.
 *
 * Returns the string which needs to be freed by the caller or
 *         NULL if the domain uses all CPU or in case of error.
 */
char *
xenDomainUsedCpus(virDomainPtr dom, virDomainDefPtr def)
{
    char *res = NULL;
    int ncpus;
    int nb_vcpu;
    virBitmapPtr cpulist = NULL;
    unsigned char *cpumap = NULL;
    size_t cpumaplen;
    int nb = 0;
    int n, m;
    virVcpuInfoPtr cpuinfo = NULL;
    virNodeInfo nodeinfo;
    xenUnifiedPrivatePtr priv;

    priv = dom->conn->privateData;

    if (priv->nbNodeCpus <= 0)
        return NULL;
    nb_vcpu = xenUnifiedDomainGetVcpusFlagsInternal(dom, def,
                                                    (VIR_DOMAIN_VCPU_LIVE |
                                                     VIR_DOMAIN_VCPU_MAXIMUM));
    if (nb_vcpu <= 0)
        return NULL;
    if (xenUnifiedNodeGetInfo(dom->conn, &nodeinfo) < 0)
        return NULL;

    if (!(cpulist = virBitmapNew(priv->nbNodeCpus)))
        goto done;
    if (VIR_ALLOC_N(cpuinfo, nb_vcpu) < 0)
        goto done;
    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    if (xalloc_oversized(nb_vcpu, cpumaplen) ||
        VIR_ALLOC_N(cpumap, nb_vcpu * cpumaplen) < 0)
        goto done;

    if ((ncpus = xenUnifiedDomainGetVcpusInternal(dom, def, cpuinfo, nb_vcpu,
                                                  cpumap, cpumaplen)) >= 0) {
        for (n = 0; n < ncpus; n++) {
            for (m = 0; m < priv->nbNodeCpus; m++) {
                if (!virBitmapIsBitSet(cpulist, m) &&
                    (VIR_CPU_USABLE(cpumap, cpumaplen, n, m))) {
                    ignore_value(virBitmapSetBit(cpulist, m));
                    nb++;
                    /* if all CPU are used just return NULL */
                    if (nb == priv->nbNodeCpus)
                        goto done;

                }
            }
        }
        res = virBitmapFormat(cpulist);
    }

 done:
    virBitmapFree(cpulist);
    VIR_FREE(cpumap);
    VIR_FREE(cpuinfo);
    return res;
}

static int
xenUnifiedStateInitialize(bool privileged,
                          virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                          void *opaque ATTRIBUTE_UNUSED)
{
    /* Don't allow driver to work in non-root libvirtd */
    if (privileged) {
        is_privileged = true;
        hostsysinfo = virSysinfoRead();
    }

    return 0;
}

static int
xenUnifiedStateCleanup(void)
{
    virSysinfoDefFree(hostsysinfo);
    return 0;
}

static virStateDriver state_driver = {
    .name = "Xen",
    .stateInitialize = xenUnifiedStateInitialize,
    .stateCleanup = xenUnifiedStateCleanup,
};

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
xenUnifiedProbe(void)
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
static bool
xenUnifiedXendProbe(void)
{
    bool ret = false;

    if (virFileExists("/usr/sbin/xend")) {
        virCommandPtr cmd;

        cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
        if (virCommandRun(cmd, NULL) == 0)
            ret = true;
        virCommandFree(cmd);
    }

    return ret;
}
#endif


static int
xenDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                            const virDomainDef *def,
                            virCapsPtr caps ATTRIBUTE_UNUSED,
                            unsigned int parseFlags ATTRIBUTE_UNUSED,
                            void *opaque ATTRIBUTE_UNUSED,
                            void *parseOpaque ATTRIBUTE_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        dev->data.chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
        def->os.type != VIR_DOMAIN_OSTYPE_HVM)
        dev->data.chr->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;

    /* forbid capabilities mode hostdev in this kind of hypervisor */
    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode 'capabilities' is not "
                         "supported in %s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO && dev->data.video->vram == 0) {
        switch (dev->data.video->type) {
        case VIR_DOMAIN_VIDEO_TYPE_VGA:
        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
        case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
            dev->data.video->vram = 16 * 1024;
        break;

        case VIR_DOMAIN_VIDEO_TYPE_XEN:
            /* Original Xen PVFB hardcoded to 4 MB */
            dev->data.video->vram = 4 * 1024;
            break;

        case VIR_DOMAIN_VIDEO_TYPE_QXL:
            /* Use 64M as the minimal video video memory for qxl device */
            return 64 * 1024;
        }
    }

    return 0;
}


static int
xenDomainDefPostParse(virDomainDefPtr def,
                      virCapsPtr caps ATTRIBUTE_UNUSED,
                      unsigned int parseFlags ATTRIBUTE_UNUSED,
                      void *opaque ATTRIBUTE_UNUSED,
                      void *parseOpaque ATTRIBUTE_UNUSED)
{
    if (!def->memballoon) {
        virDomainMemballoonDefPtr memballoon;
        if (VIR_ALLOC(memballoon) < 0)
            return -1;

        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_XEN;
        def->memballoon = memballoon;
    }

    /* add implicit input device */
    if (xenDomainDefAddImplicitInputDevice(def) <0)
        return -1;

    return 0;
}


virDomainDefParserConfig xenDomainDefParserConfig = {
    .macPrefix = { 0x00, 0x16, 0x3e },
    .devicesPostParseCallback = xenDomainDeviceDefPostParse,
    .domainPostParseCallback = xenDomainDefPostParse,
};


virDomainXMLOptionPtr
xenDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(&xenDomainDefParserConfig,
                                 NULL, NULL);
}


static virDrvOpenStatus
xenUnifiedConnectOpen(virConnectPtr conn, virConnectAuthPtr auth,
                      virConfPtr conf ATTRIBUTE_UNUSED,
                      unsigned int flags)
{
    xenUnifiedPrivatePtr priv;

    /*
     * Only the libvirtd instance can open this driver.
     * Everything else falls back to the remote driver.
     */
    if (!is_privileged)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri == NULL) {
        if (!xenUnifiedProbe())
            return VIR_DRV_OPEN_DECLINED;

#ifdef WITH_LIBXL
        /* Decline xen:// URI if xend is not running and libxenlight
         * driver is potentially available. */
        if (!xenUnifiedXendProbe())
            return VIR_DRV_OPEN_DECLINED;
#endif

        if (!(conn->uri = virURIParse("xen:///")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        if (conn->uri->scheme) {
            /* Decline any scheme which isn't "xen://" or "http://". */
            if (STRCASENEQ(conn->uri->scheme, "xen") &&
                STRCASENEQ(conn->uri->scheme, "http"))
                return VIR_DRV_OPEN_DECLINED;

#ifdef WITH_LIBXL
            /* Decline xen:// URI if xend is not running and libxenlight
             * driver is potentially available. */
            if (!xenUnifiedXendProbe())
                return VIR_DRV_OPEN_DECLINED;
#endif

            /* Return an error if the path isn't '' or '/' */
            if (conn->uri->path &&
                STRNEQ(conn->uri->path, "") &&
                STRNEQ(conn->uri->path, "/")) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    /* Allocate per-connection private data. */
    if (VIR_ALLOC(priv) < 0)
        return VIR_DRV_OPEN_ERROR;
    if (virMutexInit(&priv->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(priv->domainEvents = virObjectEventStateNew())) {
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = priv;

    priv->handle = -1;
    priv->xshandle = NULL;


    /* Hypervisor required to succeed */
    VIR_DEBUG("Trying hypervisor sub-driver");
    if (xenHypervisorOpen(conn, auth, flags) < 0)
        goto error;
    VIR_DEBUG("Activated hypervisor sub-driver");
    priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET] = 1;

    /* XenD is required to succeed */
    VIR_DEBUG("Trying XenD sub-driver");
    if (xenDaemonOpen(conn, auth, flags) < 0)
        goto error;
    VIR_DEBUG("Activated XenD sub-driver");
    priv->opened[XEN_UNIFIED_XEND_OFFSET] = 1;

    VIR_DEBUG("Trying XS sub-driver");
    if (xenStoreOpen(conn, auth, flags) < 0)
        goto error;
    VIR_DEBUG("Activated XS sub-driver");
    priv->opened[XEN_UNIFIED_XS_OFFSET] = 1;

    xenNumaInit(conn);

    if (!(priv->caps = xenHypervisorMakeCapabilities(conn))) {
        VIR_DEBUG("Failed to make capabilities");
        goto error;
    }

    if (!(priv->xmlopt = xenDomainXMLConfInit()))
        goto error;

#if WITH_XEN_INOTIFY
    VIR_DEBUG("Trying Xen inotify sub-driver");
    if (xenInotifyOpen(conn, auth, flags) < 0)
        goto error;
    VIR_DEBUG("Activated Xen inotify sub-driver");
    priv->opened[XEN_UNIFIED_INOTIFY_OFFSET] = 1;
#endif

    if (VIR_STRDUP(priv->saveDir, XEN_SAVE_DIR) < 0)
        goto error;

    if (virFileMakePath(priv->saveDir) < 0) {
        virReportSystemError(errno, _("Errored to create save dir '%s'"),
                             priv->saveDir);
        goto error;
    }

    return VIR_DRV_OPEN_SUCCESS;

 error:
    VIR_DEBUG("Failed to activate a mandatory sub-driver");
#if WITH_XEN_INOTIFY
    if (priv->opened[XEN_UNIFIED_INOTIFY_OFFSET])
        xenInotifyClose(conn);
#endif
    if (priv->opened[XEN_UNIFIED_XM_OFFSET])
        xenXMClose(conn);
    if (priv->opened[XEN_UNIFIED_XS_OFFSET])
        xenStoreClose(conn);
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        xenDaemonClose(conn);
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        xenHypervisorClose(conn);
    virMutexDestroy(&priv->lock);
    VIR_FREE(priv->saveDir);
    VIR_FREE(priv);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}

static int
xenUnifiedConnectClose(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    virObjectUnref(priv->caps);
    virObjectUnref(priv->xmlopt);
    virObjectUnref(priv->domainEvents);

#if WITH_XEN_INOTIFY
    if (priv->opened[XEN_UNIFIED_INOTIFY_OFFSET])
        xenInotifyClose(conn);
#endif
    if (priv->opened[XEN_UNIFIED_XM_OFFSET])
        xenXMClose(conn);
    if (priv->opened[XEN_UNIFIED_XS_OFFSET])
        xenStoreClose(conn);
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET])
        xenDaemonClose(conn);
    if (priv->opened[XEN_UNIFIED_HYPERVISOR_OFFSET])
        xenHypervisorClose(conn);

    VIR_FREE(priv->saveDir);
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
xenUnifiedConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "Xen";
}

/* Which features are supported by this driver? */
static int
xenUnifiedConnectSupportsFeature(virConnectPtr conn, int feature)
{
    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    switch (feature) {
    case VIR_DRV_FEATURE_MIGRATION_V1:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
        return 1;
    default:
        return 0;
    }
}

static int
xenUnifiedConnectGetVersion(virConnectPtr conn, unsigned long *hvVer)
{
    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    return xenHypervisorGetVersion(conn, hvVer);
}


static char *xenUnifiedConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static char *
xenUnifiedConnectGetSysinfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                            unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, hostsysinfo) < 0)
        return NULL;
    if (virBufferCheckError(&buf) < 0)
        return NULL;
    return virBufferContentAndReset(&buf);
}

static int
xenUnifiedConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
xenUnifiedConnectIsSecure(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret = 1;

    /* All drivers are secure, except for XenD over TCP */
    if (priv->opened[XEN_UNIFIED_XEND_OFFSET] &&
        priv->addrfamily != AF_UNIX)
        ret = 0;

    return ret;
}

static int
xenUnifiedConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* XenD reconnects for each request */
    return 1;
}

int
xenUnifiedConnectGetMaxVcpus(virConnectPtr conn, const char *type)
{
    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    if (type && STRCASENEQ(type, "Xen")) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    return xenHypervisorGetMaxVcpus(conn, type);
}

static int
xenUnifiedNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return xenDaemonNodeGetInfo(conn, info);
}

static char *
xenUnifiedConnectGetCapabilities(virConnectPtr conn)
{
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    return virCapabilitiesFormatXML(priv->caps);
}

static int
xenUnifiedConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return xenStoreListDomains(conn, ids, maxids);
}

static int
xenUnifiedConnectNumOfDomains(virConnectPtr conn)
{
    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return xenStoreNumOfDomains(conn);
}

static virDomainPtr
xenUnifiedDomainCreateXML(virConnectPtr conn,
                          const char *xml,
                          unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainPtr ret = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, priv->caps, priv->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (xenDaemonCreateXML(conn, def) < 0)
        goto cleanup;

    ret = virGetDomain(conn, def->name, def->uuid);
    if (ret)
        ret->id = def->id;

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static virDomainPtr
xenUnifiedDomainLookupByID(virConnectPtr conn, int id)
{
    virDomainPtr ret = NULL;
    virDomainDefPtr def = NULL;

    if (!(def = xenGetDomainDefForID(conn, id)))
        goto cleanup;

    if (virDomainLookupByIDEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(ret = virGetDomain(conn, def->name, def->uuid)))
        goto cleanup;

    ret->id = def->id;

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static virDomainPtr
xenUnifiedDomainLookupByUUID(virConnectPtr conn,
                             const unsigned char *uuid)
{
    virDomainPtr ret = NULL;
    virDomainDefPtr def = NULL;

    if (!(def = xenGetDomainDefForUUID(conn, uuid)))
        goto cleanup;

    if (virDomainLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(ret = virGetDomain(conn, def->name, def->uuid)))
        goto cleanup;

    ret->id = def->id;

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static virDomainPtr
xenUnifiedDomainLookupByName(virConnectPtr conn,
                             const char *name)
{
    virDomainPtr ret = NULL;
    virDomainDefPtr def = NULL;

    if (!(def = xenGetDomainDefForName(conn, name)))
        goto cleanup;

    if (virDomainLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(ret = virGetDomain(conn, def->name, def->uuid)))
        goto cleanup;

    ret->id = def->id;

 cleanup:
    virDomainDefFree(def);
    return ret;
}


static int
xenUnifiedDomainIsActive(virDomainPtr dom)
{
    virDomainDefPtr def;
    int ret = -1;

    if (!(def = xenGetDomainDefForUUID(dom->conn, dom->uuid)))
        goto cleanup;

    ret = def->id == -1 ? 0 : 1;

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainIsPersistent(virDomainPtr dom)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (priv->opened[XEN_UNIFIED_XM_OFFSET]) {
        /* Old Xen, pre-inactive domain management.
         * If the XM driver can see the guest, it is definitely persistent */
        def = xenXMDomainLookupByUUID(dom->conn, dom->uuid);
        if (def)
            ret = 1;
        else
            ret = 0;
    } else {
        /* New Xen with inactive domain management */
        def = xenDaemonLookupByUUID(dom->conn, dom->uuid);
        if (def) {
            if (def->id == -1) {
                /* If its inactive, then trivially, it must be persistent */
                ret = 1;
            } else {
                char *path;
                char uuidstr[VIR_UUID_STRING_BUFLEN];

                /* If its running there's no official way to tell, so we
                 * go behind xend's back & look at the config dir */
                virUUIDFormat(dom->uuid, uuidstr);
                if (virAsprintf(&path, "%s/%s", XEND_DOMAINS_DIR, uuidstr) < 0)
                    goto cleanup;
                if (access(path, R_OK) == 0)
                    ret = 1;
                else if (errno == ENOENT)
                    ret = 0;
            }
        }
    }

 cleanup:
    virDomainDefFree(def);

    return ret;
}

static int
xenUnifiedDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
}

static int
xenUnifiedDomainSuspend(virDomainPtr dom)
{
    int ret = -1;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSuspendEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainSuspend(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainResume(virDomainPtr dom)
{
    int ret = -1;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainResumeEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainResume(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainShutdownFlags(virDomainPtr dom,
                              unsigned int flags)
{
    int ret = -1;
    virDomainDefPtr def;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonDomainShutdown(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainShutdown(virDomainPtr dom)
{
    return xenUnifiedDomainShutdownFlags(dom, 0);
}

static int
xenUnifiedDomainReboot(virDomainPtr dom, unsigned int flags)
{
    int ret = -1;
    virDomainDefPtr def;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainRebootEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonDomainReboot(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainDestroyFlags(virDomainPtr dom,
                             unsigned int flags)
{
    int ret = -1;
    virDomainDefPtr def;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainDestroy(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainDestroy(virDomainPtr dom)
{
    return xenUnifiedDomainDestroyFlags(dom, 0);
}

static char *
xenUnifiedDomainGetOSType(virDomainPtr dom)
{
    char *ret = NULL;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (def->id < 0)
        ret = xenDaemonDomainGetOSType(dom->conn, def);
    else
        ret = xenHypervisorDomainGetOSType(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}


static unsigned long long
xenUnifiedDomainGetMaxMemory(virDomainPtr dom)
{
    unsigned long long ret = 0;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (def->id < 0)
        ret = xenDaemonDomainGetMaxMemory(dom->conn, def);
    else
        ret = xenHypervisorGetMaxMemory(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    int ret = -1;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSetMaxMemoryEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (def->id < 0)
        ret = xenDaemonDomainSetMaxMemory(dom->conn, def, memory);
    else
        ret = xenHypervisorSetMaxMemory(dom->conn, def, memory);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSetMemory(virDomainPtr dom, unsigned long memory)
{
    int ret = -1;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSetMemoryEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainSetMemory(dom->conn, def, memory);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    int ret = -1;
    virDomainDefPtr def;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (def->id < 0)
        ret = xenDaemonDomainGetInfo(dom->conn, def, info);
    else
        ret = xenHypervisorGetDomainInfo(dom->conn, def, info);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetState(virDomainPtr dom,
                         int *state,
                         int *reason,
                         unsigned int flags)
{

    int ret = -1;
    virDomainDefPtr def;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (def->id < 0)
        ret = xenDaemonDomainGetState(dom->conn, def, state, reason);
    else
        ret = xenHypervisorGetDomainState(dom->conn, def, state, reason);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSaveFlags(virDomainPtr dom, const char *to, const char *dxml,
                          unsigned int flags)
{
    int ret = -1;
    virDomainDefPtr def;

    virCheckFlags(0, -1);

    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSaveFlagsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainSave(dom->conn, def, to);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSave(virDomainPtr dom, const char *to)
{
    return xenUnifiedDomainSaveFlags(dom, to, NULL, 0);
}

static char *
xenUnifiedDomainManagedSavePath(xenUnifiedPrivatePtr priv,
                                virDomainDefPtr def)
{
    char *ret;

    if (virAsprintf(&ret, "%s/%s.save", priv->saveDir, def->name) < 0)
        return NULL;

    VIR_DEBUG("managed save image: %s", ret);
    return ret;
}

static int
xenUnifiedDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    char *name = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainManagedSaveEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (!(name = xenUnifiedDomainManagedSavePath(priv, def)))
        goto cleanup;

    ret = xenDaemonDomainSave(dom->conn, def, name);

 cleanup:
    VIR_FREE(name);
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    char *name = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (!(name = xenUnifiedDomainManagedSavePath(priv, def)))
        goto cleanup;

    ret = virFileExists(name);

 cleanup:
    VIR_FREE(name);
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    char *name = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (!(name = xenUnifiedDomainManagedSavePath(priv, def)))
        goto cleanup;

    ret = unlink(name);

 cleanup:
    VIR_FREE(name);
    return ret;
}

static int
xenUnifiedDomainRestoreFlags(virConnectPtr conn, const char *from,
                             const char *dxml, unsigned int flags)
{
    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    return xenDaemonDomainRestore(conn, from);
}

static int
xenUnifiedDomainRestore(virConnectPtr conn, const char *from)
{
    return xenUnifiedDomainRestoreFlags(conn, from, NULL, 0);
}

static int
xenUnifiedDomainCoreDump(virDomainPtr dom, const char *to, unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainCoreDumpEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainCoreDump(dom->conn, def, to, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                              unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    /* At least one of LIVE or CONFIG must be set.  MAXIMUM cannot be
     * mixed with LIVE.  */
    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0 ||
        (flags & (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) ==
         (VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }
    if (!nvcpus || (unsigned short) nvcpus != nvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("argument out of range: %d"), nvcpus);
        return -1;
    }

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonDomainSetVcpusFlags(dom->conn, def, nvcpus, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    unsigned int flags;

    /* Per the documented API, it is hypervisor-dependent whether this
     * affects just _LIVE or _LIVE|_CONFIG; in xen's case, both are
     * affected. */
    flags = VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG;

    return xenUnifiedDomainSetVcpusFlags(dom, nvcpus, flags);
}

static int
xenUnifiedDomainPinVcpu(virDomainPtr dom, unsigned int vcpu,
                        unsigned char *cpumap, int maplen)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainPinVcpuEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (dom->id < 0)
        ret = xenDaemonDomainPinVcpu(dom->conn, def, vcpu, cpumap, maplen);
    else
        ret = xenHypervisorPinVcpu(dom->conn, def, vcpu, cpumap, maplen);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetVcpusInternal(virDomainPtr dom,
                                 virDomainDefPtr def,
                                 virVcpuInfoPtr info,
                                 int maxinfo,
                                 unsigned char *cpumaps,
                                 int maplen)
{
    int ret = -1;

    if (dom->id < 0) {
        ret = xenDaemonDomainGetVcpus(dom->conn, def, info, maxinfo,
                                      cpumaps, maplen);
    } else {
        ret = xenHypervisorGetVcpus(dom->conn, def, info, maxinfo, cpumaps,
                                    maplen);
    }

    return ret;
}

static int
xenUnifiedDomainGetVcpus(virDomainPtr dom,
                         virVcpuInfoPtr info, int maxinfo,
                         unsigned char *cpumaps, int maplen)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetVcpusEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenUnifiedDomainGetVcpusInternal(dom, def, info, maxinfo, cpumaps,
                                           maplen);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetVcpusFlagsInternal(virDomainPtr dom,
                                      virDomainDefPtr def,
                                      unsigned int flags)
{
    int ret = -1;

    if (dom->id < 0) {
        ret = xenDaemonDomainGetVcpusFlags(dom->conn, def, flags);
    } else {
        if (flags == (VIR_DOMAIN_VCPU_CONFIG | VIR_DOMAIN_VCPU_MAXIMUM))
            ret = xenHypervisorGetVcpuMax(dom->conn, def);
        else
            ret = xenDaemonDomainGetVcpusFlags(dom->conn, def, flags);
    }

   return ret;
}

static int
xenUnifiedDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenUnifiedDomainGetVcpusFlagsInternal(dom, def, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetMaxVcpus(virDomainPtr dom)
{
    return xenUnifiedDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_LIVE |
                                               VIR_DOMAIN_VCPU_MAXIMUM));
}

static char *
xenUnifiedDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    virDomainDefPtr minidef = NULL;
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    char *cpus = NULL;

    if (!(minidef = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, minidef, flags) < 0)
        goto cleanup;

    xenUnifiedLock(priv);
    cpus = xenDomainUsedCpus(dom, minidef);
    xenUnifiedUnlock(priv);
    def = xenDaemonDomainGetXMLDesc(dom->conn, minidef, cpus);

    if (def)
        ret = virDomainDefFormat(def, priv->caps,
                                 virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    VIR_FREE(cpus);
    virDomainDefFree(def);
    virDomainDefFree(minidef);
    return ret;
}


static char *
xenUnifiedConnectDomainXMLFromNative(virConnectPtr conn,
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
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), format);
        return NULL;
    }

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        conf = virConfReadMem(config, strlen(config), 0);
        if (!conf)
            goto cleanup;

        def = xenParseXM(conf, priv->caps, priv->xmlopt);
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        if (xenGetDomIdFromSxprString(config, &id) < 0)
            goto cleanup;
        xenUnifiedLock(priv);
        tty = xenStoreDomainGetConsolePath(conn, id);
        vncport = xenStoreDomainGetVNCPort(conn, id);
        xenUnifiedUnlock(priv);
        def = xenParseSxprString(config, tty,
                                 vncport, priv->caps, priv->xmlopt);
    }
    if (!def)
        goto cleanup;

    ret = virDomainDefFormat(def, priv->caps, 0);

 cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return ret;
}


#define MAX_CONFIG_SIZE (1024 * 65)
static char *
xenUnifiedConnectDomainXMLToNative(virConnectPtr conn,
                                   const char *format,
                                   const char *xmlData,
                                   unsigned int flags)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;
    virConfPtr conf = NULL;
    xenUnifiedPrivatePtr priv = conn->privateData;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(format, XEN_CONFIG_FORMAT_XM) &&
        STRNEQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), format);
        goto cleanup;
    }

    if (!(def = virDomainDefParseString(xmlData, priv->caps, priv->xmlopt,
                                        NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (STREQ(format, XEN_CONFIG_FORMAT_XM)) {
        int len = MAX_CONFIG_SIZE;
        conf = xenFormatXM(conn, def);
        if (!conf)
            goto cleanup;

        if (VIR_ALLOC_N(ret, len) < 0)
            goto cleanup;

        if (virConfWriteMem(ret, &len, conf) < 0) {
            VIR_FREE(ret);
            goto cleanup;
        }
    } else if (STREQ(format, XEN_CONFIG_FORMAT_SEXPR)) {
        ret = xenFormatSxpr(conn, def);
    }

 cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    return ret;
}


static int
xenUnifiedDomainMigratePrepare(virConnectPtr dconn,
                               char **cookie,
                               int *cookielen,
                               const char *uri_in,
                               char **uri_out,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource)
{
    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    return xenDaemonDomainMigratePrepare(dconn, cookie, cookielen,
                                         uri_in, uri_out,
                                         flags, dname, resource);
}

static int
xenUnifiedDomainMigratePerform(virDomainPtr dom,
                               const char *cookie,
                               int cookielen,
                               const char *uri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(XEN_MIGRATION_FLAGS, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainMigratePerformEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainMigratePerform(dom->conn, def,
                                        cookie, cookielen, uri,
                                        flags, dname, resource);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static virDomainPtr
xenUnifiedDomainMigrateFinish(virConnectPtr dconn,
                              const char *dname,
                              const char *cookie ATTRIBUTE_UNUSED,
                              int cookielen ATTRIBUTE_UNUSED,
                              const char *uri ATTRIBUTE_UNUSED,
                              unsigned long flags)
{
    virDomainPtr ret = NULL;
    virDomainDefPtr minidef = NULL;
    virDomainDefPtr def = NULL;

    virCheckFlags(XEN_MIGRATION_FLAGS, NULL);

    if (!(minidef = xenGetDomainDefForName(dconn, dname)))
        goto cleanup;

    if (virDomainMigrateFinishEnsureACL(dconn, minidef) < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        if (!(def = xenDaemonDomainGetXMLDesc(dconn, minidef, NULL)))
            goto cleanup;

        if (xenDaemonDomainDefineXML(dconn, def) < 0)
            goto cleanup;
    }

    ret = virGetDomain(dconn, minidef->name, minidef->uuid);
    if (ret)
        ret->id = minidef->id;

 cleanup:
    virDomainDefFree(def);
    virDomainDefFree(minidef);
    return ret;
}

static int
xenUnifiedConnectListDefinedDomains(virConnectPtr conn, char **const names,
                                    int maxnames)
{
    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return xenDaemonListDefinedDomains(conn, names, maxnames);
}

static int
xenUnifiedConnectNumOfDefinedDomains(virConnectPtr conn)
{
    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return xenDaemonNumOfDefinedDomains(conn);
}

static int
xenUnifiedDomainCreateWithFlags(virDomainPtr dom, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = dom->conn->privateData;
    int ret = -1;
    virDomainDefPtr def = NULL;
    char *name = NULL;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (!(name = xenUnifiedDomainManagedSavePath(priv, def)))
        goto cleanup;

    if (virFileExists(name)) {
        ret = xenDaemonDomainRestore(dom->conn, name);
        if (ret == 0)
            unlink(name);
        goto cleanup;
    }

    ret = xenDaemonDomainCreate(dom->conn, def);

    if (ret >= 0)
        dom->id = def->id;

 cleanup:
    virDomainDefFree(def);
    VIR_FREE(name);
    return ret;
}

static int
xenUnifiedDomainCreate(virDomainPtr dom)
{
    return xenUnifiedDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
xenUnifiedDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainPtr ret = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, priv->caps, priv->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (xenDaemonDomainDefineXML(conn, def) < 0)
        goto cleanup;
    ret = virGetDomain(conn, def->name, def->uuid);

    if (ret)
        ret->id = -1;

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static virDomainPtr
xenUnifiedDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return xenUnifiedDomainDefineXMLFlags(conn, xml, 0);
}

static int
xenUnifiedDomainUndefineFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainUndefine(dom->conn, def);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainUndefine(virDomainPtr dom)
{
    return xenUnifiedDomainUndefineFlags(dom, 0);
}

static int
xenUnifiedDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    unsigned int flags = VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    virDomainDefPtr def = NULL;
    int ret = -1;

    /*
     * HACK: xend does not support changing live config without also touching
     * persistent config. We add the extra flag here to make this API work
     */
    flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainAttachDeviceEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonAttachDeviceFlags(dom->conn, def, xml, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                                  unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonAttachDeviceFlags(dom->conn, def, xml, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    unsigned int flags = VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    virDomainDefPtr def = NULL;
    int ret = -1;

    /*
     * HACK: xend does not support changing live config without also touching
     * persistent config. We add the extra flag here to make this API work
     */
    flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainDetachDeviceEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDetachDeviceFlags(dom->conn, def, xml, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                                  unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonDetachDeviceFlags(dom->conn, def, xml, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                                  unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    ret = xenDaemonUpdateDeviceFlags(dom->conn, def, xml, flags);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainGetAutostart(dom->conn, def, autostart);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainSetAutostart(virDomainPtr dom, int autostart)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainSetAutostart(dom->conn, def, autostart);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static char *
xenUnifiedDomainGetSchedulerType(virDomainPtr dom, int *nparams)
{
    virDomainDefPtr def = NULL;
    char *ret = NULL;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (dom->id < 0)
        ret = xenDaemonGetSchedulerType(dom->conn, nparams);
    else
        ret = xenHypervisorGetSchedulerType(dom->conn, nparams);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                            virTypedParameterPtr params,
                                            int *nparams,
                                            unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    if (dom->id < 0)
        ret = xenDaemonGetSchedulerParameters(dom->conn, def, params, nparams);
    else
        ret = xenHypervisorGetSchedulerParameters(dom->conn, def, params, nparams);

 cleanup:
    virDomainDefFree(def);
    return ret;
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
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, def, flags) < 0)
        goto cleanup;

    if (dom->id < 0)
        ret = xenDaemonSetSchedulerParameters(dom->conn, def, params, nparams);
    else
        ret = xenHypervisorSetSchedulerParameters(dom->conn, def, params, nparams);

 cleanup:
    virDomainDefFree(def);
    return ret;
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
xenUnifiedDomainBlockStats(virDomainPtr dom, const char *path,
                           virDomainBlockStatsPtr stats)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainBlockStatsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenHypervisorDomainBlockStats(dom->conn, def, path, stats);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainInterfaceStats(virDomainPtr dom, const char *path,
                               virDomainInterfaceStatsPtr stats)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenHypervisorDomainInterfaceStats(def, path, stats);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedDomainBlockPeek(virDomainPtr dom, const char *path,
                          unsigned long long offset, size_t size,
                          void *buffer, unsigned int flags)
{
    virDomainDefPtr def = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(def = xenGetDomainDefForDom(dom)))
        goto cleanup;

    if (virDomainBlockPeekEnsureACL(dom->conn, def) < 0)
        goto cleanup;

    ret = xenDaemonDomainBlockPeek(dom->conn, def, path, offset, size, buffer);

 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedNodeGetCellsFreeMemory(virConnectPtr conn, unsigned long long *freeMems,
                                 int startCell, int maxCells)
{
    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return 0;

    return xenHypervisorNodeGetCellsFreeMemory(conn, freeMems,
                                               startCell, maxCells);
}

static unsigned long long
xenUnifiedNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMem = 0;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (xenHypervisorNodeGetCellsFreeMemory(conn, &freeMem, -1, 1) < 0)
        return 0;
    return freeMem;
}


static int
xenUnifiedConnectDomainEventRegister(virConnectPtr conn,
                                     virConnectDomainEventCallback callback,
                                     void *opaque,
                                     virFreeCallback freefunc)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret = 0;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        virReportUnsupportedError();
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (virDomainEventStateRegister(conn, priv->domainEvents,
                                    callback, opaque, freefunc) < 0)
        ret = -1;

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedConnectDomainEventDeregister(virConnectPtr conn,
                                       virConnectDomainEventCallback callback)
{
    int ret = 0;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        virReportUnsupportedError();
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (virDomainEventStateDeregister(conn,
                                      priv->domainEvents,
                                      callback) < 0)
        ret = -1;

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedConnectDomainEventRegisterAny(virConnectPtr conn,
                                        virDomainPtr dom,
                                        int eventID,
                                        virConnectDomainEventGenericCallback callback,
                                        void *opaque,
                                        virFreeCallback freefunc)
{
    xenUnifiedPrivatePtr priv = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        virReportUnsupportedError();
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
xenUnifiedConnectDomainEventDeregisterAny(virConnectPtr conn,
                                          int callbackID)
{
    int ret = 0;
    xenUnifiedPrivatePtr priv = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    xenUnifiedLock(priv);

    if (priv->xsWatch == -1) {
        virReportUnsupportedError();
        xenUnifiedUnlock(priv);
        return -1;
    }

    if (virObjectEventStateDeregisterID(conn,
                                        priv->domainEvents,
                                        callbackID) < 0)
        ret = -1;

    xenUnifiedUnlock(priv);
    return ret;
}


static int
xenUnifiedNodeDeviceGetPCIInfo(virNodeDevicePtr dev,
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
        if (cap->data.type == VIR_NODE_DEV_CAP_PCI_DEV) {
            *domain   = cap->data.pci_dev.domain;
            *bus      = cap->data.pci_dev.bus;
            *slot     = cap->data.pci_dev.slot;
            *function = cap->data.pci_dev.function;
            break;
        }

        cap = cap->next;
    }

    if (!cap) {
        virReportError(VIR_ERR_INVALID_ARG,
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
xenUnifiedNodeDeviceDetachFlags(virNodeDevicePtr dev,
                                const char *driverName,
                                unsigned int flags)
{
    virPCIDevicePtr pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    virCheckFlags(0, -1);

    if (xenUnifiedNodeDeviceGetPCIInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (!driverName) {
        virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_XEN);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown driver name '%s'"), driverName);
        goto out;
    }

    if (virPCIDeviceDetach(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
 out:
    virPCIDeviceFree(pci);
    return ret;
}

static int
xenUnifiedNodeDeviceDettach(virNodeDevicePtr dev)
{
    return xenUnifiedNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
xenUnifiedNodeDeviceAssignedDomainId(virNodeDevicePtr dev)
{
    int numdomains;
    int ret = -1;
    size_t i;
    int *ids = NULL;
    char *bdf = NULL;
    char *xref = NULL;
    unsigned int domain, bus, slot, function;
    virConnectPtr conn = dev->conn;
    xenUnifiedPrivatePtr priv = conn->privateData;

    /* Get active domains */
    numdomains = xenUnifiedConnectNumOfDomains(conn);
    if (numdomains < 0)
        return ret;
    if (numdomains > 0) {
        if (VIR_ALLOC_N(ids, numdomains) < 0)
            goto out;
        if ((numdomains = xenUnifiedConnectListDomains(conn, &ids[0], numdomains)) < 0)
            goto out;
    }

    /* Get pci bdf */
    if (xenUnifiedNodeDeviceGetPCIInfo(dev, &domain, &bus, &slot, &function) < 0)
        goto out;

    if (virAsprintf(&bdf, "%04x:%02x:%02x.%0x",
                    domain, bus, slot, function) < 0)
        goto out;

    xenUnifiedLock(priv);
    /* Check if bdf is assigned to one of active domains */
    for (i = 0; i < numdomains; i++) {
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
xenUnifiedNodeDeviceReAttach(virNodeDevicePtr dev)
{
    virPCIDevicePtr pci;
    unsigned domain, bus, slot, function;
    int ret = -1;
    int domid;

    if (xenUnifiedNodeDeviceGetPCIInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        return -1;

    /* Check if device is assigned to an active guest */
    if ((domid = xenUnifiedNodeDeviceAssignedDomainId(dev)) >= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %s has been assigned to guest %d"),
                       dev->name, domid);
        goto out;
    }

    if (virPCIDeviceReattach(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
 out:
    virPCIDeviceFree(pci);
    return ret;
}

static int
xenUnifiedNodeDeviceReset(virNodeDevicePtr dev)
{
    virPCIDevicePtr pci;
    unsigned domain, bus, slot, function;
    int ret = -1;

    if (xenUnifiedNodeDeviceGetPCIInfo(dev, &domain, &bus, &slot, &function) < 0)
        return -1;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        return -1;

    if (virPCIDeviceReset(pci, NULL, NULL) < 0)
        goto out;

    ret = 0;
 out:
    virPCIDeviceFree(pci);
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
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (dev_name) {
        /* XXX support device aliases in future */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find default console device"));
        goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"),
                       dev_name ? dev_name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source->data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virDomainDefFree(def);
    return ret;
}

static int
xenUnifiedNodeGetMemoryParameters(virConnectPtr conn,
                                  virTypedParameterPtr params,
                                  int *nparams,
                                  unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetParameters(params, nparams, flags);
}


static int
xenUnifiedNodeSetMemoryParameters(virConnectPtr conn,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemSetParameters(params, nparams, flags);
}


static int
xenUnifiedNodeSuspendForDuration(virConnectPtr conn,
                                 unsigned int target,
                                 unsigned long long duration,
                                 unsigned int flags)
{
    if (virNodeSuspendForDurationEnsureACL(conn) < 0)
        return -1;

    return virNodeSuspend(target, duration, flags);
}


/*----- Register with libvirt.c, and initialize Xen drivers. -----*/

/* The interface which we export upwards to libvirt.c. */
static virHypervisorDriver xenUnifiedHypervisorDriver = {
    .name = "Xen",
    .connectOpen = xenUnifiedConnectOpen, /* 0.0.3 */
    .connectClose = xenUnifiedConnectClose, /* 0.0.3 */
    .connectSupportsFeature = xenUnifiedConnectSupportsFeature, /* 0.3.2 */
    .connectGetType = xenUnifiedConnectGetType, /* 0.0.3 */
    .connectGetVersion = xenUnifiedConnectGetVersion, /* 0.0.3 */
    .connectGetHostname = xenUnifiedConnectGetHostname, /* 0.7.3 */
    .connectGetSysinfo = xenUnifiedConnectGetSysinfo, /* 1.1.0 */
    .connectGetMaxVcpus = xenUnifiedConnectGetMaxVcpus, /* 0.2.1 */
    .nodeGetInfo = xenUnifiedNodeGetInfo, /* 0.1.0 */
    .connectGetCapabilities = xenUnifiedConnectGetCapabilities, /* 0.2.1 */
    .connectListDomains = xenUnifiedConnectListDomains, /* 0.0.3 */
    .connectNumOfDomains = xenUnifiedConnectNumOfDomains, /* 0.0.3 */
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
    .domainManagedSave = xenUnifiedDomainManagedSave, /* 1.0.1 */
    .domainHasManagedSaveImage = xenUnifiedDomainHasManagedSaveImage, /* 1.0.1 */
    .domainManagedSaveRemove = xenUnifiedDomainManagedSaveRemove, /* 1.0.1 */
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
    .connectDomainXMLFromNative = xenUnifiedConnectDomainXMLFromNative, /* 0.6.4 */
    .connectDomainXMLToNative = xenUnifiedConnectDomainXMLToNative, /* 0.6.4 */
    .connectListDefinedDomains = xenUnifiedConnectListDefinedDomains, /* 0.1.1 */
    .connectNumOfDefinedDomains = xenUnifiedConnectNumOfDefinedDomains, /* 0.1.5 */
    .domainCreate = xenUnifiedDomainCreate, /* 0.1.1 */
    .domainCreateWithFlags = xenUnifiedDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = xenUnifiedDomainDefineXML, /* 0.1.1 */
    .domainDefineXMLFlags = xenUnifiedDomainDefineXMLFlags, /* 1.2.12 */
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
    .connectDomainEventRegister = xenUnifiedConnectDomainEventRegister, /* 0.5.0 */
    .connectDomainEventDeregister = xenUnifiedConnectDomainEventDeregister, /* 0.5.0 */
    .nodeDeviceDettach = xenUnifiedNodeDeviceDettach, /* 0.6.1 */
    .nodeDeviceDetachFlags = xenUnifiedNodeDeviceDetachFlags, /* 1.0.5 */
    .nodeDeviceReAttach = xenUnifiedNodeDeviceReAttach, /* 0.6.1 */
    .nodeDeviceReset = xenUnifiedNodeDeviceReset, /* 0.6.1 */
    .connectIsEncrypted = xenUnifiedConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = xenUnifiedConnectIsSecure, /* 0.7.3 */
    .domainIsActive = xenUnifiedDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = xenUnifiedDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = xenUnifiedDomainIsUpdated, /* 0.8.6 */
    .connectDomainEventRegisterAny = xenUnifiedConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = xenUnifiedConnectDomainEventDeregisterAny, /* 0.8.0 */
    .domainOpenConsole = xenUnifiedDomainOpenConsole, /* 0.8.6 */
    .connectIsAlive = xenUnifiedConnectIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = xenUnifiedNodeSuspendForDuration, /* 0.9.8 */
    .nodeGetMemoryParameters = xenUnifiedNodeGetMemoryParameters, /* 0.10.2 */
    .nodeSetMemoryParameters = xenUnifiedNodeSetMemoryParameters, /* 0.10.2 */
};


static virConnectDriver xenUnifiedConnectDriver = {
    .hypervisorDriver = &xenUnifiedHypervisorDriver,
};

/**
 * xenRegister:
 *
 * Register xen related drivers
 *
 * Returns the driver priority or -1 in case of error.
 */
int
xenRegister(void)
{
    if (virRegisterStateDriver(&state_driver) == -1) return -1;

    return virRegisterConnectDriver(&xenUnifiedConnectDriver,
                                    true);
}

/**
 * xenUnifiedDomainInfoListFree:
 *
 * Free the Domain Info List
 */
void
xenUnifiedDomainInfoListFree(xenUnifiedDomainInfoListPtr list)
{
    size_t i;

    if (list == NULL)
        return;

    for (i = 0; i < list->count; i++) {
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
    for (n = 0; n < list->count; n++) {
        if (STREQ(list->doms[n]->name, name) &&
            !memcmp(list->doms[n]->uuid, uuid, VIR_UUID_BUFLEN)) {
            VIR_DEBUG("WARNING: dom already tracked");
            return -1;
        }
    }

    if (VIR_ALLOC(info) < 0)
        goto error;
    if (VIR_STRDUP(info->name, name) < 0)
        goto error;

    memcpy(info->uuid, uuid, VIR_UUID_BUFLEN);
    info->id = id;

    /* Make space on list */
    if (VIR_APPEND_ELEMENT(list->doms, list->count, info) < 0)
        goto error;

    return 0;
 error:
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
    size_t i;
    for (i = 0; i < list->count; i++) {
        if (list->doms[i]->id == id &&
            STREQ(list->doms[i]->name, name) &&
            !memcmp(list->doms[i]->uuid, uuid, VIR_UUID_BUFLEN)) {

            VIR_FREE(list->doms[i]->name);
            VIR_FREE(list->doms[i]);

            VIR_DELETE_ELEMENT(list->doms, i, list->count);
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
void xenUnifiedDomainEventDispatch(xenUnifiedPrivatePtr priv,
                                    virObjectEventPtr event)
{
    if (!priv)
        return;

    virObjectEventStateQueue(priv->domainEvents, event);
}

void xenUnifiedLock(xenUnifiedPrivatePtr priv)
{
    virMutexLock(&priv->lock);
}

void xenUnifiedUnlock(xenUnifiedPrivatePtr priv)
{
    virMutexUnlock(&priv->lock);
}
