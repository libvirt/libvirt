/*
 * libxl_driver.c: core driver methods for managing libxenlight domains
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2011-2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2011 Univention GmbH.
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
 * Authors:
 *     Jim Fehlig <jfehlig@novell.com>
 *     Markus Groß <gross@univention.de>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <math.h>
#include <libxl.h>
#include <libxl_utils.h>
#include <fcntl.h>
#include <regex.h>

#include "internal.h"
#include "virlog.h"
#include "virerror.h"
#include "virconf.h"
#include "datatypes.h"
#include "virfile.h"
#include "viralloc.h"
#include "viruuid.h"
#include "vircommand.h"
#include "libxl_domain.h"
#include "libxl_driver.h"
#include "libxl_conf.h"
#include "xen_xm.h"
#include "xen_sxpr.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "virstring.h"
#include "virsysinfo.h"
#include "viraccessapicheck.h"
#include "viratomic.h"
#include "virhostdev.h"

#define VIR_FROM_THIS VIR_FROM_LIBXL

VIR_LOG_INIT("libxl.libxl_driver");

#define LIBXL_DOM_REQ_POWEROFF 0
#define LIBXL_DOM_REQ_REBOOT   1
#define LIBXL_DOM_REQ_SUSPEND  2
#define LIBXL_DOM_REQ_CRASH    3
#define LIBXL_DOM_REQ_HALT     4

#define LIBXL_CONFIG_FORMAT_XM "xen-xm"
#define LIBXL_CONFIG_FORMAT_SEXPR "xen-sxpr"

#define HYPERVISOR_CAPABILITIES "/proc/xen/capabilities"

/* Number of Xen scheduler parameters */
#define XEN_SCHED_CREDIT_NPARAM   2


static libxlDriverPrivatePtr libxl_driver = NULL;

/* Function declarations */
static int
libxlDomainManagedSaveLoad(virDomainObjPtr vm,
                           void *opaque);


/* Function definitions */
static virDomainObjPtr
libxlDomObjFromDomain(virDomainPtr dom)
{
    virDomainObjPtr vm;
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, dom->uuid);
    if (!vm) {
        virUUIDFormat(dom->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, dom->name);
        return NULL;
    }

    return vm;
}

static int
libxlAutostartDomain(virDomainObjPtr vm,
                     void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    virErrorPtr err;
    int ret = -1;

    virObjectLock(vm);
    virResetLastError();

    if (vm->autostart && !virDomainObjIsActive(vm) &&
        libxlDomainStart(driver, vm, false, -1) < 0) {
        err = virGetLastError();
        VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                  vm->def->name,
                  err ? err->message : _("unknown error"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    return ret;
}

/*
 * Reconnect to running domains that were previously started/created
 * with libxenlight driver.
 */
static int
libxlReconnectDomain(virDomainObjPtr vm,
                     void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    libxlDomainObjPrivatePtr priv = vm->privateData;
    int rc;
    libxl_dominfo d_info;
    int len;
    uint8_t *data = NULL;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virObjectLock(vm);

    libxlDomainObjPrivateInitCtx(vm);
    /* Does domain still exist? */
    rc = libxl_domain_info(priv->ctx, &d_info, vm->def->id);
    if (rc == ERROR_INVAL) {
        goto out;
    } else if (rc != 0) {
        VIR_DEBUG("libxl_domain_info failed (code %d), ignoring domain %d",
                  rc, vm->def->id);
        goto out;
    }

    /* Is this a domain that was under libvirt control? */
    if (libxl_userdata_retrieve(priv->ctx, vm->def->id,
                                "libvirt-xml", &data, &len)) {
        VIR_DEBUG("libxl_userdata_retrieve failed, ignoring domain %d", vm->def->id);
        goto out;
    }

    /* Update domid in case it changed (e.g. reboot) while we were gone? */
    vm->def->id = d_info.domid;

    /* Update hostdev state */
    if (virHostdevUpdateDomainActiveDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                            vm->def, VIR_HOSTDEV_SP_PCI) < 0)
        goto out;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_UNKNOWN);

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    /* Re-register domain death et. al. events */
    libxlDomainEventsRegister(driver, vm);
    virObjectUnlock(vm);
    return 0;

 out:
    libxlDomainCleanup(driver, vm, VIR_DOMAIN_SHUTOFF_UNKNOWN);
    if (!vm->persistent)
        virDomainObjListRemoveLocked(driver->domains, vm);
    else
        virObjectUnlock(vm);

    return -1;
}

static void
libxlReconnectDomains(libxlDriverPrivatePtr driver)
{
    virDomainObjListForEach(driver->domains, libxlReconnectDomain, driver);
}

static int
libxlStateCleanup(void)
{
    if (!libxl_driver)
        return -1;

    virObjectUnref(libxl_driver->hostdevMgr);
    virObjectUnref(libxl_driver->config);
    virObjectUnref(libxl_driver->xmlopt);
    virObjectUnref(libxl_driver->domains);
    virObjectUnref(libxl_driver->reservedVNCPorts);

    virObjectEventStateFree(libxl_driver->domainEventState);
    virSysinfoDefFree(libxl_driver->hostsysinfo);

    virMutexDestroy(&libxl_driver->lock);
    VIR_FREE(libxl_driver);

    return 0;
}

static bool
libxlDriverShouldLoad(bool privileged)
{
    bool ret = false;
    virCommandPtr cmd;
    int status;
    char *output = NULL;

    /* Don't load if non-root */
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling libxenlight driver");
        return ret;
    }

    if (!virFileExists(HYPERVISOR_CAPABILITIES)) {
        VIR_INFO("Disabling driver as " HYPERVISOR_CAPABILITIES
                 " does not exist");
        return false;
    }
    /*
     * Don't load if not running on a Xen control domain (dom0). It is not
     * sufficient to check for the file to exist as any guest can mount
     * xenfs to /proc/xen.
     */
    status = virFileReadAll(HYPERVISOR_CAPABILITIES, 10, &output);
    if (status >= 0) {
        status = strncmp(output, "control_d", 9);
    }
    VIR_FREE(output);
    if (status) {
        VIR_INFO("No Xen capabilities detected, probably not running "
                 "in a Xen Dom0.  Disabling libxenlight driver");

        return ret;
    }

    /* Don't load if legacy xen toolstack (xend) is in use */
    cmd = virCommandNewArgList("/usr/sbin/xend", "status", NULL);
    if (virCommandRun(cmd, &status) == 0 && status == 0) {
        VIR_INFO("Legacy xen tool stack seems to be in use, disabling "
                  "libxenlight driver.");
    } else {
        ret = true;
    }
    virCommandFree(cmd);

    return ret;
}

static int
libxlStateInitialize(bool privileged,
                     virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                     void *opaque ATTRIBUTE_UNUSED)
{
    libxlDriverConfigPtr cfg;
    char ebuf[1024];

    if (!libxlDriverShouldLoad(privileged))
        return 0;

    if (VIR_ALLOC(libxl_driver) < 0)
        return -1;

    if (virMutexInit(&libxl_driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(libxl_driver);
        return -1;
    }

    /* Allocate bitmap for vnc port reservation */
    if (!(libxl_driver->reservedVNCPorts =
          virPortAllocatorNew(_("VNC"),
                              LIBXL_VNC_PORT_MIN,
                              LIBXL_VNC_PORT_MAX)))
        goto error;

    if (!(libxl_driver->domains = virDomainObjListNew()))
        goto error;

    if (!(libxl_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto error;

    if (!(cfg = libxlDriverConfigNew()))
        goto error;

    libxl_driver->config = cfg;
    if (virFileMakePath(cfg->stateDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create state dir '%s': %s"),
                       cfg->stateDir,
                       virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->libDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create lib dir '%s': %s"),
                       cfg->libDir,
                       virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->saveDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create save dir '%s': %s"),
                       cfg->saveDir,
                       virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }
    if (virFileMakePath(cfg->autoDumpDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create dump dir '%s': %s"),
                       cfg->autoDumpDir,
                       virStrerror(errno, ebuf, sizeof(ebuf)));
        goto error;
    }

    /* read the host sysinfo */
    libxl_driver->hostsysinfo = virSysinfoRead();

    libxl_driver->domainEventState = virObjectEventStateNew();
    if (!libxl_driver->domainEventState)
        goto error;

    if ((cfg->caps = libxlMakeCapabilities(cfg->ctx)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot create capabilities for libxenlight"));
        goto error;
    }

    if (!(libxl_driver->xmlopt = virDomainXMLOptionNew(&libxlDomainDefParserConfig,
                                                       &libxlDomainXMLPrivateDataCallbacks,
                                                       NULL)))
        goto error;

    /* Load running domains first. */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       cfg->stateDir,
                                       cfg->autostartDir,
                                       1,
                                       cfg->caps,
                                       libxl_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_XEN,
                                       NULL, NULL) < 0)
        goto error;

    libxlReconnectDomains(libxl_driver);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir,
                                       0,
                                       cfg->caps,
                                       libxl_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_XEN,
                                       NULL, NULL) < 0)
        goto error;

    virDomainObjListForEach(libxl_driver->domains, libxlDomainManagedSaveLoad,
                            libxl_driver);

    return 0;

 error:
    libxlStateCleanup();
    return -1;
}

static void
libxlStateAutoStart(void)
{
    if (!libxl_driver)
        return;

    virDomainObjListForEach(libxl_driver->domains, libxlAutostartDomain,
                            libxl_driver);
}

static int
libxlStateReload(void)
{
    libxlDriverConfigPtr cfg;

    if (!libxl_driver)
        return 0;

    cfg = libxlDriverConfigGet(libxl_driver);

    virDomainObjListLoadAllConfigs(libxl_driver->domains,
                                   cfg->configDir,
                                   cfg->autostartDir,
                                   1,
                                   cfg->caps,
                                   libxl_driver->xmlopt,
                                   1 << VIR_DOMAIN_VIRT_XEN,
                                   NULL, libxl_driver);

    virDomainObjListForEach(libxl_driver->domains, libxlAutostartDomain,
                            libxl_driver);

    virObjectUnref(cfg);
    return 0;
}


static virDrvOpenStatus
libxlConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL) {
        if (libxl_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        if (!(conn->uri = virURIParse("xen:///")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        /* Only xen scheme */
        if (conn->uri->scheme == NULL || STRNEQ(conn->uri->scheme, "xen"))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* Error if xen or libxl scheme specified but driver not started. */
        if (libxl_driver == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("libxenlight state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }

        /* /session isn't supported in libxenlight */
        if (conn->uri->path &&
            STRNEQ(conn->uri->path, "") &&
            STRNEQ(conn->uri->path, "/") &&
            STRNEQ(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected Xen URI path '%s', try xen:///"),
                           NULLSTR(conn->uri->path));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = libxl_driver;

    return VIR_DRV_OPEN_SUCCESS;
};

static int
libxlConnectClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    conn->privateData = NULL;
    return 0;
}

static const char *
libxlConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "Xen";
}

static int
libxlConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return 0;

    cfg = libxlDriverConfigGet(driver);
    *version = cfg->version;
    virObjectUnref(cfg);
    return 0;
}


static char *libxlConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static char *
libxlConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!driver->hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, driver->hostsysinfo) < 0)
        return NULL;
    if (virBufferError(&buf)) {
        virReportOOMError();
        return NULL;
    }
    return virBufferContentAndReset(&buf);
}

static int
libxlConnectGetMaxVcpus(virConnectPtr conn, const char *type ATTRIBUTE_UNUSED)
{
    int ret;
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg;

    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    cfg = libxlDriverConfigGet(driver);
    ret = libxl_get_max_cpus(cfg->ctx);
    /* On failure, libxl_get_max_cpus() will return ERROR_FAIL from Xen 4.4
     * onward, but it ever returning 0 is obviously wrong too (and it is
     * what happens, on failure, on Xen 4.3 and earlier). Therefore, a 'less
     * or equal' is the catchall we want. */
    if (ret <= 0)
        ret = -1;

    virObjectUnref(cfg);
    return ret;
}

static int
libxlNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return libxlDriverNodeGetInfo(conn->privateData, info);
}

static char *
libxlConnectGetCapabilities(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    char *xml;
    libxlDriverConfigPtr cfg;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    cfg = libxlDriverConfigGet(driver);
    if ((xml = virCapabilitiesFormatXML(cfg->caps)) == NULL)
        virReportOOMError();

    virObjectUnref(cfg);
    return xml;
}

static int
libxlConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int
libxlConnectNumOfDomains(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, conn);

    return n;
}

static virDomainPtr
libxlDomainCreateXML(virConnectPtr conn, const char *xml,
                     unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);

    virCheckFlags(VIR_DOMAIN_START_PAUSED, NULL);

    if (!(def = virDomainDefParseString(xml, cfg->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    def = NULL;

    if (libxlDomainStart(driver, vm, (flags & VIR_DOMAIN_START_PAUSED) != 0,
                     -1) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return dom;
}

static virDomainPtr
libxlDomainLookupByID(virConnectPtr conn, int id)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
libxlDomainLookupByName(virConnectPtr conn, const char *name)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static int
libxlDomainSuspend(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm;
    libxlDomainObjPrivatePtr priv;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (libxl_domain_pause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to suspend domain '%d' with libxenlight"),
                           dom->id);
            goto endjob;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}


static int
libxlDomainResume(virDomainPtr dom)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm;
    libxlDomainObjPrivatePtr priv;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (libxl_domain_unpause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to resume domain '%d' with libxenlight"),
                           dom->id);
            goto endjob;
        }

        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto endjob;

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;
    libxlDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if (libxl_domain_shutdown(priv->ctx, dom->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to shutdown domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }

    /* vm is marked shutoff (or removed from domains list if not persistent)
     * in shutdown event handler.
     */
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainShutdown(virDomainPtr dom)
{
    return libxlDomainShutdownFlags(dom, 0);
}


static int
libxlDomainReboot(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;
    libxlDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if (libxl_domain_reboot(priv->ctx, dom->id) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reboot domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainDestroyFlags(virDomainPtr dom,
                        unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    virObjectEventPtr event = NULL;
    libxlDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    priv = vm->privateData;
    if (libxl_domain_destroy(priv->ctx, vm->def->id, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%d'"), dom->id);
        goto cleanup;
    }

    if (libxlDomainCleanupJob(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED)) {
        if (!vm->persistent) {
            virDomainObjListRemove(driver->domains, vm);
            vm = NULL;
        }
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    return ret;
}

static int
libxlDomainDestroy(virDomainPtr dom)
{
    return libxlDomainDestroyFlags(dom, 0);
}

static char *
libxlDomainGetOSType(virDomainPtr dom)
{
    virDomainObjPtr vm;
    char *type = NULL;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (VIR_STRDUP(type, vm->def->os.type) < 0)
        goto cleanup;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return type;
}

static unsigned long long
libxlDomainGetMaxMemory(virDomainPtr dom)
{
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->def->mem.max_balloon;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                          unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virDomainDefPtr persistentDef = NULL;
    bool isActive;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_MEM_LIVE |
                  VIR_DOMAIN_MEM_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    isActive = virDomainObjIsActive(vm);

    if (flags == VIR_DOMAIN_MEM_CURRENT) {
        if (isActive)
            flags = VIR_DOMAIN_MEM_LIVE;
        else
            flags = VIR_DOMAIN_MEM_CONFIG;
    }
    if (flags == VIR_DOMAIN_MEM_MAXIMUM) {
        if (isActive)
            flags = VIR_DOMAIN_MEM_LIVE | VIR_DOMAIN_MEM_MAXIMUM;
        else
            flags = VIR_DOMAIN_MEM_CONFIG | VIR_DOMAIN_MEM_MAXIMUM;
    }

    if (!isActive && (flags & VIR_DOMAIN_MEM_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set memory on an inactive domain"));
        goto endjob;
    }

    if (flags & VIR_DOMAIN_MEM_CONFIG) {
        if (!vm->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot change persistent config of a transient domain"));
            goto endjob;
        }
        if (!(persistentDef = virDomainObjGetPersistentDef(cfg->caps,
                                                           driver->xmlopt,
                                                           vm)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        /* resize the maximum memory */

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            priv = vm->privateData;
            if (libxl_domain_setmaxmem(priv->ctx, dom->id, newmem) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set maximum memory for domain '%d'"
                                 " with libxenlight"), dom->id);
                goto endjob;
            }
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            /* Help clang 2.8 decipher the logic flow.  */
            sa_assert(persistentDef);
            persistentDef->mem.max_balloon = newmem;
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }

    } else {
        /* resize the current memory */

        if (newmem > vm->def->mem.max_balloon) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot set memory higher than max memory"));
            goto endjob;
        }

        if (flags & VIR_DOMAIN_MEM_LIVE) {
            int res;

            priv = vm->privateData;
            /* Unlock virDomainObj while ballooning memory */
            virObjectUnlock(vm);
            res = libxl_set_memory_target(priv->ctx, dom->id, newmem, 0,
                                          /* force */ 1);
            virObjectLock(vm);
            if (res < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to set memory for domain '%d'"
                                 " with libxenlight"), dom->id);
                goto endjob;
            }
        }

        if (flags & VIR_DOMAIN_MEM_CONFIG) {
            sa_assert(persistentDef);
            persistentDef->mem.cur_balloon = newmem;
            ret = virDomainSaveConfig(cfg->configDir, persistentDef);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainSetMemory(virDomainPtr dom, unsigned long memory)
{
    return libxlDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_LIVE);
}

static int
libxlDomainSetMaxMemory(virDomainPtr dom, unsigned long memory)
{
    return libxlDomainSetMemoryFlags(dom, memory, VIR_DOMAIN_MEM_MAXIMUM);
}

static int
libxlDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    virDomainObjPtr vm;
    libxl_dominfo d_info;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    priv = vm->privateData;
    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
        info->memory = vm->def->mem.cur_balloon;
        info->maxMem = vm->def->mem.max_balloon;
    } else {
        if (libxl_domain_info(priv->ctx, &d_info, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("libxl_domain_info failed for domain '%d'"), dom->id);
            goto cleanup;
        }
        info->cpuTime = d_info.cpu_time;
        info->memory = d_info.current_memkb;
        info->maxMem = d_info.max_memkb;
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetState(virDomainPtr dom,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/*
 * virDomainObjPtr must be locked on invocation
 */
static int
libxlDoDomainSave(libxlDriverPrivatePtr driver, virDomainObjPtr vm,
                  const char *to)
{
    libxlDomainObjPrivatePtr priv = vm->privateData;
    libxlSavefileHeader hdr;
    virObjectEventPtr event = NULL;
    char *xml = NULL;
    uint32_t xml_len;
    int fd = -1;
    int ret = -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Domain '%d' has to be running because libxenlight will"
                         " suspend it"), vm->def->id);
        goto cleanup;
    }

    if ((fd = virFileOpenAs(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR,
                            -1, -1, 0)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create domain save file '%s'"), to);
        goto cleanup;
    }

    if ((xml = virDomainDefFormat(vm->def, 0)) == NULL)
        goto cleanup;
    xml_len = strlen(xml) + 1;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, LIBXL_SAVE_MAGIC, sizeof(hdr.magic));
    hdr.version = LIBXL_SAVE_VERSION;
    hdr.xmlLen = xml_len;

    if (safewrite(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to write save file header"));
        goto cleanup;
    }

    if (safewrite(fd, xml, xml_len) != xml_len) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Failed to write xml description"));
        goto cleanup;
    }

    /* Unlock virDomainObj while saving domain */
    virObjectUnlock(vm);
    ret = libxl_domain_suspend(priv->ctx, vm->def->id, fd, 0, NULL);
    virObjectLock(vm);

    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to save domain '%d' with libxenlight"),
                       vm->def->id);
        ret = -1;
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SAVED);

    if (libxl_domain_destroy(priv->ctx, vm->def->id, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to destroy domain '%d'"), vm->def->id);
        goto cleanup;
    }

    libxlDomainCleanup(driver, vm, VIR_DOMAIN_SHUTOFF_SAVED);
    vm->hasManagedSave = true;
    ret = 0;

 cleanup:
    VIR_FREE(xml);
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    if (event)
        libxlDomainEventQueue(driver, event);
    return ret;
}

static int
libxlDomainSaveFlags(virDomainPtr dom, const char *to, const char *dxml,
                     unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;
    bool remove_dom = false;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSaveFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }

    if (libxlDoDomainSave(driver, vm, to) < 0)
        goto endjob;

    if (!vm->persistent)
        remove_dom = true;

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (remove_dom && vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSave(virDomainPtr dom, const char *to)
{
    return libxlDomainSaveFlags(dom, to, NULL, 0);
}

static int
libxlDomainRestoreFlags(virConnectPtr conn, const char *from,
                        const char *dxml, unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    libxlSavefileHeader hdr;
    int fd = -1;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_PAUSED, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

    fd = libxlDomainSaveImageOpen(driver, cfg, from, &def, &hdr);
    if (fd < 0)
        goto cleanup_unlock;

    if (virDomainRestoreFlagsEnsureACL(conn, def) < 0)
        goto cleanup_unlock;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup_unlock;

    def = NULL;

    ret = libxlDomainStart(driver, vm, (flags & VIR_DOMAIN_SAVE_PAUSED) != 0, fd);
    if (ret < 0 && !vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

 cleanup:
    if (VIR_CLOSE(fd) < 0)
        virReportSystemError(errno, "%s", _("cannot close file"));
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;

 cleanup_unlock:
    libxlDriverUnlock(driver);
    goto cleanup;
}

static int
libxlDomainRestore(virConnectPtr conn, const char *from)
{
    return libxlDomainRestoreFlags(conn, from, NULL, 0);
}

static int
libxlDomainCoreDump(virDomainPtr dom, const char *to, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    bool remove_dom = false;
    bool paused = false;
    int ret = -1;

    virCheckFlags(VIR_DUMP_LIVE | VIR_DUMP_CRASH, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCoreDumpEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    if (!(flags & VIR_DUMP_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (libxl_domain_pause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Before dumping core, failed to suspend domain '%d'"
                             " with libxenlight"),
                           dom->id);
            goto endjob;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_DUMP);
        paused = true;
    }

    /* Unlock virDomainObj while dumping core */
    virObjectUnlock(vm);
    ret = libxl_domain_core_dump(priv->ctx, dom->id, to, NULL);
    virObjectLock(vm);
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to dump core of domain '%d' with libxenlight"),
                       dom->id);
        ret = -1;
        goto unpause;
    }

    if (flags & VIR_DUMP_CRASH) {
        if (libxl_domain_destroy(priv->ctx, dom->id, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to destroy domain '%d'"), dom->id);
            goto unpause;
        }

        libxlDomainCleanup(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        if (!vm->persistent)
            remove_dom = true;
    }

    ret = 0;

 unpause:
    if (virDomainObjIsActive(vm) && paused) {
        if (libxl_domain_unpause(priv->ctx, dom->id) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("After dumping core, failed to resume domain '%d' with"
                             " libxenlight"), dom->id);
        } else {
            virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_UNPAUSED);
        }
    }

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (remove_dom && vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    return ret;
}

static int
libxlDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char *name = NULL;
    int ret = -1;
    bool remove_dom = false;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainManagedSaveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }
    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto endjob;
    }

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto endjob;

    VIR_INFO("Saving state to %s", name);

    if (libxlDoDomainSave(driver, vm, name) < 0)
        goto endjob;

    if (!vm->persistent)
        remove_dom = true;

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (remove_dom && vm) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }
    if (vm)
        virObjectUnlock(vm);
    VIR_FREE(name);
    return ret;
}

static int
libxlDomainManagedSaveLoad(virDomainObjPtr vm,
                           void *opaque)
{
    libxlDriverPrivatePtr driver = opaque;
    char *name;
    int ret = -1;

    virObjectLock(vm);

    if (!(name = libxlDomainManagedSavePath(driver, vm)))
        goto cleanup;

    vm->hasManagedSave = virFileExists(name);

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    VIR_FREE(name);
    return ret;
}

static int
libxlDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->hasManagedSave;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    char *name = NULL;

    virCheckFlags(0, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainManagedSaveRemoveEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    ret = unlink(name);
    vm->hasManagedSave = false;

 cleanup:
    VIR_FREE(name);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetVcpusFlags(virDomainPtr dom, unsigned int nvcpus,
                         unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    libxlDomainObjPrivatePtr priv;
    virDomainDefPtr def;
    virDomainObjPtr vm;
    libxl_bitmap map;
    uint8_t *bitmask = NULL;
    unsigned int maplen;
    size_t i;
    unsigned int pos;
    int max;
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

    if (!nvcpus) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("nvcpus is zero"));
        return -1;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && (flags & VIR_DOMAIN_VCPU_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set vcpus on an inactive domain"));
        goto endjob;
    }

    if (!vm->persistent && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot change persistent config of a transient domain"));
        goto endjob;
    }

    if ((max = libxlConnectGetMaxVcpus(dom->conn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not determine max vcpus for the domain"));
        goto endjob;
    }

    if (!(flags & VIR_DOMAIN_VCPU_MAXIMUM) && vm->def->maxvcpus < max) {
        max = vm->def->maxvcpus;
    }

    if (nvcpus > max) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable"
                         " vcpus for the domain: %d > %d"), nvcpus, max);
        goto endjob;
    }

    priv = vm->privateData;

    if (!(def = virDomainObjGetPersistentDef(cfg->caps, driver->xmlopt, vm)))
        goto endjob;

    maplen = VIR_CPU_MAPLEN(nvcpus);
    if (VIR_ALLOC_N(bitmask, maplen) < 0)
        goto endjob;

    for (i = 0; i < nvcpus; ++i) {
        pos = i / 8;
        bitmask[pos] |= 1 << (i % 8);
    }

    map.size = maplen;
    map.map = bitmask;

    switch (flags) {
    case VIR_DOMAIN_VCPU_MAXIMUM | VIR_DOMAIN_VCPU_CONFIG:
        def->maxvcpus = nvcpus;
        if (nvcpus < def->vcpus)
            def->vcpus = nvcpus;
        break;

    case VIR_DOMAIN_VCPU_CONFIG:
        def->vcpus = nvcpus;
        break;

    case VIR_DOMAIN_VCPU_LIVE:
        if (libxl_set_vcpuonline(priv->ctx, dom->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%d'"
                             " with libxenlight"), dom->id);
            goto endjob;
        }
        break;

    case VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG:
        if (libxl_set_vcpuonline(priv->ctx, dom->id, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set vcpus for domain '%d'"
                             " with libxenlight"), dom->id);
            goto endjob;
        }
        def->vcpus = nvcpus;
        break;
    }

    ret = 0;

    if (flags & VIR_DOMAIN_VCPU_CONFIG)
        ret = virDomainSaveConfig(cfg->configDir, def);

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    VIR_FREE(bitmask);
     if (vm)
        virObjectUnlock(vm);
     virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainSetVcpus(virDomainPtr dom, unsigned int nvcpus)
{
    return libxlDomainSetVcpusFlags(dom, nvcpus, VIR_DOMAIN_VCPU_LIVE);
}

static int
libxlDomainGetVcpusFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;
    bool active;

    virCheckFlags(VIR_DOMAIN_VCPU_LIVE |
                  VIR_DOMAIN_VCPU_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    active = virDomainObjIsActive(vm);

    if ((flags & (VIR_DOMAIN_VCPU_LIVE | VIR_DOMAIN_VCPU_CONFIG)) == 0) {
        if (active)
            flags |= VIR_DOMAIN_VCPU_LIVE;
        else
            flags |= VIR_DOMAIN_VCPU_CONFIG;
    }
    if ((flags & VIR_DOMAIN_VCPU_LIVE) && (flags & VIR_DOMAIN_VCPU_CONFIG)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid flag combination: (0x%x)"), flags);
        return -1;
    }

    if (flags & VIR_DOMAIN_VCPU_LIVE) {
        if (!active) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
        def = vm->def;
    } else {
        if (!vm->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is transient"));
            goto cleanup;
        }
        def = vm->newDef ? vm->newDef : vm->def;
    }

    ret = (flags & VIR_DOMAIN_VCPU_MAXIMUM) ? def->maxvcpus : def->vcpus;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainPinVcpuFlags(virDomainPtr dom, unsigned int vcpu,
                        unsigned char *cpumap, int maplen,
                        unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainDefPtr targetDef = NULL;
    virBitmapPtr pcpumap = NULL;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainPinVcpuFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if ((flags & VIR_DOMAIN_AFFECT_LIVE) && !virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is inactive"));
        goto endjob;
    }

    if (virDomainLiveConfigHelperMethod(cfg->caps, driver->xmlopt, vm,
                                        &flags, &targetDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        targetDef = vm->def;
    }

    /* Make sure coverity knows targetDef is valid at this point. */
    sa_assert(targetDef);

    pcpumap = virBitmapNewData(cpumap, maplen);
    if (!pcpumap)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        libxl_bitmap map = { .size = maplen, .map = cpumap };
        libxlDomainObjPrivatePtr priv;

        priv = vm->privateData;
        if (libxl_set_vcpuaffinity(priv->ctx, dom->id, vcpu, &map) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to pin vcpu '%d' with libxenlight"),
                           vcpu);
            goto endjob;
        }
    }

    /* full bitmap means reset the settings (if any). */
    if (virBitmapIsAllSet(pcpumap)) {
        if (virDomainVcpuPinDel(targetDef, vcpu) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to delete vcpupin xml for vcpu '%d'"),
                           vcpu);
            goto endjob;
        }
        goto done;
    }

    if (!targetDef->cputune.vcpupin) {
        if (VIR_ALLOC(targetDef->cputune.vcpupin) < 0)
            goto endjob;
        targetDef->cputune.nvcpupin = 0;
    }
    if (virDomainVcpuPinAdd(&targetDef->cputune.vcpupin,
                            &targetDef->cputune.nvcpupin,
                            cpumap,
                            maplen,
                            vcpu) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("failed to update or add vcpupin xml"));
        goto endjob;
    }

 done:
    ret = 0;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        ret = virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm);
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, targetDef);
    }

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    virBitmapFree(pcpumap);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainPinVcpu(virDomainPtr dom, unsigned int vcpu, unsigned char *cpumap,
                   int maplen)
{
    return libxlDomainPinVcpuFlags(dom, vcpu, cpumap, maplen,
                                   VIR_DOMAIN_AFFECT_LIVE);
}

static int
libxlDomainGetVcpuPinInfo(virDomainPtr dom, int ncpumaps,
                          unsigned char *cpumaps, int maplen,
                          unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm = NULL;
    virDomainDefPtr targetDef = NULL;
    virDomainVcpuPinDefPtr *vcpupin_list;
    virBitmapPtr cpumask = NULL;
    int maxcpu, hostcpus, vcpu, pcpu, n, ret = -1;
    unsigned char *cpumap;
    bool pinned;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpuPinInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(cfg->caps, driver->xmlopt, vm,
                                        &flags, &targetDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        targetDef = vm->def;
    }

    /* Make sure coverity knows targetDef is valid at this point. */
    sa_assert(targetDef);

    /* Clamp to actual number of vcpus */
    if (ncpumaps > targetDef->vcpus)
        ncpumaps = targetDef->vcpus;

    /* we use cfg->ctx, as vm->privateData->ctx may be NULL if VM is down. */
    if ((hostcpus = libxl_get_max_cpus(cfg->ctx)) < 0)
        goto cleanup;

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* initialize cpumaps */
    memset(cpumaps, 0xff, maplen * ncpumaps);
    if (maxcpu % 8) {
        for (vcpu = 0; vcpu < ncpumaps; vcpu++) {
            cpumap = VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
            cpumap[maplen - 1] &= (1 << maxcpu % 8) - 1;
        }
    }

    /* if vcpupin setting exists, there may be unused pcpus */
    for (n = 0; n < targetDef->cputune.nvcpupin; n++) {
        vcpupin_list = targetDef->cputune.vcpupin;
        vcpu = vcpupin_list[n]->vcpuid;
        cpumask = vcpupin_list[n]->cpumask;
        cpumap = VIR_GET_CPUMAP(cpumaps, maplen, vcpu);
        for (pcpu = 0; pcpu < maxcpu; pcpu++) {
            if (virBitmapGetBit(cpumask, pcpu, &pinned) < 0)
                goto cleanup;
            if (!pinned)
                VIR_UNUSE_CPU(cpumap, pcpu);
        }
    }
    ret = ncpumaps;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainGetVcpus(virDomainPtr dom, virVcpuInfoPtr info, int maxinfo,
                    unsigned char *cpumaps, int maplen)
{
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    libxl_vcpuinfo *vcpuinfo;
    int maxcpu, hostcpus;
    size_t i;
    unsigned char *cpumap;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetVcpusEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    if ((vcpuinfo = libxl_list_vcpu(priv->ctx, dom->id, &maxcpu,
                                    &hostcpus)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to list vcpus for domain '%d' with libxenlight"),
                       dom->id);
        goto cleanup;
    }

    if (cpumaps && maplen > 0)
        memset(cpumaps, 0, maplen * maxinfo);
    for (i = 0; i < maxcpu && i < maxinfo; ++i) {
        info[i].number = vcpuinfo[i].vcpuid;
        info[i].cpu = vcpuinfo[i].cpu;
        info[i].cpuTime = vcpuinfo[i].vcpu_time;
        if (vcpuinfo[i].running)
            info[i].state = VIR_VCPU_RUNNING;
        else if (vcpuinfo[i].blocked)
            info[i].state = VIR_VCPU_BLOCKED;
        else
            info[i].state = VIR_VCPU_OFFLINE;

        if (cpumaps && maplen > 0) {
            cpumap = VIR_GET_CPUMAP(cpumaps, maplen, i);
            memcpy(cpumap, vcpuinfo[i].cpumap.map,
                   MIN(maplen, vcpuinfo[i].cpumap.size));
        }

        libxl_vcpuinfo_dispose(&vcpuinfo[i]);
    }
    VIR_FREE(vcpuinfo);

    ret = maxinfo;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
libxlDomainGetXMLDesc(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, flags);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *
libxlConnectDomainXMLFromNative(virConnectPtr conn,
                                const char *nativeFormat,
                                const char *nativeConfig,
                                unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainDefPtr def = NULL;
    virConfPtr conf = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STREQ(nativeFormat, LIBXL_CONFIG_FORMAT_XM)) {
        if (!(conf = virConfReadMem(nativeConfig, strlen(nativeConfig), 0)))
            goto cleanup;

        if (!(def = xenParseXM(conf,
                               cfg->verInfo->xen_version_major,
                               cfg->caps))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("parsing xm config failed"));
            goto cleanup;
        }
    } else if (STREQ(nativeFormat, LIBXL_CONFIG_FORMAT_SEXPR)) {
        /* only support latest xend config format */
        if (!(def = xenParseSxprString(nativeConfig,
                                       XEND_CONFIG_VERSION_3_1_0,
                                       NULL,
                                       -1))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("parsing sxpr config failed"));
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    xml = virDomainDefFormat(def, VIR_DOMAIN_XML_INACTIVE);

 cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    virObjectUnref(cfg);
    return xml;
}

#define MAX_CONFIG_SIZE (1024 * 65)
static char *
libxlConnectDomainXMLToNative(virConnectPtr conn, const char * nativeFormat,
                              const char * domainXml,
                              unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainDefPtr def = NULL;
    virConfPtr conf = NULL;
    int len = MAX_CONFIG_SIZE;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(nativeFormat, LIBXL_CONFIG_FORMAT_XM)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    if (!(def = virDomainDefParseString(domainXml,
                                        cfg->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (!(conf = xenFormatXM(conn, def, cfg->verInfo->xen_version_major)))
        goto cleanup;

    if (VIR_ALLOC_N(ret, len) < 0)
        goto cleanup;

    if (virConfWriteMem(ret, &len, conf) < 0) {
        VIR_FREE(ret);
        goto cleanup;
    }

 cleanup:
    virDomainDefFree(def);
    if (conf)
        virConfFree(conf);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlConnectListDefinedDomains(virConnectPtr conn,
                               char **const names, int nnames)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                         virConnectListDefinedDomainsCheckACL, conn);
    return n;
}

static int
libxlConnectNumOfDefinedDomains(virConnectPtr conn)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, false,
                                     virConnectNumOfDefinedDomainsCheckACL,
                                     conn);
    return n;
}

static int
libxlDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_PAUSED, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = libxlDomainStart(driver, vm, (flags & VIR_DOMAIN_START_PAUSED) != 0, -1);

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainCreate(virDomainPtr dom)
{
    return libxlDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
libxlDomainDefineXML(virConnectPtr conn, const char *xml)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;

    /* Lock the driver until the virDomainObj is created and locked */
    libxlDriverLock(driver);
    if (!(def = virDomainDefParseString(xml, cfg->caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_XEN,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup_unlock;

    if (virDomainDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup_unlock;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   0,
                                   &oldDef)))
        goto cleanup_unlock;

    def = NULL;
    vm->persistent = 1;
    libxlDriverUnlock(driver);

    if (virDomainSaveConfig(cfg->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

 cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return dom;

 cleanup_unlock:
    libxlDriverUnlock(driver);
    goto cleanup;
}

static int
libxlDomainUndefineFlags(virDomainPtr dom,
                         unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    char *name = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    name = libxlDomainManagedSavePath(driver, vm);
    if (name == NULL)
        goto cleanup;

    if (virFileExists(name)) {
        if (flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE) {
            if (unlink(name) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to remove domain managed save image"));
                goto cleanup;
            }
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Refusing to undefine while domain managed "
                             "save image exists"));
            goto cleanup;
        }
    }

    if (virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    VIR_FREE(name);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        libxlDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainUndefine(virDomainPtr dom)
{
    return libxlDomainUndefineFlags(dom, 0);
}

static int
libxlDomainChangeEjectableMedia(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDiskDefPtr disk)
{
    virDomainDiskDefPtr origdisk = NULL;
    libxl_device_disk x_disk;
    size_t i;
    int ret = -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i]->bus == disk->bus &&
            STREQ(vm->def->disks[i]->dst, disk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No device with bus '%s' and target '%s'"),
                       virDomainDiskBusTypeToString(disk->bus), disk->dst);
        goto cleanup;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Removable media not supported for %s device"),
                       virDomainDiskDeviceTypeToString(disk->device));
        return -1;
    }

    if (libxlMakeDisk(disk, &x_disk) < 0)
        goto cleanup;

    if ((ret = libxl_cdrom_insert(priv->ctx, vm->def->id, &x_disk, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to change media for disk '%s'"),
                       disk->dst);
        goto cleanup;
    }

    if (virDomainDiskSetSource(origdisk, virDomainDiskGetSource(disk)) < 0)
        goto cleanup;
    virDomainDiskSetType(origdisk, virDomainDiskGetType(disk));

    virDomainDiskDefFree(disk);

    ret = 0;

 cleanup:
    return ret;
}

static int
libxlDomainAttachDeviceDiskLive(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr l_disk = dev->data.disk;
    libxl_device_disk x_disk;
    int ret = -1;

    switch (l_disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            ret = libxlDomainChangeEjectableMedia(priv, vm, l_disk);
            break;
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (l_disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {
                if (virDomainDiskIndexByName(vm->def, l_disk->dst, true) >= 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("target %s already exists"), l_disk->dst);
                    goto cleanup;
                }

                if (!virDomainDiskGetSource(l_disk)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("disk source path is missing"));
                    goto cleanup;
                }

                if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
                    goto cleanup;

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_add(priv->ctx, vm->def->id,
                                                &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to attach disk '%s'"),
                                   l_disk->dst);
                    goto cleanup;
                }

                virDomainDiskInsertPreAlloced(vm->def, l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%s' cannot be hotplugged."),
                               virDomainDiskBusTypeToString(l_disk->bus));
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device type '%s' cannot be hotplugged"),
                           virDomainDiskDeviceTypeToString(l_disk->device));
            break;
    }

 cleanup:
    return ret;
}

static int
libxlDomainAttachHostPCIDevice(libxlDriverPrivatePtr driver,
                               libxlDomainObjPrivatePtr priv,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    libxl_device_pci pcidev;
    virDomainHostdevDefPtr found;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
        return -1;

    if (virDomainHostdevFind(vm->def, hostdev, &found) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target pci device %.4x:%.2x:%.2x.%.1x already exists"),
                       hostdev->source.subsys.u.pci.addr.domain,
                       hostdev->source.subsys.u.pci.addr.bus,
                       hostdev->source.subsys.u.pci.addr.slot,
                       hostdev->source.subsys.u.pci.addr.function);
        return -1;
    }

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1) < 0)
        return -1;

    if (virHostdevPreparePCIDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                    vm->def->name, vm->def->uuid,
                                    &hostdev, 1, 0) < 0)
        return -1;

    if (libxlMakePci(hostdev, &pcidev) < 0)
        goto error;

    if (libxl_device_pci_add(priv->ctx, vm->def->id, &pcidev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to attach pci device %.4x:%.2x:%.2x.%.1x"),
                       hostdev->source.subsys.u.pci.addr.domain,
                       hostdev->source.subsys.u.pci.addr.bus,
                       hostdev->source.subsys.u.pci.addr.slot,
                       hostdev->source.subsys.u.pci.addr.function);
        goto error;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;
    return 0;

 error:
    virHostdevReAttachPCIDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                 vm->def->name, &hostdev, 1, NULL);
    return -1;
}

static int
libxlDomainAttachHostDevice(libxlDriverPrivatePtr driver,
                            libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (libxlDomainAttachHostPCIDevice(driver, priv, vm, hostdev) < 0)
            return -1;
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev subsys type '%s' not supported"),
                       virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    return 0;
}

static int
libxlDomainDetachDeviceDiskLive(libxlDomainObjPrivatePtr priv,
                                virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr l_disk = NULL;
    libxl_device_disk x_disk;
    int idx;
    int ret = -1;

    switch (dev->data.disk->device)  {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            if (dev->data.disk->bus == VIR_DOMAIN_DISK_BUS_XEN) {

                if ((idx = virDomainDiskIndexByName(vm->def,
                                                    dev->data.disk->dst,
                                                    false)) < 0) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("disk %s not found"), dev->data.disk->dst);
                    goto cleanup;
                }

                l_disk = vm->def->disks[idx];

                if (libxlMakeDisk(l_disk, &x_disk) < 0)
                    goto cleanup;

                if ((ret = libxl_device_disk_remove(priv->ctx, vm->def->id,
                                                    &x_disk, NULL)) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("libxenlight failed to detach disk '%s'"),
                                   l_disk->dst);
                    goto cleanup;
                }

                virDomainDiskRemove(vm->def, idx);
                virDomainDiskDefFree(l_disk);

            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk bus '%s' cannot be hot unplugged."),
                               virDomainDiskBusTypeToString(dev->data.disk->bus));
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot hot unplugged"),
                           virDomainDiskDeviceTypeToString(dev->data.disk->device));
            break;
    }

 cleanup:
    return ret;
}

static int
libxlDomainAttachDeviceLive(libxlDriverPrivatePtr driver,
                            libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainAttachDeviceDiskLive(priv, vm, dev);
            if (!ret)
                dev->data.disk = NULL;
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            ret = libxlDomainAttachHostDevice(driver, priv, vm, dev);
            if (!ret)
                dev->data.hostdev = NULL;
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be attached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainAttachDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    virDomainHostdevDefPtr hostdev;
    virDomainHostdevDefPtr found;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %s already exists."), disk->dst);
                return -1;
            }
            if (virDomainDiskInsert(vmdef, disk))
                return -1;
            /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
            dev->data.disk = NULL;
            break;
        case VIR_DOMAIN_DEVICE_HOSTDEV:
            hostdev = dev->data.hostdev;

            if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
                return -1;

            if (virDomainHostdevFind(vmdef, hostdev, &found) >= 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("target pci device %.4x:%.2x:%.2x.%.1x\
                                  already exists"),
                               hostdev->source.subsys.u.pci.addr.domain,
                               hostdev->source.subsys.u.pci.addr.bus,
                               hostdev->source.subsys.u.pci.addr.slot,
                               hostdev->source.subsys.u.pci.addr.function);
                return -1;
            }

            virDomainHostdevInsert(vmdef, hostdev);
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent attach of device is not supported"));
            return -1;
    }
    return 0;
}

static int
libxlComparePCIDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                      virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                      virDomainDeviceInfoPtr info1,
                      void *opaque)
{
    virDomainDeviceInfoPtr info2 = opaque;

    if (info1->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        info2->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return 0;

    if (info1->addr.pci.domain == info2->addr.pci.domain &&
        info1->addr.pci.bus == info2->addr.pci.bus &&
        info1->addr.pci.slot == info2->addr.pci.slot &&
        info1->addr.pci.function != info2->addr.pci.function)
        return -1;
    return 0;
}

static bool
libxlIsMultiFunctionDevice(virDomainDefPtr def,
                           virDomainDeviceInfoPtr dev)
{
    if (virDomainDeviceInfoIterate(def, libxlComparePCIDevice, dev) < 0)
        return true;
    return false;
}

static int
libxlDomainDetachHostPCIDevice(libxlDriverPrivatePtr driver,
                               libxlDomainObjPrivatePtr priv,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;
    libxl_device_pci pcidev;
    virDomainHostdevDefPtr detach;
    int idx;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (subsys->type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
        return -1;

    idx = virDomainHostdevFind(vm->def, hostdev, &detach);
    if (idx < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("host pci device %.4x:%.2x:%.2x.%.1x not found"),
                       subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                       subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
        return -1;
    }

    if (libxlIsMultiFunctionDevice(vm->def, detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %.4x:%.2x:%.2x.%.1x"),
                       subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                       subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
        goto error;
    }


    libxl_device_pci_init(&pcidev);

    if (libxlMakePci(detach, &pcidev) < 0)
        goto error;

    if (libxl_device_pci_remove(priv->ctx, vm->def->id, &pcidev, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("libxenlight failed to detach pci device\
                          %.4x:%.2x:%.2x.%.1x"),
                       subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                       subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
        goto error;
    }

    libxl_device_pci_dispose(&pcidev);

    virDomainHostdevRemove(vm->def, idx);

    virHostdevReAttachPCIDevices(hostdev_mgr, LIBXL_DRIVER_NAME,
                                 vm->def->name, &hostdev, 1, NULL);

    return 0;

 error:
    virDomainHostdevDefFree(detach);
    return -1;
}

static int
libxlDomainDetachHostDevice(libxlDriverPrivatePtr driver,
                            libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (subsys->type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            return libxlDomainDetachHostPCIDevice(driver, priv, vm, hostdev);

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %d"), subsys->type);
            break;
    }

    return -1;
}

static int
libxlDomainDetachDeviceLive(libxlDriverPrivatePtr driver,
                            libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            ret = libxlDomainDetachDeviceDiskLive(priv, vm, dev);
            break;

        case VIR_DOMAIN_DEVICE_HOSTDEV:
            ret = libxlDomainDetachHostDevice(driver, priv, vm, dev);
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be detached"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}


static int
libxlDomainDetachDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk, detach;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if (!(detach = virDomainDiskRemoveByName(vmdef, disk->dst))) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("no target device %s"), disk->dst);
                break;
            }
            virDomainDiskDefFree(detach);
            ret = 0;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent detach of device is not supported"));
            break;
    }

    return ret;
}

static int
libxlDomainUpdateDeviceLive(libxlDomainObjPrivatePtr priv,
                            virDomainObjPtr vm, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            switch (disk->device) {
                case VIR_DOMAIN_DISK_DEVICE_CDROM:
                    ret = libxlDomainChangeEjectableMedia(priv, vm, disk);
                    if (ret == 0)
                        dev->data.disk = NULL;
                    break;
                default:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("disk bus '%s' cannot be updated."),
                                   virDomainDiskBusTypeToString(disk->bus));
                    break;
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("device type '%s' cannot be updated"),
                           virDomainDeviceTypeToString(dev->type));
            break;
    }

    return ret;
}

static int
libxlDomainUpdateDeviceConfig(virDomainDefPtr vmdef, virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr orig;
    virDomainDiskDefPtr disk;
    int idx;
    int ret = -1;

    switch (dev->type) {
        case VIR_DOMAIN_DEVICE_DISK:
            disk = dev->data.disk;
            if ((idx = virDomainDiskIndexByName(vmdef, disk->dst, false)) < 0) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("target %s doesn't exist."), disk->dst);
                goto cleanup;
            }
            orig = vmdef->disks[idx];
            if (!(orig->device == VIR_DOMAIN_DISK_DEVICE_CDROM)) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("this disk doesn't support update"));
                goto cleanup;
            }

            if (virDomainDiskSetSource(orig, virDomainDiskGetSource(disk)) < 0)
                goto cleanup;
            virDomainDiskSetType(orig, virDomainDiskGetType(disk));
            virDomainDiskSetFormat(orig, virDomainDiskGetFormat(disk));
            if (virDomainDiskSetDriver(orig, virDomainDiskGetDriver(disk)) < 0)
                goto cleanup;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("persistent update of device is not supported"));
            goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


static int
libxlDomainAttachDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto endjob;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto endjob;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, cfg->caps,
                                                    driver->xmlopt)))
            goto endjob;

        if ((ret = libxlDomainAttachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto endjob;

        if ((ret = libxlDomainAttachDeviceLive(driver, priv, vm, dev)) < 0)
            goto endjob;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainAttachDevice(virDomainPtr dom, const char *xml)
{
    return libxlDomainAttachDeviceFlags(dom, xml,
                                        VIR_DOMAIN_DEVICE_MODIFY_LIVE);
}

static int
libxlDomainDetachDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto endjob;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto endjob;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto endjob;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, cfg->caps,
                                                    driver->xmlopt)))
            goto endjob;

        if ((ret = libxlDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto endjob;

        if ((ret = libxlDomainDetachDeviceLive(driver, priv, vm, dev)) < 0)
            goto endjob;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlDomainDetachDevice(virDomainPtr dom, const char *xml)
{
    return libxlDomainDetachDeviceFlags(dom, xml,
                                        VIR_DOMAIN_DEVICE_MODIFY_LIVE);
}

static int
libxlDomainUpdateDeviceFlags(virDomainPtr dom, const char *xml,
                             unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL;
    libxlDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_DEVICE_MODIFY_LIVE |
                  VIR_DOMAIN_DEVICE_MODIFY_CONFIG, -1);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        if (flags == VIR_DOMAIN_DEVICE_MODIFY_CURRENT)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("Domain is not running"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID,
                        "%s", _("cannot modify device on transient domain"));
         goto cleanup;
    }

    priv = vm->privateData;

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG) {
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        /* Make a copy for updated domain. */
        if (!(vmdef = virDomainObjCopyPersistentDef(vm, cfg->caps,
                                                    driver->xmlopt)))
            goto cleanup;

        if ((ret = libxlDomainUpdateDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    } else {
        ret = 0;
    }

    if (flags & VIR_DOMAIN_DEVICE_MODIFY_LIVE) {
        /* If dev exists it was created to modify the domain config. Free it. */
        virDomainDeviceDefFree(dev);
        if (!(dev = virDomainDeviceDefParse(xml, vm->def,
                                            cfg->caps, driver->xmlopt,
                                            VIR_DOMAIN_XML_INACTIVE)))
            goto cleanup;

        if ((ret = libxlDomainUpdateDeviceLive(priv, vm, dev)) < 0)
            goto cleanup;

        /*
         * update domain status forcibly because the domain status may be
         * changed even if we attach the device failed.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            ret = -1;
    }

    /* Finally, if no error until here, we can save config. */
    if (!ret && (flags & VIR_DOMAIN_DEVICE_MODIFY_CONFIG)) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 cleanup:
    virDomainDefFree(vmdef);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static unsigned long long
libxlNodeGetFreeMemory(virConnectPtr conn)
{
    libxl_physinfo phy_info;
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    unsigned long long ret = 0;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        goto cleanup;

    if (libxl_get_physinfo(cfg->ctx, &phy_info)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_physinfo_info failed"));
        goto cleanup;
    }

    ret = phy_info.free_pages * cfg->verInfo->pagesize;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static int
libxlNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int n, lastCell, numCells;
    int ret = -1, nr_nodes = 0;
    libxl_numainfo *numa_info = NULL;
    libxlDriverPrivatePtr driver = conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);

    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        goto cleanup;

    numa_info = libxl_get_numainfo(cfg->ctx, &nr_nodes);
    if (numa_info == NULL || nr_nodes == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libxl_get_numainfo failed"));
        goto cleanup;
    }

    /* Check/sanitize the cell range */
    if (startCell >= nr_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, nr_nodes - 1);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell >= nr_nodes)
        lastCell = nr_nodes - 1;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        if (numa_info[n].size == LIBXL_NUMAINFO_INVALID_ENTRY)
            freeMems[numCells++] = 0;
        else
            freeMems[numCells++] = numa_info[n].free;
    }

    ret = numCells;

 cleanup:
    libxl_numainfo_list_free(numa_info, nr_nodes);
    virObjectUnref(cfg);
    return ret;
}

static int
libxlConnectDomainEventRegister(virConnectPtr conn,
                                virConnectDomainEventCallback callback,
                                void *opaque,
                                virFreeCallback freecb)
{
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegister(conn,
                                    driver->domainEventState,
                                    callback, opaque, freecb) < 0)
        return -1;

    return 0;
}


static int
libxlConnectDomainEventDeregister(virConnectPtr conn,
                                  virConnectDomainEventCallback callback)
{
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateDeregister(conn,
                                      driver->domainEventState,
                                      callback) < 0)
        return -1;

    return 0;
}

static int
libxlDomainGetAutostart(virDomainPtr dom, int *autostart)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetAutostart(virDomainPtr dom, int autostart)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDriverConfigPtr cfg = libxlDriverConfigGet(driver);
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot set autostart for transient domain"));
        goto endjob;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if (!(configFile = virDomainConfigFile(cfg->configDir, vm->def->name)))
            goto endjob;
        if (!(autostartLink = virDomainConfigFile(cfg->autostartDir, vm->def->name)))
            goto endjob;

        if (autostart) {
            if (virFileMakePath(cfg->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     cfg->autostartDir);
                goto endjob;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s to '%s'"),
                                     autostartLink, configFile);
                goto endjob;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto endjob;
            }
        }

        vm->autostart = autostart;
    }
    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static char *
libxlDomainGetSchedulerType(virDomainPtr dom, int *nparams)
{
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    char * ret = NULL;
    const char *name = NULL;
    libxl_scheduler sched_id;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    sched_id = libxl_get_scheduler(priv->ctx);

    if (nparams)
        *nparams = 0;
    switch (sched_id) {
    case LIBXL_SCHEDULER_SEDF:
        name = "sedf";
        break;
    case LIBXL_SCHEDULER_CREDIT:
        name = "credit";
        if (nparams)
            *nparams = XEN_SCHED_CREDIT_NPARAM;
        break;
    case LIBXL_SCHEDULER_CREDIT2:
        name = "credit2";
        break;
    case LIBXL_SCHEDULER_ARINC653:
        name = "arinc653";
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Failed to get scheduler id for domain '%d'"
                     " with libxenlight"), dom->id);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, name));

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int *nparams,
                                       unsigned int flags)
{
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_domain_sched_params sc_info;
    libxl_scheduler sched_id;
    int ret = -1;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    sched_id = libxl_get_scheduler(priv->ctx);

    if (sched_id != LIBXL_SCHEDULER_CREDIT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' scheduler is supported"));
        goto cleanup;
    }

    if (libxl_domain_sched_params_get(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto cleanup;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_WEIGHT,
                                VIR_TYPED_PARAM_UINT, sc_info.weight) < 0)
        goto cleanup;

    if (*nparams > 1) {
        if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_CAP,
                                    VIR_TYPED_PARAM_UINT, sc_info.cap) < 0)
            goto cleanup;
    }

    if (*nparams > XEN_SCHED_CREDIT_NPARAM)
        *nparams = XEN_SCHED_CREDIT_NPARAM;
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainGetSchedulerParameters(virDomainPtr dom, virTypedParameterPtr params,
                                  int *nparams)
{
    return libxlDomainGetSchedulerParametersFlags(dom, params, nparams, 0);
}

static int
libxlDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                       virTypedParameterPtr params,
                                       int nparams,
                                       unsigned int flags)
{
    libxlDriverPrivatePtr driver = dom->conn->privateData;
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_domain_sched_params sc_info;
    int sched_id;
    size_t i;
    int ret = -1;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_SCHEDULER_CAP,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (libxlDomainObjBeginJob(driver, vm, LIBXL_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", _("Domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;

    sched_id = libxl_get_scheduler(priv->ctx);

    if (sched_id != LIBXL_SCHEDULER_CREDIT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only 'credit' scheduler is supported"));
        goto endjob;
    }

    if (libxl_domain_sched_params_get(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto endjob;
    }

    for (i = 0; i < nparams; ++i) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_WEIGHT))
            sc_info.weight = params[i].value.ui;
        else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CAP))
            sc_info.cap = params[i].value.ui;
    }

    if (libxl_domain_sched_params_set(priv->ctx, dom->id, &sc_info) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set scheduler parameters for domain '%d'"
                         " with libxenlight"), dom->id);
        goto endjob;
    }

    ret = 0;

 endjob:
    if (!libxlDomainObjEndJob(driver, vm))
        vm = NULL;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
libxlDomainOpenConsole(virDomainPtr dom,
                       const char *dev_name,
                       virStreamPtr st,
                       unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainChrDefPtr chr = NULL;
    libxlDomainObjPrivatePtr priv;
    char *console = NULL;

    virCheckFlags(VIR_DOMAIN_CONSOLE_FORCE, -1);

    if (dev_name) {
        /* XXX support device aliases in future */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Named device aliases are not supported"));
        goto cleanup;
    }

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (vm->def->nserials)
        chr = vm->def->serials[0];

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    ret = libxl_primary_console_get_tty(priv->ctx, vm->def->id, &console);
    if (ret)
        goto cleanup;

    if (VIR_STRDUP(chr->source.data.file.path, console) < 0)
        goto cleanup;

    /* handle mutually exclusive access to console devices */
    ret = virChrdevOpen(priv->devs,
                        &chr->source,
                        st,
                        (flags & VIR_DOMAIN_CONSOLE_FORCE) != 0);

    if (ret == 1) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Active console session exists for this domain"));
        ret = -1;
    }

 cleanup:
    VIR_FREE(console);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlDomainSetSchedulerParameters(virDomainPtr dom, virTypedParameterPtr params,
                                  int nparams)
{
    return libxlDomainSetSchedulerParametersFlags(dom, params, nparams, 0);
}

/* NUMA node affinity information is available through libxl
 * starting from Xen 4.3. */
#ifdef LIBXL_HAVE_DOMAIN_NODEAFFINITY

/* Number of Xen NUMA parameters */
# define LIBXL_NUMA_NPARAM 2

static int
libxlDomainGetNumaParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    libxlDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    libxl_bitmap nodemap;
    virBitmapPtr nodes = NULL;
    char *nodeset = NULL;
    int rc, ret = -1;
    size_t i, j;

    /* In Xen 4.3, it is possible to query the NUMA node affinity of a domain
     * via libxl, but not to change it. We therefore only allow AFFECT_LIVE. */
    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We blindly return a string, and let libvirt.c and remote_driver.c do
     * the filtering on behalf of older clients that can't parse it. */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    libxl_bitmap_init(&nodemap);

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetNumaParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if ((*nparams) == 0) {
        *nparams = LIBXL_NUMA_NPARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < LIBXL_NUMA_NPARAM && i < *nparams; i++) {
        virMemoryParameterPtr param = &params[i];
        int numnodes;

        switch (i) {
        case 0:
            /* NUMA mode */

            /* Xen implements something that is really close to numactl's
             * 'interleave' policy (see `man 8 numactl' for details). */
            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_MODE,
                                        VIR_TYPED_PARAM_INT,
                                        VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE) < 0)
                goto cleanup;

            break;

        case 1:
            /* Node affinity */

            /* Let's allocate both libxl and libvirt bitmaps */
            numnodes = libxl_get_max_nodes(priv->ctx);
            if (numnodes <= 0)
                goto cleanup;

            if (libxl_node_bitmap_alloc(priv->ctx, &nodemap, 0) ||
                !(nodes = virBitmapNew(numnodes))) {
                virReportOOMError();
                goto cleanup;
            }

            rc = libxl_domain_get_nodeaffinity(priv->ctx,
                                               vm->def->id,
                                               &nodemap);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get numa affinity"));
                goto cleanup;
            }

            /* First, we convert libxl_bitmap into virBitmap. After that,
             * we format virBitmap as a string that can be returned. */
            virBitmapClearAll(nodes);
            libxl_for_each_set_bit(j, nodemap) {
                if (virBitmapSetBit(nodes, j)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Node %zu out of range"), j);
                    goto cleanup;
                }
            }

            nodeset = virBitmapFormat(nodes);
            if (!nodeset && VIR_STRDUP(nodeset, "") < 0)
                goto cleanup;

            if (virTypedParameterAssign(param, VIR_DOMAIN_NUMA_NODESET,
                                        VIR_TYPED_PARAM_STRING, nodeset) < 0)
                goto cleanup;

            nodeset = NULL;

            break;
        }
    }

    if (*nparams > LIBXL_NUMA_NPARAM)
        *nparams = LIBXL_NUMA_NPARAM;
    ret = 0;

 cleanup:
    VIR_FREE(nodeset);
    virBitmapFree(nodes);
    libxl_bitmap_dispose(&nodemap);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
#endif

static int
libxlDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int
libxlDomainIsPersistent(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int
libxlDomainIsUpdated(virDomainPtr dom)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = libxlDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsUpdatedEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->updated;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
libxlConnectDomainEventRegisterAny(virConnectPtr conn, virDomainPtr dom, int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque, virFreeCallback freecb)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID, callback, opaque,
                                      freecb, &ret) < 0)
        ret = -1;

    return ret;
}


static int
libxlConnectDomainEventDeregisterAny(virConnectPtr conn, int callbackID)
{
    libxlDriverPrivatePtr driver = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->domainEventState,
                                        callbackID) < 0)
        return -1;

    return 0;
}


static int
libxlConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int
libxlConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    libxlDriverPrivatePtr driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);

    return ret;
}

/* Which features are supported by this driver? */
static int
libxlConnectSupportsFeature(virConnectPtr conn, int feature)
{
    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    switch (feature) {
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
        return 1;
    default:
        return 0;
    }
}

static int
libxlNodeDeviceGetPCIInfo(virNodeDeviceDefPtr def,
                          unsigned *domain,
                          unsigned *bus,
                          unsigned *slot,
                          unsigned *function)
{
    virNodeDevCapsDefPtr cap;

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
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device %s is not a PCI device"), def->name);
        return -1;
    }

    return 0;
}

static int
libxlNodeDeviceDetachFlags(virNodeDevicePtr dev,
                           const char *driverName,
                           unsigned int flags)
{
    virPCIDevicePtr pci = NULL;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    libxlDriverPrivatePtr driver = dev->conn->privateData;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virCheckFlags(0, -1);

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceDetachFlagsEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (libxlNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    if (!driverName || STREQ(driverName, "xen")) {
        if (virPCIDeviceSetStubDriver(pci, "pciback") < 0)
            goto cleanup;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported driver name '%s'"), driverName);
        goto cleanup;
    }

    if (virHostdevPCINodeDeviceDetach(hostdev_mgr, pci) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
libxlNodeDeviceDettach(virNodeDevicePtr dev)
{
    return libxlNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
libxlNodeDeviceReAttach(virNodeDevicePtr dev)
{
    virPCIDevicePtr pci = NULL;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    libxlDriverPrivatePtr driver = dev->conn->privateData;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceReAttachEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (libxlNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    if (virHostdevPCINodeDeviceReAttach(hostdev_mgr, pci) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}

static int
libxlNodeDeviceReset(virNodeDevicePtr dev)
{
    virPCIDevicePtr pci = NULL;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;
    virNodeDeviceDefPtr def = NULL;
    char *xml = NULL;
    libxlDriverPrivatePtr driver = dev->conn->privateData;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    xml = virNodeDeviceGetXMLDesc(dev, 0);
    if (!xml)
        goto cleanup;

    def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL);
    if (!def)
        goto cleanup;

    if (virNodeDeviceResetEnsureACL(dev->conn, def) < 0)
        goto cleanup;

    if (libxlNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    pci = virPCIDeviceNew(domain, bus, slot, function);
    if (!pci)
        goto cleanup;

    if (virHostdevPCINodeDeviceReset(hostdev_mgr, pci) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    VIR_FREE(xml);
    return ret;
}


static virDriver libxlDriver = {
    .no = VIR_DRV_LIBXL,
    .name = LIBXL_DRIVER_NAME,
    .connectOpen = libxlConnectOpen, /* 0.9.0 */
    .connectClose = libxlConnectClose, /* 0.9.0 */
    .connectGetType = libxlConnectGetType, /* 0.9.0 */
    .connectGetVersion = libxlConnectGetVersion, /* 0.9.0 */
    .connectGetHostname = libxlConnectGetHostname, /* 0.9.0 */
    .connectGetSysinfo = libxlConnectGetSysinfo, /* 1.1.0 */
    .connectGetMaxVcpus = libxlConnectGetMaxVcpus, /* 0.9.0 */
    .nodeGetInfo = libxlNodeGetInfo, /* 0.9.0 */
    .connectGetCapabilities = libxlConnectGetCapabilities, /* 0.9.0 */
    .connectListDomains = libxlConnectListDomains, /* 0.9.0 */
    .connectNumOfDomains = libxlConnectNumOfDomains, /* 0.9.0 */
    .connectListAllDomains = libxlConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = libxlDomainCreateXML, /* 0.9.0 */
    .domainLookupByID = libxlDomainLookupByID, /* 0.9.0 */
    .domainLookupByUUID = libxlDomainLookupByUUID, /* 0.9.0 */
    .domainLookupByName = libxlDomainLookupByName, /* 0.9.0 */
    .domainSuspend = libxlDomainSuspend, /* 0.9.0 */
    .domainResume = libxlDomainResume, /* 0.9.0 */
    .domainShutdown = libxlDomainShutdown, /* 0.9.0 */
    .domainShutdownFlags = libxlDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = libxlDomainReboot, /* 0.9.0 */
    .domainDestroy = libxlDomainDestroy, /* 0.9.0 */
    .domainDestroyFlags = libxlDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = libxlDomainGetOSType, /* 0.9.0 */
    .domainGetMaxMemory = libxlDomainGetMaxMemory, /* 0.9.0 */
    .domainSetMaxMemory = libxlDomainSetMaxMemory, /* 0.9.2 */
    .domainSetMemory = libxlDomainSetMemory, /* 0.9.0 */
    .domainSetMemoryFlags = libxlDomainSetMemoryFlags, /* 0.9.0 */
    .domainGetInfo = libxlDomainGetInfo, /* 0.9.0 */
    .domainGetState = libxlDomainGetState, /* 0.9.2 */
    .domainSave = libxlDomainSave, /* 0.9.2 */
    .domainSaveFlags = libxlDomainSaveFlags, /* 0.9.4 */
    .domainRestore = libxlDomainRestore, /* 0.9.2 */
    .domainRestoreFlags = libxlDomainRestoreFlags, /* 0.9.4 */
    .domainCoreDump = libxlDomainCoreDump, /* 0.9.2 */
    .domainSetVcpus = libxlDomainSetVcpus, /* 0.9.0 */
    .domainSetVcpusFlags = libxlDomainSetVcpusFlags, /* 0.9.0 */
    .domainGetVcpusFlags = libxlDomainGetVcpusFlags, /* 0.9.0 */
    .domainPinVcpu = libxlDomainPinVcpu, /* 0.9.0 */
    .domainPinVcpuFlags = libxlDomainPinVcpuFlags, /* 1.2.1 */
    .domainGetVcpus = libxlDomainGetVcpus, /* 0.9.0 */
    .domainGetVcpuPinInfo = libxlDomainGetVcpuPinInfo, /* 1.2.1 */
    .domainGetXMLDesc = libxlDomainGetXMLDesc, /* 0.9.0 */
    .connectDomainXMLFromNative = libxlConnectDomainXMLFromNative, /* 0.9.0 */
    .connectDomainXMLToNative = libxlConnectDomainXMLToNative, /* 0.9.0 */
    .connectListDefinedDomains = libxlConnectListDefinedDomains, /* 0.9.0 */
    .connectNumOfDefinedDomains = libxlConnectNumOfDefinedDomains, /* 0.9.0 */
    .domainCreate = libxlDomainCreate, /* 0.9.0 */
    .domainCreateWithFlags = libxlDomainCreateWithFlags, /* 0.9.0 */
    .domainDefineXML = libxlDomainDefineXML, /* 0.9.0 */
    .domainUndefine = libxlDomainUndefine, /* 0.9.0 */
    .domainUndefineFlags = libxlDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = libxlDomainAttachDevice, /* 0.9.2 */
    .domainAttachDeviceFlags = libxlDomainAttachDeviceFlags, /* 0.9.2 */
    .domainDetachDevice = libxlDomainDetachDevice,    /* 0.9.2 */
    .domainDetachDeviceFlags = libxlDomainDetachDeviceFlags, /* 0.9.2 */
    .domainUpdateDeviceFlags = libxlDomainUpdateDeviceFlags, /* 0.9.2 */
    .domainGetAutostart = libxlDomainGetAutostart, /* 0.9.0 */
    .domainSetAutostart = libxlDomainSetAutostart, /* 0.9.0 */
    .domainGetSchedulerType = libxlDomainGetSchedulerType, /* 0.9.0 */
    .domainGetSchedulerParameters = libxlDomainGetSchedulerParameters, /* 0.9.0 */
    .domainGetSchedulerParametersFlags = libxlDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = libxlDomainSetSchedulerParameters, /* 0.9.0 */
    .domainSetSchedulerParametersFlags = libxlDomainSetSchedulerParametersFlags, /* 0.9.2 */
#ifdef LIBXL_HAVE_DOMAIN_NODEAFFINITY
    .domainGetNumaParameters = libxlDomainGetNumaParameters, /* 1.1.1 */
#endif
    .nodeGetFreeMemory = libxlNodeGetFreeMemory, /* 0.9.0 */
    .nodeGetCellsFreeMemory = libxlNodeGetCellsFreeMemory, /* 1.1.1 */
    .connectDomainEventRegister = libxlConnectDomainEventRegister, /* 0.9.0 */
    .connectDomainEventDeregister = libxlConnectDomainEventDeregister, /* 0.9.0 */
    .domainManagedSave = libxlDomainManagedSave, /* 0.9.2 */
    .domainHasManagedSaveImage = libxlDomainHasManagedSaveImage, /* 0.9.2 */
    .domainManagedSaveRemove = libxlDomainManagedSaveRemove, /* 0.9.2 */
    .domainOpenConsole = libxlDomainOpenConsole, /* 1.1.2 */
    .domainIsActive = libxlDomainIsActive, /* 0.9.0 */
    .domainIsPersistent = libxlDomainIsPersistent, /* 0.9.0 */
    .domainIsUpdated = libxlDomainIsUpdated, /* 0.9.0 */
    .connectDomainEventRegisterAny = libxlConnectDomainEventRegisterAny, /* 0.9.0 */
    .connectDomainEventDeregisterAny = libxlConnectDomainEventDeregisterAny, /* 0.9.0 */
    .connectIsAlive = libxlConnectIsAlive, /* 0.9.8 */
    .connectSupportsFeature = libxlConnectSupportsFeature, /* 1.1.1 */
    .nodeDeviceDettach = libxlNodeDeviceDettach, /* 1.2.3 */
    .nodeDeviceDetachFlags = libxlNodeDeviceDetachFlags, /* 1.2.3 */
    .nodeDeviceReAttach = libxlNodeDeviceReAttach, /* 1.2.3 */
    .nodeDeviceReset = libxlNodeDeviceReset, /* 1.2.3 */
};

static virStateDriver libxlStateDriver = {
    .name = "LIBXL",
    .stateInitialize = libxlStateInitialize,
    .stateAutoStart = libxlStateAutoStart,
    .stateCleanup = libxlStateCleanup,
    .stateReload = libxlStateReload,
};


int
libxlRegister(void)
{
    if (virRegisterDriver(&libxlDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&libxlStateDriver) < 0)
        return -1;

    return 0;
}
