/*
 * bhyve_driver.c: core driver methods for managing bhyve guests
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 * Author: Roman Bogorodskiy
 */

#include <config.h>

#include <sys/utsname.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "capabilities.h"
#include "configmake.h"
#include "viralloc.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "domain_audit.h"
#include "domain_conf.h"
#include "snapshot_conf.h"
#include "fdstream.h"
#include "storage_conf.h"
#include "node_device_conf.h"
#include "virxml.h"
#include "virthread.h"
#include "virlog.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virrandom.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "viraccessapicheck.h"
#include "nodeinfo.h"

#include "bhyve_driver.h"
#include "bhyve_process.h"
#include "bhyve_utils.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_driver");

bhyveConnPtr bhyve_driver = NULL;

void
bhyveDriverLock(bhyveConnPtr driver)
{
    virMutexLock(&driver->lock);
}

void
bhyveDriverUnlock(bhyveConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static virCapsPtr
bhyveBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   0, 0)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm",
                                         VIR_ARCH_X86_64,
                                         "bhyve",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "bhyve", NULL, NULL, 0, NULL) == NULL)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

static char *
bhyveConnectGetCapabilities(virConnectPtr conn)
{
    bhyveConnPtr privconn = conn->privateData;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL)
        virReportOOMError();

    return xml;
}

static virDomainObjPtr
bhyveDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    bhyveConnPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

static virDrvOpenStatus
bhyveConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 unsigned int flags)
{
     virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

     if (conn->uri == NULL) {
         if (bhyve_driver == NULL)
             return VIR_DRV_OPEN_DECLINED;

         if (!(conn->uri = virURIParse("bhyve:///system")))
             return VIR_DRV_OPEN_ERROR;
     } else {
         if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "bhyve"))
             return VIR_DRV_OPEN_DECLINED;

         if (conn->uri->server)
             return VIR_DRV_OPEN_DECLINED;

         if (!STREQ_NULLABLE(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected bhyve URI path '%s', try bhyve:///system"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
         }

         if (bhyve_driver == NULL) {
             virReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("bhyve state driver is not active"));
             return VIR_DRV_OPEN_ERROR;
         }
     }

     if (virConnectOpenEnsureACL(conn) < 0)
         return VIR_DRV_OPEN_ERROR;

     conn->privateData = bhyve_driver;

     return VIR_DRV_OPEN_SUCCESS;
}

static int
bhyveConnectClose(virConnectPtr conn)
{
    bhyveConnPtr privconn = conn->privateData;

    virCloseCallbacksRun(privconn->closeCallbacks, conn, privconn->domains, privconn);
    conn->privateData = NULL;

    return 0;
}

static char *
bhyveConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static int
bhyveConnectGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *version)
{
    struct utsname ver;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    uname(&ver);

    if (virParseVersionString(ver.release, version, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown release: %s"), ver.release);
        return -1;
    }

    return 0;
}

static int
bhyveDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);
    info->maxMem = vm->def->mem.max_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainGetState(virDomainPtr domain,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(domain->conn, vm->def) < 0)
       goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainIsActive(virDomainPtr domain)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virObjectUnlock(obj);
    return ret;
}

static int
bhyveDomainIsPersistent(virDomainPtr domain)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    virObjectUnlock(obj);
    return ret;
}

static char *
bhyveDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(domain->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, flags);

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
bhyveDomainDefineXML(virConnectPtr conn, const char *xml)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainPtr dom = NULL;
    virDomainDefPtr def = NULL;
    virDomainDefPtr oldDef = NULL;
    virDomainObjPtr vm = NULL;

    if ((def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_BHYVE,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (virDomainDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, def,
                                   privconn->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    if (virDomainSaveConfig(BHYVE_CONFIG_DIR, vm->def) < 0)
        goto cleanup;

 cleanup:
    virDomainDefFree(def);
    virObjectUnlock(vm);

    return dom;
}

static int
bhyveDomainUndefine(virDomainPtr domain)
{
    bhyveConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainUndefineEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(BHYVE_CONFIG_DIR,
                              BHYVE_AUTOSTART_DIR,
                              vm) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
bhyveConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    bhyveConnPtr privconn = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int
bhyveConnectNumOfDomains(virConnectPtr conn)
{
    bhyveConnPtr privconn = conn->privateData;
    int count;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    count = virDomainObjListNumOfDomains(privconn->domains, true,
                                         virConnectNumOfDomainsCheckACL, conn);

    return count;
}

static int
bhyveConnectListDefinedDomains(virConnectPtr conn, char **const names,
                               int maxnames)
{
    bhyveConnPtr privconn = conn->privateData;
    int n;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    memset(names, 0, sizeof(*names) * maxnames);
    n = virDomainObjListGetInactiveNames(privconn->domains, names,
                                         maxnames, virConnectListDefinedDomainsCheckACL, conn);

    return n;
}

static int
bhyveConnectNumOfDefinedDomains(virConnectPtr conn)
{
    bhyveConnPtr privconn = conn->privateData;
    int count;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    count = virDomainObjListNumOfDomains(privconn->domains, false,
                                         virConnectNumOfDefinedDomainsCheckACL, conn);

    return count;
}

static int
bhyveConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    bhyveConnPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    ret = virDomainObjListExport(privconn->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);

    return ret;
}

static virDomainPtr
bhyveDomainLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(privconn->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virObjectUnlock(vm);
    return dom;
}

static virDomainPtr bhyveDomainLookupByName(virConnectPtr conn,
                                            const char *name)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(privconn->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virObjectUnlock(vm);
    return dom;
}

static virDomainPtr
bhyveDomainLookupByID(virConnectPtr conn,
                      int id)
{
    bhyveConnPtr privconn = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(privconn->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching ID '%d'"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

 cleanup:
    virObjectUnlock(vm);
    return dom;
}

static int
bhyveDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    bhyveConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned int start_flags = 0;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_BHYVE_PROCESS_START_AUTODESTROY;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = virBhyveProcessStart(dom->conn, privconn, vm,
                               VIR_DOMAIN_RUNNING_BOOTED,
                               start_flags);

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
bhyveDomainCreate(virDomainPtr dom)
{
    return bhyveDomainCreateWithFlags(dom, 0);
}

static int
bhyveDomainDestroy(virDomainPtr dom)
{
    bhyveConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = bhyveDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    ret = virBhyveProcessStop(privconn, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);

 cleanup:
    virObjectUnlock(vm);
    return ret;
}

static int
bhyveNodeGetCPUStats(virConnectPtr conn,
                     int cpuNum,
                     virNodeCPUStatsPtr params,
                     int *nparams,
                     unsigned int flags)
{
    if (virNodeGetCPUStatsEnsureACL(conn) < 0)
        return -1;

    return nodeGetCPUStats(cpuNum, params, nparams, flags);
}

static int
bhyveNodeGetMemoryStats(virConnectPtr conn,
                        int cellNum,
                        virNodeMemoryStatsPtr params,
                        int *nparams,
                        unsigned int flags)
{
    if (virNodeGetMemoryStatsEnsureACL(conn) < 0)
        return -1;

    return nodeGetMemoryStats(cellNum, params, nparams, flags);
}

static int
bhyveNodeGetInfo(virConnectPtr conn,
                      virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return nodeGetInfo(nodeinfo);
}

static int
bhyveStateCleanup(void)
{
    VIR_DEBUG("bhyve state cleanup");

    if (bhyve_driver == NULL)
        return -1;

    virObjectUnref(bhyve_driver->domains);
    virObjectUnref(bhyve_driver->caps);
    virObjectUnref(bhyve_driver->xmlopt);
    virObjectUnref(bhyve_driver->closeCallbacks);

    virMutexDestroy(&bhyve_driver->lock);
    VIR_FREE(bhyve_driver);

    return 0;
}

static int
bhyveStateInitialize(bool priveleged ATTRIBUTE_UNUSED,
                     virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                     void *opaque ATTRIBUTE_UNUSED)
{
    if (!priveleged) {
        VIR_INFO("Not running priveleged, disabling driver");
        return 0;
    }

    if (VIR_ALLOC(bhyve_driver) < 0) {
        return -1;
    }

    if (virMutexInit(&bhyve_driver->lock) < 0) {
        VIR_FREE(bhyve_driver);
        return -1;
    }

    if (!(bhyve_driver->closeCallbacks = virCloseCallbacksNew()))
        goto cleanup;

    if (!(bhyve_driver->caps = bhyveBuildCapabilities()))
        goto cleanup;

    if (!(bhyve_driver->xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL)))
        goto cleanup;

    if (!(bhyve_driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (virFileMakePath(BHYVE_LOG_DIR) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %s"),
                             BHYVE_LOG_DIR);
        goto cleanup;
    }

    if (virFileMakePath(BHYVE_STATE_DIR) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %s"),
                             BHYVE_LOG_DIR);
        goto cleanup;
    }

    if (virDomainObjListLoadAllConfigs(bhyve_driver->domains,
                                       BHYVE_CONFIG_DIR,
                                       NULL, 0,
                                       bhyve_driver->caps,
                                       bhyve_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_BHYVE,
                                       NULL, NULL) < 0)
        goto cleanup;

    return 0;

 cleanup:
    bhyveStateCleanup();
    return -1;
}

static int
bhyveConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                        const char *type)
{
    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    /*
     * Bhyve supports up to 16 VCPUs, but offers no method to check this
     * value. Hardcode 16...
     */
    if (!type || STRCASEEQ(type, "bhyve"))
        return 16;

    virReportError(VIR_ERR_INVALID_ARG, _("unknown type '%s'"), type);
    return -1;
}

static unsigned long long
bhyveNodeGetFreeMemory(virConnectPtr conn)
{
    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    return nodeGetFreeMemory();
}

static int
bhyveNodeGetCPUMap(virConnectPtr conn,
                   unsigned char **cpumap,
                   unsigned int *online,
                   unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return nodeGetCPUMap(cpumap, online, flags);
}

static int
bhyveNodeGetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeGetMemoryParameters(params, nparams, flags);
}

static int
bhyveNodeSetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeSetMemoryParameters(params, nparams, flags);
}

static virDriver bhyveDriver = {
    .no = VIR_DRV_BHYVE,
    .name = "bhyve",
    .connectOpen = bhyveConnectOpen, /* 1.2.2 */
    .connectClose = bhyveConnectClose, /* 1.2.2 */
    .connectGetVersion = bhyveConnectGetVersion, /* 1.2.2 */
    .connectGetHostname = bhyveConnectGetHostname, /* 1.2.2 */
    .domainGetInfo = bhyveDomainGetInfo, /* 1.2.2 */
    .domainGetState = bhyveDomainGetState, /* 1.2.2 */
    .connectGetCapabilities = bhyveConnectGetCapabilities, /* 1.2.2 */
    .connectListDomains = bhyveConnectListDomains, /* 1.2.2 */
    .connectNumOfDomains = bhyveConnectNumOfDomains, /* 1.2.2 */
    .connectListAllDomains = bhyveConnectListAllDomains, /* 1.2.2 */
    .connectListDefinedDomains = bhyveConnectListDefinedDomains, /* 1.2.2 */
    .connectNumOfDefinedDomains = bhyveConnectNumOfDefinedDomains, /* 1.2.2 */
    .domainCreate = bhyveDomainCreate, /* 1.2.2 */
    .domainCreateWithFlags = bhyveDomainCreateWithFlags, /* 1.2.3 */
    .domainDestroy = bhyveDomainDestroy, /* 1.2.2 */
    .domainLookupByUUID = bhyveDomainLookupByUUID, /* 1.2.2 */
    .domainLookupByName = bhyveDomainLookupByName, /* 1.2.2 */
    .domainLookupByID = bhyveDomainLookupByID, /* 1.2.3 */
    .domainDefineXML = bhyveDomainDefineXML, /* 1.2.2 */
    .domainUndefine = bhyveDomainUndefine, /* 1.2.2 */
    .domainGetXMLDesc = bhyveDomainGetXMLDesc, /* 1.2.2 */
    .domainIsActive = bhyveDomainIsActive, /* 1.2.2 */
    .domainIsPersistent = bhyveDomainIsPersistent, /* 1.2.2 */
    .nodeGetCPUStats = bhyveNodeGetCPUStats, /* 1.2.2 */
    .nodeGetMemoryStats = bhyveNodeGetMemoryStats, /* 1.2.2 */
    .nodeGetInfo = bhyveNodeGetInfo, /* 1.2.3 */
    .connectGetMaxVcpus = bhyveConnectGetMaxVcpus, /* 1.2.3 */
    .nodeGetFreeMemory = bhyveNodeGetFreeMemory, /* 1.2.3 */
    .nodeGetCPUMap = bhyveNodeGetCPUMap, /* 1.2.3 */
    .nodeGetMemoryParameters = bhyveNodeGetMemoryParameters, /* 1.2.3 */
    .nodeSetMemoryParameters = bhyveNodeSetMemoryParameters, /* 1.2.3 */
};


static virStateDriver bhyveStateDriver = {
    .name = "bhyve",
    .stateInitialize = bhyveStateInitialize,
    .stateCleanup = bhyveStateCleanup,
};

int
bhyveRegister(void)
{
     if (virRegisterDriver(&bhyveDriver) < 0)
        return -1;
     if (virRegisterStateDriver(&bhyveStateDriver) < 0)
        return -1;
     return 0;
}
