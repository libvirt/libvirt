/*
 * Copyright (C) 2010-2013 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_driver.c: linux container driver functions
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 */

#include <config.h>

#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <wait.h>

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"
#include "lxc_cgroup.h"
#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_domain.h"
#include "lxc_driver.h"
#include "lxc_process.h"
#include "viralloc.h"
#include "virnetdevbridge.h"
#include "virnetdevveth.h"
#include "nodeinfo.h"
#include "viruuid.h"
#include "virstatslinux.h"
#include "virhook.h"
#include "virfile.h"
#include "virpidfile.h"
#include "fdstream.h"
#include "domain_audit.h"
#include "domain_nwfilter.h"
#include "nwfilter_conf.h"
#include "network/bridge_driver.h"
#include "virinitctl.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnodesuspend.h"
#include "virprocess.h"
#include "virtime.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "virstring.h"
#include "viraccessapicheck.h"
#include "viraccessapichecklxc.h"

#define VIR_FROM_THIS VIR_FROM_LXC


#define LXC_NB_MEM_PARAM  3

static int lxcStateInitialize(bool privileged,
                              virStateInhibitCallback callback,
                              void *opaque);
static int lxcStateCleanup(void);
virLXCDriverPtr lxc_driver = NULL;

/* callbacks for nwfilter */
static int
lxcVMFilterRebuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                   virDomainObjListIterator iter, void *data)
{
    return virDomainObjListForEach(lxc_driver->domains, iter, data);
}

static void
lxcVMDriverLock(void)
{
    lxcDriverLock(lxc_driver);
}

static void
lxcVMDriverUnlock(void)
{
    lxcDriverUnlock(lxc_driver);
}

static virNWFilterCallbackDriver lxcCallbackDriver = {
    .name = "LXC",
    .vmFilterRebuild = lxcVMFilterRebuild,
    .vmDriverLock = lxcVMDriverLock,
    .vmDriverUnlock = lxcVMDriverUnlock,
};

/**
 * lxcDomObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate
 * virDomainObjPtr.
 *
 * Returns the domain object which is locked on success, NULL
 * otherwise.
 */
static virDomainObjPtr
lxcDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    virLXCDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

/* Functions */

static virDrvOpenStatus lxcConnectOpen(virConnectPtr conn,
                                       virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                       unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* Verify uri was specified */
    if (conn->uri == NULL) {
        if (lxc_driver == NULL)
            return VIR_DRV_OPEN_DECLINED;

        if (!(conn->uri = virURIParse("lxc:///")))
            return VIR_DRV_OPEN_ERROR;
    } else {
        if (conn->uri->scheme == NULL ||
            STRNEQ(conn->uri->scheme, "lxc"))
            return VIR_DRV_OPEN_DECLINED;

        /* Leave for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't '/' then they typoed, tell them correct path */
        if (conn->uri->path != NULL &&
            STRNEQ(conn->uri->path, "/")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected LXC URI path '%s', try lxc:///"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        /* URI was good, but driver isn't active */
        if (lxc_driver == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("lxc state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = lxc_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int lxcConnectClose(virConnectPtr conn)
{
    virLXCDriverPtr driver = conn->privateData;

    virCloseCallbacksRun(driver->closeCallbacks, conn, driver->domains, driver);
    conn->privateData = NULL;
    return 0;
}


static int lxcConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int lxcConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int lxcConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}


static char *lxcConnectGetCapabilities(virConnectPtr conn) {
    virLXCDriverPtr driver = conn->privateData;
    virCapsPtr caps;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        return NULL;

    if ((xml = virCapabilitiesFormatXML(caps)) == NULL)
        virReportOOMError();

    virObjectUnref(caps);
    return xml;
}


static virDomainPtr lxcDomainLookupByID(virConnectPtr conn,
                                        int id)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching id %d"), id);
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

static virDomainPtr lxcDomainLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);

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
    if (vm)
        virObjectUnlock(vm);
    return dom;
}

static virDomainPtr lxcDomainLookupByName(virConnectPtr conn,
                                          const char *name)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching name '%s'"), name);
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


static int lxcDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}


static int lxcDomainIsPersistent(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int lxcDomainIsUpdated(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainIsUpdatedEnsureACL(dom->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->updated;

cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int lxcConnectListDomains(virConnectPtr conn, int *ids, int nids) {
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int lxcConnectNumOfDomains(virConnectPtr conn) {
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, conn);

    return n;
}

static int lxcConnectListDefinedDomains(virConnectPtr conn,
                                        char **const names, int nnames) {
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                         virConnectListDefinedDomainsCheckACL, conn);

    return n;
}


static int lxcConnectNumOfDefinedDomains(virConnectPtr conn) {
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, false,
                                     virConnectNumOfDefinedDomainsCheckACL, conn);

    return n;
}



static virDomainPtr lxcDomainDefineXML(virConnectPtr conn, const char *xml)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virCapsPtr caps = NULL;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_LXC,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if ((def->nets != NULL) && !(cfg->have_netns)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(cfg->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}

static int lxcDomainUndefineFlags(virDomainPtr dom,
                                  unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(cfg->configDir,
                              cfg->autostartDir,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

static int lxcDomainUndefine(virDomainPtr dom)
{
    return lxcDomainUndefineFlags(dom, 0);
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    virDomainObjPtr vm;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetInfoEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);

    if (!virDomainObjIsActive(vm)) {
        info->cpuTime = 0;
        info->memory = vm->def->mem.cur_balloon;
    } else {
        if (virCgroupGetCpuacctUsage(priv->cgroup, &(info->cpuTime)) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("Cannot read cputime for domain"));
            goto cleanup;
        }
        if (virCgroupGetMemoryUsage(priv->cgroup, &(info->memory)) < 0) {
            /* Don't fail if we can't read memory usage due to a lack of
             * kernel support */
            if (virLastErrorIsSystemErrno(ENOENT)) {
                virResetLastError();
                info->memory = 0;
            } else {
                goto cleanup;
            }
        }
    }

    info->maxMem = vm->def->mem.max_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
lxcDomainGetState(virDomainPtr dom,
                  int *state,
                  int *reason,
                  unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
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

static char *lxcDomainGetOSType(virDomainPtr dom)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (VIR_STRDUP(ret, vm->def->os.type) < 0)
        goto cleanup;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/* Returns max memory in kb, 0 if error */
static unsigned long long
lxcDomainGetMaxMemory(virDomainPtr dom)
{
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int lxcDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetMaxMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (newmax < vm->def->mem.cur_balloon) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Cannot set max memory lower than current memory"));
        goto cleanup;
    }

    vm->def->mem.max_balloon = newmax;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int lxcDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    virDomainObjPtr vm;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSetMemoryEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (newmem > vm->def->mem.max_balloon) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (virCgroupSetMemory(priv->cgroup, newmem) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("Failed to set memory for domain"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
lxcDomainSetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    size_t i;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_MEMORY_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                               VIR_TYPED_PARAM_ULLONG,
                               NULL) < 0)
        return -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSetMemoryParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            if (virCgroupSetMemoryHardLimit(priv->cgroup, params[i].value.ul) < 0)
                ret = -1;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            if (virCgroupSetMemorySoftLimit(priv->cgroup, params[i].value.ul) < 0)
                ret = -1;
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT)) {
            if (virCgroupSetMemSwapHardLimit(priv->cgroup, params[i].value.ul) < 0)
                ret = -1;
        }
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
lxcDomainGetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    size_t i;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetMemoryParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = LXC_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < LXC_NB_MEM_PARAM && i < *nparams; i++) {
        virTypedParameterPtr param = &params[i];
        val = 0;

        switch (i) {
        case 0: /* fill memory hard limit here */
            if (virCgroupGetMemoryHardLimit(priv->cgroup, &val) < 0)
                goto cleanup;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 1: /* fill memory soft limit here */
            if (virCgroupGetMemorySoftLimit(priv->cgroup, &val) < 0)
                goto cleanup;
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 2: /* fill swap hard limit here */
            if (virCgroupGetMemSwapHardLimit(priv->cgroup, &val) < 0)
                goto cleanup;
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        /* coverity[dead_error_begin] */
        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > LXC_NB_MEM_PARAM)
        *nparams = LXC_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static char *lxcDomainGetXMLDesc(virDomainPtr dom,
                                 unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             flags);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

/**
 * lxcDomainCreateWithFlags:
 * @dom: domain to start
 * @flags: Must be 0 for now
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainCreateWithFiles(virDomainPtr dom,
                                    unsigned int nfiles,
                                    int *files,
                                    unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFilesEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((vm->def->nets != NULL) && !(cfg->have_netns)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = virLXCProcessStart(dom->conn, driver, vm,
                             nfiles, files,
                             (flags & VIR_DOMAIN_START_AUTODESTROY),
                             VIR_DOMAIN_RUNNING_BOOTED);

    if (ret == 0) {
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
        virDomainAuditStart(vm, "booted", true);
    } else {
        virDomainAuditStart(vm, "booted", false);
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    return ret;
}

/**
 * lxcDomainCreate:
 * @dom: domain to start
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainCreate(virDomainPtr dom)
{
    return lxcDomainCreateWithFiles(dom, 0, NULL, 0);
}

/**
 * lxcDomainCreateWithFlags:
 * @dom: domain to start
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainCreateWithFlags(virDomainPtr dom,
                                    unsigned int flags)
{
    return lxcDomainCreateWithFiles(dom, 0, NULL, flags);
}

/**
 * lxcDomainCreateXML:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: Must be 0 for now
 *
 * Creates a domain based on xml and starts it
 *
 * Returns 0 on success or -1 in case of error
 */
static virDomainPtr
lxcDomainCreateXMLWithFiles(virConnectPtr conn,
                            const char *xml,
                            unsigned int nfiles,
                            int *files,
                            unsigned int flags) {
    virLXCDriverPtr driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virCapsPtr caps = NULL;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, NULL);

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        1 << VIR_DOMAIN_VIRT_LXC,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virDomainCreateXMLWithFilesEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if ((def->nets != NULL) && !(cfg->have_netns)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("System lacks NETNS support"));
        goto cleanup;
    }


    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    def = NULL;

    if (virLXCProcessStart(conn, driver, vm,
                           nfiles, files,
                           (flags & VIR_DOMAIN_START_AUTODESTROY),
                           VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        virDomainAuditStart(vm, "booted", false);
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}


static virDomainPtr
lxcDomainCreateXML(virConnectPtr conn,
                   const char *xml,
                   unsigned int flags) {
    return lxcDomainCreateXMLWithFiles(conn, xml, 0, NULL,  flags);
}


static int lxcDomainGetSecurityLabel(virDomainPtr dom, virSecurityLabelPtr seclabel)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    memset(seclabel, 0, sizeof(*seclabel));

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSecurityLabelEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainVirtTypeToString(vm->def->virtType)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown virt type in domain definition '%d'"),
                       vm->def->virtType);
        goto cleanup;
    }

    /*
     * Theoretically, the pid can be replaced during this operation and
     * return the label of a different process.  If atomicity is needed,
     * further validation will be required.
     *
     * Comment from Dan Berrange:
     *
     *   Well the PID as stored in the virDomainObjPtr can't be changed
     *   because you've got a locked object.  The OS level PID could have
     *   exited, though and in extreme circumstances have cycled through all
     *   PIDs back to ours. We could sanity check that our PID still exists
     *   after reading the label, by checking that our FD connecting to the
     *   LXC monitor hasn't seen SIGHUP/ERR on poll().
     */
    if (virDomainObjIsActive(vm)) {
        virLXCDomainObjPrivatePtr priv = vm->privateData;

        if (!priv->initpid) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Init pid is not yet available"));
            goto cleanup;
        }

        if (virSecurityManagerGetProcessLabel(driver->securityManager,
                                              vm->def, priv->initpid, seclabel) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to get security label"));
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int lxcNodeGetSecurityModel(virConnectPtr conn,
                                   virSecurityModelPtr secmodel)
{
    virLXCDriverPtr driver = conn->privateData;
    virCapsPtr caps = NULL;
    int ret = 0;

    memset(secmodel, 0, sizeof(*secmodel));

    if (virNodeGetSecurityModelEnsureACL(conn) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* we treat no driver as success, but simply return no data in *secmodel */
    if (caps->host.nsecModels == 0
        || caps->host.secModels[0].model == NULL)
        goto cleanup;

    if (!virStrcpy(secmodel->model, caps->host.secModels[0].model,
                   VIR_SECURITY_MODEL_BUFLEN)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security model string exceeds max %d bytes"),
                       VIR_SECURITY_MODEL_BUFLEN - 1);
        ret = -1;
        goto cleanup;
    }

    if (!virStrcpy(secmodel->doi, caps->host.secModels[0].doi,
                   VIR_SECURITY_DOI_BUFLEN)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security DOI string exceeds max %d bytes"),
                       VIR_SECURITY_DOI_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }

cleanup:
    virObjectUnref(caps);
    return ret;
}


static int
lxcConnectDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback callback,
                              void *opaque,
                              virFreeCallback freecb)
{
    virLXCDriverPtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    ret = virDomainEventStateRegister(conn,
                                      driver->domainEventState,
                                      callback, opaque, freecb);

    return ret;
}


static int
lxcConnectDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback callback)
{
    virLXCDriverPtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    ret = virDomainEventStateDeregister(conn,
                                        driver->domainEventState,
                                        callback);

    return ret;
}


static int
lxcConnectDomainEventRegisterAny(virConnectPtr conn,
                                 virDomainPtr dom,
                                 int eventID,
                                 virConnectDomainEventGenericCallback callback,
                                 void *opaque,
                                 virFreeCallback freecb)
{
    virLXCDriverPtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}


static int
lxcConnectDomainEventDeregisterAny(virConnectPtr conn,
                                   int callbackID)
{
    virLXCDriverPtr driver = conn->privateData;
    int ret;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    ret = virDomainEventStateDeregisterID(conn,
                                          driver->domainEventState,
                                          callbackID);

    return ret;
}


/**
 * lxcDomainDestroyFlags:
 * @dom: pointer to domain to destroy
 * @flags: an OR'ed set of virDomainDestroyFlags
 *
 * Sends SIGKILL to container root process to terminate the container
 *
 * Returns 0 on success or -1 in case of error
 */
static int
lxcDomainDestroyFlags(virDomainPtr dom,
                      unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    priv = vm->privateData;
    ret = virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;
    virDomainAuditStop(vm, "destroyed");
    if (!vm->persistent) {
        virDomainObjListRemove(driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    return ret;
}

/**
 * lxcDomainDestroy:
 * @dom: pointer to domain to destroy
 *
 * Sends SIGKILL to container root process to terminate the container
 *
 * Returns 0 on success or -1 in case of error
 */
static int
lxcDomainDestroy(virDomainPtr dom)
{
    return lxcDomainDestroyFlags(dom, 0);
}

static int lxcCheckNetNsSupport(void)
{
    const char *argv[] = {"ip", "link", "set", "lo", "netns", "-1", NULL};
    int ip_rc;

    if (virRun(argv, &ip_rc) < 0 ||
        !(WIFEXITED(ip_rc) && (WEXITSTATUS(ip_rc) != 255)))
        return 0;

    if (lxcContainerAvailable(LXC_CONTAINER_FEATURE_NET) < 0)
        return 0;

    return 1;
}


static virSecurityManagerPtr
lxcSecurityInit(virLXCDriverConfigPtr cfg)
{
    VIR_INFO("lxcSecurityInit %s", cfg->securityDriverName);
    virSecurityManagerPtr mgr = virSecurityManagerNew(cfg->securityDriverName,
                                                      LXC_DRIVER_NAME,
                                                      false,
                                                      cfg->securityDefaultConfined,
                                                      cfg->securityRequireConfined);
    if (!mgr)
        goto error;

    return mgr;

error:
    VIR_ERROR(_("Failed to initialize security drivers"));
    virObjectUnref(mgr);
    return NULL;
}


static int lxcStateInitialize(bool privileged,
                              virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    virCapsPtr caps = NULL;
    char *ld;
    virLXCDriverConfigPtr cfg = NULL;

    /* Valgrind gets very annoyed when we clone containers, so
     * disable LXC when under valgrind
     * XXX remove this when valgrind is fixed
     */
    ld = getenv("LD_PRELOAD");
    if (ld && strstr(ld, "vgpreload")) {
        VIR_INFO("Running under valgrind, disabling driver");
        return 0;
    }

    /* Check that the user is root, silently disable if not */
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return 0;
    }

    /* Check that this is a container enabled kernel */
    if (lxcContainerAvailable(0) < 0) {
        VIR_INFO("LXC support not available in this kernel, disabling driver");
        return 0;
    }

    if (VIR_ALLOC(lxc_driver) < 0) {
        return -1;
    }
    if (virMutexInit(&lxc_driver->lock) < 0) {
        VIR_FREE(lxc_driver);
        return -1;
    }

    if (!(lxc_driver->domains = virDomainObjListNew()))
        goto cleanup;

    lxc_driver->domainEventState = virDomainEventStateNew();
    if (!lxc_driver->domainEventState)
        goto cleanup;

    lxc_driver->hostsysinfo = virSysinfoRead();

    if (!(lxc_driver->config = cfg = virLXCDriverConfigNew()))
        goto cleanup;

    cfg->log_libvirtd = 0; /* by default log to container logfile */
    cfg->have_netns = lxcCheckNetNsSupport();

    /* Call function to load lxc driver configuration information */
    if (virLXCLoadDriverConfig(cfg, SYSCONFDIR "/libvirt/lxc.conf") < 0)
        goto cleanup;

    if (!(lxc_driver->securityManager = lxcSecurityInit(cfg)))
        goto cleanup;

    if ((lxc_driver->activeUsbHostdevs = virUSBDeviceListNew()) == NULL)
        goto cleanup;

    if ((virLXCDriverGetCapabilities(lxc_driver, true)) == NULL)
        goto cleanup;

    if (!(lxc_driver->xmlopt = lxcDomainXMLConfInit()))
        goto cleanup;

    if (!(lxc_driver->closeCallbacks = virCloseCallbacksNew()))
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(lxc_driver, false)))
        goto cleanup;

    /* Get all the running persistent or transient configs first */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->stateDir,
                                       NULL, 1,
                                       caps,
                                       lxc_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_LXC,
                                       NULL, NULL) < 0)
        goto cleanup;

    virLXCProcessReconnectAll(lxc_driver, lxc_driver->domains);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, 0,
                                       caps,
                                       lxc_driver->xmlopt,
                                       1 << VIR_DOMAIN_VIRT_LXC,
                                       NULL, NULL) < 0)
        goto cleanup;

    virNWFilterRegisterCallbackDriver(&lxcCallbackDriver);
    return 0;

cleanup:
    virObjectUnref(caps);
    lxcStateCleanup();
    return -1;
}

/**
 * lxcStateAutoStart:
 *
 * Function to autostart the LXC daemons
 */
static void lxcStateAutoStart(void)
{
    if (!lxc_driver)
        return;

    virLXCProcessAutostartAll(lxc_driver);
}

static void lxcNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    virLXCDriverPtr driver = opaque;

    if (newVM) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
            virDomainEventStateQueue(driver->domainEventState, event);
    }
}

/**
 * lxcStateReload:
 *
 * Function to restart the LXC driver, it will recheck the configuration
 * files and perform autostart
 */
static int
lxcStateReload(void) {
    virLXCDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;

    if (!lxc_driver)
        return 0;

    if (!(caps = virLXCDriverGetCapabilities(lxc_driver, false)))
        return -1;

    cfg = virLXCDriverGetConfig(lxc_driver);

    virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                   cfg->configDir,
                                   cfg->autostartDir, 0,
                                   caps,
                                   lxc_driver->xmlopt,
                                   1 << VIR_DOMAIN_VIRT_LXC,
                                   lxcNotifyLoadDomain, lxc_driver);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return 0;
}

static int lxcStateCleanup(void)
{
    if (lxc_driver == NULL)
        return -1;

    virNWFilterUnRegisterCallbackDriver(&lxcCallbackDriver);
    virObjectUnref(lxc_driver->domains);
    virDomainEventStateFree(lxc_driver->domainEventState);

    virObjectUnref(lxc_driver->closeCallbacks);

    virSysinfoDefFree(lxc_driver->hostsysinfo);

    virObjectUnref(lxc_driver->activeUsbHostdevs);
    virObjectUnref(lxc_driver->caps);
    virObjectUnref(lxc_driver->securityManager);
    virObjectUnref(lxc_driver->xmlopt);
    virObjectUnref(lxc_driver->config);
    virMutexDestroy(&lxc_driver->lock);
    VIR_FREE(lxc_driver);

    return 0;
}


static int lxcConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct utsname ver;

    uname(&ver);

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    if (virParseVersionString(ver.release, version, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Unknown release: %s"), ver.release);
        return -1;
    }

    return 0;
}


static char *lxcConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}



/*
 * check whether the host supports CFS bandwidth
 *
 * Return 1 when CFS bandwidth is supported, 0 when CFS bandwidth is not
 * supported, -1 on error.
 */
static int lxcGetCpuBWStatus(virCgroupPtr cgroup)
{
    char *cfs_period_path = NULL;
    int ret = -1;

    if (!cgroup)
        return 0;

    if (virCgroupPathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                  "cpu.cfs_period_us", &cfs_period_path) < 0) {
        VIR_INFO("cannot get the path of cgroup CPU controller");
        ret = 0;
        goto cleanup;
    }

    if (access(cfs_period_path, F_OK) < 0) {
        ret = 0;
    } else {
        ret = 1;
    }

cleanup:
    VIR_FREE(cfs_period_path);
    return ret;
}


static char *lxcDomainGetSchedulerType(virDomainPtr dom,
                                       int *nparams)
{
    char *ret = NULL;
    int rc;
    virDomainObjPtr vm;
    virLXCDomainObjPrivatePtr priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* Domain not running, thus no cgroups - return defaults */
    if (!virDomainObjIsActive(vm)) {
        if (nparams)
            *nparams = 3;
        ignore_value(VIR_STRDUP(ret, "posix"));
        goto cleanup;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (nparams) {
        rc = lxcGetCpuBWStatus(priv->cgroup);
        if (rc < 0)
            goto cleanup;
        else if (rc == 0)
            *nparams = 1;
        else
            *nparams = 3;
    }

    ignore_value(VIR_STRDUP(ret, "posix"));

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
lxcGetVcpuBWLive(virCgroupPtr cgroup, unsigned long long *period,
                 long long *quota)
{
    if (virCgroupGetCpuCfsPeriod(cgroup, period) < 0)
        return -1;

    if (virCgroupGetCpuCfsQuota(cgroup, quota) < 0)
        return -1;

    return 0;
}


static int lxcSetVcpuBWLive(virCgroupPtr cgroup, unsigned long long period,
                            long long quota)
{
    unsigned long long old_period;

    if (period == 0 && quota == 0)
        return 0;

    if (period) {
        /* get old period, and we can rollback if set quota failed */
        if (virCgroupGetCpuCfsPeriod(cgroup, &old_period) < 0)
            return -1;

        if (virCgroupSetCpuCfsPeriod(cgroup, period) < 0)
            return -1;
    }

    if (quota) {
        if (virCgroupSetCpuCfsQuota(cgroup, quota) < 0)
            goto error;
    }

    return 0;

error:
    if (period) {
        virErrorPtr saved = virSaveLastError();
        virCgroupSetCpuCfsPeriod(cgroup, old_period);
        if (saved) {
            virSetError(saved);
            virFreeError(saved);
        }
    }

    return -1;
}


static int
lxcDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    int ret = -1;
    int rc;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_CPU_SHARES,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                               VIR_TYPED_PARAM_ULLONG,
                               VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                               VIR_TYPED_PARAM_LLONG,
                               NULL) < 0)
        return -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &vmdef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup CPU controller is not mounted"));
            goto cleanup;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CPU_SHARES)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                if (virCgroupSetCpuShares(priv->cgroup, params[i].value.ul) < 0)
                    goto cleanup;

                vm->def->cputune.shares = params[i].value.ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.shares = params[i].value.ul;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = lxcSetVcpuBWLive(priv->cgroup, params[i].value.ul, 0);
                if (rc != 0)
                    goto cleanup;

                if (params[i].value.ul)
                    vm->def->cputune.period = params[i].value.ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.period = params[i].value.ul;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = lxcSetVcpuBWLive(priv->cgroup, 0, params[i].value.l);
                if (rc != 0)
                    goto cleanup;

                if (params[i].value.l)
                    vm->def->cputune.quota = params[i].value.l;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.quota = params[i].value.l;
            }
        }
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto cleanup;


    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        rc = virDomainSaveConfig(cfg->configDir, vmdef);
        if (rc < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false, NULL);
        vmdef = NULL;
    }

    ret = 0;

cleanup:
    virDomainDefFree(vmdef);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}

static int
lxcDomainSetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int nparams)
{
    return lxcDomainSetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int
lxcDomainGetSchedulerParametersFlags(virDomainPtr dom,
                                     virTypedParameterPtr params,
                                     int *nparams,
                                     unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef;
    unsigned long long shares = 0;
    unsigned long long period = 0;
    long long quota = 0;
    int ret = -1;
    int rc;
    bool cpu_bw_status = false;
    int saved_nparams = 0;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (*nparams > 1) {
        rc = lxcGetCpuBWStatus(priv->cgroup);
        if (rc < 0)
            goto cleanup;
        cpu_bw_status = !!rc;
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        shares = persistentDef->cputune.shares;
        if (*nparams > 1) {
            period = persistentDef->cputune.period;
            quota = persistentDef->cputune.quota;
            cpu_bw_status = true; /* Allow copy of data to params[] */
        }
        goto out;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (virCgroupGetCpuShares(priv->cgroup, &shares) < 0)
        goto cleanup;

    if (*nparams > 1 && cpu_bw_status) {
        rc = lxcGetVcpuBWLive(priv->cgroup, &period, &quota);
        if (rc != 0)
            goto cleanup;
    }
out:
    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_SCHEDULER_CPU_SHARES,
                                VIR_TYPED_PARAM_ULLONG, shares) < 0)
        goto cleanup;
    saved_nparams++;

    if (cpu_bw_status) {
        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[1],
                                        VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                                        VIR_TYPED_PARAM_ULLONG, period) < 0)
                goto cleanup;
            saved_nparams++;
        }

        if (*nparams > saved_nparams) {
            if (virTypedParameterAssign(&params[2],
                                        VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                                        VIR_TYPED_PARAM_LLONG, quota) < 0)
                goto cleanup;
            saved_nparams++;
        }
    }

    *nparams = saved_nparams;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    return ret;
}

static int
lxcDomainGetSchedulerParameters(virDomainPtr domain,
                                virTypedParameterPtr params,
                                int *nparams)
{
    return lxcDomainGetSchedulerParametersFlags(domain, params, nparams, 0);
}


static int
lxcDomainSetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLKIO_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSetBlkioParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("out of blkio weight range."));
                    goto cleanup;
                }

                if (virCgroupSetBlkioWeight(priv->cgroup, params[i].value.ui) < 0)
                    goto cleanup;
            }
        }
    }
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Clang can't see that if we get here, persistentDef was set.  */
        sa_assert(persistentDef);

        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("out of blkio weight range."));
                    goto cleanup;
                }

                persistentDef->blkio.weight = params[i].value.ui;
            }
        }

        if (virDomainSaveConfig(cfg->configDir, persistentDef) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


#define LXC_NB_BLKIO_PARAM  1
static int
lxcDomainGetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    unsigned int val;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetBlkioParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of blkio parameters supported by cgroups */
        *nparams = LXC_NB_BLKIO_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virDomainLiveConfigHelperMethod(caps, driver->xmlopt,
                                        vm, &flags, &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        for (i = 0; i < *nparams && i < LXC_NB_BLKIO_PARAM; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;

            switch (i) {
            case 0: /* fill blkio weight here */
                if (virCgroupGetBlkioWeight(priv->cgroup, &val) < 0)
                    goto cleanup;
                if (virTypedParameterAssign(param, VIR_DOMAIN_BLKIO_WEIGHT,
                                            VIR_TYPED_PARAM_UINT, val) < 0)
                    goto cleanup;
                break;

            /* coverity[dead_error_begin] */
            default:
                break;
                /* should not hit here */
            }
        }
    } else if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        for (i = 0; i < *nparams && i < LXC_NB_BLKIO_PARAM; i++) {
            virTypedParameterPtr param = &params[i];

            switch (i) {
            case 0: /* fill blkio weight here */
                if (virTypedParameterAssign(param, VIR_DOMAIN_BLKIO_WEIGHT,
                                            VIR_TYPED_PARAM_UINT,
                                            persistentDef->blkio.weight) < 0)
                    goto cleanup;
                break;

            /* coverity[dead_error_begin] */
            default:
                break;
                /* should not hit here */
            }
        }
    }

    if (LXC_NB_BLKIO_PARAM < *nparams)
        *nparams = LXC_NB_BLKIO_PARAM;
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    return ret;
}


#ifdef __linux__
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path,
                        struct _virDomainInterfaceStats *stats)
{
    virDomainObjPtr vm;
    size_t i;
    int ret = -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    /* Check the path is one of the domain's network interfaces. */
    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ(vm->def->nets[i]->ifname, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0)
        ret = linuxDomainInterfaceStats(path, stats);
    else
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid path, '%s' is not a known interface"), path);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}
#else
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path ATTRIBUTE_UNUSED,
                        struct _virDomainInterfaceStats *stats ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_NO_SUPPORT, "%s", __FUNCTION__);
    return -1;
}
#endif

static int lxcDomainGetAutostart(virDomainPtr dom,
                                   int *autostart) {
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
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

static int lxcDomainSetAutostart(virDomainPtr dom,
                                   int autostart)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart) {
        ret = 0;
        goto cleanup;
    }

    configFile = virDomainConfigFile(cfg->configDir,
                                     vm->def->name);
    if (configFile == NULL)
        goto cleanup;
    autostartLink = virDomainConfigFile(cfg->autostartDir,
                                        vm->def->name);
    if (autostartLink == NULL)
        goto cleanup;

    if (autostart) {
        if (virFileMakePath(cfg->autostartDir) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create autostart directory %s"),
                                 cfg->autostartDir);
            goto cleanup;
        }

        if (symlink(configFile, autostartLink) < 0) {
            virReportSystemError(errno,
                                 _("Failed to create symlink '%s to '%s'"),
                                 autostartLink, configFile);
            goto cleanup;
        }
    } else {
        if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            virReportSystemError(errno,
                                 _("Failed to delete symlink '%s'"),
                                 autostartLink);
            goto cleanup;
        }
    }

    vm->autostart = autostart;
    ret = 0;

cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int lxcFreezeContainer(virDomainObjPtr vm)
{
    int timeout = 1000; /* In milliseconds */
    int check_interval = 1; /* In milliseconds */
    int exp = 10;
    int waited_time = 0;
    int ret = -1;
    char *state = NULL;
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    while (waited_time < timeout) {
        int r;
        /*
         * Writing "FROZEN" to the "freezer.state" freezes the group,
         * i.e., the container, temporarily transiting "FREEZING" state.
         * Once the freezing is completed, the state of the group transits
         * to "FROZEN".
         * (see linux-2.6/Documentation/cgroups/freezer-subsystem.txt)
         */
        r = virCgroupSetFreezerState(priv->cgroup, "FROZEN");

        /*
         * Returning EBUSY explicitly indicates that the group is
         * being freezed but incomplete and other errors are true
         * errors.
         */
        if (r < 0 && r != -EBUSY) {
            VIR_DEBUG("Writing freezer.state failed with errno: %d", r);
            goto error;
        }
        if (r == -EBUSY)
            VIR_DEBUG("Writing freezer.state gets EBUSY");

        /*
         * Unfortunately, returning 0 (success) is likely to happen
         * even when the freezing has not been completed. Sometimes
         * the state of the group remains "FREEZING" like when
         * returning -EBUSY and even worse may never transit to
         * "FROZEN" even if writing "FROZEN" again.
         *
         * So we don't trust the return value anyway and always
         * decide that the freezing has been complete only with
         * the state actually transit to "FROZEN".
         */
        usleep(check_interval * 1000);

        r = virCgroupGetFreezerState(priv->cgroup, &state);

        if (r < 0) {
            VIR_DEBUG("Reading freezer.state failed with errno: %d", r);
            goto error;
        }
        VIR_DEBUG("Read freezer.state: %s", state);

        if (STREQ(state, "FROZEN")) {
            ret = 0;
            goto cleanup;
        }

        waited_time += check_interval;
        /*
         * Increasing check_interval exponentially starting with
         * small initial value treats nicely two cases; One is
         * a container is under no load and waiting for long period
         * makes no sense. The other is under heavy load. The container
         * may stay longer time in FREEZING or never transit to FROZEN.
         * In that case, eager polling will just waste CPU time.
         */
        check_interval *= exp;
        VIR_FREE(state);
    }
    VIR_DEBUG("lxcFreezeContainer timeout");
error:
    /*
     * If timeout or an error on reading the state occurs,
     * activate the group again and return an error.
     * This is likely to fall the group back again gracefully.
     */
    virCgroupSetFreezerState(priv->cgroup, "THAWED");
    ret = -1;

cleanup:
    VIR_FREE(state);
    return ret;
}

static int lxcDomainSuspend(virDomainPtr dom)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (lxcFreezeContainer(vm) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("Suspend operation failed"));
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int lxcDomainResume(virDomainPtr dom)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (virCgroupSetFreezerState(priv->cgroup, "THAWED") < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("Resume operation failed"));
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (event)
        virDomainEventStateQueue(driver->domainEventState, event);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(cfg);
    return ret;
}

static int
lxcDomainOpenConsole(virDomainPtr dom,
                      const char *dev_name,
                      virStreamPtr st,
                      unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virDomainChrDefPtr chr = NULL;
    size_t i;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (dev_name) {
        for (i = 0; i < vm->def->nconsoles; i++) {
            if (vm->def->consoles[i]->info.alias &&
                STREQ(vm->def->consoles[i]->info.alias, dev_name)) {
                chr = vm->def->consoles[i];
                break;
            }
        }
    } else {
        if (vm->def->nconsoles)
            chr = vm->def->consoles[0];
        else if (vm->def->nserials)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find console device '%s'"),
                       dev_name ? dev_name : _("default"));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"), dev_name);
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
lxcDomainSendProcessSignal(virDomainPtr dom,
                           long long pid_value,
                           unsigned int signum,
                           unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virLXCDomainObjPrivatePtr priv;
    pid_t victim;
    int ret = -1;

    virCheckFlags(0, -1);

    if (signum >= VIR_DOMAIN_PROCESS_SIGNAL_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("signum value %d is out of range"),
                       signum);
        return -1;
    }

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSendProcessSignalEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    /*
     * XXX if the kernel has /proc/$PID/ns/pid we can
     * switch into container namespace & that way be
     * able to kill any PID. Alternatively if there
     * is a way to find a mapping of guest<->host PIDs
     * we can kill that way.
     */
    if (pid_value != 1) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Only the init process may be killed"));
        goto cleanup;
    }

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto cleanup;
    }
    victim = priv->initpid;

    /* We're relying on fact libvirt header signal numbers
     * are taken from Linux, to avoid mapping
     */
    if (kill(victim, signum) < 0) {
        virReportSystemError(errno,
                             _("Unable to send %d signal to process %d"),
                             signum, victim);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
lxcConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr **domains,
                  unsigned int flags)
{
    virLXCDriverPtr driver = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    ret = virDomainObjListExport(driver->domains, conn, domains,
                                 virConnectListAllDomainsCheckACL, flags);
    return ret;
}


static int
lxcDomainShutdownFlags(virDomainPtr dom,
                       unsigned int flags)
{
    virLXCDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    char *vroot = NULL;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_INITCTL |
                  VIR_DOMAIN_SHUTDOWN_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (flags == 0 ||
        (flags & VIR_DOMAIN_SHUTDOWN_INITCTL)) {
        if ((rc = virInitctlSetRunLevel(VIR_INITCTL_RUNLEVEL_POWEROFF,
                                        vroot)) < 0) {
            goto cleanup;
        }
        if (rc == 0 && flags != 0 &&
            ((flags & ~VIR_DOMAIN_SHUTDOWN_INITCTL) == 0)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("Container does not provide an initctl pipe"));
            goto cleanup;
        }
    } else {
        rc = 0;
    }

    if (rc == 0 &&
        (flags == 0 ||
         (flags & VIR_DOMAIN_SHUTDOWN_SIGNAL))) {
        if (kill(priv->initpid, SIGTERM) < 0 &&
            errno != ESRCH) {
            virReportSystemError(errno,
                                 _("Unable to send SIGTERM to init pid %llu"),
                                 (unsigned long long)priv->initpid);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(vroot);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
lxcDomainShutdown(virDomainPtr dom)
{
    return lxcDomainShutdownFlags(dom, 0);
}

static int
lxcDomainReboot(virDomainPtr dom,
                unsigned int flags)
{
    virLXCDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    char *vroot = NULL;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_REBOOT_INITCTL |
                  VIR_DOMAIN_REBOOT_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainRebootEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (flags == 0 ||
        (flags & VIR_DOMAIN_REBOOT_INITCTL)) {
        if ((rc = virInitctlSetRunLevel(VIR_INITCTL_RUNLEVEL_REBOOT,
                                        vroot)) < 0) {
            goto cleanup;
        }
        if (rc == 0 && flags != 0 &&
            ((flags & ~VIR_DOMAIN_SHUTDOWN_INITCTL) == 0)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("Container does not provide an initctl pipe"));
            goto cleanup;
        }
    } else {
        rc = 0;
    }

    if (rc == 0 &&
        (flags == 0 ||
         (flags & VIR_DOMAIN_REBOOT_SIGNAL))) {
        if (kill(priv->initpid, SIGHUP) < 0 &&
            errno != ESRCH) {
            virReportSystemError(errno,
                                 _("Unable to send SIGTERM to init pid %llu"),
                                 (unsigned long long)priv->initpid);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(vroot);
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static int
lxcDomainAttachDeviceConfig(virDomainDefPtr vmdef,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;
    virDomainDiskDefPtr disk;
    virDomainNetDefPtr net;
    virDomainHostdevDefPtr hostdev;

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
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if (virDomainNetInsert(vmdef, net) < 0)
            goto cleanup;
        dev->data.net = NULL;
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        hostdev = dev->data.hostdev;
        if (virDomainHostdevFind(vmdef, hostdev, NULL) >= 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("device is already in the domain configuration"));
            return -1;
        }
        if (virDomainHostdevInsert(vmdef, hostdev) < 0)
            return -1;
        dev->data.hostdev = NULL;
        ret = 0;
        break;

    default:
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("persistent attach of device is not supported"));
         break;
    }

cleanup:
    return ret;
}


static int
lxcDomainUpdateDeviceConfig(virDomainDefPtr vmdef,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;
    virDomainNetDefPtr net;
    int idx;
    char mac[VIR_MAC_STRING_BUFLEN];

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        idx = virDomainNetFindIdx(vmdef, net);
        if (idx == -2) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("multiple devices matching mac address %s found"),
                           virMacAddrFormat(&net->mac, mac));
            goto cleanup;
        } else if (idx < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("no matching network device was found"));
            goto cleanup;
        }

        virDomainNetDefFree(vmdef->nets[idx]);

        vmdef->nets[idx] = net;
        dev->data.net = NULL;
        ret = 0;

        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("persistent update of device is not supported"));
        break;
    }

cleanup:
    return ret;
}


static int
lxcDomainDetachDeviceConfig(virDomainDefPtr vmdef,
                            virDomainDeviceDefPtr dev)
{
    int ret = -1;
    virDomainDiskDefPtr disk, det_disk;
    virDomainNetDefPtr net;
    virDomainHostdevDefPtr hostdev, det_hostdev;
    int idx;
    char mac[VIR_MAC_STRING_BUFLEN];

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (!(det_disk = virDomainDiskRemoveByName(vmdef, disk->dst))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("no target device %s"), disk->dst);
            return -1;
        }
        virDomainDiskDefFree(det_disk);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        idx = virDomainNetFindIdx(vmdef, net);
        if (idx == -2) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("multiple devices matching mac address %s found"),
                           virMacAddrFormat(&net->mac, mac));
            goto cleanup;
        } else if (idx < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("no matching network device was found"));
            goto cleanup;
        }
        /* this is guaranteed to succeed */
        virDomainNetDefFree(virDomainNetRemove(vmdef, idx));
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        hostdev = dev->data.hostdev;
        if ((idx = virDomainHostdevFind(vmdef, hostdev, &det_hostdev)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("device not present in domain configuration"));
            return -1;
        }
        virDomainHostdevRemove(vmdef, idx);
        virDomainHostdevDefFree(det_hostdev);
        ret = 0;
        break;
    }

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("persistent detach of device is not supported"));
        break;
    }

cleanup:
    return ret;
}


static int
lxcDomainAttachDeviceDiskLive(virLXCDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainDiskDefPtr def = dev->data.disk;
    int ret = -1;
    char *dst = NULL;
    struct stat sb;
    bool created = false;
    mode_t mode = 0;
    char *tmpsrc = def->src;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if (def->type != VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk for non-block device"));
        goto cleanup;
    }
    if (def->src == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk without media"));
        goto cleanup;
    }

    if (virDomainDiskIndexByName(vm->def, def->dst, true) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %s already exists"), def->dst);
        goto cleanup;
    }

    if (stat(def->src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), def->src);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk source %s must be a character/block device"),
                       def->src);
        goto cleanup;
    }

    if (virAsprintf(&dst, "/proc/%llu/root/dev/%s",
                    (unsigned long long)priv->initpid, def->dst) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
        goto cleanup;

    mode = 0700;
    if (S_ISCHR(sb.st_mode))
        mode |= S_IFCHR;
    else
        mode |= S_IFBLK;

    /* Yes, the device name we're creating may not
     * actually correspond to the major:minor number
     * we're using, but we've no other option at this
     * time. Just have to hope that containerized apps
     * don't get upset that the major:minor is different
     * to that normally implied by the device name
     */
    VIR_DEBUG("Creating dev %s (%d,%d) from %s",
              dst, major(sb.st_rdev), minor(sb.st_rdev), def->src);
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dst);
        goto cleanup;
    }

    if (lxcContainerChown(vm->def, dst) < 0)
        goto cleanup;

    created = true;

    /* Labelling normally operates on src, but we need
     * to actally label the dst here, so hack the config */
    def->src = dst;
    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, def) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (virCgroupAllowDevicePath(priv->cgroup, def->src,
                                 (def->readonly ?
                                  VIR_CGROUP_DEVICE_READ :
                                  VIR_CGROUP_DEVICE_RW) |
                                 VIR_CGROUP_DEVICE_MKNOD) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot allow device %s for domain %s"),
                       def->src, vm->def->name);
        goto cleanup;
    }

    virDomainDiskInsertPreAlloced(vm->def, def);

    ret = 0;

cleanup:
    def->src = tmpsrc;
    virDomainAuditDisk(vm, NULL, def->src, "attach", ret == 0);
    if (dst && created && ret < 0)
        unlink(dst);
    return ret;
}


/* XXX conn required for network -> bridge resolution */
static int
lxcDomainAttachDeviceNetLive(virConnectPtr conn,
                             virDomainObjPtr vm,
                             virDomainNetDefPtr net)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int actualType;
    char *veth = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    /* preallocate new slot for device */
    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets+1) < 0)
        return -1;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (networkAllocateActualDevice(net) < 0)
        return -1;

    actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE: {
        const char *brname = virDomainNetGetActualBridgeName(net);
        if (!brname) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No bridge name specified"));
            goto cleanup;
        }
        if (!(veth = virLXCProcessSetupInterfaceBridged(conn,
                                                        vm->def,
                                                        net,
                                                        brname)))
            goto cleanup;
    }   break;
    case VIR_DOMAIN_NET_TYPE_NETWORK: {
        virNetworkPtr network;
        char *brname = NULL;
        bool fail = false;
        int active;
        virErrorPtr errobj;

        if (!(network = virNetworkLookupByName(conn,
                                               net->data.network.name)))
            goto cleanup;

        active = virNetworkIsActive(network);
        if (active != 1) {
            fail = true;
            if (active == 0)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Network '%s' is not active."),
                               net->data.network.name);
        }

        if (!fail) {
            brname = virNetworkGetBridgeName(network);
            if (brname == NULL)
                fail = true;
        }

        /* Make sure any above failure is preserved */
        errobj = virSaveLastError();
        virNetworkFree(network);
        virSetError(errobj);
        virFreeError(errobj);

        if (fail)
            goto cleanup;

        if (!(veth = virLXCProcessSetupInterfaceBridged(conn,
                                                        vm->def,
                                                        net,
                                                        brname))) {
            VIR_FREE(brname);
            goto cleanup;
        }
        VIR_FREE(brname);
    }   break;
    case VIR_DOMAIN_NET_TYPE_DIRECT: {
        if (!(veth = virLXCProcessSetupInterfaceDirect(conn,
                                                       vm->def,
                                                       net)))
            goto cleanup;
    }   break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Network device type is not supported"));
        goto cleanup;
    }

    if (virNetDevSetNamespace(veth, priv->initpid) < 0) {
        virDomainAuditNet(vm, NULL, net, "attach", false);
        goto cleanup;
    }

    virDomainAuditNet(vm, NULL, net, "attach", true);

    ret = 0;

cleanup:
    if (!ret) {
        vm->def->nets[vm->def->nnets++] = net;
    } else if (veth) {
        switch (actualType) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
            ignore_value(virNetDevVethDelete(veth));
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            ignore_value(virNetDevMacVLanDelete(veth));
            break;
        }
    }

    return ret;
}


static int
lxcDomainAttachDeviceHostdevSubsysUSBLive(virLXCDriverPtr driver,
                                          virDomainObjPtr vm,
                                          virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = dev->data.hostdev;
    int ret = -1;
    char *vroot = NULL;
    char *src = NULL;
    char *dstdir = NULL;
    char *dstfile = NULL;
    struct stat sb;
    mode_t mode;
    bool created = false;
    virUSBDevicePtr usb = NULL;

    if (virDomainHostdevFind(vm->def, def, NULL) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("host USB device already exists"));
        return -1;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (virAsprintf(&dstdir, "%s/dev/bus/%03d",
                    vroot,
                    def->source.subsys.u.usb.bus) < 0)
        goto cleanup;

    if (virAsprintf(&dstfile, "%s/%03d",
                    dstdir,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (virAsprintf(&src, "/dev/bus/usb/%03d/%03d",
                    def->source.subsys.u.usb.bus,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (!(usb = virUSBDeviceNew(def->source.subsys.u.usb.bus,
                                def->source.subsys.u.usb.device, vroot)))
        goto cleanup;

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), src);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("USB source %s was not a character device"),
                       src);
        goto cleanup;
    }

    mode = 0700 | S_IFCHR;

    if (virFileMakePath(dstdir) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %s"), dstdir);
        goto cleanup;
    }

    VIR_DEBUG("Creating dev %s (%d,%d)",
              dstfile, major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dstfile, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dstfile);
        goto cleanup;
    }
    created = true;

    if (lxcContainerChown(vm->def, dstfile) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, def, vroot) < 0)
        goto cleanup;

    if (virUSBDeviceFileIterate(usb,
                                virLXCSetupHostUsbDeviceCgroup,
                                &priv->cgroup) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    if (ret < 0 && created)
        unlink(dstfile);

    virUSBDeviceFree(usb);
    VIR_FREE(src);
    VIR_FREE(dstfile);
    VIR_FREE(dstdir);
    VIR_FREE(vroot);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevStorageLive(virLXCDriverPtr driver,
                                        virDomainObjPtr vm,
                                        virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = dev->data.hostdev;
    int ret = -1;
    char *dst = NULL;
    char *vroot = NULL;
    struct stat sb;
    bool created = false;
    mode_t mode = 0;

    if (!def->source.caps.u.storage.block) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing storage block path"));
        goto cleanup;
    }

    if (virDomainHostdevFind(vm->def, def, NULL) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("host device already exists"));
        return -1;
    }

    if (stat(def->source.caps.u.storage.block, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"),
                             def->source.caps.u.storage.block);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Hostdev source %s must be a block device"),
                       def->source.caps.u.storage.block);
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (virAsprintf(&dst, "%s/%s",
                    vroot,
                    def->source.caps.u.storage.block) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0)
        goto cleanup;

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directroy for device %s"),
                             dst);
        goto cleanup;
    }

    mode = 0700 | S_IFBLK;

    VIR_DEBUG("Creating dev %s (%d,%d)",
              def->source.caps.u.storage.block,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dst);
        goto cleanup;
    }
    created = true;

    if (lxcContainerChown(vm->def, dst) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, def, vroot) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (virCgroupAllowDevicePath(priv->cgroup, def->source.caps.u.storage.block,
                                 VIR_CGROUP_DEVICE_RW |
                                 VIR_CGROUP_DEVICE_MKNOD) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot allow device %s for domain %s"),
                       def->source.caps.u.storage.block, vm->def->name);
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    if (dst && created && ret < 0)
        unlink(dst);
    VIR_FREE(dst);
    VIR_FREE(vroot);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevMiscLive(virLXCDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = dev->data.hostdev;
    int ret = -1;
    char *dst = NULL;
    char *vroot = NULL;
    struct stat sb;
    bool created = false;
    mode_t mode = 0;

    if (!def->source.caps.u.misc.chardev) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing storage block path"));
        goto cleanup;
    }

    if (virDomainHostdevFind(vm->def, def, NULL) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("host device already exists"));
        return -1;
    }

    if (stat(def->source.caps.u.misc.chardev, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"),
                             def->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Hostdev source %s must be a block device"),
                       def->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (virAsprintf(&dst, "%s/%s",
                    vroot,
                    def->source.caps.u.misc.chardev) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0)
        goto cleanup;

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directroy for device %s"),
                             dst);
        goto cleanup;
    }

    mode = 0700 | S_IFCHR;

    VIR_DEBUG("Creating dev %s (%d,%d)",
              def->source.caps.u.misc.chardev,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dst);
        goto cleanup;
    }
    created = true;

    if (lxcContainerChown(vm->def, dst) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, def, vroot) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (virCgroupAllowDevicePath(priv->cgroup, def->source.caps.u.misc.chardev,
                                 VIR_CGROUP_DEVICE_RW |
                                 VIR_CGROUP_DEVICE_MKNOD) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot allow device %s for domain %s"),
                       def->source.caps.u.misc.chardev, vm->def->name);
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    if (dst && created && ret < 0)
        unlink(dst);
    VIR_FREE(dst);
    VIR_FREE(vroot);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevSubsysLive(virLXCDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev)
{
    switch (dev->data.hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return lxcDomainAttachDeviceHostdevSubsysUSBLive(driver, vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %s"),
                       virDomainHostdevSubsysTypeToString(dev->data.hostdev->source.subsys.type));
        return -1;
    }
}


static int
lxcDomainAttachDeviceHostdevCapsLive(virLXCDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    switch (dev->data.hostdev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return lxcDomainAttachDeviceHostdevStorageLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return lxcDomainAttachDeviceHostdevMiscLive(driver, vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %s"),
                       virDomainHostdevCapsTypeToString(dev->data.hostdev->source.caps.type));
        return -1;
    }
}


static int
lxcDomainAttachDeviceHostdevLive(virLXCDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach hostdev until init PID is known"));
        return -1;
    }

    switch (dev->data.hostdev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return lxcDomainAttachDeviceHostdevSubsysLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return lxcDomainAttachDeviceHostdevCapsLive(driver, vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %s"),
                       virDomainHostdevModeTypeToString(dev->data.hostdev->mode));
        return -1;
    }
}


static int
lxcDomainAttachDeviceLive(virConnectPtr conn,
                          virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = lxcDomainAttachDeviceDiskLive(driver, vm, dev);
        if (!ret)
            dev->data.disk = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        ret = lxcDomainAttachDeviceNetLive(conn, vm,
                                           dev->data.net);
        if (!ret)
            dev->data.net = NULL;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = lxcDomainAttachDeviceHostdevLive(driver, vm, dev);
        if (!ret)
            dev->data.disk = NULL;
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
lxcDomainDetachDeviceDiskLive(virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainDiskDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if ((idx = virDomainDiskIndexByName(vm->def,
                                        dev->data.disk->dst,
                                        false)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    def = vm->def->disks[idx];

    if (virAsprintf(&dst, "/proc/%llu/root/dev/%s",
                    (unsigned long long)priv->initpid, def->dst) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    VIR_DEBUG("Unlinking %s (backed by %s)", dst, def->src);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditDisk(vm, def->src, NULL, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditDisk(vm, def->src, NULL, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->src, VIR_CGROUP_DEVICE_RWM) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->src, vm->def->name);

    virDomainDiskRemove(vm->def, idx);
    virDomainDiskDefFree(def);

    ret = 0;

cleanup:
    VIR_FREE(dst);
    return ret;
}


static int
lxcDomainDetachDeviceNetLive(virDomainObjPtr vm,
                             virDomainDeviceDefPtr dev)
{
    int detachidx, ret = -1;
    virDomainNetDefPtr detach = NULL;
    char mac[VIR_MAC_STRING_BUFLEN];
    virNetDevVPortProfilePtr vport = NULL;

    detachidx = virDomainNetFindIdx(vm->def, dev->data.net);
    if (detachidx == -2) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("multiple devices matching mac address %s found"),
                       virMacAddrFormat(&dev->data.net->mac, mac));
        goto cleanup;
    } else if (detachidx < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("network device %s not found"),
                       virMacAddrFormat(&dev->data.net->mac, mac));
        goto cleanup;
    }
    detach = vm->def->nets[detachidx];

    switch (virDomainNetGetActualType(detach)) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virNetDevVethDelete(detach->ifname) < 0) {
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
        break;

        /* It'd be nice to support this, but with macvlan
         * once assigned to a container nothing exists on
         * the host side. Further the container can change
         * the mac address of NIC name, so we can't easily
         * find out which guest NIC it maps to
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        */

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only bridged veth devices can be detached"));
        goto cleanup;
    }

    virDomainAuditNet(vm, detach, NULL, "detach", true);

    virDomainConfNWFilterTeardown(detach);

    vport = virDomainNetGetActualVirtPortProfile(detach);
    if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
        ignore_value(virNetDevOpenvswitchRemovePort(
                        virDomainNetGetActualBridgeName(detach),
                        detach->ifname));
    ret = 0;
cleanup:
    if (!ret) {
        networkReleaseActualDevice(detach);
        virDomainNetRemove(vm->def, detachidx);
        virDomainNetDefFree(detach);
    }
    return ret;
}


static int
lxcDomainDetachDeviceHostdevUSBLive(virLXCDriverPtr driver,
                                    virDomainObjPtr vm,
                                    virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;
    char *vroot;
    virUSBDevicePtr usb = NULL;

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("usb device not found"));
        goto cleanup;
    }

    if (virAsprintf(&vroot, "/proc/%llu/root",
                    (unsigned long long)priv->initpid) < 0)
        goto cleanup;

    if (virAsprintf(&dst, "%s/dev/bus/usb/%03d/%03d",
                    vroot,
                    def->source.subsys.u.usb.bus,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (!(usb = virUSBDeviceNew(def->source.subsys.u.usb.bus,
                                def->source.subsys.u.usb.device, vroot)))
        goto cleanup;

    VIR_DEBUG("Unlinking %s", dst);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditHostdev(vm, def, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virUSBDeviceFileIterate(usb,
                                virLXCTeardownHostUsbDeviceCgroup,
                                &priv->cgroup) < 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 dst, vm->def->name);

    virObjectLock(driver->activeUsbHostdevs);
    virUSBDeviceListDel(driver->activeUsbHostdevs, usb);
    virObjectUnlock(driver->activeUsbHostdevs);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

cleanup:
    virUSBDeviceFree(usb);
    VIR_FREE(dst);
    return ret;
}


static int
lxcDomainDetachDeviceHostdevStorageLive(virDomainObjPtr vm,
                                        virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("hostdev %s not found"),
                       dev->data.hostdev->source.caps.u.storage.block);
        goto cleanup;
    }

    if (virAsprintf(&dst, "/proc/%llu/root/%s",
                    (unsigned long long)priv->initpid,
                    def->source.caps.u.storage.block) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    VIR_DEBUG("Unlinking %s", dst);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditHostdev(vm, def, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.storage.block, VIR_CGROUP_DEVICE_RWM) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->source.caps.u.storage.block, vm->def->name);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

cleanup:
    VIR_FREE(dst);
    return ret;
}


static int
lxcDomainDetachDeviceHostdevMiscLive(virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;
    char *dst = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("hostdev %s not found"),
                       dev->data.hostdev->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (virAsprintf(&dst, "/proc/%llu/root/%s",
                    (unsigned long long)priv->initpid,
                    def->source.caps.u.misc.chardev) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    VIR_DEBUG("Unlinking %s", dst);
    if (unlink(dst) < 0 && errno != ENOENT) {
        virDomainAuditHostdev(vm, def, "detach", false);
        virReportSystemError(errno,
                             _("Unable to remove device %s"), dst);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.misc.chardev, VIR_CGROUP_DEVICE_RWM) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->source.caps.u.misc.chardev, vm->def->name);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

cleanup:
    VIR_FREE(dst);
    return ret;
}


static int
lxcDomainDetachDeviceHostdevSubsysLive(virLXCDriverPtr driver,
                                       virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev)
{
    switch (dev->data.hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return lxcDomainDetachDeviceHostdevUSBLive(driver, vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %s"),
                       virDomainHostdevSubsysTypeToString(dev->data.hostdev->source.subsys.type));
        return -1;
    }
}


static int
lxcDomainDetachDeviceHostdevCapsLive(virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    switch (dev->data.hostdev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return lxcDomainDetachDeviceHostdevStorageLive(vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return lxcDomainDetachDeviceHostdevMiscLive(vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %s"),
                       virDomainHostdevCapsTypeToString(dev->data.hostdev->source.caps.type));
        return -1;
    }
}


static int
lxcDomainDetachDeviceHostdevLive(virLXCDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach hostdev until init PID is known"));
        return -1;
    }

    switch (dev->data.hostdev->mode) {
    case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
        return lxcDomainDetachDeviceHostdevSubsysLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
        return lxcDomainDetachDeviceHostdevCapsLive(vm, dev);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %s"),
                       virDomainHostdevModeTypeToString(dev->data.hostdev->mode));
        return -1;
    }
}


static int
lxcDomainDetachDeviceLive(virLXCDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = lxcDomainDetachDeviceDiskLive(vm, dev);
        break;

    case VIR_DOMAIN_DEVICE_NET:
        ret = lxcDomainDetachDeviceNetLive(vm, dev);
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = lxcDomainDetachDeviceHostdevLive(driver, vm, dev);
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type '%s' cannot be detached"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}


static int lxcDomainAttachDeviceFlags(virDomainPtr dom,
                                      const char *xml,
                                      unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    int ret = -1;
    unsigned int affect;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto cleanup;
        }
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto cleanup;
    }

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto cleanup;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto cleanup;
        if ((ret = lxcDomainAttachDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
            goto cleanup;

        if ((ret = lxcDomainAttachDeviceLive(dom->conn, driver, vm, dev_copy)) < 0)
            goto cleanup;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            ret = -1;
            goto cleanup;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static int lxcDomainAttachDevice(virDomainPtr dom,
                                 const char *xml)
{
    return lxcDomainAttachDeviceFlags(dom, xml,
                                       VIR_DOMAIN_AFFECT_LIVE);
}


static int lxcDomainUpdateDeviceFlags(virDomainPtr dom,
                                      const char *xml,
                                      unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    int ret = -1;
    unsigned int affect;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_DEVICE_MODIFY_FORCE, -1);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto cleanup;
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto cleanup;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto cleanup;
        if ((ret = lxcDomainUpdateDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
            goto cleanup;

        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to modify live devices"));

        goto cleanup;
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static int lxcDomainDetachDeviceFlags(virDomainPtr dom,
                                      const char *xml,
                                      unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virCapsPtr caps = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainDeviceDefPtr dev = NULL, dev_copy = NULL;
    int ret = -1;
    unsigned int affect;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    affect = flags & (VIR_DOMAIN_AFFECT_LIVE | VIR_DOMAIN_AFFECT_CONFIG);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        if (affect == VIR_DOMAIN_AFFECT_CURRENT)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        /* check consistency between flags and the vm state */
        if (flags & VIR_DOMAIN_AFFECT_LIVE) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot do live update a device on "
                             "inactive domain"));
            goto cleanup;
        }
    }

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) && !vm->persistent) {
         virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                        _("cannot modify device on transient domain"));
         goto cleanup;
    }

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_XML_INACTIVE);
    if (dev == NULL)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (virDomainDefCompatibleDevice(vm->def, dev) < 0)
            goto cleanup;

        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto cleanup;

        if ((ret = lxcDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy) < 0)
            goto cleanup;

        if ((ret = lxcDomainDetachDeviceLive(driver, vm, dev_copy)) < 0)
            goto cleanup;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0) {
            ret = -1;
            goto cleanup;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    if (vm)
        virObjectUnlock(vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static int lxcDomainDetachDevice(virDomainPtr dom,
                                 const char *xml)
{
    return lxcDomainDetachDeviceFlags(dom, xml,
                                      VIR_DOMAIN_AFFECT_LIVE);
}


static int lxcDomainLxcOpenNamespace(virDomainPtr dom,
                                     int **fdlist,
                                     unsigned int flags)
{
    virDomainObjPtr vm;
    virLXCDomainObjPrivatePtr priv;
    int ret = -1;
    size_t nfds = 0;

    *fdlist = NULL;
    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainLxcOpenNamespaceEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto cleanup;
    }

    if (virProcessGetNamespaces(priv->initpid, &nfds, fdlist) < 0)
        goto cleanup;

    ret = nfds;
cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}


static char *
lxcConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    virLXCDriverPtr driver = conn->privateData;
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
lxcNodeGetInfo(virConnectPtr conn,
               virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return nodeGetInfo(nodeinfo);
}


static int
lxcNodeGetCPUStats(virConnectPtr conn,
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
lxcNodeGetMemoryStats(virConnectPtr conn,
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
lxcNodeGetCellsFreeMemory(virConnectPtr conn,
                          unsigned long long *freeMems,
                          int startCell,
                          int maxCells)
{
    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return -1;

    return nodeGetCellsFreeMemory(freeMems, startCell, maxCells);
}


static unsigned long long
lxcNodeGetFreeMemory(virConnectPtr conn)
{
    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    return nodeGetFreeMemory();
}


static int
lxcNodeGetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int *nparams,
                           unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeGetMemoryParameters(params, nparams, flags);
}


static int
lxcNodeSetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return nodeSetMemoryParameters(params, nparams, flags);
}


static int
lxcNodeGetCPUMap(virConnectPtr conn,
                 unsigned char **cpumap,
                 unsigned int *online,
                 unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return nodeGetCPUMap(cpumap, online, flags);
}


static int
lxcNodeSuspendForDuration(virConnectPtr conn,
                          unsigned int target,
                          unsigned long long duration,
                          unsigned int flags)
{
    if (virNodeSuspendForDurationEnsureACL(conn) < 0)
        return -1;

    return nodeSuspendForDuration(target, duration, flags);
}


/* Function Tables */
static virDriver lxcDriver = {
    .no = VIR_DRV_LXC,
    .name = LXC_DRIVER_NAME,
    .connectOpen = lxcConnectOpen, /* 0.4.2 */
    .connectClose = lxcConnectClose, /* 0.4.2 */
    .connectGetVersion = lxcConnectGetVersion, /* 0.4.6 */
    .connectGetHostname = lxcConnectGetHostname, /* 0.6.3 */
    .connectGetSysinfo = lxcConnectGetSysinfo, /* 1.0.5 */
    .nodeGetInfo = lxcNodeGetInfo, /* 0.6.5 */
    .connectGetCapabilities = lxcConnectGetCapabilities, /* 0.6.5 */
    .connectListDomains = lxcConnectListDomains, /* 0.4.2 */
    .connectNumOfDomains = lxcConnectNumOfDomains, /* 0.4.2 */
    .connectListAllDomains = lxcConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = lxcDomainCreateXML, /* 0.4.4 */
    .domainCreateXMLWithFiles = lxcDomainCreateXMLWithFiles, /* 1.1.1 */
    .domainLookupByID = lxcDomainLookupByID, /* 0.4.2 */
    .domainLookupByUUID = lxcDomainLookupByUUID, /* 0.4.2 */
    .domainLookupByName = lxcDomainLookupByName, /* 0.4.2 */
    .domainSuspend = lxcDomainSuspend, /* 0.7.2 */
    .domainResume = lxcDomainResume, /* 0.7.2 */
    .domainDestroy = lxcDomainDestroy, /* 0.4.4 */
    .domainDestroyFlags = lxcDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = lxcDomainGetOSType, /* 0.4.2 */
    .domainGetMaxMemory = lxcDomainGetMaxMemory, /* 0.7.2 */
    .domainSetMaxMemory = lxcDomainSetMaxMemory, /* 0.7.2 */
    .domainSetMemory = lxcDomainSetMemory, /* 0.7.2 */
    .domainSetMemoryParameters = lxcDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = lxcDomainGetMemoryParameters, /* 0.8.5 */
    .domainSetBlkioParameters = lxcDomainSetBlkioParameters, /* 0.9.8 */
    .domainGetBlkioParameters = lxcDomainGetBlkioParameters, /* 0.9.8 */
    .domainGetInfo = lxcDomainGetInfo, /* 0.4.2 */
    .domainGetState = lxcDomainGetState, /* 0.9.2 */
    .domainGetSecurityLabel = lxcDomainGetSecurityLabel, /* 0.9.10 */
    .nodeGetSecurityModel = lxcNodeGetSecurityModel, /* 0.9.10 */
    .domainGetXMLDesc = lxcDomainGetXMLDesc, /* 0.4.2 */
    .connectListDefinedDomains = lxcConnectListDefinedDomains, /* 0.4.2 */
    .connectNumOfDefinedDomains = lxcConnectNumOfDefinedDomains, /* 0.4.2 */
    .domainCreate = lxcDomainCreate, /* 0.4.4 */
    .domainCreateWithFlags = lxcDomainCreateWithFlags, /* 0.8.2 */
    .domainCreateWithFiles = lxcDomainCreateWithFiles, /* 1.1.1 */
    .domainDefineXML = lxcDomainDefineXML, /* 0.4.2 */
    .domainUndefine = lxcDomainUndefine, /* 0.4.2 */
    .domainUndefineFlags = lxcDomainUndefineFlags, /* 0.9.4 */
    .domainAttachDevice = lxcDomainAttachDevice, /* 1.0.1 */
    .domainAttachDeviceFlags = lxcDomainAttachDeviceFlags, /* 1.0.1 */
    .domainDetachDevice = lxcDomainDetachDevice, /* 1.0.1 */
    .domainDetachDeviceFlags = lxcDomainDetachDeviceFlags, /* 1.0.1 */
    .domainUpdateDeviceFlags = lxcDomainUpdateDeviceFlags, /* 1.0.1 */
    .domainGetAutostart = lxcDomainGetAutostart, /* 0.7.0 */
    .domainSetAutostart = lxcDomainSetAutostart, /* 0.7.0 */
    .domainGetSchedulerType = lxcDomainGetSchedulerType, /* 0.5.0 */
    .domainGetSchedulerParameters = lxcDomainGetSchedulerParameters, /* 0.5.0 */
    .domainGetSchedulerParametersFlags = lxcDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = lxcDomainSetSchedulerParameters, /* 0.5.0 */
    .domainSetSchedulerParametersFlags = lxcDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainInterfaceStats = lxcDomainInterfaceStats, /* 0.7.3 */
    .nodeGetCPUStats = lxcNodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = lxcNodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = lxcNodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = lxcNodeGetFreeMemory, /* 0.6.5 */
    .nodeGetCPUMap = lxcNodeGetCPUMap, /* 1.0.0 */
    .connectDomainEventRegister = lxcConnectDomainEventRegister, /* 0.7.0 */
    .connectDomainEventDeregister = lxcConnectDomainEventDeregister, /* 0.7.0 */
    .connectIsEncrypted = lxcConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = lxcConnectIsSecure, /* 0.7.3 */
    .domainIsActive = lxcDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = lxcDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = lxcDomainIsUpdated, /* 0.8.6 */
    .connectDomainEventRegisterAny = lxcConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = lxcConnectDomainEventDeregisterAny, /* 0.8.0 */
    .domainOpenConsole = lxcDomainOpenConsole, /* 0.8.6 */
    .connectIsAlive = lxcConnectIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = lxcNodeSuspendForDuration, /* 0.9.8 */
    .nodeGetMemoryParameters = lxcNodeGetMemoryParameters, /* 0.10.2 */
    .nodeSetMemoryParameters = lxcNodeSetMemoryParameters, /* 0.10.2 */
    .domainSendProcessSignal = lxcDomainSendProcessSignal, /* 1.0.1 */
    .domainShutdown = lxcDomainShutdown, /* 1.0.1 */
    .domainShutdownFlags = lxcDomainShutdownFlags, /* 1.0.1 */
    .domainReboot = lxcDomainReboot, /* 1.0.1 */
    .domainLxcOpenNamespace = lxcDomainLxcOpenNamespace, /* 1.0.2 */
};

static virStateDriver lxcStateDriver = {
    .name = LXC_DRIVER_NAME,
    .stateInitialize = lxcStateInitialize,
    .stateAutoStart = lxcStateAutoStart,
    .stateCleanup = lxcStateCleanup,
    .stateReload = lxcStateReload,
};

int lxcRegister(void)
{
    virRegisterDriver(&lxcDriver);
    virRegisterStateDriver(&lxcStateDriver);
    return 0;
}
