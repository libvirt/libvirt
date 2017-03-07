/*
 * Copyright (C) 2010-2016 Red Hat, Inc.
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

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
# include <sys/sysmacros.h>
#endif

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
#include "lxc_native.h"
#include "lxc_process.h"
#include "viralloc.h"
#include "virnetdevbridge.h"
#include "virnetdevveth.h"
#include "virnetdevopenvswitch.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viruuid.h"
#include "virhook.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virfdstream.h"
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
#include "virhostdev.h"
#include "netdev_bandwidth_conf.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_driver");

#define LXC_NB_MEM_PARAM  3
#define LXC_NB_DOMAIN_BLOCK_STAT_PARAM 4


static int lxcStateInitialize(bool privileged,
                              virStateInhibitCallback callback,
                              void *opaque);
static int lxcStateCleanup(void);
virLXCDriverPtr lxc_driver = NULL;

/* callbacks for nwfilter */
static int
lxcVMFilterRebuild(virDomainObjListIterator iter, void *data)
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
 * This function looks up @domain and returns the appropriate virDomainObjPtr
 * that has to be released by calling virDomainObjEndAPI.
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
static virDomainObjPtr
lxcDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    virLXCDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUIDRef(driver->domains, domain->uuid);
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
                                       virConfPtr conf ATTRIBUTE_UNUSED,
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

    xml = virCapabilitiesFormatXML(caps);

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

    vm = virDomainObjListFindByUUIDRef(driver->domains, uuid);

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
    virDomainObjEndAPI(&vm);
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
    virDomainObjEndAPI(&vm);
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
    virDomainObjEndAPI(&obj);
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
    virDomainObjEndAPI(&obj);
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
    virDomainObjEndAPI(&obj);
    return ret;
}

static int lxcConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                     virConnectListDomainsCheckACL, conn);

    return n;
}

static int lxcConnectNumOfDomains(virConnectPtr conn)
{
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, true,
                                     virConnectNumOfDomainsCheckACL, conn);

    return n;
}

static int lxcConnectListDefinedDomains(virConnectPtr conn,
                                        char **const names, int nnames)
{
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                         virConnectListDefinedDomainsCheckACL, conn);

    return n;
}


static int lxcConnectNumOfDefinedDomains(virConnectPtr conn)
{
    virLXCDriverPtr driver = conn->privateData;
    int n;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    n = virDomainObjListNumOfDomains(driver->domains, false,
                                     virConnectNumOfDefinedDomainsCheckACL, conn);

    return n;
}



static virDomainPtr
lxcDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
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

    virObjectRef(vm);
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(cfg->configDir, driver->caps,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
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
    virDomainObjEndAPI(&vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return dom;
}

static virDomainPtr
lxcDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return lxcDomainDefineXMLFlags(conn, xml, 0);
}

static int lxcDomainUndefineFlags(virDomainPtr dom,
                                  unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
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

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(driver->domains, vm);
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
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

    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virDomainObjEndAPI(&vm);
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

    if (VIR_STRDUP(ret, virDomainOSTypeToString(vm->def->os.type)) < 0)
        goto cleanup;

 cleanup:
    virDomainObjEndAPI(&vm);
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

    ret = virDomainDefGetMemoryTotal(vm->def);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int lxcDomainSetMemoryFlags(virDomainPtr dom, unsigned long newmem,
                                   unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverPtr driver = dom->conn->privateData;
    virLXCDriverConfigPtr cfg = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virLXCDriverGetConfig(driver);

    priv = vm->privateData;

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        if (def) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Cannot resize the max memory "
                             "on an active domain"));
            goto endjob;
        }

        if (persistentDef) {
            virDomainDefSetMemoryTotal(persistentDef, newmem);
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            if (virDomainSaveConfig(cfg->configDir, driver->caps,
                                    persistentDef) < 0)
                goto endjob;
        }
    } else {
        unsigned long oldmax = 0;

        if (def)
            oldmax = virDomainDefGetMemoryTotal(def);
        if (persistentDef) {
            if (!oldmax || oldmax > virDomainDefGetMemoryTotal(persistentDef))
                oldmax = virDomainDefGetMemoryTotal(persistentDef);
        }

        if (newmem > oldmax) {
            virReportError(VIR_ERR_INVALID_ARG,
                           "%s", _("Cannot set memory higher than max memory"));
            goto endjob;
        }

        if (def) {
            if (virCgroupSetMemory(priv->cgroup, newmem) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("Failed to set memory for domain"));
                goto endjob;
            }

            def->mem.cur_balloon = newmem;
            if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
                goto endjob;
        }

        if (persistentDef) {
            persistentDef->mem.cur_balloon = newmem;
            if (virDomainSaveConfig(cfg->configDir, driver->caps,
                                    persistentDef) < 0)
                goto endjob;
        }
    }

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int lxcDomainSetMemory(virDomainPtr dom, unsigned long newmem)
{
    return lxcDomainSetMemoryFlags(dom, newmem, VIR_DOMAIN_AFFECT_LIVE);
}

static int lxcDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax)
{
    return lxcDomainSetMemoryFlags(dom, newmax, VIR_DOMAIN_MEM_MAXIMUM);
}

static int
lxcDomainSetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDef = NULL;
    virDomainObjPtr vm = NULL;
    virLXCDomainObjPrivatePtr priv = NULL;
    virLXCDriverConfigPtr cfg = NULL;
    virLXCDriverPtr driver = dom->conn->privateData;
    unsigned long long hard_limit;
    unsigned long long soft_limit;
    unsigned long long swap_hard_limit;
    bool set_hard_limit = false;
    bool set_soft_limit = false;
    bool set_swap_hard_limit = false;
    int rc;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

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
    cfg = virLXCDriverGetConfig(driver);

    if (virDomainSetMemoryParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    /* QEMU and LXC implementation are identical */
    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cgroup memory controller is not mounted"));
        goto endjob;
    }

#define VIR_GET_LIMIT_PARAMETER(PARAM, VALUE)                                \
    if ((rc = virTypedParamsGetULLong(params, nparams, PARAM, &VALUE)) < 0)  \
        goto endjob;                                                         \
                                                                             \
    if (rc == 1)                                                             \
        set_ ## VALUE = true;

    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT, swap_hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_HARD_LIMIT, hard_limit)
    VIR_GET_LIMIT_PARAMETER(VIR_DOMAIN_MEMORY_SOFT_LIMIT, soft_limit)

#undef VIR_GET_LIMIT_PARAMETER

    /* Swap hard limit must be greater than hard limit. */
    if (set_swap_hard_limit || set_hard_limit) {
        unsigned long long mem_limit = vm->def->mem.hard_limit;
        unsigned long long swap_limit = vm->def->mem.swap_hard_limit;

        if (set_swap_hard_limit)
            swap_limit = swap_hard_limit;

        if (set_hard_limit)
            mem_limit = hard_limit;

        if (mem_limit > swap_limit) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("memory hard_limit tunable value must be lower "
                             "than or equal to swap_hard_limit"));
            goto endjob;
        }
    }

#define VIR_SET_MEM_PARAMETER(FUNC, VALUE)                                      \
    if (set_ ## VALUE) {                                                        \
        if (def) {                                                              \
            if ((rc = FUNC(priv->cgroup, VALUE)) < 0)                           \
                goto endjob;                                                    \
            def->mem.VALUE = VALUE;                                             \
        }                                                                       \
                                                                                \
        if (persistentDef)                                                      \
            persistentDef->mem.VALUE = VALUE;                                   \
    }

    /* Soft limit doesn't clash with the others */
    VIR_SET_MEM_PARAMETER(virCgroupSetMemorySoftLimit, soft_limit);

    /* set hard limit before swap hard limit if decreasing it */
    if (def && def->mem.hard_limit > hard_limit) {
        VIR_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);
        /* inhibit changing the limit a second time */
        set_hard_limit = false;
    }

    VIR_SET_MEM_PARAMETER(virCgroupSetMemSwapHardLimit, swap_hard_limit);

    /* otherwise increase it after swap hard limit */
    VIR_SET_MEM_PARAMETER(virCgroupSetMemoryHardLimit, hard_limit);

#undef VIR_SET_MEM_PARAMETER

    if (def &&
        virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto endjob;

    if (persistentDef &&
        virDomainSaveConfig(cfg->configDir, driver->caps, persistentDef) < 0)
        goto endjob;
    /* QEMU and LXC implementations are identical */

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int
lxcDomainGetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    virDomainDefPtr persistentDef = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virLXCDomainObjPrivatePtr priv = NULL;
    unsigned long long val;
    int ret = -1;
    size_t i;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetMemoryParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto cleanup;

    if (def &&
        !virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_MEMORY)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup memory controller is not mounted"));
        goto cleanup;
    }

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
            if (persistentDef) {
                val = persistentDef->mem.hard_limit;
            } else if (virCgroupGetMemoryHardLimit(priv->cgroup, &val) < 0) {
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 1: /* fill memory soft limit here */
            if (persistentDef) {
                val = persistentDef->mem.soft_limit;
            } else if (virCgroupGetMemorySoftLimit(priv->cgroup, &val) < 0) {
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 2: /* fill swap hard limit here */
            if (persistentDef) {
                val = persistentDef->mem.swap_hard_limit;
            } else if (virCgroupGetMemSwapHardLimit(priv->cgroup, &val) < 0) {
                goto cleanup;
            }
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        }
    }

    if (*nparams > LXC_NB_MEM_PARAM)
        *nparams = LXC_NB_MEM_PARAM;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *lxcDomainGetXMLDesc(virDomainPtr dom,
                                 unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             driver->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *lxcConnectDomainXMLFromNative(virConnectPtr conn,
                                           const char *nativeFormat,
                                           const char *nativeConfig,
                                           unsigned int flags)
{
    char *xml = NULL;
    virDomainDefPtr def = NULL;
    virLXCDriverPtr driver = conn->privateData;
    virCapsPtr caps = virLXCDriverGetCapabilities(driver, false);

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        goto cleanup;

    if (STRNEQ(nativeFormat, LXC_CONFIG_FORMAT)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        goto cleanup;
    }

    if (!(def = lxcParseConfigString(nativeConfig, caps, driver->xmlopt)))
        goto cleanup;

    xml = virDomainDefFormat(def, caps, 0);

 cleanup:
    virObjectUnref(caps);
    virDomainDefFree(def);
    return xml;
}

/**
 * lxcDomainCreateWithFiles:
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
    virObjectEventPtr event = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    virNWFilterReadLockFilterUpdates();

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFilesEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((vm->def->nets != NULL) && !(cfg->have_netns)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto endjob;
    }

    ret = virLXCProcessStart(dom->conn, driver, vm,
                             nfiles, files,
                             (flags & VIR_DOMAIN_START_AUTODESTROY),
                             VIR_DOMAIN_RUNNING_BOOTED);

    if (ret == 0) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
        virDomainAuditStart(vm, "booted", true);
    } else {
        virDomainAuditStart(vm, "booted", false);
    }

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(cfg);
    virNWFilterUnlockFilterUpdates();
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
 * lxcDomainCreateXMLWithFiles:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @nfiles: number of file descriptors passed
 * @files: list of file descriptors passed
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Creates a domain based on xml and starts it
 *
 * Returns a new domain object or NULL in case of failure.
 */
static virDomainPtr
lxcDomainCreateXMLWithFiles(virConnectPtr conn,
                            const char *xml,
                            unsigned int nfiles,
                            int *files,
                            unsigned int flags)
{
    virLXCDriverPtr driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);


    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    virNWFilterReadLockFilterUpdates();

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, caps, driver->xmlopt,
                                        NULL, parse_flags)))
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
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;
    virObjectRef(vm);
    def = NULL;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0) {
        if (!vm->persistent) {
            virDomainObjListRemove(driver->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    if (virLXCProcessStart(conn, driver, vm,
                           nfiles, files,
                           (flags & VIR_DOMAIN_START_AUTODESTROY),
                           VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        virDomainAuditStart(vm, "booted", false);
        virLXCDomainObjEndJob(driver, vm);
        if (!vm->persistent) {
            virDomainObjListRemove(driver->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(def);
    virDomainObjEndAPI(&vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    virNWFilterUnlockFilterUpdates();
    return dom;
}

/**
 * lxcDomainCreateXML:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: bitwise-OR of supported virDomainCreateFlags
 *
 * Creates a domain based on xml and starts it
 *
 * Returns a new domain object or NULL in case of failure.
 */
static virDomainPtr
lxcDomainCreateXML(virConnectPtr conn,
                   const char *xml,
                   unsigned int flags)
{
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
    virDomainObjEndAPI(&vm);
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

    if (virConnectDomainEventRegisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegister(conn,
                                    driver->domainEventState,
                                    callback, opaque, freecb) < 0)
        return -1;

    return 0;
}


static int
lxcConnectDomainEventDeregister(virConnectPtr conn,
                                virConnectDomainEventCallback callback)
{
    virLXCDriverPtr driver = conn->privateData;

    if (virConnectDomainEventDeregisterEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateDeregister(conn,
                                      driver->domainEventState,
                                      callback) < 0)
        return -1;

    return 0;
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

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->domainEventState,
                                        callbackID) < 0)
        return -1;

    return 0;
}


/**
 * lxcDomainDestroyFlags:
 * @dom: pointer to domain to destroy
 * @flags: extra flags; not used yet.
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
    virObjectEventPtr event = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    priv = vm->privateData;
    ret = virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;
    virDomainAuditStop(vm, "destroyed");

 endjob:
    virLXCDomainObjEndJob(driver, vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
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

    if (virRun(argv, &ip_rc) < 0 || ip_rc == 255)
        return 0;

    if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_NET) < 0)
        return 0;

    return 1;
}


static virSecurityManagerPtr
lxcSecurityInit(virLXCDriverConfigPtr cfg)
{
    unsigned int flags = VIR_SECURITY_MANAGER_PRIVILEGED;

    VIR_INFO("lxcSecurityInit %s", cfg->securityDriverName);

    if (cfg->securityDefaultConfined)
        flags |= VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
    if (cfg->securityRequireConfined)
        flags |= VIR_SECURITY_MANAGER_REQUIRE_CONFINED;

    virSecurityManagerPtr mgr = virSecurityManagerNew(cfg->securityDriverName,
                                                      LXC_DRIVER_NAME, flags);
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
    const char *ld;
    virLXCDriverConfigPtr cfg = NULL;

    /* Valgrind gets very annoyed when we clone containers, so
     * disable LXC when under valgrind
     * XXX remove this when valgrind is fixed
     */
    ld = virGetEnvBlockSUID("LD_PRELOAD");
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
    if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_MNT |
                                     VIR_PROCESS_NAMESPACE_PID |
                                     VIR_PROCESS_NAMESPACE_UTS |
                                     VIR_PROCESS_NAMESPACE_IPC) < 0) {
        VIR_INFO("LXC support not available in this kernel, disabling driver");
        return 0;
    }

    if (VIR_ALLOC(lxc_driver) < 0)
        return -1;
    if (virMutexInit(&lxc_driver->lock) < 0) {
        VIR_FREE(lxc_driver);
        return -1;
    }

    if (!(lxc_driver->domains = virDomainObjListNew()))
        goto cleanup;

    lxc_driver->domainEventState = virObjectEventStateNew();
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

    if (!(lxc_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto cleanup;

    if ((virLXCDriverGetCapabilities(lxc_driver, true)) == NULL)
        goto cleanup;

    if (!(lxc_driver->xmlopt = lxcDomainXMLConfInit()))
        goto cleanup;

    if (!(lxc_driver->closeCallbacks = virCloseCallbacksNew()))
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(lxc_driver, false)))
        goto cleanup;

    if (virFileMakePath(cfg->stateDir) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %s"),
                             cfg->stateDir);
        goto cleanup;
    }

    /* Get all the running persistent or transient configs first */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->stateDir,
                                       NULL, 1,
                                       caps,
                                       lxc_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    virLXCProcessReconnectAll(lxc_driver, lxc_driver->domains);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, 0,
                                       caps,
                                       lxc_driver->xmlopt,
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
        virObjectEventPtr event =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
            virObjectEventStateQueue(driver->domainEventState, event);
    }
}

/**
 * lxcStateReload:
 *
 * Function to restart the LXC driver, it will recheck the configuration
 * files and perform autostart
 */
static int
lxcStateReload(void)
{
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
    virObjectUnref(lxc_driver->domainEventState);

    virObjectUnref(lxc_driver->closeCallbacks);

    virSysinfoDefFree(lxc_driver->hostsysinfo);

    virObjectUnref(lxc_driver->hostdevMgr);
    virObjectUnref(lxc_driver->caps);
    virObjectUnref(lxc_driver->securityManager);
    virObjectUnref(lxc_driver->xmlopt);
    virObjectUnref(lxc_driver->config);
    virMutexDestroy(&lxc_driver->lock);
    VIR_FREE(lxc_driver);

    return 0;
}

static int
lxcConnectSupportsFeature(virConnectPtr conn, int feature)
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


static char *lxcDomainGetSchedulerType(virDomainPtr dom,
                                       int *nparams)
{
    char *ret = NULL;
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
        if (virCgroupSupportsCpuBW(priv->cgroup))
            *nparams = 3;
        else
            *nparams = 1;
    }

    ignore_value(VIR_STRDUP(ret, "posix"));

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDefCopy = NULL;
    virDomainDefPtr persistentDef = NULL;
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

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (persistentDef) {
        /* Make a copy for updated domain. */
        persistentDefCopy = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!persistentDefCopy)
            goto endjob;
    }

    if (def) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPU)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("cgroup CPU controller is not mounted"));
            goto endjob;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CPU_SHARES)) {
            if (def) {
                unsigned long long val;
                if (virCgroupSetCpuShares(priv->cgroup, params[i].value.ul) < 0)
                    goto endjob;

                if (virCgroupGetCpuShares(priv->cgroup, &val) < 0)
                    goto endjob;

                def->cputune.shares = val;
                def->cputune.sharesSpecified = true;
            }

            if (persistentDef) {
                persistentDefCopy->cputune.shares = params[i].value.ul;
                persistentDefCopy->cputune.sharesSpecified = true;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD)) {
            if (def) {
                rc = lxcSetVcpuBWLive(priv->cgroup, params[i].value.ul, 0);
                if (rc != 0)
                    goto endjob;

                if (params[i].value.ul)
                    def->cputune.period = params[i].value.ul;
            }

            if (persistentDef)
                persistentDefCopy->cputune.period = params[i].value.ul;
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_QUOTA)) {
            if (def) {
                rc = lxcSetVcpuBWLive(priv->cgroup, 0, params[i].value.l);
                if (rc != 0)
                    goto endjob;

                if (params[i].value.l)
                    def->cputune.quota = params[i].value.l;
            }

            if (persistentDef)
                persistentDefCopy->cputune.quota = params[i].value.l;
        }
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto endjob;


    if (persistentDef) {
        rc = virDomainSaveConfig(cfg->configDir, driver->caps, persistentDefCopy);
        if (rc < 0)
            goto endjob;

        virDomainObjAssignDef(vm, persistentDefCopy, false, NULL);
        persistentDefCopy = NULL;
    }

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(persistentDefCopy);
    virDomainObjEndAPI(&vm);
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
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
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
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerParametersFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (*nparams > 1)
        cpu_bw_status = virCgroupSupportsCpuBW(priv->cgroup);

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto cleanup;

    if (persistentDef) {
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
    virDomainObjEndAPI(&vm);
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
lxcDomainParseBlkioDeviceStr(char *blkioDeviceStr, const char *type,
                             virBlkioDevicePtr *dev, size_t *size)
{
    char *temp;
    int ndevices = 0;
    int nsep = 0;
    size_t i;
    virBlkioDevicePtr result = NULL;

    *dev = NULL;
    *size = 0;

    if (STREQ(blkioDeviceStr, ""))
        return 0;

    temp = blkioDeviceStr;
    while (temp) {
        temp = strchr(temp, ',');
        if (temp) {
            temp++;
            nsep++;
        }
    }

    /* A valid string must have even number of fields, hence an odd
     * number of commas.  */
    if (!(nsep & 1))
        goto parse_error;

    ndevices = (nsep + 1) / 2;

    if (VIR_ALLOC_N(result, ndevices) < 0)
        return -1;

    i = 0;
    temp = blkioDeviceStr;
    while (temp) {
        char *p = temp;

        /* device path */
        p = strchr(p, ',');
        if (!p)
            goto parse_error;

        if (VIR_STRNDUP(result[i].path, temp, p - temp) < 0)
            goto cleanup;

        /* value */
        temp = p + 1;

        if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].weight) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].riops) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
            if (virStrToLong_uip(temp, &p, 10, &result[i].wiops) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
            if (virStrToLong_ullp(temp, &p, 10, &result[i].rbps) < 0)
                goto number_error;
        } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
            if (virStrToLong_ullp(temp, &p, 10, &result[i].wbps) < 0)
                goto number_error;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown parameter '%s'"), type);
            goto cleanup;
        }

        i++;

        if (*p == '\0')
            break;
        else if (*p != ',')
            goto parse_error;
        temp = p + 1;
    }

    if (!i)
        VIR_FREE(result);

    *dev = result;
    *size = i;

    return 0;

 parse_error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("unable to parse blkio device '%s' '%s'"),
                   type, blkioDeviceStr);
    goto cleanup;

 number_error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("invalid value '%s' for parameter '%s' of device '%s'"),
                   temp, type, result[i].path);

 cleanup:
    if (result) {
        virBlkioDeviceArrayClear(result, ndevices);
        VIR_FREE(result);
    }
    return -1;
}

static int
lxcDomainMergeBlkioDevice(virBlkioDevicePtr *dest_array,
                          size_t *dest_size,
                          virBlkioDevicePtr src_array,
                          size_t src_size,
                          const char *type)
{
    size_t i, j;
    virBlkioDevicePtr dest, src;

    for (i = 0; i < src_size; i++) {
        bool found = false;

        src = &src_array[i];
        for (j = 0; j < *dest_size; j++) {
            dest = &(*dest_array)[j];
            if (STREQ(src->path, dest->path)) {
                found = true;

                if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                    dest->weight = src->weight;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                    dest->riops = src->riops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                    dest->wiops = src->wiops;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                    dest->rbps = src->rbps;
                } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                    dest->wbps = src->wbps;
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, _("Unknown parameter %s"),
                                   type);
                    return -1;
                }

                break;
            }
        }
        if (!found) {
            if (!src->weight && !src->riops && !src->wiops && !src->rbps && !src->wbps)
                continue;
            if (VIR_EXPAND_N(*dest_array, *dest_size, 1) < 0)
                return -1;
            dest = &(*dest_array)[*dest_size - 1];

            if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                dest->weight = src->weight;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                dest->riops = src->riops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                dest->wiops = src->wiops;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                dest->rbps = src->rbps;
            } else if (STREQ(type, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                dest->wbps = src->wbps;
            } else {
                *dest_size = *dest_size - 1;
                return -1;
            }

            dest->path = src->path;
            src->path = NULL;
        }
    }

    return 0;
}


static int
lxcDomainBlockStats(virDomainPtr dom,
                    const char *path,
                    virDomainBlockStatsPtr stats)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    int ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;
    virLXCDomainObjPrivatePtr priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainBlockStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

   if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio cgroup isn't mounted"));
        goto endjob;
    }

    if (!*path) {
        /* empty path - return entire domain blkstats instead */
        ret = virCgroupGetBlkioIoServiced(priv->cgroup,
                                          &stats->rd_bytes,
                                          &stats->wr_bytes,
                                          &stats->rd_req,
                                          &stats->wr_req);
        goto endjob;
    }

    if (!(disk = virDomainDiskByName(vm->def, path, false))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid path: %s"), path);
        goto endjob;
    }

    if (!disk->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %s"), disk->dst);
        goto endjob;
    }

    ret = virCgroupGetBlkioIoDeviceServiced(priv->cgroup,
                                            disk->info.alias,
                                            &stats->rd_bytes,
                                            &stats->wr_bytes,
                                            &stats->rd_req,
                                            &stats->wr_req);

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcDomainBlockStatsFlags(virDomainPtr dom,
                         const char * path,
                         virTypedParameterPtr params,
                         int * nparams,
                         unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    int tmp, ret = -1;
    virDomainObjPtr vm;
    virDomainDiskDefPtr disk = NULL;
    virLXCDomainObjPrivatePtr priv;
    long long rd_req, rd_bytes, wr_req, wr_bytes;
    virTypedParameterPtr param;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!params && !*nparams) {
        *nparams = LXC_NB_DOMAIN_BLOCK_STAT_PARAM;
        return 0;
    }

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainBlockStatsFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio cgroup isn't mounted"));
        goto endjob;
    }

    if (!*path) {
        /* empty path - return entire domain blkstats instead */
        if (virCgroupGetBlkioIoServiced(priv->cgroup,
                                        &rd_bytes,
                                        &wr_bytes,
                                        &rd_req,
                                        &wr_req) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("domain stats query failed"));
            goto endjob;
        }
    } else {
        if (!(disk = virDomainDiskByName(vm->def, path, false))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("invalid path: %s"), path);
            goto endjob;
        }

        if (!disk->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing disk device alias name for %s"), disk->dst);
            goto endjob;
        }

        if (virCgroupGetBlkioIoDeviceServiced(priv->cgroup,
                                              disk->info.alias,
                                              &rd_bytes,
                                              &wr_bytes,
                                              &rd_req,
                                              &wr_req) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("domain stats query failed"));
            goto endjob;
        }
    }

    tmp = 0;
    ret = -1;

    if (tmp < *nparams && wr_bytes != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES,
                                    VIR_TYPED_PARAM_LLONG, wr_bytes) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && wr_req != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_WRITE_REQ,
                                    VIR_TYPED_PARAM_LLONG, wr_req) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && rd_bytes != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_READ_BYTES,
                                    VIR_TYPED_PARAM_LLONG, rd_bytes) < 0)
            goto endjob;
        tmp++;
    }

    if (tmp < *nparams && rd_req != -1) {
        param = &params[tmp];
        if (virTypedParameterAssign(param, VIR_DOMAIN_BLOCK_STATS_READ_REQ,
                                    VIR_TYPED_PARAM_LLONG, rd_req) < 0)
            goto endjob;
        tmp++;
    }

    ret = 0;
    *nparams = tmp;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcDomainSetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    size_t i;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = NULL;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_BLKIO_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_READ_BPS,
                               VIR_TYPED_PARAM_STRING,
                               VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS,
                               VIR_TYPED_PARAM_STRING,
                               NULL) < 0)
        return -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;
    cfg = virLXCDriverGetConfig(driver);

    if (virDomainSetBlkioParametersEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (def) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto endjob;
        }
    }

    ret = 0;
    if (def) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                if (virCgroupSetBlkioWeight(priv->cgroup, params[i].value.ui) < 0)
                    ret = -1;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                size_t ndevices;
                virBlkioDevicePtr devices = NULL;
                size_t j;

                if (lxcDomainParseBlkioDeviceStr(params[i].value.s,
                                                 param->field,
                                                 &devices,
                                                 &ndevices) < 0) {
                    ret = -1;
                    continue;
                }

                if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWeight(priv->cgroup,
                                                          devices[j].path,
                                                          devices[j].weight) < 0 ||
                            virCgroupGetBlkioDeviceWeight(priv->cgroup,
                                                          devices[j].path,
                                                          &devices[j].weight) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceReadIops(priv->cgroup,
                                                            devices[j].path,
                                                            devices[j].riops) < 0 ||
                            virCgroupGetBlkioDeviceReadIops(priv->cgroup,
                                                            devices[j].path,
                                                            &devices[j].riops) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWriteIops(priv->cgroup,
                                                             devices[j].path,
                                                             devices[j].wiops) < 0 ||
                            virCgroupGetBlkioDeviceWriteIops(priv->cgroup,
                                                             devices[j].path,
                                                             &devices[j].wiops) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceReadBps(priv->cgroup,
                                                           devices[j].path,
                                                           devices[j].rbps) < 0 ||
                            virCgroupGetBlkioDeviceReadBps(priv->cgroup,
                                                           devices[j].path,
                                                           &devices[j].rbps) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                    for (j = 0; j < ndevices; j++) {
                        if (virCgroupSetBlkioDeviceWriteBps(priv->cgroup,
                                                            devices[j].path,
                                                            devices[j].wbps) < 0 ||
                            virCgroupGetBlkioDeviceWriteBps(priv->cgroup,
                                                            devices[j].path,
                                                            &devices[j].wbps) < 0) {
                            ret = -1;
                            break;
                        }
                    }
                } else {
                    virReportError(VIR_ERR_INVALID_ARG, _("Unknown blkio parameter %s"),
                                   param->field);
                    ret = -1;
                    virBlkioDeviceArrayClear(devices, ndevices);
                    VIR_FREE(devices);

                    continue;
                }

                if (j != ndevices ||
                    lxcDomainMergeBlkioDevice(&def->blkio.devices,
                                              &def->blkio.ndevices,
                                              devices, ndevices, param->field) < 0)
                    ret = -1;
                virBlkioDeviceArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }
    }
    if (ret < 0)
        goto endjob;
    if (persistentDef) {
        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                persistentDef->blkio.weight = params[i].value.ui;
            } else if (STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_IOPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_READ_BPS) ||
                       STREQ(param->field, VIR_DOMAIN_BLKIO_DEVICE_WRITE_BPS)) {
                virBlkioDevicePtr devices = NULL;
                size_t ndevices;

                if (lxcDomainParseBlkioDeviceStr(params[i].value.s,
                                                 param->field,
                                                 &devices,
                                                 &ndevices) < 0) {
                    ret = -1;
                    continue;
                }
                if (lxcDomainMergeBlkioDevice(&persistentDef->blkio.devices,
                                              &persistentDef->blkio.ndevices,
                                              devices, ndevices, param->field) < 0)
                    ret = -1;
                virBlkioDeviceArrayClear(devices, ndevices);
                VIR_FREE(devices);
            }
        }

        if (virDomainSaveConfig(cfg->configDir, driver->caps, persistentDef) < 0)
            ret = -1;
    }

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


#define LXC_NB_BLKIO_PARAM  6

static int
lxcDomainGetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def = NULL;
    virDomainDefPtr persistentDef = NULL;
    int maxparams = LXC_NB_BLKIO_PARAM;
    unsigned int val;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We blindly return a string, and let libvirt.c and
     * remote_driver.c do the filtering on behalf of older clients
     * that can't parse it.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!(vm = lxcDomObjFromDomain(dom)))
        return -1;

    priv = vm->privateData;

    if (virDomainGetBlkioParametersEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((*nparams) == 0) {
        /* Current number of blkio parameters supported by cgroups */
        *nparams = LXC_NB_BLKIO_PARAM;
        ret = 0;
        goto cleanup;
    } else if (*nparams < maxparams) {
        maxparams = *nparams;
    }

    *nparams = 0;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto cleanup;

    if (def) {
        if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_BLKIO)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        /* fill blkio weight here */
        if (virCgroupGetBlkioWeight(priv->cgroup, &val) < 0)
            goto cleanup;
        if (virTypedParameterAssign(&(params[(*nparams)++]),
                                    VIR_DOMAIN_BLKIO_WEIGHT,
                                    VIR_TYPED_PARAM_UINT, val) < 0)
            goto cleanup;

        if (virDomainGetBlkioParametersAssignFromDef(def, params, nparams,
                                                     maxparams) < 0)
            goto cleanup;

    } else if (persistentDef) {
        /* fill blkio weight here */
        if (virTypedParameterAssign(&(params[(*nparams)++]),
                                    VIR_DOMAIN_BLKIO_WEIGHT,
                                    VIR_TYPED_PARAM_UINT,
                                    persistentDef->blkio.weight) < 0)
            goto cleanup;

        if (virDomainGetBlkioParametersAssignFromDef(persistentDef, params,
                                                     nparams, maxparams) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


#ifdef __linux__
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path,
                        virDomainInterfaceStatsPtr stats)
{
    virDomainObjPtr vm;
    size_t i;
    int ret = -1;
    virLXCDriverPtr driver = dom->conn->privateData;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
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
        ret = virNetDevTapInterfaceStats(path, stats);
    else
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid path, '%s' is not a known interface"), path);

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}
#else
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path ATTRIBUTE_UNUSED,
                        virDomainInterfaceStatsPtr stats ATTRIBUTE_UNUSED)
{
    virReportUnsupportedError();
    return -1;
}
#endif

static int lxcDomainGetAutostart(virDomainPtr dom,
                                   int *autostart)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
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

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot set autostart for transient domain"));
        goto endjob;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart) {
        ret = 0;
        goto endjob;
    }

    configFile = virDomainConfigFile(cfg->configDir,
                                     vm->def->name);
    if (configFile == NULL)
        goto endjob;
    autostartLink = virDomainConfigFile(cfg->autostartDir,
                                        vm->def->name);
    if (autostartLink == NULL)
        goto endjob;

    if (autostart) {
        if (virFileMakePath(cfg->autostartDir) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create autostart directory %s"),
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
    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainObjEndAPI(&vm);
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
         * being frozen but incomplete, and other errors are true
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
    virObjectEventPtr event = NULL;
    int ret = -1;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (lxcFreezeContainer(vm) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("Suspend operation failed"));
            goto endjob;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto endjob;
    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}

static int lxcDomainResume(virDomainPtr dom)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;
    int state;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    state = virDomainObjGetState(vm, NULL);
    if (state == VIR_DOMAIN_RUNNING) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is already running"));
        goto endjob;
    } else if (state == VIR_DOMAIN_PAUSED) {
        if (virCgroupSetFreezerState(priv->cgroup, "THAWED") < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("Resume operation failed"));
            goto endjob;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto endjob;
    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
    virDomainObjEndAPI(&vm);
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
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcDomainSendProcessSignal(virDomainPtr dom,
                           long long pid_value,
                           unsigned int signum,
                           unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
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

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
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
        goto endjob;
    }

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto endjob;
    }
    victim = priv->initpid;

    /* We're relying on fact libvirt header signal numbers
     * are taken from Linux, to avoid mapping
     */
    if (kill(victim, signum) < 0) {
        virReportSystemError(errno,
                             _("Unable to send %d signal to process %d"),
                             signum, victim);
        goto endjob;
    }

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
lxcDomainInitctlCallback(pid_t pid ATTRIBUTE_UNUSED,
                         void *opaque)
{
    int *command = opaque;
    return virInitctlSetRunLevel(*command);
}


static int
lxcDomainShutdownFlags(virDomainPtr dom,
                       unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virLXCDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_INITCTL |
                  VIR_DOMAIN_SHUTDOWN_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto endjob;
    }

    if (flags == 0 ||
        (flags & VIR_DOMAIN_SHUTDOWN_INITCTL)) {
        int command = VIR_INITCTL_RUNLEVEL_POWEROFF;

        if ((rc = virProcessRunInMountNamespace(priv->initpid,
                                                lxcDomainInitctlCallback,
                                                &command)) < 0)
            goto endjob;
        if (rc == 0 && flags != 0 &&
            ((flags & ~VIR_DOMAIN_SHUTDOWN_INITCTL) == 0)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("Container does not provide an initctl pipe"));
            goto endjob;
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
                                 (long long) priv->initpid);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virLXCDriverPtr driver = dom->conn->privateData;
    virLXCDomainObjPrivatePtr priv;
    virDomainObjPtr vm;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_REBOOT_INITCTL |
                  VIR_DOMAIN_REBOOT_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto endjob;
    }

    if (flags == 0 ||
        (flags & VIR_DOMAIN_REBOOT_INITCTL)) {
        int command = VIR_INITCTL_RUNLEVEL_REBOOT;

        if ((rc = virProcessRunInMountNamespace(priv->initpid,
                                                lxcDomainInitctlCallback,
                                                &command)) < 0)
            goto endjob;
        if (rc == 0 && flags != 0 &&
            ((flags & ~VIR_DOMAIN_SHUTDOWN_INITCTL) == 0)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("Container does not provide an initctl pipe"));
            goto endjob;
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
                                 (long long) priv->initpid);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
            goto cleanup;

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
        if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
            goto cleanup;

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


struct lxcDomainAttachDeviceMknodData {
    virLXCDriverPtr driver;
    mode_t mode;
    dev_t dev;
    virDomainObjPtr vm;
    virDomainDeviceDefPtr def;
    char *file;
};

static int
lxcDomainAttachDeviceMknodHelper(pid_t pid ATTRIBUTE_UNUSED,
                                 void *opaque)
{
    struct lxcDomainAttachDeviceMknodData *data = opaque;
    int ret = -1;

    virSecurityManagerPostFork(data->driver->securityManager);

    if (virFileMakeParentPath(data->file) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %s"), data->file);
        goto cleanup;
    }

    /* Yes, the device name we're creating may not
     * actually correspond to the major:minor number
     * we're using, but we've no other option at this
     * time. Just have to hope that containerized apps
     * don't get upset that the major:minor is different
     * to that normally implied by the device name
     */
    VIR_DEBUG("Creating dev %s (%d,%d)",
              data->file, major(data->dev), minor(data->dev));
    if (mknod(data->file, data->mode, data->dev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             data->file);
        goto cleanup;
    }

    if (lxcContainerChown(data->vm->def, data->file) < 0)
        goto cleanup;

    /* Labelling normally operates on src, but we need
     * to actually label the dst here, so hack the config */
    switch (data->def->type) {
    case VIR_DOMAIN_DEVICE_DISK: {
        virDomainDiskDefPtr def = data->def->data.disk;
        char *tmpsrc = def->src->path;
        def->src->path = data->file;
        if (virSecurityManagerSetDiskLabel(data->driver->securityManager,
                                           data->vm->def, def) < 0) {
            def->src->path = tmpsrc;
            goto cleanup;
        }
        def->src->path = tmpsrc;
    }   break;

    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        virDomainHostdevDefPtr def = data->def->data.hostdev;
        if (virSecurityManagerSetHostdevLabel(data->driver->securityManager,
                                              data->vm->def, def, NULL) < 0)
            goto cleanup;
    }   break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected device type %d"),
                       data->def->type);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0)
        unlink(data->file);
    return ret;
}


static int
lxcDomainAttachDeviceMknod(virLXCDriverPtr driver,
                           mode_t mode,
                           dev_t dev,
                           virDomainObjPtr vm,
                           virDomainDeviceDefPtr def,
                           char *file)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    struct lxcDomainAttachDeviceMknodData data;

    memset(&data, 0, sizeof(data));

    data.driver = driver;
    data.mode = mode;
    data.dev = dev;
    data.vm = vm;
    data.def = def;
    data.file = file;

    if (virSecurityManagerPreFork(driver->securityManager) < 0)
        return -1;

    if (virProcessRunInMountNamespace(priv->initpid,
                                      lxcDomainAttachDeviceMknodHelper,
                                      &data) < 0) {
        virSecurityManagerPostFork(driver->securityManager);
        return -1;
    }

    virSecurityManagerPostFork(driver->securityManager);
    return 0;
}


static int
lxcDomainAttachDeviceUnlinkHelper(pid_t pid ATTRIBUTE_UNUSED,
                                  void *opaque)
{
    const char *path = opaque;

    VIR_DEBUG("Unlinking %s", path);
    if (unlink(path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove device %s"), path);
        return -1;
    }

    return 0;
}


static int
lxcDomainAttachDeviceUnlink(virDomainObjPtr vm,
                            char *file)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    if (virProcessRunInMountNamespace(priv->initpid,
                                      lxcDomainAttachDeviceUnlinkHelper,
                                      file) < 0) {
        return -1;
    }

    return 0;
}


static int
lxcDomainAttachDeviceDiskLive(virLXCDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainDiskDefPtr def = dev->data.disk;
    int ret = -1;
    struct stat sb;
    char *file = NULL;
    int perms;
    const char *src = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        goto cleanup;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    src = virDomainDiskGetSource(def);
    if (src == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk without media"));
        goto cleanup;
    }

    if (!virStorageSourceIsBlockLocal(def->src)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk for non-block device"));
        goto cleanup;
    }

    if (virDomainDiskIndexByName(vm->def, def->dst, true) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %s already exists"), def->dst);
        goto cleanup;
    }

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), src);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk source %s must be a block device"),
                       src);
        goto cleanup;
    }

    perms = (def->src->readonly ?
             VIR_CGROUP_DEVICE_READ :
             VIR_CGROUP_DEVICE_RW) |
        VIR_CGROUP_DEVICE_MKNOD;

    if (virCgroupAllowDevice(priv->cgroup,
                             'b',
                             major(sb.st_rdev),
                             minor(sb.st_rdev),
                             perms) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks + 1) < 0)
        goto cleanup;

    if (virAsprintf(&file,
                    "/dev/%s", def->dst) < 0)
        goto cleanup;

    if (lxcDomainAttachDeviceMknod(driver,
                                   0700 | S_IFBLK,
                                   sb.st_rdev,
                                   vm,
                                   dev,
                                   file) < 0) {
        if (virCgroupDenyDevice(priv->cgroup,
                                'b',
                                major(sb.st_rdev),
                                minor(sb.st_rdev),
                                perms) < 0)
            VIR_WARN("cannot deny device %s for domain %s",
                     src, vm->def->name);
        goto cleanup;
    }

    virDomainDiskInsertPreAlloced(vm->def, def);

    ret = 0;

 cleanup:
    if (src)
        virDomainAuditDisk(vm, NULL, def->src, "attach", ret == 0);
    VIR_FREE(file);
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
    virDomainNetType actualType;
    virNetDevBandwidthPtr actualBandwidth;
    char *veth = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        return -1;
    }

    if (virLXCProcessValidateInterface(net) < 0)
       return -1;

    /* preallocate new slot for device */
    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets+1) < 0)
        return -1;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (networkAllocateActualDevice(vm->def, net) < 0)
        return -1;

    actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK: {
        const char *brname = virDomainNetGetActualBridgeName(net);
        if (!brname) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No bridge name specified"));
            goto cleanup;
        }
        if (!(veth = virLXCProcessSetupInterfaceTap(vm->def, net, brname)))
            goto cleanup;
    }   break;
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (!(veth = virLXCProcessSetupInterfaceTap(vm->def, net, NULL)))
            goto cleanup;
        break;
    case VIR_DOMAIN_NET_TYPE_DIRECT: {
        if (!(veth = virLXCProcessSetupInterfaceDirect(conn, vm->def, net)))
            goto cleanup;
    }   break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Network device type is not supported"));
        goto cleanup;
    }
    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportBandwidth(actualType)) {
            if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false) < 0)
                goto cleanup;
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet",
                     virDomainNetTypeToString(actualType));
        }
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
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            ignore_value(virNetDevVethDelete(veth));
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            ignore_value(virNetDevMacVLanDelete(veth));
            break;

        default:
            /* no-op */
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
    char *src = NULL;
    struct stat sb;
    virUSBDevicePtr usb = NULL;
    virDomainHostdevSubsysUSBPtr usbsrc;

    if (virDomainHostdevFind(vm->def, def, NULL) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("host USB device already exists"));
        return -1;
    }

    usbsrc = &def->source.subsys.u.usb;
    if (virAsprintf(&src, "/dev/bus/usb/%03d/%03d",
                    usbsrc->bus, usbsrc->device) < 0)
        goto cleanup;

    if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL)))
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

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1) < 0)
        goto cleanup;

    if (virUSBDeviceFileIterate(usb,
                                virLXCSetupHostUSBDeviceCgroup,
                                priv->cgroup) < 0)
        goto cleanup;

    if (lxcDomainAttachDeviceMknod(driver,
                                   0700 | S_IFCHR,
                                   sb.st_rdev,
                                   vm,
                                   dev,
                                   src) < 0) {
        if (virUSBDeviceFileIterate(usb,
                                    virLXCTeardownHostUSBDeviceCgroup,
                                    priv->cgroup) < 0)
            VIR_WARN("cannot deny device %s for domain %s",
                     src, vm->def->name);
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    virUSBDeviceFree(usb);
    VIR_FREE(src);
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
    struct stat sb;

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

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0)
        goto cleanup;

    if (virCgroupAllowDevice(priv->cgroup,
                             'b',
                             major(sb.st_rdev),
                             minor(sb.st_rdev),
                             VIR_CGROUP_DEVICE_RWM) < 0)
        goto cleanup;

    if (lxcDomainAttachDeviceMknod(driver,
                                   0700 | S_IFBLK,
                                   sb.st_rdev,
                                   vm,
                                   dev,
                                   def->source.caps.u.storage.block) < 0) {
        if (virCgroupDenyDevice(priv->cgroup,
                                'b',
                                major(sb.st_rdev),
                                minor(sb.st_rdev),
                                VIR_CGROUP_DEVICE_RWM) < 0)
            VIR_WARN("cannot deny device %s for domain %s",
                     def->source.caps.u.storage.block, vm->def->name);
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
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
    struct stat sb;

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

    if (virCgroupAllowDevice(priv->cgroup,
                             'c',
                             major(sb.st_rdev),
                             minor(sb.st_rdev),
                             VIR_CGROUP_DEVICE_RWM) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0)
        goto cleanup;

    if (lxcDomainAttachDeviceMknod(driver,
                                   0700 | S_IFBLK,
                                   sb.st_rdev,
                                   vm,
                                   dev,
                                   def->source.caps.u.misc.chardev) < 0) {
        if (virCgroupDenyDevice(priv->cgroup,
                                'c',
                                major(sb.st_rdev),
                                minor(sb.st_rdev),
                                VIR_CGROUP_DEVICE_RWM) < 0)
            VIR_WARN("cannot deny device %s for domain %s",
                     def->source.caps.u.storage.block, vm->def->name);
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
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

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
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
    const char *src;

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
    src = virDomainDiskGetSource(def);

    if (virAsprintf(&dst, "/dev/%s", def->dst) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (lxcDomainAttachDeviceUnlink(vm, dst) < 0) {
        virDomainAuditDisk(vm, def->src, NULL, "detach", false);
        goto cleanup;
    }
    virDomainAuditDisk(vm, def->src, NULL, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, src,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 src, vm->def->name);

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
    virDomainNetType actualType;
    virDomainNetDefPtr detach = NULL;
    virNetDevVPortProfilePtr vport = NULL;

    if ((detachidx = virDomainNetFindIdx(vm->def, dev->data.net)) < 0)
        goto cleanup;

    detach = vm->def->nets[detachidx];
    actualType = virDomainNetGetActualType(detach);

    /* clear network bandwidth */
    if (virDomainNetGetActualBandwidth(detach) &&
        virNetDevSupportBandwidth(actualType) &&
        virNetDevBandwidthClear(detach->ifname))
        goto cleanup;

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
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
        networkReleaseActualDevice(vm->def, detach);
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
    virUSBDevicePtr usb = NULL;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;
    virDomainHostdevSubsysUSBPtr usbsrc;

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("usb device not found"));
        goto cleanup;
    }

    usbsrc = &def->source.subsys.u.usb;
    if (virAsprintf(&dst, "/dev/bus/usb/%03d/%03d",
                    usbsrc->bus, usbsrc->device) < 0)
        goto cleanup;

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL)))
        goto cleanup;

    if (lxcDomainAttachDeviceUnlink(vm, dst) < 0) {
        virDomainAuditHostdev(vm, def, "detach", false);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virUSBDeviceFileIterate(usb,
                                virLXCTeardownHostUSBDeviceCgroup,
                                priv->cgroup) < 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 dst, vm->def->name);

    virObjectLock(hostdev_mgr->activeUSBHostdevs);
    virUSBDeviceListDel(hostdev_mgr->activeUSBHostdevs, usb);
    virObjectUnlock(hostdev_mgr->activeUSBHostdevs);

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

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (lxcDomainAttachDeviceUnlink(vm, def->source.caps.u.storage.block) < 0) {
        virDomainAuditHostdev(vm, def, "detach", false);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.storage.block,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->source.caps.u.storage.block, vm->def->name);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

 cleanup:
    return ret;
}


static int
lxcDomainDetachDeviceHostdevMiscLive(virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevDefPtr def = NULL;
    int idx, ret = -1;

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

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        goto cleanup;
    }

    if (lxcDomainAttachDeviceUnlink(vm, def->source.caps.u.misc.chardev) < 0) {
        virDomainAuditHostdev(vm, def, "detach", false);
        goto cleanup;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.misc.chardev,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s",
                 def->source.caps.u.misc.chardev, vm->def->name);

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

 cleanup:
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
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto endjob;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH) < 0)
            goto endjob;

        if ((ret = lxcDomainAttachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH) < 0)
            goto endjob;

        if ((ret = lxcDomainAttachDeviceLive(dom->conn, driver, vm, dev_copy)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, driver->caps, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
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
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_DEVICE_MODIFY_FORCE, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto endjob;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (dev == NULL)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE) < 0)
            goto endjob;

        if ((ret = lxcDomainUpdateDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE) < 0)
            goto endjob;

        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to modify live devices"));

        goto endjob;
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, driver->caps, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }
 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
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
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto endjob;

    dev = dev_copy = virDomainDeviceDefParse(xml, vm->def,
                                             caps, driver->xmlopt,
                                             VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                             VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
    if (dev == NULL)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG &&
        flags & VIR_DOMAIN_AFFECT_LIVE) {
        /* If we are affecting both CONFIG and LIVE
         * create a deep copy of device as adding
         * to CONFIG takes one instance.
         */
        dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                          caps, driver->xmlopt);
        if (!dev_copy)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, caps, driver->xmlopt);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev,
                                         VIR_DOMAIN_DEVICE_ACTION_DETACH) < 0)
            goto endjob;

        if ((ret = lxcDomainDetachDeviceConfig(vmdef, dev)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_copy,
                                         VIR_DOMAIN_DEVICE_ACTION_DETACH) < 0)
            goto endjob;

        if ((ret = lxcDomainDetachDeviceLive(driver, vm, dev_copy)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainSaveConfig(cfg->configDir, driver->caps, vmdef);
        if (!ret) {
            virDomainObjAssignDef(vm, vmdef, false, NULL);
            vmdef = NULL;
        }
    }

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainDefFree(vmdef);
    if (dev != dev_copy)
        virDomainDeviceDefFree(dev_copy);
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
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
    virLXCDriverPtr driver = dom->conn->privateData;
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

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is not running"));
        goto endjob;
    }

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto endjob;
    }

    if (virProcessGetNamespaces(priv->initpid, &nfds, fdlist) < 0)
        goto endjob;

    ret = nfds;

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    if (virBufferCheckError(&buf) < 0)
        return NULL;
    return virBufferContentAndReset(&buf);
}


static int
lxcNodeGetInfo(virConnectPtr conn,
               virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return virCapabilitiesGetNodeInfo(nodeinfo);
}


static int
lxcDomainMemoryStats(virDomainPtr dom,
                     virDomainMemoryStatPtr stats,
                     unsigned int nr_stats,
                     unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;
    unsigned long long swap_usage;
    unsigned long mem_usage;
    virLXCDriverPtr driver = dom->conn->privateData;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainMemoryStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_QUERY) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not active"));
        goto endjob;
    }

    if (virCgroupGetMemSwapUsage(priv->cgroup, &swap_usage) < 0)
        goto endjob;

    if (virCgroupGetMemoryUsage(priv->cgroup, &mem_usage) < 0)
        goto endjob;

    ret = 0;
    if (ret < nr_stats) {
        stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON;
        stats[ret].val = vm->def->mem.cur_balloon;
        ret++;
    }
    if (ret < nr_stats) {
        stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_SWAP_IN;
        stats[ret].val = swap_usage;
        ret++;
    }
    if (ret < nr_stats) {
        stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_RSS;
        stats[ret].val = mem_usage;
        ret++;
    }

 endjob:
    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
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

    return virHostCPUGetStats(cpuNum, params, nparams, flags);
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

    return virHostMemGetStats(cellNum, params, nparams, flags);
}


static int
lxcNodeGetCellsFreeMemory(virConnectPtr conn,
                          unsigned long long *freeMems,
                          int startCell,
                          int maxCells)
{
    if (virNodeGetCellsFreeMemoryEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetCellsFree(freeMems, startCell, maxCells);
}


static unsigned long long
lxcNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMem;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;

    return freeMem;
}


static int
lxcNodeGetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int *nparams,
                           unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetParameters(params, nparams, flags);
}


static int
lxcNodeSetMemoryParameters(virConnectPtr conn,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemSetParameters(params, nparams, flags);
}


static int
lxcNodeGetCPUMap(virConnectPtr conn,
                 unsigned char **cpumap,
                 unsigned int *online,
                 unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return virHostCPUGetMap(cpumap, online, flags);
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


static int
lxcDomainSetMetadata(virDomainPtr dom,
                      int type,
                      const char *metadata,
                      const char *key,
                      const char *uri,
                      unsigned int flags)
{
    virLXCDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virLXCDriverConfigPtr cfg = NULL;
    virCapsPtr caps = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return -1;

    cfg = virLXCDriverGetConfig(driver);

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (virLXCDomainObjBeginJob(driver, vm, LXC_JOB_MODIFY) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri, caps,
                                  driver->xmlopt, cfg->stateDir,
                                  cfg->configDir, flags);

    if (ret == 0) {
        virObjectEventPtr ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(driver->domainEventState, ev);
    }

    virLXCDomainObjEndJob(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;
}


static char *
lxcDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = lxcDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcDomainGetCPUStats(virDomainPtr dom,
                     virTypedParameterPtr params,
                     unsigned int nparams,
                     int start_cpu,
                     unsigned int ncpus,
                     unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;
    virLXCDomainObjPrivatePtr priv;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainGetCPUStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_CPUACCT)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cgroup CPUACCT controller is not mounted"));
        goto cleanup;
    }

    if (start_cpu == -1)
        ret = virCgroupGetDomainTotalCpuStats(priv->cgroup,
                                              params, nparams);
    else
        ret = virCgroupGetPercpuStats(priv->cgroup, params,
                                      nparams, start_cpu, ncpus, NULL);
 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcNodeGetFreePages(virConnectPtr conn,
                    unsigned int npages,
                    unsigned int *pages,
                    int startCell,
                    unsigned int cellCount,
                    unsigned long long *counts,
                    unsigned int flags)
{
    virCheckFlags(0, -1);

    if (virNodeGetFreePagesEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetFreePages(npages, pages, startCell, cellCount, counts);
}


static int
lxcNodeAllocPages(virConnectPtr conn,
                  unsigned int npages,
                  unsigned int *pageSizes,
                  unsigned long long *pageCounts,
                  int startCell,
                  unsigned int cellCount,
                  unsigned int flags)
{
    bool add = !(flags & VIR_NODE_ALLOC_PAGES_SET);

    virCheckFlags(VIR_NODE_ALLOC_PAGES_SET, -1);

    if (virNodeAllocPagesEnsureACL(conn) < 0)
        return -1;

    return virHostMemAllocPages(npages, pageSizes, pageCounts,
                                startCell, cellCount, add);
}


static int
lxcDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    if (virDomainHasManagedSaveImageEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/* Function Tables */
static virHypervisorDriver lxcHypervisorDriver = {
    .name = LXC_DRIVER_NAME,
    .connectOpen = lxcConnectOpen, /* 0.4.2 */
    .connectClose = lxcConnectClose, /* 0.4.2 */
    .connectSupportsFeature = lxcConnectSupportsFeature, /* 1.2.2 */
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
    .domainSetMemoryFlags = lxcDomainSetMemoryFlags, /* 1.2.7 */
    .domainSetMemoryParameters = lxcDomainSetMemoryParameters, /* 0.8.5 */
    .domainGetMemoryParameters = lxcDomainGetMemoryParameters, /* 0.8.5 */
    .domainSetBlkioParameters = lxcDomainSetBlkioParameters, /* 0.9.8 */
    .domainGetBlkioParameters = lxcDomainGetBlkioParameters, /* 0.9.8 */
    .domainGetInfo = lxcDomainGetInfo, /* 0.4.2 */
    .domainGetState = lxcDomainGetState, /* 0.9.2 */
    .domainGetSecurityLabel = lxcDomainGetSecurityLabel, /* 0.9.10 */
    .nodeGetSecurityModel = lxcNodeGetSecurityModel, /* 0.9.10 */
    .domainGetXMLDesc = lxcDomainGetXMLDesc, /* 0.4.2 */
    .connectDomainXMLFromNative = lxcConnectDomainXMLFromNative, /* 1.2.2 */
    .connectListDefinedDomains = lxcConnectListDefinedDomains, /* 0.4.2 */
    .connectNumOfDefinedDomains = lxcConnectNumOfDefinedDomains, /* 0.4.2 */
    .domainCreate = lxcDomainCreate, /* 0.4.4 */
    .domainCreateWithFlags = lxcDomainCreateWithFlags, /* 0.8.2 */
    .domainCreateWithFiles = lxcDomainCreateWithFiles, /* 1.1.1 */
    .domainDefineXML = lxcDomainDefineXML, /* 0.4.2 */
    .domainDefineXMLFlags = lxcDomainDefineXMLFlags, /* 1.2.12 */
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
    .domainBlockStats = lxcDomainBlockStats, /* 1.2.2 */
    .domainBlockStatsFlags = lxcDomainBlockStatsFlags, /* 1.2.2 */
    .domainInterfaceStats = lxcDomainInterfaceStats, /* 0.7.3 */
    .domainMemoryStats = lxcDomainMemoryStats, /* 1.2.2 */
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
    .domainSetMetadata = lxcDomainSetMetadata, /* 1.1.3 */
    .domainGetMetadata = lxcDomainGetMetadata, /* 1.1.3 */
    .domainGetCPUStats = lxcDomainGetCPUStats, /* 1.2.2 */
    .nodeGetMemoryParameters = lxcNodeGetMemoryParameters, /* 0.10.2 */
    .nodeSetMemoryParameters = lxcNodeSetMemoryParameters, /* 0.10.2 */
    .domainSendProcessSignal = lxcDomainSendProcessSignal, /* 1.0.1 */
    .domainShutdown = lxcDomainShutdown, /* 1.0.1 */
    .domainShutdownFlags = lxcDomainShutdownFlags, /* 1.0.1 */
    .domainReboot = lxcDomainReboot, /* 1.0.1 */
    .domainLxcOpenNamespace = lxcDomainLxcOpenNamespace, /* 1.0.2 */
    .nodeGetFreePages = lxcNodeGetFreePages, /* 1.2.6 */
    .nodeAllocPages = lxcNodeAllocPages, /* 1.2.9 */
    .domainHasManagedSaveImage = lxcDomainHasManagedSaveImage, /* 1.2.13 */
};

static virConnectDriver lxcConnectDriver = {
    .hypervisorDriver = &lxcHypervisorDriver,
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
    if (virRegisterConnectDriver(&lxcConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&lxcStateDriver) < 0)
        return -1;
    return 0;
}
