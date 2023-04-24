/*
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_driver.c: linux container driver functions
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

#ifdef __linux__
# include <sys/sysmacros.h>
#endif

#include <sys/stat.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>

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
#include "virnetdevveth.h"
#include "virnetdevopenvswitch.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "viruuid.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virfdstream.h"
#include "domain_audit.h"
#include "domain_cgroup.h"
#include "domain_driver.h"
#include "domain_nwfilter.h"
#include "domain_validate.h"
#include "virinitctl.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnodesuspend.h"
#include "virprocess.h"
#include "virtypedparam.h"
#include "viruri.h"
#include "virstring.h"
#include "viraccessapicheck.h"
#include "viraccessapichecklxc.h"
#include "virhostdev.h"
#include "netdev_bandwidth_conf.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_driver");

#define LXC_NB_MEM_PARAM  3
#define LXC_NB_DOMAIN_BLOCK_STAT_PARAM 4


static int lxcStateCleanup(void);
virLXCDriver *lxc_driver = NULL;


/**
 * lxcDomObjFromDomain:
 * @domain: Domain pointer that has to be looked up
 *
 * This function looks up @domain and returns the appropriate virDomainObj *
 * that has to be released by calling virDomainObjEndAPI.
 *
 * Returns the domain object with incremented reference counter which is locked
 * on success, NULL otherwise.
 */
static virDomainObj *
lxcDomObjFromDomain(virDomainPtr domain)
{
    virDomainObj *vm;
    virLXCDriver *driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

/* Functions */

static int
lxcConnectURIProbe(char **uri)
{
    if (lxc_driver == NULL)
        return 0;

    *uri = g_strdup("lxc:///system");
    return 1;
}


static virDrvOpenStatus lxcConnectOpen(virConnectPtr conn,
                                       virConnectAuthPtr auth G_GNUC_UNUSED,
                                       virConf *conf G_GNUC_UNUSED,
                                       unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    /* If path isn't '/' then they typoed, tell them correct path */
    if (STRNEQ(conn->uri->path, "") &&
        STRNEQ(conn->uri->path, "/") &&
        STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected LXC URI path '%1$s', try lxc:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    /* URI was good, but driver isn't active */
    if (lxc_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("lxc state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = lxc_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int lxcConnectClose(virConnectPtr conn)
{
    virLXCDriver *driver = conn->privateData;

    virCloseCallbacksDomainRunForConn(driver->domains, conn);

    conn->privateData = NULL;
    return 0;
}


static int lxcConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int lxcConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int lxcConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}


static char *lxcConnectGetCapabilities(virConnectPtr conn) {
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    char *xml;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virLXCDriverGetCapabilities(driver, true)))
        return NULL;

    xml = virCapabilitiesFormatXML(caps);

    return xml;
}


static virDomainPtr lxcDomainLookupByID(virConnectPtr conn,
                                        int id)
{
    virLXCDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(driver->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching id %1$d"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr lxcDomainLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid)
{
    virLXCDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(driver->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%1$s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr lxcDomainLookupByName(virConnectPtr conn,
                                          const char *name)
{
    virLXCDriver *driver = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching name '%1$s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}


static int lxcDomainIsActive(virDomainPtr dom)
{
    virDomainObj *obj;
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
    virDomainObj *obj;
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
    virDomainObj *obj;
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
    virLXCDriver *driver = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(driver->domains, ids, nids,
                                        virConnectListDomainsCheckACL, conn);
}

static int lxcConnectNumOfDomains(virConnectPtr conn)
{
    virLXCDriver *driver = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);
}

static int lxcConnectListDefinedDomains(virConnectPtr conn,
                                        char **const names, int nnames)
{
    virLXCDriver *driver = conn->privateData;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetInactiveNames(driver->domains, names, nnames,
                                            virConnectListDefinedDomainsCheckACL,
                                            conn);
}


static int lxcConnectNumOfDefinedDomains(virConnectPtr conn)
{
    virLXCDriver *driver = conn->privateData;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(driver->domains, false,
                                        virConnectNumOfDefinedDomainsCheckACL,
                                        conn);
}



static virDomainPtr
lxcDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    virDomainPtr dom = NULL;
    virObjectEvent *event = NULL;
    g_autoptr(virDomainDef) oldDef = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    g_autoptr(virCaps) caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
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

    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   0, &oldDef)))
        goto cleanup;

    vm->persistent = 1;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         driver->xmlopt, cfg->configDir) < 0) {
        virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

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

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(driver->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
    return ret;
}

static int lxcDomainUndefine(virDomainPtr dom)
{
    return lxcDomainUndefineFlags(dom, 0);
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    virDomainObj *vm;
    int ret = -1;
    virLXCDomainObjPrivate *priv;

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
    virDomainObj *vm;
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
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

/* Returns max memory in kb, 0 if error */
static unsigned long long
lxcDomainGetMaxMemory(virDomainPtr dom)
{
    virDomainObj *vm;
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
    virDomainObj *vm;
    virDomainDef *def = NULL;
    virDomainDef *persistentDef = NULL;
    int ret = -1;
    virLXCDomainObjPrivate *priv;
    virLXCDriver *driver = dom->conn->privateData;
    g_autoptr(virLXCDriverConfig) cfg = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_MEM_MAXIMUM, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    cfg = virLXCDriverGetConfig(driver);

    priv = vm->privateData;

    if (virDomainSetMemoryFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_MEM_MAXIMUM) {
        if (def) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Cannot resize the max memory on an active domain"));
            goto endjob;
        }

        if (persistentDef) {
            virDomainDefSetMemoryTotal(persistentDef, newmem);
            if (persistentDef->mem.cur_balloon > newmem)
                persistentDef->mem.cur_balloon = newmem;
            if (virDomainDefSave(persistentDef,
                                 driver->xmlopt, cfg->configDir) < 0)
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
            if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
                goto endjob;
        }

        if (persistentDef) {
            persistentDef->mem.cur_balloon = newmem;
            if (virDomainDefSave(persistentDef,
                                 driver->xmlopt, cfg->configDir) < 0)
                goto endjob;
        }
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virDomainDef *def = NULL;
    virDomainDef *persistentDef = NULL;
    virDomainObj *vm = NULL;
    virLXCDomainObjPrivate *priv = NULL;
    g_autoptr(virLXCDriverConfig) cfg = NULL;
    virLXCDriver *driver = dom->conn->privateData;
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

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
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

    if (virDomainCgroupSetMemoryLimitParameters(priv->cgroup, vm, def,
                                                persistentDef,
                                                params, nparams) < 0)
        goto endjob;

    if (def &&
        virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;

    if (persistentDef &&
        virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir) < 0)
        goto endjob;
    /* QEMU and LXC implementations are identical */

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
lxcDomainGetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    virDomainDef *persistentDef = NULL;
    virDomainDef *def = NULL;
    virDomainObj *vm = NULL;
    virLXCDomainObjPrivate *priv = NULL;
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             driver->xmlopt,
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
    g_autoptr(virDomainDef) def = NULL;
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = virLXCDriverGetCapabilities(driver, false);

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(nativeFormat, LXC_CONFIG_FORMAT)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
        return NULL;
    }

    if (!(def = lxcParseConfigString(nativeConfig, caps, driver->xmlopt)))
        return NULL;

    return virDomainDefFormat(def, driver->xmlopt, 0);
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    virConnect *autoDestroyConn = NULL;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        autoDestroyConn = dom->conn;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFilesEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if ((vm->def->nets != NULL) && !(cfg->have_netns)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto endjob;
    }

    ret = virLXCProcessStart(driver, vm, nfiles, files, autoDestroyConn,
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
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
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
    virLXCDriver *driver = conn->privateData;
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) def = NULL;
    virDomainPtr dom = NULL;
    virObjectEvent *event = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    g_autoptr(virCaps) caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;
    virConnect *autoDestroyConn = NULL;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        autoDestroyConn = conn;

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!(def = virDomainDefParseString(xml, driver->xmlopt,
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


    if (!(vm = virDomainObjListAdd(driver->domains, &def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0) {
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    if (virLXCProcessStart(driver, vm, nfiles, files, autoDestroyConn,
                           VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        virDomainAuditStart(vm, "booted", false);
        virDomainObjEndJob(vm);
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virDomainAuditStart(vm, "booted", true);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    memset(seclabel, 0, sizeof(*seclabel));

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetSecurityLabelEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /*
     * Theoretically, the pid can be replaced during this operation and
     * return the label of a different process.  If atomicity is needed,
     * further validation will be required.
     *
     * Comment from Dan Berrange:
     *
     *   Well the PID as stored in the virDomainObj *can't be changed
     *   because you've got a locked object.  The OS level PID could have
     *   exited, though and in extreme circumstances have cycled through all
     *   PIDs back to ours. We could sanity check that our PID still exists
     *   after reading the label, by checking that our FD connecting to the
     *   LXC monitor hasn't seen SIGHUP/ERR on poll().
     */
    if (virDomainObjIsActive(vm)) {
        virLXCDomainObjPrivate *priv = vm->privateData;

        if (!priv->initpid) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Init pid is not yet available"));
            goto cleanup;
        }

        if (virSecurityManagerGetProcessLabel(driver->securityManager,
                                              vm->def, priv->initpid,
                                              seclabel) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int lxcNodeGetSecurityModel(virConnectPtr conn,
                                   virSecurityModelPtr secmodel)
{
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;

    memset(secmodel, 0, sizeof(*secmodel));

    if (virNodeGetSecurityModelEnsureACL(conn) < 0)
        return -1;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        return -1;

    /* we treat no driver as success, but simply return no data in *secmodel */
    if (caps->host.nsecModels == 0
        || caps->host.secModels[0].model == NULL)
        return 0;

    if (virStrcpy(secmodel->model, caps->host.secModels[0].model,
                  VIR_SECURITY_MODEL_BUFLEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security model string exceeds max %1$d bytes"),
                       VIR_SECURITY_MODEL_BUFLEN - 1);
        return -1;
    }

    if (virStrcpy(secmodel->doi, caps->host.secModels[0].doi,
                  VIR_SECURITY_DOI_BUFLEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("security DOI string exceeds max %1$d bytes"),
                       VIR_SECURITY_DOI_BUFLEN-1);
        return -1;
    }

    return 0;
}


static int
lxcConnectDomainEventRegister(virConnectPtr conn,
                              virConnectDomainEventCallback callback,
                              void *opaque,
                              virFreeCallback freecb)
{
    virLXCDriver *driver = conn->privateData;

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
    virLXCDriver *driver = conn->privateData;

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
    virLXCDriver *driver = conn->privateData;
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
    virLXCDriver *driver = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->domainEventState,
                                        callbackID, true) < 0)
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;
    virLXCDomainObjPrivate *priv;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_DESTROY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    priv = vm->privateData;
    ret = virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED, 0);
    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;
    virDomainAuditStop(vm, "destroyed");

 endjob:
    virDomainObjEndJob(vm);
    if (!vm->persistent)
        virDomainObjListRemove(driver->domains, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    g_autoptr(virCommand) cmd = virCommandNewArgList("ip", "link", "set", "lo",
                                                     "netns", "-1", NULL);
    int ip_rc;

    if (virCommandRun(cmd, &ip_rc) < 0 || ip_rc == 255)
        return 0;

    if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_NET) < 0)
        return 0;

    return 1;
}


static virSecurityManager *
lxcSecurityInit(virLXCDriverConfig *cfg)
{
    unsigned int flags = VIR_SECURITY_MANAGER_PRIVILEGED;
    virSecurityManager *mgr;

    VIR_INFO("lxcSecurityInit %s", cfg->securityDriverName);

    if (cfg->securityDefaultConfined)
        flags |= VIR_SECURITY_MANAGER_DEFAULT_CONFINED;
    if (cfg->securityRequireConfined)
        flags |= VIR_SECURITY_MANAGER_REQUIRE_CONFINED;

    mgr = virSecurityManagerNew(cfg->securityDriverName,
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
                              const char *root,
                              bool monolithic G_GNUC_UNUSED,
                              virStateInhibitCallback callback G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED)
{
    virLXCDriverConfig *cfg = NULL;
    bool autostart = true;
    const char *defsecmodel;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    /* Check that the user is root, silently disable if not */
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return VIR_DRV_STATE_INIT_SKIPPED;
    }

    /* Check that this is a container enabled kernel */
    if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_MNT |
                                     VIR_PROCESS_NAMESPACE_PID |
                                     VIR_PROCESS_NAMESPACE_UTS |
                                     VIR_PROCESS_NAMESPACE_IPC) < 0) {
        VIR_INFO("LXC support not available in this kernel, disabling driver");
        return VIR_DRV_STATE_INIT_SKIPPED;
    }

    lxc_driver = g_new0(virLXCDriver, 1);
    lxc_driver->lockFD = -1;
    if (virMutexInit(&lxc_driver->lock) < 0) {
        g_clear_pointer(&lxc_driver, g_free);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (!(lxc_driver->domains = virDomainObjListNew()))
        goto cleanup;

    lxc_driver->domainEventState = virObjectEventStateNew();
    if (!lxc_driver->domainEventState)
        goto cleanup;

    lxc_driver->hostsysinfo = virSysinfoRead();

    if (!(lxc_driver->config = cfg = virLXCDriverConfigNew()))
        goto cleanup;

    cfg->log_libvirtd = false; /* by default log to container logfile */
    cfg->have_netns = lxcCheckNetNsSupport();

    /* Call function to load lxc driver configuration information */
    if (virLXCLoadDriverConfig(cfg, SYSCONFDIR "/libvirt/lxc.conf") < 0)
        goto cleanup;

    if (!(lxc_driver->securityManager = lxcSecurityInit(cfg)))
        goto cleanup;

    if (!(lxc_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto cleanup;

    defsecmodel = virSecurityManagerGetModel(lxc_driver->securityManager);

    if (!(lxc_driver->xmlopt = lxcDomainXMLConfInit(lxc_driver, defsecmodel)))
        goto cleanup;

    if (g_mkdir_with_parents(cfg->stateDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %1$s"),
                             cfg->stateDir);
        goto cleanup;
    }

    if ((lxc_driver->lockFD =
         virPidFileAcquire(cfg->stateDir, "driver", getpid())) < 0)
        goto cleanup;

    /* Get all the running persistent or transient configs first */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->stateDir,
                                       NULL, true,
                                       lxc_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    virLXCProcessReconnectAll(lxc_driver, lxc_driver->domains);

    /* Then inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                       cfg->configDir,
                                       cfg->autostartDir, false,
                                       lxc_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    if (virDriverShouldAutostart(cfg->stateDir, &autostart) < 0)
        goto cleanup;

    if (autostart)
        virLXCProcessAutostartAll(lxc_driver);

    return VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    lxcStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}

static void lxcNotifyLoadDomain(virDomainObj *vm, int newVM, void *opaque)
{
    virLXCDriver *driver = opaque;

    if (newVM) {
        virObjectEvent *event =
            virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
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
    g_autoptr(virLXCDriverConfig) cfg = NULL;

    if (!lxc_driver)
        return 0;

    cfg = virLXCDriverGetConfig(lxc_driver);

    virDomainObjListLoadAllConfigs(lxc_driver->domains,
                                   cfg->configDir,
                                   cfg->autostartDir, false,
                                   lxc_driver->xmlopt,
                                   lxcNotifyLoadDomain, lxc_driver);
    return 0;
}

static int lxcStateCleanup(void)
{
    if (lxc_driver == NULL)
        return -1;

    virObjectUnref(lxc_driver->domains);
    virObjectUnref(lxc_driver->domainEventState);

    virSysinfoDefFree(lxc_driver->hostsysinfo);

    virObjectUnref(lxc_driver->hostdevMgr);
    virObjectUnref(lxc_driver->caps);
    virObjectUnref(lxc_driver->securityManager);
    virObjectUnref(lxc_driver->xmlopt);

    if (lxc_driver->lockFD != -1)
        virPidFileRelease(lxc_driver->config->stateDir, "driver", lxc_driver->lockFD);

    virObjectUnref(lxc_driver->config);
    virMutexDestroy(&lxc_driver->lock);
    g_clear_pointer(&lxc_driver, g_free);

    return 0;
}

static int
lxcConnectSupportsFeature(virConnectPtr conn, int feature)
{
    int supported;

    if (virConnectSupportsFeatureEnsureACL(conn) < 0)
        return -1;

    if (virDriverFeatureIsGlobal(feature, &supported))
        return supported;

    switch ((virDrvFeature) feature) {
    case VIR_DRV_FEATURE_REMOTE:
    case VIR_DRV_FEATURE_PROGRAM_KEEPALIVE:
    case VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK:
    case VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK:
    case VIR_DRV_FEATURE_TYPED_PARAM_STRING:
    case VIR_DRV_FEATURE_NETWORK_UPDATE_HAS_CORRECT_ORDER:
    case VIR_DRV_FEATURE_FD_PASSING:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Global feature %1$d should have already been handled"),
                       feature);
        return -1;
    case VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION:
    case VIR_DRV_FEATURE_MIGRATION_DIRECT:
    case VIR_DRV_FEATURE_MIGRATION_OFFLINE:
    case VIR_DRV_FEATURE_MIGRATION_P2P:
    case VIR_DRV_FEATURE_MIGRATION_PARAMS:
    case VIR_DRV_FEATURE_MIGRATION_V1:
    case VIR_DRV_FEATURE_MIGRATION_V2:
    case VIR_DRV_FEATURE_MIGRATION_V3:
    case VIR_DRV_FEATURE_XML_MIGRATABLE:
    default:
        return 0;
    }
}


static int lxcConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    unsigned long long tmpver;
    struct utsname ver;

    uname(&ver);

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    if (virStringParseVersion(&tmpver, ver.release, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Unknown release: %1$s"), ver.release);
        return -1;
    }

    *version = tmpver;

    return 0;
}


static int
lxcDomainInterfaceAddresses(virDomainPtr dom,
                            virDomainInterfacePtr **ifaces,
                            unsigned int source,
                            unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceAddressesEnsureACL(dom->conn, vm->def, source) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    switch (source) {
    case VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE:
        ret = virDomainNetDHCPInterfaces(vm->def, ifaces);
        break;

    case VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_ARP:
        ret = virDomainNetARPInterfaces(vm->def, ifaces);
        break;

    default:
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("Unknown IP address data source %1$d"),
                       source);
        break;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
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
    virDomainObj *vm;
    virLXCDomainObjPrivate *priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainGetSchedulerTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    /* Domain not running, thus no cgroups - return defaults */
    if (!virDomainObjIsActive(vm)) {
        if (nparams)
            *nparams = 3;
        ret = g_strdup("posix");
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

    ret = g_strdup("posix");

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcGetVcpuBWLive(virCgroup *cgroup, unsigned long long *period,
                 long long *quota)
{
    return virCgroupGetCpuPeriodQuota(cgroup, period, quota);
}


static int lxcSetVcpuBWLive(virCgroup *cgroup, unsigned long long period,
                            long long quota)
{
    return virCgroupSetupCpuPeriodQuota(cgroup, period, quota);
}


static int
lxcDomainSetSchedulerParametersFlags(virDomainPtr dom,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     unsigned int flags)
{
    virLXCDriver *driver = dom->conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    size_t i;
    virDomainObj *vm = NULL;
    virDomainDef *def = NULL;
    g_autoptr(virDomainDef) persistentDefCopy = NULL;
    virDomainDef *persistentDef = NULL;
    int ret = -1;
    int rc;
    virLXCDomainObjPrivate *priv;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

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

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjGetDefs(vm, flags, &def, &persistentDef) < 0)
        goto endjob;

    if (persistentDef) {
        /* Make a copy for updated domain. */
        persistentDefCopy = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL);
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
                if (virCgroupSetCpuShares(priv->cgroup, params[i].value.ul) < 0)
                    goto endjob;

                def->cputune.shares = params[i].value.ul;
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

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;


    if (persistentDef) {
        rc = virDomainDefSave(persistentDefCopy, driver->xmlopt,
                              cfg->configDir);
        if (rc < 0)
            goto endjob;

        virDomainObjAssignDef(vm, &persistentDefCopy, false, NULL);
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virDomainObj *vm = NULL;
    virDomainDef *def;
    virDomainDef *persistentDef;
    unsigned long long shares = 0;
    unsigned long long period = 0;
    long long quota = 0;
    int ret = -1;
    int rc;
    bool cpu_bw_status = false;
    int saved_nparams = 0;
    virLXCDomainObjPrivate *priv;

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
lxcDomainBlockStats(virDomainPtr dom,
                    const char *path,
                    virDomainBlockStatsPtr stats)
{
    int ret = -1;
    virDomainObj *vm;
    virDomainDiskDef *disk = NULL;
    virLXCDomainObjPrivate *priv;

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainBlockStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

   if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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
                       _("invalid path: %1$s"), path);
        goto endjob;
    }

    if (!disk->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %1$s"), disk->dst);
        goto endjob;
    }

    ret = virCgroupGetBlkioIoDeviceServiced(priv->cgroup,
                                            disk->info.alias,
                                            &stats->rd_bytes,
                                            &stats->wr_bytes,
                                            &stats->rd_req,
                                            &stats->wr_req);

 endjob:
    virDomainObjEndJob(vm);

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
    int tmp, ret = -1;
    virDomainObj *vm;
    virDomainDiskDef *disk = NULL;
    virLXCDomainObjPrivate *priv;
    long long rd_req, rd_bytes, wr_req, wr_bytes;
    virTypedParameterPtr param;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    /* We don't return strings, and thus trivially support this flag.  */
    flags &= ~VIR_TYPED_PARAM_STRING_OKAY;

    if (!*nparams) {
        *nparams = LXC_NB_DOMAIN_BLOCK_STAT_PARAM;
        return 0;
    }

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainBlockStatsFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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
                           _("invalid path: %1$s"), path);
            goto endjob;
        }

        if (!disk->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing disk device alias name for %1$s"), disk->dst);
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
    virDomainObjEndJob(vm);

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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    virDomainDef *def = NULL;
    virDomainDef *persistentDef = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = NULL;
    virLXCDomainObjPrivate *priv;

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

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
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
        ret = virDomainCgroupSetupDomainBlkioParameters(priv->cgroup, def,
                                                        params, nparams);
    }
    if (ret < 0)
        goto endjob;
    if (persistentDef) {
        ret = virDomainDriverSetupPersistentDefBlkioParams(persistentDef,
                                                           params,
                                                           nparams);

        if (virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir) < 0)
            ret = -1;
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


#define LXC_NB_BLKIO_PARAM  6

static int
lxcDomainGetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    virDomainObj *vm = NULL;
    virDomainDef *def = NULL;
    virDomainDef *persistentDef = NULL;
    int maxparams = LXC_NB_BLKIO_PARAM;
    unsigned int val;
    int ret = -1;
    virLXCDomainObjPrivate *priv;

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


static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *device,
                        virDomainInterfaceStatsPtr stats)
{
    virDomainObj *vm;
    int ret = -1;
    virDomainNetDef *net = NULL;

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainInterfaceStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!(net = virDomainNetFind(vm->def, device)))
        goto endjob;

    if (virNetDevTapInterfaceStats(net->ifname, stats,
                                   !virDomainNetTypeSharesHostView(net)) < 0)
        goto endjob;

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int lxcDomainGetAutostart(virDomainPtr dom,
                                   int *autostart)
{
    virDomainObj *vm;
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
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
        if (g_mkdir_with_parents(cfg->autostartDir, 0777) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create autostart directory %1$s"),
                                 cfg->autostartDir);
            goto endjob;
        }

        if (symlink(configFile, autostartLink) < 0) {
            virReportSystemError(errno,
                                 _("Failed to create symlink '%1$s' to '%2$s'"),
                                 autostartLink, configFile);
            goto endjob;
        }
    } else {
        if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
            virReportSystemError(errno,
                                 _("Failed to delete symlink '%1$s'"),
                                 autostartLink);
            goto endjob;
        }
    }

    vm->autostart = autostart;
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int lxcFreezeContainer(virDomainObj *vm)
{
    int timeout = 1000; /* In milliseconds */
    int check_interval = 1; /* In milliseconds */
    int exp = 10;
    int waited_time = 0;
    g_autofree char *state = NULL;
    virLXCDomainObjPrivate *priv = vm->privateData;

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
        g_usleep(check_interval * 1000);

        r = virCgroupGetFreezerState(priv->cgroup, &state);

        if (r < 0) {
            VIR_DEBUG("Reading freezer.state failed with errno: %d", r);
            goto error;
        }
        VIR_DEBUG("Read freezer.state: %s", state);

        if (STREQ(state, "FROZEN"))
            return 0;

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
    }
    VIR_DEBUG("lxcFreezeContainer timeout");
 error:
    /*
     * If timeout or an error on reading the state occurs,
     * activate the group again and return an error.
     * This is likely to fall the group back again gracefully.
     */
    virCgroupSetFreezerState(priv->cgroup, "THAWED");
    return -1;
}

static int lxcDomainSuspend(virDomainPtr dom)
{
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainSuspendEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virObjectEventStateQueue(driver->domainEventState, event);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int lxcDomainResume(virDomainPtr dom)
{
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;
    int state;
    virLXCDomainObjPrivate *priv;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainResumeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto endjob;
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virObjectEventStateQueue(driver->domainEventState, event);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
lxcDomainOpenConsole(virDomainPtr dom,
                      const char *dev_name,
                      virStreamPtr st,
                      unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;
    virDomainChrDef *chr = NULL;
    size_t i;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

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
                       _("cannot find console device '%1$s'"),
                       dev_name ? dev_name : _("default"));
        goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %1$s is not using a PTY"),
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
    virDomainObj *vm = NULL;
    virLXCDomainObjPrivate *priv;
    pid_t victim;
    int ret = -1;

    virCheckFlags(0, -1);

    if (signum >= VIR_DOMAIN_PROCESS_SIGNAL_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("signum value %1$d is out of range"),
                       signum);
        return -1;
    }

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainSendProcessSignalEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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
                             _("Unable to send %1$d signal to process %2$d"),
                             signum, victim);
        goto endjob;
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcConnectListAllDomains(virConnectPtr conn,
                         virDomainPtr **domains,
                  unsigned int flags)
{
    virLXCDriver *driver = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(driver->domains, conn, domains,
                                  virConnectListAllDomainsCheckACL, flags);
}


static int
lxcDomainShutdownFlags(virDomainPtr dom,
                       unsigned int flags)
{
    virLXCDomainObjPrivate *priv;
    virDomainObj *vm;
    int ret = -1;
    int rc = -1;

    virCheckFlags(VIR_DOMAIN_SHUTDOWN_INITCTL |
                  VIR_DOMAIN_SHUTDOWN_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto endjob;
    }

    if (flags == 0 ||
        (flags & VIR_DOMAIN_SHUTDOWN_INITCTL)) {
        int command = VIR_INITCTL_RUNLEVEL_POWEROFF;

        if ((rc = virLXCDomainSetRunlevel(vm, command)) < 0) {
            if (flags != 0 &&
                (flags & VIR_DOMAIN_SHUTDOWN_INITCTL)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("Container does not provide an initctl pipe"));
                goto endjob;
            }
        }
    }

    if (rc < 0 &&
        (flags == 0 ||
         (flags & VIR_DOMAIN_SHUTDOWN_SIGNAL))) {
        if (kill(priv->initpid, SIGTERM) < 0 &&
            errno != ESRCH) {
            virReportSystemError(errno,
                                 _("Unable to send SIGTERM to init pid %1$llu"),
                                 (long long)priv->initpid);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

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
    virLXCDomainObjPrivate *priv;
    virDomainObj *vm;
    int ret = -1;
    int rc = -1;

    virCheckFlags(VIR_DOMAIN_REBOOT_INITCTL |
                  VIR_DOMAIN_REBOOT_SIGNAL, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainRebootEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (priv->initpid == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Init process ID is not yet known"));
        goto endjob;
    }

    if (flags == 0 ||
        (flags & VIR_DOMAIN_REBOOT_INITCTL)) {
        int command = VIR_INITCTL_RUNLEVEL_REBOOT;

        if ((rc = virLXCDomainSetRunlevel(vm, command)) < 0) {
            if (flags != 0 &&
                (flags & VIR_DOMAIN_REBOOT_INITCTL)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("Container does not provide an initctl pipe"));
                goto endjob;
            }
        }
    }

    if (rc < 0 &&
        (flags == 0 ||
         (flags & VIR_DOMAIN_REBOOT_SIGNAL))) {
        if (kill(priv->initpid, SIGHUP) < 0 &&
            errno != ESRCH) {
            virReportSystemError(errno,
                                 _("Unable to send SIGTERM to init pid %1$llu"),
                                 (long long)priv->initpid);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
lxcDomainAttachDeviceConfig(virDomainDef *vmdef,
                            virDomainDeviceDef *dev)
{
    int ret = -1;
    virDomainDiskDef *disk;
    virDomainNetDef *net;
    virDomainHostdevDef *hostdev;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (virDomainDiskIndexByName(vmdef, disk->dst, true) >= 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("target %1$s already exists."), disk->dst);
            return -1;
        }
        virDomainDiskInsert(vmdef, disk);
        /* vmdef has the pointer. Generic codes for vmdef will do all jobs */
        dev->data.disk = NULL;
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if (virDomainNetInsert(vmdef, net) < 0)
            return -1;
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

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("persistent attach of device is not supported"));
         break;
    }

    return ret;
}


static int
lxcDomainUpdateDeviceConfig(virDomainDef *vmdef,
                            virDomainDeviceDef *dev)
{
    int ret = -1;
    virDomainNetDef *net;
    virDomainDeviceDef oldDev = { .type = dev->type };
    int idx;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
            return -1;

        oldDev.data.net = vmdef->nets[idx];
        if (virDomainDefCompatibleDevice(vmdef, dev, &oldDev,
                                         VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                         false) < 0)
            return -1;

        if (virDomainNetUpdate(vmdef, idx, net) < 0)
            return -1;

        virDomainNetDefFree(oldDev.data.net);
        dev->data.net = NULL;
        ret = 0;

        break;

    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("persistent update of device is not supported"));
        break;
    }

    return ret;
}


static int
lxcDomainDetachDeviceConfig(virDomainDef *vmdef,
                            virDomainDeviceDef *dev)
{
    int ret = -1;
    virDomainDiskDef *disk;
    virDomainDiskDef *det_disk;
    virDomainNetDef *net;
    virDomainHostdevDef *hostdev;
    virDomainHostdevDef *det_hostdev;
    int idx;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        disk = dev->data.disk;
        if (!(det_disk = virDomainDiskRemoveByName(vmdef, disk->dst))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("no target device %1$s"), disk->dst);
            return -1;
        }
        virDomainDiskDefFree(det_disk);
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        net = dev->data.net;
        if ((idx = virDomainNetFindIdx(vmdef, net)) < 0)
            return -1;

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

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_AUDIO:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("persistent detach of device is not supported"));
        break;
    }

    return ret;
}


struct lxcDomainAttachDeviceMknodData {
    virLXCDriver *driver;
    mode_t mode;
    dev_t dev;
    virDomainObj *vm;
    virDomainDeviceDef *def;
    char *file;
};

static int
lxcDomainAttachDeviceMknodHelper(pid_t pid G_GNUC_UNUSED,
                                 void *opaque)
{
    struct lxcDomainAttachDeviceMknodData *data = opaque;
    int ret = -1;

    virSecurityManagerPostFork(data->driver->securityManager);

    if (virFileMakeParentPath(data->file) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %1$s"), data->file);
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
                             _("Unable to create device %1$s"),
                             data->file);
        goto cleanup;
    }

    if (lxcContainerChown(data->vm->def, data->file) < 0)
        goto cleanup;

    /* Labelling normally operates on src, but we need
     * to actually label the dst here, so hack the config */
    switch (data->def->type) {
    case VIR_DOMAIN_DEVICE_DISK: {
        virDomainDiskDef *def = data->def->data.disk;
        char *tmpsrc = def->src->path;
        def->src->path = data->file;
        if (virSecurityManagerSetImageLabel(data->driver->securityManager,
                                            data->vm->def, def->src,
                                            VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN) < 0) {
            def->src->path = tmpsrc;
            goto cleanup;
        }
        def->src->path = tmpsrc;
    }   break;

    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        virDomainHostdevDef *def = data->def->data.hostdev;
        if (virSecurityManagerSetHostdevLabel(data->driver->securityManager,
                                              data->vm->def, def, NULL) < 0)
            goto cleanup;
    }   break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected device type %1$d"),
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
lxcDomainAttachDeviceMknod(virLXCDriver *driver,
                           mode_t mode,
                           dev_t dev,
                           virDomainObj *vm,
                           virDomainDeviceDef *def,
                           char *file)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    struct lxcDomainAttachDeviceMknodData data = { 0 };

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
lxcDomainAttachDeviceUnlinkHelper(pid_t pid G_GNUC_UNUSED,
                                  void *opaque)
{
    const char *path = opaque;

    VIR_DEBUG("Unlinking %s", path);
    if (unlink(path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove device %1$s"), path);
        return -1;
    }

    return 0;
}


static int
lxcDomainAttachDeviceUnlink(virDomainObj *vm,
                            char *file)
{
    virLXCDomainObjPrivate *priv = vm->privateData;

    if (virProcessRunInMountNamespace(priv->initpid,
                                      lxcDomainAttachDeviceUnlinkHelper,
                                      file) < 0) {
        return -1;
    }

    return 0;
}


static int
lxcDomainAttachDeviceDiskLive(virLXCDriver *driver,
                              virDomainObj *vm,
                              virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainDiskDef *def = dev->data.disk;
    int ret = -1;
    struct stat sb;
    g_autofree char *file = NULL;
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
                       _("target %1$s already exists"), def->dst);
        goto cleanup;
    }

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"), src);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk source %1$s must be a block device"),
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

    file = g_strdup_printf("/dev/%s", def->dst);

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
            VIR_WARN("cannot deny device %s for domain %s: %s",
                     src, vm->def->name, virGetLastErrorMessage());
        goto cleanup;
    }

    virDomainDiskInsert(vm->def, def);

    ret = 0;

 cleanup:
    if (src)
        virDomainAuditDisk(vm, NULL, def->src, "attach", ret == 0);
    return ret;
}


static int
lxcDomainAttachDeviceNetLive(virLXCDriver *driver,
                             virDomainObj *vm,
                             virDomainNetDef *net)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    int ret = -1;
    virDomainNetType actualType;
    const virNetDevBandwidth *actualBandwidth;
    char *veth = NULL;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        return -1;
    }

    if (virLXCProcessValidateInterface(net) < 0)
       return -1;

    /* preallocate new slot for device */
    vm->def->nets = g_renew(virDomainNetDef *,
                            vm->def->nets,
                            vm->def->nnets + 1);

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        g_autoptr(virConnect) netconn = virGetConnectNetwork();
        if (!netconn || virDomainNetAllocateActualDevice(netconn, vm->def, net) < 0)
            return -1;
    }

    /* final validation now that actual type is known */
    if (virDomainActualNetDefValidate(net) < 0)
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
        if (!(veth = virLXCProcessSetupInterfaceDirect(driver, vm->def, net)))
            goto cleanup;
    }   break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Network device type is not supported"));
        goto cleanup;
    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainNetType, actualType);
        goto cleanup;
    }
    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportsBandwidth(actualType)) {
            if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false,
                                      !virDomainNetTypeSharesHostView(net)) < 0)
                goto cleanup;
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet: %s",
                     virDomainNetTypeToString(actualType), virGetLastErrorMessage());
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

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
        default:
            /* no-op */
            break;
        }
    }

    return ret;
}


static int
lxcDomainAttachDeviceHostdevSubsysUSBLive(virLXCDriver *driver,
                                          virDomainObj *vm,
                                          virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = dev->data.hostdev;
    int ret = -1;
    g_autofree char *src = NULL;
    struct stat sb;
    virUSBDevice *usb = NULL;
    virDomainHostdevSubsysUSB *usbsrc;

    if (virDomainHostdevFind(vm->def, def, NULL) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("host USB device already exists"));
        return -1;
    }

    usbsrc = &def->source.subsys.u.usb;
    src = g_strdup_printf("/dev/bus/usb/%03d/%03d", usbsrc->bus, usbsrc->device);

    if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL)))
        goto cleanup;

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"), src);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("USB source %1$s was not a character device"),
                       src);
        goto cleanup;
    }

    vm->def->hostdevs = g_renew(virDomainHostdevDef *,
                                vm->def->hostdevs,
                                vm->def->nhostdevs + 1);

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
            VIR_WARN("cannot deny device %s for domain %s: %s",
                     src, vm->def->name, virGetLastErrorMessage());
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    virUSBDeviceFree(usb);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevStorageLive(virLXCDriver *driver,
                                        virDomainObj *vm,
                                        virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = dev->data.hostdev;
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
                             _("Unable to access %1$s"),
                             def->source.caps.u.storage.block);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Hostdev source %1$s must be a block device"),
                       def->source.caps.u.storage.block);
        goto cleanup;
    }

    vm->def->hostdevs = g_renew(virDomainHostdevDef *,
                                vm->def->hostdevs,
                                vm->def->nhostdevs + 1);

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
            VIR_WARN("cannot deny device %s for domain %s: %s",
                     def->source.caps.u.storage.block, vm->def->name, virGetLastErrorMessage());
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevMiscLive(virLXCDriver *driver,
                                     virDomainObj *vm,
                                     virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = dev->data.hostdev;
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
                             _("Unable to access %1$s"),
                             def->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Hostdev source %1$s must be a block device"),
                       def->source.caps.u.misc.chardev);
        goto cleanup;
    }

    if (virCgroupAllowDevice(priv->cgroup,
                             'c',
                             major(sb.st_rdev),
                             minor(sb.st_rdev),
                             VIR_CGROUP_DEVICE_RWM) < 0)
        goto cleanup;

    vm->def->hostdevs = g_renew(virDomainHostdevDef *,
                                vm->def->hostdevs,
                                vm->def->nhostdevs + 1);

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
            VIR_WARN("cannot deny device %s for domain %s: %s",
                     def->source.caps.u.storage.block, vm->def->name, virGetLastErrorMessage());
        goto cleanup;
    }

    vm->def->hostdevs[vm->def->nhostdevs++] = def;

    ret = 0;

 cleanup:
    virDomainAuditHostdev(vm, def, "attach", ret == 0);
    return ret;
}


static int
lxcDomainAttachDeviceHostdevSubsysLive(virLXCDriver *driver,
                                       virDomainObj *vm,
                                       virDomainDeviceDef *dev)
{
    switch (dev->data.hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return lxcDomainAttachDeviceHostdevSubsysUSBLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %1$s"),
                       virDomainHostdevSubsysTypeToString(dev->data.hostdev->source.subsys.type));
        return -1;
    }
}


static int
lxcDomainAttachDeviceHostdevCapsLive(virLXCDriver *driver,
                                     virDomainObj *vm,
                                     virDomainDeviceDef *dev)
{
    switch (dev->data.hostdev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return lxcDomainAttachDeviceHostdevStorageLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return lxcDomainAttachDeviceHostdevMiscLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %1$s"),
                       virDomainHostdevCapsTypeToString(dev->data.hostdev->source.caps.type));
        return -1;
    }
}


static int
lxcDomainAttachDeviceHostdevLive(virLXCDriver *driver,
                                 virDomainObj *vm,
                                 virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;

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
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %1$s"),
                       virDomainHostdevModeTypeToString(dev->data.hostdev->mode));
        return -1;
    }
}


static int
lxcDomainAttachDeviceLive(virLXCDriver *driver,
                          virDomainObj *vm,
                          virDomainDeviceDef *dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = lxcDomainAttachDeviceDiskLive(driver, vm, dev);
        if (!ret)
            dev->data.disk = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        ret = lxcDomainAttachDeviceNetLive(driver, vm,
                                           dev->data.net);
        if (!ret)
            dev->data.net = NULL;
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = lxcDomainAttachDeviceHostdevLive(driver, vm, dev);
        if (!ret)
            dev->data.hostdev = NULL;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type '%1$s' cannot be attached"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}


static int
lxcDomainDetachDeviceDiskLive(virDomainObj *vm,
                              virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainDiskDef *def = NULL;
    int idx;
    g_autofree char *dst = NULL;
    const char *src;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        return -1;
    }

    if ((idx = virDomainDiskIndexByName(vm->def,
                                        dev->data.disk->dst,
                                        false)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("disk %1$s not found"), dev->data.disk->dst);
        return -1;
    }

    def = vm->def->disks[idx];
    src = virDomainDiskGetSource(def);

    dst = g_strdup_printf("/dev/%s", def->dst);

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        return -1;
    }

    if (lxcDomainAttachDeviceUnlink(vm, dst) < 0) {
        virDomainAuditDisk(vm, def->src, NULL, "detach", false);
        return -1;
    }
    virDomainAuditDisk(vm, def->src, NULL, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, src,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s: %s",
                 src, vm->def->name, virGetLastErrorMessage());

    virDomainDiskRemove(vm->def, idx);
    virDomainDiskDefFree(def);

    return 0;
}


static int
lxcDomainDetachDeviceNetLive(virDomainObj *vm,
                             virDomainDeviceDef *dev)
{
    int detachidx, ret = -1;
    virDomainNetType actualType;
    virDomainNetDef *detach = NULL;
    const virNetDevVPortProfile *vport = NULL;
    virErrorPtr save_err = NULL;

    if ((detachidx = virDomainNetFindIdx(vm->def, dev->data.net)) < 0)
        goto cleanup;

    detach = vm->def->nets[detachidx];
    actualType = virDomainNetGetActualType(detach);

    /* clear network bandwidth */
    if (virDomainNetGetActualBandwidth(detach) &&
        virNetDevSupportsBandwidth(actualType) &&
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
         */
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Only bridged veth devices can be detached"));
        goto cleanup;
    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainNetType, actualType);
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
        virErrorPreserveLast(&save_err);
        if (detach->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            g_autoptr(virConnect) conn = virGetConnectNetwork();
            if (conn)
                virDomainNetReleaseActualDevice(conn, vm->def, detach);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(detach->ifname));
        }
        virDomainNetRemove(vm->def, detachidx);
        virDomainNetDefFree(detach);
        virErrorRestore(&save_err);
    }
    return ret;
}


static int
lxcDomainDetachDeviceHostdevUSBLive(virLXCDriver *driver,
                                    virDomainObj *vm,
                                    virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = NULL;
    int idx, ret = -1;
    g_autofree char *dst = NULL;
    virUSBDevice *usb = NULL;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    virDomainHostdevSubsysUSB *usbsrc;

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("usb device not found"));
        goto cleanup;
    }

    usbsrc = &def->source.subsys.u.usb;
    dst = g_strdup_printf("/dev/bus/usb/%03d/%03d", usbsrc->bus, usbsrc->device);

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
        VIR_WARN("cannot deny device %s for domain %s: %s",
                 dst, vm->def->name, virGetLastErrorMessage());

    VIR_WITH_OBJECT_LOCK_GUARD(hostdev_mgr->activeUSBHostdevs) {
        virUSBDeviceListDel(hostdev_mgr->activeUSBHostdevs, usb);
    }

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    ret = 0;

 cleanup:
    virUSBDeviceFree(usb);
    return ret;
}


static int
lxcDomainDetachDeviceHostdevStorageLive(virDomainObj *vm,
                                        virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = NULL;
    int idx;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        return -1;
    }

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("hostdev %1$s not found"),
                       dev->data.hostdev->source.caps.u.storage.block);
        return -1;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        return -1;
    }

    if (lxcDomainAttachDeviceUnlink(vm, def->source.caps.u.storage.block) < 0) {
        virDomainAuditHostdev(vm, def, "detach", false);
        return -1;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.storage.block,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s: %s",
                 def->source.caps.u.storage.block, vm->def->name, virGetLastErrorMessage());

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    return 0;
}


static int
lxcDomainDetachDeviceHostdevMiscLive(virDomainObj *vm,
                                     virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;
    virDomainHostdevDef *def = NULL;
    int idx;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Cannot attach disk until init PID is known"));
        return -1;
    }

    if ((idx = virDomainHostdevFind(vm->def,
                                    dev->data.hostdev,
                                    &def)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("hostdev %1$s not found"),
                       dev->data.hostdev->source.caps.u.misc.chardev);
        return -1;
    }

    if (!virCgroupHasController(priv->cgroup, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("devices cgroup isn't mounted"));
        return -1;
    }

    if (lxcDomainAttachDeviceUnlink(vm, def->source.caps.u.misc.chardev) < 0) {
        virDomainAuditHostdev(vm, def, "detach", false);
        return -1;
    }
    virDomainAuditHostdev(vm, def, "detach", true);

    if (virCgroupDenyDevicePath(priv->cgroup, def->source.caps.u.misc.chardev,
                                VIR_CGROUP_DEVICE_RWM, false) != 0)
        VIR_WARN("cannot deny device %s for domain %s: %s",
                 def->source.caps.u.misc.chardev, vm->def->name, virGetLastErrorMessage());

    virDomainHostdevRemove(vm->def, idx);
    virDomainHostdevDefFree(def);

    return 0;
}


static int
lxcDomainDetachDeviceHostdevSubsysLive(virLXCDriver *driver,
                                       virDomainObj *vm,
                                       virDomainDeviceDef *dev)
{
    switch (dev->data.hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return lxcDomainDetachDeviceHostdevUSBLive(driver, vm, dev);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %1$s"),
                       virDomainHostdevSubsysTypeToString(dev->data.hostdev->source.subsys.type));
        return -1;
    }
}


static int
lxcDomainDetachDeviceHostdevCapsLive(virDomainObj *vm,
                                     virDomainDeviceDef *dev)
{
    switch (dev->data.hostdev->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return lxcDomainDetachDeviceHostdevStorageLive(vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return lxcDomainDetachDeviceHostdevMiscLive(vm, dev);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device type %1$s"),
                       virDomainHostdevCapsTypeToString(dev->data.hostdev->source.caps.type));
        return -1;
    }
}


static int
lxcDomainDetachDeviceHostdevLive(virLXCDriver *driver,
                                 virDomainObj *vm,
                                 virDomainDeviceDef *dev)
{
    virLXCDomainObjPrivate *priv = vm->privateData;

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
    case VIR_DOMAIN_HOSTDEV_MODE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %1$s"),
                       virDomainHostdevModeTypeToString(dev->data.hostdev->mode));
        return -1;
    }
}


static int
lxcDomainDetachDeviceLive(virLXCDriver *driver,
                          virDomainObj *vm,
                          virDomainDeviceDef *dev)
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

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type '%1$s' cannot be detached"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}


static int lxcDomainAttachDeviceFlags(virDomainPtr dom,
                                      const char *xml,
                                      unsigned int flags)
{
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    g_autoptr(virDomainDeviceDef) dev_config = NULL;
    g_autoptr(virDomainDeviceDef) dev_live = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainAttachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!(dev_config = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt,
                                                   NULL,
                                                   VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!(dev_live = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt,
                                                 NULL,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL);
        if (!vmdef)
            goto endjob;

        if (virDomainDefCompatibleDevice(vmdef, dev_config, NULL,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH,
                                         false) < 0)
            goto endjob;

        if ((ret = lxcDomainAttachDeviceConfig(vmdef, dev_config)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (virDomainDefCompatibleDevice(vm->def, dev_live, NULL,
                                         VIR_DOMAIN_DEVICE_ACTION_ATTACH,
                                         true) < 0)
            goto endjob;

        if ((ret = lxcDomainAttachDeviceLive(driver, vm, dev_live)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret)
            virDomainObjAssignDef(vm, &vmdef, false, NULL);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    virDomainDeviceDef *dev = NULL;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainUpdateDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to modify live devices"));
        goto endjob;
    }

    if (!(dev = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto endjob;

    /* Make a copy for updated domain. */
    if (!(vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL)))
        goto endjob;

    /* virDomainDefCompatibleDevice call is delayed until we know the
     * device we're going to update. */
    if (lxcDomainUpdateDeviceConfig(vmdef, dev) < 0)
        goto endjob;

    if (virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir) < 0)
        goto endjob;

    virDomainObjAssignDef(vm, &vmdef, false, NULL);
    ret = 0;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainDeviceDefFree(dev);
    virDomainObjEndAPI(&vm);
    return ret;
}


static int lxcDomainDetachDeviceFlags(virDomainPtr dom,
                                      const char *xml,
                                      unsigned int flags)
{
    virLXCDriver *driver = dom->conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    virDomainObj *vm = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    g_autoptr(virDomainDeviceDef) dev_config = NULL;
    g_autoptr(virDomainDeviceDef) dev_live = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                               VIR_DOMAIN_DEF_PARSE_INACTIVE;
    int ret = -1;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDetachDeviceFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    if (virDomainObjUpdateModificationImpact(vm, &flags) < 0)
        goto endjob;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto endjob;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        if (!(dev_config = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt,
                                                   NULL, parse_flags)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!(dev_live = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt,
                                                 NULL, parse_flags)))
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(vm, driver->xmlopt, NULL);
        if (!vmdef)
            goto endjob;

        if ((ret = lxcDomainDetachDeviceConfig(vmdef, dev_config)) < 0)
            goto endjob;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if ((ret = lxcDomainDetachDeviceLive(driver, vm, dev_live)) < 0)
            goto endjob;
        /*
         * update domain status forcibly because the domain status may be
         * changed even if we failed to attach the device. For example,
         * a new controller may be created.
         */
        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0) {
            ret = -1;
            goto endjob;
        }
    }

    /* Finally, if no error until here, we can save config. */
    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        ret = virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir);
        if (!ret)
            virDomainObjAssignDef(vm, &vmdef, false, NULL);
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
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
    virDomainObj *vm;
    virLXCDomainObjPrivate *priv;
    int ret = -1;
    size_t nfds = 0;

    *fdlist = NULL;
    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainLxcOpenNamespaceEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto endjob;
    }

    if (virProcessGetNamespaces(priv->initpid, &nfds, fdlist) < 0)
        goto endjob;

    ret = nfds;

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static char *
lxcConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    virLXCDriver *driver = conn->privateData;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

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
    virDomainObj *vm;
    int ret = -1;
    virLXCDomainObjPrivate *priv;
    unsigned long long swap_usage;
    unsigned long mem_usage;

    virCheckFlags(0, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        goto cleanup;

    priv = vm->privateData;

    if (virDomainMemoryStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

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
    virDomainObjEndJob(vm);

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

    return virNodeSuspend(target, duration, flags);
}


static int
lxcDomainSetMetadata(virDomainPtr dom,
                      int type,
                      const char *metadata,
                      const char *key,
                      const char *uri,
                      unsigned int flags)
{
    virLXCDriver *driver = dom->conn->privateData;
    virDomainObj *vm;
    g_autoptr(virLXCDriverConfig) cfg = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return -1;

    cfg = virLXCDriverGetConfig(driver);

    if (virDomainSetMetadataEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri,
                                  driver->xmlopt, cfg->stateDir,
                                  cfg->configDir, flags);

    if (ret == 0) {
        virObjectEvent *ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(driver->domainEventState, ev);
    }

    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


static char *
lxcDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virDomainObj *vm;
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
    virDomainObj *vm = NULL;
    int ret = -1;
    virLXCDomainObjPrivate *priv;

    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return ret;

    priv = vm->privateData;

    if (virDomainGetCPUStatsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

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


static char *
lxcDomainGetHostname(virDomainPtr dom,
                     unsigned int flags)
{
    virDomainObj *vm = NULL;
    char macaddr[VIR_MAC_STRING_BUFLEN];
    g_autoptr(virConnect) conn = NULL;
    size_t i, j;
    char *hostname = NULL;

    virCheckFlags(VIR_DOMAIN_GET_HOSTNAME_LEASE, NULL);

    if (!(vm = lxcDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetHostnameEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjBeginJob(vm, VIR_JOB_QUERY) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto endjob;

    if (!(conn = virGetConnectNetwork()))
        goto endjob;

    for (i = 0; i < vm->def->nnets; i++) {
        g_autoptr(virNetwork) network = NULL;
        virDomainNetDef *net = vm->def->nets[i];
        g_autofree virNetworkDHCPLeasePtr *leases = NULL;
        int n_leases;

        if (net->type != VIR_DOMAIN_NET_TYPE_NETWORK)
            continue;

        virMacAddrFormat(&net->mac, macaddr);
        network = virNetworkLookupByName(conn, net->data.network.name);

        if (!network)
            goto endjob;

        if ((n_leases = virNetworkGetDHCPLeases(network, macaddr,
                                                &leases, 0)) < 0)
            goto endjob;

        for (j = 0; j < n_leases; j++) {
            virNetworkDHCPLeasePtr lease = leases[j];

            if (lease->hostname && !hostname)
                hostname = g_strdup(lease->hostname);

            virNetworkDHCPLeaseFree(lease);
        }

        if (hostname)
            goto endjob;
    }

    if (!hostname) {
        virReportError(VIR_ERR_NO_HOSTNAME,
                       _("no hostname found for domain %1$s"),
                       vm->def->name);
        goto endjob;
    }

 endjob:
    virDomainObjEndJob(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return hostname;
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
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    int lastCell;

    virCheckFlags(0, -1);

    if (virNodeGetFreePagesEnsureACL(conn) < 0)
        return -1;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        return -1;

    lastCell = virCapabilitiesHostNUMAGetMaxNode(caps->host.numa);

    return virHostMemGetFreePages(npages, pages, startCell, cellCount,
                                  lastCell, counts);
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
    virLXCDriver *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    int lastCell;
    bool add = !(flags & VIR_NODE_ALLOC_PAGES_SET);

    virCheckFlags(VIR_NODE_ALLOC_PAGES_SET, -1);

    if (virNodeAllocPagesEnsureACL(conn) < 0)
        return -1;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        return -1;

    lastCell = virCapabilitiesHostNUMAGetMaxNode(caps->host.numa);

    return virHostMemAllocPages(npages, pageSizes, pageCounts,
                                startCell, cellCount,
                                lastCell, add);
}


static int
lxcDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObj *vm = NULL;
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
    .connectURIProbe = lxcConnectURIProbe,
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
    .domainGetHostname = lxcDomainGetHostname, /* 6.0.0 */
    .domainInterfaceAddresses = lxcDomainInterfaceAddresses, /* 6.1.0 */
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
    .localOnly = true,
    .uriSchemes = (const char *[]){ "lxc", NULL },
    .hypervisorDriver = &lxcHypervisorDriver,
};

static virStateDriver lxcStateDriver = {
    .name = LXC_DRIVER_NAME,
    .stateInitialize = lxcStateInitialize,
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
