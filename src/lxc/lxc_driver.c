/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <config.h>

#include <fcntl.h>
#include <sched.h>
#include <sys/utsname.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <unistd.h>
#include <wait.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_driver.h"
#include "memory.h"
#include "util.h"
#include "virnetdevbridge.h"
#include "virnetdevveth.h"
#include "nodeinfo.h"
#include "uuid.h"
#include "stats_linux.h"
#include "hooks.h"
#include "virfile.h"
#include "virpidfile.h"
#include "fdstream.h"
#include "domain_audit.h"
#include "domain_nwfilter.h"
#include "network/bridge_driver.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnodesuspend.h"
#include "virtime.h"
#include "virtypedparam.h"
#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_LXC

#define START_POSTFIX ": starting up\n"

#define LXC_NB_MEM_PARAM  3

typedef struct _lxcDomainObjPrivate lxcDomainObjPrivate;
typedef lxcDomainObjPrivate *lxcDomainObjPrivatePtr;
struct _lxcDomainObjPrivate {
    int monitor;
    int monitorWatch;
};


static int lxcStartup(int privileged);
static int lxcShutdown(void);
static lxc_driver_t *lxc_driver = NULL;

/* Functions */

static void lxcDriverLock(lxc_driver_t *driver)
{
    virMutexLock(&driver->lock);
}
static void lxcDriverUnlock(lxc_driver_t *driver)
{
    virMutexUnlock(&driver->lock);
}

static void *lxcDomainObjPrivateAlloc(void)
{
    lxcDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    priv->monitor = -1;
    priv->monitorWatch = -1;

    return priv;
}

static void lxcDomainObjPrivateFree(void *data)
{
    lxcDomainObjPrivatePtr priv = data;

    VIR_FREE(priv);
}


static void lxcDomainEventQueue(lxc_driver_t *driver,
                                virDomainEventPtr event);

static int lxcVmTerminate(lxc_driver_t *driver,
                          virDomainObjPtr vm,
                          virDomainShutoffReason reason);
static int lxcProcessAutoDestroyInit(lxc_driver_t *driver);
static void lxcProcessAutoDestroyRun(lxc_driver_t *driver,
                                     virConnectPtr conn);
static void lxcProcessAutoDestroyShutdown(lxc_driver_t *driver);
static int lxcProcessAutoDestroyAdd(lxc_driver_t *driver,
                                    virDomainObjPtr vm,
                                    virConnectPtr conn);
static int lxcProcessAutoDestroyRemove(lxc_driver_t *driver,
                                       virDomainObjPtr vm);


static virDrvOpenStatus lxcOpen(virConnectPtr conn,
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
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("Unexpected LXC URI path '%s', try lxc:///"),
                     conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }

        /* URI was good, but driver isn't active */
        if (lxc_driver == NULL) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("lxc state driver is not active"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    conn->privateData = lxc_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int lxcClose(virConnectPtr conn)
{
    lxc_driver_t *driver = conn->privateData;

    lxcDriverLock(driver);
    virDomainEventStateDeregisterConn(conn,
                                      driver->domainEventState);
    lxcProcessAutoDestroyRun(driver, conn);
    lxcDriverUnlock(driver);

    conn->privateData = NULL;
    return 0;
}


static int lxcIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int lxcIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int lxcIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}


static char *lxcGetCapabilities(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    char *xml;

    lxcDriverLock(driver);
    if ((xml = virCapabilitiesFormatXML(driver->caps)) == NULL)
        virReportOOMError();
    lxcDriverUnlock(driver);

    return xml;
}


static virDomainPtr lxcDomainLookupByID(virConnectPtr conn,
                                        int id)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    lxcDriverUnlock(driver);

    if (!vm) {
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching id %d"), id);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr lxcDomainLookupByUUID(virConnectPtr conn,
                                          const unsigned char *uuid)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}

static virDomainPtr lxcDomainLookupByName(virConnectPtr conn,
                                          const char *name)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    lxcDriverUnlock(driver);
    if (!vm) {
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching name '%s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return dom;
}


static int lxcDomainIsActive(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    lxcDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int lxcDomainIsPersistent(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    lxcDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int lxcDomainIsUpdated(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    lxcDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }
    ret = obj->updated;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int lxcListDomains(virConnectPtr conn, int *ids, int nids) {
    lxc_driver_t *driver = conn->privateData;
    int n;

    lxcDriverLock(driver);
    n = virDomainObjListGetActiveIDs(&driver->domains, ids, nids);
    lxcDriverUnlock(driver);

    return n;
}

static int lxcNumDomains(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    int n;

    lxcDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    lxcDriverUnlock(driver);

    return n;
}

static int lxcListDefinedDomains(virConnectPtr conn,
                                 char **const names, int nnames) {
    lxc_driver_t *driver = conn->privateData;
    int n;

    lxcDriverLock(driver);
    n = virDomainObjListGetInactiveNames(&driver->domains, names, nnames);
    lxcDriverUnlock(driver);

    return n;
}


static int lxcNumDefinedDomains(virConnectPtr conn) {
    lxc_driver_t *driver = conn->privateData;
    int n;

    lxcDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    lxcDriverUnlock(driver);

    return n;
}



static virDomainPtr lxcDomainDefine(virConnectPtr conn, const char *xml)
{
    lxc_driver_t *driver = conn->privateData;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int dupVM;

    lxcDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        1 << VIR_DOMAIN_VIRT_LXC,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if ((dupVM = virDomainObjIsDuplicate(&driver->domains, def, 0)) < 0)
        goto cleanup;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, def, false)))
        goto cleanup;
    def = NULL;
    vm->persistent = 1;

    if (virDomainSaveConfig(driver->configDir,
                            vm->newDef ? vm->newDef : vm->def) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !dupVM ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(def);
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        lxcDomainEventQueue(driver, event);
    lxcDriverUnlock(driver);
    return dom;
}

static int lxcDomainUndefineFlags(virDomainPtr dom,
                                  unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(driver->configDir,
                              driver->autostartDir,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        lxcDomainEventQueue(driver, event);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcDomainUndefine(virDomainPtr dom)
{
    return lxcDomainUndefineFlags(dom, 0);
}

static int lxcDomainGetInfo(virDomainPtr dom,
                            virDomainInfoPtr info)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virCgroupPtr cgroup = NULL;
    int ret = -1, rc;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    info->state = virDomainObjGetState(vm, NULL);

    if (!virDomainObjIsActive(vm) || driver->cgroup == NULL) {
        info->cpuTime = 0;
        info->memory = vm->def->mem.cur_balloon;
    } else {
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("Unable to get cgroup for %s"), vm->def->name);
            goto cleanup;
        }

        if (virCgroupGetCpuacctUsage(cgroup, &(info->cpuTime)) < 0) {
            lxcError(VIR_ERR_OPERATION_FAILED,
                     "%s", _("Cannot read cputime for domain"));
            goto cleanup;
        }
        if ((rc = virCgroupGetMemoryUsage(cgroup, &(info->memory))) < 0) {
            lxcError(VIR_ERR_OPERATION_FAILED,
                     "%s", _("Cannot read memory usage for domain"));
            if (rc == -ENOENT) {
                /* Don't fail if we can't read memory usage due to a lack of
                 * kernel support */
                info->memory = 0;
            } else
                goto cleanup;
        }
    }

    info->maxMem = vm->def->mem.max_balloon;
    info->nrVirtCpu = 1;
    ret = 0;

cleanup:
    lxcDriverUnlock(driver);
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
lxcDomainGetState(virDomainPtr dom,
                  int *state,
                  int *reason,
                  unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static char *lxcGetOSType(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = strdup(vm->def->os.type);

    if (ret == NULL)
        virReportOOMError();

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

/* Returns max memory in kb, 0 if error */
static unsigned long long
lxcDomainGetMaxMemory(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    unsigned long long ret = 0;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                         _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = vm->def->mem.max_balloon;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int lxcDomainSetMaxMemory(virDomainPtr dom, unsigned long newmax) {
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                         _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmax < vm->def->mem.cur_balloon) {
        lxcError(VIR_ERR_INVALID_ARG,
                         "%s", _("Cannot set max memory lower than current memory"));
        goto cleanup;
    }

    vm->def->mem.max_balloon = newmax;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int lxcDomainSetMemory(virDomainPtr dom, unsigned long newmem) {
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virCgroupPtr cgroup = NULL;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (newmem > vm->def->mem.max_balloon) {
        lxcError(VIR_ERR_INVALID_ARG,
                 "%s", _("Cannot set memory higher than max memory"));
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (driver->cgroup == NULL) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("cgroups must be configured on the host"));
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("Unable to get cgroup for %s"), vm->def->name);
        goto cleanup;
    }

    if (virCgroupSetMemory(cgroup, newmem) < 0) {
        lxcError(VIR_ERR_OPERATION_FAILED,
                 "%s", _("Failed to set memory for domain"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (cgroup)
        virCgroupFree(&cgroup);
    return ret;
}

static int
lxcDomainSetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr cgroup = NULL;
    virDomainObjPtr vm = NULL;
    int ret = -1;
    int rc;

    virCheckFlags(0, -1);
    if (virTypedParameterArrayValidate(params, nparams,
                                       VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                       VIR_TYPED_PARAM_ULLONG,
                                       VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                       VIR_TYPED_PARAM_ULLONG,
                                       VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                       VIR_TYPED_PARAM_ULLONG,
                                       NULL) < 0)
        return -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_MEMORY_HARD_LIMIT)) {
            rc = virCgroupSetMemoryHardLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory hard_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT)) {
            rc = virCgroupSetMemorySoftLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set memory soft_limit tunable"));
                ret = -1;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT)) {
            rc = virCgroupSetMemSwapHardLimit(cgroup, params[i].value.ul);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to set swap_hard_limit tunable"));
                ret = -1;
            }
        }
    }

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int
lxcDomainGetMemoryParameters(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr cgroup = NULL;
    virDomainObjPtr vm = NULL;
    unsigned long long val;
    int ret = -1;
    int rc;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of memory parameters supported by cgroups */
        *nparams = LXC_NB_MEM_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("Unable to get cgroup for %s"), vm->def->name);
        goto cleanup;
    }

    for (i = 0; i < LXC_NB_MEM_PARAM && i < *nparams; i++) {
        virTypedParameterPtr param = &params[i];
        val = 0;

        switch(i) {
        case 0: /* fill memory hard limit here */
            rc = virCgroupGetMemoryHardLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory hard limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 1: /* fill memory soft limit here */
            rc = virCgroupGetMemorySoftLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get memory soft limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;
        case 2: /* fill swap hard limit here */
            rc = virCgroupGetMemSwapHardLimit(cgroup, &val);
            if (rc != 0) {
                virReportSystemError(-rc, "%s",
                                     _("unable to get swap hard limit"));
                goto cleanup;
            }
            if (virTypedParameterAssign(param,
                                        VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                                        VIR_TYPED_PARAM_ULLONG, val) < 0)
                goto cleanup;
            break;

        default:
            break;
            /* should not hit here */
        }
    }

    if (*nparams > LXC_NB_MEM_PARAM)
        *nparams = LXC_NB_MEM_PARAM;
    ret = 0;

cleanup:
    if (cgroup)
        virCgroupFree(&cgroup);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static char *lxcDomainGetXMLDesc(virDomainPtr dom,
                                 unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    ret = virDomainDefFormat((flags & VIR_DOMAIN_XML_INACTIVE) &&
                             vm->newDef ? vm->newDef : vm->def,
                             flags);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static int lxcProcessAutoDestroyInit(lxc_driver_t *driver)
{
    if (!(driver->autodestroy = virHashCreate(5, NULL)))
        return -1;

    return 0;
}

struct lxcProcessAutoDestroyData {
    lxc_driver_t *driver;
    virConnectPtr conn;
};

static void lxcProcessAutoDestroyDom(void *payload,
                                     const void *name,
                                     void *opaque)
{
    struct lxcProcessAutoDestroyData *data = opaque;
    virConnectPtr conn = payload;
    const char *uuidstr = name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainObjPtr dom;
    virDomainEventPtr event = NULL;

    VIR_DEBUG("conn=%p uuidstr=%s thisconn=%p", conn, uuidstr, data->conn);

    if (data->conn != conn)
        return;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        VIR_WARN("Failed to parse %s", uuidstr);
        return;
    }

    if (!(dom = virDomainFindByUUID(&data->driver->domains,
                                    uuid))) {
        VIR_DEBUG("No domain object to kill");
        return;
    }

    VIR_DEBUG("Killing domain");
    lxcVmTerminate(data->driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (dom && !dom->persistent)
        virDomainRemoveInactive(&data->driver->domains, dom);

    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        lxcDomainEventQueue(data->driver, event);
    virHashRemoveEntry(data->driver->autodestroy, uuidstr);
}

/*
 * Precondition: driver is locked
 */
static void lxcProcessAutoDestroyRun(lxc_driver_t *driver, virConnectPtr conn)
{
    struct lxcProcessAutoDestroyData data = {
        driver, conn
    };
    VIR_DEBUG("conn=%p", conn);
    virHashForEach(driver->autodestroy, lxcProcessAutoDestroyDom, &data);
}

static void lxcProcessAutoDestroyShutdown(lxc_driver_t *driver)
{
    virHashFree(driver->autodestroy);
}

static int lxcProcessAutoDestroyAdd(lxc_driver_t *driver,
                                    virDomainObjPtr vm,
                                    virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s uuid=%s conn=%p", vm->def->name, uuidstr, conn);
    if (virHashAddEntry(driver->autodestroy, uuidstr, conn) < 0)
        return -1;
    return 0;
}

static int lxcProcessAutoDestroyRemove(lxc_driver_t *driver,
                                       virDomainObjPtr vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s uuid=%s", vm->def->name, uuidstr);
    if (virHashRemoveEntry(driver->autodestroy, uuidstr) < 0)
        return -1;
    return 0;
}


/**
 * lxcVmCleanup:
 * @driver: pointer to driver structure
 * @vm: pointer to VM to clean up
 * @reason: reason for switching the VM to shutoff state
 *
 * Cleanout resources associated with the now dead VM
 *
 */
static void lxcVmCleanup(lxc_driver_t *driver,
                         virDomainObjPtr vm,
                         virDomainShutoffReason reason)
{
    virCgroupPtr cgroup;
    int i;
    lxcDomainObjPrivatePtr priv = vm->privateData;
    virNetDevVPortProfilePtr vport = NULL;

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_STOPPED, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    /* Stop autodestroy in case guest is restarted */
    lxcProcessAutoDestroyRemove(driver, vm);

    virEventRemoveHandle(priv->monitorWatch);
    VIR_FORCE_CLOSE(priv->monitor);

    virPidFileDelete(driver->stateDir, vm->def->name);
    virDomainDeleteConfig(driver->stateDir, NULL, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = -1;
    vm->def->id = -1;
    priv->monitor = -1;
    priv->monitorWatch = -1;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr iface = vm->def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(iface);
        ignore_value(virNetDevSetOnline(iface->ifname, false));
        if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
            ignore_value(virNetDevOpenvswitchRemovePort(
                            virDomainNetGetActualBridgeName(iface),
                            iface->ifname));
        ignore_value(virNetDevVethDelete(iface->ifname));
        networkReleaseActualDevice(iface);
    }

    virDomainConfVMNWFilterTeardown(vm);

    if (driver->cgroup &&
        virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) == 0) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }
}


static int lxcSetupInterfaceBridged(virConnectPtr conn,
                                    virDomainDefPtr vm,
                                    virDomainNetDefPtr net,
                                    const char *brname,
                                    unsigned int *nveths,
                                    char ***veths)
{
    int ret = -1;
    char *parentVeth;
    char *containerVeth = NULL;
    const virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(net);

    VIR_DEBUG("calling vethCreate()");
    parentVeth = net->ifname;
    if (virNetDevVethCreate(&parentVeth, &containerVeth) < 0)
        goto cleanup;
    VIR_DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);

    if (net->ifname == NULL)
        net->ifname = parentVeth;

    if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0) {
        virReportOOMError();
        VIR_FREE(containerVeth);
        goto cleanup;
    }
    (*veths)[(*nveths)] = containerVeth;
    (*nveths)++;

    if (virNetDevSetMAC(containerVeth, net->mac) < 0)
        goto cleanup;

    if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
        ret = virNetDevOpenvswitchAddPort(brname, parentVeth, net->mac,
                                          vm->uuid, vport);
    else
        ret = virNetDevBridgeAddPort(brname, parentVeth);
    if (ret < 0)
        goto cleanup;

    if (virNetDevSetOnline(parentVeth, true) < 0)
        goto cleanup;

    if (virNetDevBandwidthSet(net->ifname,
                              virDomainNetGetActualBandwidth(net)) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("cannot set bandwidth limits on %s"),
                 net->ifname);
        goto cleanup;
    }

    if (net->filter &&
        virDomainConfNWFilterInstantiate(conn, vm->uuid, net) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    return ret;
}


static int lxcSetupInterfaceDirect(virConnectPtr conn,
                                   virDomainDefPtr def,
                                   virDomainNetDefPtr net,
                                   unsigned int *nveths,
                                   char ***veths)
{
    int ret = 0;
    char *res_ifname = NULL;
    lxc_driver_t *driver = conn->privateData;
    virNetDevBandwidthPtr bw;
    virNetDevVPortProfilePtr prof;

    /* XXX how todo bandwidth controls ?
     * Since the 'net-ifname' is about to be moved to a different
     * namespace & renamed, there will be no host side visible
     * interface for the container to attach rules to
     */
    bw = virDomainNetGetActualBandwidth(net);
    if (bw) {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                 _("Unable to set network bandwidth on direct interfaces"));
        return -1;
    }

    /* XXX how todo port profiles ?
     * Although we can do the association during container
     * startup, at shutdown we are unable to disassociate
     * because the macvlan device was moved to the container
     * and automagically dies when the container dies. So
     * we have no dev to perform disassociation with.
     */
    prof = virDomainNetGetActualVirtPortProfile(net);
    if (prof) {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                 _("Unable to set port profile on direct interfaces"));
        return -1;
    }

    if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0) {
        virReportOOMError();
        return -1;
    }
    (*veths)[(*nveths)] = NULL;

    if (virNetDevMacVLanCreateWithVPortProfile(
            net->ifname, net->mac,
            virDomainNetGetActualDirectDev(net),
            virDomainNetGetActualDirectMode(net),
            false, false, def->uuid,
            virDomainNetGetActualVirtPortProfile(net),
            &res_ifname,
            VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
            driver->stateDir,
            virDomainNetGetActualBandwidth(net)) < 0)
        goto cleanup;

    (*veths)[(*nveths)] = res_ifname;
    (*nveths)++;

    ret = 0;

cleanup:
    return ret;
}


/**
 * lxcSetupInterfaces:
 * @conn: pointer to connection
 * @def: pointer to virtual machine structure
 * @nveths: number of interfaces
 * @veths: interface names
 *
 * Sets up the container interfaces by creating the veth device pairs and
 * attaching the parent end to the appropriate bridge.  The container end
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcSetupInterfaces(virConnectPtr conn,
                              virDomainDefPtr def,
                              unsigned int *nveths,
                              char ***veths)
{
    int ret = -1;
    size_t i;

    for (i = 0 ; i < def->nnets ; i++) {
        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (networkAllocateActualDevice(def->nets[i]) < 0)
            goto cleanup;

        switch (virDomainNetGetActualType(def->nets[i])) {
        case VIR_DOMAIN_NET_TYPE_NETWORK: {
            virNetworkPtr network;
            char *brname = NULL;

            if (!(network = virNetworkLookupByName(conn,
                                                   def->nets[i]->data.network.name)))
                goto cleanup;

            brname = virNetworkGetBridgeName(network);
            virNetworkFree(network);
            if (!brname)
                goto cleanup;

            if (lxcSetupInterfaceBridged(conn,
                                         def,
                                         def->nets[i],
                                         brname,
                                         nveths,
                                         veths) < 0) {
                VIR_FREE(brname);
                goto cleanup;
            }
            VIR_FREE(brname);
            break;
        }
        case VIR_DOMAIN_NET_TYPE_BRIDGE: {
            const char *brname = virDomainNetGetActualBridgeName(def->nets[i]);
            if (!brname) {
                lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("No bridge name specified"));
                goto cleanup;
            }
            if (lxcSetupInterfaceBridged(conn,
                                         def,
                                         def->nets[i],
                                         brname,
                                         nveths,
                                         veths) < 0)
                goto cleanup;
        }   break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            if (lxcSetupInterfaceDirect(conn,
                                        def,
                                        def->nets[i],
                                        nveths,
                                        veths) < 0)
                goto cleanup;
            break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_LAST:
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("Unsupported network type %s"),
                     virDomainNetTypeToString(
                         virDomainNetGetActualType(def->nets[i])
                         ));
            goto cleanup;
        }
    }

    ret= 0;

cleanup:
    if (ret != 0) {
        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr iface = def->nets[i];
            virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(iface);
            if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            networkReleaseActualDevice(iface);
        }
    }
    return ret;
}


static int lxcMonitorClient(lxc_driver_t * driver,
                            virDomainObjPtr vm)
{
    char *sockpath = NULL;
    int fd;
    struct sockaddr_un addr;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    driver->stateDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to set security context for monitor for %s"),
                  vm->def->name);
        goto error;
    }

    fd = socket(PF_UNIX, SOCK_STREAM, 0);

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0) {
        VIR_ERROR(_("Failed to clear security context for monitor for %s"),
                  vm->def->name);
        goto error;
    }

    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to create client socket"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, sockpath) == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("Socket path %s too big for destination"), sockpath);
        goto error;
    }

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to connect to client socket"));
        goto error;
    }

    VIR_FREE(sockpath);
    return fd;

error:
    VIR_FREE(sockpath);
    VIR_FORCE_CLOSE(fd);
    return -1;
}


static int lxcVmTerminate(lxc_driver_t *driver,
                          virDomainObjPtr vm,
                          virDomainShutoffReason reason)
{
    virCgroupPtr group = NULL;
    int rc;

    if (vm->pid <= 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("Invalid PID %d for container"), vm->pid);
        return -1;
    }

    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm->def, false);
    virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
    /* Clear out dynamically assigned labels */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabel.model);
        VIR_FREE(vm->def->seclabel.label);
        VIR_FREE(vm->def->seclabel.imagelabel);
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) == 0) {
        rc = virCgroupKillPainfully(group);
        if (rc < 0) {
            virReportSystemError(-rc, "%s",
                                 _("Failed to kill container PIDs"));
            rc = -1;
            goto cleanup;
        }
        if (rc == 1) {
            lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Some container PIDs refused to die"));
            rc = -1;
            goto cleanup;
        }
    } else {
        /* If cgroup doesn't exist, the VM pids must have already
         * died and so we're just cleaning up stale state
         */
    }

    lxcVmCleanup(driver, vm, reason);

    rc = 0;

cleanup:
    virCgroupFree(&group);
    return rc;
}

static void lxcMonitorEvent(int watch,
                            int fd,
                            int events ATTRIBUTE_UNUSED,
                            void *data)
{
    lxc_driver_t *driver = lxc_driver;
    virDomainObjPtr vm = data;
    virDomainEventPtr event = NULL;
    lxcDomainObjPrivatePtr priv;

    lxcDriverLock(driver);
    virDomainObjLock(vm);
    lxcDriverUnlock(driver);

    priv = vm->privateData;

    if (priv->monitor != fd || priv->monitorWatch != watch) {
        virEventRemoveHandle(watch);
        goto cleanup;
    }

    if (lxcVmTerminate(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0) {
        virEventRemoveHandle(watch);
    } else {
        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        virDomainAuditStop(vm, "shutdown");
    }
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event) {
        lxcDriverLock(driver);
        lxcDomainEventQueue(driver, event);
        lxcDriverUnlock(driver);
    }
}


static virCommandPtr
lxcBuildControllerCmd(lxc_driver_t *driver,
                      virDomainObjPtr vm,
                      int nveths,
                      char **veths,
                      int *ttyFDs,
                      size_t nttyFDs,
                      int handshakefd)
{
    size_t i;
    char *filterstr;
    char *outputstr;
    virCommandPtr cmd;

    cmd = virCommandNew(vm->def->emulator);

    /* The controller may call ip command, so we have to retain PATH. */
    virCommandAddEnvPass(cmd, "PATH");

    virCommandAddEnvFormat(cmd, "LIBVIRT_DEBUG=%d",
                           virLogGetDefaultPriority());

    if (virLogGetNbFilters() > 0) {
        filterstr = virLogGetFilters();
        if (!filterstr) {
            virReportOOMError();
            goto cleanup;
        }

        virCommandAddEnvPair(cmd, "LIBVIRT_LOG_FILTERS", filterstr);
        VIR_FREE(filterstr);
    }

    if (driver->log_libvirtd) {
        if (virLogGetNbOutputs() > 0) {
            outputstr = virLogGetOutputs();
            if (!outputstr) {
                virReportOOMError();
                goto cleanup;
            }

            virCommandAddEnvPair(cmd, "LIBVIRT_LOG_OUTPUTS", outputstr);
            VIR_FREE(outputstr);
        }
    } else {
        virCommandAddEnvFormat(cmd,
                               "LIBVIRT_LOG_OUTPUTS=%d:stderr",
                               virLogGetDefaultPriority());
    }

    virCommandAddArgList(cmd, "--name", vm->def->name, NULL);
    for (i = 0 ; i < nttyFDs ; i++) {
        virCommandAddArg(cmd, "--console");
        virCommandAddArgFormat(cmd, "%d", ttyFDs[i]);
        virCommandPreserveFD(cmd, ttyFDs[i]);
    }

    if (driver->securityDriverName)
        virCommandAddArgPair(cmd, "--security", driver->securityDriverName);

    virCommandAddArg(cmd, "--handshake");
    virCommandAddArgFormat(cmd, "%d", handshakefd);
    virCommandAddArg(cmd, "--background");

    for (i = 0 ; i < nveths ; i++) {
        virCommandAddArgList(cmd, "--veth", veths[i], NULL);
    }

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                              VIR_HOOK_LXC_OP_START, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup;
    }

    virCommandPreserveFD(cmd, handshakefd);

    return cmd;
cleanup:
    virCommandFree(cmd);
    return NULL;
}

static int
lxcReadLogOutput(virDomainObjPtr vm,
                 char *logfile,
                 off_t pos,
                 char *buf,
                 size_t buflen)
{
    int fd;
    off_t off;
    int whence;
    int got = 0, ret = -1;
    int retries = 10;

    if ((fd = open(logfile, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("failed to open logfile %s"),
                             logfile);
        goto cleanup;
    }

    if (pos < 0) {
        off = 0;
        whence = SEEK_END;
    } else {
        off = pos;
        whence = SEEK_SET;
    }

    if (lseek(fd, off, whence) < 0) {
        if (whence == SEEK_END)
            virReportSystemError(errno,
                                 _("unable to seek to end of log for %s"),
                                 logfile);
        else
            virReportSystemError(errno,
                                 _("unable to seek to %lld from start for %s"),
                                 (long long)off, logfile);
        goto cleanup;
    }

    while (retries) {
        ssize_t bytes;
        int isdead = 0;

        if (kill(vm->pid, 0) == -1 && errno == ESRCH)
            isdead = 1;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failure while reading guest log output"));
            goto cleanup;
        }

        got += bytes;
        buf[got] = '\0';

        if ((got == buflen-1) || isdead) {
            break;
        }

        usleep(100*1000);
        retries--;
    }


    ret = got;
cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * lxcVmStart:
 * @conn: pointer to connection
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @autoDestroy: mark the domain for auto destruction
 * @reason: reason for switching vm to running state
 *
 * Starts a vm
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcVmStart(virConnectPtr conn,
                      lxc_driver_t * driver,
                      virDomainObjPtr vm,
                      bool autoDestroy,
                      virDomainRunningReason reason)
{
    int rc = -1, r;
    size_t nttyFDs = 0;
    int *ttyFDs = NULL;
    size_t i;
    char *logfile = NULL;
    int logfd = -1;
    unsigned int nveths = 0;
    char **veths = NULL;
    int handshakefds[2] = { -1, -1 };
    off_t pos = -1;
    char ebuf[1024];
    char *timestamp;
    virCommandPtr cmd = NULL;
    lxcDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr err = NULL;

    if (!lxc_driver->cgroup) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("The 'cpuacct', 'devices' & 'memory' cgroups controllers must be mounted"));
        return -1;
    }

    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_CPUACCT)) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to find 'cpuacct' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_DEVICES)) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to find 'devices' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_MEMORY)) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to find 'memory' cgroups controller mount"));
        return -1;
    }

    if (virFileMakePath(driver->logDir) < 0) {
        virReportSystemError(errno,
                             _("Cannot create log directory '%s'"),
                             driver->logDir);
        return -1;
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    driver->logDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
    }

    /* Do this up front, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(driver->caps, vm, true) < 0)
        goto cleanup;

    /* Here we open all the PTYs we need on the host OS side.
     * The LXC controller will open the guest OS side PTYs
     * and forward I/O between them.
     */
    nttyFDs = vm->def->nconsoles;
    if (VIR_ALLOC_N(ttyFDs, nttyFDs) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    VIR_DEBUG("Generating domain security label (if required)");
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DEFAULT)
        vm->def->seclabel.type = VIR_DOMAIN_SECLABEL_NONE;

    if (virSecurityManagerGenLabel(driver->securityManager, vm->def) < 0) {
        virDomainAuditSecurityLabel(vm, false);
        goto cleanup;
    }
    virDomainAuditSecurityLabel(vm, true);

    VIR_DEBUG("Setting domain security labels");
    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def, NULL) < 0)
        goto cleanup;

    for (i = 0 ; i < vm->def->nconsoles ; i++)
        ttyFDs[i] = -1;

    for (i = 0 ; i < vm->def->nconsoles ; i++) {
        char *ttyPath;
        if (vm->def->consoles[i]->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
            lxcError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Only PTY console types are supported"));
            goto cleanup;
        }

        if (virFileOpenTty(&ttyFDs[i], &ttyPath, 1) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }

        VIR_FREE(vm->def->consoles[i]->source.data.file.path);
        vm->def->consoles[i]->source.data.file.path = ttyPath;

        VIR_FREE(vm->def->consoles[i]->info.alias);
        if (virAsprintf(&vm->def->consoles[i]->info.alias, "console%zu", i) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    }

    if (lxcSetupInterfaces(conn, vm->def, &nveths, &veths) != 0)
        goto cleanup;

    /* Save the configuration for the controller */
    if (virDomainSaveConfig(driver->stateDir, vm->def) < 0)
        goto cleanup;

    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    if (pipe(handshakefds) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create pipe"));
        goto cleanup;
    }

    if (!(cmd = lxcBuildControllerCmd(driver,
                                      vm,
                                      nveths, veths,
                                      ttyFDs, nttyFDs,
                                      handshakefds[1])))
        goto cleanup;
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);

    /* Log timestamp */
    if ((timestamp = virTimeStringNow()) == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, START_POSTFIX, strlen(START_POSTFIX)) < 0) {
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));
    }
    VIR_FREE(timestamp);

    /* Log generated command line */
    virCommandWriteArgLog(cmd, logfd);
    if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_CLOSE(handshakefds[1]) < 0) {
        virReportSystemError(errno, "%s", _("could not close handshake fd"));
        goto cleanup;
    }

    /* Connect to the controller as a client *first* because
     * this will block until the child has written their
     * pid file out to disk */
    if ((priv->monitor = lxcMonitorClient(driver, vm)) < 0)
        goto cleanup;

    /* And get its pid */
    if ((r = virPidFileRead(driver->stateDir, vm->def->name, &vm->pid)) < 0) {
        virReportSystemError(-r,
                             _("Failed to read pid file %s/%s.pid"),
                             driver->stateDir, vm->def->name);
        goto cleanup;
    }

    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);

    if (lxcContainerWaitForContinue(handshakefds[0]) < 0) {
        char out[1024];

        if (!(lxcReadLogOutput(vm, logfile, pos, out, 1024) < 0)) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("guest failed to start: %s"), out);
        }

        goto error;
    }

    if ((priv->monitorWatch = virEventAddHandle(
             priv->monitor,
             VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP,
             lxcMonitorEvent,
             vm, NULL)) < 0) {
        goto error;
    }

    if (autoDestroy &&
        lxcProcessAutoDestroyAdd(driver, vm, conn) < 0)
        goto error;

    /*
     * Again, need to save the live configuration, because the function
     * requires vm->def->id != -1 to save tty info surely.
     */
    if (virDomainSaveConfig(driver->stateDir, vm->def) < 0)
        goto error;

    if (virDomainObjSetDefTransient(driver->caps, vm, false) < 0)
        goto error;

    /* Write domain status to disk. */
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto error;

    rc = 0;

cleanup:
    if (rc != 0 && !err)
        err = virSaveLastError();
    virCommandFree(cmd);
    if (VIR_CLOSE(logfd) < 0) {
        virReportSystemError(errno, "%s", _("could not close logfile"));
        rc = -1;
    }
    for (i = 0 ; i < nveths ; i++) {
        if (rc != 0)
            ignore_value(virNetDevVethDelete(veths[i]));
        VIR_FREE(veths[i]);
    }
    if (rc != 0) {
        VIR_FORCE_CLOSE(priv->monitor);
        virDomainConfVMNWFilterTeardown(vm);

        virSecurityManagerRestoreAllLabel(driver->securityManager,
                                          vm->def, false);
        virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
        /* Clear out dynamically assigned labels */
        if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
            VIR_FREE(vm->def->seclabel.model);
            VIR_FREE(vm->def->seclabel.label);
            VIR_FREE(vm->def->seclabel.imagelabel);
        }
    }
    for (i = 0 ; i < nttyFDs ; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);
    VIR_FORCE_CLOSE(handshakefds[0]);
    VIR_FORCE_CLOSE(handshakefds[1]);
    VIR_FREE(logfile);

    if (err) {
        virSetError(err);
        virFreeError(err);
    }

    return rc;

error:
    err = virSaveLastError();
    lxcVmTerminate(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    goto cleanup;
}

/**
 * lxcDomainStartWithFlags:
 * @dom: domain to start
 * @flags: Must be 0 for now
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainStartWithFlags(virDomainPtr dom, unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if ((vm->def->nets != NULL) && !(driver->have_netns)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = lxcVmStart(dom->conn, driver, vm,
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
        virDomainObjUnlock(vm);
    if (event)
        lxcDomainEventQueue(driver, event);
    lxcDriverUnlock(driver);
    return ret;
}

/**
 * lxcDomainStart:
 * @dom: domain to start
 *
 * Looks up domain and starts it.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcDomainStart(virDomainPtr dom)
{
    return lxcDomainStartWithFlags(dom, 0);
}

/**
 * lxcDomainCreateAndStart:
 * @conn: pointer to connection
 * @xml: XML definition of domain
 * @flags: Must be 0 for now
 *
 * Creates a domain based on xml and starts it
 *
 * Returns 0 on success or -1 in case of error
 */
static virDomainPtr
lxcDomainCreateAndStart(virConnectPtr conn,
                        const char *xml,
                        unsigned int flags) {
    lxc_driver_t *driver = conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr def;
    virDomainPtr dom = NULL;
    virDomainEventPtr event = NULL;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, NULL);

    lxcDriverLock(driver);
    if (!(def = virDomainDefParseString(driver->caps, xml,
                                        1 << VIR_DOMAIN_VIRT_LXC,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    if (virSecurityManagerVerify(driver->securityManager, def) < 0)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, def, 1) < 0)
        goto cleanup;

    if ((def->nets != NULL) && !(driver->have_netns)) {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
                 "%s", _("System lacks NETNS support"));
        goto cleanup;
    }


    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, def, false)))
        goto cleanup;
    def = NULL;

    if (lxcVmStart(conn, driver, vm,
                   (flags & VIR_DOMAIN_START_AUTODESTROY),
                   VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        virDomainAuditStart(vm, "booted", false);
        virDomainRemoveInactive(&driver->domains, vm);
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
        virDomainObjUnlock(vm);
    if (event)
        lxcDomainEventQueue(driver, event);
    lxcDriverUnlock(driver);
    return dom;
}


static int lxcDomainGetSecurityLabel(virDomainPtr dom, virSecurityLabelPtr seclabel)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    memset(seclabel, 0, sizeof(*seclabel));

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainVirtTypeToString(vm->def->virtType)) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
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
        if (virSecurityManagerGetProcessLabel(driver->securityManager,
                                              vm->def, vm->pid, seclabel) < 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("Failed to get security label"));
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcNodeGetSecurityModel(virConnectPtr conn,
                                   virSecurityModelPtr secmodel)
{
    lxc_driver_t *driver = conn->privateData;
    int ret = 0;

    lxcDriverLock(driver);
    memset(secmodel, 0, sizeof(*secmodel));

    /* NULL indicates no driver, which we treat as
     * success, but simply return no data in *secmodel */
    if (driver->caps->host.secModel.model == NULL)
        goto cleanup;

    if (!virStrcpy(secmodel->model, driver->caps->host.secModel.model,
                   VIR_SECURITY_MODEL_BUFLEN)) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("security model string exceeds max %d bytes"),
                 VIR_SECURITY_MODEL_BUFLEN - 1);
        ret = -1;
        goto cleanup;
    }

    if (!virStrcpy(secmodel->doi, driver->caps->host.secModel.doi,
                   VIR_SECURITY_DOI_BUFLEN)) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("security DOI string exceeds max %d bytes"),
                 VIR_SECURITY_DOI_BUFLEN-1);
        ret = -1;
        goto cleanup;
    }

cleanup:
    lxcDriverUnlock(driver);
    return ret;
}


static int
lxcDomainEventRegister(virConnectPtr conn,
                       virConnectDomainEventCallback callback,
                       void *opaque,
                       virFreeCallback freecb)
{
    lxc_driver_t *driver = conn->privateData;
    int ret;

    lxcDriverLock(driver);
    ret = virDomainEventStateRegister(conn,
                                      driver->domainEventState,
                                      callback, opaque, freecb);
    lxcDriverUnlock(driver);

    return ret;
}


static int
lxcDomainEventDeregister(virConnectPtr conn,
                         virConnectDomainEventCallback callback)
{
    lxc_driver_t *driver = conn->privateData;
    int ret;

    lxcDriverLock(driver);
    ret = virDomainEventStateDeregister(conn,
                                        driver->domainEventState,
                                        callback);
    lxcDriverUnlock(driver);

    return ret;
}


static int
lxcDomainEventRegisterAny(virConnectPtr conn,
                          virDomainPtr dom,
                          int eventID,
                          virConnectDomainEventGenericCallback callback,
                          void *opaque,
                          virFreeCallback freecb)
{
    lxc_driver_t *driver = conn->privateData;
    int ret;

    lxcDriverLock(driver);
    if (virDomainEventStateRegisterID(conn,
                                      driver->domainEventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;
    lxcDriverUnlock(driver);

    return ret;
}


static int
lxcDomainEventDeregisterAny(virConnectPtr conn,
                            int callbackID)
{
    lxc_driver_t *driver = conn->privateData;
    int ret;

    lxcDriverLock(driver);
    ret = virDomainEventStateDeregisterID(conn,
                                          driver->domainEventState,
                                          callbackID);
    lxcDriverUnlock(driver);

    return ret;
}


/* driver must be locked before calling */
static void lxcDomainEventQueue(lxc_driver_t *driver,
                                 virDomainEventPtr event)
{
    virDomainEventStateQueue(driver->domainEventState, event);
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
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is not running"));
        goto cleanup;
    }

    ret = lxcVmTerminate(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    virDomainAuditStop(vm, "destroyed");
    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    if (event)
        lxcDomainEventQueue(driver, event);
    lxcDriverUnlock(driver);
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


struct lxcAutostartData {
    lxc_driver_t *driver;
    virConnectPtr conn;
};

static void
lxcAutostartDomain(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    const struct lxcAutostartData *data = opaque;

    virDomainObjLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        int ret = lxcVmStart(data->conn, data->driver, vm, false,
                             VIR_DOMAIN_RUNNING_BOOTED);
        virDomainAuditStart(vm, "booted", ret >= 0);
        if (ret < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : "");
        } else {
            virDomainEventPtr event =
                virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                lxcDomainEventQueue(data->driver, event);
        }
    }
    virDomainObjUnlock(vm);
}

static void
lxcAutostartConfigs(lxc_driver_t *driver) {
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("lxc:///");
    /* Ignoring NULL conn which is mostly harmless here */

    struct lxcAutostartData data = { driver, conn };

    lxcDriverLock(driver);
    virHashForEach(driver->domains.objs, lxcAutostartDomain, &data);
    lxcDriverUnlock(driver);

    if (conn)
        virConnectClose(conn);
}

static void
lxcReconnectVM(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    lxc_driver_t *driver = opaque;
    lxcDomainObjPrivatePtr priv;

    virDomainObjLock(vm);
    VIR_DEBUG("Reconnect %d %d %d\n", vm->def->id, vm->pid, vm->state.state);

    priv = vm->privateData;

    if (vm->pid != 0) {
        vm->def->id = vm->pid;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);

        if ((priv->monitor = lxcMonitorClient(driver, vm)) < 0)
            goto error;

        if ((priv->monitorWatch = virEventAddHandle(
                 priv->monitor,
                 VIR_EVENT_HANDLE_ERROR | VIR_EVENT_HANDLE_HANGUP,
                 lxcMonitorEvent,
                 vm, NULL)) < 0)
            goto error;

        if (virSecurityManagerReserveLabel(driver->securityManager,
                                           vm->def, vm->pid) < 0)
            goto error;
    } else {
        vm->def->id = -1;
        VIR_FORCE_CLOSE(priv->monitor);
    }

cleanup:
    virDomainObjUnlock(vm);
    return;

error:
    lxcVmTerminate(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    virDomainAuditStop(vm, "failed");
    goto cleanup;
}


static int
lxcSecurityInit(lxc_driver_t *driver)
{
    virSecurityManagerPtr mgr = virSecurityManagerNew(driver->securityDriverName,
                                                      false,
                                                      driver->securityDefaultConfined,
                                                      driver->securityRequireConfined);
    if (!mgr)
        goto error;

    driver->securityManager = mgr;

    return 0;

error:
    VIR_ERROR(_("Failed to initialize security drivers"));
    virSecurityManagerFree(mgr);
    return -1;
}


static int lxcStartup(int privileged)
{
    char *ld;
    int rc;

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
    lxcDriverLock(lxc_driver);

    if (virDomainObjListInit(&lxc_driver->domains) < 0)
        goto cleanup;

    lxc_driver->domainEventState = virDomainEventStateNew();
    if (!lxc_driver->domainEventState)
        goto cleanup;

    lxc_driver->log_libvirtd = 0; /* by default log to container logfile */
    lxc_driver->have_netns = lxcCheckNetNsSupport();

    rc = virCgroupForDriver("lxc", &lxc_driver->cgroup, privileged, 1);
    if (rc < 0) {
        char buf[1024] ATTRIBUTE_UNUSED;
        VIR_DEBUG("Unable to create cgroup for LXC driver: %s",
                  virStrerror(-rc, buf, sizeof(buf)));
        /* Don't abort startup. We will explicitly report to
         * the user when they try to start a VM
         */
    }

    /* Call function to load lxc driver configuration information */
    if (lxcLoadDriverConfig(lxc_driver) < 0)
        goto cleanup;

    if (lxcSecurityInit(lxc_driver) < 0)
        goto cleanup;

    if ((lxc_driver->caps = lxcCapsInit(lxc_driver)) == NULL)
        goto cleanup;

    lxc_driver->caps->privateDataAllocFunc = lxcDomainObjPrivateAlloc;
    lxc_driver->caps->privateDataFreeFunc = lxcDomainObjPrivateFree;

    if (lxcProcessAutoDestroyInit(lxc_driver) < 0)
        goto cleanup;

    /* Get all the running persistent or transient configs first */
    if (virDomainLoadAllConfigs(lxc_driver->caps,
                                &lxc_driver->domains,
                                lxc_driver->stateDir,
                                NULL,
                                1, 1 << VIR_DOMAIN_VIRT_LXC,
                                NULL, NULL) < 0)
        goto cleanup;

    virHashForEach(lxc_driver->domains.objs, lxcReconnectVM, lxc_driver);

    /* Then inactive persistent configs */
    if (virDomainLoadAllConfigs(lxc_driver->caps,
                                &lxc_driver->domains,
                                lxc_driver->configDir,
                                lxc_driver->autostartDir,
                                0, 1 << VIR_DOMAIN_VIRT_LXC,
                                NULL, NULL) < 0)
        goto cleanup;

    lxcDriverUnlock(lxc_driver);

    lxcAutostartConfigs(lxc_driver);

    return 0;

cleanup:
    lxcDriverUnlock(lxc_driver);
    lxcShutdown();
    return -1;
}

static void lxcNotifyLoadDomain(virDomainObjPtr vm, int newVM, void *opaque)
{
    lxc_driver_t *driver = opaque;

    if (newVM) {
        virDomainEventPtr event =
            virDomainEventNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);
        if (event)
            lxcDomainEventQueue(driver, event);
    }
}

/**
 * lxcReload:
 *
 * Function to restart the LXC driver, it will recheck the configuration
 * files and perform autostart
 */
static int
lxcReload(void) {
    if (!lxc_driver)
        return 0;

    lxcDriverLock(lxc_driver);
    virDomainLoadAllConfigs(lxc_driver->caps,
                            &lxc_driver->domains,
                            lxc_driver->configDir,
                            lxc_driver->autostartDir,
                            0, 1 << VIR_DOMAIN_VIRT_LXC,
                            lxcNotifyLoadDomain, lxc_driver);
    lxcDriverUnlock(lxc_driver);

    lxcAutostartConfigs(lxc_driver);

    return 0;
}

static int lxcShutdown(void)
{
    if (lxc_driver == NULL)
        return -1;

    lxcDriverLock(lxc_driver);
    virDomainObjListDeinit(&lxc_driver->domains);
    virDomainEventStateFree(lxc_driver->domainEventState);

    lxcProcessAutoDestroyShutdown(lxc_driver);

    virCapabilitiesFree(lxc_driver->caps);
    virSecurityManagerFree(lxc_driver->securityManager);
    VIR_FREE(lxc_driver->configDir);
    VIR_FREE(lxc_driver->autostartDir);
    VIR_FREE(lxc_driver->stateDir);
    VIR_FREE(lxc_driver->logDir);
    lxcDriverUnlock(lxc_driver);
    virMutexDestroy(&lxc_driver->lock);
    VIR_FREE(lxc_driver);

    return 0;
}

/**
 * lxcActive:
 *
 * Checks if the LXC daemon is active, i.e. has an active domain
 *
 * Returns 1 if active, 0 otherwise
 */
static int
lxcActive(void) {
    int active;

    if (lxc_driver == NULL)
        return 0;

    lxcDriverLock(lxc_driver);
    active = virDomainObjListNumOfDomains(&lxc_driver->domains, 1);
    lxcDriverUnlock(lxc_driver);

    return active;
}

static int lxcVersion(virConnectPtr conn ATTRIBUTE_UNUSED, unsigned long *version)
{
    struct utsname ver;

    uname(&ver);

    if (virParseVersionString(ver.release, version, true) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR, _("Unknown release: %s"), ver.release);
        return -1;
    }

    return 0;
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


static bool lxcCgroupControllerActive(lxc_driver_t *driver,
                                      int controller)
{
    if (driver->cgroup == NULL)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;
    if (!virCgroupMounted(driver->cgroup, controller))
        return false;
#if 0
    if (driver->cgroupControllers & (1 << controller))
        return true;
#endif
    return false;
}



static char *lxcGetSchedulerType(virDomainPtr domain,
                                 int *nparams)
{
    lxc_driver_t *driver = domain->conn->privateData;
    char *ret = NULL;
    int rc;

    lxcDriverLock(driver);
    if (!lxcCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (nparams) {
        rc = lxcGetCpuBWStatus(driver->cgroup);
        if (rc < 0)
            goto cleanup;
        else if (rc == 0)
            *nparams = 1;
        else
            *nparams = 3;
    }

    ret = strdup("posix");
    if (!ret)
        virReportOOMError();

cleanup:
    lxcDriverUnlock(driver);
    return ret;
}


static int
lxcGetVcpuBWLive(virCgroupPtr cgroup, unsigned long long *period,
                 long long *quota)
{
    int rc;

    rc = virCgroupGetCpuCfsPeriod(cgroup, period);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth period tunable"));
        return -1;
    }

    rc = virCgroupGetCpuCfsQuota(cgroup, quota);
    if (rc < 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu bandwidth tunable"));
        return -1;
    }

    return 0;
}


static int lxcSetVcpuBWLive(virCgroupPtr cgroup, unsigned long long period,
                            long long quota)
{
    int rc;
    unsigned long long old_period;

    if (period == 0 && quota == 0)
        return 0;

    if (period) {
        /* get old period, and we can rollback if set quota failed */
        rc = virCgroupGetCpuCfsPeriod(cgroup, &old_period);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to get cpu bandwidth period"));
            return -1;
        }

        rc = virCgroupSetCpuCfsPeriod(cgroup, period);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to set cpu bandwidth period"));
            return -1;
        }
    }

    if (quota) {
        rc = virCgroupSetCpuCfsQuota(cgroup, quota);
        if (rc < 0) {
            virReportSystemError(-rc,
                                 "%s", _("Unable to set cpu bandwidth quota"));
            goto cleanup;
        }
    }

    return 0;

cleanup:
    if (period) {
        rc = virCgroupSetCpuCfsPeriod(cgroup, old_period);
        if (rc < 0)
            virReportSystemError(-rc,
                                 _("%s"),
                                 "Unable to rollback cpu bandwidth period");
    }

    return -1;
}


static int
lxcSetSchedulerParametersFlags(virDomainPtr dom,
                               virTypedParameterPtr params,
                               int nparams,
                               unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr vmdef = NULL;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParameterArrayValidate(params, nparams,
                                       VIR_DOMAIN_SCHEDULER_CPU_SHARES,
                                       VIR_TYPED_PARAM_ULLONG,
                                       VIR_DOMAIN_SCHEDULER_VCPU_PERIOD,
                                       VIR_TYPED_PARAM_ULLONG,
                                       VIR_DOMAIN_SCHEDULER_VCPU_QUOTA,
                                       VIR_TYPED_PARAM_LLONG,
                                       NULL) < 0)
        return -1;

    lxcDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(driver->caps, vm, &flags,
                                        &vmdef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        /* Make a copy for updated domain. */
        vmdef = virDomainObjCopyPersistentDef(driver->caps, vm);
        if (!vmdef)
            goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!lxcCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
            lxcError(VIR_ERR_OPERATION_INVALID,
                     "%s", _("cgroup CPU controller is not mounted"));
            goto cleanup;
        }
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("cannot find cgroup for domain %s"),
                     vm->def->name);
            goto cleanup;
        }
    }

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_CPU_SHARES)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = virCgroupSetCpuShares(group, params[i].value.ul);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set cpu shares tunable"));
                    goto cleanup;
                }

                vm->def->cputune.shares = params[i].value.ul;
            }

            if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
                vmdef->cputune.shares = params[i].value.ul;
            }
        } else if (STREQ(param->field, VIR_DOMAIN_SCHEDULER_VCPU_PERIOD)) {
            if (flags & VIR_DOMAIN_AFFECT_LIVE) {
                rc = lxcSetVcpuBWLive(group, params[i].value.ul, 0);
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
                rc = lxcSetVcpuBWLive(group, 0, params[i].value.l);
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

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;


    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        rc = virDomainSaveConfig(driver->configDir, vmdef);
        if (rc < 0)
            goto cleanup;

        virDomainObjAssignDef(vm, vmdef, false);
        vmdef = NULL;
    }

    ret = 0;

cleanup:
    virDomainDefFree(vmdef);
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int
lxcSetSchedulerParameters(virDomainPtr domain,
                          virTypedParameterPtr params,
                          int nparams)
{
    return lxcSetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int
lxcGetSchedulerParametersFlags(virDomainPtr dom,
                               virTypedParameterPtr params,
                               int *nparams,
                               unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef;
    unsigned long long shares = 0;
    unsigned long long period = 0;
    long long quota = 0;
    int ret = -1;
    int rc;
    bool cpu_bw_status = false;
    int saved_nparams = 0;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    lxcDriverLock(driver);

    if (*nparams > 1) {
        rc = lxcGetCpuBWStatus(driver->cgroup);
        if (rc < 0)
            goto cleanup;
        cpu_bw_status = !!rc;
    }

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(driver->caps, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        shares = persistentDef->cputune.shares;
        if (*nparams > 1 && cpu_bw_status) {
            period = persistentDef->cputune.period;
            quota = persistentDef->cputune.quota;
        }
        goto out;
    }

    if (!lxcCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_CPU)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("cgroup CPU controller is not mounted"));
        goto cleanup;
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("cannot find cgroup for domain %s"), vm->def->name);
        goto cleanup;
    }

    rc = virCgroupGetCpuShares(group, &shares);
    if (rc != 0) {
        virReportSystemError(-rc, "%s",
                             _("unable to get cpu shares tunable"));
        goto cleanup;
    }

    if (*nparams > 1 && cpu_bw_status) {
        rc = lxcGetVcpuBWLive(group, &period, &quota);
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
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int
lxcGetSchedulerParameters(virDomainPtr domain,
                          virTypedParameterPtr params,
                          int *nparams)
{
    return lxcGetSchedulerParametersFlags(domain, params, nparams, 0);
}


static int
lxcDomainSetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    if (virTypedParameterArrayValidate(params, nparams,
                                       VIR_DOMAIN_BLKIO_WEIGHT,
                                       VIR_TYPED_PARAM_UINT,
                                       NULL) < 0)
        return -1;

    lxcDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                        _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(driver->caps, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!lxcCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            lxcError(VIR_ERR_OPERATION_INVALID, _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            virTypedParameterPtr param = &params[i];

            if (STREQ(param->field, VIR_DOMAIN_BLKIO_WEIGHT)) {
                int rc;

                if (params[i].value.ui > 1000 || params[i].value.ui < 100) {
                    lxcError(VIR_ERR_INVALID_ARG, "%s",
                             _("out of blkio weight range."));
                    goto cleanup;
                }

                rc = virCgroupSetBlkioWeight(group, params[i].value.ui);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to set blkio weight tunable"));
                    goto cleanup;
                }
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
                    lxcError(VIR_ERR_INVALID_ARG, "%s",
                             _("out of blkio weight range."));
                    goto cleanup;
                }

                persistentDef->blkio.weight = params[i].value.ui;
            }
        }

        if (virDomainSaveConfig(driver->configDir, persistentDef) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}


#define LXC_NB_BLKIO_PARAM  1
static int
lxcDomainGetBlkioParameters(virDomainPtr dom,
                            virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    int i;
    virCgroupPtr group = NULL;
    virDomainObjPtr vm = NULL;
    virDomainDefPtr persistentDef = NULL;
    unsigned int val;
    int ret = -1;
    int rc;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);
    lxcDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (vm == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("No such domain %s"), dom->uuid);
        goto cleanup;
    }

    if ((*nparams) == 0) {
        /* Current number of blkio parameters supported by cgroups */
        *nparams = LXC_NB_BLKIO_PARAM;
        ret = 0;
        goto cleanup;
    }

    if (virDomainLiveConfigHelperMethod(driver->caps, vm, &flags,
                                        &persistentDef) < 0)
        goto cleanup;

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!lxcCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_BLKIO)) {
            lxcError(VIR_ERR_OPERATION_INVALID, _("blkio cgroup isn't mounted"));
            goto cleanup;
        }

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) != 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR,
                     _("cannot find cgroup for domain %s"), vm->def->name);
            goto cleanup;
        }

        for (i = 0; i < *nparams && i < LXC_NB_BLKIO_PARAM; i++) {
            virTypedParameterPtr param = &params[i];
            val = 0;

            switch (i) {
            case 0: /* fill blkio weight here */
                rc = virCgroupGetBlkioWeight(group, &val);
                if (rc != 0) {
                    virReportSystemError(-rc, "%s",
                                         _("unable to get blkio weight"));
                    goto cleanup;
                }
                if (virTypedParameterAssign(param, VIR_DOMAIN_BLKIO_WEIGHT,
                                            VIR_TYPED_PARAM_UINT, val) < 0)
                    goto cleanup;
                break;

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
    if (group)
        virCgroupFree(&group);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}


#ifdef __linux__
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path,
                        struct _virDomainInterfaceStats *stats)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int i;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is not running"));
        goto cleanup;
    }

    /* Check the path is one of the domain's network interfaces. */
    for (i = 0 ; i < vm->def->nnets ; i++) {
        if (vm->def->nets[i]->ifname &&
            STREQ(vm->def->nets[i]->ifname, path)) {
            ret = 0;
            break;
        }
    }

    if (ret == 0)
        ret = linuxDomainInterfaceStats(path, stats);
    else
        lxcError(VIR_ERR_INVALID_ARG,
                 _("Invalid path, '%s' is not a known interface"), path);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}
#else
static int
lxcDomainInterfaceStats(virDomainPtr dom,
                        const char *path ATTRIBUTE_UNUSED,
                        struct _virDomainInterfaceStats *stats ATTRIBUTE_UNUSED)
{
    lxcError(VIR_ERR_NO_SUPPORT, "%s", __FUNCTION__);
    return -1;
}
#endif

static int lxcDomainGetAutostart(virDomainPtr dom,
                                   int *autostart) {
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    lxcDriverUnlock(driver);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    *autostart = vm->autostart;
    ret = 0;

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int lxcDomainSetAutostart(virDomainPtr dom,
                                   int autostart) {
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *configFile = NULL, *autostartLink = NULL;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!vm->persistent) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart == autostart) {
        ret = 0;
        goto cleanup;
    }

    configFile = virDomainConfigFile(driver->configDir,
                                     vm->def->name);
    if (configFile == NULL)
        goto cleanup;
    autostartLink = virDomainConfigFile(driver->autostartDir,
                                        vm->def->name);
    if (autostartLink == NULL)
        goto cleanup;

    if (autostart) {
        if (virFileMakePath(driver->autostartDir) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create autostart directory %s"),
                                 driver->autostartDir);
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
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcFreezeContainer(lxc_driver_t *driver, virDomainObjPtr vm)
{
    int timeout = 1000; /* In milliseconds */
    int check_interval = 1; /* In milliseconds */
    int exp = 10;
    int waited_time = 0;
    int ret = -1;
    char *state = NULL;
    virCgroupPtr cgroup = NULL;

    if (!(driver->cgroup &&
          virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) == 0))
        return -1;

    /* From here on, we know that cgroup != NULL.  */

    while (waited_time < timeout) {
        int r;
        /*
         * Writing "FROZEN" to the "freezer.state" freezes the group,
         * i.e., the container, temporarily transiting "FREEZING" state.
         * Once the freezing is completed, the state of the group transits
         * to "FROZEN".
         * (see linux-2.6/Documentation/cgroups/freezer-subsystem.txt)
         */
        r = virCgroupSetFreezerState(cgroup, "FROZEN");

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

        r = virCgroupGetFreezerState(cgroup, &state);

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
    virCgroupSetFreezerState(cgroup, "THAWED");
    ret = -1;

cleanup:
    virCgroupFree(&cgroup);
    VIR_FREE(state);
    return ret;
}

static int lxcDomainSuspend(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) != VIR_DOMAIN_PAUSED) {
        if (lxcFreezeContainer(driver, vm) < 0) {
            lxcError(VIR_ERR_OPERATION_FAILED,
                     "%s", _("Suspend operation failed"));
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (event)
        lxcDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int lxcUnfreezeContainer(lxc_driver_t *driver, virDomainObjPtr vm)
{
    int ret;
    virCgroupPtr cgroup = NULL;

    if (!(driver->cgroup &&
        virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) == 0))
        return -1;

    ret = virCgroupSetFreezerState(cgroup, "THAWED");

    virCgroupFree(&cgroup);
    return ret;
}

static int lxcDomainResume(virDomainPtr dom)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainEventPtr event = NULL;
    int ret = -1;

    lxcDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("Domain is not running"));
        goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (lxcUnfreezeContainer(driver, vm) < 0) {
            lxcError(VIR_ERR_OPERATION_FAILED,
                     "%s", _("Resume operation failed"));
            goto cleanup;
        }
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNPAUSED);

        event = virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    }

    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (event)
        lxcDomainEventQueue(driver, event);
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int
lxcDomainOpenConsole(virDomainPtr dom,
                      const char *dev_name,
                      virStreamPtr st,
                      unsigned int flags)
{
    lxc_driver_t *driver = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ret = -1;
    virDomainChrDefPtr chr = NULL;
    size_t i;

    virCheckFlags(0, -1);

    lxcDriverLock(driver);
    virUUIDFormat(dom->uuid, uuidstr);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        lxcError(VIR_ERR_NO_DOMAIN,
                 _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (!virDomainObjIsActive(vm)) {
        lxcError(VIR_ERR_OPERATION_INVALID,
                 "%s", _("domain is not running"));
        goto cleanup;
    }

    if (dev_name) {
        for (i = 0 ; i < vm->def->nconsoles ; i++) {
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
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("cannot find console device '%s'"),
                 dev_name ? dev_name : _("default"));
        goto cleanup;
    }

    if (chr->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("character device %s is not using a PTY"), dev_name);
        goto cleanup;
    }

    if (virFDStreamOpenFile(st, chr->source.data.file.path,
                            0, 0, O_RDWR) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    lxcDriverUnlock(driver);
    return ret;
}

static int
lxcVMFilterRebuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                   virHashIterator iter, void *data)
{
    virHashForEach(lxc_driver->domains.objs, iter, data);

    return 0;
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

/* Function Tables */
static virDriver lxcDriver = {
    .no = VIR_DRV_LXC,
    .name = "LXC",
    .open = lxcOpen, /* 0.4.2 */
    .close = lxcClose, /* 0.4.2 */
    .version = lxcVersion, /* 0.4.6 */
    .getHostname = virGetHostname, /* 0.6.3 */
    .nodeGetInfo = nodeGetInfo, /* 0.6.5 */
    .getCapabilities = lxcGetCapabilities, /* 0.6.5 */
    .listDomains = lxcListDomains, /* 0.4.2 */
    .numOfDomains = lxcNumDomains, /* 0.4.2 */
    .domainCreateXML = lxcDomainCreateAndStart, /* 0.4.4 */
    .domainLookupByID = lxcDomainLookupByID, /* 0.4.2 */
    .domainLookupByUUID = lxcDomainLookupByUUID, /* 0.4.2 */
    .domainLookupByName = lxcDomainLookupByName, /* 0.4.2 */
    .domainSuspend = lxcDomainSuspend, /* 0.7.2 */
    .domainResume = lxcDomainResume, /* 0.7.2 */
    .domainDestroy = lxcDomainDestroy, /* 0.4.4 */
    .domainDestroyFlags = lxcDomainDestroyFlags, /* 0.9.4 */
    .domainGetOSType = lxcGetOSType, /* 0.4.2 */
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
    .listDefinedDomains = lxcListDefinedDomains, /* 0.4.2 */
    .numOfDefinedDomains = lxcNumDefinedDomains, /* 0.4.2 */
    .domainCreate = lxcDomainStart, /* 0.4.4 */
    .domainCreateWithFlags = lxcDomainStartWithFlags, /* 0.8.2 */
    .domainDefineXML = lxcDomainDefine, /* 0.4.2 */
    .domainUndefine = lxcDomainUndefine, /* 0.4.2 */
    .domainUndefineFlags = lxcDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = lxcDomainGetAutostart, /* 0.7.0 */
    .domainSetAutostart = lxcDomainSetAutostart, /* 0.7.0 */
    .domainGetSchedulerType = lxcGetSchedulerType, /* 0.5.0 */
    .domainGetSchedulerParameters = lxcGetSchedulerParameters, /* 0.5.0 */
    .domainGetSchedulerParametersFlags = lxcGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = lxcSetSchedulerParameters, /* 0.5.0 */
    .domainSetSchedulerParametersFlags = lxcSetSchedulerParametersFlags, /* 0.9.2 */
    .domainInterfaceStats = lxcDomainInterfaceStats, /* 0.7.3 */
    .nodeGetCPUStats = nodeGetCPUStats, /* 0.9.3 */
    .nodeGetMemoryStats = nodeGetMemoryStats, /* 0.9.3 */
    .nodeGetCellsFreeMemory = nodeGetCellsFreeMemory, /* 0.6.5 */
    .nodeGetFreeMemory = nodeGetFreeMemory, /* 0.6.5 */
    .domainEventRegister = lxcDomainEventRegister, /* 0.7.0 */
    .domainEventDeregister = lxcDomainEventDeregister, /* 0.7.0 */
    .isEncrypted = lxcIsEncrypted, /* 0.7.3 */
    .isSecure = lxcIsSecure, /* 0.7.3 */
    .domainIsActive = lxcDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = lxcDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = lxcDomainIsUpdated, /* 0.8.6 */
    .domainEventRegisterAny = lxcDomainEventRegisterAny, /* 0.8.0 */
    .domainEventDeregisterAny = lxcDomainEventDeregisterAny, /* 0.8.0 */
    .domainOpenConsole = lxcDomainOpenConsole, /* 0.8.6 */
    .isAlive = lxcIsAlive, /* 0.9.8 */
    .nodeSuspendForDuration = nodeSuspendForDuration, /* 0.9.8 */
};

static virStateDriver lxcStateDriver = {
    .name = "LXC",
    .initialize = lxcStartup,
    .cleanup = lxcShutdown,
    .active = lxcActive,
    .reload = lxcReload,
};

int lxcRegister(void)
{
    virRegisterDriver(&lxcDriver);
    virRegisterStateDriver(&lxcStateDriver);
    virNWFilterRegisterCallbackDriver(&lxcCallbackDriver);
    return 0;
}
