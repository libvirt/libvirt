/*---------------------------------------------------------------------------*/
/* Copyright 2010, diateam (www.diateam.net)
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */
/*---------------------------------------------------------------------------*/

#include <config.h>

#include <fcntl.h>

#include "internal.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "files.h"
#include "memory.h"
#include "uuid.h"
#include "vmx.h"
#include "vmware_conf.h"
#include "vmware_driver.h"

static const char *vmw_types[] = { "player", "ws" };

static void
vmwareDriverLock(struct vmware_driver *driver)
{
    virMutexLock(&driver->lock);
}

static void
vmwareDriverUnlock(struct vmware_driver *driver)
{
    virMutexUnlock(&driver->lock);
}

static void *
vmwareDataAllocFunc(void)
{
    vmwareDomainPtr dom;

    if (VIR_ALLOC(dom) < 0)
        return NULL;

    dom->vmxPath = NULL;
    dom->gui = true;

    return dom;
}

static void
vmwareDataFreeFunc(void *data)
{
    vmwareDomainPtr dom = data;

    VIR_FREE(dom->vmxPath);
    VIR_FREE(dom);
}

static virDrvOpenStatus
vmwareOpen(virConnectPtr conn,
           virConnectAuthPtr auth ATTRIBUTE_UNUSED,
           int flags ATTRIBUTE_UNUSED)
{
    struct vmware_driver *driver;
    char * vmrun = NULL;

    if (conn->uri == NULL) {
        /* @TODO accept */
        return VIR_DRV_OPEN_DECLINED;
    } else {
        if (conn->uri->scheme == NULL ||
            (STRNEQ(conn->uri->scheme, "vmwareplayer") &&
             STRNEQ(conn->uri->scheme, "vmwarews")))
            return VIR_DRV_OPEN_DECLINED;

        /* If server name is given, its for remote driver */
        if (conn->uri->server != NULL)
            return VIR_DRV_OPEN_DECLINED;

        /* If path isn't /session, then they typoed, so tell them correct path */
        if (conn->uri->path == NULL || STRNEQ(conn->uri->path, "/session")) {
            vmwareError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected VMware URI path '%s', try vmwareplayer:///session or vmwarews:///session"),
                        NULLSTR(conn->uri->path));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    /* We now know the URI is definitely for this driver, so beyond
     * here, don't return DECLINED, always use ERROR */

    vmrun = virFindFileInPath(VMRUN);

    if (vmrun == NULL) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("%s utility is missing"), VMRUN);
        return VIR_DRV_OPEN_ERROR;
    } else {
        VIR_FREE(vmrun);
    }

    if (VIR_ALLOC(driver) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }

    if (virMutexInit(&driver->lock) < 0)
        goto cleanup;

    driver->type = STRNEQ(conn->uri->scheme, "vmwareplayer") ?
      TYPE_WORKSTATION : TYPE_PLAYER;

    if (virDomainObjListInit(&driver->domains) < 0)
        goto cleanup;

    if (!(driver->caps = vmwareCapsInit()))
        goto cleanup;

    driver->caps->privateDataAllocFunc = vmwareDataAllocFunc;
    driver->caps->privateDataFreeFunc = vmwareDataFreeFunc;

    if (vmwareLoadDomains(driver) < 0)
        goto cleanup;

    if (vmwareExtractVersion(driver) < 0)
        goto cleanup;

    conn->privateData = driver;

    return VIR_DRV_OPEN_SUCCESS;

  cleanup:
    vmwareFreeDriver(driver);
    return VIR_DRV_OPEN_ERROR;
};

static int
vmwareClose(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;

    vmwareFreeDriver(driver);

    conn->privateData = NULL;

    return 0;
}

static const char *
vmwareGetType(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "VMware";
}

static int
vmwareGetVersion(virConnectPtr conn, unsigned long *version)
{
    struct vmware_driver *driver = conn->privateData;

    vmwareDriverLock(driver);
    *version = driver->version;
    vmwareDriverUnlock(driver);
    return 0;
}

static int
vmwareStopVM(struct vmware_driver *driver, virDomainObjPtr vm)
{
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINAL, "stop",
        PROGRAM_SENTINAL, "soft", NULL
    };

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);

    if (virRun(cmd, NULL) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, _("Could not exec %s"), VMRUN);
        return -1;
    }

    vm->def->id = -1;
    vm->state = VIR_DOMAIN_SHUTOFF;

    return 0;
}

static int
vmwareStartVM(struct vmware_driver *driver, virDomainObjPtr vm)
{
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINAL, "start",
        PROGRAM_SENTINAL, PROGRAM_SENTINAL, NULL
    };
    const char *vmxPath = ((vmwareDomainPtr) vm->privateData)->vmxPath;

    if (vm->state != VIR_DOMAIN_SHUTOFF) {
        vmwareError(VIR_ERR_OPERATION_INVALID, "%s",
                    _("domain is not in shutoff state"));
        return -1;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, vmxPath);
    if (!((vmwareDomainPtr) vm->privateData)->gui)
        vmwareSetSentinal(cmd, NOGUI);
    else
        vmwareSetSentinal(cmd, NULL);

    if (virRun(cmd, NULL) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, _("Could not exec %s"), VMRUN);
        return -1;
    }

    if ((vm->def->id = vmwareExtractPid(vmxPath)) < 0) {
        vmwareStopVM(driver, vm);
        return -1;
    }

    vm->state = VIR_DOMAIN_RUNNING;

    return 0;
}

static virDomainPtr
vmwareDomainDefineXML(virConnectPtr conn, const char *xml)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;

    ctx.formatFileName = vmwareCopyVMXFileName;

    vmwareDriverLock(driver);
    if ((vmdef = virDomainDefParseString(driver->caps, xml,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, vmdef, 1) < 0)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->caps, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("Failed to write vmx file '%s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, vmdef, false)))
        goto cleanup;

    pDomain = vm->privateData;
    if ((pDomain->vmxPath = strdup(vmxPath)) == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    vmwareDomainConfigDisplay(pDomain, vmdef);

    vmdef = NULL;
    vm->persistent = 1;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = -1;

  cleanup:
    virDomainDefFree(vmdef);
    VIR_FREE(vmx);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);
    VIR_FREE(vmxPath);
    if (vm)
        virDomainObjUnlock(vm);
    vmwareDriverUnlock(driver);
    return dom;
}

static int
vmwareDomainShutdown(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    vmwareDriverLock(driver);

    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    if (vm->state != VIR_DOMAIN_RUNNING) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (vmwareStopVM(driver, vm) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
    }

    ret = 0;
  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static int
vmwareDomainSuspend(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;

    virDomainObjPtr vm;
    const char *cmd[] = {
      VMRUN, "-T", PROGRAM_SENTINAL, "pause",
      PROGRAM_SENTINAL, NULL
    };
    int ret = -1;

    if (driver->type == TYPE_PLAYER) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("vmplayer does not support libvirt suspend/resume"
                      " (vmware pause/unpause) operation "));
        return ret;
    }

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);
    if (vm->state != VIR_DOMAIN_RUNNING) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    vm->state = VIR_DOMAIN_PAUSED;
    ret = 0;

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
vmwareDomainResume(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;

    virDomainObjPtr vm;
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINAL, "unpause", PROGRAM_SENTINAL,
        NULL
    };
    int ret = -1;

    if (driver->type == TYPE_PLAYER) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("vmplayer does not support libvirt suspend/resume"
                      "(vmware pause/unpause) operation "));
        return ret;
    }

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);
    if (vm->state != VIR_DOMAIN_PAUSED) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in suspend state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    vm->state = VIR_DOMAIN_RUNNING;
    ret = 0;

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
vmwareDomainReboot(virDomainPtr dom, unsigned int flags ATTRIBUTE_UNUSED)
{
    struct vmware_driver *driver = dom->conn->privateData;
    const char * vmxPath = NULL;

    virDomainObjPtr vm;
    const char *cmd[] = {
        VMRUN, "-T", PROGRAM_SENTINAL,
        "reset", PROGRAM_SENTINAL, "soft", NULL
    };
    int ret = -1;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);
    vmxPath = ((vmwareDomainPtr) vm->privateData)->vmxPath;

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    vmwareSetSentinal(cmd, vmw_types[driver->type]);
    vmwareSetSentinal(cmd, ((vmwareDomainPtr) vm->privateData)->vmxPath);


    if (vm->state != VIR_DOMAIN_RUNNING) {
        vmwareError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("domain is not in running state"));
        goto cleanup;
    }

    if (virRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static virDomainPtr
vmwareDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainDefPtr vmdef = NULL;
    virDomainObjPtr vm = NULL;
    virDomainPtr dom = NULL;
    char *vmx = NULL;
    char *vmxPath = NULL;
    vmwareDomainPtr pDomain = NULL;
    virVMXContext ctx;

    ctx.formatFileName = vmwareCopyVMXFileName;

    vmwareDriverLock(driver);

    if ((vmdef = virDomainDefParseString(driver->caps, xml,
                                         VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (virDomainObjIsDuplicate(&driver->domains, vmdef, 1) < 0)
        goto cleanup;

    /* generate vmx file */
    vmx = virVMXFormatConfig(&ctx, driver->caps, vmdef, 7);
    if (vmx == NULL)
        goto cleanup;

    if (vmwareVmxPath(vmdef, &vmxPath) < 0)
        goto cleanup;

    /* create vmx file */
    if (virFileWriteStr(vmxPath, vmx, S_IRUSR|S_IWUSR) < 0) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    _("Failed to write vmx file '%s'"), vmxPath);
        goto cleanup;
    }

    /* assign def */
    if (!(vm = virDomainAssignDef(driver->caps,
                                  &driver->domains, vmdef, false)))
        goto cleanup;

    pDomain = vm->privateData;
    pDomain->vmxPath = strdup(vmxPath);

    vmwareDomainConfigDisplay(pDomain, vmdef);
    vmdef = NULL;

    if (vmwareStartVM(driver, vm) < 0) {
        virDomainRemoveInactive(&driver->domains, vm);
        vm = NULL;
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid);
    if (dom)
        dom->id = vm->def->id;

cleanup:
    virDomainDefFree(vmdef);
    VIR_FREE(vmx);
    VIR_FREE(vmxPath);
    if(vm)
        virDomainObjUnlock(vm);
    vmwareDriverUnlock(driver);
    return dom;
}

static int
vmwareDomainCreateWithFlags(virDomainPtr dom,
                            unsigned int flags ATTRIBUTE_UNUSED)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(dom->uuid, uuidstr);
        vmwareError(VIR_ERR_NO_DOMAIN,
                    _("No domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        vmwareError(VIR_ERR_OPERATION_INVALID,
                    "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = vmwareStartVM(driver, vm);

cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static int
vmwareDomainCreate(virDomainPtr dom)
{
    return vmwareDomainCreateWithFlags(dom, 0);
}

static int
vmwareDomainUndefine(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(dom->uuid, uuidstr);
        vmwareError(VIR_ERR_NO_DOMAIN,
                    _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainObjIsActive(vm)) {
        vmwareError(VIR_ERR_OPERATION_INVALID,
                    "%s", _("cannot undefine active domain"));
        goto cleanup;
    }

    if (!vm->persistent) {
        vmwareError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("cannot undefine transient domain"));
        goto cleanup;
    }

    virDomainRemoveInactive(&driver->domains, vm);
    vm = NULL;
    ret = 0;

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    vmwareDriverUnlock(driver);
    return ret;
}

static virDomainPtr
vmwareDomainLookupByID(virConnectPtr conn, int id)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainFindByID(&driver->domains, id);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
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

static char *
vmwareGetOSType(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    if (!(ret = strdup(vm->def->os.type)))
        virReportOOMError();

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}


static virDomainPtr
vmwareDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
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

static virDomainPtr
vmwareDomainLookupByName(virConnectPtr conn, const char *name)
{
    struct vmware_driver *driver = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vmwareDriverLock(driver);
    vm = virDomainFindByName(&driver->domains, name);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
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

static int
vmwareDomainIsActive(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    vmwareDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);
    if (!obj) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

  cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static int
vmwareDomainIsPersistent(virDomainPtr dom)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    vmwareDriverLock(driver);
    obj = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);
    if (!obj) {
        vmwareError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

  cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}


static char *
vmwareDomainDumpXML(virDomainPtr dom, int flags)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    ret = virDomainDefFormat(vm->def, flags);

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static int
vmwareNumDefinedDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 0);
    vmwareDriverUnlock(driver);

    return n;
}

static int
vmwareNumDomains(virConnectPtr conn)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    n = virDomainObjListNumOfDomains(&driver->domains, 1);
    vmwareDriverUnlock(driver);

    return n;
}


static int
vmwareListDomains(virConnectPtr conn, int *ids, int nids)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    n = virDomainObjListGetActiveIDs(&driver->domains, ids, nids);
    vmwareDriverUnlock(driver);

    return n;
}

static int
vmwareListDefinedDomains(virConnectPtr conn,
                         char **const names, int nnames)
{
    struct vmware_driver *driver = conn->privateData;
    int n;

    vmwareDriverLock(driver);
    n = virDomainObjListGetInactiveNames(&driver->domains, names, nnames);
    vmwareDriverUnlock(driver);
    return n;
}

static int
vmwareDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    struct vmware_driver *driver = dom->conn->privateData;
    virDomainObjPtr vm;
    int ret = -1;

    vmwareDriverLock(driver);
    vm = virDomainFindByUUID(&driver->domains, dom->uuid);
    vmwareDriverUnlock(driver);

    if (!vm) {
        vmwareError(VIR_ERR_NO_DOMAIN, "%s",
                    _("no domain with matching uuid"));
        goto cleanup;
    }

    info->state = vm->state;
    info->cpuTime = 0;
    info->maxMem = vm->def->mem.max_balloon;
    info->memory = vm->def->mem.cur_balloon;
    info->nrVirtCpu = vm->def->vcpus;
    ret = 0;

  cleanup:
    if (vm)
        virDomainObjUnlock(vm);
    return ret;
}

static virDriver vmwareDriver = {
    VIR_DRV_VMWARE,
    "VMWARE",
    vmwareOpen,                 /* open */
    vmwareClose,                /* close */
    NULL,                       /* supports_feature */
    vmwareGetType,              /* type */
    vmwareGetVersion,           /* version */
    NULL,                       /* libvirtVersion (impl. in libvirt.c) */
    NULL,                       /* getHostname */
    NULL,                       /* getMaxVcpus */
    NULL,                       /* nodeGetInfo */
    NULL,                       /* getCapabilities */
    vmwareListDomains,          /* listDomains */
    vmwareNumDomains,           /* numOfDomains */
    vmwareDomainCreateXML,      /* domainCreateXML */
    vmwareDomainLookupByID,     /* domainLookupByID */
    vmwareDomainLookupByUUID,   /* domainLookupByUUID */
    vmwareDomainLookupByName,   /* domainLookupByName */
    vmwareDomainSuspend,        /* domainSuspend */
    vmwareDomainResume,         /* domainResume */
    vmwareDomainShutdown,       /* domainShutdown */
    vmwareDomainReboot,         /* domainReboot */
    vmwareDomainShutdown,        /* domainDestroy */
    vmwareGetOSType,            /* domainGetOSType */
    NULL,                       /* domainGetMaxMemory */
    NULL,                       /* domainSetMaxMemory */
    NULL,                       /* domainSetMemory */
    vmwareDomainGetInfo,        /* domainGetInfo */
    NULL,                       /* domainSave */
    NULL,                       /* domainRestore */
    NULL,                       /* domainCoreDump */
    NULL,                       /* domainSetVcpus */
    NULL,                       /* domainSetVcpusFlags */
    NULL,                       /* domainGetVcpusFlags */
    NULL,                       /* domainPinVcpu */
    NULL,                       /* domainGetVcpus */
    NULL,                       /* domainGetMaxVcpus */
    NULL,                       /* domainGetSecurityLabel */
    NULL,                       /* nodeGetSecurityModel */
    vmwareDomainDumpXML,        /* domainDumpXML */
    NULL,                       /* domainXmlFromNative */
    NULL,                       /* domainXmlToNative */
    vmwareListDefinedDomains,   /* listDefinedDomains */
    vmwareNumDefinedDomains,    /* numOfDefinedDomains */
    vmwareDomainCreate,         /* domainCreate */
    vmwareDomainCreateWithFlags,/* domainCreateWithFlags */
    vmwareDomainDefineXML,      /* domainDefineXML */
    vmwareDomainUndefine,       /* domainUndefine */
    NULL,                       /* domainAttachDevice */
    NULL,                       /* domainAttachDeviceFlags */
    NULL,                       /* domainDetachDevice */
    NULL,                       /* domainDetachDeviceFlags */
    NULL,                       /* domainUpdateDeviceFlags */
    NULL,                       /* domainGetAutostart */
    NULL,                       /* domainSetAutostart */
    NULL,                       /* domainGetSchedulerType */
    NULL,                       /* domainGetSchedulerParameters */
    NULL,                       /* domainSetSchedulerParameters */
    NULL,                       /* domainMigratePrepare */
    NULL,                       /* domainMigratePerform */
    NULL,                       /* domainMigrateFinish */
    NULL,                       /* domainBlockStats */
    NULL,                       /* domainInterfaceStats */
    NULL,                       /* domainMemoryStats */
    NULL,                       /* domainBlockPeek */
    NULL,                       /* domainMemoryPeek */
    NULL,                       /* domainGetBlockInfo */
    NULL,                       /* nodeGetCellsFreeMemory */
    NULL,                       /* getFreeMemory */
    NULL,                       /* domainEventRegister */
    NULL,                       /* domainEventDeregister */
    NULL,                       /* domainMigratePrepare2 */
    NULL,                       /* domainMigrateFinish2 */
    NULL,                       /* nodeDeviceDettach */
    NULL,                       /* nodeDeviceReAttach */
    NULL,                       /* nodeDeviceReset */
    NULL,                       /* domainMigratePrepareTunnel */
    NULL,                       /* IsEncrypted */
    NULL,                       /* IsSecure */
    vmwareDomainIsActive,       /* DomainIsActive */
    vmwareDomainIsPersistent,   /* DomainIsPersistent */
    NULL,                       /* domainIsUpdated */
    NULL,                       /* cpuCompare */
    NULL,                       /* cpuBaseline */
    NULL,                       /* domainGetJobInfo */
    NULL,                       /* domainAbortJob */
    NULL,                       /* domainMigrateSetMaxDowntime */
    NULL,                       /* domainEventRegisterAny */
    NULL,                       /* domainEventDeregisterAny */
    NULL,                       /* domainManagedSave */
    NULL,                       /* domainHasManagedSaveImage */
    NULL,                       /* domainManagedSaveRemove */
    NULL,                       /* domainSnapshotCreateXML */
    NULL,                       /* domainSnapshotDumpXML */
    NULL,                       /* domainSnapshotNum */
    NULL,                       /* domainSnapshotListNames */
    NULL,                       /* domainSnapshotLookupByName */
    NULL,                       /* domainHasCurrentSnapshot */
    NULL,                       /* domainSnapshotCurrent */
    NULL,                       /* domainRevertToSnapshot */
    NULL,                       /* domainSnapshotDelete */
    NULL,                       /* qemuDomainMonitorCommand */
    NULL,                       /* domainSetMemoryParameters */
    NULL,                       /* domainGetMemoryParameters */
    NULL,                       /* domainOpenConsole */
};

int
vmwareRegister(void)
{
    if (virRegisterDriver(&vmwareDriver) < 0)
        return -1;
    return 0;
}
